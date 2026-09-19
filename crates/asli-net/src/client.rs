//! The real transport, over a WebSocket.
//!
//! Everything interesting happens in [`crate::session`], which has no I/O. This module is the thin
//! layer that moves frames between that driver and a socket, plus the reconnect loop that keeps
//! trying. Keeping the two apart is what lets the protocol rules be tested without a server.

use std::time::{SystemTime, UNIX_EPOCH};

use futures_util::{SinkExt, StreamExt};
use tokio::sync::mpsc;
use tokio_tungstenite::tungstenite::protocol::Message as WsMessage;

use crate::envelope::{AuthFailCode, ErrorCode};
use crate::error::{Error, Result};
use crate::session::{Action, Session};

/// Something originating on this device that the connection must carry.
///
/// A channel of `String` could only ever carry text, which silently made images unsendable and
/// left the retained fetch with no route to the socket at all. Naming the three things a client
/// can originate makes each one reach the right `Session` method instead.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum LocalEvent {
    /// Text copied on this device.
    Text(String),
    /// A PNG copied on this device. Sealed and sent as chunks.
    Image(Vec<u8>),
    /// Ask the relay for the clip it is holding.
    ///
    /// Explicit by design: a retained clip is never applied automatically on connect, because a
    /// device that just copied something locally would lose it to a stale clip from the relay.
    FetchRetained,
}

/// A clip that arrived, decrypted and validated.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReceivedClip {
    /// Normalized UTF-8 text, ready to write to the clipboard.
    pub text: String,
    /// Capture time from inside the ciphertext.
    pub ts_ms: u64,
    /// Whether this was a stored clip rather than a live one.
    ///
    /// A retained clip must not be written to the clipboard automatically on connect. Offer it as
    /// an explicit action instead, or a device that just copied something locally will lose it to
    /// a stale clip from the relay.
    pub retained: bool,
}

/// Something worth telling the rest of the application about.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ClientEvent {
    /// The handshake completed.
    Authenticated {
        /// Connections in the room, including this one. Never a device count.
        peers: u32,
        /// Whether a retained clip can be fetched.
        has_retained: bool,
        /// Relay supplied and unauthenticated, so advisory only.
        stored_at: Option<u64>,
    },
    /// A clip arrived.
    Clip(ReceivedClip),
    /// A chunked image arrived, reassembled and validated.
    ///
    /// Surfaced rather than folded into [`ClientEvent::Clip`] because writing an image to the
    /// clipboard is a different platform call than writing text, and a caller without image
    /// support should be able to ignore this without discarding text by accident.
    Image {
        /// Normalized PNG bytes.
        png: Vec<u8>,
        /// Capture time from inside the ciphertext.
        ts_ms: u64,
    },
    /// The room connection count changed.
    Presence {
        /// Connections in the room.
        peers: u32,
    },
    /// The relay reported a non fatal problem.
    RelayError {
        /// Machine readable code.
        code: ErrorCode,
        /// Floor before retrying, when supplied.
        retry_after_ms: Option<u64>,
    },
    /// A local clip was skipped because the relay would not accept it.
    ///
    /// Surfaced rather than swallowed: a user whose copy silently vanished has no way to find out
    /// why, which is the complaint every competitor in this space collects.
    ClipSkipped {
        /// Size of the content in bytes.
        got: usize,
        /// The relay's announced limit.
        limit: usize,
    },
    /// A clip or image arrived and was discarded, for a reason that is only this device's to
    /// know. See [`Action::Dropped`].
    Dropped {
        /// Why, as a short fixed label.
        reason: &'static str,
        /// Whether it was the relay's stored clip.
        retained: bool,
    },
    /// This device's clock disagrees with the relay's. See [`Action::ClockSkew`].
    ClockSkew {
        /// The relay's clock minus ours, in milliseconds.
        skew_ms: i64,
    },
}

/// Why a connection ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Disconnect {
    /// The relay closed with this code. See section 12.1 of the protocol.
    Close(u16),
    /// The socket ended without a close frame.
    Eof,
    /// Authentication was rejected.
    AuthFailed(AuthFailCode),
    /// The local clip channel closed, meaning the application is shutting down.
    LocalChannelClosed,
}

/// Selects the rustls crypto backend once per process.
///
/// rustls 0.23 will not guess. With no provider installed it panics on the first handshake, at
/// runtime, in release, on a user's machine. Installing it here means a downstream consumer of
/// this crate cannot inherit that trap by forgetting to do it themselves.
///
/// The result is deliberately ignored: an error means another provider is already installed,
/// which is a legitimate choice by the embedding application and not ours to override.
fn install_crypto_provider() {
    use std::sync::Once;

    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
}

/// Wall clock in milliseconds.
///
/// Used for message timestamps and the guards' age windows. A clock that is wrong by more than a
/// minute will cause peers to reject this device's clips, which is why `ts_ms` is advisory and the
/// sequence number carries the security weight.
#[must_use]
pub fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
}

/// Connects, authenticates, and pumps frames until the connection ends.
///
/// Returns why it ended, so the caller can decide whether to reconnect. This function never
/// retries by itself: pacing belongs to [`crate::backoff`] and the decision belongs to
/// [`crate::state`].
///
/// # Errors
///
/// Returns [`Error::Transport`] if the socket fails, and a protocol error if the relay sends
/// something this client cannot make sense of.
pub async fn run_once(
    url: &str,
    session: &mut Session,
    local_rx: &mut mpsc::Receiver<LocalEvent>,
    on_event: &mut dyn FnMut(ClientEvent),
) -> Result<Disconnect> {
    install_crypto_provider();

    let (mut socket, _) = tokio_tungstenite::connect_async(url)
        .await
        .map_err(|e| Error::Transport(format!("{e}")))?;

    let hello = session.hello_frame()?;
    socket
        .send(WsMessage::Text(hello.into()))
        .await
        .map_err(|e| Error::Transport(format!("{e}")))?;

    loop {
        tokio::select! {
            incoming = socket.next() => {
                let Some(message) = incoming else {
                    return Ok(Disconnect::Eof);
                };
                let message = message.map_err(|e| Error::Transport(format!("{e}")))?;

                match message {
                    WsMessage::Text(text) => {
                        for action in session.handle_frame(text.as_str(), now_ms())? {
                            match action {
                                Action::Send(frame) => socket
                                    .send(WsMessage::Text(frame.into()))
                                    .await
                                    .map_err(|e| Error::Transport(format!("{e}")))?,
                                Action::AuthFailed(code) => {
                                    return Ok(Disconnect::AuthFailed(code));
                                }
                                Action::Authenticated { peers, has_retained, stored_at } => {
                                    on_event(ClientEvent::Authenticated { peers, has_retained, stored_at });
                                }
                                Action::Clip { text, ts_ms, retained } => {
                                    on_event(ClientEvent::Clip(ReceivedClip { text, ts_ms, retained }));
                                }
                                Action::Image { png, ts_ms } => {
                                    on_event(ClientEvent::Image { png, ts_ms });
                                }
                                Action::Presence { peers } => {
                                    on_event(ClientEvent::Presence { peers });
                                }
                                Action::RelayError { code, retry_after_ms } => {
                                    on_event(ClientEvent::RelayError { code, retry_after_ms });
                                }
                                Action::Dropped { reason, retained } => {
                                    on_event(ClientEvent::Dropped { reason, retained });
                                }
                                Action::ClockSkew { skew_ms } => {
                                    on_event(ClientEvent::ClockSkew { skew_ms });
                                }
                            }
                        }
                    }
                    WsMessage::Close(frame) => {
                        let code = frame.map_or(1000, |f| u16::from(f.code));
                        return Ok(Disconnect::Close(code));
                    }
                    // Protocol level pings are answered by the library. Binary frames are not part
                    // of v1, so they are ignored rather than treated as fatal.
                    WsMessage::Ping(_) | WsMessage::Pong(_) | WsMessage::Binary(_)
                    | WsMessage::Frame(_) => {}
                }
            }

            local = local_rx.recv() => {
                let Some(event) = local else {
                    return Ok(Disconnect::LocalChannelClosed);
                };
                for frame in frames_for(session, event, on_event)? {
                    socket
                        .send(WsMessage::Text(frame.into()))
                        .await
                        .map_err(|e| Error::Transport(format!("{e}")))?;
                }
            }
        }
    }
}

/// Turns something that happened on this device into the frames that carry it.
///
/// Split out of [`run_once`] because the three variants each have their own rules, and a select
/// arm is the wrong place to read them. Returns an empty list when there is nothing to send, which
/// is a normal outcome rather than an error: empty content, the echo of our own write, or a
/// retained fetch raised before the handshake finished.
fn frames_for(
    session: &mut Session,
    event: LocalEvent,
    on_event: &mut dyn FnMut(ClientEvent),
) -> Result<Vec<String>> {
    match event {
        LocalEvent::Text(text) => match session.observe_local(&text, now_ms()) {
            Ok(Some(frame)) => Ok(vec![frame]),
            // Nothing to send: empty content, the echo of our own write, or a copy that raced the
            // handshake. The last of those is timing rather than corruption, and treating it as
            // fatal would drop the whole connection over one early copy.
            Ok(None) | Err(Error::OutOfOrder(_)) => Ok(Vec::new()),
            Err(Error::ContentTooLarge { got, limit }) => {
                on_event(ClientEvent::ClipSkipped { got, limit });
                Ok(Vec::new())
            }
            Err(other) => Err(other),
        },
        // Order matters and is preserved by the caller: clip_begin, chunks, then clip_end. The
        // receiver commits nothing to the clipboard until the final chunk verifies.
        LocalEvent::Image(png) => match session.observe_local_image(&png, now_ms()) {
            Ok(frames) => Ok(frames),
            Err(Error::ContentTooLarge { got, limit }) => {
                on_event(ClientEvent::ClipSkipped { got, limit });
                Ok(Vec::new())
            }
            // A copy made while the handshake is still in flight is ordinary timing, not a
            // protocol violation. Treating it as fatal killed the whole connection over one
            // early image, which is far worse than dropping that image.
            Err(Error::OutOfOrder(_)) => Ok(Vec::new()),
            Err(other) => Err(other),
        },
        // The tray can raise this at any moment, including while reconnecting, so asking too
        // early is ignored rather than fatal.
        LocalEvent::FetchRetained => match session.fetch_last_frame() {
            Ok(frame) => Ok(vec![frame]),
            Err(Error::OutOfOrder(_)) => Ok(Vec::new()),
            Err(other) => Err(other),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_clock_looks_like_a_wall_clock() {
        let now = now_ms();
        // Somewhere after 2020 and before 2100, which catches a unit mix up.
        assert!(now > 1_577_836_800_000, "got {now}");
        assert!(now < 4_102_444_800_000, "got {now}");
    }

    #[tokio::test]
    async fn a_failed_dial_is_a_transport_error_not_a_panic() {
        let mut session =
            Session::new(asli_crypto::Identity::from_secret(&[1u8; 32]), [0u8; 16], 0);
        let (_tx, mut rx) = mpsc::channel(1);
        let mut events = |_: ClientEvent| {};

        // Port 1 on loopback refuses connections, which is the failure every laptop sees when it
        // wakes up before the network is back.
        let result = run_once("ws://127.0.0.1:1/v1", &mut session, &mut rx, &mut events).await;
        assert!(matches!(result, Err(Error::Transport(_))), "got {result:?}");
    }
}

#[cfg(test)]
mod tls_tests {
    use super::*;

    /// The regression guard for the bug that 69 unit tests missed.
    ///
    /// Every other test in this crate drives a fake transport, so nothing ever reached rustls and
    /// nothing noticed that no crypto provider was selected. Dialling a real address fails for
    /// many honest reasons (no network, refused, DNS), but a missing provider does not fail, it
    /// panics. So this asserts on the absence of a panic rather than on the connection.
    #[tokio::test]
    async fn tls_dial_does_not_panic_for_want_of_a_crypto_provider() {
        let (_tx, mut rx) = mpsc::channel::<LocalEvent>(1);
        let identity = asli_crypto::Identity::generate().expect("rng works");
        let mut session = Session::new(identity, [7u8; 16], 1);
        let mut sink = |_: ClientEvent| {};

        // Port 1 on loopback: nothing listens there, so this returns a transport error quickly.
        // The point is that it returns at all instead of panicking inside rustls.
        let result = run_once("wss://127.0.0.1:1/v1", &mut session, &mut rx, &mut sink).await;
        assert!(
            result.is_err(),
            "expected a transport error, got {result:?}"
        );
    }

    #[test]
    fn provider_installation_is_idempotent() {
        install_crypto_provider();
        install_crypto_provider();
    }
}
