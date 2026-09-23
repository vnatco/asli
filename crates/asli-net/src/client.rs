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
pub use crate::session::{DeviceInfo, PeerInfo};

/// Something originating on this device that the connection must carry.
///
/// A channel of `String` could only ever carry text, which silently made images unsendable and
/// left the retained fetch with no route to the socket at all. Naming the things a client can
/// originate makes each one reach the right `Session` method instead.
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
    /// This device's name or operating system changed. Announced at once when connected, and
    /// used for every announcement after.
    DeviceInfo(DeviceInfo),
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
    /// The device that copied it, from inside the ciphertext.
    pub device_id: [u8; 16],
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
        /// The device that copied it, from inside the ciphertext.
        device_id: [u8; 16],
    },
    /// Another device announced its name and operating system.
    ///
    /// Sent by each device when it connects and again whenever the room's connection count
    /// changes, so after a count goes down, a device that stays silent is the one that left.
    Peer(PeerInfo),
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
/// Refuses a relay URL whose transport is not encrypted.
///
/// `wss://` always passes. `ws://` passes only for a loopback host, which is how the relay is run
/// locally while working on it; there is no address on a network where cleartext is acceptable,
/// and no setting to turn this off.
fn require_encrypted_transport(url: &str) -> Result<()> {
    if is_encrypted_transport(url) {
        Ok(())
    } else {
        Err(Error::Transport(
            "the relay address must start with wss://, or ws:// for a local relay".to_owned(),
        ))
    }
}

/// Split out so it can be tested without a relay, and reused by the settings screen.
#[must_use]
pub fn is_encrypted_transport(url: &str) -> bool {
    let lower = url.trim().to_ascii_lowercase();
    if lower.starts_with("wss://") {
        return true;
    }
    let Some(rest) = lower.strip_prefix("ws://") else {
        return false;
    };
    // Host part only: up to the first `/`, `?` or `#`, minus any port and any credentials, which
    // is what stops `ws://localhost@evil.example/` and `ws://evil.example/localhost` passing.
    let host = rest
        .split(['/', '?', '#'])
        .next()
        .unwrap_or_default()
        .rsplit('@')
        .next()
        .unwrap_or_default();
    let host = host.strip_prefix('[').map_or_else(
        || host.split(':').next().unwrap_or_default(),
        |v6| v6.split(']').next().unwrap_or_default(),
    );
    host == "localhost" || host == "::1" || host == "127.0.0.1"
}

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

    // Before anything is sent. A relay reached over plain `ws://` still receives sealed payloads,
    // but it hands a network attacker the room id, the sizes and the timing of every clip, and
    // lets one tamper with the handshake. The protocol requires `wss://` for exactly that reason,
    // and a mistyped scheme in Settings, or an edited configuration file, must not be able to
    // downgrade the transport in silence.
    require_encrypted_transport(url)?;

    // Bounded, so a network that swallows packets mid connect cannot hang the reconnect loop.
    let (mut socket, _) =
        tokio::time::timeout(CONNECT_TIMEOUT, tokio_tungstenite::connect_async(url))
            .await
            .map_err(|_| Error::Transport("the relay did not answer in time".to_owned()))?
            .map_err(|e| Error::Transport(format!("{e}")))?;

    let hello = session.hello_frame()?;
    socket
        .send(WsMessage::Text(hello.into()))
        .await
        .map_err(|e| Error::Transport(format!("{e}")))?;

    let mut unconfirmed = None;
    let outcome = converse(&mut socket, session, local_rx, on_event, &mut unconfirmed).await;
    // However the connection ended, a copy the relay never confirmed goes out again on the next
    // one. Otherwise a copy made just as the network dropped, before this side noticed, was lost
    // with the connection it was sent on.
    if let Some(event) = unconfirmed {
        session.stash_resend(event);
    }
    outcome
}

/// Everything after the handshake starts: relay traffic in, local copies out, liveness.
async fn converse(
    socket: &mut Socket,
    session: &mut Session,
    local_rx: &mut mpsc::Receiver<LocalEvent>,
    on_event: &mut dyn FnMut(ClientEvent),
    unconfirmed: &mut Option<LocalEvent>,
) -> Result<Disconnect> {
    // Liveness. A connection whose other end vanished, which is what sleep and a network change
    // both leave behind, sends nothing and reports nothing: the socket just stays quiet forever,
    // the tray says Synced, and nothing arrives. So this side pings, and treats a long enough
    // silence as the end of the connection. The relay's own pings and the answers to ours both
    // count as traffic.
    let mut last_heard = tokio::time::Instant::now();
    let mut ping = tokio::time::interval(PING_INTERVAL);
    ping.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    // When the relay asked us to slow down, local clips wait until then. They are coalesced while
    // they wait, so only the newest goes when the pause ends.
    let mut hold_until: Option<tokio::time::Instant> = None;
    // Pings are numbered, so the answer to the one sent right after a copy can be told apart from
    // the answer to an earlier one. That answer is what confirms the copy reached the relay:
    // frames arrive in order, so the relay read the copy before the ping.
    let mut pings: u64 = 0;
    let mut confirming: Option<u64> = None;

    loop {
        let ready = session.is_ready();
        let held = hold_until.is_some_and(|until| tokio::time::Instant::now() < until);

        // A copy the last connection lost goes first, once this one can carry it.
        if ready && !held && unconfirmed.is_none() {
            if let Some(event) = session.take_resend() {
                send_local(
                    socket,
                    session,
                    vec![event],
                    on_event,
                    unconfirmed,
                    &mut pings,
                    &mut confirming,
                )
                .await?;
            }
        }

        tokio::select! {
            incoming = socket.next() => {
                let Some(message) = incoming else {
                    return Ok(Disconnect::Eof);
                };
                let message = message.map_err(|e| Error::Transport(format!("{e}")))?;
                last_heard = tokio::time::Instant::now();

                match message {
                    WsMessage::Text(text) => {
                        let actions = match session.handle_frame(text.as_str(), now_ms()) {
                            Ok(actions) => actions,
                            // A type from a newer relay. The protocol says to ignore it.
                            Err(Error::UnknownType) => continue,
                            Err(other) => return Err(other),
                        };
                        for action in actions {
                            if let Some(end) = apply_action(action, socket, &mut hold_until, on_event).await? {
                                return Ok(end);
                            }
                        }
                    }
                    WsMessage::Close(frame) => {
                        let code = frame.map_or(1000, |f| u16::from(f.code));
                        return Ok(Disconnect::Close(code));
                    }
                    WsMessage::Pong(payload) => {
                        if confirming.is_some_and(|n| payload.as_ref() == n.to_be_bytes()) {
                            confirming = None;
                            *unconfirmed = None;
                        }
                    }
                    // Protocol level pings are answered by the library. Binary frames are not part
                    // of v1, so they are ignored rather than treated as fatal.
                    WsMessage::Ping(_) | WsMessage::Binary(_) | WsMessage::Frame(_) => {}
                }
            }

            // Only once the handshake is done. Read earlier, a copy made while offline was taken
            // off the queue before the relay would accept it and thrown away, and with it very
            // often the one copy the person was waiting to see on the other machine.
            local = local_rx.recv(), if ready && !held => {
                let Some(event) = local else {
                    return Ok(Disconnect::LocalChannelClosed);
                };
                let batch = coalesce(event, local_rx);
                // One unconfirmed copy is tracked, the newest: a newer copy replaces it on every
                // device's clipboard anyway, so once one is sent the older no longer matters.
                // send_local only replaces it when this batch actually sends a copy.
                send_local(socket, session, batch, on_event, unconfirmed, &mut pings, &mut confirming).await?;
            }

            _ = ping.tick() => {
                if last_heard.elapsed() > SILENCE_LIMIT {
                    return Ok(Disconnect::Eof);
                }
                pings = pings.wrapping_add(1);
                socket
                    .send(WsMessage::Ping(pings.to_be_bytes().to_vec().into()))
                    .await
                    .map_err(|e| Error::Transport(format!("{e}")))?;
            }

            () = tokio::time::sleep_until(hold_until.unwrap_or_else(tokio::time::Instant::now)), if held => {
                hold_until = None;
            }
        }
    }
}

/// Sends local events, and asks the relay to confirm the copy among them.
async fn send_local(
    socket: &mut Socket,
    session: &mut Session,
    events: Vec<LocalEvent>,
    on_event: &mut dyn FnMut(ClientEvent),
    unconfirmed: &mut Option<LocalEvent>,
    pings: &mut u64,
    confirming: &mut Option<u64>,
) -> Result<()> {
    for event in events {
        let copy =
            matches!(event, LocalEvent::Text(_) | LocalEvent::Image(_)).then(|| event.clone());
        let frames = frames_for(session, event, on_event)?;
        let sent_something = !frames.is_empty();
        for frame in frames {
            socket
                .send(WsMessage::Text(frame.into()))
                .await
                .map_err(|e| Error::Transport(format!("{e}")))?;
        }
        if let (Some(copy), true) = (copy, sent_something) {
            *pings = pings.wrapping_add(1);
            socket
                .send(WsMessage::Ping(pings.to_be_bytes().to_vec().into()))
                .await
                .map_err(|e| Error::Transport(format!("{e}")))?;
            *confirming = Some(*pings);
            *unconfirmed = Some(copy);
        }
    }
    Ok(())
}

/// Carries out one thing the session decided. Returns how the connection ends, if it does.
async fn apply_action(
    action: Action,
    socket: &mut Socket,
    hold_until: &mut Option<tokio::time::Instant>,
    on_event: &mut dyn FnMut(ClientEvent),
) -> Result<Option<Disconnect>> {
    match action {
        Action::Send(frame) => socket
            .send(WsMessage::Text(frame.into()))
            .await
            .map_err(|e| Error::Transport(format!("{e}")))?,
        Action::AuthFailed(code) => return Ok(Some(Disconnect::AuthFailed(code))),
        Action::Authenticated {
            peers,
            has_retained,
            stored_at,
        } => on_event(ClientEvent::Authenticated {
            peers,
            has_retained,
            stored_at,
        }),
        Action::Clip {
            text,
            ts_ms,
            retained,
            device_id,
        } => on_event(ClientEvent::Clip(ReceivedClip {
            text,
            ts_ms,
            retained,
            device_id,
        })),
        Action::Image {
            png,
            ts_ms,
            device_id,
        } => on_event(ClientEvent::Image {
            png,
            ts_ms,
            device_id,
        }),
        Action::Peer(peer) => on_event(ClientEvent::Peer(peer)),
        Action::Presence { peers } => on_event(ClientEvent::Presence { peers }),
        Action::RelayError {
            code,
            retry_after_ms,
        } => {
            // Asked to slow down: local copies wait until then instead of being refused one by one.
            if let Some(wait) = retry_after_ms {
                *hold_until =
                    Some(tokio::time::Instant::now() + std::time::Duration::from_millis(wait));
            }
            on_event(ClientEvent::RelayError {
                code,
                retry_after_ms,
            });
        }
        Action::Dropped { reason, retained } => {
            on_event(ClientEvent::Dropped { reason, retained });
        }
        Action::ClockSkew { skew_ms } => on_event(ClientEvent::ClockSkew { skew_ms }),
    }
    Ok(None)
}

/// The connection to the relay.
type Socket =
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>;

/// How long to wait for the relay to accept a connection.
const CONNECT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(20);

/// How often this side pings the relay.
const PING_INTERVAL: std::time::Duration = std::time::Duration::from_secs(25);

/// How long a connection may be silent before it is treated as gone. Two pings and some slack.
const SILENCE_LIMIT: std::time::Duration = std::time::Duration::from_secs(70);

/// Collapses everything already queued behind `first` into what is still worth sending.
///
/// The clipboard is last write wins, so of several copies made while waiting only the newest
/// matters, and sending them all in one burst would run straight into the relay's rate limit. A
/// request for the stored clip is kept alongside, since it is not a copy, and so is the newest
/// device information, which goes first so the copy after it is sent under the new name.
fn coalesce(first: LocalEvent, local_rx: &mut mpsc::Receiver<LocalEvent>) -> Vec<LocalEvent> {
    let mut newest_copy = None;
    let mut newest_info = None;
    let mut fetch = false;
    let mut take = |event: LocalEvent| match event {
        LocalEvent::FetchRetained => fetch = true,
        LocalEvent::DeviceInfo(info) => newest_info = Some(LocalEvent::DeviceInfo(info)),
        copy => newest_copy = Some(copy),
    };
    take(first);
    while let Ok(next) = local_rx.try_recv() {
        take(next);
    }
    newest_info
        .into_iter()
        .chain(newest_copy)
        .chain(fetch.then_some(LocalEvent::FetchRetained))
        .collect()
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
        // Stored whatever happens, so a name changed while offline is the one announced next.
        LocalEvent::DeviceInfo(info) => {
            session.set_device_info(info);
            Ok(session.announce_frame(now_ms())?.into_iter().collect())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::is_encrypted_transport;

    #[test]
    fn cleartext_is_refused_unless_the_relay_is_local() {
        for url in [
            "wss://asli.vnat.dev/v1",
            "WSS://ASLI.VNAT.DEV/v1",
            "  wss://asli.vnat.dev/v1  ",
            "ws://localhost:3006/v1",
            "ws://127.0.0.1:3006/v1",
            "ws://[::1]:3006/v1",
        ] {
            assert!(is_encrypted_transport(url), "must be allowed: {url}");
        }

        for url in [
            "ws://asli.vnat.dev/v1",
            "ws://192.168.1.10:3006/v1",
            // A host that only looks local. Credentials before the @, and a path after the host,
            // are the two ways to smuggle the word past a careless check.
            "ws://localhost@evil.example/v1",
            "ws://evil.example/localhost",
            "ws://localhost.evil.example/v1",
            "http://asli.vnat.dev/v1",
            "asli.vnat.dev/v1",
            "",
        ] {
            assert!(!is_encrypted_transport(url), "must be refused: {url}");
        }
    }

    use super::*;

    #[test]
    fn a_backlog_of_copies_is_sent_as_the_newest_one() {
        let (tx, mut rx) = mpsc::channel(16);
        for text in ["first", "second"] {
            tx.try_send(LocalEvent::Text(text.to_owned()))
                .expect("queued");
        }
        tx.try_send(LocalEvent::FetchRetained).expect("queued");
        tx.try_send(LocalEvent::Text("newest".to_owned()))
            .expect("queued");

        let batch = coalesce(LocalEvent::Text("zeroth".to_owned()), &mut rx);
        assert_eq!(batch.len(), 2);
        assert!(matches!(&batch[0], LocalEvent::Text(text) if text == "newest"));
        assert!(matches!(batch[1], LocalEvent::FetchRetained));
    }

    #[test]
    fn device_information_is_never_mistaken_for_a_copy() {
        let info = |name: &str| {
            LocalEvent::DeviceInfo(DeviceInfo {
                name: name.to_owned(),
                os: "Linux".to_owned(),
            })
        };
        let (tx, mut rx) = mpsc::channel(16);
        tx.try_send(LocalEvent::Text("copied".to_owned()))
            .expect("queued");
        tx.try_send(info("renamed")).expect("queued");

        let batch = coalesce(info("first"), &mut rx);
        assert_eq!(batch.len(), 2, "one name and one copy, got {batch:?}");
        assert!(matches!(&batch[0], LocalEvent::DeviceInfo(i) if i.name == "renamed"));
        assert!(matches!(&batch[1], LocalEvent::Text(text) if text == "copied"));
    }

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
