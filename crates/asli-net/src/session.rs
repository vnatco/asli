//! The protocol driver.
//!
//! This is sans I/O on purpose: it consumes frames and produces frames, and knows nothing about
//! sockets, threads or timers. Every rule in `docs/PROTOCOL.md` that can be checked without a
//! network is checked here and tested without one, which is what makes the interesting cases
//! (replay, rollback, a stale retained clip, an oversize clip) cheap to cover.
//!
//! The caller supplies the current time, so tests are deterministic.

use asli_core::{EchoGuard, Incoming, ReplayGuard, Verdict};
use asli_crypto::clip::{self, ContentType, Inner, DEVICE_ID_LEN, MSG_ID_LEN, NONCE_LEN, TAG_LEN};
use asli_crypto::identity::ROOM_ID_LEN;
use asli_crypto::Identity;

use crate::envelope::{
    self, Auth, AuthFailCode, Clip, ErrorCode, FetchLast, Hello, Limits, Message, Pong,
    PROTOCOL_VERSION,
};
use crate::error::{Error, Result};

/// Default retention window to allow for a retained clip, until a relay announces its own.
pub const DEFAULT_RETENTION_MS: u64 = 24 * 60 * 60 * 1000;

/// Client identifier sent in `hello`. Deliberately carries no hostname or username.
pub const CLIENT_ID: &str = concat!("asli/", env!("CARGO_PKG_VERSION"));

/// How far the driver has progressed through the handshake.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Phase {
    New,
    HelloSent,
    Authenticating,
    Ready,
}

/// Something the caller should do.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Action {
    /// Send this frame to the relay.
    Send(String),
    /// The relay accepted us.
    Authenticated {
        /// Connections in the room, including this one. Never a device count.
        peers: u32,
        /// Whether a retained clip is available to fetch.
        has_retained: bool,
        /// When the relay stored it. Relay supplied and not authenticated, so advisory only.
        stored_at: Option<u64>,
    },
    /// A clip arrived, decrypted and validated. Write it to the clipboard.
    ///
    /// The content hash has already been recorded in the echo guard, so the clipboard change this
    /// write causes will be suppressed.
    Clip {
        /// Normalized UTF-8 text.
        text: String,
        /// Capture time from inside the ciphertext.
        ts_ms: u64,
        /// Whether the relay delivered this as a stored clip rather than a live one.
        retained: bool,
    },
    /// The room connection count changed.
    Presence {
        /// Connections in the room. Never a device count.
        peers: u32,
    },
    /// The relay reported a non fatal problem.
    RelayError {
        /// Machine readable code.
        code: ErrorCode,
        /// Floor before retrying, when the relay supplied one.
        retry_after_ms: Option<u64>,
    },
    /// Authentication was rejected.
    AuthFailed(AuthFailCode),
}

/// Drives one connection's worth of protocol.
pub struct Session {
    identity: Identity,
    device_id: [u8; DEVICE_ID_LEN],
    seq: u64,
    epoch: u32,
    phase: Phase,
    limits: Option<Limits>,
    echo: EchoGuard,
    replay: ReplayGuard,
    peers: u32,
    pinned_auth: Option<([u8; 16], u64)>,
}

impl Session {
    /// Creates a driver for one device.
    ///
    /// `seq` is the per device counter, persisted across restarts. Starting it below a value the
    /// peers have already seen would make every clip look like a rollback to them, so it must be
    /// restored from storage rather than reset.
    #[must_use]
    pub fn new(identity: Identity, device_id: [u8; DEVICE_ID_LEN], seq: u64) -> Self {
        Self {
            identity,
            device_id,
            seq,
            epoch: 0,
            phase: Phase::New,
            limits: None,
            echo: EchoGuard::default(),
            replay: ReplayGuard::new(device_id, DEFAULT_RETENTION_MS),
            peers: 0,
            pinned_auth: None,
        }
    }

    /// The per device counter, for persisting.
    #[must_use]
    pub const fn seq(&self) -> u64 {
        self.seq
    }

    /// Connections in the room as last reported. Never a device count.
    #[must_use]
    pub const fn peers(&self) -> u32 {
        self.peers
    }

    /// The limits the relay announced, once the handshake has got that far.
    #[must_use]
    pub const fn limits(&self) -> Option<Limits> {
        self.limits
    }

    /// Whether the handshake completed.
    #[must_use]
    pub fn is_ready(&self) -> bool {
        self.phase == Phase::Ready
    }

    /// Forces the nonce and timestamp used in `auth`.
    ///
    /// This exists so that the frozen test vectors can be reproduced exactly. Production code must
    /// never call it: a repeated client nonce weakens the handshake's freshness.
    pub const fn pin_auth_inputs(&mut self, nonce_c: [u8; 16], client_time_ms: u64) {
        self.pinned_auth = Some((nonce_c, client_time_ms));
    }

    /// Builds the `hello` frame, which must be the first message on every connection.
    ///
    /// # Errors
    ///
    /// Returns an error only if serialization fails.
    pub fn hello_frame(&mut self) -> Result<String> {
        self.phase = Phase::HelloSent;
        Message::Hello(Hello {
            v: PROTOCOL_VERSION,
            suites: vec![asli_crypto::SUITE.to_owned()],
            enc: vec!["json".to_owned()],
            client: Some(CLIENT_ID.to_owned()),
        })
        .to_frame()
    }

    /// Builds a `fetch_last` frame.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfOrder`] if the handshake has not completed.
    pub fn fetch_last_frame(&self) -> Result<String> {
        if self.phase != Phase::Ready {
            return Err(Error::OutOfOrder("fetch_last before auth_ok"));
        }
        Message::FetchLast(FetchLast {
            v: PROTOCOL_VERSION,
        })
        .to_frame()
    }

    /// Handles a frame from the relay.
    ///
    /// # Errors
    ///
    /// Returns an error for a malformed frame, an incompatible relay, or a message that arrived in
    /// a state that cannot accept it. A clip that fails to decrypt or fails validation is **not**
    /// an error: it is discarded silently and produces no action, because a verification failure
    /// means either corruption or an active attack and neither warrants a reply that would confirm
    /// anything to the relay.
    pub fn handle_frame(&mut self, frame: &str, now_ms: u64) -> Result<Vec<Action>> {
        let message = Message::parse(frame)?;
        if message.version() != PROTOCOL_VERSION {
            return Err(Error::Unsupported("protocol version"));
        }

        match message {
            Message::Challenge(challenge) => self.on_challenge(&challenge, now_ms),
            Message::AuthOk(ok) => {
                self.phase = Phase::Ready;
                self.peers = ok.peers;
                Ok(vec![Action::Authenticated {
                    peers: ok.peers,
                    has_retained: ok.has_retained,
                    stored_at: ok.stored_at,
                }])
            }
            Message::AuthFail(fail) => Ok(vec![Action::AuthFailed(fail.code)]),
            Message::Clip(clip) => self.on_clip(&clip, now_ms),
            Message::Presence(presence) => {
                self.peers = presence.peers;
                Ok(vec![Action::Presence {
                    peers: presence.peers,
                }])
            }
            Message::Ping(ping) => Ok(vec![Action::Send(
                Message::Pong(Pong {
                    v: PROTOCOL_VERSION,
                    t: ping.t,
                })
                .to_frame()?,
            )]),
            Message::Pong(_) => Ok(Vec::new()),
            Message::Error(err) => Ok(vec![Action::RelayError {
                code: err.code,
                retry_after_ms: err.retry_after_ms,
            }]),
            // These are client to server only. A relay sending one is broken or hostile.
            Message::Hello(_) | Message::Auth(_) | Message::FetchLast(_) => {
                Err(Error::OutOfOrder("relay sent a client only message"))
            }
        }
    }

    fn on_challenge(
        &mut self,
        challenge: &envelope::Challenge,
        now_ms: u64,
    ) -> Result<Vec<Action>> {
        if self.phase != Phase::HelloSent {
            return Err(Error::OutOfOrder("challenge outside the handshake"));
        }
        if challenge.suite != asli_crypto::SUITE {
            return Err(Error::Unsupported("cryptographic suite"));
        }
        if challenge.enc != "json" {
            return Err(Error::Unsupported("envelope encoding"));
        }

        let nonce_s: [u8; 32] = envelope::fixed("nonce_s", &challenge.nonce_s)?;
        self.limits = Some(challenge.limits);

        let (nonce_c, client_time_ms) = match self.pinned_auth {
            Some(pinned) => pinned,
            None => (asli_crypto::random::bytes::<16>()?, now_ms),
        };

        let sig = asli_crypto::auth::sign_auth(&self.identity, &nonce_s, &nonce_c, client_time_ms);

        self.phase = Phase::Authenticating;
        Ok(vec![Action::Send(
            Message::Auth(Auth {
                v: PROTOCOL_VERSION,
                room: self.identity.room_id(),
                pub_key: self.identity.public_key().to_vec(),
                nonce_c: nonce_c.to_vec(),
                client_time_ms,
                sig: sig.to_vec(),
            })
            .to_frame()?,
        )])
    }

    fn on_clip(&mut self, clip: &Clip, now_ms: u64) -> Result<Vec<Action>> {
        if self.phase != Phase::Ready {
            return Err(Error::OutOfOrder("clip before auth_ok"));
        }

        // Structural checks first. A wrong length here is a protocol error, not a discard, because
        // a well behaved relay never forwards one.
        let msg_id: [u8; MSG_ID_LEN] = envelope::fixed("msg_id", &clip.msg_id)?;
        let nonce: [u8; NONCE_LEN] = envelope::fixed("n", &clip.n)?;
        if clip.ct.len() <= TAG_LEN {
            return Err(Error::FieldLength {
                field: "ct",
                expected: TAG_LEN + 1,
                got: clip.ct.len(),
            });
        }

        // Everything from here is a silent discard. The relay learns nothing from our silence.
        if clip.room != self.identity.room_id() {
            return Ok(Vec::new());
        }
        if !self.epoch_is_acceptable(clip.epoch) {
            return Ok(Vec::new());
        }

        let room_id_bytes: [u8; ROOM_ID_LEN] = self.identity.room_id_bytes();
        let Ok(inner) = clip::open(
            &self.identity.enc_key(clip.epoch),
            clip.epoch,
            &room_id_bytes,
            &msg_id,
            &nonce,
            &clip.ct,
        ) else {
            return Ok(Vec::new());
        };

        let retained = clip.is_retained();
        let verdict = self.replay.check(
            &Incoming {
                msg_id,
                device_id: inner.device_id,
                seq: inner.seq,
                ts_ms: inner.ts_ms,
                retained,
            },
            now_ms,
        );
        if verdict != Verdict::Accept {
            return Ok(Vec::new());
        }

        if inner.content_type != ContentType::Text {
            // Images are specified but not produced by any v1 client.
            return Ok(Vec::new());
        }
        let Ok(text) = String::from_utf8(inner.content) else {
            return Ok(Vec::new());
        };

        // Record before the caller writes, never after. The clipboard change notification can
        // arrive before the write call returns, and a hash recorded afterwards loses that race.
        self.echo.remember(asli_core::hash(text.as_bytes()), now_ms);

        Ok(vec![Action::Clip {
            text,
            ts_ms: inner.ts_ms,
            retained,
        }])
    }

    /// During a rotation window a peer may be one epoch ahead or behind.
    const fn epoch_is_acceptable(&self, epoch: u32) -> bool {
        epoch >= self.epoch.saturating_sub(1) && epoch <= self.epoch.saturating_add(1)
    }

    /// Turns a local clipboard change into a frame to send.
    ///
    /// Returns `None` when there is nothing to send: the content is empty, or it is the echo of a
    /// clip this session just wrote to the clipboard.
    ///
    /// # Errors
    ///
    /// Returns [`Error::ContentTooLarge`] when the content exceeds the relay's announced limit,
    /// so the caller can tell the user why the clip was skipped instead of being disconnected for
    /// it. Returns [`Error::OutOfOrder`] before the handshake completes.
    pub fn observe_local(&mut self, text: &str, now_ms: u64) -> Result<Option<String>> {
        if self.phase != Phase::Ready {
            return Err(Error::OutOfOrder("clip before auth_ok"));
        }

        let normalized = asli_core::normalize(text);
        if !asli_core::is_syncable(&normalized) {
            return Ok(None);
        }

        let hash = asli_core::hash(normalized.as_bytes());
        if self.echo.take_echo(hash, now_ms) {
            // We wrote this ourselves a moment ago. Sending it back is how a loop starts.
            return Ok(None);
        }

        if let Some(limits) = self.limits {
            let limit = usize::try_from(limits.max_content_bytes).unwrap_or(usize::MAX);
            if normalized.len() > limit {
                return Err(Error::ContentTooLarge {
                    got: normalized.len(),
                    limit,
                });
            }
        }

        // Deliberately NOT remembered here. The echo guard exists to swallow the clipboard change
        // event caused by us writing a received clip, and that seeding happens on the receive path
        // just before the write. A local copy causes no self inflicted event, so recording it here
        // would only swallow the user's next identical copy, which PLAN section 13 requires to
        // sync. The relay echoing our own clip back is layer one's job: the device id check drops
        // it regardless of any hash.
        self.seq = self.seq.saturating_add(1);

        let msg_id: [u8; MSG_ID_LEN] = asli_crypto::random::bytes()?;
        let inner = Inner {
            content_type: ContentType::Text,
            device_id: self.device_id,
            seq: self.seq,
            ts_ms: now_ms,
            content: normalized.as_bytes().to_vec(),
        };

        let sealed = clip::seal(
            &self.identity.enc_key(self.epoch),
            self.epoch,
            &self.identity.room_id_bytes(),
            &msg_id,
            &inner,
        )?;

        Ok(Some(
            Message::Clip(Clip {
                v: PROTOCOL_VERSION,
                room: self.identity.room_id(),
                epoch: self.epoch,
                msg_id: msg_id.to_vec(),
                n: sealed.nonce.to_vec(),
                ct: sealed.ciphertext,
                retained: None,
                stored_at: None,
            })
            .to_frame()?,
        ))
    }
}

/// A duplex channel that carries protocol frames.
///
/// The driver above needs no transport at all, which is what makes it testable. This trait exists
/// so that the same pump loop can run over a real socket or over an in memory queue.
pub trait Transport {
    /// Sends one frame.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Transport`] if the frame could not be queued.
    fn send_text(&mut self, frame: &str) -> Result<()>;

    /// Takes the next frame, or `None` if none is waiting.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Transport`] if the connection failed.
    fn recv_text(&mut self) -> Result<Option<String>>;
}

/// Feeds every waiting frame through the session, sending anything it asks to send.
///
/// Returns the actions that are not simple sends, so a caller can act on clips and status changes
/// without re-implementing the plumbing.
///
/// # Errors
///
/// Propagates transport and protocol errors.
pub fn pump<T: Transport>(
    session: &mut Session,
    transport: &mut T,
    now_ms: u64,
) -> Result<Vec<Action>> {
    let mut out = Vec::new();
    while let Some(frame) = transport.recv_text()? {
        for action in session.handle_frame(&frame, now_ms)? {
            match action {
                Action::Send(frame) => transport.send_text(&frame)?,
                other => out.push(other),
            }
        }
    }
    Ok(out)
}

/// An in memory transport for tests.
#[derive(Debug, Default)]
pub struct FakeTransport {
    /// Frames the session sent, oldest first.
    pub sent: Vec<String>,
    /// Frames waiting to be delivered to the session, oldest first.
    pub inbox: std::collections::VecDeque<String>,
}

impl FakeTransport {
    /// Queues a frame as if the relay had sent it.
    pub fn deliver(&mut self, frame: impl Into<String>) {
        self.inbox.push_back(frame.into());
    }

    /// The most recently sent frame, parsed.
    ///
    /// # Panics
    ///
    /// Panics if nothing was sent or the frame does not parse, which in a test is the point.
    #[must_use]
    pub fn last_sent(&self) -> Message {
        let frame = self.sent.last().expect("a frame was sent");
        Message::parse(frame).expect("sent frame parses")
    }
}

impl Transport for FakeTransport {
    fn send_text(&mut self, frame: &str) -> Result<()> {
        self.sent.push(frame.to_owned());
        Ok(())
    }

    fn recv_text(&mut self) -> Result<Option<String>> {
        Ok(self.inbox.pop_front())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECRET: [u8; 32] = [42u8; 32];
    const DEVICE_A: [u8; 16] = [0xaa; 16];
    const DEVICE_B: [u8; 16] = [0xbb; 16];
    const NOW: u64 = 1_789_459_200_000;

    fn limits_json() -> String {
        r#"{"max_frame_bytes":1048576,"max_content_bytes":716800,"retain_max_bytes":65536,"msgs_per_sec":2,"room_bytes_per_day":52428800}"#.to_owned()
    }

    fn challenge_frame(nonce_s: &[u8; 32]) -> String {
        format!(
            r#"{{"v":1,"type":"challenge","suite":"asli-v1","enc":"json","nonce_s":"{}","server_time_ms":{NOW},"limits":{}}}"#,
            envelope::encode_b64(nonce_s),
            limits_json()
        )
    }

    fn auth_ok_frame() -> String {
        r#"{"v":1,"type":"auth_ok","conn_id":"c_1","peers":2,"has_retained":false}"#.to_owned()
    }

    /// A session that has completed the handshake against a fake relay.
    fn ready_session(device_id: [u8; 16]) -> (Session, FakeTransport) {
        let mut session = Session::new(Identity::from_secret(&SECRET), device_id, 0);
        let mut transport = FakeTransport::default();

        let hello = session.hello_frame().expect("hello");
        transport.send_text(&hello).expect("send");
        transport.deliver(challenge_frame(&[9u8; 32]));
        transport.deliver(auth_ok_frame());

        let actions = pump(&mut session, &mut transport, NOW).expect("handshake");
        assert!(matches!(actions[0], Action::Authenticated { .. }));
        assert!(session.is_ready());
        (session, transport)
    }

    #[test]
    fn the_handshake_sends_hello_then_auth() {
        let (session, transport) = ready_session(DEVICE_A);
        assert_eq!(transport.sent.len(), 2, "hello and auth");

        let Message::Hello(hello) = Message::parse(&transport.sent[0]).unwrap() else {
            panic!("first frame must be hello")
        };
        assert_eq!(hello.suites, ["asli-v1"]);
        assert_eq!(hello.enc, ["json"]);

        let Message::Auth(auth) = Message::parse(&transport.sent[1]).unwrap() else {
            panic!("second frame must be auth")
        };
        assert_eq!(auth.room, session.identity.room_id());
        assert_eq!(auth.pub_key.len(), 32);
        assert_eq!(auth.nonce_c.len(), 16);
        assert_eq!(auth.sig.len(), 64);
    }

    #[test]
    fn the_relays_limits_are_recorded() {
        let (session, _) = ready_session(DEVICE_A);
        assert_eq!(session.limits().expect("limits").max_content_bytes, 716_800);
    }

    #[test]
    fn a_clip_round_trips_between_two_devices() {
        let (mut a, _) = ready_session(DEVICE_A);
        let (mut b, _) = ready_session(DEVICE_B);

        let frame = a
            .observe_local("copied on device a", NOW)
            .expect("seals")
            .expect("something to send");

        let actions = b.handle_frame(&frame, NOW).expect("opens");
        assert_eq!(
            actions,
            vec![Action::Clip {
                text: "copied on device a".to_owned(),
                ts_ms: NOW,
                retained: false,
            }]
        );
    }

    #[test]
    fn our_own_clip_coming_back_is_dropped() {
        // The relay excludes the sender, but a malicious one might not, and a reconnecting device
        // fetching the retained clip can legitimately receive its own message.
        let (mut a, _) = ready_session(DEVICE_A);
        let frame = a.observe_local("mine", NOW).unwrap().unwrap();
        assert_eq!(a.handle_frame(&frame, NOW).unwrap(), Vec::new());
    }

    #[test]
    fn a_replayed_message_id_is_dropped() {
        let (mut a, _) = ready_session(DEVICE_A);
        let (mut b, _) = ready_session(DEVICE_B);
        let frame = a.observe_local("once", NOW).unwrap().unwrap();

        assert_eq!(b.handle_frame(&frame, NOW).unwrap().len(), 1);
        assert_eq!(b.handle_frame(&frame, NOW).unwrap(), Vec::new(), "replay");
    }

    #[test]
    fn a_rolled_back_sequence_number_is_dropped() {
        let (mut a, _) = ready_session(DEVICE_A);
        let (mut b, _) = ready_session(DEVICE_B);

        let first = a.observe_local("one", NOW).unwrap().unwrap();
        let second = a.observe_local("two", NOW).unwrap().unwrap();
        assert_eq!(b.handle_frame(&second, NOW).unwrap().len(), 1);
        // The relay now replays the earlier message, which carries a lower seq.
        assert_eq!(b.handle_frame(&first, NOW).unwrap(), Vec::new());
    }

    #[test]
    fn a_stale_live_clip_is_dropped() {
        let (mut a, _) = ready_session(DEVICE_A);
        let (mut b, _) = ready_session(DEVICE_B);
        let frame = a.observe_local("old news", NOW).unwrap().unwrap();
        // Two minutes and one second later.
        assert_eq!(b.handle_frame(&frame, NOW + 120_001).unwrap(), Vec::new());
    }

    #[test]
    fn a_retained_clip_is_accepted_late_and_marked() {
        let (mut a, _) = ready_session(DEVICE_A);
        let (mut b, _) = ready_session(DEVICE_B);
        let frame = a.observe_local("from this morning", NOW).unwrap().unwrap();

        // The relay adds the retained marker when serving a stored clip.
        let mut value: serde_json::Value = serde_json::from_str(&frame).unwrap();
        value["retained"] = serde_json::Value::Bool(true);
        value["stored_at"] = serde_json::json!(NOW);
        let retained_frame = value.to_string();

        let actions = b
            .handle_frame(&retained_frame, NOW + 60 * 60 * 1000)
            .expect("accepts a retained clip outside the live window");
        assert_eq!(
            actions,
            vec![Action::Clip {
                text: "from this morning".to_owned(),
                ts_ms: NOW,
                retained: true,
            }]
        );
    }

    #[test]
    fn a_tampered_ciphertext_is_discarded_silently() {
        let (mut a, _) = ready_session(DEVICE_A);
        let (mut b, _) = ready_session(DEVICE_B);
        let frame = a.observe_local("authentic", NOW).unwrap().unwrap();

        let mut value: serde_json::Value = serde_json::from_str(&frame).unwrap();
        let ct = value["ct"].as_str().unwrap().to_owned();
        let mut bytes = data_encoding::BASE64.decode(ct.as_bytes()).unwrap();
        bytes[0] ^= 0x01;
        value["ct"] = serde_json::Value::String(envelope::encode_b64(&bytes));

        // Not an error: a verification failure gets silence, never a reply that would tell the
        // relay anything.
        assert_eq!(b.handle_frame(&value.to_string(), NOW).unwrap(), Vec::new());
    }

    #[test]
    fn a_clip_for_another_room_is_discarded() {
        let (mut a, _) = ready_session(DEVICE_A);
        let (mut b, _) = ready_session(DEVICE_B);
        let frame = a.observe_local("wrong room", NOW).unwrap().unwrap();

        let mut value: serde_json::Value = serde_json::from_str(&frame).unwrap();
        value["room"] = serde_json::json!("00000000000000000000000000");
        assert_eq!(b.handle_frame(&value.to_string(), NOW).unwrap(), Vec::new());
    }

    #[test]
    fn our_own_write_does_not_bounce_back_out() {
        let (mut a, _) = ready_session(DEVICE_A);
        let (mut b, _) = ready_session(DEVICE_B);

        let frame = a.observe_local("shared text", NOW).unwrap().unwrap();
        let actions = b.handle_frame(&frame, NOW).unwrap();
        let Action::Clip { text, .. } = &actions[0] else {
            panic!("expected a clip")
        };

        // B writes it to the clipboard, and its watcher fires with the same content.
        assert_eq!(
            b.observe_local(text, NOW + 10).unwrap(),
            None,
            "the echo of our own write must not be resent"
        );
    }

    #[test]
    fn the_same_text_copied_again_on_purpose_still_syncs() {
        let (mut a, _) = ready_session(DEVICE_A);
        assert!(a.observe_local("twice", NOW).unwrap().is_some());

        // Inside the echo guard's time to live, which is the case that matters. Using a gap longer
        // than the TTL would pass even with the send path seeding the guard, and would have hidden
        // exactly the bug this asserts against: copying the same text twice in a row is a normal
        // thing people do, and it must reach the other machine both times.
        assert!(
            a.observe_local("twice", NOW + 50).unwrap().is_some(),
            "an immediate deliberate re-copy must still be sent"
        );
        assert!(a.observe_local("twice", NOW + 20_000).unwrap().is_some());
    }

    #[test]
    fn empty_and_whitespace_only_content_is_not_sent() {
        let (mut a, _) = ready_session(DEVICE_A);
        assert_eq!(a.observe_local("", NOW).unwrap(), None);
        assert_eq!(a.observe_local("   \n\t ", NOW).unwrap(), None);
    }

    #[test]
    fn crlf_is_normalized_before_sealing() {
        let (mut a, _) = ready_session(DEVICE_A);
        let (mut b, _) = ready_session(DEVICE_B);
        let frame = a
            .observe_local("line one\r\nline two\r\n", NOW)
            .unwrap()
            .unwrap();
        let actions = b.handle_frame(&frame, NOW).unwrap();
        assert_eq!(
            actions,
            vec![Action::Clip {
                text: "line one\nline two\n".to_owned(),
                ts_ms: NOW,
                retained: false,
            }]
        );
    }

    #[test]
    fn oversize_content_is_refused_locally_with_the_limit() {
        let (mut a, _) = ready_session(DEVICE_A);
        let huge = "x".repeat(716_801);
        assert_eq!(
            a.observe_local(&huge, NOW),
            Err(Error::ContentTooLarge {
                got: 716_801,
                limit: 716_800
            }),
            "better to say why than to be disconnected for it"
        );
    }

    #[test]
    fn the_sequence_number_advances_per_clip() {
        let (mut a, _) = ready_session(DEVICE_A);
        assert_eq!(a.seq(), 0);
        a.observe_local("one", NOW).unwrap();
        a.observe_local("two", NOW).unwrap();
        assert_eq!(a.seq(), 2);
    }

    #[test]
    fn clips_are_refused_before_the_handshake_completes() {
        let mut session = Session::new(Identity::from_secret(&SECRET), DEVICE_A, 0);
        assert!(matches!(
            session.observe_local("too early", NOW),
            Err(Error::OutOfOrder(_))
        ));
        assert!(matches!(
            session.fetch_last_frame(),
            Err(Error::OutOfOrder(_))
        ));
    }

    #[test]
    fn a_ping_is_answered_with_a_pong_that_echoes_t() {
        let (mut session, _) = ready_session(DEVICE_A);
        let actions = session
            .handle_frame(r#"{"v":1,"type":"ping","t":1234}"#, NOW)
            .unwrap();
        let Action::Send(frame) = &actions[0] else {
            panic!("expected a send")
        };
        let Message::Pong(pong) = Message::parse(frame).unwrap() else {
            panic!("expected a pong")
        };
        assert_eq!(pong.t, Some(1234));
    }

    #[test]
    fn presence_updates_the_peer_count() {
        let (mut session, _) = ready_session(DEVICE_A);
        let actions = session
            .handle_frame(r#"{"v":1,"type":"presence","peers":3}"#, NOW)
            .unwrap();
        assert_eq!(actions, vec![Action::Presence { peers: 3 }]);
        assert_eq!(session.peers(), 3);
    }

    #[test]
    fn a_relay_error_is_surfaced_with_its_retry_floor() {
        let (mut session, _) = ready_session(DEVICE_A);
        let actions = session
            .handle_frame(
                r#"{"v":1,"type":"error","code":"RATE_LIMITED","retry_after_ms":5000}"#,
                NOW,
            )
            .unwrap();
        assert_eq!(
            actions,
            vec![Action::RelayError {
                code: ErrorCode::RateLimited,
                retry_after_ms: Some(5000)
            }]
        );
    }

    #[test]
    fn auth_failure_is_reported_rather_than_retried_here() {
        let mut session = Session::new(Identity::from_secret(&SECRET), DEVICE_A, 0);
        session.hello_frame().unwrap();
        let actions = session
            .handle_frame(r#"{"v":1,"type":"auth_fail","code":"BAD_SIGNATURE"}"#, NOW)
            .unwrap();
        assert_eq!(
            actions,
            vec![Action::AuthFailed(AuthFailCode::BadSignature)]
        );
        assert!(!session.is_ready());
    }

    #[test]
    fn an_incompatible_relay_is_rejected() {
        let mut session = Session::new(Identity::from_secret(&SECRET), DEVICE_A, 0);
        session.hello_frame().unwrap();

        let wrong_suite = format!(
            r#"{{"v":1,"type":"challenge","suite":"asli-v2","enc":"json","nonce_s":"{}","server_time_ms":1,"limits":{}}}"#,
            envelope::encode_b64(&[0u8; 32]),
            limits_json()
        );
        assert_eq!(
            session.handle_frame(&wrong_suite, NOW),
            Err(Error::Unsupported("cryptographic suite"))
        );
    }

    #[test]
    fn a_relay_speaking_a_future_version_is_rejected() {
        let mut session = Session::new(Identity::from_secret(&SECRET), DEVICE_A, 0);
        session.hello_frame().unwrap();
        assert_eq!(
            session.handle_frame(r#"{"v":2,"type":"presence","peers":1}"#, NOW),
            Err(Error::Unsupported("protocol version"))
        );
    }

    #[test]
    fn a_relay_sending_a_client_only_message_is_an_error() {
        let (mut session, _) = ready_session(DEVICE_A);
        assert!(matches!(
            session.handle_frame(r#"{"v":1,"type":"fetch_last"}"#, NOW),
            Err(Error::OutOfOrder(_))
        ));
    }

    #[test]
    fn a_clip_with_a_wrong_length_field_is_a_protocol_error() {
        let (mut session, _) = ready_session(DEVICE_A);
        let frame = format!(
            r#"{{"v":1,"type":"clip","room":"{}","epoch":0,"msg_id":"{}","n":"{}","ct":"{}"}}"#,
            session.identity.room_id(),
            envelope::encode_b64(&[0u8; 15]),
            envelope::encode_b64(&[0u8; 24]),
            envelope::encode_b64(&[0u8; 40])
        );
        assert!(matches!(
            session.handle_frame(&frame, NOW),
            Err(Error::FieldLength {
                field: "msg_id",
                ..
            })
        ));
    }

    #[test]
    fn fetch_last_is_available_once_ready() {
        let (session, _) = ready_session(DEVICE_A);
        let frame = session.fetch_last_frame().expect("frame");
        assert!(matches!(
            Message::parse(&frame).unwrap(),
            Message::FetchLast(_)
        ));
    }

    #[test]
    fn a_neighbouring_epoch_is_accepted_during_rotation() {
        let (session, _) = ready_session(DEVICE_A);
        assert!(session.epoch_is_acceptable(0));
        assert!(session.epoch_is_acceptable(1));
        assert!(!session.epoch_is_acceptable(2));
    }
}
