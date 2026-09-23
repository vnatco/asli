//! The protocol driver.
//!
//! This is sans I/O on purpose: it consumes frames and produces frames, and knows nothing about
//! sockets, threads or timers. Every rule in `docs/PROTOCOL.md` that can be checked without a
//! network is checked here and tested without one, which is what makes the interesting cases
//! (replay, rollback, a stale retained clip, an oversize clip) cheap to cover.
//!
//! The caller supplies the current time, so tests are deterministic.

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

use asli_core::{EchoGuard, Incoming, ReplayGuard, ReplayMemory, Verdict};
use asli_crypto::announce;
use asli_crypto::chunk::{self, Assembly, ChunkPos};
use asli_crypto::clip::{self, ContentType, Inner, DEVICE_ID_LEN, MSG_ID_LEN, NONCE_LEN, TAG_LEN};
use asli_crypto::identity::ROOM_ID_LEN;
use asli_crypto::Identity;

use crate::envelope::{
    self, Announce, Auth, AuthFailCode, Clip, ClipChunk, ErrorCode, FetchLast, Hello, Limits,
    Message, Pong, PROTOCOL_VERSION,
};
use crate::error::{Error, Result};

/// Default retention window to allow for a retained clip, until a relay announces its own.
pub const DEFAULT_RETENTION_MS: u64 = 24 * 60 * 60 * 1000;

/// Client identifier sent in `hello`. Deliberately carries no hostname or username.
pub const CLIENT_ID: &str = concat!("asli/", env!("CARGO_PKG_VERSION"));

/// What this device says about itself to the others in the room.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceInfo {
    /// What the person calls this device.
    pub name: String,
    /// The operating system, as a short human readable label.
    pub os: String,
}

/// What another device in the room said about itself, decrypted and validated.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerInfo {
    /// The device, the same identifier its clips carry.
    pub device_id: [u8; DEVICE_ID_LEN],
    /// What the person calls it. At most 64 bytes.
    pub name: String,
    /// Its operating system. At most 64 bytes.
    pub os: String,
    /// When it announced itself, by its own clock.
    pub ts_ms: u64,
}

/// How many announcement message ids are remembered for dedup.
const ANNOUNCE_SEEN_CAPACITY: usize = 64;

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
        /// The device that copied it.
        device_id: [u8; DEVICE_ID_LEN],
    },
    /// A chunked image arrived, reassembled and validated.
    ///
    /// Separate from [`Action::Clip`] because an image is not written to the clipboard by the same
    /// code path as text, and because a caller that does not support images should be able to
    /// ignore this variant without accidentally discarding text.
    Image {
        /// Normalized PNG bytes.
        png: Vec<u8>,
        /// Capture time from inside the ciphertext.
        ts_ms: u64,
        /// The device that copied it.
        device_id: [u8; DEVICE_ID_LEN],
    },
    /// Another device announced its name and operating system.
    Peer(PeerInfo),
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
    /// A clip or image arrived and was discarded. Nothing is sent back: the relay learns nothing
    /// from our silence. This exists so the device itself can say why, because a discard that
    /// leaves no trace is indistinguishable from a clip that was never sent.
    Dropped {
        /// Why, as a short fixed label. Never content.
        reason: &'static str,
        /// Whether it was the relay's stored clip rather than a live one, which is what a device
        /// that asked for the stored clip needs to know to report that nothing came of it.
        retained: bool,
    },
    /// This device's clock disagrees with the relay's by more than [`CLOCK_SKEW_WARN_MS`].
    ///
    /// Clips are judged by their capture time, so a device whose clock is off by more than the
    /// replay window has every clip it sends dropped by the others, and drops every clip they
    /// send it, with nothing failing anywhere.
    ClockSkew {
        /// The relay's clock minus ours, in milliseconds.
        skew_ms: i64,
    },
}

/// How far this device's clock may drift from the relay's before it is reported.
///
/// Half the freshness window, which accepts clips up to a day old or a day ahead. Anything short of
/// this syncs normally, a time zone mistake included, so warning earlier would only be noise. At
/// this point it is worth fixing before it reaches the limit and clips start being dropped.
pub const CLOCK_SKEW_WARN_MS: i64 = 12 * 60 * 60 * 1000;

/// A discard, reported to this device only.
fn dropped(reason: &'static str, retained: bool) -> Vec<Action> {
    vec![Action::Dropped { reason, retained }]
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
    /// See [`Session::share_replay_memory`].
    replay_sink: Option<Arc<Mutex<ReplayMemory>>>,
    /// Whether arriving clips are remembered so the clipboard change they cause is not sent back.
    /// See [`Session::leave_echoes_to_caller`].
    echo_guard: bool,
    /// A local copy sent on a connection that died before the relay confirmed receiving it.
    /// Sent again first thing on the next connection.
    resend: Option<crate::client::LocalEvent>,
    peers: u32,
    pinned_auth: Option<([u8; 16], u64)>,
    /// The chunked message currently being reassembled, if any.
    ///
    /// Exactly one at a time. A sender that interleaves two chunked messages on one connection is
    /// outside the protocol, and allowing it would mean unbounded concurrent assemblies, which is
    /// the memory exhaustion this cap exists to prevent.
    assembly: Option<Assembly>,
    /// What this device announces. Nothing is announced until it is set.
    device_info: Option<DeviceInfo>,
    /// Whether the relay on this connection is known not to forward announcements.
    ///
    /// A relay from before announcements answers one with `UNKNOWN_TYPE` and keeps the connection,
    /// so the first such answer settles it, and nothing more is announced until the next
    /// connection, which may be to a relay that has since been updated.
    announce_refused: bool,
    /// Whether an announcement went out on this connection, which is what makes an
    /// `UNKNOWN_TYPE` answer mean the relay does not know announcements.
    announced: bool,
    /// Message ids of recent announcements, so a replayed one is not reported twice.
    announce_seen: VecDeque<[u8; MSG_ID_LEN]>,
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
            assembly: None,
            replay_sink: None,
            echo_guard: true,
            resend: None,
            device_info: None,
            announce_refused: false,
            announced: false,
            announce_seen: VecDeque::new(),
        }
    }

    /// Sets what this device announces, shortening an over long name or system to fit.
    ///
    /// Takes effect at the next announcement. To announce a change at once on a live connection,
    /// send [`crate::client::LocalEvent::DeviceInfo`] instead, which calls this and then announces.
    pub fn set_device_info(&mut self, mut info: DeviceInfo) {
        let name_len = announce::truncate_utf8(&info.name, announce::MAX_FIELD_BYTES).len();
        info.name.truncate(name_len);
        let os_len = announce::truncate_utf8(&info.os, announce::MAX_FIELD_BYTES).len();
        info.os.truncate(os_len);
        self.device_info = Some(info);
    }

    /// Builds an announcement of this device, or nothing when there is nothing to announce.
    ///
    /// Nothing before the handshake completes, nothing while no device information is set, and
    /// nothing to a relay that already answered one with `UNKNOWN_TYPE` on this connection.
    ///
    /// # Errors
    ///
    /// Returns an error only if randomness or sealing fails.
    pub fn announce_frame(&mut self, now_ms: u64) -> Result<Option<String>> {
        if self.phase != Phase::Ready || self.announce_refused {
            return Ok(None);
        }
        let Some(info) = &self.device_info else {
            return Ok(None);
        };

        let msg_id: [u8; MSG_ID_LEN] = asli_crypto::random::bytes()?;
        let sealed = announce::seal(
            &self.identity.enc_key(self.epoch),
            self.epoch,
            &self.identity.room_id_bytes(),
            &msg_id,
            &announce::Announce {
                device_id: self.device_id,
                ts_ms: now_ms,
                name: info.name.clone(),
                os: info.os.clone(),
            },
        )?;
        self.announced = true;

        Ok(Some(
            Message::Announce(Announce {
                v: PROTOCOL_VERSION,
                room: self.identity.room_id(),
                epoch: self.epoch,
                msg_id: msg_id.to_vec(),
                n: sealed.nonce.to_vec(),
                ct: sealed.ciphertext,
            })
            .to_frame()?,
        ))
    }

    /// Appends an announcement to `actions`, when there is one to make.
    fn push_announce(&mut self, actions: &mut Vec<Action>, now_ms: u64) -> Result<()> {
        if let Some(frame) = self.announce_frame(now_ms)? {
            actions.push(Action::Send(frame));
        }
        Ok(())
    }

    /// Keeps a copy the relay never confirmed, for the next connection to send.
    pub(crate) fn stash_resend(&mut self, event: crate::client::LocalEvent) {
        self.resend = Some(event);
    }

    /// The copy to send again, if the last connection lost one.
    pub(crate) fn take_resend(&mut self) -> Option<crate::client::LocalEvent> {
        self.resend.take()
    }

    /// For a caller that recognises its own clipboard writes before they reach this session.
    ///
    /// The application does, at the clipboard. The guard here then never sees the echo it is
    /// waiting for, so its entry lingers, and a person copying the same text again on purpose
    /// within its lifetime had that copy swallowed.
    pub const fn leave_echoes_to_caller(&mut self) {
        self.echo_guard = false;
    }

    /// Takes back what the replay guard learned in an earlier run, so a replay is refused from the
    /// first message rather than only after this session has seen the original.
    pub fn restore_replay(&mut self, memory: &ReplayMemory) {
        self.replay.restore(memory);
    }

    /// Where to publish what the replay guard learns, after every accepted clip, for saving.
    ///
    /// Shared rather than returned, because the session is borrowed by the transport for the whole
    /// life of a connection, and the caller has to be able to save while it runs.
    pub fn share_replay_memory(&mut self, sink: Arc<Mutex<ReplayMemory>>) {
        self.replay_sink = Some(sink);
    }

    fn publish_replay(&self) {
        if let Some(sink) = &self.replay_sink {
            if let Ok(mut memory) = sink.lock() {
                *memory = self.replay.memory();
            }
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
        // A new connection. Half an image from the one before can never be finished now.
        self.assembly = None;
        // And possibly a different relay, so whether it forwards announcements is found out again.
        self.announce_refused = false;
        self.announced = false;
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
                let mut actions = vec![Action::Authenticated {
                    peers: ok.peers,
                    has_retained: ok.has_retained,
                    stored_at: ok.stored_at,
                }];
                // Introduce ourselves to whoever is already in the room. They answer when the
                // presence count they see changes, which is how this device learns about them.
                self.push_announce(&mut actions, now_ms)?;
                Ok(actions)
            }
            Message::AuthFail(fail) => Ok(vec![Action::AuthFailed(fail.code)]),
            Message::Clip(clip) => self.on_clip(&clip, now_ms),
            Message::ClipBegin(c) | Message::ClipChunk(c) | Message::ClipEnd(c) => {
                self.on_chunk(&c, now_ms)
            }
            Message::Presence(presence) => {
                let changed = presence.peers != self.peers;
                self.peers = presence.peers;
                let mut actions = vec![Action::Presence {
                    peers: presence.peers,
                }];
                // Any change, up or down. Up, so a device that just joined learns about this one.
                // Down, so every device still here says so, and the one that left is the one that
                // stays silent.
                if changed {
                    self.push_announce(&mut actions, now_ms)?;
                }
                Ok(actions)
            }
            Message::Announce(announce) => self.on_announce(&announce, now_ms),
            Message::Ping(ping) => Ok(vec![Action::Send(
                Message::Pong(Pong {
                    v: PROTOCOL_VERSION,
                    t: ping.t,
                })
                .to_frame()?,
            )]),
            Message::Pong(_) => Ok(Vec::new()),
            // A relay from before announcements answers one this way and keeps the connection. The
            // only type this client ever sends that a conforming relay could fail to know is
            // `announce`, so this is that answer, and it is ours to absorb rather than a problem
            // to show anyone.
            Message::Error(err) if err.code == ErrorCode::UnknownType && self.announced => {
                self.announce_refused = true;
                Ok(Vec::new())
            }
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

        let mut actions = Vec::new();
        let skew_ms = i64::try_from(challenge.server_time_ms)
            .unwrap_or(i64::MAX)
            .saturating_sub(i64::try_from(now_ms).unwrap_or(i64::MAX));
        // A pinned time is a test fixture, not this device's clock, so there is nothing to report.
        if self.pinned_auth.is_none() && skew_ms.saturating_abs() > CLOCK_SKEW_WARN_MS {
            actions.push(Action::ClockSkew { skew_ms });
        }

        let sig = asli_crypto::auth::sign_auth(&self.identity, &nonce_s, &nonce_c, client_time_ms);

        self.phase = Phase::Authenticating;
        actions.push(Action::Send(
            Message::Auth(Auth {
                v: PROTOCOL_VERSION,
                room: self.identity.room_id(),
                pub_key: self.identity.public_key().to_vec(),
                nonce_c: nonce_c.to_vec(),
                client_time_ms,
                sig: sig.to_vec(),
            })
            .to_frame()?,
        ));
        Ok(actions)
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

        // Everything from here is a discard the relay never hears about. The device is told,
        // through Action::Dropped, so its log can say why.
        if clip.room != self.identity.room_id() {
            return Ok(dropped("wrong_room", clip.is_retained()));
        }
        if !self.epoch_is_acceptable(clip.epoch) {
            return Ok(dropped("unknown_epoch", clip.is_retained()));
        }

        let room_id_bytes: [u8; ROOM_ID_LEN] = self.identity.room_id_bytes();
        let Ok(mut inner) = clip::open(
            &self.identity.enc_key(clip.epoch),
            clip.epoch,
            &room_id_bytes,
            &msg_id,
            &nonce,
            &clip.ct,
        ) else {
            return Ok(dropped("could_not_decrypt", clip.is_retained()));
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
            return Ok(dropped(verdict.reason(), retained));
        }
        self.publish_replay();

        if inner.content_type != ContentType::Text {
            // Images are specified but not produced by any v1 client.
            return Ok(Vec::new());
        }
        let Ok(text) = String::from_utf8(inner.take_content()) else {
            return Ok(Vec::new());
        };

        // Record before the caller writes, never after. The clipboard change notification can
        // arrive before the write call returns, and a hash recorded afterwards loses that race.
        if self.echo_guard {
            self.echo.remember(asli_core::hash(text.as_bytes()), now_ms);
        }

        Ok(vec![Action::Clip {
            text,
            ts_ms: inner.ts_ms,
            retained,
            device_id: inner.device_id,
        }])
    }

    fn on_announce(&mut self, message: &Announce, now_ms: u64) -> Result<Vec<Action>> {
        if self.phase != Phase::Ready {
            return Err(Error::OutOfOrder("announce before auth_ok"));
        }

        // Structural checks are protocol errors, as for a clip.
        let msg_id: [u8; MSG_ID_LEN] = envelope::fixed("msg_id", &message.msg_id)?;
        let nonce: [u8; NONCE_LEN] = envelope::fixed("n", &message.n)?;
        if message.ct.len() <= TAG_LEN {
            return Err(Error::FieldLength {
                field: "ct",
                expected: TAG_LEN + 1,
                got: message.ct.len(),
            });
        }

        // Everything from here is a silent discard. An announcement only labels a device, so a
        // discarded one costs a name on a screen, and none of these is worth a log line.
        if message.room != self.identity.room_id() || !self.epoch_is_acceptable(message.epoch) {
            return Ok(Vec::new());
        }
        if self.announce_seen.contains(&msg_id) {
            return Ok(Vec::new());
        }

        let Ok(opened) = announce::open(
            &self.identity.enc_key(message.epoch),
            message.epoch,
            &self.identity.room_id_bytes(),
            &msg_id,
            &nonce,
            &message.ct,
        ) else {
            return Ok(Vec::new());
        };

        // Our own, sent back by a relay that should not have. Nothing to learn from it.
        if opened.device_id == self.device_id {
            return Ok(Vec::new());
        }
        // The same freshness window clips are held to, which is what bounds a replay.
        let too_old = now_ms.saturating_sub(opened.ts_ms) > asli_core::replay::DEFAULT_MAX_AGE_MS;
        let too_new =
            opened.ts_ms.saturating_sub(now_ms) > asli_core::replay::DEFAULT_FUTURE_SKEW_MS;
        if too_old || too_new {
            return Ok(Vec::new());
        }

        if self.announce_seen.len() >= ANNOUNCE_SEEN_CAPACITY {
            self.announce_seen.pop_front();
        }
        self.announce_seen.push_back(msg_id);

        Ok(vec![Action::Peer(PeerInfo {
            device_id: opened.device_id,
            name: opened.name,
            os: opened.os,
            ts_ms: opened.ts_ms,
        })])
    }

    fn on_chunk(&mut self, chunk: &ClipChunk, now_ms: u64) -> Result<Vec<Action>> {
        if self.phase != Phase::Ready {
            return Err(Error::OutOfOrder("chunk before auth_ok"));
        }

        // Structural checks are protocol errors, as for a whole clip: a well behaved relay never
        // forwards a malformed one.
        let msg_id: [u8; MSG_ID_LEN] = envelope::fixed("msg_id", &chunk.msg_id)?;
        let nonce: [u8; NONCE_LEN] = envelope::fixed("n", &chunk.n)?;
        if chunk.ct.len() <= TAG_LEN {
            return Err(Error::FieldLength {
                field: "ct",
                expected: TAG_LEN + 1,
                got: chunk.ct.len(),
            });
        }

        // Everything from here is a silent discard, matching on_clip.
        if chunk.room != self.identity.room_id() || !self.epoch_is_acceptable(chunk.epoch) {
            return Ok(Vec::new());
        }

        let final_chunk = chunk.idx.checked_add(1) == Some(chunk.chunk_count);
        let pos = ChunkPos {
            idx: chunk.idx,
            chunk_count: chunk.chunk_count,
            final_chunk,
        };

        // A fresh message id replaces any assembly in progress. Dropping the old one is correct:
        // the sender moved on, and holding a partial forever is how a memory leak starts.
        let starting_over = self
            .assembly
            .as_ref()
            .is_none_or(|existing| existing.msg_id() != &msg_id);
        if starting_over {
            if chunk.idx != 0 {
                // Joining a stream mid flight can never complete, so there is nothing to hold.
                return Ok(Vec::new());
            }
            let Ok(assembly) =
                Assembly::new(msg_id, chunk.epoch, chunk.chunk_count, self.assembly_cap())
            else {
                return Ok(Vec::new());
            };
            self.assembly = Some(assembly);
        }

        let Ok(piece) = chunk::open_chunk(
            &self.identity.enc_key(chunk.epoch),
            chunk.epoch,
            &self.identity.room_id_bytes(),
            &msg_id,
            &nonce,
            pos,
            &chunk.ct,
        ) else {
            // A chunk that does not verify at the position it claims means the stream has been
            // tampered with, so the whole assembly is abandoned rather than continued.
            self.assembly = None;
            return Ok(Vec::new());
        };

        let Some(assembly) = self.assembly.as_mut() else {
            return Ok(Vec::new());
        };
        if assembly
            .accept(&msg_id, chunk.epoch, chunk.idx, chunk.chunk_count, piece)
            .is_err()
        {
            self.assembly = None;
            return Ok(Vec::new());
        }

        if !final_chunk || !assembly.is_complete() {
            return Ok(Vec::new());
        }

        let Some(assembly) = self.assembly.take() else {
            return Ok(Vec::new());
        };
        let Ok(mut inner) = assembly.finish() else {
            return Ok(dropped("could_not_decrypt", false));
        };

        let verdict = self.replay.check(
            &Incoming {
                msg_id,
                device_id: inner.device_id,
                seq: inner.seq,
                ts_ms: inner.ts_ms,
                retained: false,
            },
            now_ms,
        );
        if verdict != Verdict::Accept {
            return Ok(dropped(verdict.reason(), false));
        }
        self.publish_replay();

        match inner.content_type {
            ContentType::ImagePng => Ok(vec![Action::Image {
                png: inner.take_content(),
                ts_ms: inner.ts_ms,
                device_id: inner.device_id,
            }]),
            // Text is never chunked in v1: accepting it here would mean two code paths for the
            // same content, and two paths to get loop prevention wrong on. ContentType is non
            // exhaustive, so a future type lands here too and is ignored until it is handled,
            // which is the safe direction.
            _ => Ok(Vec::new()),
        }
    }

    /// The cap on reassembled bytes, which is larger than the content cap.
    ///
    /// The content cap measures the payload a person copied. What arrives in chunks is the padded
    /// inner plaintext: a header plus padding to the next bucket. Applying the content cap to the
    /// padded total rejects any image within one bucket of the limit, which is a silent failure
    /// for exactly the largest images that still ought to work. The sender compares raw content
    /// against the content cap, so the two sides have to agree about what is being measured.
    fn assembly_cap(&self) -> usize {
        let content = self.max_content_bytes();
        // Padding rounds up to at most one 64 KiB bucket past the body, and the body adds the
        // inner header on top of the content.
        content
            .saturating_add(clip::INNER_HEADER_LEN)
            .saturating_add(64 * 1024)
    }

    /// The content cap this relay announced, or a conservative default before `challenge`.
    fn max_content_bytes(&self) -> usize {
        self.limits.map_or(8 * 1024 * 1024, |limits| {
            usize::try_from(limits.max_content_bytes).unwrap_or(usize::MAX)
        })
    }

    /// Seals a local image into a run of chunk frames, ready to send in order.
    ///
    /// Images are not written to the clipboard by this crate, so unlike [`Session::observe_local`]
    /// there is no echo guard interaction here: the caller owns that decision along with capture.
    ///
    /// # Errors
    ///
    /// Returns [`Error::ContentTooLarge`] when the image exceeds the relay's announced content
    /// limit, and [`Error::OutOfOrder`] before the handshake completes.
    pub fn observe_local_image(&mut self, png: &[u8], now_ms: u64) -> Result<Vec<String>> {
        if self.phase != Phase::Ready {
            return Err(Error::OutOfOrder("image before auth_ok"));
        }
        if png.is_empty() {
            return Ok(Vec::new());
        }

        let limit = self.max_content_bytes();
        if png.len() > limit {
            return Err(Error::ContentTooLarge {
                got: png.len(),
                limit,
            });
        }

        self.seq = self.seq.saturating_add(1);
        let msg_id: [u8; MSG_ID_LEN] = asli_crypto::random::bytes()?;
        let inner = Inner {
            content_type: ContentType::ImagePng,
            device_id: self.device_id,
            seq: self.seq,
            ts_ms: now_ms,
            content: png.to_vec(),
        };

        let sealed = chunk::seal_chunks(
            &self.identity.enc_key(self.epoch),
            self.epoch,
            &self.identity.room_id_bytes(),
            &msg_id,
            &inner,
            chunk::DEFAULT_CHUNK_BYTES,
        )?;

        let room = self.identity.room_id();
        let mut frames = Vec::with_capacity(sealed.len());
        for piece in sealed {
            let payload = ClipChunk {
                v: PROTOCOL_VERSION,
                room: room.clone(),
                epoch: self.epoch,
                msg_id: msg_id.to_vec(),
                idx: piece.idx,
                chunk_count: piece.chunk_count,
                n: piece.nonce.to_vec(),
                ct: piece.ciphertext,
            };
            let message = if piece.final_chunk {
                Message::ClipEnd(payload)
            } else if piece.idx == 0 {
                Message::ClipBegin(payload)
            } else {
                Message::ClipChunk(payload)
            };
            frames.push(message.to_frame()?);
        }
        Ok(frames)
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

    #[test]
    fn a_clock_far_from_the_relays_is_reported_and_a_close_one_is_not() {
        let hour = 60 * 60 * 1000;
        for (offset_ms, reported) in [
            (0i64, false),
            (4 * hour, false),
            (-13 * hour, true),
            (13 * hour, true),
        ] {
            let mut session = Session::new(Identity::from_secret(&SECRET), DEVICE_A, 0);
            session.hello_frame().expect("hello");
            let now = NOW.checked_add_signed(offset_ms).expect("in range");
            let actions = session
                .handle_frame(&challenge_frame(&[9u8; 32]), now)
                .expect("challenge");
            let skew = actions.iter().find_map(|a| match a {
                Action::ClockSkew { skew_ms } => Some(*skew_ms),
                _ => None,
            });
            assert_eq!(skew.is_some(), reported, "offset {offset_ms}");
            if let Some(skew) = skew {
                assert_eq!(skew, -offset_ms, "relay minus ours");
            }
            assert!(
                actions.iter().any(|a| matches!(a, Action::Send(_))),
                "the handshake goes on regardless"
            );
        }
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
                device_id: DEVICE_A,
            }]
        );
    }

    #[test]
    fn our_own_clip_coming_back_is_dropped() {
        // The relay excludes the sender, but a malicious one might not, and a reconnecting device
        // fetching the retained clip can legitimately receive its own message.
        let (mut a, _) = ready_session(DEVICE_A);
        let frame = a.observe_local("mine", NOW).unwrap().unwrap();
        assert_eq!(
            a.handle_frame(&frame, NOW).unwrap(),
            vec![Action::Dropped {
                reason: "own_device",
                retained: false
            }]
        );
    }

    #[test]
    fn a_replayed_message_id_is_dropped() {
        let (mut a, _) = ready_session(DEVICE_A);
        let (mut b, _) = ready_session(DEVICE_B);
        let frame = a.observe_local("once", NOW).unwrap().unwrap();

        assert_eq!(b.handle_frame(&frame, NOW).unwrap().len(), 1);
        assert_eq!(
            b.handle_frame(&frame, NOW).unwrap(),
            vec![Action::Dropped {
                reason: "duplicate",
                retained: false
            }],
            "replay"
        );
    }

    #[test]
    fn a_rolled_back_sequence_number_is_dropped() {
        let (mut a, _) = ready_session(DEVICE_A);
        let (mut b, _) = ready_session(DEVICE_B);

        let first = a.observe_local("one", NOW).unwrap().unwrap();
        let second = a.observe_local("two", NOW).unwrap().unwrap();
        assert_eq!(b.handle_frame(&second, NOW).unwrap().len(), 1);
        // The relay now replays the earlier message, which carries a lower seq.
        assert_eq!(
            b.handle_frame(&first, NOW).unwrap(),
            vec![Action::Dropped {
                reason: "rollback",
                retained: false
            }]
        );
    }

    #[test]
    fn a_stale_live_clip_is_dropped() {
        let (mut a, _) = ready_session(DEVICE_A);
        let (mut b, _) = ready_session(DEVICE_B);
        let frame = a.observe_local("old news", NOW).unwrap().unwrap();
        // A day and a millisecond later.
        assert_eq!(
            b.handle_frame(&frame, NOW + asli_core::replay::DEFAULT_MAX_AGE_MS + 1)
                .unwrap(),
            vec![Action::Dropped {
                reason: "too_old",
                retained: false
            }]
        );
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
                device_id: DEVICE_A,
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
        assert_eq!(
            b.handle_frame(&value.to_string(), NOW).unwrap(),
            vec![Action::Dropped {
                reason: "could_not_decrypt",
                retained: false
            }]
        );
    }

    #[test]
    fn a_clip_for_another_room_is_discarded() {
        let (mut a, _) = ready_session(DEVICE_A);
        let (mut b, _) = ready_session(DEVICE_B);
        let frame = a.observe_local("wrong room", NOW).unwrap().unwrap();

        let mut value: serde_json::Value = serde_json::from_str(&frame).unwrap();
        value["room"] = serde_json::json!("00000000000000000000000000");
        assert_eq!(
            b.handle_frame(&value.to_string(), NOW).unwrap(),
            vec![Action::Dropped {
                reason: "wrong_room",
                retained: false
            }]
        );
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
                device_id: DEVICE_A,
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

    /// Seals an image as the peer device would, returning the frames in order.
    fn image_frames(session_seq: u64, png: &[u8]) -> (Vec<String>, [u8; 16]) {
        let (mut peer, _) = ready_session(DEVICE_B);
        let _ = session_seq;
        let frames = peer.observe_local_image(png, NOW).expect("seals");
        let first = Message::parse(&frames[0]).expect("parses");
        let msg_id = match first {
            Message::ClipBegin(c) | Message::ClipChunk(c) | Message::ClipEnd(c) => {
                let bytes: [u8; 16] = c.msg_id.as_slice().try_into().expect("16 bytes");
                bytes
            }
            _ => panic!("expected a chunk frame"),
        };
        (frames, msg_id)
    }

    fn big_png() -> Vec<u8> {
        (0..600_000u32)
            .map(|i| u8::try_from(i % 251).unwrap_or(0))
            .collect()
    }

    #[test]
    fn a_chunked_image_round_trips() {
        let png = big_png();
        let (frames, _) = image_frames(1, &png);
        assert!(
            frames.len() > 2,
            "expected several chunks, got {}",
            frames.len()
        );

        let (mut a, _) = ready_session(DEVICE_A);
        let mut actions = Vec::new();
        for frame in &frames {
            actions.extend(a.handle_frame(frame, NOW).expect("handled"));
        }

        assert_eq!(actions.len(), 1, "exactly one action, on the final chunk");
        match &actions[0] {
            Action::Image { png: got, .. } => assert_eq!(got, &png),
            other => panic!("expected an image, got {other:?}"),
        }
    }

    #[test]
    fn nothing_is_emitted_until_the_final_chunk() {
        let (frames, _) = image_frames(1, &big_png());
        let (mut a, _) = ready_session(DEVICE_A);
        for frame in &frames[..frames.len() - 1] {
            let actions = a.handle_frame(frame, NOW).expect("handled");
            assert!(actions.is_empty(), "a partial assembly must commit nothing");
        }
        let last = a
            .handle_frame(&frames[frames.len() - 1], NOW)
            .expect("handled");
        assert_eq!(last.len(), 1);
    }

    #[test]
    fn a_truncated_stream_commits_nothing() {
        let (frames, _) = image_frames(1, &big_png());
        let (mut a, _) = ready_session(DEVICE_A);
        // Everything except the final chunk. The image must never appear.
        for frame in &frames[..frames.len() - 1] {
            assert!(a.handle_frame(frame, NOW).expect("handled").is_empty());
        }
    }

    #[test]
    fn a_dropped_interior_chunk_commits_nothing() {
        let (frames, _) = image_frames(1, &big_png());
        let (mut a, _) = ready_session(DEVICE_A);
        let mut actions = Vec::new();
        for (i, frame) in frames.iter().enumerate() {
            if i == 1 {
                continue;
            }
            actions.extend(a.handle_frame(frame, NOW).expect("handled"));
        }
        assert!(actions.is_empty(), "a gap must not reassemble");
    }

    #[test]
    fn a_reordered_chunk_is_discarded() {
        let (frames, _) = image_frames(1, &big_png());
        let (mut a, _) = ready_session(DEVICE_A);
        let mut order: Vec<&String> = frames.iter().collect();
        order.swap(1, 2);
        let mut actions = Vec::new();
        for frame in order {
            actions.extend(a.handle_frame(frame, NOW).expect("handled"));
        }
        // The AAD binds the index, so a swapped chunk fails to open and the assembly is abandoned.
        assert!(actions.is_empty(), "reordering must not reassemble");
    }

    #[test]
    fn a_replayed_chunk_is_discarded() {
        let (frames, _) = image_frames(1, &big_png());
        let (mut a, _) = ready_session(DEVICE_A);
        let mut actions = Vec::new();
        actions.extend(a.handle_frame(&frames[0], NOW).expect("handled"));
        actions.extend(a.handle_frame(&frames[0], NOW).expect("handled"));
        for frame in &frames[1..] {
            actions.extend(a.handle_frame(frame, NOW).expect("handled"));
        }
        assert!(
            actions.is_empty(),
            "a repeated index must poison the assembly"
        );
    }

    #[test]
    fn a_stray_foreign_chunk_does_not_destroy_an_assembly_in_flight() {
        let (first, _) = image_frames(1, &big_png());
        let (second, _) = image_frames(2, &big_png());
        let (mut a, _) = ready_session(DEVICE_A);

        assert!(a.handle_frame(&first[0], NOW).expect("handled").is_empty());

        // An interior chunk of an unrelated message. It cannot start an assembly and must not be
        // folded into this one, so it is ignored outright. Letting it abort the transfer in
        // progress would hand any peer a cheap way to break another peer's image transfer by
        // emitting a single stray frame.
        assert!(a.handle_frame(&second[1], NOW).expect("handled").is_empty());

        let mut actions = Vec::new();
        for frame in &first[1..] {
            actions.extend(a.handle_frame(frame, NOW).expect("handled"));
        }
        assert_eq!(
            actions.len(),
            1,
            "the legitimate transfer must still complete"
        );
    }

    #[test]
    fn a_new_message_replaces_an_unfinished_assembly() {
        let (first, _) = image_frames(1, &big_png());
        let png = big_png();
        let (second, _) = image_frames(2, &png);
        let (mut a, _) = ready_session(DEVICE_A);

        // Abandon the first message part way through.
        assert!(a.handle_frame(&first[0], NOW).expect("handled").is_empty());
        assert!(a.handle_frame(&first[1], NOW).expect("handled").is_empty());

        // A fresh begin supersedes it. Holding the abandoned one forever is how a leak starts.
        let mut actions = Vec::new();
        for frame in &second {
            actions.extend(a.handle_frame(frame, NOW).expect("handled"));
        }
        assert_eq!(actions.len(), 1, "the second message completes");
        match &actions[0] {
            Action::Image { png: got, .. } => assert_eq!(got, &png),
            other => panic!("expected an image, got {other:?}"),
        }
    }

    #[test]
    fn a_stream_joined_mid_flight_is_ignored() {
        let (frames, _) = image_frames(1, &big_png());
        let (mut a, _) = ready_session(DEVICE_A);
        // Starting at an interior chunk can never complete, so it is dropped rather than tracked.
        assert!(a.handle_frame(&frames[1], NOW).expect("handled").is_empty());
    }

    #[test]
    fn an_image_just_under_the_cap_survives_padding_on_the_way_back() {
        // Regression. The relay announces a 700 KiB content cap. An image of 700000 bytes is
        // inside it, but its padded inner plaintext is 720896 bytes, so capping the reassembly at
        // the content limit silently discarded it mid stream. The sender measures raw content and
        // the receiver must measure the padded total, or the two disagree and large images vanish.
        let png: Vec<u8> = (0..700_000u32)
            .map(|i| u8::try_from(i % 251).unwrap_or(0))
            .collect();

        let (mut sender, _) = ready_session(DEVICE_B);
        let frames = sender
            .observe_local_image(&png, NOW)
            .expect("sender accepts an image inside the content cap");

        let (mut receiver, _) = ready_session(DEVICE_A);
        let mut actions = Vec::new();
        for frame in &frames {
            actions.extend(receiver.handle_frame(frame, NOW).expect("handled"));
        }

        assert_eq!(actions.len(), 1, "the image must reassemble");
        match &actions[0] {
            Action::Image { png: got, .. } => assert_eq!(got.len(), png.len()),
            other => panic!("expected an image, got {other:?}"),
        }
    }

    #[test]
    fn an_image_beyond_the_content_cap_is_refused_before_sealing() {
        let (mut a, _) = ready_session(DEVICE_A);
        let limit = a.limits().expect("limits announced").max_content_bytes;
        let oversize = vec![0u8; usize::try_from(limit).unwrap_or(usize::MAX) + 1];
        let err = a
            .observe_local_image(&oversize, NOW)
            .expect_err("must refuse");
        assert!(matches!(err, Error::ContentTooLarge { .. }));
    }

    #[test]
    fn an_empty_image_produces_no_frames() {
        let (mut a, _) = ready_session(DEVICE_A);
        assert!(a.observe_local_image(&[], NOW).expect("ok").is_empty());
    }

    #[test]
    fn chunk_frames_carry_the_right_types_in_order() {
        let (frames, _) = image_frames(1, &big_png());
        let types: Vec<&str> = frames
            .iter()
            .map(|f| {
                let m = Message::parse(f).expect("parses");
                match m {
                    Message::ClipBegin(_) => "begin",
                    Message::ClipChunk(_) => "chunk",
                    Message::ClipEnd(_) => "end",
                    _ => "other",
                }
            })
            .collect();
        assert_eq!(types[0], "begin");
        assert_eq!(types[types.len() - 1], "end");
        assert!(types[1..types.len() - 1].iter().all(|t| *t == "chunk"));
    }

    fn presence_frame(peers: u32) -> String {
        format!(r#"{{"v":1,"type":"presence","peers":{peers}}}"#)
    }

    fn info(name: &str) -> DeviceInfo {
        DeviceInfo {
            name: name.to_owned(),
            os: "Linux".to_owned(),
        }
    }

    /// The frames an action list asks to send, parsed.
    fn sends(actions: &[Action]) -> Vec<Message> {
        actions
            .iter()
            .filter_map(|action| match action {
                Action::Send(frame) => Some(Message::parse(frame).expect("parses")),
                _ => None,
            })
            .collect()
    }

    /// A session with device information set, taken through the handshake by hand so the
    /// announcement that follows `auth_ok` is visible.
    fn announcing_session(device_id: [u8; 16], name: &str) -> (Session, Vec<Action>) {
        let mut session = Session::new(Identity::from_secret(&SECRET), device_id, 0);
        session.set_device_info(info(name));
        session.hello_frame().expect("hello");
        session
            .handle_frame(&challenge_frame(&[9u8; 32]), NOW)
            .expect("challenge");
        let actions = session
            .handle_frame(&auth_ok_frame(), NOW)
            .expect("auth_ok");
        (session, actions)
    }

    #[test]
    fn an_announcement_goes_out_after_auth_ok_and_reaches_the_other_device() {
        let (_, actions) = announcing_session(DEVICE_A, "ThinkPad X1");
        assert!(matches!(actions[0], Action::Authenticated { .. }));
        let Some(Action::Send(frame)) = actions.get(1) else {
            panic!("expected an announcement after auth_ok, got {actions:?}")
        };

        let (mut b, _) = ready_session(DEVICE_B);
        assert_eq!(
            b.handle_frame(frame, NOW).expect("opens"),
            vec![Action::Peer(PeerInfo {
                device_id: DEVICE_A,
                name: "ThinkPad X1".to_owned(),
                os: "Linux".to_owned(),
                ts_ms: NOW,
            })]
        );
    }

    #[test]
    fn nothing_is_announced_without_device_information() {
        let (mut session, transport) = ready_session(DEVICE_A);
        assert_eq!(transport.sent.len(), 2, "hello and auth, no announcement");
        assert_eq!(session.announce_frame(NOW).expect("no error"), None);
        let actions = session
            .handle_frame(&presence_frame(3), NOW)
            .expect("presence");
        assert!(sends(&actions).is_empty());
    }

    #[test]
    fn a_change_in_presence_either_way_announces_again_and_no_change_does_not() {
        let (mut session, _) = announcing_session(DEVICE_A, "desk");
        // auth_ok said two. The relay's presence broadcast for our own arrival repeats that.
        let same = session
            .handle_frame(&presence_frame(2), NOW)
            .expect("presence");
        assert!(sends(&same).is_empty(), "no change, no announcement");

        for peers in [3, 2] {
            let actions = session
                .handle_frame(&presence_frame(peers), NOW)
                .expect("presence");
            assert_eq!(actions[0], Action::Presence { peers });
            assert!(
                matches!(sends(&actions).as_slice(), [Message::Announce(_)]),
                "a change to {peers} must announce, got {actions:?}"
            );
        }
    }

    #[test]
    fn our_own_announcement_is_never_reported() {
        let (mut a, actions) = announcing_session(DEVICE_A, "mine");
        let Some(Action::Send(frame)) = actions.get(1) else {
            panic!("expected an announcement")
        };
        assert!(a.handle_frame(frame, NOW).expect("handled").is_empty());
    }

    #[test]
    fn a_replayed_or_stale_announcement_is_ignored() {
        let (_, actions) = announcing_session(DEVICE_A, "laptop");
        let Some(Action::Send(frame)) = actions.get(1) else {
            panic!("expected an announcement")
        };
        let (mut b, _) = ready_session(DEVICE_B);
        assert_eq!(b.handle_frame(frame, NOW).expect("first").len(), 1);
        assert!(
            b.handle_frame(frame, NOW).expect("again").is_empty(),
            "dedup"
        );

        let (mut c, _) = ready_session(DEVICE_B);
        let late = NOW + asli_core::replay::DEFAULT_MAX_AGE_MS + 1;
        assert!(
            c.handle_frame(frame, late).expect("late").is_empty(),
            "too old"
        );
    }

    #[test]
    fn a_tampered_announcement_is_discarded_silently() {
        let (_, actions) = announcing_session(DEVICE_A, "laptop");
        let Some(Action::Send(frame)) = actions.get(1) else {
            panic!("expected an announcement")
        };
        let Message::Announce(mut message) = Message::parse(frame).expect("parses") else {
            panic!("expected an announce frame")
        };
        message.ct[0] ^= 1;
        let tampered = Message::Announce(message).to_frame().expect("serializes");
        let (mut b, _) = ready_session(DEVICE_B);
        assert!(b.handle_frame(&tampered, NOW).expect("handled").is_empty());
    }

    #[test]
    fn an_over_long_name_is_shortened_rather_than_refused() {
        let (_, actions) = announcing_session(DEVICE_A, &"n".repeat(200));
        let Some(Action::Send(frame)) = actions.get(1) else {
            panic!("expected an announcement")
        };
        let (mut b, _) = ready_session(DEVICE_B);
        let got = b.handle_frame(frame, NOW).expect("opens");
        let [Action::Peer(peer)] = got.as_slice() else {
            panic!("expected a peer, got {got:?}")
        };
        assert_eq!(peer.name.len(), announce::MAX_FIELD_BYTES);
    }

    #[test]
    fn a_relay_that_does_not_know_announcements_is_left_alone_until_the_next_connection() {
        let (mut session, _) = announcing_session(DEVICE_A, "desk");
        // What a relay from before announcements answers, keeping the connection open.
        let refusal =
            r#"{"v":1,"type":"error","code":"UNKNOWN_TYPE","message":"unknown message type"}"#;
        assert!(
            session
                .handle_frame(refusal, NOW)
                .expect("absorbed")
                .is_empty(),
            "the refusal is ours to absorb, not a relay error to show"
        );
        let actions = session
            .handle_frame(&presence_frame(5), NOW)
            .expect("presence");
        assert!(
            sends(&actions).is_empty(),
            "no more announcements on this connection"
        );
        assert_eq!(session.announce_frame(NOW).expect("no error"), None);

        // A new connection may be to a relay that has since been updated.
        session.hello_frame().expect("hello");
        session
            .handle_frame(&challenge_frame(&[9u8; 32]), NOW)
            .expect("challenge");
        let actions = session
            .handle_frame(&auth_ok_frame(), NOW)
            .expect("auth_ok");
        assert!(matches!(sends(&actions).as_slice(), [Message::Announce(_)]));
    }

    #[test]
    fn unknown_type_before_any_announcement_is_still_reported() {
        let (mut session, _) = ready_session(DEVICE_A);
        let refusal = r#"{"v":1,"type":"error","code":"UNKNOWN_TYPE"}"#;
        assert_eq!(
            session.handle_frame(refusal, NOW).expect("handled"),
            vec![Action::RelayError {
                code: ErrorCode::UnknownType,
                retry_after_ms: None,
            }]
        );
    }

    #[test]
    fn a_received_clip_names_the_device_that_sent_it() {
        let (mut a, _) = ready_session(DEVICE_A);
        let (mut b, _) = ready_session(DEVICE_B);
        let frame = a.observe_local("from a", NOW).unwrap().unwrap();
        let actions = b.handle_frame(&frame, NOW).unwrap();
        assert!(matches!(
            actions.as_slice(),
            [Action::Clip { device_id, .. }] if *device_id == DEVICE_A
        ));
    }
}
