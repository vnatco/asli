//! Sending a file to one of the other devices, and receiving one.
//!
//! The daemon holds the connection, so everything here runs inside it: an offer goes out, the other
//! device's person accepts or declines, and on acceptance the file follows in pieces addressed to
//! that device alone, a few at a time, each one acknowledged. `asli_crypto::file` has the messages
//! and protocol section 18.8 the rules.
//!
//! Nothing is kept unless the person accepts it. What is kept is written under a temporary name,
//! renamed only once its size and hash match the offer, given a name of this device's choosing
//! made from the sender's, and marked as downloaded where the system has such a mark. It is never
//! opened.

use std::collections::HashMap;
use std::fs::{self, File};
use std::io::{Read as _, Seek as _, Write as _};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use asli_crypto::device::DeviceKeys;
use asli_crypto::file::{Ack, AckState, Answer, Cancel, Chunk, Offer, CHUNK_BYTES, OFFER_ID_LEN};
use asli_net::client::{LocalEvent, MsgKind};
use sha2::{Digest as _, Sha256};
use tokio::sync::mpsc;
use zeroize::Zeroizing;

use crate::clipboard_io::log_line;
use crate::devices::DevicesHandle;

/// Largest file offered or accepted.
pub const MAX_FILE_BYTES: u64 = 4 * 1024 * 1024 * 1024;

/// Pieces sent ahead of the last acknowledgement. Six of 256 KiB keeps at most a megabyte and a
/// half in flight, which a slow receiver holds in the relay's buffer, not more.
const WINDOW: u32 = 6;

/// Bytes of file a second this device sends, all transfers together. The relay allows 8 MiB a
/// second of frames, and a piece grows by a third in base64, so this stays under it with room to
/// spare: a piece over the limit is dropped, and the receiver then waits for it forever.
const PACE_BYTES_PER_SEC: f64 = 5.0 * 1024.0 * 1024.0;
/// How far ahead of that rate a quiet sender may start.
const PACE_BURST: f64 = 2.0 * 1024.0 * 1024.0;

/// How long a transfer under way may go without progress before it is given up.
const STALL: std::time::Duration = std::time::Duration::from_secs(60);

/// A token bucket for outgoing pieces.
#[derive(Debug, Default)]
struct Pace {
    tokens: f64,
    /// When it was last topped up. `None` before the first piece, which finds it full.
    at: Option<Instant>,
}

impl Pace {
    /// Takes `bytes` if they are there, after topping up for the time gone by.
    fn take(&mut self, bytes: usize, now: Instant) -> bool {
        self.tokens = match self.at {
            None => PACE_BURST,
            Some(at) => (self.tokens + now.duration_since(at).as_secs_f64() * PACE_BYTES_PER_SEC)
                .min(PACE_BURST),
        };
        self.at = Some(now);
        #[allow(clippy::cast_precision_loss)]
        let bytes = bytes as f64;
        if self.tokens < bytes {
            return false;
        }
        self.tokens -= bytes;
        true
    }
}

/// An offer id, in hex, as the window and the command line name it.
pub type OfferId = [u8; OFFER_ID_LEN];

/// Which way a transfer goes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    /// From this device.
    Sending,
    /// To this device.
    Receiving,
}

/// Where a transfer stands.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Stage {
    /// Offered, waiting for the other device's person to answer.
    Offered,
    /// Pieces are moving. Carries how many have been acknowledged.
    Moving(u32),
    /// Finished. For a received file, carries where it was kept.
    Done(Option<PathBuf>),
    /// Turned down by the other device.
    Declined,
    /// Called off by either side.
    Cancelled,
    /// Did not make it. Carries why.
    Failed(String),
}

impl Stage {
    /// Whether the transfer is over, one way or another.
    #[must_use]
    pub const fn finished(&self) -> bool {
        !matches!(self, Self::Offered | Self::Moving(_))
    }
}

/// One transfer, as the window and the command line show it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Listed {
    /// Its offer id.
    pub id: OfferId,
    /// Which way it goes.
    pub direction: Direction,
    /// The other device's name.
    pub peer: String,
    /// The file's name.
    pub name: String,
    /// Its size.
    pub size: u64,
    /// How many pieces it is sent in.
    pub chunks: u64,
    /// Where it stands.
    pub stage: Stage,
}

/// The transfers this device is part of, shared between the daemon, the window and the request
/// watcher.
#[derive(Debug, Clone, Default)]
pub struct Transfers(Arc<Mutex<State>>);

#[derive(Default)]
struct State {
    link: Option<Link>,
    devices: DevicesHandle,
    sending: HashMap<OfferId, Outgoing>,
    receiving: HashMap<OfferId, Incoming>,
    pace: Pace,
    /// Bumped on every change, so a window knows to redraw.
    revision: u64,
}

impl std::fmt::Debug for State {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("State")
            .field("linked", &self.link.is_some())
            .field("sending", &self.sending.len())
            .field("receiving", &self.receiving.len())
            .finish_non_exhaustive()
    }
}

/// What a transfer needs from the live connection.
struct Link {
    tx: mpsc::Sender<LocalEvent>,
    device_secret: Zeroizing<[u8; 32]>,
    device_id: [u8; 16],
    room: [u8; 16],
    conn_id: Option<String>,
}

impl Link {
    fn keys(&self) -> DeviceKeys {
        DeviceKeys::from_secret(&self.device_secret)
    }
}

struct Outgoing {
    offer: Offer,
    path: PathBuf,
    peer: String,
    /// The receiver's connection, once it has answered.
    to: Option<String>,
    /// The next piece to send.
    next: u32,
    acked: u32,
    stage: Stage,
    /// The last time it got anywhere.
    moved: Instant,
}

struct Incoming {
    offer: Offer,
    peer: String,
    /// Where it is being written, under a temporary name, and where it goes once it checks out.
    part: Option<(File, PathBuf, PathBuf)>,
    hasher: Sha256,
    received: u32,
    written: u64,
    stage: Stage,
    /// The last time it got anywhere.
    moved: Instant,
}

impl Transfers {
    /// Connects the transfers to a live connection.
    pub(crate) fn attach(
        &self,
        tx: mpsc::Sender<LocalEvent>,
        device_secret: &[u8; 32],
        device_id: [u8; 16],
        room: [u8; 16],
        devices: DevicesHandle,
    ) {
        if let Ok(mut state) = self.0.lock() {
            state.link = Some(Link {
                tx,
                device_secret: Zeroizing::new(*device_secret),
                device_id,
                room,
                conn_id: None,
            });
            state.devices = devices;
        }
    }

    /// A connection came up. Anything under way on the previous one is over: its pieces were
    /// addressed to a connection that no longer exists, and there is no resuming in this version.
    pub(crate) fn connected(&self, conn_id: &str) {
        let Ok(mut state) = self.0.lock() else {
            return;
        };
        if let Some(link) = state.link.as_mut() {
            link.conn_id = Some(conn_id.to_owned());
        }
        fail_all_live(&mut state, "the connection dropped. Try again.");
    }

    /// Carries on any transfer the pace held back, and gives up on any that stopped moving.
    /// Called often; costs nothing when idle.
    pub(crate) fn tick(&self) {
        let Ok(mut guard) = self.0.lock() else {
            return;
        };
        let state = &mut *guard;
        let now = Instant::now();
        let mut gave_up = false;
        for outgoing in state.sending.values_mut() {
            if matches!(outgoing.stage, Stage::Moving(_)) && now - outgoing.moved > STALL {
                outgoing.stage = Stage::Failed("the other device stopped answering.".to_owned());
                gave_up = true;
            }
        }
        for incoming in state.receiving.values_mut() {
            if matches!(incoming.stage, Stage::Moving(_)) && now - incoming.moved > STALL {
                discard_part(incoming);
                incoming.stage = Stage::Failed("the other device stopped sending.".to_owned());
                gave_up = true;
            }
        }
        if gave_up {
            state.revision += 1;
        }
        let Some(link) = state.link.as_ref() else {
            return;
        };
        for outgoing in state.sending.values_mut() {
            if matches!(outgoing.stage, Stage::Moving(_)) {
                pump(link, &mut state.pace, outgoing);
            }
        }
    }

    /// A connection ended.
    pub(crate) fn disconnected(&self) {
        if let Ok(mut state) = self.0.lock() {
            fail_all_live(&mut state, "the connection dropped. Try again.");
        }
    }

    /// The relay refused more transfer traffic today.
    pub(crate) fn over_quota(&self) {
        if let Ok(mut state) = self.0.lock() {
            fail_all_live(
                &mut state,
                "the relay's daily transfer allowance is used up. Try again tomorrow.",
            );
        }
    }

    /// Everything to show, newest first.
    #[must_use]
    pub fn list(&self) -> Vec<Listed> {
        let Ok(state) = self.0.lock() else {
            return Vec::new();
        };
        let mut out: Vec<(u64, Listed)> = state
            .sending
            .values()
            .map(|o| {
                (
                    o.offer.ts_ms,
                    Listed {
                        id: o.offer.offer_id,
                        direction: Direction::Sending,
                        peer: o.peer.clone(),
                        name: o.offer.name.clone(),
                        size: o.offer.size,
                        chunks: o.offer.chunk_count(),
                        stage: o.stage.clone(),
                    },
                )
            })
            .chain(state.receiving.values().map(|i| {
                (
                    i.offer.ts_ms,
                    Listed {
                        id: i.offer.offer_id,
                        direction: Direction::Receiving,
                        peer: i.peer.clone(),
                        name: crate::transfer::safe_name(&i.offer.name),
                        size: i.offer.size,
                        chunks: i.offer.chunk_count(),
                        stage: i.stage.clone(),
                    },
                )
            }))
            .collect();
        out.sort_by_key(|(ts, _)| std::cmp::Reverse(*ts));
        out.into_iter().map(|(_, listed)| listed).collect()
    }

    /// A number that changes whenever anything shown does.
    #[must_use]
    pub fn revision(&self) -> u64 {
        self.0.lock().map_or(0, |state| state.revision)
    }

    /// Forgets the transfers that are over, so they leave the list.
    pub fn clear_finished(&self) {
        if let Ok(mut state) = self.0.lock() {
            state.sending.retain(|_, o| !o.stage.finished());
            state.receiving.retain(|_, i| !i.stage.finished());
            state.revision += 1;
        }
    }

    /// Offers a file to a device. The file is hashed on a thread of its own, since it can be large,
    /// and offered once that is done.
    ///
    /// # Errors
    ///
    /// Returns a sentence for the person when the file cannot be read, is too large, or the device
    /// is not connected.
    pub fn send(&self, path: &Path, to: [u8; 16]) -> Result<(), String> {
        let metadata =
            fs::metadata(path).map_err(|err| format!("Couldn't read the file: {err}"))?;
        if !metadata.is_file() {
            return Err("Only files can be sent, not folders.".to_owned());
        }
        if metadata.len() > MAX_FILE_BYTES {
            return Err("That file is larger than 4 GB, the most Asli sends.".to_owned());
        }
        let (peer, conn) = {
            let state = self
                .0
                .lock()
                .map_err(|_| "Asli is shutting down.".to_owned())?;
            if state
                .link
                .as_ref()
                .and_then(|l| l.conn_id.as_ref())
                .is_none()
            {
                return Err("Asli is not connected right now.".to_owned());
            }
            let peer = state
                .devices
                .name_of(&to)
                .unwrap_or_else(|| "that device".to_owned());
            (peer, state.devices.conn_of(&to))
        };
        let Some(conn) = conn else {
            return Err(format!("{peer} is not connected right now."));
        };

        let this = self.clone();
        let path = path.to_path_buf();
        std::thread::Builder::new()
            .name("asli-hash".to_owned())
            .spawn(move || {
                let outcome = hash_file(&path).and_then(|(size, sha256)| {
                    this.offer(path.clone(), to, &conn, &peer, size, sha256)
                });
                if let Err(err) = outcome {
                    eprintln!("{}", log_line("file_offer_failed", &err));
                    crate::notify::file_failed(&display_name(&path), &err);
                }
            })
            .map_err(|err| err.to_string())?;
        Ok(())
    }

    fn offer(
        &self,
        path: PathBuf,
        to: [u8; 16],
        conn: &str,
        peer: &str,
        size: u64,
        sha256: [u8; 32],
    ) -> Result<(), String> {
        let mut state = self
            .0
            .lock()
            .map_err(|_| "Asli is shutting down.".to_owned())?;
        let link = state.link.as_ref().ok_or("Asli is not connected.")?;
        let reply_to = link.conn_id.clone().ok_or("Asli is not connected.")?;
        let offer = Offer {
            offer_id: asli_crypto::random::bytes().map_err(|e| e.to_string())?,
            from_device_id: link.device_id,
            to_device_id: to,
            size,
            sha256,
            chunk_bytes: CHUNK_BYTES,
            ts_ms: asli_net::client::now_ms(),
            reply_to,
            name: truncate_name(&display_name(&path)),
        };
        let body = offer
            .encode(&link.keys(), &link.room)
            .map_err(|e| e.to_string())?;
        send_msg(link, MsgKind::FileOffer, body, conn)?;
        eprintln!(
            "{}",
            log_line("file_offered", &format!("{size} bytes to {peer}"))
        );
        state.sending.insert(
            offer.offer_id,
            Outgoing {
                offer,
                path,
                peer: peer.to_owned(),
                to: None,
                next: 0,
                acked: 0,
                stage: Stage::Offered,
                moved: Instant::now(),
            },
        );
        state.revision += 1;
        Ok(())
    }

    /// Accepts an offered file, keeping it in `folder`.
    ///
    /// # Errors
    ///
    /// Returns a sentence for the person when there is no such offer waiting, or the folder cannot
    /// be written to.
    pub fn accept(&self, id: &OfferId, folder: &Path) -> Result<(), String> {
        let mut state = self
            .0
            .lock()
            .map_err(|_| "Asli is shutting down.".to_owned())?;
        let State {
            link, receiving, ..
        } = &mut *state;
        let link = link.as_ref().ok_or("Asli is not connected.")?;
        let incoming = receiving
            .get_mut(id)
            .filter(|i| i.stage == Stage::Offered)
            .ok_or("That file is no longer waiting.")?;
        let final_path = unique_path(folder, &safe_name(&incoming.offer.name));
        let part_path = part_path_for(&final_path);
        let file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&part_path)
            .map_err(|err| format!("Couldn't write to {}: {err}", folder.display()))?;
        let answer = Answer {
            offer_id: *id,
            from_device_id: link.device_id,
            accepted: true,
            reply_to: link.conn_id.clone().ok_or("Asli is not connected.")?,
        };
        let body = answer
            .encode(&link.keys(), &link.room)
            .map_err(|e| e.to_string())?;
        if let Err(err) = send_msg(link, MsgKind::FileAnswer, body, &incoming.offer.reply_to) {
            let _ = fs::remove_file(&part_path);
            return Err(err);
        }
        incoming.part = Some((file, part_path, final_path));
        incoming.stage = Stage::Moving(0);
        incoming.moved = Instant::now();
        state.revision += 1;
        Ok(())
    }

    /// Turns an offered file down.
    pub fn decline(&self, id: &OfferId) {
        let Ok(mut state) = self.0.lock() else {
            return;
        };
        let State {
            link, receiving, ..
        } = &mut *state;
        let (Some(link), Some(incoming)) = (link.as_ref(), receiving.get_mut(id)) else {
            return;
        };
        if incoming.stage != Stage::Offered {
            return;
        }
        let answer = Answer {
            offer_id: *id,
            from_device_id: link.device_id,
            accepted: false,
            reply_to: link.conn_id.clone().unwrap_or_default(),
        };
        if let Ok(body) = answer.encode(&link.keys(), &link.room) {
            let _ = send_msg(link, MsgKind::FileAnswer, body, &incoming.offer.reply_to);
        }
        incoming.stage = Stage::Declined;
        state.revision += 1;
    }

    /// Calls a transfer off, either way round.
    pub fn cancel(&self, id: &OfferId) {
        let Ok(mut state) = self.0.lock() else {
            return;
        };
        let to = state
            .sending
            .get(id)
            .filter(|o| !o.stage.finished())
            .and_then(|o| {
                o.to.clone()
                    .or_else(|| state.devices.conn_of(&o.offer.to_device_id))
            })
            .or_else(|| {
                state
                    .receiving
                    .get(id)
                    .filter(|i| !i.stage.finished())
                    .map(|i| i.offer.reply_to.clone())
            });
        if let (Some(link), Some(to)) = (state.link.as_ref(), to) {
            let _ = send_msg(
                link,
                MsgKind::FileCancel,
                Cancel { offer_id: *id }.encode(),
                &to,
            );
        }
        if let Some(outgoing) = state.sending.get_mut(id) {
            if !outgoing.stage.finished() {
                outgoing.stage = Stage::Cancelled;
            }
        }
        if let Some(incoming) = state.receiving.get_mut(id) {
            if !incoming.stage.finished() {
                discard_part(incoming);
                incoming.stage = Stage::Cancelled;
            }
        }
        state.revision += 1;
    }

    /// Acts on a file message from another device. Returns the name and sender of a newly offered
    /// file, so the caller can bring it to the person's attention.
    pub(crate) fn on_message(&self, kind: MsgKind, body: &[u8]) -> Option<(String, String, u64)> {
        let Ok(mut state) = self.0.lock() else {
            return None;
        };
        let offered = match kind {
            MsgKind::FileOffer => on_offer(&mut state, body),
            MsgKind::FileAnswer => {
                on_answer(&mut state, body);
                None
            }
            MsgKind::FileChunk => {
                on_chunk(&mut state, body);
                None
            }
            MsgKind::FileAck => {
                on_ack(&mut state, body);
                None
            }
            MsgKind::FileCancel => {
                on_cancel(&mut state, body);
                None
            }
            _ => None,
        };
        state.revision += 1;
        offered
    }
}

fn on_offer(state: &mut State, body: &[u8]) -> Option<(String, String, u64)> {
    let link = state.link.as_ref()?;
    // Believed only when signed by the key its claimed sender pinned. The name shown is the one
    // that device's card gave, not anything the offer says.
    let from = Offer::claimed_sender(body).ok()?;
    let pinned = state
        .devices
        .pinned()
        .into_iter()
        .find(|device| device.device_id == from)?;
    let offer = Offer::decode(body, &link.room, &pinned.sign_pub).ok()?;
    if offer.to_device_id != link.device_id
        || offer.size > MAX_FILE_BYTES
        || state.receiving.contains_key(&offer.offer_id)
    {
        return None;
    }
    let peer = pinned.name.clone();
    let name = safe_name(&offer.name);
    let size = offer.size;
    eprintln!(
        "{}",
        log_line("file_offered_here", &format!("{size} bytes from {peer}"))
    );
    state.receiving.insert(
        offer.offer_id,
        Incoming {
            offer,
            peer: peer.clone(),
            part: None,
            hasher: Sha256::new(),
            received: 0,
            written: 0,
            stage: Stage::Offered,
            moved: Instant::now(),
        },
    );
    Some((peer, name, size))
}

fn on_answer(state: &mut State, body: &[u8]) {
    let Some(link) = state.link.as_ref() else {
        return;
    };
    let Ok(from) = Answer::claimed_sender(body) else {
        return;
    };
    let Some(pinned) = state
        .devices
        .pinned()
        .into_iter()
        .find(|device| device.device_id == from)
    else {
        return;
    };
    let Ok(answer) = Answer::decode(body, &link.room, &pinned.sign_pub) else {
        return;
    };
    let Some(outgoing) = state.sending.get_mut(&answer.offer_id) else {
        return;
    };
    // Only the device it was offered to may answer.
    if outgoing.offer.to_device_id != answer.from_device_id || outgoing.stage != Stage::Offered {
        return;
    }
    if !answer.accepted {
        outgoing.stage = Stage::Declined;
        return;
    }
    outgoing.to = Some(answer.reply_to);
    outgoing.stage = Stage::Moving(0);
    outgoing.moved = Instant::now();
    pump(link, &mut state.pace, outgoing);
}

fn on_ack(state: &mut State, body: &[u8]) {
    let Some(link) = state.link.as_ref() else {
        return;
    };
    let Ok(ack) = Ack::decode(body) else {
        return;
    };
    let Some(outgoing) = state.sending.get_mut(&ack.offer_id) else {
        return;
    };
    if outgoing.stage.finished() {
        return;
    }
    outgoing.acked = outgoing.acked.max(ack.received);
    outgoing.moved = Instant::now();
    match ack.state {
        AckState::Receiving => {
            outgoing.stage = Stage::Moving(outgoing.acked);
            pump(link, &mut state.pace, outgoing);
        }
        AckState::Done => {
            eprintln!(
                "{}",
                log_line("file_sent", &format!("{} bytes", outgoing.offer.size))
            );
            outgoing.stage = Stage::Done(None);
        }
        AckState::Corrupt => {
            outgoing.stage = Stage::Failed("it arrived damaged. Try again.".to_owned());
        }
    }
}

/// Sends pieces until the window is full, the pace runs out, or the file is out.
fn pump(link: &Link, pace: &mut Pace, outgoing: &mut Outgoing) {
    let Some(to) = outgoing.to.clone() else {
        return;
    };
    let total = u32::try_from(outgoing.offer.chunk_count()).unwrap_or(u32::MAX);
    while outgoing.next < total && outgoing.next < outgoing.acked.saturating_add(WINDOW) {
        if !pace.take(expected_len(&outgoing.offer, outgoing.next), Instant::now()) {
            // The pacer's tick carries on from here.
            return;
        }
        let data = match read_chunk(&outgoing.path, outgoing.next, outgoing.offer.chunk_bytes) {
            Ok(data) => data,
            Err(err) => {
                outgoing.stage = Stage::Failed(format!("couldn't read the file: {err}"));
                return;
            }
        };
        let chunk = Chunk {
            offer_id: outgoing.offer.offer_id,
            index: outgoing.next,
            data,
        };
        let Ok(body) = chunk.encode() else {
            outgoing.stage = Stage::Failed("a piece was too large".to_owned());
            return;
        };
        if send_msg(link, MsgKind::FileChunk, body, &to).is_err() {
            // The queue to the connection is full. The next acknowledgement tries again.
            return;
        }
        outgoing.next += 1;
    }
}

fn on_chunk(state: &mut State, body: &[u8]) {
    let Some(link) = state.link.as_ref() else {
        return;
    };
    let Ok(chunk) = Chunk::decode(body) else {
        return;
    };
    let Some(incoming) = state.receiving.get_mut(&chunk.offer_id) else {
        return;
    };
    if !matches!(incoming.stage, Stage::Moving(_)) || chunk.index != incoming.received {
        return;
    }
    let expected = expected_len(&incoming.offer, chunk.index);
    if chunk.data.len() != expected {
        fail_incoming(link, incoming, "a piece arrived the wrong size");
        return;
    }
    let Some((file, _, _)) = incoming.part.as_mut() else {
        return;
    };
    if let Err(err) = file.write_all(&chunk.data) {
        let reason = format!("couldn't write the file: {err}");
        fail_incoming(link, incoming, &reason);
        return;
    }
    incoming.hasher.update(&chunk.data);
    incoming.received += 1;
    incoming.moved = Instant::now();
    incoming.written += chunk.data.len() as u64;

    let done = u64::from(incoming.received) == incoming.offer.chunk_count();
    let state_now = if done {
        finish_incoming(incoming)
    } else {
        incoming.stage = Stage::Moving(incoming.received);
        AckState::Receiving
    };
    let ack = Ack {
        offer_id: chunk.offer_id,
        received: incoming.received,
        state: state_now,
    };
    let _ = send_msg(
        link,
        MsgKind::FileAck,
        ack.encode(),
        &incoming.offer.reply_to,
    );
}

/// Checks a fully arrived file against its offer, and keeps it or throws it away.
fn finish_incoming(incoming: &mut Incoming) -> AckState {
    let digest: [u8; 32] = std::mem::take(&mut incoming.hasher).finalize().into();
    let Some((file, part, final_path)) = incoming.part.take() else {
        return AckState::Corrupt;
    };
    let synced = file.sync_all();
    drop(file);
    if digest != incoming.offer.sha256 || incoming.written != incoming.offer.size || synced.is_err()
    {
        let _ = fs::remove_file(&part);
        incoming.stage = Stage::Failed("it arrived damaged, so it was thrown away".to_owned());
        crate::notify::file_failed(&safe_name(&incoming.offer.name), "it arrived damaged");
        return AckState::Corrupt;
    }
    // Checked again at the rename: something with the same name may have appeared meanwhile. Its
    // own temporary file is still there, so the name chosen at the start is checked on its own.
    let folder = final_path
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_default();
    let target = if final_path.exists() {
        unique_path(&folder, &safe_name(&incoming.offer.name))
    } else {
        final_path
    };
    if let Err(err) = fs::rename(&part, &target) {
        let _ = fs::remove_file(&part);
        incoming.stage = Stage::Failed(format!("couldn't keep it: {err}"));
        return AckState::Corrupt;
    }
    mark_downloaded(&target);
    eprintln!(
        "{}",
        log_line("file_received", &format!("{} bytes", incoming.offer.size))
    );
    crate::notify::file_received(
        &target
            .file_name()
            .map_or_else(String::new, |n| n.to_string_lossy().into_owned()),
        &folder.display().to_string(),
    );
    incoming.stage = Stage::Done(Some(target));
    AckState::Done
}

fn on_cancel(state: &mut State, body: &[u8]) {
    let Ok(cancel) = Cancel::decode(body) else {
        return;
    };
    if let Some(outgoing) = state.sending.get_mut(&cancel.offer_id) {
        if !outgoing.stage.finished() {
            outgoing.stage = Stage::Cancelled;
        }
    }
    if let Some(incoming) = state.receiving.get_mut(&cancel.offer_id) {
        if !incoming.stage.finished() {
            discard_part(incoming);
            incoming.stage = Stage::Cancelled;
        }
    }
}

fn fail_incoming(link: &Link, incoming: &mut Incoming, reason: &str) {
    discard_part(incoming);
    incoming.stage = Stage::Failed(reason.to_owned());
    let cancel = Cancel {
        offer_id: incoming.offer.offer_id,
    };
    let _ = send_msg(
        link,
        MsgKind::FileCancel,
        cancel.encode(),
        &incoming.offer.reply_to,
    );
    crate::notify::file_failed(&safe_name(&incoming.offer.name), reason);
}

fn discard_part(incoming: &mut Incoming) {
    if let Some((file, part, _)) = incoming.part.take() {
        drop(file);
        let _ = fs::remove_file(part);
    }
}

fn fail_all_live(state: &mut State, reason: &str) {
    for outgoing in state.sending.values_mut() {
        if !outgoing.stage.finished() {
            outgoing.stage = Stage::Failed(reason.to_owned());
        }
    }
    for incoming in state.receiving.values_mut() {
        if !incoming.stage.finished() {
            discard_part(incoming);
            incoming.stage = Stage::Failed(reason.to_owned());
        }
    }
    state.revision += 1;
}

fn send_msg(link: &Link, kind: MsgKind, body: Vec<u8>, to: &str) -> Result<(), String> {
    link.tx
        .try_send(LocalEvent::Message {
            kind,
            body,
            to: Some(to.to_owned()),
            token: None,
        })
        .map_err(|_| "Asli is busy. Try again in a moment.".to_owned())
}

/// The length piece `index` must have.
fn expected_len(offer: &Offer, index: u32) -> usize {
    let start = u64::from(index) * u64::from(offer.chunk_bytes);
    let len = offer
        .size
        .saturating_sub(start)
        .min(u64::from(offer.chunk_bytes));
    usize::try_from(len).unwrap_or(usize::MAX)
}

fn read_chunk(path: &Path, index: u32, chunk_bytes: u32) -> std::io::Result<Vec<u8>> {
    let mut file = File::open(path)?;
    file.seek(std::io::SeekFrom::Start(
        u64::from(index) * u64::from(chunk_bytes),
    ))?;
    let mut data = Vec::with_capacity(chunk_bytes as usize);
    file.take(u64::from(chunk_bytes)).read_to_end(&mut data)?;
    Ok(data)
}

fn hash_file(path: &Path) -> Result<(u64, [u8; 32]), String> {
    let mut file = File::open(path).map_err(|err| format!("couldn't read it: {err}"))?;
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; 1024 * 1024];
    let mut size = 0u64;
    loop {
        let n = file
            .read(&mut buf)
            .map_err(|err| format!("couldn't read it: {err}"))?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
        size += n as u64;
    }
    if size > MAX_FILE_BYTES {
        return Err("it is larger than 4 GB".to_owned());
    }
    Ok((size, hasher.finalize().into()))
}

fn display_name(path: &Path) -> String {
    path.file_name().map_or_else(
        || "file".to_owned(),
        |name| name.to_string_lossy().into_owned(),
    )
}

/// Shortens a name to what an offer carries, keeping its extension.
fn truncate_name(name: &str) -> String {
    asli_crypto::announce::truncate_utf8(name, asli_crypto::file::MAX_NAME_BYTES).to_owned()
}

/// Makes a file name safe to create in a folder of this device's choosing from the name a sender
/// gave, which is not trusted: no path, so it cannot land outside the folder; no control
/// characters; nothing Windows refuses or reserves; nothing hidden; never empty.
#[must_use]
pub fn safe_name(raw: &str) -> String {
    // The last path component only, whichever separator the sender's system used.
    let base = raw.rsplit(['/', '\\']).next().unwrap_or(raw);
    let mut name: String = base
        .chars()
        .map(|c| {
            if c.is_control()
                || is_invisible(c)
                || matches!(c, '<' | '>' | ':' | '"' | '|' | '?' | '*')
            {
                '_'
            } else {
                c
            }
        })
        .collect();
    // Windows drops trailing dots and spaces, which would make two different names collide.
    while name.ends_with(['.', ' ']) {
        name.pop();
    }
    let name = name.trim_start().to_owned();
    let mut name = if name.is_empty() || name == "." || name == ".." {
        "file".to_owned()
    } else {
        name
    };
    if name.starts_with('.') {
        name.insert(0, '_');
    }
    let stem = name.split('.').next().unwrap_or("").to_ascii_uppercase();
    let reserved = matches!(stem.as_str(), "CON" | "PRN" | "AUX" | "NUL")
        || ((stem.starts_with("COM") || stem.starts_with("LPT"))
            && stem.len() == 4
            && stem.as_bytes()[3].is_ascii_digit());
    if reserved {
        name.insert(0, '_');
    }
    asli_crypto::announce::truncate_utf8(&name, 200).to_owned()
}

/// Direction overrides and zero width characters, which can make `gpj.exe` read as `exe.jpg`.
fn is_invisible(c: char) -> bool {
    matches!(c,
        '\u{061C}' | '\u{180E}' | '\u{200B}'..='\u{200F}' | '\u{202A}'..='\u{202E}'
            | '\u{2060}'..='\u{2064}' | '\u{2066}'..='\u{2069}' | '\u{FEFF}')
}

/// `name` in `folder`, or `name (2)`, `name (3)` and so on, whichever does not exist yet.
fn unique_path(folder: &Path, name: &str) -> PathBuf {
    let first = folder.join(name);
    if !first.exists() && !part_path_for(&first).exists() {
        return first;
    }
    let (stem, ext) = match name.rfind('.') {
        Some(dot) if dot > 0 => (&name[..dot], &name[dot..]),
        _ => (name, ""),
    };
    (2..10_000)
        .map(|n| folder.join(format!("{stem} ({n}){ext}")))
        .find(|candidate| !candidate.exists() && !part_path_for(candidate).exists())
        .unwrap_or(first)
}

fn part_path_for(path: &Path) -> PathBuf {
    let mut name = path.as_os_str().to_owned();
    name.push(".asli-part");
    PathBuf::from(name)
}

/// Marks a received file as downloaded, so the system treats it as it treats anything from the
/// internet: Windows' Mark of the Web, macOS's quarantine. Linux has no such mark; the file is
/// simply not executable.
fn mark_downloaded(path: &Path) {
    #[cfg(target_os = "windows")]
    {
        let mut stream = path.as_os_str().to_owned();
        stream.push(":Zone.Identifier");
        let _ = fs::write(PathBuf::from(stream), b"[ZoneTransfer]\r\nZoneId=3\r\n");
    }
    #[cfg(target_os = "macos")]
    {
        let value = format!("0081;{:x};Asli;", asli_net::client::now_ms() / 1000);
        let _ = std::process::Command::new("/usr/bin/xattr")
            .args(["-w", "com.apple.quarantine", &value])
            .arg(path)
            .output();
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let _ = fs::set_permissions(path, fs::Permissions::from_mode(0o644));
    }
}

/// Where a transfer stands, in words, for a list.
#[must_use]
pub fn describe(stage: &Stage, chunks: u64) -> String {
    match stage {
        Stage::Offered => "waiting for an answer".to_owned(),
        Stage::Moving(done) => {
            let percent = u64::from(*done)
                .saturating_mul(100)
                .checked_div(chunks)
                .unwrap_or(0);
            format!("{percent}%")
        }
        Stage::Done(Some(path)) => format!("done, in {}", path.display()),
        Stage::Done(None) => "done".to_owned(),
        Stage::Declined => "turned down".to_owned(),
        Stage::Cancelled => "called off".to_owned(),
        Stage::Failed(why) => format!("stopped: {why}"),
    }
}

/// The folder a received file goes to unless the person picks another.
#[must_use]
pub fn default_folder() -> PathBuf {
    directories::UserDirs::new()
        .and_then(|dirs| dirs.download_dir().map(Path::to_path_buf))
        .or_else(|| directories::UserDirs::new().map(|dirs| dirs.home_dir().to_path_buf()))
        .unwrap_or_else(std::env::temp_dir)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_name_from_another_device_cannot_escape_its_folder_or_hide() {
        for (given, kept) in [
            ("report.pdf", "report.pdf"),
            ("../../.config/autostart/evil.desktop", "evil.desktop"),
            ("..\\..\\Startup\\run.lnk", "run.lnk"),
            ("C:\\Windows\\System32\\x.dll", "x.dll"),
            (".bashrc", "_.bashrc"),
            ("..", "file"),
            ("", "file"),
            ("notes. ", "notes"),
            ("CON.txt", "_CON.txt"),
            ("com1", "_com1"),
            ("a<b>c:d|e?f*g\"h", "a_b_c_d_e_f_g_h"),
            ("line\nbreak\u{202e}txt.exe", "line_break_txt.exe"),
        ] {
            assert_eq!(safe_name(given), kept, "for {given:?}");
        }
    }

    #[test]
    fn the_pace_allows_a_burst_then_refills_at_its_rate() {
        let start = Instant::now();
        let mut pace = Pace::default();
        let piece = usize::try_from(CHUNK_BYTES).expect("fits");
        let burst = (0..100).take_while(|_| pace.take(piece, start)).count();
        assert_eq!(burst, 8, "two megabytes of 256 KiB pieces");
        let later = start + std::time::Duration::from_millis(100);
        let refilled = (0..100).take_while(|_| pace.take(piece, later)).count();
        assert_eq!(refilled, 2, "a tenth of a second at 5 MiB a second");
    }

    #[test]
    fn a_taken_name_gets_a_number() {
        let dir = std::env::temp_dir().join(format!("asli-unique-{}", std::process::id()));
        let _ = fs::create_dir_all(&dir);
        fs::write(dir.join("a.txt"), b"x").expect("writes");
        assert_eq!(unique_path(&dir, "a.txt"), dir.join("a (2).txt"));
        assert_eq!(unique_path(&dir, "b.txt"), dir.join("b.txt"));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn every_piece_but_the_last_is_full() {
        let offer = Offer {
            offer_id: [0; 16],
            from_device_id: [0; 16],
            to_device_id: [0; 16],
            size: u64::from(CHUNK_BYTES) * 2 + 10,
            sha256: [0; 32],
            chunk_bytes: CHUNK_BYTES,
            ts_ms: 0,
            reply_to: String::new(),
            name: String::new(),
        };
        assert_eq!(expected_len(&offer, 0), CHUNK_BYTES as usize);
        assert_eq!(expected_len(&offer, 2), 10);
        assert_eq!(offer.chunk_count(), 3);
    }
}
