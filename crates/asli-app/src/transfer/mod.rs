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
use asli_crypto::file::{
    Ack, AckState, Answer, Cancel, Chunk, Direct, Offer, CHUNK_BYTES, OFFER_ID_LEN,
};
use asli_net::client::{LocalEvent, MsgKind};
use sha2::{Digest as _, Sha256};
use tokio::sync::mpsc;
use zeroize::Zeroizing;

use crate::clipboard_io::log_line;
use crate::devices::DevicesHandle;

mod about;

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

/// How long a sender waits for the last word once every piece has gone: the receiver checks the
/// whole file and flushes it to disk first, which takes a while for a large file on a slow disk.
/// Longer than the two minutes a direct transfer waits for that word itself, so this never calls
/// a file lost that is still being confirmed.
const FINISHING: std::time::Duration = std::time::Duration::from_secs(150);

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
    /// The other device.
    pub device_id: [u8; 16],
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
    /// Files only on the local network, never through the relay.
    same_network_only: bool,
    /// Files being read and hashed before they are offered, with the device each goes to: a large
    /// file takes a while, and the device it is for shows that it is on its way.
    preparing: Vec<([u8; 16], PathBuf)>,
    /// Whether the relay has read this device's goodbye.
    leave_sent: bool,
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
    /// Going straight to the receiver on the local network, not through the relay.
    direct: bool,
    /// The receiver's connection when it was offered, and since when the receiver has not been
    /// on it: an offer to a device that went away is not left waiting for an answer forever.
    offered_to: String,
    gone_since: Option<Instant>,
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
    /// Coming straight from the sender on the local network, not through the relay.
    direct: bool,
    /// The person chose this exact name and agreed to replace a file already there.
    replace: bool,
    /// Since when the sender has not been on the connection it offered from.
    gone_since: Option<Instant>,
    /// The last acknowledgement, when it could not be sent: the sender waits for it, so it is
    /// sent again on the next tick rather than left to stall the transfer.
    owed_ack: Option<(u32, AckState)>,
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

    /// Tells the other devices this one is leaving the account, and waits up to `patience` for the
    /// relay to have read it. Returns whether it did.
    #[must_use]
    pub fn say_leaving(&self, patience: std::time::Duration) -> bool {
        let queued = self.0.lock().is_ok_and(|mut state| {
            state.leave_sent = false;
            about::say_leaving(&state)
        });
        if !queued {
            return false;
        }
        let until = Instant::now() + patience;
        while Instant::now() < until {
            if self.0.lock().is_ok_and(|state| state.leave_sent) {
                return true;
            }
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
        false
    }

    /// Asks one device which Asli it runs, saying which this one is.
    pub(crate) fn ask_version(&self, conn_id: &str) {
        if let Ok(state) = self.0.lock() {
            about::announce(&state, true, Some(conn_id));
        }
    }

    /// The relay read a message sent with `token`.
    pub(crate) fn sent(&self, token: u64) {
        if token == about::LEAVE_TOKEN {
            if let Ok(mut state) = self.0.lock() {
                state.leave_sent = true;
            }
        }
    }

    /// Keeps files to the local network, or lets them go through the relay when it cannot be used.
    pub fn set_same_network_only(&self, on: bool) {
        if let Ok(mut state) = self.0.lock() {
            state.same_network_only = on;
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
        // Tells the others which Asli this is, and asks the same of them.
        about::announce(&state, true, None);
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
            let limit = if u64::from(outgoing.next) >= outgoing.offer.chunk_count() {
                FINISHING
            } else {
                STALL
            };
            if matches!(outgoing.stage, Stage::Moving(_)) && now - outgoing.moved > limit {
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
        // An offer still waiting for an answer ends once the device at the other end has been
        // off the connection it was made on for a while: gone offline, or restarted, which ends
        // everything it had under way. Not checked while this device is offline itself, which
        // ends every offer on its own.
        if state
            .link
            .as_ref()
            .is_some_and(|link| link.conn_id.is_some())
        {
            let devices = &state.devices;
            for outgoing in state.sending.values_mut() {
                if outgoing.stage == Stage::Offered {
                    let here = devices.conn_of(&outgoing.offer.to_device_id);
                    if went_away(
                        here.as_deref(),
                        &outgoing.offered_to,
                        &mut outgoing.gone_since,
                        now,
                    ) {
                        outgoing.stage = Stage::Failed("the other device went offline.".to_owned());
                        gave_up = true;
                    }
                }
            }
            for incoming in state.receiving.values_mut() {
                if incoming.stage == Stage::Offered {
                    let here = devices.conn_of(&incoming.offer.from_device_id);
                    let offered_from = incoming.offer.reply_to.clone();
                    if went_away(
                        here.as_deref(),
                        &offered_from,
                        &mut incoming.gone_since,
                        now,
                    ) {
                        incoming.stage = Stage::Failed("the other device went offline.".to_owned());
                        gave_up = true;
                    }
                }
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
        for incoming in state.receiving.values_mut() {
            if let Some((received, ack)) = incoming.owed_ack {
                if send_ack(link, incoming, received, ack).is_ok() {
                    incoming.owed_ack = None;
                }
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
                        device_id: o.offer.to_device_id,
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
                        device_id: i.offer.from_device_id,
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

    /// How many files offered to this device wait for an answer.
    #[must_use]
    pub fn offers_waiting(&self) -> u32 {
        self.0.lock().map_or(0, |state| {
            let count = state
                .receiving
                .values()
                .filter(|i| i.stage == Stage::Offered)
                .count();
            u32::try_from(count).unwrap_or(u32::MAX)
        })
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
        let kept = path.clone();
        self.set_preparing(to, &path, true);
        let spawned = std::thread::Builder::new()
            .name("asli-hash".to_owned())
            .spawn(move || {
                let outcome = hash_file(&path).and_then(|hashed| {
                    // Called off while it was being read: it is not offered at all.
                    if !this.is_preparing(to, &path) {
                        return Ok(());
                    }
                    this.offer(path.clone(), to, &conn, &peer, hashed)
                });
                this.set_preparing(to, &path, false);
                if let Err(err) = outcome {
                    eprintln!("{}", log_line("file_offer_failed", &err));
                    crate::notify::file_failed(&display_name(&path), &err);
                }
            });
        if let Err(err) = spawned {
            self.set_preparing(to, &kept, false);
            return Err(err.to_string());
        }
        Ok(())
    }

    fn set_preparing(&self, to: [u8; 16], path: &Path, on: bool) {
        if let Ok(mut state) = self.0.lock() {
            if on {
                state.preparing.push((to, path.to_path_buf()));
            } else if let Some(at) = state
                .preparing
                .iter()
                .position(|(device, p)| *device == to && p == path)
            {
                state.preparing.remove(at);
            }
            state.revision += 1;
        }
    }

    fn is_preparing(&self, to: [u8; 16], path: &Path) -> bool {
        self.0.lock().is_ok_and(|state| {
            state
                .preparing
                .iter()
                .any(|(device, p)| *device == to && p == path)
        })
    }

    /// How many files are being read before they are offered, per device.
    #[must_use]
    pub fn preparing(&self) -> Vec<[u8; 16]> {
        self.0.lock().map_or_else(
            |_| Vec::new(),
            |state| state.preparing.iter().map(|(device, _)| *device).collect(),
        )
    }

    fn offer(
        &self,
        path: PathBuf,
        to: [u8; 16],
        conn: &str,
        peer: &str,
        (size, sha256): (u64, [u8; 32]),
    ) -> Result<(), String> {
        let mut state = self
            .0
            .lock()
            .map_err(|_| "Asli is shutting down.".to_owned())?;
        let link = state.link.as_ref().ok_or("Asli is not connected.")?;
        let reply_to = link.conn_id.clone().ok_or("Asli is not connected.")?;
        let offer_id: OfferId = asli_crypto::random::bytes().map_err(|e| e.to_string())?;
        // Listening starts now, so the address can go in the offer. The listener waits on this
        // lock, so it sees the transfer only once it is recorded below.
        let direct = state
            .devices
            .pinned()
            .into_iter()
            .find(|device| device.device_id == to)
            .and_then(|device| {
                let key = Zeroizing::new(asli_crypto::random::bytes::<32>().ok()?);
                let addrs = crate::direct::listen(self, offer_id, key.clone());
                if addrs.is_empty() {
                    return None;
                }
                Direct::new(addrs, &device.box_pub, &key).ok()
            });
        if direct.is_none() && state.same_network_only {
            return Err(format!(
                "{peer} can't be reached on this network, and Same Network Only is on."
            ));
        }
        let offer = Offer {
            offer_id,
            from_device_id: link.device_id,
            to_device_id: to,
            size,
            sha256,
            chunk_bytes: CHUNK_BYTES,
            ts_ms: asli_net::client::now_ms(),
            reply_to,
            name: truncate_name(&display_name(&path)),
            direct,
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
                direct: false,
                offered_to: conn.to_owned(),
                gone_since: None,
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
        let name = self
            .0
            .lock()
            .ok()
            .and_then(|state| state.receiving.get(id).map(|i| safe_name(&i.offer.name)))
            .ok_or("That file is no longer waiting.")?;
        self.accept_as(id, unique_path(folder, &name), false)
    }

    /// Accepts an offered file under the exact path the person chose in a save dialog. With
    /// `replace`, a file already there is replaced once this one has arrived and checked out,
    /// which the dialog asked them about.
    ///
    /// # Errors
    ///
    /// Returns a sentence for the person when there is no such offer waiting, or the folder cannot
    /// be written to.
    pub fn accept_as(
        &self,
        id: &OfferId,
        final_path: PathBuf,
        replace: bool,
    ) -> Result<(), String> {
        let folder = final_path
            .parent()
            .map(Path::to_path_buf)
            .unwrap_or_default();
        let mut state = self
            .0
            .lock()
            .map_err(|_| "Asli is shutting down.".to_owned())?;
        let State {
            link,
            receiving,
            same_network_only,
            ..
        } = &mut *state;
        let link = link.as_ref().ok_or("Asli is not connected.")?;
        let incoming = receiving
            .get_mut(id)
            .filter(|i| i.stage == Stage::Offered)
            .ok_or("That file is no longer waiting.")?;
        let part_path = part_path_for(&final_path);
        let file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&part_path)
            .map_err(|err| format!("Couldn't write to {}: {err}", folder.display()))?;
        // Straight from the sender if it is on this network, which is tried first; through the
        // relay otherwise, which needs the answer now.
        let direct = incoming.offer.direct.as_ref().and_then(|direct| {
            let key = direct.open_key(&link.keys()).ok()?;
            Some((direct.addrs.clone(), key))
        });
        if direct.is_none() && *same_network_only {
            drop(file);
            let _ = fs::remove_file(&part_path);
            return Err(
                "It can only come through the relay, and Same Network Only is on.".to_owned(),
            );
        }
        if direct.is_none() {
            if let Err(err) = answer(link, id, true, &incoming.offer.reply_to) {
                let _ = fs::remove_file(&part_path);
                return Err(err);
            }
        }
        incoming.part = Some((file, part_path, final_path));
        incoming.replace = replace;
        incoming.stage = Stage::Moving(0);
        incoming.moved = Instant::now();
        state.revision += 1;
        drop(state);

        if let Some((addrs, key)) = direct {
            let this = self.clone();
            let id = *id;
            std::thread::Builder::new()
                .name("asli-direct-fetch".to_owned())
                .spawn(move || {
                    if !crate::direct::fetch(&this, id, &key, &addrs) {
                        this.answer_through_relay(&id);
                    }
                })
                .map_err(|err| err.to_string())?;
        }
        Ok(())
    }

    /// The sender could not be reached on this network: asks for the file through the relay.
    fn answer_through_relay(&self, id: &OfferId) {
        let Ok(mut state) = self.0.lock() else {
            return;
        };
        let State {
            link,
            receiving,
            same_network_only,
            ..
        } = &mut *state;
        let Some(incoming) = receiving.get_mut(id) else {
            return;
        };
        if incoming.stage != Stage::Moving(0) || incoming.direct {
            return;
        }
        if *same_network_only {
            let reason = "it couldn't be reached on this network, and Same Network Only is on";
            match link.as_ref() {
                Some(link) => fail_incoming(link, incoming, reason),
                None => give_up_incoming(incoming, reason),
            }
            state.revision += 1;
            return;
        }
        let sent = link
            .as_ref()
            .ok_or_else(|| "Asli is not connected.".to_owned())
            .and_then(|link| answer(link, id, true, &incoming.offer.reply_to));
        if let Err(err) = sent {
            discard_part(incoming);
            incoming.stage = Stage::Failed(err);
        }
        state.revision += 1;
    }

    /// Whether a sender's listener should keep waiting for `id`.
    pub(crate) fn direct_waiting(&self, id: &OfferId) -> bool {
        self.0.lock().is_ok_and(|state| {
            state
                .sending
                .get(id)
                .is_some_and(|o| o.stage == Stage::Offered)
        })
    }

    /// The receiver reached this device directly. Returns the file and its offer to send, unless
    /// it was answered, called off or finished meanwhile.
    pub(crate) fn direct_begin(&self, id: &OfferId) -> Option<(PathBuf, Offer)> {
        let mut state = self.0.lock().ok()?;
        let outgoing = state.sending.get_mut(id)?;
        if outgoing.stage != Stage::Offered {
            return None;
        }
        outgoing.stage = Stage::Moving(0);
        outgoing.moved = Instant::now();
        outgoing.direct = true;
        let begun = (outgoing.path.clone(), outgoing.offer.clone());
        state.revision += 1;
        Some(begun)
    }

    /// `sent` pieces have gone. Returns false once the transfer was called off.
    pub(crate) fn direct_progress(&self, id: &OfferId, sent: u32) -> bool {
        let Ok(mut state) = self.0.lock() else {
            return false;
        };
        let Some(outgoing) = state.sending.get_mut(id) else {
            return false;
        };
        // Finished, or taken over by the relay.
        if outgoing.stage.finished() || !outgoing.direct {
            return false;
        }
        outgoing.acked = sent;
        outgoing.next = sent;
        outgoing.stage = Stage::Moving(sent);
        outgoing.moved = Instant::now();
        state.revision += 1;
        true
    }

    /// The receiver said how a direct transfer ended.
    pub(crate) fn direct_finished(&self, id: &OfferId, ended: AckState) {
        let Ok(mut state) = self.0.lock() else {
            return;
        };
        if let Some(outgoing) = state.sending.get_mut(id) {
            if !outgoing.stage.finished() && outgoing.direct {
                outgoing.stage = if ended == AckState::Done {
                    eprintln!(
                        "{}",
                        log_line("file_sent", &format!("{} bytes", outgoing.offer.size))
                    );
                    Stage::Done(None)
                } else {
                    Stage::Failed("it arrived damaged. Try again.".to_owned())
                };
            }
        }
        state.revision += 1;
    }

    /// A direct transfer from this device broke off.
    pub(crate) fn direct_failed(&self, id: &OfferId, reason: &str) {
        let Ok(mut state) = self.0.lock() else {
            return;
        };
        if let Some(outgoing) = state.sending.get_mut(id) {
            if !outgoing.stage.finished() && outgoing.direct {
                outgoing.stage = Stage::Failed(reason.to_owned());
            }
        }
        state.revision += 1;
    }

    /// The first piece came straight from the sender: the relay plays no part from here on.
    pub(crate) fn direct_receiving(&self, id: &OfferId) {
        if let Ok(mut state) = self.0.lock() {
            if let Some(incoming) = state.receiving.get_mut(id) {
                incoming.direct = true;
                incoming.moved = Instant::now();
            }
        }
    }

    /// Keeps a piece that came straight from the sender. Returns how the transfer ended once it
    /// has, and an error when it should stop: called off, or failed.
    pub(crate) fn direct_piece(&self, id: &OfferId, data: &[u8]) -> Result<Option<AckState>, ()> {
        let mut state = self.0.lock().map_err(|_| ())?;
        let incoming = state.receiving.get_mut(id).ok_or(())?;
        if !matches!(incoming.stage, Stage::Moving(_)) {
            return Err(());
        }
        let taken = take_piece(incoming, data);
        state.revision += 1;
        match taken {
            Ok(ended) => Ok(ended),
            Err(reason) => {
                if let Some(incoming) = state.receiving.get_mut(id) {
                    give_up_incoming(incoming, &reason);
                }
                Err(())
            }
        }
    }

    /// A direct transfer to this device broke off.
    pub(crate) fn direct_receive_failed(&self, id: &OfferId, reason: &str) {
        let Ok(mut state) = self.0.lock() else {
            return;
        };
        if let Some(incoming) = state.receiving.get_mut(id) {
            if !incoming.stage.finished() {
                give_up_incoming(incoming, reason);
            }
        }
        state.revision += 1;
    }

    /// Turns an offered file down.
    pub fn decline(&self, id: &OfferId) {
        let Ok(mut state) = self.0.lock() else {
            return;
        };
        let State {
            link, receiving, ..
        } = &mut *state;
        let Some(incoming) = receiving.get_mut(id) else {
            return;
        };
        if incoming.stage != Stage::Offered {
            return;
        }
        // Turned down here whatever happens. The sender is told when it can be; when it cannot,
        // its offer ends on its own once this device is gone from where it was asked.
        if let Some(link) = link.as_ref() {
            if let Err(err) = answer(link, id, false, &incoming.offer.reply_to) {
                eprintln!("{}", log_line("file_decline_unsent", &err));
            }
        }
        incoming.stage = Stage::Declined;
        state.revision += 1;
    }

    /// Calls off everything on its way to one device, and drops what is still being read for it.
    pub fn cancel_to(&self, device: &[u8; 16]) {
        let ids: Vec<OfferId> = self.0.lock().map_or_else(
            |_| Vec::new(),
            |mut state| {
                state.preparing.retain(|(to, _)| to != device);
                state
                    .sending
                    .values()
                    .filter(|o| o.offer.to_device_id == *device && !o.stage.finished())
                    .map(|o| o.offer.offer_id)
                    .collect()
            },
        );
        for id in ids {
            self.cancel(&id);
        }
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
    pub(crate) fn on_message(
        &self,
        kind: MsgKind,
        body: &[u8],
    ) -> Option<([u8; 16], String, String, u64)> {
        let Ok(mut state) = self.0.lock() else {
            return None;
        };
        let mut ask = None;
        match kind {
            MsgKind::FileOffer => ask = on_offer(&mut state, body),
            MsgKind::FileAnswer => on_answer(&mut state, body),
            MsgKind::FileChunk => on_chunk(&mut state, body),
            MsgKind::FileAck => on_ack(&mut state, body),
            MsgKind::FileCancel => on_cancel(&mut state, body),
            MsgKind::About => about::on_about(&state, body),
            MsgKind::Leave => about::on_leave(&mut state, body),
            _ => {}
        }
        state.revision += 1;
        ask
    }
}

/// Records a file offered to this device. Returns the sender's name, the file's name and its size,
/// to ask the person about.
fn on_offer(state: &mut State, body: &[u8]) -> Option<([u8; 16], String, String, u64)> {
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
    // Signed, but possibly old: a relay could hold on to an offer and send it again later, to
    // ask about a file that was settled long ago. Only one made recently, by the same rule as a
    // card, is asked about.
    let now_ms = asli_net::client::now_ms();
    let fresh = now_ms.saturating_sub(offer.ts_ms) <= asli_core::replay::DEFAULT_MAX_AGE_MS
        && offer.ts_ms.saturating_sub(now_ms) <= asli_core::replay::DEFAULT_FUTURE_SKEW_MS;
    // Nor is one made on a connection the sender is known to have left: answered, it would go
    // nowhere. When where the sender is now is not known yet, the offer is believed.
    let moved_on = state
        .devices
        .conn_of(&from)
        .is_some_and(|conn| conn != offer.reply_to);
    if !fresh || moved_on {
        eprintln!(
            "{}",
            log_line("file_offer_stale", "an old offer arrived again; ignored")
        );
        return None;
    }
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
            direct: false,
            replace: false,
            gone_since: None,
            owed_ack: None,
        },
    );
    Some((from, peer, name, size))
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
    // The receiver asks through the relay only when nothing reached it directly, so an answer
    // arriving while this device is sending directly means the direct path is not getting
    // through: the relay takes the transfer over from the start, and the direct send stops.
    let taking_over = outgoing.direct && !outgoing.stage.finished();
    // Only the device it was offered to may answer.
    if outgoing.offer.to_device_id != answer.from_device_id
        || !(outgoing.stage == Stage::Offered || taking_over)
    {
        return;
    }
    if taking_over {
        eprintln!(
            "{}",
            log_line(
                "file_direct_abandoned",
                "the receiver asked through the relay"
            )
        );
        outgoing.direct = false;
        outgoing.next = 0;
        outgoing.acked = 0;
    }
    if !answer.accepted {
        outgoing.stage = Stage::Declined;
        return;
    }
    if state.same_network_only {
        outgoing.stage = Stage::Failed(
            "it couldn't be reached on this network, and Same Network Only is on.".to_owned(),
        );
        let cancel = Cancel {
            offer_id: answer.offer_id,
        };
        let _ = send_msg(link, MsgKind::FileCancel, cancel.encode(), &answer.reply_to);
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
        if !pace.take(piece_len(&outgoing.offer, outgoing.next), Instant::now()) {
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
    if !matches!(incoming.stage, Stage::Moving(_))
        || incoming.direct
        || chunk.index != incoming.received
    {
        return;
    }
    let ended = match take_piece(incoming, &chunk.data) {
        Ok(ended) => ended,
        Err(reason) => {
            fail_incoming(link, incoming, &reason);
            return;
        }
    };
    let state = ended.unwrap_or(AckState::Receiving);
    incoming.owed_ack = send_ack(link, incoming, incoming.received, state)
        .err()
        .map(|()| (incoming.received, state));
}

/// Tells the sender how far a relayed file has got.
fn send_ack(link: &Link, incoming: &Incoming, received: u32, state: AckState) -> Result<(), ()> {
    let ack = Ack {
        offer_id: incoming.offer.offer_id,
        received,
        state,
    };
    send_msg(
        link,
        MsgKind::FileAck,
        ack.encode(),
        &incoming.offer.reply_to,
    )
    .map_err(|_| ())
}

/// Writes the next piece, by whichever way it came. Returns how the transfer ended once the last
/// piece is in, and why it cannot go on otherwise.
fn take_piece(incoming: &mut Incoming, data: &[u8]) -> Result<Option<AckState>, String> {
    if data.len() != piece_len(&incoming.offer, incoming.received)
        || u64::from(incoming.received) >= incoming.offer.chunk_count()
    {
        return Err("a piece arrived the wrong size".to_owned());
    }
    let (file, _, _) = incoming
        .part
        .as_mut()
        .ok_or_else(|| "it was called off".to_owned())?;
    file.write_all(data)
        .map_err(|err| format!("couldn't write the file: {err}"))?;
    incoming.hasher.update(data);
    incoming.received += 1;
    incoming.moved = Instant::now();
    incoming.written += data.len() as u64;
    if u64::from(incoming.received) == incoming.offer.chunk_count() {
        Ok(Some(finish_incoming(incoming)))
    } else {
        incoming.stage = Stage::Moving(incoming.received);
        Ok(None)
    }
}

/// Checks a fully arrived file against its offer, and keeps it or throws it away.
fn finish_incoming(incoming: &mut Incoming) -> AckState {
    let digest: [u8; 32] = std::mem::take(&mut incoming.hasher).finalize().into();
    let Some((file, part, final_path)) = incoming.part.take() else {
        return AckState::Corrupt;
    };
    let synced = file.sync_all();
    drop(file);
    if digest != incoming.offer.sha256 || incoming.written != incoming.offer.size {
        let _ = fs::remove_file(&part);
        incoming.stage = Stage::Failed("it arrived damaged, so it was thrown away".to_owned());
        crate::notify::file_failed(&safe_name(&incoming.offer.name), "it arrived damaged");
        return AckState::Corrupt;
    }
    // Arrived whole, but the disk would not take it: a full disk, or one that went away.
    if let Err(err) = synced {
        let _ = fs::remove_file(&part);
        incoming.stage = Stage::Failed(format!("it couldn't be written to disk: {err}"));
        crate::notify::file_failed(
            &safe_name(&incoming.offer.name),
            &format!("it couldn't be written to disk: {err}"),
        );
        return AckState::Corrupt;
    }
    // Checked again at the rename: something with the same name may have appeared meanwhile. Its
    // own temporary file is still there, so the name chosen at the start is checked on its own.
    let folder = final_path
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_default();
    let target = if final_path.exists() && !incoming.replace {
        unique_path(&folder, &safe_name(&incoming.offer.name))
    } else {
        final_path
    };
    if let Err(err) = fs::rename(&part, &target) {
        let _ = fs::remove_file(&part);
        incoming.stage = Stage::Failed(format!("couldn't keep it: {err}"));
        crate::notify::file_failed(
            &safe_name(&incoming.offer.name),
            &format!("it couldn't be kept: {err}"),
        );
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

/// Gives up on a file coming to this device, without telling the sender.
fn give_up_incoming(incoming: &mut Incoming, reason: &str) {
    discard_part(incoming);
    incoming.stage = Stage::Failed(reason.to_owned());
    crate::notify::file_failed(&safe_name(&incoming.offer.name), reason);
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

/// How long the device at the other end of a waiting offer may be off its connection before the
/// offer ends. Long enough to ride out the moment after any device leaves, when the others count
/// as offline until they announce themselves again.
const GONE: std::time::Duration = std::time::Duration::from_secs(20);

/// Whether the device at the other end of an offer has been off the connection the offer belongs
/// to for longer than [`GONE`], keeping track of since when in `gone_since`.
fn went_away(
    here: Option<&str>,
    offered_on: &str,
    gone_since: &mut Option<Instant>,
    now: Instant,
) -> bool {
    if here == Some(offered_on) {
        *gone_since = None;
        return false;
    }
    let since = *gone_since.get_or_insert(now);
    now.duration_since(since) > GONE
}

fn fail_all_live(state: &mut State, reason: &str) {
    // A direct transfer does not go through the relay, so it carries on without it.
    for outgoing in state.sending.values_mut() {
        if !outgoing.stage.finished() && !outgoing.direct {
            outgoing.stage = Stage::Failed(reason.to_owned());
        }
    }
    for incoming in state.receiving.values_mut() {
        if !incoming.stage.finished() && !incoming.direct {
            discard_part(incoming);
            incoming.stage = Stage::Failed(reason.to_owned());
        }
    }
    state.revision += 1;
}

/// Sends this device's signed answer to an offer.
fn answer(link: &Link, id: &OfferId, accepted: bool, to: &str) -> Result<(), String> {
    let body = Answer {
        offer_id: *id,
        from_device_id: link.device_id,
        accepted,
        reply_to: link.conn_id.clone().ok_or("Asli is not connected.")?,
    }
    .encode(&link.keys(), &link.room)
    .map_err(|e| e.to_string())?;
    send_msg(link, MsgKind::FileAnswer, body, to)
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
pub(crate) fn piece_len(offer: &Offer, index: u32) -> usize {
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
    // Windows reserves these device names, whatever follows the first dot, with spaces before it
    // ignored, and counts the superscript digits after COM and LPT as digits.
    let stem = name
        .split('.')
        .next()
        .unwrap_or("")
        .trim_end()
        .to_ascii_uppercase();
    let numbered = |prefix: &str| {
        stem.strip_prefix(prefix).is_some_and(|rest| {
            let mut chars = rest.chars();
            matches!(
                (chars.next(), chars.next()),
                (Some('0'..='9' | '\u{b9}' | '\u{b2}' | '\u{b3}'), None)
            )
        })
    };
    let reserved = matches!(stem.as_str(), "CON" | "PRN" | "AUX" | "NUL")
        || numbered("COM")
        || numbered("LPT");
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
    // None of these stops the file being kept; a mark that could not be set is logged. It cannot
    // be on some disks at all: FAT and exFAT hold no Zone.Identifier stream.
    let failed = |what: &str, why: String| {
        eprintln!(
            "{}",
            log_line("mark_downloaded_failed", &format!("{what}: {why}"))
        );
    };
    #[cfg(target_os = "windows")]
    {
        let mut stream = path.as_os_str().to_owned();
        stream.push(":Zone.Identifier");
        if let Err(err) = fs::write(PathBuf::from(stream), b"[ZoneTransfer]\r\nZoneId=3\r\n") {
            failed("Zone.Identifier", err.to_string());
        }
    }
    #[cfg(target_os = "macos")]
    {
        let value = format!("0081;{:x};Asli;", asli_net::client::now_ms() / 1000);
        match std::process::Command::new("/usr/bin/xattr")
            .args(["-w", "com.apple.quarantine", &value])
            .arg(path)
            .output()
        {
            Ok(out) if out.status.success() => {}
            Ok(out) => failed(
                "quarantine",
                String::from_utf8_lossy(&out.stderr).trim().to_owned(),
            ),
            Err(err) => failed("quarantine", err.to_string()),
        }
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        if let Err(err) = fs::set_permissions(path, fs::Permissions::from_mode(0o644)) {
            failed("permissions", err.to_string());
        }
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

    #[test]
    fn an_offer_ends_only_once_the_other_device_has_been_gone_a_while() {
        let start = Instant::now();
        let mut gone = None;
        // On its connection: nothing happens.
        assert!(!went_away(Some("c_1"), "c_1", &mut gone, start));
        assert!(gone.is_none());
        // Off it, briefly, as in the moment after another device leaves: not yet.
        assert!(!went_away(None, "c_1", &mut gone, start));
        assert!(!went_away(None, "c_1", &mut gone, start + GONE / 2));
        // Back on it: the clock starts over.
        assert!(!went_away(Some("c_1"), "c_1", &mut gone, start + GONE / 2));
        assert!(gone.is_none());
        // Restarted, so on a different connection, for longer than the grace: it ends.
        let later = start + GONE;
        assert!(!went_away(Some("c_2"), "c_1", &mut gone, later));
        assert!(went_away(
            Some("c_2"),
            "c_1",
            &mut gone,
            later + GONE + std::time::Duration::from_secs(1)
        ));
    }
    use super::*;

    #[test]
    fn a_name_from_another_device_cannot_escape_its_folder_or_hide() {
        for (given, kept) in [
            ("report.pdf", "report.pdf"),
            ("../../.config/autostart/evil.desktop", "evil.desktop"),
            ("COM\u{b9}.txt", "_COM\u{b9}.txt"),
            ("lpt3.log", "_lpt3.log"),
            ("con .txt", "_con .txt"),
            ("COM10.txt", "COM10.txt"),
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
            direct: None,
        };
        assert_eq!(piece_len(&offer, 0), CHUNK_BYTES as usize);
        assert_eq!(piece_len(&offer, 2), 10);
        assert_eq!(offer.chunk_count(), 3);
    }
}
