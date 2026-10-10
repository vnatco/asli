//! The shelf: files this device keeps on offer to the account's other devices, and what is on
//! theirs.
//!
//! A shelved file stays where it is on disk; only its path is remembered, in `shelf.json`. Taking
//! it off the shelf, by hand or when it expires, forgets the path and never touches the file. A
//! device that wants an item asks for it under an offer id of its own choosing, and the file comes
//! as an ordinary transfer that it accepts without asking the person again, since they just did.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use asli_crypto::shelf::{self as wire, Action, Item, List, Request, ITEM_ID_LEN, MAX_ITEMS};
use asli_net::client::{now_ms, LocalEvent, MsgKind};

use super::{
    display_name, send_msg, truncate_name, Link, OfferId, State, Transfers, MAX_FILE_BYTES,
};
use crate::clipboard_io::log_line;

/// How long a file stays on the shelf.
pub const KEEP_FOR_MS: u64 = 24 * 60 * 60 * 1000;

/// An item on this device's shelf, as `shelf.json` keeps it.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct Mine {
    /// Its item id, in hex.
    id: String,
    path: PathBuf,
    name: String,
    size: u64,
    expires_ms: u64,
}

/// The shelf's part of the transfer state.
#[derive(Debug, Default)]
pub(super) struct Shelf {
    /// Where this device's shelf is kept.
    file: Option<PathBuf>,
    mine: Vec<Mine>,
    /// The latest list heard from each other device.
    theirs: HashMap<[u8; 16], List>,
    /// Offers this device asked for, by offer id, with the device asked.
    wanted: HashMap<OfferId, [u8; 16]>,
}

impl Shelf {
    /// Drops what a device that left had on its shelf.
    pub(super) fn forget_device(&mut self, device: &[u8; 16]) {
        self.theirs.remove(device);
    }
}

/// One item, as the window and the command line show it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Shelved {
    /// The device it is on, or `None` for this one.
    pub device_id: Option<[u8; 16]>,
    /// That device's name.
    pub device: String,
    /// The item.
    pub item_id: [u8; ITEM_ID_LEN],
    /// Its name.
    pub name: String,
    /// Its size.
    pub size: u64,
    /// When it comes off the shelf by itself.
    pub expires_ms: u64,
}

impl Transfers {
    /// Loads this device's shelf from `file`, leaving out what expired or no longer exists.
    pub(crate) fn load_shelf(&self, file: PathBuf) {
        let mine: Vec<Mine> = std::fs::read(&file)
            .ok()
            .and_then(|bytes| serde_json::from_slice(&bytes).ok())
            .unwrap_or_default();
        let now = now_ms();
        if let Ok(mut state) = self.0.lock() {
            state.shelf.mine = mine
                .into_iter()
                .filter(|m| m.expires_ms > now && m.path.is_file())
                .collect();
            state.shelf.file = Some(file);
            save(&state.shelf);
        }
    }

    /// Puts a file on this device's shelf for a day.
    ///
    /// # Errors
    ///
    /// Returns a sentence for the person when the file cannot be read, is too large, or the shelf
    /// is full.
    pub fn shelve(&self, path: &Path) -> Result<(), String> {
        let metadata =
            std::fs::metadata(path).map_err(|err| format!("Couldn't read the file: {err}"))?;
        if !metadata.is_file() {
            return Err("Only files can go on the shelf, not folders.".to_owned());
        }
        if metadata.len() > MAX_FILE_BYTES {
            return Err("That file is larger than 4 GB, the most Asli sends.".to_owned());
        }
        let path = std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
        let id: [u8; ITEM_ID_LEN] = asli_crypto::random::bytes().map_err(|e| e.to_string())?;
        let mut state = self
            .0
            .lock()
            .map_err(|_| "Asli is shutting down.".to_owned())?;
        if state.shelf.mine.iter().any(|m| m.path == path) {
            return Err("That file is on the shelf already.".to_owned());
        }
        if state.shelf.mine.len() >= MAX_ITEMS {
            return Err(format!(
                "The shelf holds {MAX_ITEMS} files. Take one off first."
            ));
        }
        state.shelf.mine.push(Mine {
            id: crate::config::hex(&id),
            name: truncate_name(&display_name(&path)),
            path,
            size: metadata.len(),
            expires_ms: now_ms() + KEEP_FOR_MS,
        });
        changed(&mut state);
        Ok(())
    }

    /// Takes an item off this device's shelf. The file itself stays where it is.
    pub fn unshelve(&self, item: &[u8; ITEM_ID_LEN]) {
        if let Ok(mut state) = self.0.lock() {
            let hex = crate::config::hex(item);
            let before = state.shelf.mine.len();
            state.shelf.mine.retain(|m| m.id != hex);
            if state.shelf.mine.len() != before {
                changed(&mut state);
            }
        }
    }

    /// What is on this device's shelf, and on the shelves of the devices connected now.
    #[must_use]
    pub fn shelf(&self) -> (Vec<Shelved>, Vec<Shelved>) {
        let Ok(state) = self.0.lock() else {
            return (Vec::new(), Vec::new());
        };
        let now = now_ms();
        let mine = state
            .shelf
            .mine
            .iter()
            .filter_map(|m| {
                Some(Shelved {
                    device_id: None,
                    device: "This device".to_owned(),
                    item_id: crate::devices::id_bytes(&m.id)?,
                    name: m.name.clone(),
                    size: m.size,
                    expires_ms: m.expires_ms,
                })
            })
            .collect();
        let mut theirs: Vec<Shelved> = state
            .shelf
            .theirs
            .iter()
            .filter(|(device, _)| state.devices.conn_of(device).is_some())
            .flat_map(|(device, list)| {
                let name = state
                    .devices
                    .name_of(device)
                    .unwrap_or_else(|| "Another device".to_owned());
                list.items
                    .iter()
                    .filter(move |item| item.expires_ms > now)
                    .map(move |item| Shelved {
                        device_id: Some(*device),
                        device: name.clone(),
                        item_id: item.item_id,
                        name: super::safe_name(&item.name),
                        size: item.size,
                        expires_ms: item.expires_ms,
                    })
            })
            .collect();
        theirs.sort_by(|a, b| a.device.cmp(&b.device).then(a.name.cmp(&b.name)));
        (mine, theirs)
    }

    /// Asks `device` for an item on its shelf. It arrives as a transfer, accepted without asking,
    /// into the downloads folder.
    ///
    /// # Errors
    ///
    /// Returns a sentence for the person when the device is not connected.
    pub fn take(&self, device: [u8; 16], item: [u8; ITEM_ID_LEN]) -> Result<(), String> {
        let want_id: OfferId = asli_crypto::random::bytes().map_err(|e| e.to_string())?;
        let mut state = self
            .0
            .lock()
            .map_err(|_| "Asli is shutting down.".to_owned())?;
        request(&state, device, Action::Send, item, want_id)?;
        state.shelf.wanted.insert(want_id, device);
        Ok(())
    }

    /// Asks `device` to take an item off its shelf. The file stays on that device.
    ///
    /// # Errors
    ///
    /// Returns a sentence for the person when the device is not connected.
    pub fn take_off(&self, device: [u8; 16], item: [u8; ITEM_ID_LEN]) -> Result<(), String> {
        let state = self
            .0
            .lock()
            .map_err(|_| "Asli is shutting down.".to_owned())?;
        request(&state, device, Action::Remove, item, [0u8; 16])
    }
}

/// Saves this device's shelf, tells the other devices, and redraws.
fn changed(state: &mut State) {
    save(&state.shelf);
    announce(state, false, None);
    state.revision += 1;
}

fn save(shelf: &Shelf) {
    if let Some(file) = &shelf.file {
        if let Ok(bytes) = serde_json::to_vec_pretty(&shelf.mine) {
            let _ = crate::config::write_atomically(file, &bytes, 0o600);
        }
    }
}

/// Tells the room, or one connection, what is on this device's shelf. With `ask`, also asks every
/// device for its own.
pub(super) fn announce(state: &State, ask: bool, to: Option<&str>) {
    let Some(link) = state.link.as_ref() else {
        return;
    };
    let Some(reply_to) = link.conn_id.clone() else {
        return;
    };
    let items = state
        .shelf
        .mine
        .iter()
        .filter_map(|m| {
            Some(Item {
                item_id: crate::devices::id_bytes(&m.id)?,
                size: m.size,
                expires_ms: m.expires_ms,
                name: m.name.clone(),
            })
        })
        .collect();
    let list = List {
        from_device_id: link.device_id,
        ts_ms: now_ms(),
        ask,
        reply_to,
        items,
    };
    let Ok(body) = list.encode(&link.keys(), &link.room) else {
        return;
    };
    let _ = match to {
        Some(to) => send_msg(link, MsgKind::ShelfList, body, to),
        None => broadcast(link, MsgKind::ShelfList, body),
    };
}

fn broadcast(link: &Link, kind: MsgKind, body: Vec<u8>) -> Result<(), String> {
    link.tx
        .try_send(LocalEvent::Message {
            kind,
            body,
            to: None,
            token: None,
        })
        .map_err(|_| "Asli is busy. Try again in a moment.".to_owned())
}

fn request(
    state: &State,
    device: [u8; 16],
    action: Action,
    item_id: [u8; ITEM_ID_LEN],
    want_id: OfferId,
) -> Result<(), String> {
    let link = state.link.as_ref().ok_or("Asli is not connected.")?;
    let name = state
        .devices
        .name_of(&device)
        .unwrap_or_else(|| "That device".to_owned());
    let conn = state
        .devices
        .conn_of(&device)
        .ok_or_else(|| format!("{name} is not connected right now."))?;
    let body = Request {
        from_device_id: link.device_id,
        action,
        item_id,
        want_id,
        reply_to: link.conn_id.clone().ok_or("Asli is not connected.")?,
    }
    .encode(&link.keys(), &link.room)
    .map_err(|e| e.to_string())?;
    send_msg(link, MsgKind::ShelfRequest, body, &conn)
}

/// The key pinned for whichever device a shelf message says it is from.
fn pinned_key(state: &State, body: &[u8]) -> Option<[u8; 32]> {
    let from = wire::claimed_sender(body).ok()?;
    state
        .devices
        .pinned()
        .into_iter()
        .find(|device| device.device_id == from)
        .map(|device| device.sign_pub)
}

/// Another device's shelf. Answers with this device's own when it asks.
pub(super) fn on_list(state: &mut State, body: &[u8]) {
    let Some(link) = state.link.as_ref() else {
        return;
    };
    let Some(sign_pub) = pinned_key(state, body) else {
        return;
    };
    let Ok(list) = List::decode(body, &link.room, &sign_pub) else {
        return;
    };
    if list.from_device_id == link.device_id {
        return;
    }
    if list.ask {
        announce(state, false, Some(&list.reply_to));
    }
    let newer = state
        .shelf
        .theirs
        .get(&list.from_device_id)
        .is_none_or(|known| known.ts_ms < list.ts_ms);
    if newer {
        state.shelf.theirs.insert(list.from_device_id, list);
    }
}

/// Another device asked for something on this device's shelf. Returns the file to send it, and the
/// offer id it asked for, when it asked for a file.
pub(super) fn on_request(state: &mut State, body: &[u8]) -> Option<(PathBuf, [u8; 16], OfferId)> {
    let link = state.link.as_ref()?;
    let sign_pub = pinned_key(state, body)?;
    let request = Request::decode(body, &link.room, &sign_pub).ok()?;
    let hex = crate::config::hex(&request.item_id);
    let now = now_ms();
    let item = state
        .shelf
        .mine
        .iter()
        .find(|m| m.id == hex && m.expires_ms > now)?;
    match request.action {
        Action::Send => {
            eprintln!(
                "{}",
                log_line("shelf_taken", &format!("{} bytes", item.size))
            );
            Some((item.path.clone(), request.from_device_id, request.want_id))
        }
        Action::Remove => {
            state.shelf.mine.retain(|m| m.id != hex);
            changed(state);
            None
        }
    }
}

/// Whether an offer is one this device asked for, from the device it asked.
pub(super) fn was_wanted(state: &mut State, offer_id: &OfferId, from: &[u8; 16]) -> bool {
    if state.shelf.wanted.get(offer_id) == Some(from) {
        state.shelf.wanted.remove(offer_id);
        return true;
    }
    false
}

/// Takes what expired off this device's shelf.
pub(super) fn expire(state: &mut State) {
    let now = now_ms();
    let before = state.shelf.mine.len();
    state.shelf.mine.retain(|m| m.expires_ms > now);
    if state.shelf.mine.len() != before {
        changed(state);
    }
}
