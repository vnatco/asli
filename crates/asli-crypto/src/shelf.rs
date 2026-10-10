//! The shelf: files a device keeps on offer to the account's other devices, until it takes them off
//! or they expire.
//!
//! The files stay on the device that shelved them. It tells the others what is on its shelf, and
//! any of them can ask for an item, which then comes as an ordinary file transfer
//! (see [`crate::file`]) under the id the asker chose, so the asker knows it asked for it.
//!
//! ```text
//! list    = u8(1) || from_device_id[16] || u64be(ts_ms) || u8(ask) || text(reply_to) || u8(count)
//!           || count * ( item_id[16] || u64be(size) || u64be(expires_ms)
//!                        || u16be(name_len) || name )
//!           || signature, label "asli/v2/shelf-list"
//! request = u8(1) || from_device_id[16] || u8(action) || item_id[16] || want_id[16]
//!           || text(reply_to) || signature, label "asli/v2/shelf-request"
//! ```
//!
//! A list with `ask` set also asks every device that hears it for its own list, which is how a
//! device that just connected learns what the others hold. `action` is 1 to have the item sent and
//! 2 to take it off the shelf. Both are signed, and believed only from a device whose key is pinned.

use crate::clip::DEVICE_ID_LEN;
use crate::device::DeviceKeys;
use crate::error::{Error, Result};
use crate::file::{sign, verify, version, MAX_NAME_BYTES, OFFER_ID_LEN};
use crate::identity::{PUB_KEY_LEN, ROOM_ID_LEN, SIGNATURE_LEN};
use crate::msg::{Reader, Writer};

/// Most items one shelf holds.
pub const MAX_ITEMS: usize = 32;
/// Length of an item id.
pub const ITEM_ID_LEN: usize = 16;

const LABEL_LIST: &[u8] = b"asli/v2/shelf-list";
const LABEL_REQUEST: &[u8] = b"asli/v2/shelf-request";

/// One file on a shelf.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Item {
    /// Chosen by the device that shelved it.
    pub item_id: [u8; ITEM_ID_LEN],
    /// Its size in bytes.
    pub size: u64,
    /// When it comes off the shelf by itself, by the shelving device's clock.
    pub expires_ms: u64,
    /// Its name. Untrusted, as in an offer.
    pub name: String,
}

/// What is on one device's shelf.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct List {
    /// The device whose shelf it is.
    pub from_device_id: [u8; DEVICE_ID_LEN],
    /// When it was made, so an older list never replaces a newer one.
    pub ts_ms: u64,
    /// Whether the device also asks for everyone else's list.
    pub ask: bool,
    /// Its connection, for replies.
    pub reply_to: String,
    /// The items.
    pub items: Vec<Item>,
}

impl List {
    /// Encodes and signs the list.
    ///
    /// # Errors
    ///
    /// Returns [`Error::AnnounceField`] for too many items, a name too long, or a connection id
    /// too long.
    pub fn encode(&self, keys: &DeviceKeys, room: &[u8; ROOM_ID_LEN]) -> Result<Vec<u8>> {
        let count = u8::try_from(self.items.len()).map_err(|_| Error::AnnounceField)?;
        if self.items.len() > MAX_ITEMS {
            return Err(Error::AnnounceField);
        }
        let mut body = Writer::default();
        body.u8(1)
            .bytes(&self.from_device_id)
            .u64(self.ts_ms)
            .u8(u8::from(self.ask));
        body.text(&self.reply_to)?;
        body.u8(count);
        for item in &self.items {
            let name = item.name.as_bytes();
            if name.len() > MAX_NAME_BYTES {
                return Err(Error::AnnounceField);
            }
            let name_len = u16::try_from(name.len()).map_err(|_| Error::AnnounceField)?;
            body.bytes(&item.item_id)
                .u64(item.size)
                .u64(item.expires_ms)
                .bytes(&name_len.to_be_bytes())
                .bytes(name);
        }
        Ok(sign(keys, LABEL_LIST, room, body))
    }

    /// Decodes a list, checking it was signed by `sign_pub`, the key pinned for its sender.
    ///
    /// # Errors
    ///
    /// Returns an error for a malformed list or one not signed by that key.
    pub fn decode(
        body: &[u8],
        room: &[u8; ROOM_ID_LEN],
        sign_pub: &[u8; PUB_KEY_LEN],
    ) -> Result<Self> {
        verify(LABEL_LIST, room, body, sign_pub)?;
        let mut r = Reader::new(&body[..body.len() - SIGNATURE_LEN]);
        version(&mut r)?;
        let from_device_id = r.array()?;
        let ts_ms = r.u64()?;
        let ask = match r.u8()? {
            0 => false,
            1 => true,
            _ => return Err(Error::InnerMalformed),
        };
        let reply_to = r.text()?;
        let count = usize::from(r.u8()?);
        if count > MAX_ITEMS {
            return Err(Error::AnnounceField);
        }
        let mut items = Vec::with_capacity(count);
        for _ in 0..count {
            let item_id = r.array()?;
            let size = r.u64()?;
            let expires_ms = r.u64()?;
            let len = usize::from(u16::from_be_bytes(r.array()?));
            if len > MAX_NAME_BYTES {
                return Err(Error::AnnounceField);
            }
            let name = std::str::from_utf8(r.bytes(len)?)
                .map_err(|_| Error::NotUtf8)?
                .to_owned();
            items.push(Item {
                item_id,
                size,
                expires_ms,
                name,
            });
        }
        r.done()?;
        Ok(Self {
            from_device_id,
            ts_ms,
            ask,
            reply_to,
            items,
        })
    }
}

/// What a device asks of another's shelf.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    /// Send me this item.
    Send,
    /// Take this item off your shelf.
    Remove,
}

/// A request for an item on another device's shelf.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request {
    /// The device asking.
    pub from_device_id: [u8; DEVICE_ID_LEN],
    /// What it asks.
    pub action: Action,
    /// The item.
    pub item_id: [u8; ITEM_ID_LEN],
    /// For [`Action::Send`], the offer id the file is to come under, so the asker knows it.
    pub want_id: [u8; OFFER_ID_LEN],
    /// The asker's connection.
    pub reply_to: String,
}

impl Request {
    /// Encodes and signs the request.
    ///
    /// # Errors
    ///
    /// Returns [`Error::AnnounceField`] for a connection id that is too long.
    pub fn encode(&self, keys: &DeviceKeys, room: &[u8; ROOM_ID_LEN]) -> Result<Vec<u8>> {
        let action = match self.action {
            Action::Send => 1,
            Action::Remove => 2,
        };
        let mut body = Writer::default();
        body.u8(1)
            .bytes(&self.from_device_id)
            .u8(action)
            .bytes(&self.item_id)
            .bytes(&self.want_id);
        body.text(&self.reply_to)?;
        Ok(sign(keys, LABEL_REQUEST, room, body))
    }

    /// Decodes a request, checking it was signed by `sign_pub`.
    ///
    /// # Errors
    ///
    /// Returns an error for a malformed request or one not signed by that key.
    pub fn decode(
        body: &[u8],
        room: &[u8; ROOM_ID_LEN],
        sign_pub: &[u8; PUB_KEY_LEN],
    ) -> Result<Self> {
        verify(LABEL_REQUEST, room, body, sign_pub)?;
        let mut r = Reader::new(&body[..body.len() - SIGNATURE_LEN]);
        version(&mut r)?;
        let from_device_id = r.array()?;
        let action = match r.u8()? {
            1 => Action::Send,
            2 => Action::Remove,
            _ => return Err(Error::InnerMalformed),
        };
        let request = Self {
            from_device_id,
            action,
            item_id: r.array()?,
            want_id: r.array()?,
            reply_to: r.text()?,
        };
        r.done()?;
        Ok(request)
    }
}

/// The device a list or a request says it is from, read before anything is checked, so the
/// receiver can look up the key that device pinned.
///
/// # Errors
///
/// Returns [`Error::InnerMalformed`] for a body too short to say.
pub fn claimed_sender(body: &[u8]) -> Result<[u8; DEVICE_ID_LEN]> {
    let mut r = Reader::new(body);
    version(&mut r)?;
    r.array()
}

#[cfg(test)]
mod tests {
    use super::*;

    const ROOM: [u8; ROOM_ID_LEN] = [9u8; ROOM_ID_LEN];

    fn list() -> List {
        List {
            from_device_id: [1u8; 16],
            ts_ms: 1000,
            ask: true,
            reply_to: "c_0011aabb".to_owned(),
            items: vec![
                Item {
                    item_id: [2u8; 16],
                    size: 12_345,
                    expires_ms: 90_000,
                    name: "slides.key".to_owned(),
                },
                Item {
                    item_id: [3u8; 16],
                    size: 0,
                    expires_ms: 90_000,
                    name: "empty.txt".to_owned(),
                },
            ],
        }
    }

    #[test]
    fn a_list_round_trips_signed_by_its_device_only() {
        let owner = DeviceKeys::from_secret(&[1u8; 32]);
        let other = DeviceKeys::from_secret(&[2u8; 32]);
        let body = list().encode(&owner, &ROOM).expect("encodes");
        assert_eq!(claimed_sender(&body).expect("names"), [1u8; 16]);
        assert_eq!(
            List::decode(&body, &ROOM, &owner.sign_pub()).expect("decodes"),
            list()
        );
        assert!(List::decode(&body, &ROOM, &other.sign_pub()).is_err());
        assert!(List::decode(&body, &[8u8; ROOM_ID_LEN], &owner.sign_pub()).is_err());
    }

    #[test]
    fn a_request_round_trips_and_cannot_pass_as_a_list() {
        let asker = DeviceKeys::from_secret(&[3u8; 32]);
        let request = Request {
            from_device_id: [3u8; 16],
            action: Action::Remove,
            item_id: [2u8; 16],
            want_id: [7u8; 16],
            reply_to: "c_99887766".to_owned(),
        };
        let body = request.encode(&asker, &ROOM).expect("encodes");
        assert_eq!(claimed_sender(&body).expect("names"), [3u8; 16]);
        assert_eq!(
            Request::decode(&body, &ROOM, &asker.sign_pub()).expect("decodes"),
            request
        );
        assert!(List::decode(&body, &ROOM, &asker.sign_pub()).is_err());
    }

    #[test]
    fn a_shelf_holds_at_most_its_limit() {
        let owner = DeviceKeys::from_secret(&[1u8; 32]);
        let mut full = list();
        full.items = vec![full.items[0].clone(); MAX_ITEMS + 1];
        assert!(full.encode(&owner, &ROOM).is_err());
    }
}
