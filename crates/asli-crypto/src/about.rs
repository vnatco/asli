//! Which version of Asli a device runs, so the others can show it and say when one is behind.
//!
//! ```text
//! about = u8(1) || from_device_id[16] || u8(ask) || text(reply_to) || u32be(build)
//!         || text(version) || signature, label "asli/v2/about"
//! ```
//!
//! A device sends one to the room when it connects, with `ask` set, and every device that hears
//! that answers with its own to `reply_to` alone. `build` is the number of commits the build came
//! from, higher meaning newer, and 0 when unknown. Believed only from a device whose key is pinned.
//!
//! A device leaving the account, to join another, says goodbye the same way, so the others take it
//! off their lists:
//!
//! ```text
//! leave = u8(1) || from_device_id[16] || u64be(ts_ms) || signature, label "asli/v2/leave"
//! ```

use crate::clip::DEVICE_ID_LEN;
use crate::device::DeviceKeys;
use crate::error::{Error, Result};
use crate::file::{sign, verify, version};
use crate::identity::{PUB_KEY_LEN, ROOM_ID_LEN, SIGNATURE_LEN};
use crate::msg::{Reader, Writer};

const LABEL_ABOUT: &[u8] = b"asli/v2/about";

/// What one device says about the Asli it runs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct About {
    /// The device.
    pub from_device_id: [u8; DEVICE_ID_LEN],
    /// Whether it also asks every device for theirs.
    pub ask: bool,
    /// Its connection, for replies.
    pub reply_to: String,
    /// Its build number. Higher is newer; 0 is unknown.
    pub build: u32,
    /// Its version, as a person reads it.
    pub version: String,
}

impl About {
    /// Encodes and signs it.
    ///
    /// # Errors
    ///
    /// Returns [`Error::AnnounceField`] for a version or connection id that is too long.
    pub fn encode(&self, keys: &DeviceKeys, room: &[u8; ROOM_ID_LEN]) -> Result<Vec<u8>> {
        let mut body = Writer::default();
        body.u8(1)
            .bytes(&self.from_device_id)
            .u8(u8::from(self.ask));
        body.text(&self.reply_to)?;
        body.bytes(&self.build.to_be_bytes());
        body.text(&self.version)?;
        Ok(sign(keys, LABEL_ABOUT, room, body))
    }

    /// Decodes it, checking it was signed by `sign_pub`, the key pinned for its sender.
    ///
    /// # Errors
    ///
    /// Returns an error for a malformed message or one not signed by that key.
    pub fn decode(
        body: &[u8],
        room: &[u8; ROOM_ID_LEN],
        sign_pub: &[u8; PUB_KEY_LEN],
    ) -> Result<Self> {
        verify(LABEL_ABOUT, room, body, sign_pub)?;
        let mut r = Reader::new(&body[..body.len() - SIGNATURE_LEN]);
        version(&mut r)?;
        let from_device_id = r.array()?;
        let ask = match r.u8()? {
            0 => false,
            1 => true,
            _ => return Err(Error::InnerMalformed),
        };
        let about = Self {
            from_device_id,
            ask,
            reply_to: r.text()?,
            build: u32::from_be_bytes(r.array()?),
            version: r.text()?,
        };
        r.done()?;
        Ok(about)
    }

    /// The device it says it is from, read before anything is checked.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InnerMalformed`] for a body too short to say.
    pub fn claimed_sender(body: &[u8]) -> Result<[u8; DEVICE_ID_LEN]> {
        let mut r = Reader::new(body);
        version(&mut r)?;
        r.array()
    }
}

const LABEL_LEAVE: &[u8] = b"asli/v2/leave";

/// A device saying it is leaving the account.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Leave {
    /// The device leaving.
    pub from_device_id: [u8; DEVICE_ID_LEN],
    /// When, by its clock.
    pub ts_ms: u64,
}

impl Leave {
    /// Encodes and signs it.
    #[must_use]
    pub fn encode(&self, keys: &DeviceKeys, room: &[u8; ROOM_ID_LEN]) -> Vec<u8> {
        let mut body = Writer::default();
        body.u8(1).bytes(&self.from_device_id).u64(self.ts_ms);
        sign(keys, LABEL_LEAVE, room, body)
    }

    /// Decodes it, checking it was signed by `sign_pub`, the key pinned for its sender.
    ///
    /// # Errors
    ///
    /// Returns an error for a malformed message or one not signed by that key.
    pub fn decode(
        body: &[u8],
        room: &[u8; ROOM_ID_LEN],
        sign_pub: &[u8; PUB_KEY_LEN],
    ) -> Result<Self> {
        verify(LABEL_LEAVE, room, body, sign_pub)?;
        let mut r = Reader::new(&body[..body.len() - SIGNATURE_LEN]);
        version(&mut r)?;
        let leave = Self {
            from_device_id: r.array()?,
            ts_ms: r.u64()?,
        };
        r.done()?;
        Ok(leave)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn about_round_trips_signed_by_its_device_only() {
        let room = [9u8; ROOM_ID_LEN];
        let keys = DeviceKeys::from_secret(&[1u8; 32]);
        let other = DeviceKeys::from_secret(&[2u8; 32]);
        let about = About {
            from_device_id: [1u8; 16],
            ask: true,
            reply_to: "c_0011aabb".to_owned(),
            build: 131,
            version: "0.1.0".to_owned(),
        };
        let body = about.encode(&keys, &room).expect("encodes");
        assert_eq!(About::claimed_sender(&body).expect("names"), [1u8; 16]);
        assert_eq!(
            About::decode(&body, &room, &keys.sign_pub()).expect("decodes"),
            about
        );
        assert!(About::decode(&body, &room, &other.sign_pub()).is_err());
    }

    #[test]
    fn a_goodbye_counts_only_from_the_device_itself() {
        let room = [9u8; ROOM_ID_LEN];
        let keys = DeviceKeys::from_secret(&[1u8; 32]);
        let other = DeviceKeys::from_secret(&[2u8; 32]);
        let leave = Leave {
            from_device_id: [1u8; 16],
            ts_ms: 5,
        };
        let body = leave.encode(&keys, &room);
        assert_eq!(About::claimed_sender(&body).expect("names"), [1u8; 16]);
        assert_eq!(
            Leave::decode(&body, &room, &keys.sign_pub()).expect("decodes"),
            leave
        );
        assert!(Leave::decode(&body, &room, &other.sign_pub()).is_err());
        assert!(About::decode(&body, &room, &keys.sign_pub()).is_err());
    }
}
