//! Sending a file to one device: the offer, the answer, the pieces, and the acknowledgements.
//!
//! Every message here travels as a `msg` frame (see [`crate::msg`]), sealed under the room key
//! like everything else, and addressed to one connection. The offer and the answer are signed by
//! the device that sends them, so the person accepting sees the name of the device whose pinned key
//! signed the offer, not a name the offer merely claims, and only the device offered the file can
//! accept it.
//!
//! ```text
//! offer   = u8(1) || offer_id[16] || from_device_id[16] || to_device_id[16] || u64be(size)
//!           || sha256[32] || u32be(chunk_bytes) || u64be(ts_ms) || text(reply_to)
//!           || u16be(name_len) || name || signature, label "asli/v2/file-offer"
//! answer  = u8(1) || offer_id[16] || from_device_id[16] || u8(accepted) || text(reply_to)
//!           || signature, label "asli/v2/file-answer"
//! chunk   = u8(1) || offer_id[16] || u32be(index) || u32be(len) || bytes
//! ack     = u8(1) || offer_id[16] || u32be(received) || u8(state)
//! cancel  = u8(1) || offer_id[16]
//! ```
//!
//! `reply_to` is the sender's connection id, so the answer and the pieces can be addressed back
//! to it alone. The pieces are not signed one by one: they are sealed under the room key, which
//! only the account's devices hold, and the whole file is checked against the offer's hash before
//! it is kept, so a piece that was altered, swapped or left out is caught at the end.

use crate::clip::DEVICE_ID_LEN;
use crate::device::DeviceKeys;
use crate::error::{Error, Result};
use crate::identity::{verify_signature, PUB_KEY_LEN, ROOM_ID_LEN, SIGNATURE_LEN};
use crate::msg::{Reader, Writer};

/// Length of an offer id.
pub const OFFER_ID_LEN: usize = 16;
/// Length of the content hash.
pub const HASH_LEN: usize = 32;
/// Size of every piece but the last.
pub const CHUNK_BYTES: u32 = 256 * 1024;
/// Longest file name an offer may carry, in bytes.
pub const MAX_NAME_BYTES: usize = 255;

const LABEL_OFFER: &[u8] = b"asli/v2/file-offer";
const LABEL_ANSWER: &[u8] = b"asli/v2/file-answer";

/// A file one device offers another.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Offer {
    /// Chosen by the sender, unique per file.
    pub offer_id: [u8; OFFER_ID_LEN],
    /// The device offering it.
    pub from_device_id: [u8; DEVICE_ID_LEN],
    /// The device it is offered to, so it cannot be redirected to another.
    pub to_device_id: [u8; DEVICE_ID_LEN],
    /// Its size in bytes.
    pub size: u64,
    /// SHA-256 of its contents.
    pub sha256: [u8; HASH_LEN],
    /// Size of every piece but the last.
    pub chunk_bytes: u32,
    /// When it was offered, by the sender's clock.
    pub ts_ms: u64,
    /// The sender's connection, for the answer and the pieces to be addressed to.
    pub reply_to: String,
    /// Its name, as the sender has it. Untrusted: the receiver makes its own safe name from it.
    pub name: String,
}

impl Offer {
    /// How many pieces the file is sent in.
    #[must_use]
    pub fn chunk_count(&self) -> u64 {
        if self.chunk_bytes == 0 {
            return 0;
        }
        self.size.div_ceil(u64::from(self.chunk_bytes)).max(1)
    }

    /// Encodes and signs the offer.
    ///
    /// # Errors
    ///
    /// Returns [`Error::AnnounceField`] for a name or connection id that is too long.
    pub fn encode(&self, keys: &DeviceKeys, room: &[u8; ROOM_ID_LEN]) -> Result<Vec<u8>> {
        let name = self.name.as_bytes();
        let name_len = u16::try_from(name.len()).map_err(|_| Error::AnnounceField)?;
        if name.len() > MAX_NAME_BYTES {
            return Err(Error::AnnounceField);
        }
        let mut body = Writer::default();
        body.u8(1)
            .bytes(&self.offer_id)
            .bytes(&self.from_device_id)
            .bytes(&self.to_device_id)
            .u64(self.size)
            .bytes(&self.sha256)
            .bytes(&self.chunk_bytes.to_be_bytes())
            .u64(self.ts_ms);
        body.text(&self.reply_to)?;
        body.bytes(&name_len.to_be_bytes()).bytes(name);
        Ok(sign(keys, LABEL_OFFER, room, body))
    }

    /// Decodes an offer, checking it was signed by `sign_pub`: the key pinned for the device it
    /// says it is from. Who that is must be known before the offer is believed, so the caller looks
    /// the key up with [`Offer::claimed_sender`] first.
    ///
    /// # Errors
    ///
    /// Returns an error for a malformed offer or one not signed by that key.
    pub fn decode(
        body: &[u8],
        room: &[u8; ROOM_ID_LEN],
        sign_pub: &[u8; PUB_KEY_LEN],
    ) -> Result<Self> {
        verify(LABEL_OFFER, room, body, sign_pub)?;
        let mut r = Reader::new(&body[..body.len() - SIGNATURE_LEN]);
        version(&mut r)?;
        let offer = Self {
            offer_id: r.array()?,
            from_device_id: r.array()?,
            to_device_id: r.array()?,
            size: r.u64()?,
            sha256: r.array()?,
            chunk_bytes: u32::from_be_bytes(r.array()?),
            ts_ms: r.u64()?,
            reply_to: r.text()?,
            name: {
                let len = usize::from(u16::from_be_bytes(r.array()?));
                if len > MAX_NAME_BYTES {
                    return Err(Error::AnnounceField);
                }
                std::str::from_utf8(r.bytes(len)?)
                    .map_err(|_| Error::NotUtf8)?
                    .to_owned()
            },
        };
        r.done()?;
        if offer.chunk_bytes == 0 || offer.chunk_bytes > CHUNK_BYTES {
            return Err(Error::InnerMalformed);
        }
        Ok(offer)
    }

    /// The device an offer says it is from, read before anything is checked, so the receiver
    /// can look up the key that device pinned.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InnerMalformed`] for a body too short to say.
    pub fn claimed_sender(body: &[u8]) -> Result<[u8; DEVICE_ID_LEN]> {
        let mut r = Reader::new(body);
        version(&mut r)?;
        r.bytes(OFFER_ID_LEN)?;
        r.array()
    }
}

/// A receiver's answer to an offer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Answer {
    /// The offer answered.
    pub offer_id: [u8; OFFER_ID_LEN],
    /// The device answering: the one the file was offered to.
    pub from_device_id: [u8; DEVICE_ID_LEN],
    /// Whether it accepted.
    pub accepted: bool,
    /// Its connection, for the pieces to be addressed to.
    pub reply_to: String,
}

impl Answer {
    /// Encodes and signs the answer.
    ///
    /// # Errors
    ///
    /// Returns [`Error::AnnounceField`] for a connection id that is too long.
    pub fn encode(&self, keys: &DeviceKeys, room: &[u8; ROOM_ID_LEN]) -> Result<Vec<u8>> {
        let mut body = Writer::default();
        body.u8(1)
            .bytes(&self.offer_id)
            .bytes(&self.from_device_id)
            .u8(u8::from(self.accepted));
        body.text(&self.reply_to)?;
        Ok(sign(keys, LABEL_ANSWER, room, body))
    }

    /// Decodes an answer, checking it was signed by `sign_pub`.
    ///
    /// # Errors
    ///
    /// Returns an error for a malformed answer or one not signed by that key.
    pub fn decode(
        body: &[u8],
        room: &[u8; ROOM_ID_LEN],
        sign_pub: &[u8; PUB_KEY_LEN],
    ) -> Result<Self> {
        verify(LABEL_ANSWER, room, body, sign_pub)?;
        let mut r = Reader::new(&body[..body.len() - SIGNATURE_LEN]);
        version(&mut r)?;
        let answer = Self {
            offer_id: r.array()?,
            from_device_id: r.array()?,
            accepted: match r.u8()? {
                0 => false,
                1 => true,
                _ => return Err(Error::InnerMalformed),
            },
            reply_to: r.text()?,
        };
        r.done()?;
        Ok(answer)
    }

    /// The device an answer says it is from, read before it is checked.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InnerMalformed`] for a body too short to say.
    pub fn claimed_sender(body: &[u8]) -> Result<[u8; DEVICE_ID_LEN]> {
        let mut r = Reader::new(body);
        version(&mut r)?;
        r.bytes(OFFER_ID_LEN)?;
        r.array()
    }
}

/// One piece of a file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Chunk {
    /// The file it belongs to.
    pub offer_id: [u8; OFFER_ID_LEN],
    /// Its position, from zero.
    pub index: u32,
    /// Its bytes.
    pub data: Vec<u8>,
}

impl Chunk {
    /// Encodes the piece.
    ///
    /// # Errors
    ///
    /// Returns [`Error::ChunkTooLarge`] for a piece larger than [`CHUNK_BYTES`].
    pub fn encode(&self) -> Result<Vec<u8>> {
        let len = u32::try_from(self.data.len()).map_err(|_| Error::ChunkTooLarge)?;
        if len > CHUNK_BYTES {
            return Err(Error::ChunkTooLarge);
        }
        let mut body = Writer::default();
        body.u8(1)
            .bytes(&self.offer_id)
            .bytes(&self.index.to_be_bytes())
            .bytes(&len.to_be_bytes())
            .bytes(&self.data);
        Ok(body.finish())
    }

    /// Decodes a piece.
    ///
    /// # Errors
    ///
    /// Returns an error for a malformed piece or one larger than [`CHUNK_BYTES`].
    pub fn decode(body: &[u8]) -> Result<Self> {
        let mut r = Reader::new(body);
        version(&mut r)?;
        let offer_id = r.array()?;
        let index = u32::from_be_bytes(r.array()?);
        let len = u32::from_be_bytes(r.array()?);
        if len > CHUNK_BYTES {
            return Err(Error::ChunkTooLarge);
        }
        let data = r
            .bytes(usize::try_from(len).map_err(|_| Error::InnerMalformed)?)?
            .to_vec();
        r.done()?;
        Ok(Self {
            offer_id,
            index,
            data,
        })
    }
}

/// Where a transfer stands, as the receiver reports it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AckState {
    /// Still receiving.
    Receiving,
    /// Every piece arrived and the file matched its hash; it has been kept.
    Done,
    /// The file did not match its hash, and was thrown away.
    Corrupt,
}

/// The receiver's acknowledgement of the pieces so far.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ack {
    /// The file.
    pub offer_id: [u8; OFFER_ID_LEN],
    /// How many pieces have arrived, in order, from the first.
    pub received: u32,
    /// Where it stands.
    pub state: AckState,
}

impl Ack {
    /// Encodes the acknowledgement.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut body = Writer::default();
        body.u8(1)
            .bytes(&self.offer_id)
            .bytes(&self.received.to_be_bytes())
            .u8(match self.state {
                AckState::Receiving => 0,
                AckState::Done => 1,
                AckState::Corrupt => 2,
            });
        body.finish()
    }

    /// Decodes an acknowledgement.
    ///
    /// # Errors
    ///
    /// Returns an error for a malformed one.
    pub fn decode(body: &[u8]) -> Result<Self> {
        let mut r = Reader::new(body);
        version(&mut r)?;
        let ack = Self {
            offer_id: r.array()?,
            received: u32::from_be_bytes(r.array()?),
            state: match r.u8()? {
                0 => AckState::Receiving,
                1 => AckState::Done,
                2 => AckState::Corrupt,
                _ => return Err(Error::InnerMalformed),
            },
        };
        r.done()?;
        Ok(ack)
    }
}

/// Either side calling a transfer off.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Cancel {
    /// The file.
    pub offer_id: [u8; OFFER_ID_LEN],
}

impl Cancel {
    /// Encodes the cancellation.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut body = Writer::default();
        body.u8(1).bytes(&self.offer_id);
        body.finish()
    }

    /// Decodes a cancellation.
    ///
    /// # Errors
    ///
    /// Returns an error for a malformed one.
    pub fn decode(body: &[u8]) -> Result<Self> {
        let mut r = Reader::new(body);
        version(&mut r)?;
        let cancel = Self {
            offer_id: r.array()?,
        };
        r.done()?;
        Ok(cancel)
    }
}

fn version(r: &mut Reader<'_>) -> Result<()> {
    match r.u8()? {
        1 => Ok(()),
        other => Err(Error::InnerVersion(other)),
    }
}

fn sign(keys: &DeviceKeys, label: &[u8], room: &[u8; ROOM_ID_LEN], mut body: Writer) -> Vec<u8> {
    let mut covered = Vec::with_capacity(label.len() + ROOM_ID_LEN + body.as_slice().len());
    covered.extend_from_slice(label);
    covered.extend_from_slice(room);
    covered.extend_from_slice(body.as_slice());
    let sig = keys.sign(&covered);
    body.bytes(&sig);
    body.finish()
}

fn verify(
    label: &[u8],
    room: &[u8; ROOM_ID_LEN],
    body: &[u8],
    sign_pub: &[u8; PUB_KEY_LEN],
) -> Result<()> {
    let split = body
        .len()
        .checked_sub(SIGNATURE_LEN)
        .ok_or(Error::InnerMalformed)?;
    let mut covered = Vec::with_capacity(label.len() + ROOM_ID_LEN + split);
    covered.extend_from_slice(label);
    covered.extend_from_slice(room);
    covered.extend_from_slice(&body[..split]);
    let sig: [u8; SIGNATURE_LEN] = body[split..]
        .try_into()
        .map_err(|_| Error::InnerMalformed)?;
    verify_signature(sign_pub, &covered, &sig)
}

#[cfg(test)]
mod tests {
    use super::*;

    const ROOM: [u8; ROOM_ID_LEN] = [9u8; ROOM_ID_LEN];

    fn offer() -> Offer {
        Offer {
            offer_id: [1u8; 16],
            from_device_id: [2u8; 16],
            to_device_id: [3u8; 16],
            size: 600_000,
            sha256: [4u8; 32],
            chunk_bytes: CHUNK_BYTES,
            ts_ms: 1_767_225_600_000,
            reply_to: "c_0011aabb".to_owned(),
            name: "asli-0.1.0-macos-universal.dmg".to_owned(),
        }
    }

    #[test]
    fn an_offer_round_trips_signed_by_its_sender_only() {
        let sender = DeviceKeys::from_secret(&[1u8; 32]);
        let other = DeviceKeys::from_secret(&[2u8; 32]);
        let body = offer().encode(&sender, &ROOM).expect("encodes");
        assert_eq!(Offer::claimed_sender(&body).expect("names"), [2u8; 16]);
        assert_eq!(
            Offer::decode(&body, &ROOM, &sender.sign_pub()).expect("decodes"),
            offer()
        );
        assert!(Offer::decode(&body, &ROOM, &other.sign_pub()).is_err());
        assert!(Offer::decode(&body, &[8u8; ROOM_ID_LEN], &sender.sign_pub()).is_err());
        assert_eq!(offer().chunk_count(), 3);
    }

    #[test]
    fn an_offer_is_bound_to_the_device_it_was_made_for() {
        // Changing the recipient breaks the signature, so an offer cannot be redirected.
        let sender = DeviceKeys::from_secret(&[1u8; 32]);
        let mut body = offer().encode(&sender, &ROOM).expect("encodes");
        body[1 + 16 + 16] ^= 0x01;
        assert!(Offer::decode(&body, &ROOM, &sender.sign_pub()).is_err());
    }

    #[test]
    fn an_answer_round_trips_signed_by_its_sender_only() {
        let receiver = DeviceKeys::from_secret(&[3u8; 32]);
        let answer = Answer {
            offer_id: [1u8; 16],
            from_device_id: [3u8; 16],
            accepted: true,
            reply_to: "c_ffee0011".to_owned(),
        };
        let body = answer.encode(&receiver, &ROOM).expect("encodes");
        assert_eq!(Answer::claimed_sender(&body).expect("names"), [3u8; 16]);
        assert_eq!(
            Answer::decode(&body, &ROOM, &receiver.sign_pub()).expect("decodes"),
            answer
        );
        assert!(Answer::decode(
            &body,
            &ROOM,
            &DeviceKeys::from_secret(&[9u8; 32]).sign_pub()
        )
        .is_err());
    }

    #[test]
    fn chunks_acks_and_cancels_round_trip_and_refuse_nonsense() {
        let chunk = Chunk {
            offer_id: [1u8; 16],
            index: 7,
            data: vec![5u8; 1000],
        };
        assert_eq!(
            Chunk::decode(&chunk.encode().expect("encodes")).expect("decodes"),
            chunk
        );
        let big = Chunk {
            data: vec![0u8; CHUNK_BYTES as usize + 1],
            ..chunk
        };
        assert!(big.encode().is_err());

        let ack = Ack {
            offer_id: [1u8; 16],
            received: 9,
            state: AckState::Done,
        };
        assert_eq!(Ack::decode(&ack.encode()).expect("decodes"), ack);
        let cancel = Cancel {
            offer_id: [1u8; 16],
        };
        assert_eq!(Cancel::decode(&cancel.encode()).expect("decodes"), cancel);
        assert!(Ack::decode(&[1u8; 5]).is_err());
    }
}
