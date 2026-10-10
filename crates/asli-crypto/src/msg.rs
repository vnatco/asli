//! Device to device messages, sealed under the room key and carried by the relay as `msg` frames.
//!
//! One AEAD construction serves every kind: the section 9.1 AAD with type code [`TYPE_MSG`], and a
//! plaintext that names its kind inside the ciphertext, so the relay cannot tell a device card
//! from a join request or a file. Every body that makes a claim about a device is signed by that
//! device's key, and every signature covers a purpose label and the room it was made for, so a
//! message cannot be replayed as another kind or into another room.
//!
//! ```text
//! plaintext = u8(1) || u8(kind) || u32be(body_len) || body || zero bytes to a multiple of 256
//! ```

use zeroize::Zeroizing;

use crate::clip::{self, Sealed, DEVICE_ID_LEN, MSG_ID_LEN, NONCE_LEN};
use crate::device::{DeviceKeys, BOX_PUB_LEN};
use crate::error::{Error, Result};
use crate::identity::{verify_signature, PUB_KEY_LEN, ROOM_ID_LEN, SIGNATURE_LEN};
use crate::kdf::KEY_LEN;
use crate::random;

/// Type code bound into the AAD of every `msg` frame.
pub const TYPE_MSG: u8 = 6;
/// Version of the plaintext framing.
pub const MSG_VERSION: u8 = 1;
/// Plaintexts are padded to a multiple of this, so a length says little about the content.
pub const PAD_TO: usize = 256;
/// Longest text field a body carries: a device name, an operating system, a connection id.
pub const MAX_TEXT_BYTES: usize = 64;

/// What a message is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Kind {
    /// A device saying who it is, signed by its own key.
    Card,
    /// A new device asking to join, in an enrollment room.
    JoinRequest,
    /// The answer to a join request: the account key, sealed to the new device.
    JoinGrant,
    /// A join request turned down.
    JoinDecline,
    /// A new account key, sealed to each remaining device, after one was removed.
    Rekey,
    /// Where the approving device listens on its local network, for a new device to reach it.
    JoinWhere,
    /// Which version of Asli a device runs. See [`crate::about`].
    About,
    /// A device leaving the account.
    Leave,
    /// A file offered to one device. See [`crate::file`].
    FileOffer,
    /// The answer to a file offer.
    FileAnswer,
    /// One piece of a file.
    FileChunk,
    /// The receiver's acknowledgement of the pieces so far.
    FileAck,
    /// Either side calling a transfer off.
    FileCancel,
    /// What is on a device's shelf. See [`crate::shelf`].
    ShelfList,
    /// A request for an item on another device's shelf.
    ShelfRequest,
    /// A kind this version does not know. Ignored, so later kinds can be added.
    Other(u8),
}

impl Kind {
    /// The byte that names this kind.
    #[must_use]
    pub const fn code(self) -> u8 {
        match self {
            Self::Card => 1,
            Self::JoinRequest => 2,
            Self::JoinGrant => 3,
            Self::JoinDecline => 4,
            Self::Rekey => 5,
            Self::JoinWhere => 6,
            Self::About => 7,
            Self::Leave => 8,
            Self::FileOffer => 16,
            Self::FileAnswer => 17,
            Self::FileChunk => 18,
            Self::FileAck => 19,
            Self::FileCancel => 20,
            Self::ShelfList => 21,
            Self::ShelfRequest => 22,
            Self::Other(code) => code,
        }
    }

    /// The kind a byte names.
    #[must_use]
    pub const fn from_code(code: u8) -> Self {
        match code {
            1 => Self::Card,
            2 => Self::JoinRequest,
            3 => Self::JoinGrant,
            4 => Self::JoinDecline,
            5 => Self::Rekey,
            6 => Self::JoinWhere,
            7 => Self::About,
            8 => Self::Leave,
            16 => Self::FileOffer,
            17 => Self::FileAnswer,
            18 => Self::FileChunk,
            19 => Self::FileAck,
            20 => Self::FileCancel,
            21 => Self::ShelfList,
            22 => Self::ShelfRequest,
            other => Self::Other(other),
        }
    }
}

/// Seals one message.
///
/// # Errors
///
/// Returns [`Error::Rng`] if randomness fails, [`Error::InnerMalformed`] for a body too large for
/// its length field, and [`Error::Seal`] if encryption fails.
pub fn seal(
    enc_key: &[u8; KEY_LEN],
    epoch: u32,
    room_id_bytes: &[u8; ROOM_ID_LEN],
    msg_id: &[u8; MSG_ID_LEN],
    kind: Kind,
    body: &[u8],
) -> Result<Sealed> {
    let body_len = u32::try_from(body.len()).map_err(|_| Error::InnerMalformed)?;
    let used = 2 + 4 + body.len();
    let mut plaintext = Zeroizing::new(Vec::with_capacity(used.div_ceil(PAD_TO) * PAD_TO));
    plaintext.push(MSG_VERSION);
    plaintext.push(kind.code());
    plaintext.extend_from_slice(&body_len.to_be_bytes());
    plaintext.extend_from_slice(body);
    plaintext.resize(used.div_ceil(PAD_TO) * PAD_TO, 0);

    let nonce: [u8; NONCE_LEN] = random::bytes()?;
    let ciphertext = clip::seal_typed(
        TYPE_MSG,
        enc_key,
        epoch,
        room_id_bytes,
        msg_id,
        &nonce,
        &plaintext,
    )?;
    Ok(Sealed { nonce, ciphertext })
}

/// Opens one message, returning its kind and body.
///
/// # Errors
///
/// Returns [`Error::Open`] if it does not decrypt, [`Error::InnerVersion`] for an unknown framing
/// version, and [`Error::InnerMalformed`] for a length that does not fit or non zero padding.
pub fn open(
    enc_key: &[u8; KEY_LEN],
    epoch: u32,
    room_id_bytes: &[u8; ROOM_ID_LEN],
    msg_id: &[u8; MSG_ID_LEN],
    nonce: &[u8; NONCE_LEN],
    ciphertext: &[u8],
) -> Result<(Kind, Zeroizing<Vec<u8>>)> {
    let plaintext = clip::open_typed(
        TYPE_MSG,
        enc_key,
        epoch,
        room_id_bytes,
        msg_id,
        nonce,
        ciphertext,
    )?;
    if plaintext.len() < 6 || plaintext.len() % PAD_TO != 0 {
        return Err(Error::InnerMalformed);
    }
    if plaintext[0] != MSG_VERSION {
        return Err(Error::InnerVersion(plaintext[0]));
    }
    let kind = Kind::from_code(plaintext[1]);
    let len = usize::try_from(u32::from_be_bytes([
        plaintext[2],
        plaintext[3],
        plaintext[4],
        plaintext[5],
    ]))
    .map_err(|_| Error::InnerMalformed)?;
    let end = 6usize.checked_add(len).ok_or(Error::InnerMalformed)?;
    let body = plaintext.get(6..end).ok_or(Error::InnerMalformed)?;
    if plaintext[end..].iter().any(|&b| b != 0) {
        return Err(Error::InnerMalformed);
    }
    Ok((kind, Zeroizing::new(body.to_vec())))
}

/// Writes fields in order, for a body and for the bytes its signature covers.
#[derive(Default)]
pub(crate) struct Writer(Vec<u8>);

impl Writer {
    pub(crate) fn bytes(&mut self, bytes: &[u8]) -> &mut Self {
        self.0.extend_from_slice(bytes);
        self
    }

    pub(crate) fn u8(&mut self, value: u8) -> &mut Self {
        self.0.push(value);
        self
    }

    pub(crate) fn u64(&mut self, value: u64) -> &mut Self {
        self.0.extend_from_slice(&value.to_be_bytes());
        self
    }

    /// A short text field: a length byte and UTF-8, at most [`MAX_TEXT_BYTES`].
    pub(crate) fn text(&mut self, text: &str) -> Result<&mut Self> {
        let len = u8::try_from(text.len()).map_err(|_| Error::AnnounceField)?;
        if text.len() > MAX_TEXT_BYTES {
            return Err(Error::AnnounceField);
        }
        self.0.push(len);
        self.0.extend_from_slice(text.as_bytes());
        Ok(self)
    }

    /// A long field: a 32 bit length and the bytes.
    pub(crate) fn blob(&mut self, bytes: &[u8]) -> Result<&mut Self> {
        let len = u32::try_from(bytes.len()).map_err(|_| Error::InnerMalformed)?;
        self.0.extend_from_slice(&len.to_be_bytes());
        self.0.extend_from_slice(bytes);
        Ok(self)
    }

    pub(crate) fn finish(self) -> Vec<u8> {
        self.0
    }

    pub(crate) fn as_slice(&self) -> &[u8] {
        &self.0
    }
}

/// Reads fields in order, refusing to run past the end.
pub(crate) struct Reader<'a> {
    buf: &'a [u8],
    at: usize,
}

impl<'a> Reader<'a> {
    pub(crate) const fn new(buf: &'a [u8]) -> Self {
        Self { buf, at: 0 }
    }

    pub(crate) fn bytes(&mut self, len: usize) -> Result<&'a [u8]> {
        let end = self.at.checked_add(len).ok_or(Error::InnerMalformed)?;
        let out = self.buf.get(self.at..end).ok_or(Error::InnerMalformed)?;
        self.at = end;
        Ok(out)
    }

    pub(crate) fn array<const N: usize>(&mut self) -> Result<[u8; N]> {
        self.bytes(N)?.try_into().map_err(|_| Error::InnerMalformed)
    }

    pub(crate) fn u8(&mut self) -> Result<u8> {
        Ok(self.array::<1>()?[0])
    }

    pub(crate) fn u64(&mut self) -> Result<u64> {
        Ok(u64::from_be_bytes(self.array()?))
    }

    pub(crate) fn text(&mut self) -> Result<String> {
        let len = usize::from(self.u8()?);
        if len > MAX_TEXT_BYTES {
            return Err(Error::AnnounceField);
        }
        let bytes = self.bytes(len)?;
        Ok(std::str::from_utf8(bytes)
            .map_err(|_| Error::NotUtf8)?
            .to_owned())
    }

    pub(crate) fn blob(&mut self) -> Result<&'a [u8]> {
        let len = usize::try_from(u32::from_be_bytes(self.array()?))
            .map_err(|_| Error::InnerMalformed)?;
        self.bytes(len)
    }

    /// Where the reader is, so a signature can cover everything before it.
    pub(crate) const fn position(&self) -> usize {
        self.at
    }

    pub(crate) fn done(&self) -> Result<()> {
        if self.at == self.buf.len() {
            Ok(())
        } else {
            Err(Error::InnerMalformed)
        }
    }
}

/// The bytes a signature covers: a purpose label, the room it was made for, and the body before
/// the signature.
fn signed_bytes(label: &[u8], room_id_bytes: &[u8; ROOM_ID_LEN], body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(label.len() + ROOM_ID_LEN + body.len());
    out.extend_from_slice(label);
    out.extend_from_slice(room_id_bytes);
    out.extend_from_slice(body);
    out
}

/// Signs `body` for `room` under `label` and appends the signature.
fn sign_into(
    keys: &DeviceKeys,
    label: &[u8],
    room_id_bytes: &[u8; ROOM_ID_LEN],
    mut body: Writer,
) -> Vec<u8> {
    let sig = keys.sign(&signed_bytes(label, room_id_bytes, body.as_slice()));
    body.bytes(&sig);
    body.finish()
}

/// Checks the signature that ends `body`, made by `sign_pub`, and returns what it covers.
fn verify_tail<'a>(
    label: &[u8],
    room_id_bytes: &[u8; ROOM_ID_LEN],
    body: &'a [u8],
    sign_pub: &[u8; PUB_KEY_LEN],
) -> Result<&'a [u8]> {
    let split = body
        .len()
        .checked_sub(SIGNATURE_LEN)
        .ok_or(Error::InnerMalformed)?;
    let (covered, sig) = body.split_at(split);
    let sig: [u8; SIGNATURE_LEN] = sig.try_into().map_err(|_| Error::InnerMalformed)?;
    verify_signature(sign_pub, &signed_bytes(label, room_id_bytes, covered), &sig)?;
    Ok(covered)
}

// ---------------------------------------------------------------------------------------------
// Device card
// ---------------------------------------------------------------------------------------------

/// Signature label for a device card.
pub const LABEL_CARD: &[u8] = b"asli/v2/card";

/// A device saying who it is, signed by its own key.
///
/// Sent after every connection and whenever the room's connection count changes, like the older
/// `announce`, which it replaces between devices that both know it. The first card seen for a
/// device id pins that id to its signing key; a later card with another key for the same id is
/// refused, so one device cannot take another's place in the list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Card {
    /// The device's id, the one its clips carry.
    pub device_id: [u8; DEVICE_ID_LEN],
    /// The key its messages are signed with.
    pub sign_pub: [u8; PUB_KEY_LEN],
    /// The key a secret is sealed to for it.
    pub box_pub: [u8; BOX_PUB_LEN],
    /// When it was made, by the sender's clock.
    pub ts_ms: u64,
    /// The relay's id for the connection it came from, so a message can be sent to this device
    /// alone. Assigned by the relay, so it says nothing about the device.
    pub conn_id: String,
    /// What the person calls the device.
    pub name: String,
    /// Its operating system.
    pub os: String,
}

impl Card {
    /// Encodes and signs a card for `room`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::AnnounceField`] for a text field over [`MAX_TEXT_BYTES`].
    pub fn encode(&self, keys: &DeviceKeys, room_id_bytes: &[u8; ROOM_ID_LEN]) -> Result<Vec<u8>> {
        if keys.sign_pub() != self.sign_pub || keys.box_pub() != self.box_pub {
            return Err(Error::BadPublicKey);
        }
        let mut body = Writer::default();
        body.u8(1)
            .bytes(&self.device_id)
            .bytes(&self.sign_pub)
            .bytes(&self.box_pub)
            .u64(self.ts_ms);
        body.text(&self.conn_id)?.text(&self.name)?.text(&self.os)?;
        Ok(sign_into(keys, LABEL_CARD, room_id_bytes, body))
    }

    /// Decodes a card and checks it is signed by the key it names, for `room`.
    ///
    /// # Errors
    ///
    /// Returns an error for a malformed card or a signature that does not verify.
    pub fn decode(body: &[u8], room_id_bytes: &[u8; ROOM_ID_LEN]) -> Result<Self> {
        let mut r = Reader::new(body);
        if r.u8()? != 1 {
            return Err(Error::InnerVersion(body[0]));
        }
        let device_id = r.array()?;
        let sign_pub = r.array()?;
        let box_pub = r.array()?;
        let ts_ms = r.u64()?;
        let conn_id = r.text()?;
        let name = r.text()?;
        let os = r.text()?;
        let covered = r.position();
        r.bytes(SIGNATURE_LEN)?;
        r.done()?;
        verify_tail(LABEL_CARD, room_id_bytes, body, &sign_pub)?;
        debug_assert_eq!(covered, body.len() - SIGNATURE_LEN);
        Ok(Self {
            device_id,
            sign_pub,
            box_pub,
            ts_ms,
            conn_id,
            name,
            os,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: [u8; 32] = [7u8; 32];
    const ROOM: [u8; ROOM_ID_LEN] = [9u8; ROOM_ID_LEN];
    const MSG_ID: [u8; MSG_ID_LEN] = [3u8; MSG_ID_LEN];

    fn card(keys: &DeviceKeys) -> Card {
        Card {
            device_id: [1u8; DEVICE_ID_LEN],
            sign_pub: keys.sign_pub(),
            box_pub: keys.box_pub(),
            ts_ms: 1_767_225_600_000,
            conn_id: "c_9fK2xQ".to_owned(),
            name: "ThinkPad X1".to_owned(),
            os: "Windows 11".to_owned(),
        }
    }

    #[test]
    fn a_message_round_trips_and_hides_its_length() {
        let sealed = seal(&KEY, 0, &ROOM, &MSG_ID, Kind::Card, b"hello").expect("seals");
        assert_eq!(sealed.ciphertext.len(), PAD_TO + clip::TAG_LEN);
        let (kind, body) =
            open(&KEY, 0, &ROOM, &MSG_ID, &sealed.nonce, &sealed.ciphertext).expect("opens");
        assert_eq!(kind, Kind::Card);
        assert_eq!(body.as_slice(), b"hello");
    }

    #[test]
    fn a_message_is_bound_to_its_room_epoch_and_id() {
        let sealed = seal(&KEY, 0, &ROOM, &MSG_ID, Kind::Card, b"hello").expect("seals");
        let n = &sealed.nonce;
        let ct = &sealed.ciphertext;
        assert!(open(&KEY, 1, &ROOM, &MSG_ID, n, ct).is_err());
        assert!(open(&KEY, 0, &[8u8; ROOM_ID_LEN], &MSG_ID, n, ct).is_err());
        assert!(open(&KEY, 0, &ROOM, &[4u8; MSG_ID_LEN], n, ct).is_err());
        // Nor is a message accepted as a clip or an announcement, or the other way round.
        assert!(clip::open(&KEY, 0, &ROOM, &MSG_ID, n, ct).is_err());
    }

    #[test]
    fn an_unknown_kind_opens_as_other_so_it_can_be_ignored() {
        let sealed = seal(&KEY, 0, &ROOM, &MSG_ID, Kind::Other(200), b"x").expect("seals");
        let (kind, _) =
            open(&KEY, 0, &ROOM, &MSG_ID, &sealed.nonce, &sealed.ciphertext).expect("opens");
        assert_eq!(kind, Kind::Other(200));
    }

    #[test]
    fn a_card_is_signed_by_the_device_it_names_and_for_one_room() {
        let keys = DeviceKeys::from_secret(&[1u8; 32]);
        let encoded = card(&keys).encode(&keys, &ROOM).expect("encodes");
        assert_eq!(Card::decode(&encoded, &ROOM).expect("decodes"), card(&keys));

        assert!(
            Card::decode(&encoded, &[8u8; ROOM_ID_LEN]).is_err(),
            "a card from one room is not accepted in another"
        );
        let mut tampered = encoded.clone();
        let name_at = encoded.len() - SIGNATURE_LEN - 12;
        tampered[name_at] ^= 0x01;
        assert!(Card::decode(&tampered, &ROOM).is_err());
    }

    #[test]
    fn a_card_cannot_name_keys_it_does_not_hold() {
        let keys = DeviceKeys::from_secret(&[1u8; 32]);
        let other = DeviceKeys::from_secret(&[2u8; 32]);
        assert_eq!(card(&other).encode(&keys, &ROOM), Err(Error::BadPublicKey));
    }
}
