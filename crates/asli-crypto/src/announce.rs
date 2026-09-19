//! Sealing and opening device announcements.
//!
//! An announcement is how one device tells the others in the room what to call it: a name a
//! person chose, and the operating system it runs. Both are exactly the kind of detail the relay
//! must never learn, so an announcement is sealed like a clip, under the same epoch key, with the
//! same public header. Only the type code in the associated data differs:
//!
//! ```text
//! AAD = clip AAD with type_code = 5                                  (51 bytes, fixed)
//! ```
//!
//! That one byte is what keeps the two apart. A clip ciphertext presented as an announcement, or
//! the other way round, fails the tag check, so a relay cannot turn one into the other.
//!
//! The inner plaintext is always [`PLAINTEXT_LEN`] bytes, whatever the name, so the ciphertext
//! length says nothing about how long the name is:
//!
//! ```text
//! u8(version = 1)
//! u8(16) || device_id                                              (1 + 16)
//! u64be(ts_ms)                                                     (8)
//! u8(name_len) || name                                             (1 + at most 64)
//! u8(os_len)   || os                                               (1 + at most 64)
//! zero padding to 256 bytes
//! ```
//!
//! What is deliberately absent: a sequence number. An announcement changes nothing but a label on
//! a screen, so a replayed one is low harm, and giving it a counter would mean sharing the clip
//! counter, whose reservations are persisted and must never be disturbed. The receiver bounds
//! replays instead, with the timestamp window clips use and a message id dedup.

use zeroize::Zeroizing;

use crate::clip::{self, Sealed, DEVICE_ID_LEN, MSG_ID_LEN, NONCE_LEN};
use crate::error::{Error, Result};
use crate::identity::ROOM_ID_LEN;
use crate::kdf::KEY_LEN;
use crate::random;

/// Message type code for an announcement, bound in the associated data.
///
/// Codes 1 to 4 belong to the clip and its three chunk types.
pub const TYPE_ANNOUNCE: u8 = 5;
/// Version byte of the announcement plaintext layout.
pub const ANNOUNCE_VERSION: u8 = 1;
/// Longest name or operating system, in bytes of UTF-8.
pub const MAX_FIELD_BYTES: usize = 64;
/// Size of every announcement plaintext, padding included.
pub const PLAINTEXT_LEN: usize = 256;

const DEVICE_ID_LEN_U8: u8 = 16;
const _: () = assert!(DEVICE_ID_LEN_U8 as usize == DEVICE_ID_LEN);
// The largest body fits with room to spare, so padding never has to grow.
const _: () = assert!(1 + 1 + DEVICE_ID_LEN + 8 + 2 * (1 + MAX_FIELD_BYTES) <= PLAINTEXT_LEN);

/// What one device says about itself.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Announce {
    /// The sending device, the same identifier its clips carry.
    pub device_id: [u8; DEVICE_ID_LEN],
    /// Sender wall clock in milliseconds. Bounds replays, carries no other weight.
    pub ts_ms: u64,
    /// What the person calls this device.
    pub name: String,
    /// The operating system, as a short human readable label.
    pub os: String,
}

/// The longest prefix of `text` that fits in `max` bytes without splitting a character.
///
/// For the sending side, which shortens an over long name rather than refusing to announce it.
#[must_use]
pub fn truncate_utf8(text: &str, max: usize) -> &str {
    if text.len() <= max {
        return text;
    }
    let mut end = max;
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    &text[..end]
}

/// Encodes and pads the plaintext.
///
/// # Errors
///
/// Returns [`Error::AnnounceField`] when the name or the operating system is longer than
/// [`MAX_FIELD_BYTES`]. Shorten with [`truncate_utf8`] first.
pub fn encode(announce: &Announce) -> Result<Zeroizing<Vec<u8>>> {
    let name = announce.name.as_bytes();
    let os = announce.os.as_bytes();
    let (Ok(name_len), Ok(os_len)) = (u8::try_from(name.len()), u8::try_from(os.len())) else {
        return Err(Error::AnnounceField);
    };
    if name.len() > MAX_FIELD_BYTES || os.len() > MAX_FIELD_BYTES {
        return Err(Error::AnnounceField);
    }

    let mut out = Zeroizing::new(vec![0u8; PLAINTEXT_LEN]);
    let buf = out.as_mut_slice();
    let mut at = 0;

    buf[at] = ANNOUNCE_VERSION;
    at += 1;
    buf[at] = DEVICE_ID_LEN_U8;
    at += 1;
    buf[at..at + DEVICE_ID_LEN].copy_from_slice(&announce.device_id);
    at += DEVICE_ID_LEN;
    buf[at..at + 8].copy_from_slice(&announce.ts_ms.to_be_bytes());
    at += 8;

    buf[at] = name_len;
    at += 1;
    buf[at..at + name.len()].copy_from_slice(name);
    at += name.len();

    buf[at] = os_len;
    at += 1;
    buf[at..at + os.len()].copy_from_slice(os);
    // The remaining bytes are already zero, which is the padding.

    Ok(out)
}

/// Decodes a plaintext produced by [`encode`].
///
/// Strict on purpose: the length must be exact, both fields valid UTF-8 within the bound, and the
/// padding all zero. A sender that does otherwise is not one of ours.
///
/// # Errors
///
/// Returns [`Error::InnerMalformed`], [`Error::InnerVersion`], [`Error::AnnounceField`] or
/// [`Error::NotUtf8`].
pub fn decode(buf: &[u8]) -> Result<Announce> {
    if buf.len() != PLAINTEXT_LEN {
        return Err(Error::InnerMalformed);
    }
    let mut at = 0;

    let version = buf[at];
    at += 1;
    if version != ANNOUNCE_VERSION {
        return Err(Error::InnerVersion(version));
    }

    if buf[at] != DEVICE_ID_LEN_U8 {
        return Err(Error::InnerMalformed);
    }
    at += 1;
    let mut device_id = [0u8; DEVICE_ID_LEN];
    device_id.copy_from_slice(&buf[at..at + DEVICE_ID_LEN]);
    at += DEVICE_ID_LEN;

    let ts_ms = u64::from_be_bytes(
        buf[at..at + 8]
            .try_into()
            .map_err(|_| Error::InnerMalformed)?,
    );
    at += 8;

    let (name, next) = field(buf, at)?;
    let (os, next) = field(buf, next)?;

    if buf[next..].iter().any(|&byte| byte != 0) {
        return Err(Error::InnerMalformed);
    }

    Ok(Announce {
        device_id,
        ts_ms,
        name,
        os,
    })
}

/// Reads one length prefixed text field, returning it and where the next one starts.
fn field(buf: &[u8], at: usize) -> Result<(String, usize)> {
    let len = usize::from(*buf.get(at).ok_or(Error::InnerMalformed)?);
    if len > MAX_FIELD_BYTES {
        return Err(Error::AnnounceField);
    }
    let start = at + 1;
    let bytes = buf.get(start..start + len).ok_or(Error::InnerMalformed)?;
    let text = std::str::from_utf8(bytes).map_err(|_| Error::NotUtf8)?;
    Ok((text.to_owned(), start + len))
}

/// Seals an announcement under the epoch key, with a fresh random nonce.
///
/// # Errors
///
/// Returns [`Error::AnnounceField`] for an over long field, [`Error::Rng`] if randomness is
/// unavailable, or [`Error::Seal`] if the AEAD refuses the input.
pub fn seal(
    enc_key: &[u8; KEY_LEN],
    epoch: u32,
    room_id_bytes: &[u8; ROOM_ID_LEN],
    msg_id: &[u8; MSG_ID_LEN],
    announce: &Announce,
) -> Result<Sealed> {
    let nonce: [u8; NONCE_LEN] = random::bytes()?;
    let ciphertext = seal_with_nonce(enc_key, epoch, room_id_bytes, msg_id, &nonce, announce)?;
    Ok(Sealed { nonce, ciphertext })
}

/// Seals with a caller supplied nonce.
///
/// This exists for known answer tests. Production code must use [`seal`], because reusing a nonce
/// with the same key breaks the AEAD.
///
/// # Errors
///
/// As for [`seal`], less the randomness failure.
pub fn seal_with_nonce(
    enc_key: &[u8; KEY_LEN],
    epoch: u32,
    room_id_bytes: &[u8; ROOM_ID_LEN],
    msg_id: &[u8; MSG_ID_LEN],
    nonce: &[u8; NONCE_LEN],
    announce: &Announce,
) -> Result<Vec<u8>> {
    let plaintext = encode(announce)?;
    clip::seal_typed(
        TYPE_ANNOUNCE,
        enc_key,
        epoch,
        room_id_bytes,
        msg_id,
        nonce,
        &plaintext,
    )
}

/// Opens a sealed announcement.
///
/// # Errors
///
/// Returns [`Error::Open`] if the ciphertext, tag, nonce or associated data do not match, which
/// includes a clip presented as an announcement, and a decoding error for a malformed plaintext.
pub fn open(
    enc_key: &[u8; KEY_LEN],
    epoch: u32,
    room_id_bytes: &[u8; ROOM_ID_LEN],
    msg_id: &[u8; MSG_ID_LEN],
    nonce: &[u8; NONCE_LEN],
    ciphertext: &[u8],
) -> Result<Announce> {
    let plaintext = clip::open_typed(
        TYPE_ANNOUNCE,
        enc_key,
        epoch,
        room_id_bytes,
        msg_id,
        nonce,
        ciphertext,
    )?;
    decode(&plaintext)
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: [u8; 32] = [7u8; 32];
    const ROOM: [u8; ROOM_ID_LEN] = [9u8; ROOM_ID_LEN];
    const MSG_ID: [u8; MSG_ID_LEN] = [3u8; MSG_ID_LEN];

    fn sample() -> Announce {
        Announce {
            device_id: [1u8; DEVICE_ID_LEN],
            ts_ms: 1_767_225_600_000,
            name: "ThinkPad X1".to_owned(),
            os: "Windows 11".to_owned(),
        }
    }

    #[test]
    fn round_trips() {
        let sealed = seal(&KEY, 0, &ROOM, &MSG_ID, &sample()).expect("seals");
        let opened =
            open(&KEY, 0, &ROOM, &MSG_ID, &sealed.nonce, &sealed.ciphertext).expect("opens");
        assert_eq!(opened, sample());
    }

    #[test]
    fn the_ciphertext_length_does_not_depend_on_the_name() {
        let short = Announce {
            name: "a".to_owned(),
            ..sample()
        };
        let long = Announce {
            name: "b".repeat(MAX_FIELD_BYTES),
            ..sample()
        };
        let a = seal(&KEY, 0, &ROOM, &MSG_ID, &short).expect("seals");
        let b = seal(&KEY, 0, &ROOM, &MSG_ID, &long).expect("seals");
        assert_eq!(a.ciphertext.len(), b.ciphertext.len());
    }

    #[test]
    fn a_tampered_ciphertext_is_refused() {
        let sealed = seal(&KEY, 0, &ROOM, &MSG_ID, &sample()).expect("seals");
        let mut ct = sealed.ciphertext;
        ct[10] ^= 1;
        assert_eq!(
            open(&KEY, 0, &ROOM, &MSG_ID, &sealed.nonce, &ct),
            Err(Error::Open)
        );
        let sealed = seal(&KEY, 0, &ROOM, &MSG_ID, &sample()).expect("seals");
        assert_eq!(
            open(
                &KEY,
                0,
                &ROOM,
                &[4u8; MSG_ID_LEN],
                &sealed.nonce,
                &sealed.ciphertext
            ),
            Err(Error::Open),
            "the message id is bound"
        );
    }

    #[test]
    fn a_clip_cannot_be_opened_as_an_announcement_or_the_reverse() {
        let plaintext = encode(&sample()).expect("encodes");
        let nonce = [5u8; NONCE_LEN];
        let as_clip =
            clip::seal_with_nonce(&KEY, 0, &ROOM, &MSG_ID, &nonce, &plaintext).expect("seals");
        assert_eq!(
            open(&KEY, 0, &ROOM, &MSG_ID, &nonce, &as_clip),
            Err(Error::Open)
        );

        let sealed = seal(&KEY, 0, &ROOM, &MSG_ID, &sample()).expect("seals");
        assert_eq!(
            clip::open(&KEY, 0, &ROOM, &MSG_ID, &sealed.nonce, &sealed.ciphertext),
            Err(Error::Open)
        );
    }

    #[test]
    fn an_over_long_field_is_refused_on_both_sides() {
        let long = Announce {
            os: "x".repeat(MAX_FIELD_BYTES + 1),
            ..sample()
        };
        assert_eq!(encode(&long).err(), Some(Error::AnnounceField));

        let mut buf = encode(&sample()).expect("encodes").to_vec();
        // The name length byte sits right after the version, the device id and the timestamp.
        buf[1 + 1 + DEVICE_ID_LEN + 8] = u8::try_from(MAX_FIELD_BYTES + 1).expect("fits");
        assert_eq!(decode(&buf), Err(Error::AnnounceField));
    }

    #[test]
    fn padding_and_length_are_checked() {
        let good = encode(&sample()).expect("encodes").to_vec();
        let mut dirty = good.clone();
        dirty[PLAINTEXT_LEN - 1] = 1;
        assert_eq!(decode(&dirty), Err(Error::InnerMalformed));
        assert_eq!(
            decode(&good[..PLAINTEXT_LEN - 1]),
            Err(Error::InnerMalformed)
        );
    }

    #[test]
    fn truncation_never_splits_a_character() {
        let text = "\u{e9}".repeat(40); // two bytes each, 80 bytes
        let cut = truncate_utf8(&text, 63);
        assert_eq!(cut.len(), 62);
        assert_eq!(truncate_utf8("short", 64), "short");
    }
}
