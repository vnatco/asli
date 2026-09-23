//! Sealing and opening clipboard events.
//!
//! The public header is what the relay sees: protocol version, message type, room id, epoch,
//! message id and nonce. The associated data binds all of it:
//!
//! ```text
//! AAD = "asli/v1/aad" || u8(v) || u8(type_code) || u32be(epoch)
//!    || u8(16) || room_id_bytes || u8(16) || msg_id                 (51 bytes, fixed)
//! ```
//!
//! AAD is a fixed, length prefixed byte string and never serialized JSON, because JSON key order,
//! whitespace and number formatting are not canonical and two implementations would eventually
//! disagree about the bytes being authenticated.
//!
//! What is deliberately not in the AAD: `device_id`, `seq`, `ts_ms` and the content type. Those
//! live inside the ciphertext. Putting `device_id` in the AAD would hand the relay a stable per
//! device fingerprint for free, which is exactly the metadata we are trying not to leak. The
//! `msg_id` has to be public, because the relay uses it for dedup and sender exclusion, so it is
//! bound in the AAD instead.

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};
use zeroize::Zeroizing;

use crate::error::{Error, Result};
use crate::identity::ROOM_ID_LEN;
use crate::kdf::KEY_LEN;
use crate::random;

/// Protocol version carried in the public header and bound in the AAD.
pub const PROTOCOL_VERSION: u8 = 1;
/// Message type code for a clip.
pub const TYPE_CLIP: u8 = 1;
/// Length of a message id in bytes.
pub const MSG_ID_LEN: usize = 16;
/// Length of a device id in bytes.
pub const DEVICE_ID_LEN: usize = 16;
/// Length of the XChaCha20-Poly1305 nonce in bytes.
pub const NONCE_LEN: usize = 24;
/// Length of the Poly1305 tag in bytes, appended to the ciphertext.
pub const TAG_LEN: usize = 16;
/// Length of the associated data in bytes. Fixed in v1.
pub const AAD_LEN: usize = 51;
/// Domain separation label for the associated data.
pub const LABEL_AAD: &[u8] = b"asli/v1/aad";
/// Version byte of the inner plaintext layout.
pub const INNER_VERSION: u8 = 1;
/// Size of the inner plaintext header, before the content bytes.
pub const INNER_HEADER_LEN: usize = 1 + 1 + 1 + DEVICE_ID_LEN + 8 + 8 + 4;

// Length prefixes written into the AAD and the inner plaintext. These are separate `u8` constants
// rather than casts so that the wire format has no runtime panic path at all. The compile time
// assertions below keep them honest if a length ever changes.
const ROOM_ID_LEN_U8: u8 = 16;
const MSG_ID_LEN_U8: u8 = 16;
const DEVICE_ID_LEN_U8: u8 = 16;
const _: () = assert!(ROOM_ID_LEN_U8 as usize == ROOM_ID_LEN);
const _: () = assert!(MSG_ID_LEN_U8 as usize == MSG_ID_LEN);
const _: () = assert!(DEVICE_ID_LEN_U8 as usize == DEVICE_ID_LEN);

/// What a clip carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ContentType {
    /// UTF-8 text. The only type in v1.
    Text,
    /// A PNG image. Specified for v1.1, not yet produced by the client.
    ImagePng,
}

impl ContentType {
    /// The byte written into the inner plaintext.
    #[must_use]
    pub const fn code(self) -> u8 {
        match self {
            Self::Text => 1,
            Self::ImagePng => 2,
        }
    }

    /// Parses a content type byte.
    ///
    /// # Errors
    ///
    /// Returns [`Error::ContentType`] for an unknown code.
    pub const fn from_code(code: u8) -> Result<Self> {
        match code {
            1 => Ok(Self::Text),
            2 => Ok(Self::ImagePng),
            other => Err(Error::ContentType(other)),
        }
    }
}

/// The decrypted contents of a clip, including the fields that defend against a malicious relay.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Inner {
    /// Text or image.
    pub content_type: ContentType,
    /// Which device sent this. Receivers drop their own device id.
    pub device_id: [u8; DEVICE_ID_LEN],
    /// Per device monotonic counter. Receivers reject a value at or below the highest already
    /// seen from that device, which catches a relay replaying or rolling back one device.
    pub seq: u64,
    /// Sender wall clock in milliseconds. Advisory only: `seq` and `msg_id` carry the security
    /// weight, this drives the max age window and user interface ordering.
    pub ts_ms: u64,
    /// The clipboard payload itself.
    pub content: Vec<u8>,
}

impl Inner {
    /// Takes the decrypted payload out, leaving the clip empty.
    ///
    /// [`Drop`] wipes whatever is still here, which makes the field impossible to move out of
    /// normally. A caller that genuinely needs to own the bytes says so through this method, and
    /// takes responsibility for them: from that point the buffer is theirs and this crate no
    /// longer wipes it.
    #[must_use]
    pub fn take_content(&mut self) -> Vec<u8> {
        core::mem::take(&mut self.content)
    }
}

impl Drop for Inner {
    /// Wipes the decrypted payload when it goes out of scope.
    ///
    /// The keys in this crate have always been zeroized; the thing the keys protect was not. A
    /// decrypted clip is whatever was copied, which is routinely a password or a recovery phrase,
    /// and a plain `Vec` left to the allocator stays legible in the freed page and travels into
    /// swap and hibernation images.
    ///
    /// The honest limit, stated because it would otherwise be easy to overestimate what this
    /// buys. It wipes clips this crate still owns: ones rejected by the replay guard, ones of a
    /// content type the client does not handle, and every error path. A clip that is accepted is
    /// moved out through [`Inner::take_content`] and lives on in the caller, and the operating
    /// system's own clipboard is beyond reach entirely.
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.content.zeroize();
    }
}

/// Builds the 51 byte associated data for a clip.
#[must_use]
pub fn build_aad(
    version: u8,
    type_code: u8,
    epoch: u32,
    room_id_bytes: &[u8; ROOM_ID_LEN],
    msg_id: &[u8; MSG_ID_LEN],
) -> [u8; AAD_LEN] {
    let mut aad = [0u8; AAD_LEN];
    let mut at = 0;

    aad[at..at + LABEL_AAD.len()].copy_from_slice(LABEL_AAD);
    at += LABEL_AAD.len();

    aad[at] = version;
    at += 1;
    aad[at] = type_code;
    at += 1;

    aad[at..at + 4].copy_from_slice(&epoch.to_be_bytes());
    at += 4;

    aad[at] = ROOM_ID_LEN_U8;
    at += 1;
    aad[at..at + ROOM_ID_LEN].copy_from_slice(room_id_bytes);
    at += ROOM_ID_LEN;

    aad[at] = MSG_ID_LEN_U8;
    at += 1;
    aad[at..at + MSG_ID_LEN].copy_from_slice(msg_id);
    at += MSG_ID_LEN;

    debug_assert_eq!(at, AAD_LEN);
    aad
}

/// Rounds a plaintext length up to the next padding bucket.
///
/// Exact ciphertext lengths leak the length of whatever was copied, which for a clipboard is
/// unusually sensitive: it reveals password and token lengths and makes specific documents easy
/// to fingerprint. Powers of two up to 64 KiB, then multiples of 64 KiB, because doubling a 2 MiB
/// image to 4 MiB would be a real cost for no extra privacy.
#[must_use]
pub fn padded_len(len: usize) -> usize {
    const SMALL_MAX: usize = 64 * 1024;
    if len <= SMALL_MAX {
        let mut bucket = 256;
        while bucket < len {
            bucket *= 2;
        }
        return bucket;
    }
    len.div_ceil(SMALL_MAX) * SMALL_MAX
}

/// Encodes and pads the inner plaintext.
#[must_use]
pub fn encode_inner(inner: &Inner) -> Zeroizing<Vec<u8>> {
    let body_len = INNER_HEADER_LEN + inner.content.len();
    let total = padded_len(body_len);

    let mut out = Zeroizing::new(vec![0u8; total]);
    let buf = out.as_mut_slice();
    let mut at = 0;

    buf[at] = INNER_VERSION;
    at += 1;
    buf[at] = inner.content_type.code();
    at += 1;
    buf[at] = DEVICE_ID_LEN_U8;
    at += 1;
    buf[at..at + DEVICE_ID_LEN].copy_from_slice(&inner.device_id);
    at += DEVICE_ID_LEN;
    buf[at..at + 8].copy_from_slice(&inner.seq.to_be_bytes());
    at += 8;
    buf[at..at + 8].copy_from_slice(&inner.ts_ms.to_be_bytes());
    at += 8;

    // Content length is explicit, so de-padding needs no heuristics.
    let content_len = u32::try_from(inner.content.len()).unwrap_or(u32::MAX);
    buf[at..at + 4].copy_from_slice(&content_len.to_be_bytes());
    at += 4;

    buf[at..at + inner.content.len()].copy_from_slice(&inner.content);
    // The remaining bytes are already zero, which is the padding.

    out
}

/// Decodes the inner plaintext produced by [`encode_inner`].
///
/// # Errors
///
/// Returns [`Error::InnerMalformed`], [`Error::InnerVersion`] or [`Error::ContentType`].
pub fn decode_inner(buf: &[u8]) -> Result<Inner> {
    if buf.len() < INNER_HEADER_LEN {
        return Err(Error::InnerMalformed);
    }
    let mut at = 0;

    let version = buf[at];
    at += 1;
    if version != INNER_VERSION {
        return Err(Error::InnerVersion(version));
    }

    let content_type = ContentType::from_code(buf[at])?;
    at += 1;

    if buf[at] as usize != DEVICE_ID_LEN {
        return Err(Error::InnerMalformed);
    }
    at += 1;
    let mut device_id = [0u8; DEVICE_ID_LEN];
    device_id.copy_from_slice(&buf[at..at + DEVICE_ID_LEN]);
    at += DEVICE_ID_LEN;

    let seq = u64::from_be_bytes(
        buf[at..at + 8]
            .try_into()
            .map_err(|_| Error::InnerMalformed)?,
    );
    at += 8;
    let ts_ms = u64::from_be_bytes(
        buf[at..at + 8]
            .try_into()
            .map_err(|_| Error::InnerMalformed)?,
    );
    at += 8;

    let content_len = usize::try_from(u32::from_be_bytes(
        buf[at..at + 4]
            .try_into()
            .map_err(|_| Error::InnerMalformed)?,
    ))
    .map_err(|_| Error::InnerMalformed)?;
    at += 4;

    if buf.len() < at + content_len {
        return Err(Error::InnerMalformed);
    }
    let content = buf[at..at + content_len].to_vec();

    Ok(Inner {
        content_type,
        device_id,
        seq,
        ts_ms,
        content,
    })
}

/// A sealed clip, ready to be put on the wire.
pub struct Sealed {
    /// The 24 byte nonce, sent in the public header.
    pub nonce: [u8; NONCE_LEN],
    /// Ciphertext with the 16 byte tag appended.
    pub ciphertext: Vec<u8>,
}

/// Seals a clip under the epoch key.
///
/// The nonce is 24 fresh bytes from the operating system CSPRNG. Random 192 bit nonces are the
/// reason to pick `XChaCha` here: several devices share one key, so a counter scheme would need
/// nonce space partitioning that a stateless design cannot coordinate.
///
/// # Errors
///
/// Returns [`Error::Rng`] if randomness is unavailable, or [`Error::Seal`] if the AEAD refuses
/// the input.
pub fn seal(
    enc_key: &[u8; KEY_LEN],
    epoch: u32,
    room_id_bytes: &[u8; ROOM_ID_LEN],
    msg_id: &[u8; MSG_ID_LEN],
    inner: &Inner,
) -> Result<Sealed> {
    let nonce: [u8; NONCE_LEN] = random::bytes()?;
    let plaintext = encode_inner(inner);
    let ciphertext = seal_with_nonce(enc_key, epoch, room_id_bytes, msg_id, &nonce, &plaintext)?;
    Ok(Sealed { nonce, ciphertext })
}

/// Seals with a caller supplied nonce.
///
/// This exists for known answer tests. Production code must use [`seal`], because reusing a nonce
/// with the same key breaks the AEAD.
///
/// # Errors
///
/// Returns [`Error::Seal`] if the AEAD refuses the input.
pub fn seal_with_nonce(
    enc_key: &[u8; KEY_LEN],
    epoch: u32,
    room_id_bytes: &[u8; ROOM_ID_LEN],
    msg_id: &[u8; MSG_ID_LEN],
    nonce: &[u8; NONCE_LEN],
    plaintext: &[u8],
) -> Result<Vec<u8>> {
    seal_typed(
        TYPE_CLIP,
        enc_key,
        epoch,
        room_id_bytes,
        msg_id,
        nonce,
        plaintext,
    )
}

/// Seals any single frame message under the epoch key, with its own type code in the AAD.
///
/// Shared by clips and announcements. The type code is what keeps them apart: a clip ciphertext
/// presented as an announcement, or the other way round, fails the tag check.
pub(crate) fn seal_typed(
    type_code: u8,
    enc_key: &[u8; KEY_LEN],
    epoch: u32,
    room_id_bytes: &[u8; ROOM_ID_LEN],
    msg_id: &[u8; MSG_ID_LEN],
    nonce: &[u8; NONCE_LEN],
    plaintext: &[u8],
) -> Result<Vec<u8>> {
    let aad = build_aad(PROTOCOL_VERSION, type_code, epoch, room_id_bytes, msg_id);
    let cipher = XChaCha20Poly1305::new(&Key::from(*enc_key));
    cipher
        .encrypt(
            &XNonce::from(*nonce),
            Payload {
                msg: plaintext,
                aad: &aad,
            },
        )
        .map_err(|_| Error::Seal)
}

/// Opens a sealed clip.
///
/// # Errors
///
/// Returns [`Error::Open`] if the ciphertext, tag, nonce or associated data do not match. The
/// cause is deliberately not distinguished, so our error paths reveal nothing to an attacker.
pub fn open(
    enc_key: &[u8; KEY_LEN],
    epoch: u32,
    room_id_bytes: &[u8; ROOM_ID_LEN],
    msg_id: &[u8; MSG_ID_LEN],
    nonce: &[u8; NONCE_LEN],
    ciphertext: &[u8],
) -> Result<Inner> {
    let plaintext = open_typed(
        TYPE_CLIP,
        enc_key,
        epoch,
        room_id_bytes,
        msg_id,
        nonce,
        ciphertext,
    )?;
    decode_inner(&plaintext)
}

/// Opens any single frame message sealed by [`seal_typed`] under the same type code.
pub(crate) fn open_typed(
    type_code: u8,
    enc_key: &[u8; KEY_LEN],
    epoch: u32,
    room_id_bytes: &[u8; ROOM_ID_LEN],
    msg_id: &[u8; MSG_ID_LEN],
    nonce: &[u8; NONCE_LEN],
    ciphertext: &[u8],
) -> Result<Zeroizing<Vec<u8>>> {
    let aad = build_aad(PROTOCOL_VERSION, type_code, epoch, room_id_bytes, msg_id);
    let cipher = XChaCha20Poly1305::new(&Key::from(*enc_key));
    Ok(Zeroizing::new(
        cipher
            .decrypt(
                &XNonce::from(*nonce),
                Payload {
                    msg: ciphertext,
                    aad: &aad,
                },
            )
            .map_err(|_| Error::Open)?,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: [u8; 32] = [7u8; 32];
    const ROOM: [u8; ROOM_ID_LEN] = [9u8; ROOM_ID_LEN];
    const MSG_ID: [u8; MSG_ID_LEN] = [3u8; MSG_ID_LEN];

    fn sample() -> Inner {
        Inner {
            content_type: ContentType::Text,
            device_id: [1u8; DEVICE_ID_LEN],
            seq: 42,
            ts_ms: 1_767_225_600_000,
            content: b"hello from the other machine".to_vec(),
        }
    }

    #[test]
    fn aad_is_fixed_length_and_stable() {
        let aad = build_aad(PROTOCOL_VERSION, TYPE_CLIP, 0, &ROOM, &MSG_ID);
        assert_eq!(aad.len(), AAD_LEN);
        assert!(aad.starts_with(LABEL_AAD));
        let again = build_aad(PROTOCOL_VERSION, TYPE_CLIP, 0, &ROOM, &MSG_ID);
        assert_eq!(aad, again);
    }

    #[test]
    fn aad_changes_with_every_bound_field() {
        let base = build_aad(PROTOCOL_VERSION, TYPE_CLIP, 0, &ROOM, &MSG_ID);
        assert_ne!(base, build_aad(2, TYPE_CLIP, 0, &ROOM, &MSG_ID));
        assert_ne!(base, build_aad(PROTOCOL_VERSION, 2, 0, &ROOM, &MSG_ID));
        assert_ne!(
            base,
            build_aad(PROTOCOL_VERSION, TYPE_CLIP, 1, &ROOM, &MSG_ID)
        );
        assert_ne!(
            base,
            build_aad(PROTOCOL_VERSION, TYPE_CLIP, 0, &[8u8; ROOM_ID_LEN], &MSG_ID)
        );
        assert_ne!(
            base,
            build_aad(PROTOCOL_VERSION, TYPE_CLIP, 0, &ROOM, &[4u8; MSG_ID_LEN])
        );
    }

    #[test]
    fn inner_round_trips() {
        let inner = sample();
        let encoded = encode_inner(&inner);
        let decoded = decode_inner(&encoded).expect("decodes");
        assert_eq!(inner, decoded);
    }

    #[test]
    fn padding_hides_exact_length() {
        let short = Inner {
            content: b"a".to_vec(),
            ..sample()
        };
        let longer = Inner {
            content: b"abcdefghijklmnopqrstuvwxyz".to_vec(),
            ..sample()
        };
        assert_eq!(encode_inner(&short).len(), encode_inner(&longer).len());
    }

    #[test]
    fn padding_buckets_are_as_documented() {
        assert_eq!(padded_len(0), 256);
        assert_eq!(padded_len(256), 256);
        assert_eq!(padded_len(257), 512);
        assert_eq!(padded_len(65_536), 65_536);
        assert_eq!(padded_len(65_537), 131_072);
        assert_eq!(padded_len(200_000), 262_144);
    }

    #[test]
    fn seal_open_round_trips() {
        let inner = sample();
        let sealed = seal(&KEY, 0, &ROOM, &MSG_ID, &inner).expect("seals");
        let opened =
            open(&KEY, 0, &ROOM, &MSG_ID, &sealed.nonce, &sealed.ciphertext).expect("opens");
        assert_eq!(inner, opened);
    }

    #[test]
    fn ciphertext_is_padded_and_tagged() {
        let inner = sample();
        let sealed = seal(&KEY, 0, &ROOM, &MSG_ID, &inner).expect("seals");
        assert_eq!(
            sealed.ciphertext.len(),
            padded_len(INNER_HEADER_LEN + inner.content.len()) + TAG_LEN
        );
    }

    #[test]
    fn nonces_do_not_repeat() {
        let inner = sample();
        let a = seal(&KEY, 0, &ROOM, &MSG_ID, &inner).expect("seals");
        let b = seal(&KEY, 0, &ROOM, &MSG_ID, &inner).expect("seals");
        assert_ne!(a.nonce, b.nonce);
        assert_ne!(a.ciphertext, b.ciphertext);
    }

    #[test]
    fn open_rejects_a_flipped_ciphertext_bit() {
        let sealed = seal(&KEY, 0, &ROOM, &MSG_ID, &sample()).expect("seals");
        let mut ct = sealed.ciphertext.clone();
        ct[0] ^= 0x01;
        assert_eq!(
            open(&KEY, 0, &ROOM, &MSG_ID, &sealed.nonce, &ct),
            Err(Error::Open)
        );
    }

    #[test]
    fn open_rejects_a_flipped_tag_bit() {
        let sealed = seal(&KEY, 0, &ROOM, &MSG_ID, &sample()).expect("seals");
        let mut ct = sealed.ciphertext.clone();
        let last = ct.len() - 1;
        ct[last] ^= 0x01;
        assert_eq!(
            open(&KEY, 0, &ROOM, &MSG_ID, &sealed.nonce, &ct),
            Err(Error::Open)
        );
    }

    #[test]
    fn open_rejects_a_flipped_nonce_bit() {
        let sealed = seal(&KEY, 0, &ROOM, &MSG_ID, &sample()).expect("seals");
        let mut nonce = sealed.nonce;
        nonce[0] ^= 0x01;
        assert_eq!(
            open(&KEY, 0, &ROOM, &MSG_ID, &nonce, &sealed.ciphertext),
            Err(Error::Open)
        );
    }

    #[test]
    fn open_rejects_truncated_and_empty_ciphertext() {
        let sealed = seal(&KEY, 0, &ROOM, &MSG_ID, &sample()).expect("seals");
        let truncated = &sealed.ciphertext[..sealed.ciphertext.len() - 1];
        assert_eq!(
            open(&KEY, 0, &ROOM, &MSG_ID, &sealed.nonce, truncated),
            Err(Error::Open)
        );
        assert_eq!(
            open(&KEY, 0, &ROOM, &MSG_ID, &sealed.nonce, &[]),
            Err(Error::Open)
        );
    }

    #[test]
    fn open_rejects_changed_associated_data() {
        let sealed = seal(&KEY, 0, &ROOM, &MSG_ID, &sample()).expect("seals");
        // Wrong epoch.
        assert_eq!(
            open(&KEY, 1, &ROOM, &MSG_ID, &sealed.nonce, &sealed.ciphertext),
            Err(Error::Open)
        );
        // Wrong room.
        assert_eq!(
            open(
                &KEY,
                0,
                &[8u8; ROOM_ID_LEN],
                &MSG_ID,
                &sealed.nonce,
                &sealed.ciphertext
            ),
            Err(Error::Open)
        );
        // Wrong message id.
        assert_eq!(
            open(
                &KEY,
                0,
                &ROOM,
                &[4u8; MSG_ID_LEN],
                &sealed.nonce,
                &sealed.ciphertext
            ),
            Err(Error::Open)
        );
    }

    #[test]
    fn open_rejects_the_wrong_key() {
        let sealed = seal(&KEY, 0, &ROOM, &MSG_ID, &sample()).expect("seals");
        let mut other = KEY;
        other[0] ^= 0x01;
        assert_eq!(
            open(&other, 0, &ROOM, &MSG_ID, &sealed.nonce, &sealed.ciphertext),
            Err(Error::Open)
        );
    }

    #[test]
    fn decode_inner_rejects_malformed_input() {
        assert_eq!(decode_inner(&[]), Err(Error::InnerMalformed));
        assert_eq!(decode_inner(&[0u8; 10]), Err(Error::InnerMalformed));

        let mut encoded = encode_inner(&sample()).to_vec();
        encoded[0] = 9;
        assert_eq!(decode_inner(&encoded), Err(Error::InnerVersion(9)));

        let mut encoded = encode_inner(&sample()).to_vec();
        encoded[1] = 99;
        assert_eq!(decode_inner(&encoded), Err(Error::ContentType(99)));

        // A content length that runs past the end of the buffer.
        let mut encoded = encode_inner(&sample()).to_vec();
        let at = 1 + 1 + 1 + DEVICE_ID_LEN + 8 + 8;
        encoded[at..at + 4].copy_from_slice(&u32::MAX.to_be_bytes());
        assert_eq!(decode_inner(&encoded), Err(Error::InnerMalformed));
    }

    #[test]
    fn empty_content_round_trips() {
        let inner = Inner {
            content: Vec::new(),
            ..sample()
        };
        let sealed = seal(&KEY, 0, &ROOM, &MSG_ID, &inner).expect("seals");
        let opened =
            open(&KEY, 0, &ROOM, &MSG_ID, &sealed.nonce, &sealed.ciphertext).expect("opens");
        assert_eq!(inner, opened);
    }

    #[test]
    fn large_content_round_trips() {
        let inner = Inner {
            content: vec![b'x'; 200_000],
            ..sample()
        };
        let sealed = seal(&KEY, 0, &ROOM, &MSG_ID, &inner).expect("seals");
        let opened =
            open(&KEY, 0, &ROOM, &MSG_ID, &sealed.nonce, &sealed.ciphertext).expect("opens");
        assert_eq!(inner, opened);
    }
}
