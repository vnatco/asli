//! Chunked transfer, for payloads too large for one frame.
//!
//! A clip is one sealed message. An image is not: a 2 MiB screenshot against a 1 MiB frame cap has
//! to cross in pieces, and pieces are where chunked AEAD schemes usually go wrong.
//!
//! The failure mode is specific. If each chunk is sealed with only the message id bound, then
//! every chunk of a message is interchangeable from the AEAD's point of view, and a relay can
//! reorder them, drop one from the middle, or truncate the stream early, and every individual
//! chunk still verifies. The receiver reassembles corrupted or attacker chosen content and has no
//! way to notice. So the index, the total count and the final flag are bound into each chunk's
//! associated data, which makes a chunk verify only in the exact position it was sealed for.
//!
//! ```text
//! AAD = "asli/v1/caad"                (12 bytes)
//!    || u8(v)                          protocol version                  (1)
//!    || u8(type_code)                   2, 3 or 4                        (1)
//!    || u32be(epoch)                                                     (4)
//!    || u8(16) || room_id_bytes                                          (1 + 16)
//!    || u8(16) || msg_id                                                 (1 + 16)
//!    || u32be(idx)                      0 based chunk index              (4)
//!    || u32be(chunk_count)              total chunks in this message     (4)
//!    || u8(final)                       1 for the last chunk, else 0     (1)
//!
//! total = 12 + 1 + 1 + 4 + 17 + 17 + 4 + 4 + 1 = 61 bytes, fixed
//! ```
//!
//! The label differs from the single clip AAD (`asli/v1/aad`), so a chunk can never be mistaken
//! for a whole clip even if every other field somehow matched. The clip AAD stays exactly 51 bytes
//! as section 9.1 specifies: this is a separate construction, not an extension of it.
//!
//! What is deliberately still absent: `device_id`, `seq` and `ts_ms`. Those live in the inner
//! plaintext of the reassembled message, exactly as they do for a single clip, so the relay gains
//! no per device identifier from a chunked transfer either.

use zeroize::Zeroizing;

use crate::clip::{
    ContentType, Inner, DEVICE_ID_LEN, INNER_HEADER_LEN, MSG_ID_LEN, NONCE_LEN, TAG_LEN,
};
use crate::error::{Error, Result};
use crate::identity::ROOM_ID_LEN;
use crate::kdf::KEY_LEN;

/// Protocol version carried in every chunk header.
pub const PROTOCOL_VERSION: u8 = 1;

/// Message type code for `clip_begin`.
pub const TYPE_CLIP_BEGIN: u8 = 2;
/// Message type code for `clip_chunk`.
pub const TYPE_CLIP_CHUNK: u8 = 3;
/// Message type code for `clip_end`.
pub const TYPE_CLIP_END: u8 = 4;

/// Domain separation label for chunk associated data.
pub const LABEL_CHUNK_AAD: &[u8] = b"asli/v1/caad";

/// Length of chunk associated data in bytes. Fixed in v1.
pub const CHUNK_AAD_LEN: usize = 61;

/// Default payload size per chunk, before sealing.
///
/// Chosen so that a sealed chunk plus its base64 expansion and JSON envelope sits comfortably
/// inside a 1 MiB frame cap: 256 KiB becomes about 341 KiB encoded, leaving ample headroom.
pub const DEFAULT_CHUNK_BYTES: usize = 256 * 1024;

/// Largest number of chunks one message may have.
///
/// A cap that exists so a hostile `chunk_count` cannot make a receiver preallocate. At the default
/// chunk size this still permits a 1 GiB payload, far beyond any content limit a relay announces.
pub const MAX_CHUNKS: u32 = 4096;

// Length prefixes as `u8` constants, so the layout has no runtime panic path.
const ROOM_ID_LEN_U8: u8 = 16;
const MSG_ID_LEN_U8: u8 = 16;
const _: () = assert!(ROOM_ID_LEN_U8 as usize == ROOM_ID_LEN);
const _: () = assert!(MSG_ID_LEN_U8 as usize == MSG_ID_LEN);

/// Where a chunk sits in its message.
///
/// These three fields travel together everywhere because they are exactly what the associated
/// data binds. Passing them as one value means a caller cannot seal at one position and open at
/// another by transposing two arguments, which is the mistake this type exists to prevent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChunkPos {
    /// Zero based index of this chunk.
    pub idx: u32,
    /// Total chunks in this message.
    pub chunk_count: u32,
    /// Whether this is the last chunk.
    pub final_chunk: bool,
}

impl ChunkPos {
    /// The type code a chunk at this position carries.
    #[must_use]
    pub const fn type_code(self) -> u8 {
        chunk_type_code(self.idx, self.final_chunk)
    }
}

/// Builds the 61 byte associated data for one chunk.
///
/// `idx`, `chunk_count` and `final_chunk` are the fields that make reordering, dropping and
/// truncation detectable, so they are bound here rather than carried in the plaintext.
#[must_use]
pub fn build_chunk_aad(
    version: u8,
    type_code: u8,
    epoch: u32,
    room_id_bytes: &[u8; ROOM_ID_LEN],
    msg_id: &[u8; MSG_ID_LEN],
    pos: ChunkPos,
) -> [u8; CHUNK_AAD_LEN] {
    let ChunkPos {
        idx,
        chunk_count,
        final_chunk,
    } = pos;
    let mut aad = [0u8; CHUNK_AAD_LEN];
    let mut at = 0;

    aad[at..at + LABEL_CHUNK_AAD.len()].copy_from_slice(LABEL_CHUNK_AAD);
    at += LABEL_CHUNK_AAD.len();

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

    aad[at..at + 4].copy_from_slice(&idx.to_be_bytes());
    at += 4;
    aad[at..at + 4].copy_from_slice(&chunk_count.to_be_bytes());
    at += 4;

    aad[at] = u8::from(final_chunk);
    at += 1;

    debug_assert_eq!(at, CHUNK_AAD_LEN);
    aad
}

/// One sealed chunk, ready for the wire.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SealedChunk {
    /// Zero based index of this chunk.
    pub idx: u32,
    /// Total chunks in this message, repeated in every chunk and bound in its AAD.
    pub chunk_count: u32,
    /// Whether this is the last chunk.
    pub final_chunk: bool,
    /// Fresh 24 byte nonce for this chunk alone.
    pub nonce: [u8; NONCE_LEN],
    /// Ciphertext with the 16 byte tag appended.
    pub ciphertext: Vec<u8>,
}

/// Splits an inner plaintext into sealed chunks.
///
/// The whole message is encoded and padded exactly as a single clip would be, then split. Doing it
/// in that order means the padding hides the true content length rather than only the length of
/// the final chunk, and it means the reassembled bytes are byte for byte what `decode_inner`
/// already understands.
///
/// # Errors
///
/// Returns [`Error::Rng`] if randomness is unavailable, [`Error::Seal`] if the AEAD refuses the
/// input, and [`Error::ChunkCount`] if the payload would need more than [`MAX_CHUNKS`] chunks.
pub fn seal_chunks(
    enc_key: &[u8; KEY_LEN],
    epoch: u32,
    room_id_bytes: &[u8; ROOM_ID_LEN],
    msg_id: &[u8; MSG_ID_LEN],
    inner: &Inner,
    chunk_bytes: usize,
) -> Result<Vec<SealedChunk>> {
    let plaintext = crate::clip::encode_inner(inner);
    seal_plaintext_chunks(
        enc_key,
        epoch,
        room_id_bytes,
        msg_id,
        &plaintext,
        chunk_bytes,
    )
}

/// Splits an already encoded plaintext into sealed chunks.
///
/// Exposed so the vector generator can seal a fixed plaintext with fixed nonces. Production code
/// should call [`seal_chunks`].
///
/// # Errors
///
/// As [`seal_chunks`].
pub fn seal_plaintext_chunks(
    enc_key: &[u8; KEY_LEN],
    epoch: u32,
    room_id_bytes: &[u8; ROOM_ID_LEN],
    msg_id: &[u8; MSG_ID_LEN],
    plaintext: &[u8],
    chunk_bytes: usize,
) -> Result<Vec<SealedChunk>> {
    let chunk_bytes = chunk_bytes.max(1);
    let total = plaintext.len().div_ceil(chunk_bytes).max(1);
    let chunk_count = u32::try_from(total).map_err(|_| Error::ChunkCount)?;
    if chunk_count > MAX_CHUNKS {
        return Err(Error::ChunkCount);
    }

    let mut out = Vec::with_capacity(total);
    for (index, piece) in plaintext.chunks(chunk_bytes).enumerate() {
        let idx = u32::try_from(index).map_err(|_| Error::ChunkCount)?;
        let pos = ChunkPos {
            idx,
            chunk_count,
            final_chunk: idx + 1 == chunk_count,
        };
        let nonce: [u8; NONCE_LEN] = crate::random::bytes()?;
        let ciphertext =
            seal_chunk_with_nonce(enc_key, epoch, room_id_bytes, msg_id, &nonce, pos, piece)?;
        out.push(SealedChunk {
            idx,
            chunk_count,
            final_chunk: pos.final_chunk,
            nonce,
            ciphertext,
        });
    }
    Ok(out)
}

/// Seals one chunk with a caller supplied nonce.
///
/// For known answer tests. Production code must let [`seal_chunks`] draw the nonce, because
/// reusing one with the same key breaks the AEAD.
///
/// # Errors
///
/// Returns [`Error::Seal`] if the AEAD refuses the input.
pub fn seal_chunk_with_nonce(
    enc_key: &[u8; KEY_LEN],
    epoch: u32,
    room_id_bytes: &[u8; ROOM_ID_LEN],
    msg_id: &[u8; MSG_ID_LEN],
    nonce: &[u8; NONCE_LEN],
    pos: ChunkPos,
    piece: &[u8],
) -> Result<Vec<u8>> {
    use chacha20poly1305::aead::{Aead, KeyInit, Payload};
    use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};

    let aad = build_chunk_aad(
        PROTOCOL_VERSION,
        pos.type_code(),
        epoch,
        room_id_bytes,
        msg_id,
        pos,
    );
    let cipher = XChaCha20Poly1305::new(Key::from_slice(enc_key));
    cipher
        .encrypt(
            XNonce::from_slice(nonce),
            Payload {
                msg: piece,
                aad: &aad,
            },
        )
        .map_err(|_| Error::Seal)
}

/// Opens one chunk, returning its plaintext piece.
///
/// # Errors
///
/// Returns [`Error::Open`] if anything about the chunk does not match the position it claims.
pub fn open_chunk(
    enc_key: &[u8; KEY_LEN],
    epoch: u32,
    room_id_bytes: &[u8; ROOM_ID_LEN],
    msg_id: &[u8; MSG_ID_LEN],
    nonce: &[u8; NONCE_LEN],
    pos: ChunkPos,
    ciphertext: &[u8],
) -> Result<Zeroizing<Vec<u8>>> {
    use chacha20poly1305::aead::{Aead, KeyInit, Payload};
    use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};

    let aad = build_chunk_aad(
        PROTOCOL_VERSION,
        pos.type_code(),
        epoch,
        room_id_bytes,
        msg_id,
        pos,
    );
    let cipher = XChaCha20Poly1305::new(Key::from_slice(enc_key));
    let plaintext = cipher
        .decrypt(
            XNonce::from_slice(nonce),
            Payload {
                msg: ciphertext,
                aad: &aad,
            },
        )
        .map_err(|_| Error::Open)?;
    Ok(Zeroizing::new(plaintext))
}

/// The type code a chunk at this position carries.
///
/// The first chunk is `clip_begin`, the last is `clip_end`, everything between is `clip_chunk`.
/// A single chunk message is both, and resolves to `clip_end` so that a receiver cannot be handed
/// a `clip_begin` that silently completes.
#[must_use]
pub const fn chunk_type_code(idx: u32, final_chunk: bool) -> u8 {
    if final_chunk {
        TYPE_CLIP_END
    } else if idx == 0 {
        TYPE_CLIP_BEGIN
    } else {
        TYPE_CLIP_CHUNK
    }
}

/// Reassembles chunks into an inner clip, refusing anything incomplete or out of order.
///
/// Nothing is returned until the count matches and every index from zero to `chunk_count - 1` has
/// arrived exactly once, which is what the receiving rule in the protocol requires: a partial
/// assembly is discarded, never committed.
pub struct Assembly {
    msg_id: [u8; MSG_ID_LEN],
    epoch: u32,
    chunk_count: u32,
    pieces: Vec<Option<Zeroizing<Vec<u8>>>>,
    received: u32,
    bytes: usize,
    max_bytes: usize,
}

impl Assembly {
    /// Starts an assembly for a message whose first chunk has arrived.
    ///
    /// # Errors
    ///
    /// Returns [`Error::ChunkCount`] for a count of zero or one above [`MAX_CHUNKS`].
    pub fn new(
        msg_id: [u8; MSG_ID_LEN],
        epoch: u32,
        chunk_count: u32,
        max_bytes: usize,
    ) -> Result<Self> {
        if chunk_count == 0 || chunk_count > MAX_CHUNKS {
            return Err(Error::ChunkCount);
        }
        // Allocating one Option per chunk is bounded by MAX_CHUNKS, so a hostile count cannot turn
        // into a large allocation.
        let slots = usize::try_from(chunk_count).map_err(|_| Error::ChunkCount)?;
        Ok(Self {
            msg_id,
            epoch,
            chunk_count,
            pieces: vec![None; slots],
            received: 0,
            bytes: 0,
            max_bytes,
        })
    }

    /// The message this assembly belongs to.
    #[must_use]
    pub const fn msg_id(&self) -> &[u8; MSG_ID_LEN] {
        &self.msg_id
    }

    /// Total chunks expected.
    #[must_use]
    pub const fn chunk_count(&self) -> u32 {
        self.chunk_count
    }

    /// Bytes accepted so far, across all chunks.
    #[must_use]
    pub const fn bytes(&self) -> usize {
        self.bytes
    }

    /// Whether every chunk has arrived.
    #[must_use]
    pub const fn is_complete(&self) -> bool {
        self.received == self.chunk_count
    }

    /// Accepts one opened chunk.
    ///
    /// # Errors
    ///
    /// Returns [`Error::ChunkMismatch`] when the chunk belongs to another message, claims a
    /// different total, sits outside the range, or repeats an index already held, and
    /// [`Error::ChunkTooLarge`] when the accumulated payload exceeds the cap.
    pub fn accept(
        &mut self,
        msg_id: &[u8; MSG_ID_LEN],
        epoch: u32,
        idx: u32,
        chunk_count: u32,
        piece: Zeroizing<Vec<u8>>,
    ) -> Result<()> {
        if msg_id != &self.msg_id || epoch != self.epoch || chunk_count != self.chunk_count {
            return Err(Error::ChunkMismatch);
        }
        let slot = usize::try_from(idx).map_err(|_| Error::ChunkMismatch)?;
        let Some(entry) = self.pieces.get_mut(slot) else {
            return Err(Error::ChunkMismatch);
        };
        if entry.is_some() {
            // A repeated index is either a buggy sender or a relay replaying a chunk to see what
            // happens. Either way the assembly is no longer trustworthy.
            return Err(Error::ChunkMismatch);
        }

        let next = self.bytes.saturating_add(piece.len());
        if next > self.max_bytes {
            return Err(Error::ChunkTooLarge);
        }

        self.bytes = next;
        *entry = Some(piece);
        self.received += 1;
        Ok(())
    }

    /// Reassembles and decodes, consuming the assembly.
    ///
    /// # Errors
    ///
    /// Returns [`Error::ChunkIncomplete`] if a chunk is still missing, and whatever
    /// [`crate::clip::decode_inner`] returns for a payload that does not decode.
    pub fn finish(self) -> Result<Inner> {
        if !self.is_complete() {
            return Err(Error::ChunkIncomplete);
        }
        let mut joined = Zeroizing::new(Vec::with_capacity(self.bytes));
        for piece in &self.pieces {
            let Some(piece) = piece.as_ref() else {
                return Err(Error::ChunkIncomplete);
            };
            joined.extend_from_slice(piece);
        }
        if joined.len() < INNER_HEADER_LEN {
            return Err(Error::InnerMalformed);
        }
        crate::clip::decode_inner(&joined)
    }
}

/// Whether a content type is permitted to travel chunked.
///
/// Text is never chunked in v1: it is small enough to fit a frame with room to spare, and allowing
/// two paths for the same content would mean two paths to test and two to get wrong.
#[must_use]
pub const fn may_chunk(content_type: ContentType) -> bool {
    matches!(content_type, ContentType::ImagePng)
}

/// How many chunks a payload of this size will produce.
#[must_use]
pub fn chunk_count_for(payload_len: usize, chunk_bytes: usize) -> u32 {
    let chunk_bytes = chunk_bytes.max(1);
    let total = payload_len.div_ceil(chunk_bytes).max(1);
    u32::try_from(total).unwrap_or(u32::MAX)
}

/// Smallest possible sealed chunk, used by receivers to reject absurd input cheaply.
pub const MIN_SEALED_CHUNK_LEN: usize = TAG_LEN + 1;

/// Size of the device id, re-exported so callers building an [`Inner`] need one import fewer.
pub const CHUNK_DEVICE_ID_LEN: usize = DEVICE_ID_LEN;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::clip::{ContentType, Inner};

    const KEY: [u8; KEY_LEN] = [7u8; KEY_LEN];
    const ROOM: [u8; ROOM_ID_LEN] = [9u8; ROOM_ID_LEN];
    const MSG_ID: [u8; MSG_ID_LEN] = [3u8; MSG_ID_LEN];
    const OTHER_MSG_ID: [u8; MSG_ID_LEN] = [4u8; MSG_ID_LEN];
    const MAX_BYTES: usize = 8 * 1024 * 1024;

    fn image(len: usize) -> Inner {
        Inner {
            content_type: ContentType::ImagePng,
            device_id: [1u8; DEVICE_ID_LEN],
            seq: 42,
            ts_ms: 1_767_225_600_000,
            content: (0..len)
                .map(|i| u8::try_from(i % 251).unwrap_or(0))
                .collect(),
        }
    }

    fn seal(inner: &Inner, chunk_bytes: usize) -> Vec<SealedChunk> {
        seal_chunks(&KEY, 0, &ROOM, &MSG_ID, inner, chunk_bytes).expect("seals")
    }

    fn open_all(chunks: &[SealedChunk]) -> Result<Inner> {
        let count = chunks[0].chunk_count;
        let mut assembly = Assembly::new(MSG_ID, 0, count, MAX_BYTES).expect("starts");
        for chunk in chunks {
            let piece = open_chunk(
                &KEY,
                0,
                &ROOM,
                &MSG_ID,
                &chunk.nonce,
                ChunkPos {
                    idx: chunk.idx,
                    chunk_count: chunk.chunk_count,
                    final_chunk: chunk.final_chunk,
                },
                &chunk.ciphertext,
            )?;
            assembly.accept(&MSG_ID, 0, chunk.idx, chunk.chunk_count, piece)?;
        }
        assembly.finish()
    }

    #[test]
    fn aad_is_fixed_length_and_distinct_from_a_clip() {
        let pos = ChunkPos {
            idx: 0,
            chunk_count: 3,
            final_chunk: false,
        };
        let aad = build_chunk_aad(1, TYPE_CLIP_BEGIN, 0, &ROOM, &MSG_ID, pos);
        assert_eq!(aad.len(), CHUNK_AAD_LEN);
        assert!(aad.starts_with(LABEL_CHUNK_AAD));
        // The clip label is a prefix of neither, so the two constructions cannot be confused.
        assert_ne!(&aad[..11], crate::clip::LABEL_AAD);
    }

    #[test]
    fn aad_changes_with_index_count_and_final_flag() {
        let at = |idx, chunk_count, final_chunk| ChunkPos {
            idx,
            chunk_count,
            final_chunk,
        };
        let base = build_chunk_aad(1, TYPE_CLIP_CHUNK, 0, &ROOM, &MSG_ID, at(1, 3, false));
        assert_ne!(
            base,
            build_chunk_aad(1, TYPE_CLIP_CHUNK, 0, &ROOM, &MSG_ID, at(2, 3, false)),
            "index must be bound"
        );
        assert_ne!(
            base,
            build_chunk_aad(1, TYPE_CLIP_CHUNK, 0, &ROOM, &MSG_ID, at(1, 4, false)),
            "count must be bound"
        );
        assert_ne!(
            base,
            build_chunk_aad(1, TYPE_CLIP_CHUNK, 0, &ROOM, &MSG_ID, at(1, 3, true)),
            "final flag must be bound"
        );
        assert_ne!(
            base,
            build_chunk_aad(1, TYPE_CLIP_CHUNK, 1, &ROOM, &MSG_ID, at(1, 3, false)),
            "epoch must be bound"
        );
        assert_ne!(
            base,
            build_chunk_aad(1, TYPE_CLIP_CHUNK, 0, &ROOM, &OTHER_MSG_ID, at(1, 3, false)),
            "message id must be bound"
        );
    }

    #[test]
    fn type_codes_follow_position() {
        assert_eq!(chunk_type_code(0, false), TYPE_CLIP_BEGIN);
        assert_eq!(chunk_type_code(1, false), TYPE_CLIP_CHUNK);
        assert_eq!(chunk_type_code(2, true), TYPE_CLIP_END);
        // A single chunk message is final, so it is an end rather than a begin.
        assert_eq!(chunk_type_code(0, true), TYPE_CLIP_END);
    }

    #[test]
    fn round_trips_a_multi_chunk_image() {
        let inner = image(700_000);
        let chunks = seal(&inner, 64 * 1024);
        assert!(chunks.len() > 5, "expected several chunks");
        assert_eq!(open_all(&chunks).expect("opens"), inner);
    }

    #[test]
    fn round_trips_a_single_chunk_message() {
        let inner = image(100);
        let chunks = seal(&inner, DEFAULT_CHUNK_BYTES);
        assert_eq!(chunks.len(), 1);
        assert!(chunks[0].final_chunk);
        assert_eq!(open_all(&chunks).expect("opens"), inner);
    }

    #[test]
    fn a_reordered_chunk_does_not_verify() {
        let chunks = seal(&image(300_000), 64 * 1024);
        // Present chunk 1's ciphertext as if it were chunk 2. The AAD binds the index, so the tag
        // check fails rather than silently producing scrambled content.
        let result = open_chunk(
            &KEY,
            0,
            &ROOM,
            &MSG_ID,
            &chunks[1].nonce,
            ChunkPos {
                idx: 2,
                chunk_count: chunks[1].chunk_count,
                final_chunk: false,
            },
            &chunks[1].ciphertext,
        );
        assert_eq!(result.err(), Some(Error::Open));
    }

    #[test]
    fn a_truncated_stream_is_rejected() {
        let chunks = seal(&image(300_000), 64 * 1024);
        let count = chunks[0].chunk_count;
        let mut assembly = Assembly::new(MSG_ID, 0, count, MAX_BYTES).expect("starts");
        // Everything except the last chunk.
        for chunk in &chunks[..chunks.len() - 1] {
            let piece = open_chunk(
                &KEY,
                0,
                &ROOM,
                &MSG_ID,
                &chunk.nonce,
                ChunkPos {
                    idx: chunk.idx,
                    chunk_count: chunk.chunk_count,
                    final_chunk: chunk.final_chunk,
                },
                &chunk.ciphertext,
            )
            .expect("opens");
            assembly
                .accept(&MSG_ID, 0, chunk.idx, chunk.chunk_count, piece)
                .expect("accepts");
        }
        assert!(!assembly.is_complete());
        assert_eq!(assembly.finish().err(), Some(Error::ChunkIncomplete));
    }

    #[test]
    fn a_dropped_middle_chunk_is_rejected() {
        let chunks = seal(&image(300_000), 64 * 1024);
        let count = chunks[0].chunk_count;
        let mut assembly = Assembly::new(MSG_ID, 0, count, MAX_BYTES).expect("starts");
        for chunk in chunks.iter().filter(|c| c.idx != 1) {
            let piece = open_chunk(
                &KEY,
                0,
                &ROOM,
                &MSG_ID,
                &chunk.nonce,
                ChunkPos {
                    idx: chunk.idx,
                    chunk_count: chunk.chunk_count,
                    final_chunk: chunk.final_chunk,
                },
                &chunk.ciphertext,
            )
            .expect("opens");
            assembly
                .accept(&MSG_ID, 0, chunk.idx, chunk.chunk_count, piece)
                .expect("accepts");
        }
        assert_eq!(assembly.finish().err(), Some(Error::ChunkIncomplete));
    }

    #[test]
    fn a_replayed_chunk_is_rejected() {
        let chunks = seal(&image(300_000), 64 * 1024);
        let count = chunks[0].chunk_count;
        let mut assembly = Assembly::new(MSG_ID, 0, count, MAX_BYTES).expect("starts");
        let piece = open_chunk(
            &KEY,
            0,
            &ROOM,
            &MSG_ID,
            &chunks[0].nonce,
            ChunkPos {
                idx: 0,
                chunk_count: count,
                final_chunk: false,
            },
            &chunks[0].ciphertext,
        )
        .expect("opens");
        assembly
            .accept(&MSG_ID, 0, 0, count, piece.clone())
            .expect("accepts");
        assert_eq!(
            assembly.accept(&MSG_ID, 0, 0, count, piece).err(),
            Some(Error::ChunkMismatch)
        );
    }

    #[test]
    fn a_chunk_from_another_message_is_rejected() {
        let chunks = seal(&image(300_000), 64 * 1024);
        let count = chunks[0].chunk_count;
        let mut assembly = Assembly::new(MSG_ID, 0, count, MAX_BYTES).expect("starts");
        let piece = Zeroizing::new(vec![0u8; 16]);
        assert_eq!(
            assembly.accept(&OTHER_MSG_ID, 0, 0, count, piece).err(),
            Some(Error::ChunkMismatch)
        );
    }

    #[test]
    fn a_chunk_claiming_another_total_is_rejected() {
        let mut assembly = Assembly::new(MSG_ID, 0, 4, MAX_BYTES).expect("starts");
        let piece = Zeroizing::new(vec![0u8; 16]);
        assert_eq!(
            assembly.accept(&MSG_ID, 0, 0, 5, piece).err(),
            Some(Error::ChunkMismatch)
        );
    }

    #[test]
    fn an_index_outside_the_range_is_rejected() {
        let mut assembly = Assembly::new(MSG_ID, 0, 2, MAX_BYTES).expect("starts");
        let piece = Zeroizing::new(vec![0u8; 16]);
        assert_eq!(
            assembly.accept(&MSG_ID, 0, 7, 2, piece).err(),
            Some(Error::ChunkMismatch)
        );
    }

    #[test]
    fn the_accumulated_cap_is_enforced_mid_stream() {
        let mut assembly = Assembly::new(MSG_ID, 0, 4, 100).expect("starts");
        let piece = Zeroizing::new(vec![0u8; 60]);
        assembly
            .accept(&MSG_ID, 0, 0, 4, piece.clone())
            .expect("first fits");
        assert_eq!(
            assembly.accept(&MSG_ID, 0, 1, 4, piece).err(),
            Some(Error::ChunkTooLarge),
            "the cap must bite before the assembly completes, not after"
        );
    }

    #[test]
    fn an_absurd_chunk_count_is_refused() {
        assert_eq!(
            Assembly::new(MSG_ID, 0, 0, MAX_BYTES).err(),
            Some(Error::ChunkCount)
        );
        assert_eq!(
            Assembly::new(MSG_ID, 0, MAX_CHUNKS + 1, MAX_BYTES).err(),
            Some(Error::ChunkCount)
        );
    }

    #[test]
    fn a_flipped_bit_in_a_chunk_does_not_verify() {
        let chunks = seal(&image(300_000), 64 * 1024);
        let mut ct = chunks[0].ciphertext.clone();
        ct[0] ^= 0x01;
        let result = open_chunk(
            &KEY,
            0,
            &ROOM,
            &MSG_ID,
            &chunks[0].nonce,
            ChunkPos {
                idx: 0,
                chunk_count: chunks[0].chunk_count,
                final_chunk: false,
            },
            &ct,
        );
        assert_eq!(result.err(), Some(Error::Open));
    }

    #[test]
    fn every_chunk_gets_its_own_nonce() {
        let chunks = seal(&image(300_000), 64 * 1024);
        let mut nonces: Vec<_> = chunks.iter().map(|c| c.nonce).collect();
        nonces.sort_unstable();
        let before = nonces.len();
        nonces.dedup();
        assert_eq!(nonces.len(), before, "nonce reuse across chunks");
    }

    #[test]
    fn only_images_may_chunk_in_v1() {
        assert!(may_chunk(ContentType::ImagePng));
        assert!(!may_chunk(ContentType::Text));
    }

    #[test]
    fn chunk_count_for_matches_what_sealing_produces() {
        for len in [0usize, 1, 1000, 64 * 1024, 64 * 1024 + 1, 700_000] {
            let inner = image(len);
            let produced = seal(&inner, 64 * 1024).len();
            let encoded = crate::clip::encode_inner(&inner);
            assert_eq!(
                produced,
                usize::try_from(chunk_count_for(encoded.len(), 64 * 1024)).unwrap_or(0),
                "mismatch at {len}"
            );
        }
    }
}
