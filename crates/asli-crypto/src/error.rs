//! Error type for every fallible operation in this crate.

use core::fmt;

/// Everything that can go wrong in `asli-crypto`.
///
/// Variants deliberately carry no attacker controlled data and no secret material, so an
/// `Error` is always safe to log.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    /// The operating system random number generator failed. This is fatal by design: we never
    /// fall back to a user space PRNG.
    Rng,
    /// A join token did not start with the expected prefix.
    TokenPrefix,
    /// A join token contained characters outside the Crockford base32 alphabet.
    TokenAlphabet,
    /// A join token decoded to the wrong number of bytes, or ended mid byte. Both mean it was
    /// cut short or had characters dropped.
    TokenLength,
    /// A join token carried an unsupported format version byte.
    TokenVersion(u8),
    /// A join token's checksum did not match, so it was mistyped or truncated.
    TokenChecksum,
    /// A byte string had the wrong length for the field it was being parsed into.
    FieldLength {
        /// Name of the field, a static string, never user input.
        field: &'static str,
        /// How many bytes were expected.
        expected: usize,
        /// How many bytes were supplied.
        got: usize,
    },
    /// AEAD sealing failed. In practice this only happens if the plaintext is absurdly large.
    Seal,
    /// AEAD opening failed: the ciphertext, tag, nonce or associated data did not match.
    ///
    /// This is deliberately one variant. Distinguishing the causes would leak information to an
    /// attacker who can observe our error paths.
    Open,
    /// The decrypted inner plaintext was malformed.
    InnerMalformed,
    /// The decrypted inner plaintext carried an unsupported version byte.
    InnerVersion(u8),
    /// The decrypted inner plaintext carried an unknown content type byte.
    ContentType(u8),
    /// A public key was not a valid Ed25519 encoding.
    BadPublicKey,
    /// A signature was not a valid Ed25519 encoding, or did not verify.
    BadSignature,
    /// A room id did not match the public key that was presented with it.
    RoomBinding,
    /// Text was not valid UTF-8.
    NotUtf8,
    /// A chunk count was zero, or beyond the cap that bounds a receiver's allocation.
    ChunkCount,
    /// A chunk did not belong where it claimed: wrong message, wrong total, an index outside the
    /// range, or an index that already arrived.
    ///
    /// One variant rather than four on purpose. Distinguishing them would tell a relay probing the
    /// receiver exactly which of its manipulations was detected.
    ChunkMismatch,
    /// Reassembly was attempted with a chunk still missing.
    ChunkIncomplete,
    /// The chunks accumulated past the size cap, detected mid stream rather than at the end.
    ChunkTooLarge,
    /// A device name or operating system in an announcement was longer than the field allows.
    AnnounceField,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Rng => f.write_str("the operating system random number generator failed"),
            Self::TokenPrefix => f.write_str("join token does not start with the expected prefix"),
            Self::TokenAlphabet => f.write_str("join token contains invalid characters"),
            Self::TokenLength => f.write_str("join token has the wrong length, it looks cut off"),
            Self::TokenVersion(v) => write!(f, "join token format version {v} is not supported"),
            Self::TokenChecksum => {
                f.write_str("join token checksum does not match, it looks mistyped or truncated")
            }
            Self::FieldLength {
                field,
                expected,
                got,
            } => write!(f, "field {field} expected {expected} bytes, got {got}"),
            Self::Seal => f.write_str("encryption failed"),
            Self::Open => f.write_str("decryption failed"),
            Self::InnerMalformed => f.write_str("decrypted payload is malformed"),
            Self::InnerVersion(v) => write!(f, "payload version {v} is not supported"),
            Self::ContentType(t) => write!(f, "content type {t} is not supported"),
            Self::BadPublicKey => f.write_str("invalid public key"),
            Self::BadSignature => f.write_str("invalid signature"),
            Self::RoomBinding => f.write_str("room id does not match the public key"),
            Self::NotUtf8 => f.write_str("content is not valid UTF-8"),
            Self::ChunkCount => f.write_str("chunk count is zero or beyond the supported maximum"),
            Self::ChunkMismatch => f.write_str("a chunk did not belong to this message"),
            Self::ChunkIncomplete => f.write_str("a chunk is missing, so nothing was reassembled"),
            Self::ChunkTooLarge => f.write_str("the chunked payload exceeded the size cap"),
            Self::AnnounceField => f.write_str(
                "a device name or operating system is longer than an announcement allows",
            ),
        }
    }
}

impl std::error::Error for Error {}

/// Convenient result alias.
pub type Result<T> = core::result::Result<T, Error>;
