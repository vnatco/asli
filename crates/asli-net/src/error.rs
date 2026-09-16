//! Errors from the transport layer.

use core::fmt;

/// Everything the transport can fail at.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    /// A frame was not valid JSON, or did not match the schema for its type.
    ///
    /// The detail is a static description, never the frame itself, because a frame can carry
    /// ciphertext and must not reach a log.
    Malformed(&'static str),
    /// A binary field decoded to the wrong number of bytes.
    FieldLength {
        /// Which field, a static string.
        field: &'static str,
        /// How many bytes the protocol requires.
        expected: usize,
        /// How many bytes arrived.
        got: usize,
    },
    /// A base64 field was not canonical base64.
    BadBase64(&'static str),
    /// The relay announced a protocol version or suite this client cannot speak.
    Unsupported(&'static str),
    /// A message arrived in a state that does not accept it, for example a clip before `auth_ok`.
    OutOfOrder(&'static str),
    /// Content is larger than the limit the relay announced.
    ContentTooLarge {
        /// Size of the content in bytes.
        got: usize,
        /// The announced limit in bytes.
        limit: usize,
    },
    /// The relay rejected authentication. Carries the machine readable code.
    AuthFailed(crate::envelope::AuthFailCode),
    /// A cryptographic operation failed.
    Crypto(asli_crypto::Error),
    /// The socket closed or could not be established.
    Transport(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Malformed(what) => write!(f, "malformed message: {what}"),
            Self::FieldLength {
                field,
                expected,
                got,
            } => write!(f, "field {field} expected {expected} bytes, got {got}"),
            Self::BadBase64(field) => write!(f, "field {field} is not valid base64"),
            Self::Unsupported(what) => write!(f, "the relay is not compatible: {what}"),
            Self::OutOfOrder(what) => write!(f, "message arrived out of order: {what}"),
            Self::ContentTooLarge { got, limit } => write!(
                f,
                "this clipboard item is {got} bytes and the relay accepts at most {limit}"
            ),
            Self::AuthFailed(code) => {
                write!(f, "the relay rejected authentication: {}", code.as_str())
            }
            Self::Crypto(err) => write!(f, "cryptographic failure: {err}"),
            Self::Transport(detail) => write!(f, "connection problem: {detail}"),
        }
    }
}

impl std::error::Error for Error {}

impl From<asli_crypto::Error> for Error {
    fn from(err: asli_crypto::Error) -> Self {
        Self::Crypto(err)
    }
}

/// Convenient result alias.
pub type Result<T> = core::result::Result<T, Error>;
