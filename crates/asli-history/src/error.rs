//! Error type for the history store.

use core::fmt;

/// Everything that can go wrong reading or writing the history.
///
/// No variant carries clipboard content or key material, so an `Error` is always safe to log.
#[derive(Debug)]
#[non_exhaustive]
pub enum Error {
    /// The store file could not be read, written, renamed or removed.
    Io(std::io::Error),
    /// A cryptographic operation failed.
    ///
    /// On open this means the file does not decrypt under this account's key, which happens when
    /// the account was reset, when the file belongs to a different account, or when it was
    /// tampered with. All three are the same recovery: discard and start again.
    Crypto(asli_crypto::Error),
    /// The file exists but its framing is not something this version understands.
    Malformed,
    /// The file carries a format version from a newer build.
    UnsupportedVersion(u8),
    /// An entry was requested that is not in the store.
    NotFound,
    /// A configured cap was nonsense, for example zero entries.
    BadConfig(&'static str),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(err) => write!(f, "history file error: {err}"),
            Self::Crypto(err) => write!(f, "history could not be decrypted: {err}"),
            Self::Malformed => f.write_str("the history file is malformed"),
            Self::UnsupportedVersion(v) => {
                write!(f, "history format version {v} is from a newer build")
            }
            Self::NotFound => f.write_str("no such history entry"),
            Self::BadConfig(what) => write!(f, "invalid history configuration: {what}"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(err) => Some(err),
            Self::Crypto(err) => Some(err),
            _ => None,
        }
    }
}

impl From<std::io::Error> for Error {
    fn from(err: std::io::Error) -> Self {
        Self::Io(err)
    }
}

impl From<asli_crypto::Error> for Error {
    fn from(err: asli_crypto::Error) -> Self {
        Self::Crypto(err)
    }
}

/// Convenient result alias.
pub type Result<T> = core::result::Result<T, Error>;
