//! Errors from the application layer.

use core::fmt;

/// Everything the application layer can fail at.
#[derive(Debug)]
#[non_exhaustive]
pub enum Error {
    /// The configuration directory could not be determined or created.
    ConfigDir(String),
    /// Reading or writing a file under the configuration directory failed.
    Io(std::io::Error),
    /// A configuration or state file could not be parsed.
    Parse(String),
    /// No account exists yet on this device.
    NoAccount,
    /// An account already exists and would have been overwritten.
    AccountExists,
    /// The secret could not be stored anywhere, neither the keychain nor a file.
    SecretStore(String),
    /// The keychain exists but refused access: it is locked, or a prompt was dismissed or denied.
    ///
    /// Kept apart from "no account", because it may well hold one. Treating it as empty offered
    /// to create a new account over the real one.
    KeychainLocked(String),
    /// Something in the crypto layer failed.
    Crypto(asli_crypto::Error),
    /// Something in the clipboard layer failed.
    Clipboard(asli_clipboard::Error),
    /// Something in the transport layer failed.
    Net(asli_net::Error),
    /// A QR code could not be rendered.
    Qr(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ConfigDir(detail) => write!(f, "could not use the configuration directory: {detail}"),
            Self::Io(err) => write!(f, "file error: {err}"),
            Self::Parse(detail) => write!(f, "could not parse a stored file: {detail}"),
            Self::NoAccount => f.write_str(
                "no account on this device yet. Run 'asli create' to make one, or 'asli join <token>' to use an existing one",
            ),
            Self::AccountExists => f.write_str(
                "an account already exists on this device. Run 'asli reset' first if you really want to replace it",
            ),
            Self::SecretStore(detail) => write!(f, "could not store the account key: {detail}"),
            Self::KeychainLocked(detail) => write!(
                f,
                "the keychain is locked or refused access, so the account key cannot be read. Unlock it and start Asli again ({detail})"
            ),
            Self::Crypto(err) => write!(f, "{err}"),
            Self::Clipboard(err) => write!(f, "{err}"),
            Self::Net(err) => write!(f, "{err}"),
            Self::Qr(detail) => write!(f, "could not render the QR code: {detail}"),
        }
    }
}

impl std::error::Error for Error {}

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

impl From<asli_clipboard::Error> for Error {
    fn from(err: asli_clipboard::Error) -> Self {
        Self::Clipboard(err)
    }
}

impl From<asli_net::Error> for Error {
    fn from(err: asli_net::Error) -> Self {
        Self::Net(err)
    }
}

/// Convenient result alias.
pub type Result<T> = core::result::Result<T, Error>;
