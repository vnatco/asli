//! Errors from the clipboard layer.
//!
//! These are deliberately specific about *which* platform mechanism failed, because the single
//! most common support question for a tool like this is "why is nothing syncing on my machine",
//! and the answer is almost always in this enum.

use core::fmt;

/// Everything the clipboard layer can fail at.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    /// No usable clipboard backend exists for this session.
    ///
    /// The message names what was tried, because this is the error a user will paste into an
    /// issue.
    NoBackend(String),
    /// Could not connect to the display server.
    Connect(String),
    /// The compositor does not offer a clipboard manager protocol, and there is no fallback.
    ///
    /// On Wayland this means neither `ext-data-control-v1` nor `wlr-data-control-unstable-v1` is
    /// advertised, and no X11 display is available to bridge through. river is the known case.
    NoProtocol(String),
    /// A required X11 extension is missing or too old.
    MissingExtension(&'static str),
    /// The display server connection broke while we were watching it.
    ConnectionLost(String),
    /// Reading the current selection failed or timed out.
    Read(String),
    /// Taking ownership of the selection, or writing the clipboard, failed.
    Write(String),
    /// The clipboard held bytes that are not valid UTF-8, where text was expected.
    NotUtf8,
    /// The watcher was asked to stop.
    Shutdown,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoBackend(detail) => {
                write!(f, "no usable clipboard backend for this session: {detail}")
            }
            Self::Connect(detail) => write!(f, "could not connect to the display server: {detail}"),
            Self::NoProtocol(detail) => write!(
                f,
                "this compositor offers no clipboard manager protocol: {detail}"
            ),
            Self::MissingExtension(name) => {
                write!(f, "the {name} extension is missing or too old")
            }
            Self::ConnectionLost(detail) => {
                write!(f, "lost the display server connection: {detail}")
            }
            Self::Read(detail) => write!(f, "could not read the clipboard: {detail}"),
            Self::Write(detail) => write!(f, "could not write the clipboard: {detail}"),
            Self::NotUtf8 => f.write_str("the clipboard held text that is not valid UTF-8"),
            Self::Shutdown => f.write_str("the clipboard watcher was shut down"),
        }
    }
}

impl std::error::Error for Error {}

/// Convenient result alias.
pub type Result<T> = core::result::Result<T, Error>;
