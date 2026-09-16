//! Clipboard monitoring and writing, with one backend per platform.
//!
//! No existing crate does what this app needs. The closest, `clipboard-rs`, polls the whole
//! clipboard every 500 ms on Wayland, which is exactly the behaviour that makes clipboard tools
//! feel bad. So this crate owns the abstraction and reuses proven plumbing underneath: `x11rb`
//! for X11, the Wayland protocol crates for data control, `clipboard-win` on Windows and
//! `objc2-app-kit` on macOS.
//!
//! # The contract
//!
//! A [`ClipboardWatcher`] delivers events when the clipboard changes because **someone else**
//! changed it. Events caused by our own [`ClipboardWriter::write`] are suppressed by the backend
//! wherever the platform gives us a sequence number to do it with, and by the content hash guard
//! in `asli-core` everywhere else.
//!
//! A watcher must never deliver an event for content marked sensitive by its source application.
//! That check belongs in the backend, before the content is ever read into our memory, because
//! the marker travels with the offer and the whole point is not to touch a password at all.
//!
//! # Status
//!
//! All three platforms are implemented. The Linux backends are verified on real hardware. The
//! Windows and macOS ones are compile checked only, because both were written on Linux, and the
//! macOS one additionally carries open questions about the pasteboard permission alert that only
//! real hardware can settle.

#![forbid(unsafe_code)]

pub mod error;
pub mod image_bytes;
pub mod session;

#[cfg(target_os = "linux")]
pub mod linux_wayland;
#[cfg(target_os = "linux")]
pub mod linux_x11;
#[cfg(target_os = "macos")]
pub mod macos;
#[cfg(target_os = "windows")]
pub mod windows;

pub use error::{Error, Result};
pub use session::{Backend, Env, Plan, SessionKind};

/// What a clipboard event carries.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ClipContent {
    /// UTF-8 text, already normalized by `asli_core::normalize`.
    Text(String),
    /// A PNG image, and only ever a PNG.
    ///
    /// One format on the wire, converted at exactly one boundary if a platform offers something
    /// else. Deskflow carries BMP and that is why images pasted from macOS arrive corrupted on
    /// Windows, so this stays a single format on purpose.
    ImagePng(Vec<u8>),
}

impl ClipContent {
    /// Size in bytes, for the cap check that must happen before anything else.
    #[must_use]
    pub fn len(&self) -> usize {
        match self {
            Self::Text(text) => text.len(),
            Self::ImagePng(bytes) => bytes.len(),
        }
    }

    /// Whether there is nothing to sync.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// A short label for logs. Never the content itself.
    #[must_use]
    pub const fn kind_label(&self) -> &'static str {
        match self {
            Self::Text(_) => "text",
            Self::ImagePng(_) => "image/png",
        }
    }
}

/// One observed clipboard change.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClipEvent {
    /// The content, normalized.
    pub content: ClipContent,
    /// The source application marked this as sensitive, so it must not be synced.
    ///
    /// Backends set this from the platform markers: `x-kde-passwordManagerHint` on Linux, the
    /// `ExcludeClipboardContentFromMonitorProcessing` family on Windows, and the
    /// `org.nspasteboard.ConcealedType` conventions on macOS. When it is set, the content field
    /// is empty: we never read a secret we were told not to read.
    pub sensitive: bool,
}

/// What the platform gave us to recognise our own write later.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct WriteReceipt {
    /// A platform sequence number, where one exists. `changeCount` on macOS,
    /// `GetClipboardSequenceNumber` on Windows. Wayland data control has no equivalent.
    pub seq: Option<u64>,
}

/// Watches the system clipboard.
pub trait ClipboardWatcher: Send {
    /// Runs the watch loop, calling `sink` for every change that was not ours.
    ///
    /// This blocks until [`ClipboardWatcher::shutdown`] is called or the display server
    /// connection is lost.
    ///
    /// # Errors
    ///
    /// Returns an error if the connection cannot be established or is lost. A watcher that
    /// returns an error is finished: the supervisor reconnects by building a new one.
    fn run(&mut self, sink: &mut dyn FnMut(ClipEvent)) -> Result<()>;

    /// Asks the watch loop to stop. Safe to call from another thread.
    fn shutdown(&self);
}

/// Writes to the system clipboard.
pub trait ClipboardWriter: Send {
    /// Puts content on the clipboard.
    ///
    /// Callers must record the content hash in their echo guard **before** calling this, because
    /// the change notification can arrive before this function returns.
    ///
    /// # Errors
    ///
    /// Returns an error if the clipboard could not be written, for example because another
    /// application holds it open.
    fn write(&self, content: &ClipContent) -> Result<WriteReceipt>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn content_reports_its_size_and_label() {
        let text = ClipContent::Text("hello".to_owned());
        assert_eq!(text.len(), 5);
        assert!(!text.is_empty());
        assert_eq!(text.kind_label(), "text");

        let empty = ClipContent::Text(String::new());
        assert!(empty.is_empty());

        let png = ClipContent::ImagePng(vec![0u8; 12]);
        assert_eq!(png.len(), 12);
        assert_eq!(png.kind_label(), "image/png");
    }

    #[test]
    fn a_sensitive_event_carries_no_content() {
        // The contract: backends must not read content they were told is a secret.
        let event = ClipEvent {
            content: ClipContent::Text(String::new()),
            sensitive: true,
        };
        assert!(event.sensitive);
        assert!(event.content.is_empty());
    }
}
