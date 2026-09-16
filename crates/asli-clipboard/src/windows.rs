//! The Windows backend, built on `AddClipboardFormatListener`.
//!
//! Windows is the one platform that tells us when the clipboard changes without being asked, so
//! there is no polling here at all and an idle machine does no clipboard work.
//!
//! Three Win32 behaviours shape every decision below, and each one has cost a comparable tool a
//! bug report:
//!
//! 1. **`WM_CLIPBOARDUPDATE` is broadcast to every listener at once.** Every clipboard manager,
//!    cloud clipboard, antivirus scanner and remote desktop bridge on the machine races to open
//!    the clipboard in the same few milliseconds, and exactly one wins. Opening it from inside the
//!    notification handler is therefore documented by Microsoft as "mostly fails, sometimes works"
//!    on Windows 11. So the handler only notes that something changed, and the read happens later
//!    with backoff.
//! 2. **A format can be advertised without existing yet.** Asking for a delay rendered format
//!    makes the owning application produce it while the system waits, for up to 30 seconds, and we
//!    would be holding the clipboard open for all of it. Enumerating formats never triggers that,
//!    so we enumerate first and then ask for exactly one format.
//! 3. **There is a real sequence number.** `GetClipboardSequenceNumber` increments on every
//!    change, so recognising our own write is exact here, with no hashing and no timing window.
//!    This is the Windows equivalent of the `XFixes` owner check.
//!
//! Everything here goes through `clipboard-win`'s safe wrappers rather than raw bindings, because
//! the crate sets `forbid(unsafe_code)` and the `windows` crate is `unsafe` at every call site.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use clipboard_win::monitor::{Monitor, Shutdown};
use clipboard_win::{raw, Clipboard, EnumFormats};

use crate::error::{Error, Result};
use crate::image_bytes;
use crate::{ClipContent, ClipEvent, ClipboardWatcher, WriteReceipt};

/// How long to coalesce a burst of clipboard changes before reading.
///
/// One user copy often produces several notifications: an application that opens and closes the
/// clipboard more than once, or a history utility re-rendering formats afterwards. Reading once at
/// the end of the burst also avoids catching a partial set of formats mid write.
const DEBOUNCE: Duration = Duration::from_millis(100);

/// First retry delay when the clipboard is locked by another process.
const RETRY_BASE: Duration = Duration::from_millis(1);

/// How many times to retry opening the clipboard.
///
/// Doubling from 1 ms gives roughly 127 ms of waiting across eight attempts. Scintilla settled on
/// this shape after finding that most contention clears within one or two retries, which makes a
/// flat delay per attempt pure latency. Chromium uses five attempts at a flat 5 ms, and the .NET
/// clipboard uses ten at 100 ms, which is far too slow to sit in a clipboard event path.
const RETRY_ATTEMPTS: u32 = 8;

/// Clipboard format names that mark content as not for us.
///
/// Registered rather than constant, because Windows assigns their ids at runtime and hands the
/// same id to every process that registers the same name. That shared id is the whole mechanism
/// by which an unrelated application and this one agree about a piece of clipboard content.
const EXCLUDE_FROM_MONITORS: &str = "ExcludeClipboardContentFromMonitorProcessing";
/// Serialized `DWORD` of zero here means the item must stay out of the local clipboard history.
const CAN_INCLUDE_IN_HISTORY: &str = "CanIncludeInClipboardHistory";
/// Serialized `DWORD` of zero here means the item must not be synced to the user's other devices,
/// which is precisely what this application does.
const CAN_UPLOAD_TO_CLOUD: &str = "CanUploadToCloudClipboard";

/// The registered name Windows applications use for PNG on the clipboard.
///
/// Modern applications offer this alongside their bitmap, and it is preferred because it needs no
/// conversion and carries an alpha channel that a DIB round trip can lose.
const PNG_FORMAT: &str = "PNG";

/// `CF_DIBV5`, the device independent bitmap with an alpha channel.
const CF_DIBV5: u32 = 17;

/// `CF_DIB`, the older device independent bitmap.
const CF_DIB: u32 = 8;

/// `CF_UNICODETEXT`, the only text format worth reading.
///
/// `CF_TEXT` is the ANSI one and Windows synthesizes it from this, so reading it would only lose
/// information for content outside the active code page.
const CF_UNICODETEXT: u32 = 13;

/// Converts a device independent bitmap into PNG.
///
/// Windows hands out a DIB with no file header, because inside a clipboard there is no file. The
/// header is reconstructed by [`crate::image_bytes::bmp_file_header_for_dib`], which is pure byte
/// arithmetic and tested on every platform, and only the decode and re-encode happen here.
///
/// This is the single conversion boundary in the whole project. Carrying a second image format on
/// the wire instead is what makes Deskflow's macOS to Windows image paste fail.
///
/// # Errors
///
/// Returns [`Error::Read`] if the bitmap is malformed or cannot be re-encoded.
fn dib_to_png(dib: &[u8]) -> Result<Vec<u8>> {
    image_bytes::check_size(dib.len())?;

    let header = image_bytes::bmp_file_header_for_dib(dib)?;
    let mut bmp = Vec::with_capacity(header.len() + dib.len());
    bmp.extend_from_slice(&header);
    bmp.extend_from_slice(dib);

    let decoded = image::load_from_memory_with_format(&bmp, image::ImageFormat::Bmp)
        .map_err(|e| Error::Read(format!("could not decode the clipboard bitmap: {e}")))?;

    let mut png = std::io::Cursor::new(Vec::new());
    decoded
        .write_to(&mut png, image::ImageFormat::Png)
        .map_err(|e| Error::Read(format!("could not re-encode the bitmap as PNG: {e}")))?;

    Ok(png.into_inner())
}

/// The registered ids of the formats resolved once at startup: the three exclusion markers, and
/// PNG.
#[derive(Debug, Clone, Copy, Default)]
struct ExclusionFormats {
    exclude_from_monitors: Option<u32>,
    can_include_in_history: Option<u32>,
    can_upload_to_cloud: Option<u32>,
    png: Option<u32>,
}

impl ExclusionFormats {
    /// Registers the format names this backend needs.
    ///
    /// `RegisterClipboardFormat` returning `None` is not fatal: it means this Windows build does
    /// not know the name, in which case no application can be marking content with it either.
    fn register() -> Self {
        Self {
            exclude_from_monitors: raw::register_format(EXCLUDE_FROM_MONITORS).map(Into::into),
            can_include_in_history: raw::register_format(CAN_INCLUDE_IN_HISTORY).map(Into::into),
            can_upload_to_cloud: raw::register_format(CAN_UPLOAD_TO_CLOUD).map(Into::into),
            png: raw::register_format(PNG_FORMAT).map(Into::into),
        }
    }
}

/// What the clipboard is offering, as far as the sensitivity decision is concerned.
///
/// Gathered as plain data so the decision itself is a pure function, testable on any platform
/// rather than only on Windows.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Offer {
    /// Format ids currently on the clipboard.
    pub formats: Vec<u32>,
    /// The payload of `CanIncludeInClipboardHistory`, when that format is present.
    pub can_include_in_history: Option<Vec<u8>>,
    /// The payload of `CanUploadToCloudClipboard`, when that format is present.
    pub can_upload_to_cloud: Option<Vec<u8>>,
}

/// Reads a serialized `DWORD` payload as a boolean permission.
///
/// Microsoft specifies these as a four byte `DWORD`, zero meaning "no". A payload that is missing,
/// short or malformed is treated as no permission: for a clipboard sync tool, failing closed costs
/// one unsynced clip, and failing open leaks a password.
#[must_use]
pub fn dword_permits(payload: Option<&[u8]>) -> bool {
    match payload {
        None => true,
        Some(bytes) => match bytes.get(..4) {
            Some(head) => u32::from_le_bytes([head[0], head[1], head[2], head[3]]) != 0,
            None => false,
        },
    }
}

/// Decides whether an offer must be skipped without reading its content.
///
/// Presence alone is the signal for `ExcludeClipboardContentFromMonitorProcessing`: Microsoft
/// documents it as carrying "any data at all", so there is no payload to inspect.
#[must_use]
pub fn is_sensitive(offer: &Offer, formats: &ExclusionFormatIds) -> bool {
    if let Some(id) = formats.exclude_from_monitors {
        if offer.formats.contains(&id) {
            return true;
        }
    }

    if let Some(id) = formats.can_include_in_history {
        if offer.formats.contains(&id) && !dword_permits(offer.can_include_in_history.as_deref()) {
            return true;
        }
    }

    if let Some(id) = formats.can_upload_to_cloud {
        if offer.formats.contains(&id) && !dword_permits(offer.can_upload_to_cloud.as_deref()) {
            return true;
        }
    }

    false
}

/// The registered ids, in a form the pure decision function can take.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ExclusionFormatIds {
    /// Id of `ExcludeClipboardContentFromMonitorProcessing`, if registered.
    pub exclude_from_monitors: Option<u32>,
    /// Id of `CanIncludeInClipboardHistory`, if registered.
    pub can_include_in_history: Option<u32>,
    /// Id of `CanUploadToCloudClipboard`, if registered.
    pub can_upload_to_cloud: Option<u32>,
}

impl From<ExclusionFormats> for ExclusionFormatIds {
    fn from(value: ExclusionFormats) -> Self {
        Self {
            exclude_from_monitors: value.exclude_from_monitors,
            can_include_in_history: value.can_include_in_history,
            can_upload_to_cloud: value.can_upload_to_cloud,
        }
    }
}

/// How long to wait before the nth attempt at opening the clipboard.
///
/// Exposed so the arithmetic is tested rather than assumed.
#[must_use]
pub fn retry_delay(attempt: u32) -> Duration {
    RETRY_BASE * 2u32.saturating_pow(attempt)
}

/// Total time spent waiting if every attempt fails.
#[must_use]
pub fn retry_budget(attempts: u32) -> Duration {
    (0..attempts).map(retry_delay).sum()
}

/// Whether a change notification describes our own write.
///
/// `GetClipboardSequenceNumber` increments on every change, so the value captured immediately
/// after writing identifies that write exactly. This is layer three of loop prevention, and on
/// Windows it is precise: no hashing, no time window, no guessing.
#[must_use]
pub fn is_our_own_write(current: Option<u32>, last_written: Option<u32>) -> bool {
    match (current, last_written) {
        (Some(current), Some(written)) => current == written,
        _ => false,
    }
}

/// The Windows clipboard.
///
/// The `Monitor` itself is deliberately not held here. `clipboard-win` documents it as unsafe to
/// move between threads, while [`ClipboardWatcher`] requires `Send`, so the monitor is created
/// inside [`ClipboardWatcher::run`] on whichever thread runs the loop, and only its `Shutdown`
/// handle (which is `Send`) is published back here.
pub struct WindowsClipboard {
    formats: ExclusionFormats,
    shutdown: Arc<AtomicBool>,
    /// Published by `run` once the monitor exists.
    ///
    /// `Shutdown` signals by being dropped, so stopping the loop means taking this and letting it
    /// fall out of scope.
    stopper: Arc<Mutex<Option<Shutdown>>>,
    /// Sequence number captured immediately after our own last write.
    last_written_seq: Option<u32>,
    /// Whether the first notification has been seen.
    ///
    /// Windows does not announce the existing clipboard on startup the way a Wayland compositor
    /// does, so this exists only to swallow a notification that arrives from our own startup
    /// activity before the first real copy.
    seen_first_event: bool,
}

impl WindowsClipboard {
    /// Registers the exclusion formats and prepares the watcher.
    ///
    /// # Errors
    ///
    /// Currently infallible, and returns `Result` so that adding a real failure later is not a
    /// breaking change to callers.
    pub fn connect() -> Result<Self> {
        Ok(Self {
            formats: ExclusionFormats::register(),
            shutdown: Arc::new(AtomicBool::new(false)),
            stopper: Arc::new(Mutex::new(None)),
            last_written_seq: None,
            seen_first_event: false,
        })
    }

    /// A handle that can ask the watch loop to stop from another thread.
    #[must_use]
    pub fn shutdown_handle(&self) -> Arc<AtomicBool> {
        Arc::clone(&self.shutdown)
    }

    /// Opens the clipboard, retrying while another process holds it.
    ///
    /// `clipboard-win`'s own retry yields the scheduler between attempts rather than sleeping, so
    /// the backoff is layered here instead.
    fn open_with_backoff() -> Result<Clipboard> {
        let mut last = None;

        for attempt in 0..RETRY_ATTEMPTS {
            match Clipboard::new_attempts(1) {
                Ok(clipboard) => return Ok(clipboard),
                Err(err) => {
                    last = Some(err);
                    std::thread::sleep(retry_delay(attempt));
                }
            }
        }

        Err(Error::Read(format!(
            "another application held the clipboard open for {} ms: {}",
            retry_budget(RETRY_ATTEMPTS).as_millis(),
            last.map_or_else(|| "unknown".to_owned(), |e| format!("{e}"))
        )))
    }

    /// Collects the format list and the exclusion payloads.
    ///
    /// Enumeration never triggers a delayed render, so this is safe to do before deciding whether
    /// to read anything. The payloads read here are four byte integers belonging to the exclusion
    /// formats, never content.
    fn collect_offer(&self) -> Offer {
        let formats: Vec<u32> = EnumFormats::new().collect();

        let read_flag = |id: Option<u32>| -> Option<Vec<u8>> {
            let id = id?;
            if !formats.contains(&id) {
                return None;
            }
            let mut buf = Vec::new();
            raw::get_vec(id, &mut buf).ok().map(|_| buf)
        };

        Offer {
            can_include_in_history: read_flag(self.formats.can_include_in_history),
            can_upload_to_cloud: read_flag(self.formats.can_upload_to_cloud),
            formats,
        }
    }

    /// Reads the clipboard as text, after deciding it is safe to read at all.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Read`] if the clipboard cannot be opened or the read fails, and
    /// [`Error::NotUtf8`] if the conversion produces invalid UTF-8.
    pub fn read_clipboard(&self) -> Result<Option<ClipEvent>> {
        let _guard = Self::open_with_backoff()?;

        let offer = self.collect_offer();

        if is_sensitive(&offer, &self.formats.into()) {
            return Ok(Some(ClipEvent {
                content: ClipContent::Text(String::new()),
                sensitive: true,
            }));
        }

        // Text wins when a source offers both, which nearly every application does: copying a
        // rich text selection also puts a bitmap rendering on the clipboard, and syncing the
        // picture instead of the words would be astonishing.
        if offer.formats.contains(&CF_UNICODETEXT) {
            let mut buf = Vec::new();
            raw::get_string(&mut buf)
                .map_err(|e| Error::Read(format!("could not read clipboard text: {e}")))?;

            let raw_text = String::from_utf8(buf).map_err(|_| Error::NotUtf8)?;

            // Normalize at exactly one boundary, here, so the same text hashes identically on
            // every platform. Windows text arrives CRLF terminated and with a trailing NUL, both
            // of which this strips. Skipping it is how two machines end up growing the text on
            // every hop.
            let text = asli_core::normalize(&raw_text).into_owned();
            if !asli_core::is_syncable(&text) {
                return Ok(None);
            }

            return Ok(Some(ClipEvent {
                content: ClipContent::Text(text),
                sensitive: false,
            }));
        }

        // A source that offers PNG directly is preferred: no conversion, and the alpha channel
        // survives, which a DIB round trip can lose.
        if let Some(png_id) = self.formats.png {
            if offer.formats.contains(&png_id) {
                let mut buf = Vec::new();
                raw::get_vec(png_id, &mut buf)
                    .map_err(|e| Error::Read(format!("could not read the clipboard image: {e}")))?;
                image_bytes::validate_png(&buf)?;
                return Ok(Some(ClipEvent {
                    content: ClipContent::ImagePng(buf),
                    sensitive: false,
                }));
            }
        }

        // Older applications offer only a device independent bitmap, so it is converted here,
        // at the single conversion boundary in the project.
        for dib_format in [CF_DIBV5, CF_DIB] {
            if offer.formats.contains(&dib_format) {
                let mut buf = Vec::new();
                raw::get_vec(dib_format, &mut buf).map_err(|e| {
                    Error::Read(format!("could not read the clipboard bitmap: {e}"))
                })?;
                let png = dib_to_png(&buf)?;
                return Ok(Some(ClipEvent {
                    content: ClipContent::ImagePng(png),
                    sensitive: false,
                }));
            }
        }

        // A file list, or a format v1 does not carry.
        Ok(None)
    }

    /// Puts text on the clipboard and records the sequence number it produced.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Write`] if the clipboard cannot be opened or written.
    pub fn set_text(&mut self, text: &str) -> Result<WriteReceipt> {
        let native = asli_core::to_platform(text, asli_core::LineEnding::Crlf);

        let seq = {
            let _guard = Self::open_with_backoff()
                .map_err(|e| Error::Write(format!("could not open the clipboard: {e}")))?;

            // set_string empties the clipboard, converts to UTF-16 and terminates the string
            // itself, so adding a NUL here would put two on the clipboard.
            raw::set_string(&native)
                .map_err(|e| Error::Write(format!("could not set clipboard text: {e}")))?;

            raw::seq_num().map(Into::into)
        };

        self.last_written_seq = seq;
        Ok(WriteReceipt {
            seq: seq.map(u64::from),
        })
    }
}

impl ClipboardWatcher for WindowsClipboard {
    fn run(&mut self, sink: &mut dyn FnMut(ClipEvent)) -> Result<()> {
        let mut monitor = Monitor::new()
            .map_err(|e| Error::Connect(format!("could not create the clipboard listener: {e}")))?;

        // Published so shutdown() can drop it from another thread, which is how this crate
        // interrupts the blocking recv below.
        if let Ok(mut slot) = self.stopper.lock() {
            *slot = Some(monitor.shutdown_channel());
        }

        // A shutdown requested before run started must still be honoured.
        if self.shutdown.load(Ordering::Relaxed) {
            return Ok(());
        }

        loop {
            let got_event = monitor
                .recv()
                .map_err(|e| Error::ConnectionLost(format!("clipboard listener failed: {e}")))?;

            if !got_event || self.shutdown.load(Ordering::Relaxed) {
                return Ok(());
            }

            // The notification handler does no clipboard work whatsoever. Waiting here lets the
            // burst that one copy produces collapse into a single read, and lets whichever
            // application is mid write finish and release the lock.
            std::thread::sleep(DEBOUNCE);

            // Drain anything that piled up during the debounce, so a burst is one read.
            while monitor.try_recv().unwrap_or(false) {}

            if self.shutdown.load(Ordering::Relaxed) {
                return Ok(());
            }

            if is_our_own_write(raw::seq_num().map(Into::into), self.last_written_seq) {
                continue;
            }

            if !self.seen_first_event {
                self.seen_first_event = true;
            }

            match self.read_clipboard() {
                Ok(Some(event)) => sink(event),
                // Either there is no text on the clipboard, or the read lost the race for the
                // lock. Both are routine and neither should stop the watcher.
                Ok(None) | Err(Error::Read(_) | Error::NotUtf8) => {}
                Err(other) => return Err(other),
            }
        }
    }

    fn shutdown(&self) {
        self.shutdown.store(true, Ordering::Relaxed);

        // Shutdown signals by being dropped, so taking it out of the slot is the signal.
        if let Ok(mut slot) = self.stopper.lock() {
            slot.take();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ids() -> ExclusionFormatIds {
        ExclusionFormatIds {
            exclude_from_monitors: Some(0xC001),
            can_include_in_history: Some(0xC002),
            can_upload_to_cloud: Some(0xC003),
        }
    }

    #[test]
    fn plain_text_is_not_sensitive() {
        let offer = Offer {
            formats: vec![CF_UNICODETEXT],
            ..Offer::default()
        };
        assert!(!is_sensitive(&offer, &ids()));
    }

    #[test]
    fn the_monitor_exclusion_format_needs_no_payload() {
        // Microsoft documents this one as carrying "any data at all": presence is the signal.
        let offer = Offer {
            formats: vec![CF_UNICODETEXT, 0xC001],
            ..Offer::default()
        };
        assert!(is_sensitive(&offer, &ids()));
    }

    #[test]
    fn a_zero_dword_means_skip() {
        let offer = Offer {
            formats: vec![CF_UNICODETEXT, 0xC003],
            can_upload_to_cloud: Some(vec![0, 0, 0, 0]),
            ..Offer::default()
        };
        assert!(
            is_sensitive(&offer, &ids()),
            "CanUploadToCloudClipboard of zero is an application saying do not send this to my \
             other devices, which is exactly what we do"
        );
    }

    #[test]
    fn a_one_dword_means_allow() {
        let offer = Offer {
            formats: vec![CF_UNICODETEXT, 0xC003],
            can_upload_to_cloud: Some(vec![1, 0, 0, 0]),
            ..Offer::default()
        };
        assert!(!is_sensitive(&offer, &ids()));
    }

    #[test]
    fn history_exclusion_is_honoured_too() {
        let offer = Offer {
            formats: vec![CF_UNICODETEXT, 0xC002],
            can_include_in_history: Some(vec![0, 0, 0, 0]),
            ..Offer::default()
        };
        assert!(is_sensitive(&offer, &ids()));
    }

    #[test]
    fn a_malformed_payload_fails_closed() {
        // One unsynced clip is a far cheaper mistake than one leaked password.
        assert!(!dword_permits(Some(&[0, 0])));
        assert!(!dword_permits(Some(&[])));
        assert!(dword_permits(None));
        assert!(dword_permits(Some(&[1, 0, 0, 0])));
        assert!(!dword_permits(Some(&[0, 0, 0, 0])));
    }

    #[test]
    fn an_unregistered_format_cannot_mark_anything() {
        // If Windows never gave us an id, no application can be using that name either.
        let offer = Offer {
            formats: vec![CF_UNICODETEXT, 0xC001],
            ..Offer::default()
        };
        assert!(!is_sensitive(&offer, &ExclusionFormatIds::default()));
    }

    #[test]
    fn retry_backoff_doubles_and_stays_under_a_fifth_of_a_second() {
        assert_eq!(retry_delay(0), Duration::from_millis(1));
        assert_eq!(retry_delay(1), Duration::from_millis(2));
        assert_eq!(retry_delay(7), Duration::from_millis(128));

        let budget = retry_budget(RETRY_ATTEMPTS);
        assert_eq!(budget, Duration::from_millis(255));
        assert!(
            budget < Duration::from_millis(400),
            "a clipboard event path cannot afford a long stall"
        );
    }

    #[test]
    fn our_own_write_is_recognised_exactly() {
        assert!(is_our_own_write(Some(42), Some(42)));
        assert!(!is_our_own_write(Some(43), Some(42)));
    }

    #[test]
    fn without_a_sequence_number_nothing_is_suppressed() {
        // Failing open here is correct: the content hash guard in asli-core is the second layer,
        // and suppressing a real copy is worse than sending one extra.
        assert!(!is_our_own_write(None, Some(42)));
        assert!(!is_our_own_write(Some(42), None));
        assert!(!is_our_own_write(None, None));
    }
}
