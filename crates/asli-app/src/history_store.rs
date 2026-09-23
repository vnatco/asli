//! The real history, on disk and encrypted.
//!
//! This is the implementation the window's [`crate::window::HistorySource`] seam was shaped for.
//! Everything it does is delegated to `asli-history`, which owns the file format, the key
//! derivation and the eviction policy. Nothing here decides anything about how history is stored;
//! it only translates between that crate's vocabulary and the window's.
//!
//! The two vocabularies line up deliberately: `asli_history::Summary` carries the same fields as
//! [`crate::window::HistoryEntry`], and `asli_history::Content` the same variants as
//! [`crate::window::HistoryContent`]. That is why this file is a translation and not a design.
//!
//! # What is not stored
//!
//! A clip the platform marked as concealed. The marker exists because a password manager asked
//! for that clip to be left alone, and writing it into a list on disk would undo exactly that.
//! The refusal happens inside `asli-history`, which reports it rather than silently dropping it.

use asli_history::{Content, Kind, Limits, Store};

use crate::clipboard_io::log_line;
use crate::config::{Config, Paths};
use crate::window::{HistoryContent, HistoryEntry, HistorySource};

/// The file the history lives in, beside the configuration.
const FILE: &str = "history.bin";

/// History backed by the encrypted store.
pub struct StoreHistory {
    store: Store,
    enabled: bool,
    /// Bumped on every change. See [`HistorySource::revision`].
    revision: u64,
}

/// Opens the history for this account, discarding a file that cannot be read.
///
/// A history is a convenience, not a record of account. A file left by a previous account will not
/// decrypt under this one, and refusing to start over that would be the wrong trade, so
/// `open_or_reset` starts again and says what it discarded.
///
/// # Errors
///
/// Returns the underlying error if the file could not be read or removed, or if the configured
/// limits are nonsense.
pub fn open(
    paths: &Paths,
    secret: &[u8; 32],
    config: &Config,
) -> Result<StoreHistory, asli_history::Error> {
    let limits = Limits {
        max_entries: config.history_entries,
        ..Limits::default()
    };

    let (store, discarded) = Store::open_or_reset(paths.dir.join(FILE), secret, limits)?;

    if let Some(reason) = discarded {
        // Said out loud. A history that silently empties looks like data loss, and the usual
        // cause is joining a different account, which is a thing the person did on purpose.
        eprintln!(
            "{}",
            log_line(
                "history_reset",
                &format!("previous file unusable: {reason}")
            )
        );
    }

    Ok(StoreHistory {
        store,
        enabled: config.keep_history,
        revision: 0,
    })
}

impl core::fmt::Debug for StoreHistory {
    /// Written by hand, like the one in `asli-history`, and for the same reason: a derived
    /// implementation would print the entries.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("StoreHistory")
            .field("enabled", &self.enabled)
            .field("entries", &self.store.len())
            .field("revision", &self.revision)
            .finish()
    }
}

impl HistorySource for StoreHistory {
    fn enabled(&self) -> bool {
        self.enabled
    }

    fn entries(&self) -> Vec<HistoryEntry> {
        self.store
            .list()
            .into_iter()
            .map(|summary| HistoryEntry {
                preview: summary.preview,
                is_image: matches!(summary.kind, Kind::ImagePng),
                ts_ms: summary.ts_ms,
                bytes: summary.bytes,
                from: summary.device_id,
                key: summary.id,
            })
            .collect()
    }

    fn restore(&self, index: usize) -> Option<HistoryContent> {
        // Looked up by position because that is what the window knows: a row index. The entry id
        // never leaves this file, which keeps identifiers out of the markup entirely.
        let id = self.store.list().get(index).map(|summary| summary.id)?;

        match self.store.get(&id) {
            Ok(Content::Text(text)) => Some(HistoryContent::Text(text)),
            Ok(Content::ImagePng(png)) => Some(HistoryContent::ImagePng(png)),
            // `Content` is deliberately non exhaustive, so a kind added later lands here rather
            // than breaking the build. Refusing is right: this version has no way to put a kind
            // it does not recognise onto a clipboard, and guessing would paste the wrong thing.
            Ok(_) => {
                eprintln!(
                    "{}",
                    log_line("history_read_failed", "an entry of an unknown kind")
                );
                None
            }
            Err(err) => {
                eprintln!("{}", log_line("history_read_failed", &err.to_string()));
                None
            }
        }
    }

    fn record(&mut self, content: HistoryContent, sensitive: bool, ts_ms: u64, from: [u8; 16]) {
        if !self.enabled {
            return;
        }

        let content = match content {
            HistoryContent::Text(text) => Content::Text(text),
            HistoryContent::ImagePng(png) => Content::ImagePng(png),
        };

        self.revision = self.revision.wrapping_add(1);
        if let Err(err) = self.store.append_from(content, sensitive, ts_ms, from) {
            // Never fatal. Failing to remember a clip must not stop it being synced, which is the
            // thing the person actually asked for.
            eprintln!("{}", log_line("history_write_failed", &err.to_string()));
        }
    }

    fn forget(&mut self, index: usize) -> bool {
        let Some(id) = self.store.list().get(index).map(|summary| summary.id) else {
            return false;
        };

        self.revision = self.revision.wrapping_add(1);
        match self.store.remove(&id) {
            Ok(()) => true,
            Err(err) => {
                eprintln!("{}", log_line("history_remove_failed", &err.to_string()));
                false
            }
        }
    }

    fn clear(&mut self) {
        self.revision = self.revision.wrapping_add(1);
        if let Err(err) = self.store.clear() {
            eprintln!("{}", log_line("history_clear_failed", &err.to_string()));
        }
    }

    fn set_enabled(&mut self, enabled: bool) {
        self.enabled = enabled;
        if !enabled {
            // Turning it off means the list goes, not that it freezes. Anything else leaves a
            // file of clipboard contents behind after somebody asked for it to stop.
            self.clear();
        }
    }

    fn set_limit(&mut self, limit: usize) {
        // The store fixes its limits when it opens, and reopening would need the account secret
        // again, which this type deliberately does not keep. The new value is already saved to the
        // configuration by the caller, so it applies on the next start. The Settings screen says
        // so rather than implying the change took effect now.
        let _ = limit;
    }

    fn revision(&self) -> u64 {
        // Enabled is part of what the screen shows, so flipping it counts as a change too.
        self.revision.wrapping_mul(2) | u64::from(self.enabled)
    }
}

/// Removes the archive, overwriting it first.
///
/// For `asli reset`. The records are sealed with a key derived from the same root secret, so the
/// leaked key this command abandons would still read anything left behind.
///
/// # Errors
///
/// Returns [`crate::Error::Io`] if the file exists and cannot be overwritten or removed.
pub fn wipe(paths: &Paths) -> crate::Result<()> {
    asli_history::wipe_file(&paths.dir.join(FILE))
        .map_err(|e| crate::Error::Parse(format!("could not wipe the history: {e}")))
}
