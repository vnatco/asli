//! Encrypted local clipboard history for Asli.
//!
//! This is the first thing in the project to put clipboard content on disk, so the rules are
//! tighter than they would be for an ordinary cache:
//!
//! - **Encrypted at rest** under a key derived from the account secret with its own HKDF label,
//!   never the clip key. See [`key`].
//! - **Content marked sensitive is never recorded.** A password manager's copy leaves no trace,
//!   not even an encrypted one. The clipboard layer already sets that flag from the platform
//!   markers, so the decision is made before the bytes ever reach this crate.
//!   Refusing is also why [`Store::append`] returns [`Appended`] rather than a bare id: a caller
//!   that believes it stored something needs to be told when it did not.
//! - **Capped, and purgeable for real.** [`Store::clear`] overwrites the file before unlinking,
//!   because a plain `remove_file` leaves the plaintext recoverable.
//!
//! # Format
//!
//! One file. A short plaintext header, then a sequence of framed records, each sealed
//! independently with `XChaCha20-Poly1305` through `asli_crypto::clip`, which is the same AEAD
//! path the wire protocol uses. There is one cryptographic approach in this codebase, not two.
//!
//! ```text
//! header:  "ASLIHIST" || u8(format version)
//! record:  u32be(len) || 16 byte id || 24 byte nonce || ciphertext||tag
//! ```
//!
//! Each record's id is bound into its associated data, so a record cannot be moved to another id
//! or lifted into another account's file and still open.
//!
//! Sealing per record rather than sealing the whole file is deliberate: deleting one entry
//! rewrites the file but never has to decrypt the others, and a single corrupt record does not
//! cost the whole history.

#![forbid(unsafe_code)]

pub mod error;
pub mod key;

pub use error::{Error, Result};

use std::fs::{self, File, OpenOptions};
use std::io::{Seek, SeekFrom, Write};
// Read is only needed by the test helper that inspects the raw file on disk.
#[cfg(test)]
use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use asli_crypto::clip;
use zeroize::Zeroizing;

/// Magic bytes at the head of the file, so a wrong file is rejected rather than misparsed.
const MAGIC: &[u8; 8] = b"ASLIHIST";
/// Current on disk format version.
const FORMAT_VERSION: u8 = 1;
/// Header length: magic plus the version byte.
const HEADER_LEN: usize = MAGIC.len() + 1;

/// Length of an entry id, in bytes.
pub const ID_LEN: usize = 16;

/// Largest record this build will read, as a guard against a corrupt or hostile length prefix.
const MAX_RECORD_BYTES: usize = 64 * 1024 * 1024;

/// Smallest a record can be and still hold anything: an id, a nonce and a tag, with no content.
const MIN_RECORD_BYTES: usize = ID_LEN + clip::NONCE_LEN + clip::TAG_LEN;

/// How many characters of text a listing carries as a preview.
pub const PREVIEW_CHARS: usize = 120;

/// An entry id. Random, so ids do not leak ordering or count.
pub type Id = [u8; ID_LEN];

/// What a history entry holds.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Content {
    /// UTF-8 text, as normalized by the clipboard layer.
    Text(String),
    /// A PNG image, and only ever a PNG.
    ImagePng(Vec<u8>),
}

impl Content {
    /// Size in bytes.
    #[must_use]
    pub fn len(&self) -> usize {
        match self {
            Self::Text(text) => text.len(),
            Self::ImagePng(bytes) => bytes.len(),
        }
    }

    /// Whether there is nothing here.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Whether this is an image, which is budgeted separately from text.
    #[must_use]
    pub const fn is_image(&self) -> bool {
        matches!(self, Self::ImagePng(_))
    }

    /// A short label for logs. Never the content itself.
    #[must_use]
    pub const fn kind_label(&self) -> &'static str {
        match self {
            Self::Text(_) => "text",
            Self::ImagePng(_) => "image/png",
        }
    }

    fn content_type(&self) -> clip::ContentType {
        match self {
            Self::Text(_) => clip::ContentType::Text,
            Self::ImagePng(_) => clip::ContentType::ImagePng,
        }
    }

    fn as_bytes(&self) -> &[u8] {
        match self {
            Self::Text(text) => text.as_bytes(),
            Self::ImagePng(bytes) => bytes,
        }
    }

    fn from_parts(content_type: clip::ContentType, bytes: Vec<u8>) -> Result<Self> {
        match content_type {
            clip::ContentType::Text => String::from_utf8(bytes)
                .map(Self::Text)
                .map_err(|_| Error::Malformed),
            clip::ContentType::ImagePng => Ok(Self::ImagePng(bytes)),
            // ContentType is non exhaustive upstream. A type added later is not something this
            // build can render, so it is rejected rather than shown as the wrong thing.
            _ => Err(Error::Malformed),
        }
    }
}

/// What happened to an [`Store::append`] call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Appended {
    /// Stored as a new entry.
    Stored(Id),
    /// Identical content was already at the top, so nothing changed.
    AlreadyNewest(Id),
    /// Identical content existed further down and was moved to the top.
    MovedToTop(Id),
    /// Refused because the source marked it sensitive. Nothing was written.
    RefusedSensitive,
    /// Refused because it was empty.
    RefusedEmpty,
    /// Refused because it exceeds the per entry cap on its own.
    RefusedTooLarge {
        /// Size of the content in bytes.
        got: usize,
        /// The cap it exceeded.
        limit: usize,
    },
}

impl Appended {
    /// The id, when something is now in the store because of this call.
    #[must_use]
    pub const fn id(self) -> Option<Id> {
        match self {
            Self::Stored(id) | Self::AlreadyNewest(id) | Self::MovedToTop(id) => Some(id),
            _ => None,
        }
    }

    /// Whether the store changed on disk.
    #[must_use]
    pub const fn changed(self) -> bool {
        matches!(self, Self::Stored(_) | Self::MovedToTop(_))
    }
}

/// One row in a listing: enough to draw a list, without decrypting more than necessary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Summary {
    /// Which entry this is.
    pub id: Id,
    /// When it was captured, milliseconds since the Unix epoch.
    pub ts_ms: u64,
    /// Text or image.
    pub kind: Kind,
    /// Size of the full content in bytes.
    pub bytes: usize,
    /// First [`PREVIEW_CHARS`] characters, for text only. Empty for an image.
    pub preview: String,
}

/// The content type of an entry, without carrying the content.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// UTF-8 text.
    Text,
    /// A PNG image.
    ImagePng,
}

/// Caps on how much history is kept.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    /// Maximum number of entries, oldest evicted first.
    pub max_entries: usize,
    /// Maximum total bytes of text content.
    pub max_text_bytes: usize,
    /// Maximum total bytes of image content.
    ///
    /// Images are budgeted separately on purpose. Under one shared budget a single screenshot
    /// evicts the entire text history, which is precisely backwards: the text entries are small,
    /// numerous and the reason people open a history at all.
    pub max_image_bytes: usize,
    /// Largest single entry that will be stored at all.
    pub max_entry_bytes: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_entries: 100,
            max_text_bytes: 2 * 1024 * 1024,
            max_image_bytes: 16 * 1024 * 1024,
            max_entry_bytes: 8 * 1024 * 1024,
        }
    }
}

impl Limits {
    fn validate(self) -> Result<Self> {
        if self.max_entries == 0 {
            return Err(Error::BadConfig("max_entries must be at least 1"));
        }
        if self.max_entry_bytes == 0 {
            return Err(Error::BadConfig("max_entry_bytes must be at least 1"));
        }
        Ok(self)
    }
}

/// One decrypted entry, held in memory.
#[derive(Debug, Clone)]
struct Entry {
    id: Id,
    ts_ms: u64,
    content: Content,
}

impl Entry {
    fn summary(&self) -> Summary {
        let (kind, preview) = match &self.content {
            Content::Text(text) => (Kind::Text, text.chars().take(PREVIEW_CHARS).collect()),
            Content::ImagePng(_) => (Kind::ImagePng, String::new()),
        };
        Summary {
            id: self.id,
            ts_ms: self.ts_ms,
            kind,
            bytes: self.content.len(),
            preview,
        }
    }
}

/// The history store.
///
/// Entries are held newest first in memory and rewritten to disk on every change. That is the
/// right trade at these sizes: a hundred entries is nothing to rewrite, and it keeps the file a
/// single self consistent artefact rather than an append log needing compaction.
pub struct Store {
    path: PathBuf,
    key: Zeroizing<[u8; key::KEY_LEN]>,
    limits: Limits,
    entries: Vec<Entry>,
}

/// Written by hand rather than derived, and that is the whole point.
///
/// A derived `Debug` would print the history key and every decrypted entry, so a single
/// `{store:?}` in a log line, or one panic message from an `expect` in a test, would spill both
/// the key and the clipboard contents. This prints the shape and nothing else.
impl core::fmt::Debug for Store {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Store")
            .field("path", &self.path)
            .field("key", &"<redacted>")
            .field("limits", &self.limits)
            .field("entries", &self.entries.len())
            .finish()
    }
}

impl Store {
    /// Opens the store at `path`, creating it if it does not exist.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Io`] if the file cannot be read, [`Error::Crypto`] if it does not decrypt
    /// under this account's key, [`Error::Malformed`] if the framing is wrong, and
    /// [`Error::BadConfig`] if the limits are nonsense.
    pub fn open(
        path: impl Into<PathBuf>,
        secret: &[u8; key::KEY_LEN],
        limits: Limits,
    ) -> Result<Self> {
        let path = path.into();
        let limits = limits.validate()?;
        let key = key::derive(secret);

        let entries = if path.exists() {
            let raw = fs::read(&path)?;
            decode_all(&raw, &key)?
        } else {
            Vec::new()
        };

        Ok(Self {
            path,
            key,
            limits,
            entries,
        })
    }

    /// Opens the store, discarding a file that cannot be read.
    ///
    /// A history is a convenience, not a record of account. If the file belongs to a previous
    /// account, or was truncated by a full disk, the useful behaviour is to start again rather
    /// than refuse to run. The caller is told what was discarded so it can say so.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Io`] if the unreadable file could not be removed, or [`Error::BadConfig`]
    /// for nonsense limits.
    pub fn open_or_reset(
        path: impl Into<PathBuf>,
        secret: &[u8; key::KEY_LEN],
        limits: Limits,
    ) -> Result<(Self, Option<Error>)> {
        let path = path.into();
        match Self::open(&path, secret, limits) {
            Ok(store) => Ok((store, None)),
            Err(err @ (Error::Crypto(_) | Error::Malformed | Error::UnsupportedVersion(_))) => {
                if path.exists() {
                    shred(&path)?;
                }
                let store = Self::open(&path, secret, limits)?;
                Ok((store, Some(err)))
            }
            Err(other) => Err(other),
        }
    }

    /// Number of entries currently held.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the history is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// The caps in force.
    #[must_use]
    pub const fn limits(&self) -> Limits {
        self.limits
    }

    /// Records a clipboard capture.
    ///
    /// `sensitive` comes straight from the clipboard layer's platform markers. When it is set
    /// nothing is written, and the content is not even encrypted first.
    ///
    /// Identical content already present is moved to the top rather than duplicated, which is
    /// what every clipboard manager does and what people expect when they copy the same thing
    /// twice.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Io`] if the file could not be written, or [`Error::Crypto`] if sealing
    /// failed.
    pub fn append(&mut self, content: Content, sensitive: bool, ts_ms: u64) -> Result<Appended> {
        if sensitive {
            return Ok(Appended::RefusedSensitive);
        }
        if content.is_empty() {
            return Ok(Appended::RefusedEmpty);
        }
        if content.len() > self.limits.max_entry_bytes {
            return Ok(Appended::RefusedTooLarge {
                got: content.len(),
                limit: self.limits.max_entry_bytes,
            });
        }

        if let Some(position) = self.entries.iter().position(|e| e.content == content) {
            if position == 0 {
                // Already the newest. Touching the timestamp would rewrite the file for nothing.
                return Ok(Appended::AlreadyNewest(self.entries[0].id));
            }
            let mut existing = self.entries.remove(position);
            existing.ts_ms = ts_ms;
            let id = existing.id;
            self.entries.insert(0, existing);
            self.persist()?;
            return Ok(Appended::MovedToTop(id));
        }

        let id: Id = asli_crypto::random::bytes()?;
        self.entries.insert(0, Entry { id, ts_ms, content });
        self.evict();
        self.persist()?;
        Ok(Appended::Stored(id))
    }

    /// Lists entries, newest first.
    #[must_use]
    pub fn list(&self) -> Vec<Summary> {
        self.entries.iter().map(Entry::summary).collect()
    }

    /// Lists at most `limit` entries, newest first.
    #[must_use]
    pub fn list_recent(&self, limit: usize) -> Vec<Summary> {
        self.entries
            .iter()
            .take(limit)
            .map(Entry::summary)
            .collect()
    }

    /// Fetches one entry's full content.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if no entry has that id.
    pub fn get(&self, id: &Id) -> Result<Content> {
        self.entries
            .iter()
            .find(|e| &e.id == id)
            .map(|e| e.content.clone())
            .ok_or(Error::NotFound)
    }

    /// Removes one entry.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if no entry has that id, or [`Error::Io`] if the rewrite
    /// failed.
    pub fn remove(&mut self, id: &Id) -> Result<()> {
        let position = self
            .entries
            .iter()
            .position(|e| &e.id == id)
            .ok_or(Error::NotFound)?;
        self.entries.remove(position);
        self.persist()
    }

    /// Deletes everything, overwriting the file before unlinking it.
    ///
    /// `remove_file` unlinks but leaves the blocks holding plaintext until they are reused, which
    /// is how deleted secrets get recovered. This overwrites first. It is not a guarantee on a
    /// copy on write or log structured filesystem, or against a drive that remaps blocks, and the
    /// documentation says so rather than implying more.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Io`] if the file could not be overwritten or removed.
    pub fn clear(&mut self) -> Result<()> {
        self.entries.clear();
        if self.path.exists() {
            shred(&self.path)?;
        }
        Ok(())
    }

    /// Drops entries until every cap is satisfied, oldest first.
    fn evict(&mut self) {
        while self.entries.len() > self.limits.max_entries {
            self.entries.pop();
        }

        // Two budgets, walked separately, so a screenshot cannot evict the text history.
        self.evict_by_budget(false, self.limits.max_text_bytes);
        self.evict_by_budget(true, self.limits.max_image_bytes);
    }

    fn evict_by_budget(&mut self, images: bool, budget: usize) {
        let total = |entries: &[Entry]| -> usize {
            entries
                .iter()
                .filter(|e| e.content.is_image() == images)
                .map(|e| e.content.len())
                .sum()
        };

        while total(&self.entries) > budget {
            let Some(position) = self
                .entries
                .iter()
                .rposition(|e| e.content.is_image() == images)
            else {
                return;
            };
            self.entries.remove(position);
        }
    }

    /// Writes the whole store through a temporary file and a rename.
    fn persist(&self) -> Result<()> {
        let mut buf = Vec::with_capacity(HEADER_LEN + self.entries.len() * 128);
        buf.extend_from_slice(MAGIC);
        buf.push(FORMAT_VERSION);

        for entry in &self.entries {
            let inner = clip::Inner {
                content_type: entry.content.content_type(),
                // The clip framing carries a device id and a sequence number for replay defence
                // on the wire. Neither means anything for a local file, so they are fixed.
                device_id: [0u8; clip::DEVICE_ID_LEN],
                seq: 0,
                ts_ms: entry.ts_ms,
                content: entry.content.as_bytes().to_vec(),
            };

            // The entry id goes in the msg_id slot, which puts it in the associated data. A
            // record therefore cannot be relabelled or moved between files and still open.
            let sealed = clip::seal(&self.key, 0, &ROOM, &entry.id, &inner)?;

            let len = u32::try_from(ID_LEN + clip::NONCE_LEN + sealed.ciphertext.len())
                .map_err(|_| Error::Malformed)?;
            buf.extend_from_slice(&len.to_be_bytes());
            buf.extend_from_slice(&entry.id);
            buf.extend_from_slice(&sealed.nonce);
            buf.extend_from_slice(&sealed.ciphertext);
        }

        write_atomic(&self.path, &buf)
    }
}

/// A fixed room id for the associated data.
///
/// The wire format binds the real room id so a clip cannot be replayed into another account. A
/// local file has no room, and the key already differs per account, so a constant is honest here
/// rather than pretending to a binding that does nothing.
const ROOM: [u8; 16] = *b"asli/history/v1\0";

fn decode_all(raw: &[u8], key: &[u8; key::KEY_LEN]) -> Result<Vec<Entry>> {
    if raw.is_empty() {
        return Ok(Vec::new());
    }
    if raw.len() < HEADER_LEN || &raw[..MAGIC.len()] != MAGIC {
        return Err(Error::Malformed);
    }
    let version = raw[MAGIC.len()];
    if version != FORMAT_VERSION {
        return Err(Error::UnsupportedVersion(version));
    }

    let mut entries = Vec::new();
    let mut at = HEADER_LEN;

    while at < raw.len() {
        // A truncated tail is what an interrupted write looks like. Everything before it is
        // still good, so keep it rather than discarding the file.
        let Some(len_bytes) = raw.get(at..at + 4) else {
            break;
        };
        let len = u32::from_be_bytes(len_bytes.try_into().map_err(|_| Error::Malformed)?) as usize;
        at += 4;

        // A length outside this range is a corrupt or hostile prefix rather than merely an
        // unexpected one, so it fails the whole read instead of being skipped over.
        if !(MIN_RECORD_BYTES..=MAX_RECORD_BYTES).contains(&len) {
            return Err(Error::Malformed);
        }
        let Some(record) = raw.get(at..at + len) else {
            break;
        };
        at += len;

        let id: Id = record[..ID_LEN].try_into().map_err(|_| Error::Malformed)?;
        let nonce: [u8; clip::NONCE_LEN] = record[ID_LEN..ID_LEN + clip::NONCE_LEN]
            .try_into()
            .map_err(|_| Error::Malformed)?;
        let ciphertext = &record[ID_LEN + clip::NONCE_LEN..];

        let inner = clip::open(key, 0, &ROOM, &id, &nonce, ciphertext)?;
        let content = Content::from_parts(inner.content_type, inner.content)?;
        entries.push(Entry {
            id,
            ts_ms: inner.ts_ms,
            content,
        });
    }

    Ok(entries)
}

/// Writes through a temporary file and renames it into place.
///
/// A rename within a directory is atomic, so an interrupted write leaves either the old file or
/// the new one, never a half written mixture.
fn write_atomic(path: &Path, bytes: &[u8]) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }

    let mut temp = path.to_path_buf();
    let mut name = path
        .file_name()
        .map(std::ffi::OsString::from)
        .unwrap_or_default();
    name.push(".tmp");
    temp.set_file_name(name);

    {
        let mut file = create_private(&temp)?;
        file.write_all(bytes)?;
        file.sync_all()?;
    }

    fs::rename(&temp, path)?;
    Ok(())
}

/// Creates a file readable only by its owner.
fn create_private(path: &Path) -> Result<File> {
    let mut options = OpenOptions::new();
    options.write(true).create(true).truncate(true);

    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }

    options.open(path).map_err(Error::Io)
}

/// Overwrites a file's contents before unlinking it.
fn shred(path: &Path) -> Result<()> {
    let len = fs::metadata(path)?.len();

    if len > 0 {
        let mut file = OpenOptions::new().write(true).open(path)?;
        let zeros = vec![0u8; 64 * 1024];
        let mut written = 0u64;
        while written < len {
            let chunk = usize::try_from(len - written)
                .unwrap_or(zeros.len())
                .min(zeros.len());
            file.write_all(&zeros[..chunk])?;
            written += chunk as u64;
        }
        file.seek(SeekFrom::Start(0))?;
        file.sync_all()?;
    }

    fs::remove_file(path)?;
    Ok(())
}

/// Wall clock in milliseconds, for callers that do not carry their own.
#[must_use]
pub fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
}

/// Reads a file's raw bytes, so a test can inspect what actually landed on disk.
///
/// Deliberately not public. This crate exists to keep clipboard content encrypted at rest, and a
/// public helper that hands back the raw file would be an odd thing for it to offer. Every caller
/// is a test in this module.
///
/// # Errors
///
/// Returns [`Error::Io`] if the file cannot be read.
#[cfg(test)]
fn raw_bytes(path: &Path) -> Result<Vec<u8>> {
    let mut buf = Vec::new();
    File::open(path)?.read_to_end(&mut buf)?;
    Ok(buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECRET: [u8; 32] = [7u8; 32];
    const NOW: u64 = 1_767_225_600_000;

    struct Temp(PathBuf);

    impl Temp {
        fn new(name: &str) -> Self {
            let mut path = std::env::temp_dir();
            let unique = format!("asli-history-{}-{}-{}", std::process::id(), name, now_ms());
            path.push(unique);
            path.push("history.bin");
            Self(path)
        }

        fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for Temp {
        fn drop(&mut self) {
            if let Some(dir) = self.0.parent() {
                let _ = fs::remove_dir_all(dir);
            }
        }
    }

    fn store(temp: &Temp) -> Store {
        Store::open(temp.path(), &SECRET, Limits::default()).expect("opens")
    }

    fn text(s: &str) -> Content {
        Content::Text(s.to_owned())
    }

    #[test]
    fn round_trips_through_encryption() {
        let temp = Temp::new("roundtrip");
        let mut store = store(&temp);
        let Appended::Stored(id) = store.append(text("hello"), false, NOW).expect("appends") else {
            panic!("expected a new entry");
        };

        let reopened = Store::open(temp.path(), &SECRET, Limits::default()).expect("reopens");
        assert_eq!(reopened.len(), 1);
        assert_eq!(reopened.get(&id).expect("gets"), text("hello"));
    }

    #[test]
    fn images_round_trip_too() {
        let temp = Temp::new("image");
        let mut store = store(&temp);
        let png = Content::ImagePng(vec![0x89, b'P', b'N', b'G', 1, 2, 3]);
        let Appended::Stored(id) = store.append(png.clone(), false, NOW).expect("appends") else {
            panic!("expected a new entry");
        };

        let reopened = Store::open(temp.path(), &SECRET, Limits::default()).expect("reopens");
        assert_eq!(reopened.get(&id).expect("gets"), png);
        assert_eq!(reopened.list()[0].kind, Kind::ImagePng);
        assert!(reopened.list()[0].preview.is_empty());
    }

    #[test]
    fn another_account_cannot_read_it() {
        let temp = Temp::new("wrongkey");
        let mut store = store(&temp);
        store.append(text("private"), false, NOW).expect("appends");

        let mut other = SECRET;
        other[0] ^= 0xff;
        let err = Store::open(temp.path(), &other, Limits::default()).expect_err("must not open");
        assert!(matches!(err, Error::Crypto(_)), "got {err:?}");
    }

    #[test]
    fn sensitive_content_is_never_recorded() {
        let temp = Temp::new("sensitive");
        let mut store = store(&temp);

        let outcome = store
            .append(text("hunter2 from a password manager"), true, NOW)
            .expect("returns");
        assert_eq!(outcome, Appended::RefusedSensitive);
        assert!(store.is_empty());

        // Nothing was written at all, so there is not even a file to inspect.
        assert!(!temp.path().exists(), "a refused entry created a file");
    }

    #[test]
    fn empty_and_oversized_entries_are_refused() {
        let temp = Temp::new("refusals");
        let mut store = store(&temp);

        assert_eq!(
            store.append(text(""), false, NOW).expect("returns"),
            Appended::RefusedEmpty
        );

        let limits = Limits {
            max_entry_bytes: 16,
            ..Limits::default()
        };
        let temp2 = Temp::new("refusals2");
        let mut small = Store::open(temp2.path(), &SECRET, limits).expect("opens");
        let outcome = small
            .append(
                text("this is definitely longer than sixteen bytes"),
                false,
                NOW,
            )
            .expect("returns");
        assert!(matches!(
            outcome,
            Appended::RefusedTooLarge { limit: 16, .. }
        ));
        assert!(small.is_empty());
    }

    #[test]
    fn the_entry_cap_evicts_oldest_first() {
        let temp = Temp::new("entrycap");
        let limits = Limits {
            max_entries: 3,
            ..Limits::default()
        };
        let mut store = Store::open(temp.path(), &SECRET, limits).expect("opens");

        for i in 0..5 {
            store
                .append(text(&format!("entry {i}")), false, NOW + i)
                .expect("appends");
        }

        let listed = store.list();
        assert_eq!(listed.len(), 3);
        assert_eq!(listed[0].preview, "entry 4");
        assert_eq!(listed[2].preview, "entry 2");
    }

    #[test]
    fn a_big_image_does_not_evict_the_text_history() {
        // The reason images have their own budget. Under one shared budget this test would end
        // with the text entries gone, which is exactly the wrong outcome.
        let temp = Temp::new("budgets");
        let limits = Limits {
            max_entries: 100,
            max_text_bytes: 1024,
            max_image_bytes: 4096,
            max_entry_bytes: 8192,
        };
        let mut store = Store::open(temp.path(), &SECRET, limits).expect("opens");

        for i in 0..5 {
            store
                .append(text(&format!("text entry {i}")), false, NOW + i)
                .expect("appends");
        }
        store
            .append(Content::ImagePng(vec![0u8; 3000]), false, NOW + 10)
            .expect("appends");

        let texts = store
            .list()
            .into_iter()
            .filter(|s| s.kind == Kind::Text)
            .count();
        assert_eq!(texts, 5, "the image evicted text entries");
    }

    #[test]
    fn the_image_budget_evicts_images_only() {
        let temp = Temp::new("imagebudget");
        let limits = Limits {
            max_entries: 100,
            max_text_bytes: 1024,
            max_image_bytes: 2048,
            max_entry_bytes: 8192,
        };
        let mut store = Store::open(temp.path(), &SECRET, limits).expect("opens");

        store.append(text("keep me"), false, NOW).expect("appends");
        for i in 0..3 {
            store
                .append(Content::ImagePng(vec![i; 1000]), false, NOW + u64::from(i))
                .expect("appends");
        }

        let listed = store.list();
        let images = listed.iter().filter(|s| s.kind == Kind::ImagePng).count();
        let texts = listed.iter().filter(|s| s.kind == Kind::Text).count();
        assert_eq!(texts, 1, "text was evicted by the image budget");
        assert!(images <= 2, "image budget not enforced, got {images}");
    }

    #[test]
    fn copying_the_same_text_again_moves_it_to_the_top() {
        let temp = Temp::new("dedup");
        let mut store = store(&temp);

        store.append(text("first"), false, NOW).expect("appends");
        store
            .append(text("second"), false, NOW + 1)
            .expect("appends");
        store
            .append(text("third"), false, NOW + 2)
            .expect("appends");

        let outcome = store
            .append(text("first"), false, NOW + 3)
            .expect("appends");
        assert!(matches!(outcome, Appended::MovedToTop(_)));

        let listed = store.list();
        assert_eq!(listed.len(), 3, "dedup created a duplicate");
        assert_eq!(listed[0].preview, "first");
        assert_eq!(listed[0].ts_ms, NOW + 3, "timestamp was not refreshed");
    }

    #[test]
    fn recopying_the_newest_changes_nothing() {
        let temp = Temp::new("dedup-top");
        let mut store = store(&temp);
        store.append(text("only"), false, NOW).expect("appends");

        let outcome = store.append(text("only"), false, NOW + 5).expect("appends");
        assert!(matches!(outcome, Appended::AlreadyNewest(_)));
        assert!(!outcome.changed());
        assert_eq!(store.len(), 1);
    }

    #[test]
    fn purge_leaves_no_plaintext_and_no_file() {
        let temp = Temp::new("purge");
        let mut store = store(&temp);
        store
            .append(text("a very distinctive secret string"), false, NOW)
            .expect("appends");
        assert!(temp.path().exists());

        store.clear().expect("clears");
        assert!(store.is_empty());
        assert!(!temp.path().exists(), "the file survived a purge");

        // Reopening gives an empty store rather than an error.
        let reopened = Store::open(temp.path(), &SECRET, Limits::default()).expect("reopens");
        assert!(reopened.is_empty());
    }

    #[test]
    fn the_file_never_holds_plaintext() {
        let temp = Temp::new("ciphertext");
        let mut store = store(&temp);
        store
            .append(text("plaintext-canary-value"), false, NOW)
            .expect("appends");

        let raw = raw_bytes(temp.path()).expect("reads");
        let needle = b"plaintext-canary-value";
        assert!(
            !raw.windows(needle.len()).any(|w| w == needle),
            "the canary was found in the file"
        );
    }

    #[test]
    fn removing_one_entry_keeps_the_rest() {
        let temp = Temp::new("remove");
        let mut store = store(&temp);
        let Appended::Stored(first) = store.append(text("one"), false, NOW).expect("appends")
        else {
            panic!("expected a new entry");
        };
        store.append(text("two"), false, NOW + 1).expect("appends");

        store.remove(&first).expect("removes");
        assert_eq!(store.len(), 1);
        assert!(matches!(store.get(&first), Err(Error::NotFound)));

        let reopened = Store::open(temp.path(), &SECRET, Limits::default()).expect("reopens");
        assert_eq!(reopened.len(), 1);
        assert_eq!(reopened.list()[0].preview, "two");
    }

    #[test]
    fn removing_an_unknown_id_is_not_found() {
        let temp = Temp::new("remove-missing");
        let mut store = store(&temp);
        assert!(matches!(store.remove(&[9u8; ID_LEN]), Err(Error::NotFound)));
    }

    #[test]
    fn a_corrupt_file_fails_safely() {
        let temp = Temp::new("corrupt");
        let mut store = store(&temp);
        store
            .append(text("something"), false, NOW)
            .expect("appends");

        // Flip a byte inside the first record's ciphertext.
        let mut raw = raw_bytes(temp.path()).expect("reads");
        let offset = HEADER_LEN + 4 + ID_LEN + clip::NONCE_LEN;
        raw[offset] ^= 0xff;
        fs::write(temp.path(), &raw).expect("writes");

        let err = Store::open(temp.path(), &SECRET, Limits::default()).expect_err("must fail");
        assert!(matches!(err, Error::Crypto(_)), "got {err:?}");
    }

    #[test]
    fn a_foreign_file_is_rejected_by_its_magic() {
        let temp = Temp::new("foreign");
        fs::create_dir_all(temp.path().parent().unwrap()).expect("mkdir");
        fs::write(temp.path(), b"this is not a history file at all").expect("writes");

        let err = Store::open(temp.path(), &SECRET, Limits::default()).expect_err("must fail");
        assert!(matches!(err, Error::Malformed), "got {err:?}");
    }

    #[test]
    fn a_newer_format_version_is_named_not_guessed() {
        let temp = Temp::new("version");
        fs::create_dir_all(temp.path().parent().unwrap()).expect("mkdir");
        let mut raw = MAGIC.to_vec();
        raw.push(FORMAT_VERSION + 1);
        fs::write(temp.path(), &raw).expect("writes");

        let err = Store::open(temp.path(), &SECRET, Limits::default()).expect_err("must fail");
        assert!(matches!(err, Error::UnsupportedVersion(_)), "got {err:?}");
    }

    #[test]
    fn an_interrupted_write_keeps_the_records_that_landed() {
        let temp = Temp::new("crash");
        let mut store = store(&temp);
        store.append(text("first"), false, NOW).expect("appends");
        store
            .append(text("second"), false, NOW + 1)
            .expect("appends");

        // Chop the tail, which is what a write cut short by a crash looks like.
        let raw = raw_bytes(temp.path()).expect("reads");
        fs::write(temp.path(), &raw[..raw.len() - 20]).expect("writes");

        let reopened = Store::open(temp.path(), &SECRET, Limits::default()).expect("reopens");
        assert_eq!(reopened.len(), 1, "the intact record was lost");
        assert_eq!(reopened.list()[0].preview, "second");
    }

    #[test]
    fn open_or_reset_discards_a_file_it_cannot_read() {
        let temp = Temp::new("reset");
        let mut store = store(&temp);
        store
            .append(text("old account"), false, NOW)
            .expect("appends");

        let mut other = SECRET;
        other[5] ^= 0xff;
        let (fresh, discarded) =
            Store::open_or_reset(temp.path(), &other, Limits::default()).expect("opens");
        assert!(fresh.is_empty());
        assert!(discarded.is_some(), "the caller was not told");
    }

    #[test]
    fn nonsense_limits_are_rejected() {
        let temp = Temp::new("limits");
        let limits = Limits {
            max_entries: 0,
            ..Limits::default()
        };
        assert!(matches!(
            Store::open(temp.path(), &SECRET, limits),
            Err(Error::BadConfig(_))
        ));
    }

    #[test]
    fn previews_are_bounded_and_do_not_split_characters() {
        let temp = Temp::new("preview");
        let mut store = store(&temp);
        let long = "ასლი ".repeat(200);
        store.append(text(&long), false, NOW).expect("appends");

        let summary = &store.list()[0];
        assert_eq!(summary.preview.chars().count(), PREVIEW_CHARS);
        assert_eq!(summary.bytes, long.len());
    }

    #[test]
    fn list_recent_caps_what_it_returns() {
        let temp = Temp::new("recent");
        let mut store = store(&temp);
        for i in 0..10 {
            store
                .append(text(&format!("entry {i}")), false, NOW + i)
                .expect("appends");
        }
        assert_eq!(store.list_recent(3).len(), 3);
        assert_eq!(store.list_recent(100).len(), 10);
    }

    #[test]
    fn the_file_is_owner_only() {
        let temp = Temp::new("mode");
        let mut store = store(&temp);
        store.append(text("private"), false, NOW).expect("appends");

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let mode = fs::metadata(temp.path())
                .expect("stats")
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o600, "mode was {:o}", mode & 0o777);
        }
    }

    #[test]
    fn no_temporary_file_is_left_behind() {
        let temp = Temp::new("notemp");
        let mut store = store(&temp);
        store.append(text("written"), false, NOW).expect("appends");

        let dir = temp.path().parent().expect("has a parent");
        let strays: Vec<_> = fs::read_dir(dir)
            .expect("reads dir")
            .filter_map(std::result::Result::ok)
            .filter(|e| e.file_name().to_string_lossy().ends_with(".tmp"))
            .collect();
        assert!(strays.is_empty(), "a .tmp file survived");
    }
}
