//! Loop prevention, layer two: a hash ring buffer with a time to live.
//!
//! When we write a received clip to the local clipboard, the operating system tells us the
//! clipboard changed, and without this guard we would send it straight back out. Device A sends
//! to B, B writes and resends, A writes and resends, and the traffic never stops.
//!
//! Two details carry all the weight:
//!
//! 1. **Record the hash before writing, never after.** The change notification can arrive before
//!    the write call returns. KDE Connect gets this right (it seeds its comparison value before
//!    calling `setMimeData`) and it is the difference between working and a race.
//! 2. **Entries expire.** Without a time to live, copying the same text again on purpose a minute
//!    later is silently swallowed forever. Several clipboard sync tools have shipped exactly that
//!    bug, KDE Connect included, because their guard is a single remembered value with no expiry.
//!
//! This is layer two of three. Layer one is the device id inside the ciphertext, and layer three
//! is the platform sequence number captured at write time.

use std::collections::VecDeque;

use sha2::{Digest, Sha256};

/// Hash of a normalized clipboard payload.
pub type ContentHash = [u8; 32];

/// Hashes an already normalized payload.
///
/// Callers must pass the normalized bytes. Hashing raw platform bytes is the bug this module
/// exists to prevent.
#[must_use]
pub fn hash(normalized: &[u8]) -> ContentHash {
    let mut hasher = Sha256::new();
    hasher.update(normalized);
    hasher.finalize().into()
}

/// Default number of hashes remembered.
pub const DEFAULT_CAPACITY: usize = 20;
/// Default time to live for an entry, in milliseconds.
pub const DEFAULT_TTL_MS: u64 = 15_000;

/// A small ring buffer of recently written or sent content hashes.
///
/// The caller supplies the current time in milliseconds, so behaviour is deterministic and
/// testable, and so the same guard works against a monotonic clock or a wall clock.
#[derive(Debug, Clone)]
pub struct EchoGuard {
    entries: VecDeque<(ContentHash, u64)>,
    capacity: usize,
    ttl_ms: u64,
}

impl Default for EchoGuard {
    fn default() -> Self {
        Self::new(DEFAULT_CAPACITY, DEFAULT_TTL_MS)
    }
}

impl EchoGuard {
    /// Creates a guard that remembers `capacity` hashes for `ttl_ms` milliseconds each.
    ///
    /// # Panics
    ///
    /// Panics if `capacity` is zero, which would disable loop prevention entirely.
    #[must_use]
    pub fn new(capacity: usize, ttl_ms: u64) -> Self {
        assert!(
            capacity > 0,
            "an echo guard with no capacity prevents nothing"
        );
        Self {
            entries: VecDeque::with_capacity(capacity),
            capacity,
            ttl_ms,
        }
    }

    /// Records a hash we are about to put on the clipboard, or are about to send.
    ///
    /// Call this **before** touching the clipboard.
    pub fn remember(&mut self, hash: ContentHash, now_ms: u64) {
        self.expire(now_ms);
        // Refresh an existing entry rather than storing it twice.
        self.entries.retain(|(h, _)| *h != hash);
        if self.entries.len() == self.capacity {
            self.entries.pop_front();
        }
        self.entries.push_back((hash, now_ms));
    }

    /// Whether a locally observed change is an echo of something we just wrote or sent.
    ///
    /// This consumes the match: an echo is expected exactly once, and a second identical change
    /// is a real user action (copying the same text twice in a row) which must still sync.
    pub fn take_echo(&mut self, hash: ContentHash, now_ms: u64) -> bool {
        self.expire(now_ms);
        if let Some(pos) = self.entries.iter().position(|(h, _)| *h == hash) {
            self.entries.remove(pos);
            true
        } else {
            false
        }
    }

    /// Whether a hash is currently remembered, without consuming it.
    #[must_use]
    pub fn contains(&self, hash: ContentHash, now_ms: u64) -> bool {
        self.entries
            .iter()
            .any(|(h, at)| *h == hash && !self.is_expired(*at, now_ms))
    }

    /// Number of live entries.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the guard is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Forgets everything. Used when sync is paused or the account is reset.
    pub fn clear(&mut self) {
        self.entries.clear();
    }

    const fn is_expired(&self, at_ms: u64, now_ms: u64) -> bool {
        now_ms.saturating_sub(at_ms) > self.ttl_ms
    }

    fn expire(&mut self, now_ms: u64) {
        while let Some((_, at)) = self.entries.front() {
            if self.is_expired(*at, now_ms) {
                self.entries.pop_front();
            } else {
                break;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn h(text: &str) -> ContentHash {
        hash(text.as_bytes())
    }

    #[test]
    fn suppresses_the_echo_of_our_own_write() {
        let mut guard = EchoGuard::default();
        guard.remember(h("received text"), 1_000);
        assert!(guard.take_echo(h("received text"), 1_010));
    }

    #[test]
    fn does_not_suppress_unrelated_content() {
        let mut guard = EchoGuard::default();
        guard.remember(h("received text"), 1_000);
        assert!(!guard.take_echo(h("something the user copied"), 1_010));
    }

    #[test]
    fn the_same_text_copied_again_on_purpose_still_syncs() {
        // This is the bug that a single remembered value with no expiry ships with.
        let mut guard = EchoGuard::default();
        guard.remember(h("hello"), 1_000);
        // The echo of our own write is swallowed once.
        assert!(guard.take_echo(h("hello"), 1_050));
        // The user copies the same text again a moment later. It must go out.
        assert!(!guard.take_echo(h("hello"), 2_000));
    }

    #[test]
    fn entries_expire() {
        let mut guard = EchoGuard::new(20, 15_000);
        guard.remember(h("hello"), 1_000);
        assert!(!guard.take_echo(h("hello"), 1_000 + 15_001));
    }

    #[test]
    fn entries_survive_until_the_ttl() {
        let mut guard = EchoGuard::new(20, 15_000);
        guard.remember(h("hello"), 1_000);
        assert!(guard.take_echo(h("hello"), 1_000 + 15_000));
    }

    #[test]
    fn evicts_the_oldest_when_full() {
        let mut guard = EchoGuard::new(3, 60_000);
        guard.remember(h("one"), 1);
        guard.remember(h("two"), 2);
        guard.remember(h("three"), 3);
        guard.remember(h("four"), 4);
        assert_eq!(guard.len(), 3);
        assert!(
            !guard.contains(h("one"), 5),
            "oldest should have been evicted"
        );
        assert!(guard.contains(h("four"), 5));
    }

    #[test]
    fn remembering_twice_refreshes_rather_than_duplicating() {
        let mut guard = EchoGuard::new(3, 10_000);
        guard.remember(h("same"), 1_000);
        guard.remember(h("same"), 5_000);
        assert_eq!(guard.len(), 1);
        // The refreshed timestamp is what counts for expiry.
        assert!(guard.contains(h("same"), 14_000));
        assert!(!guard.contains(h("same"), 16_000));
    }

    #[test]
    fn a_ping_pong_between_two_devices_terminates() {
        // Device A sends, device B writes and would resend, device A writes and would resend.
        let mut device_a = EchoGuard::default();
        let mut device_b = EchoGuard::default();

        // A sends its own copy, so A remembers it.
        device_a.remember(h("shared"), 1_000);

        // B receives and writes, remembering before the write.
        device_b.remember(h("shared"), 1_020);
        // B's watcher fires. Suppressed, so nothing goes back out.
        assert!(device_b.take_echo(h("shared"), 1_030));

        // Nothing returns to A, but even if a relay echoed it back, A would suppress it too.
        assert!(device_a.take_echo(h("shared"), 1_040));
    }

    #[test]
    fn clearing_forgets_everything() {
        let mut guard = EchoGuard::default();
        guard.remember(h("x"), 1);
        guard.clear();
        assert!(guard.is_empty());
        assert!(!guard.take_echo(h("x"), 2));
    }

    #[test]
    fn hashing_is_stable_and_distinguishes_content() {
        assert_eq!(hash(b"abc"), hash(b"abc"));
        assert_ne!(hash(b"abc"), hash(b"abd"));
        // Known SHA-256 of "abc", so a hash function swap is caught here.
        assert_eq!(
            hash(b"abc")[..4],
            [0xba, 0x78, 0x16, 0xbf],
            "content hash is SHA-256"
        );
    }
}
