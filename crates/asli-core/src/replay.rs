//! Loop prevention layer one, and the defence against a malicious or buggy relay.
//!
//! The relay is untrusted. It cannot read or forge a clip, but nothing stops it from re-sending
//! an old one, holding one back and delivering it later, or replaying a specific device's
//! messages. These checks run on every decrypted clip, in order, and all of them use fields that
//! live **inside** the ciphertext, so the relay cannot influence them.
//!
//! What this catches: our own messages coming back, duplicates, stale clips presented as fresh,
//! and per device rollback. What it does not catch, because a single untrusted relay makes it
//! impossible: messages that are simply dropped, or delayed within the freshness window. Those
//! are accepted limitations and are documented in the threat model rather than papered over.

use std::collections::{HashMap, VecDeque};

/// Length of a device id in bytes.
pub const DEVICE_ID_LEN: usize = 16;
/// Length of a message id in bytes.
pub const MSG_ID_LEN: usize = 16;

/// How many recent message ids are remembered.
pub const DEFAULT_MSG_ID_CAPACITY: usize = 256;
/// How old a live message may be before it is rejected, in milliseconds.
///
/// A day, as a sanity bound rather than the defence. The defence against replay is the message id
/// and the per device sequence number, and those survive restarts through [`Memory`]. A window of
/// two minutes used to carry that weight instead, which made sync depend on every device's clock
/// being right: a machine showing the correct local time in the wrong time zone is hours off, and
/// every clip to and from it was dropped with nothing failing anywhere.
pub const DEFAULT_MAX_AGE_MS: u64 = 24 * 60 * 60 * 1000;
/// How far into the future a sender's clock may run before we reject it, in milliseconds.
///
/// A day, for the same reason as [`DEFAULT_MAX_AGE_MS`]: wide enough for any time zone mistake.
pub const DEFAULT_FUTURE_SKEW_MS: u64 = 24 * 60 * 60 * 1000;

/// How far a device's sequence number may jump in one step before the clip is refused.
///
/// Without a bound this is a permanent denial of sync. `seq` is chosen by the sender and the high
/// water mark is persisted and never lowered, so one clip claiming a peer's device id with
/// `seq = u64::MAX` would park that peer's mark at the ceiling and every genuine clip from it
/// afterwards would read as a rollback, on every device, across restarts, until the replay store
/// was edited by hand. Only a room member can do it, and a room member can already read the
/// clipboard, so this is denial of service rather than disclosure. It is still worth closing.
///
/// The value is deliberately generous. A device reserves [`SEQ_RESERVATION`] numbers per start,
/// so a peer that restarted a thousand times while this device was away has legitimately advanced
/// by a million. A jump past that is not a peer that has been busy, it is a forged number.
///
/// [`SEQ_RESERVATION`]: https://docs.rs/asli-app
pub const MAX_SEQ_JUMP: u64 = 1_000_000;

/// How many devices a guard tracks a sequence number for.
///
/// `highest_seq` is keyed by an attacker chosen device id, which made it the one unbounded
/// collection in the tree: a room member could mint ids until the store filled the disk. A real
/// account has a handful of devices, so the cap is far above any honest use and the oldest entry
/// is dropped once it is reached.
pub const DEFAULT_DEVICE_CAPACITY: usize = 64;

/// The decision for one incoming clip.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// Apply it to the clipboard.
    Accept,
    /// It came from this device. The relay excludes the sender, but a malicious one might not.
    OwnDevice,
    /// This message id was already seen. Replay, or a duplicate delivery.
    Duplicate,
    /// The sequence number went backwards for that device, which is a rollback attempt.
    Rollback,
    /// Older than the freshness window allows.
    TooOld,
    /// The sender's clock is implausibly far ahead.
    FromTheFuture,
    /// The sequence number jumped further than [`MAX_SEQ_JUMP`] in one step. Refused without
    /// recording, so a forged number cannot park the high water mark out of reach.
    SeqJump,
}

impl Verdict {
    /// Whether the clip should be applied.
    #[must_use]
    pub const fn is_accept(self) -> bool {
        matches!(self, Self::Accept)
    }

    /// A short, stable reason string for structured logs. Never contains clipboard content.
    #[must_use]
    pub const fn reason(self) -> &'static str {
        match self {
            Self::Accept => "accept",
            Self::OwnDevice => "own_device",
            Self::Duplicate => "duplicate",
            Self::Rollback => "rollback",
            Self::TooOld => "too_old",
            Self::FromTheFuture => "future_skew",
            Self::SeqJump => "seq_jump",
        }
    }
}

/// One incoming clip, as far as these checks are concerned.
#[derive(Debug, Clone, Copy)]
pub struct Incoming {
    /// Public message id from the envelope, bound in the associated data.
    pub msg_id: [u8; MSG_ID_LEN],
    /// Sending device, from inside the ciphertext.
    pub device_id: [u8; DEVICE_ID_LEN],
    /// Per device counter, from inside the ciphertext.
    pub seq: u64,
    /// Sender wall clock in milliseconds, from inside the ciphertext.
    pub ts_ms: u64,
    /// Whether the relay delivered this as a stored clip rather than a live one.
    pub retained: bool,
}

/// What a guard has learned that must survive a restart.
///
/// The sequence numbers and message ids are what actually stop a relay replaying old clips. Kept
/// only in memory, they were forgotten on every restart, and a device that had just started
/// could be sent a clip from last week and would apply it. Saved and restored, they protect a
/// device from its first second, with no dependence on anyone's clock.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Memory {
    /// The highest sequence number accepted from each device.
    pub highest_seq: Vec<([u8; DEVICE_ID_LEN], u64)>,
    /// The most recent message ids accepted, oldest first.
    pub recent: Vec<[u8; MSG_ID_LEN]>,
}

/// Tracks what this device has already seen.
#[derive(Debug, Clone)]
pub struct ReplayGuard {
    own_device_id: [u8; DEVICE_ID_LEN],
    seen: VecDeque<[u8; MSG_ID_LEN]>,
    capacity: usize,
    highest_seq: HashMap<[u8; DEVICE_ID_LEN], u64>,
    /// Device ids in the order they were first seen, so the map above can be bounded.
    device_order: VecDeque<[u8; DEVICE_ID_LEN]>,
    device_capacity: usize,
    max_age_ms: u64,
    retained_max_age_ms: u64,
    future_skew_ms: u64,
}

impl ReplayGuard {
    /// Creates a guard for this device with the default windows.
    ///
    /// `retained_max_age_ms` should match the relay's retention period, since a stored clip is
    /// legitimately older than the live window allows.
    #[must_use]
    pub fn new(own_device_id: [u8; DEVICE_ID_LEN], retained_max_age_ms: u64) -> Self {
        Self {
            own_device_id,
            seen: VecDeque::with_capacity(DEFAULT_MSG_ID_CAPACITY),
            capacity: DEFAULT_MSG_ID_CAPACITY,
            highest_seq: HashMap::new(),
            device_order: VecDeque::new(),
            device_capacity: DEFAULT_DEVICE_CAPACITY,
            max_age_ms: DEFAULT_MAX_AGE_MS,
            retained_max_age_ms,
            future_skew_ms: DEFAULT_FUTURE_SKEW_MS,
        }
    }

    /// Checks one clip and records it if it is accepted.
    ///
    /// The order matters. Own device first, because it is free and unconditional. Duplicates
    /// next, because a replayed message must not advance any state. Then freshness, then
    /// rollback. Nothing is recorded unless the verdict is [`Verdict::Accept`], so a rejected
    /// message cannot poison the state a later legitimate one depends on.
    pub fn check(&mut self, incoming: &Incoming, now_ms: u64) -> Verdict {
        if incoming.device_id == self.own_device_id {
            return Verdict::OwnDevice;
        }

        if self.seen.contains(&incoming.msg_id) {
            return Verdict::Duplicate;
        }

        if incoming.ts_ms > now_ms.saturating_add(self.future_skew_ms) {
            return Verdict::FromTheFuture;
        }

        let max_age = if incoming.retained {
            self.retained_max_age_ms
        } else {
            self.max_age_ms
        };
        if now_ms.saturating_sub(incoming.ts_ms) > max_age {
            return Verdict::TooOld;
        }

        if let Some(highest) = self.highest_seq.get(&incoming.device_id).copied() {
            if incoming.seq <= highest {
                return Verdict::Rollback;
            }
            // The bound applies only once a device is known. A first clip from a device has no
            // mark to jump from, and refusing it against a baseline of zero would lock out an
            // honest peer that had genuinely advanced a long way before this device was added,
            // which is a worse failure than the one being prevented.
            if incoming.seq - highest > MAX_SEQ_JUMP {
                return Verdict::SeqJump;
            }
        }

        self.record(incoming);
        Verdict::Accept
    }

    fn record(&mut self, incoming: &Incoming) {
        if self.seen.len() == self.capacity {
            self.seen.pop_front();
        }
        self.seen.push_back(incoming.msg_id);

        if self
            .highest_seq
            .insert(incoming.device_id, incoming.seq)
            .is_none()
        {
            // A device not seen before. Remember the order so the map can be bounded, and drop
            // the oldest entry once it is full rather than letting minted device ids grow it
            // without limit.
            self.device_order.push_back(incoming.device_id);
            while self.device_order.len() > self.device_capacity {
                if let Some(evicted) = self.device_order.pop_front() {
                    self.highest_seq.remove(&evicted);
                }
            }
        }
    }

    /// Device ids this guard has accepted a clip from. The client derives its "connected devices"
    /// count from this, because the relay only ever sees connections and cannot identify devices.
    #[must_use]
    pub fn known_devices(&self) -> usize {
        self.highest_seq.len()
    }

    /// Everything this guard has learned, for saving.
    #[must_use]
    pub fn memory(&self) -> Memory {
        let mut highest_seq: Vec<_> = self.highest_seq.iter().map(|(d, s)| (*d, *s)).collect();
        highest_seq.sort_unstable();
        Memory {
            highest_seq,
            recent: self.seen.iter().copied().collect(),
        }
    }

    /// Takes back what an earlier run learned. Never lowers anything already known.
    pub fn restore(&mut self, memory: &Memory) {
        for (device, seq) in &memory.highest_seq {
            // A restored file is bounded the same way a live guard is. It is written by this
            // process, but it is still a file on disk, and a guard that trusted it without a cap
            // would reintroduce the unbounded map one restart later.
            if self.highest_seq.len() >= self.device_capacity
                && !self.highest_seq.contains_key(device)
            {
                continue;
            }
            match self.highest_seq.entry(*device) {
                std::collections::hash_map::Entry::Occupied(mut slot) => {
                    let highest = slot.get_mut();
                    *highest = (*highest).max(*seq);
                }
                std::collections::hash_map::Entry::Vacant(slot) => {
                    slot.insert(*seq);
                    self.device_order.push_back(*device);
                }
            }
        }
        for msg_id in &memory.recent {
            if !self.seen.contains(msg_id) {
                if self.seen.len() == self.capacity {
                    self.seen.pop_front();
                }
                self.seen.push_back(*msg_id);
            }
        }
    }

    /// Forgets everything except this device's identity. Used on account reset.
    pub fn clear(&mut self) {
        self.seen.clear();
        self.highest_seq.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const OURS: [u8; DEVICE_ID_LEN] = [1u8; DEVICE_ID_LEN];
    const THEIRS: [u8; DEVICE_ID_LEN] = [2u8; DEVICE_ID_LEN];
    const OTHER: [u8; DEVICE_ID_LEN] = [3u8; DEVICE_ID_LEN];
    const RETENTION_MS: u64 = 24 * 60 * 60 * 1000;
    const NOW: u64 = 1_767_225_600_000;

    fn guard() -> ReplayGuard {
        ReplayGuard::new(OURS, RETENTION_MS)
    }

    fn clip(msg_id: u8, device: [u8; DEVICE_ID_LEN], seq: u64, ts_ms: u64) -> Incoming {
        Incoming {
            msg_id: [msg_id; MSG_ID_LEN],
            device_id: device,
            seq,
            ts_ms,
            retained: false,
        }
    }

    #[test]
    fn accepts_a_fresh_clip_from_another_device() {
        let mut g = guard();
        assert_eq!(g.check(&clip(1, THEIRS, 1, NOW), NOW), Verdict::Accept);
    }

    #[test]
    fn drops_our_own_clip_even_if_the_relay_sends_it_back() {
        let mut g = guard();
        assert_eq!(g.check(&clip(1, OURS, 1, NOW), NOW), Verdict::OwnDevice);
    }

    #[test]
    fn drops_a_replayed_message_id() {
        let mut g = guard();
        assert_eq!(g.check(&clip(1, THEIRS, 1, NOW), NOW), Verdict::Accept);
        assert_eq!(g.check(&clip(1, THEIRS, 2, NOW), NOW), Verdict::Duplicate);
    }

    #[test]
    fn drops_a_rolled_back_sequence_number() {
        let mut g = guard();
        assert_eq!(g.check(&clip(1, THEIRS, 5, NOW), NOW), Verdict::Accept);
        // A relay replaying an older message from that device, with a fresh message id.
        assert_eq!(g.check(&clip(2, THEIRS, 4, NOW), NOW), Verdict::Rollback);
        assert_eq!(g.check(&clip(3, THEIRS, 5, NOW), NOW), Verdict::Rollback);
        assert_eq!(g.check(&clip(4, THEIRS, 6, NOW), NOW), Verdict::Accept);
    }

    #[test]
    fn refuses_an_implausible_sequence_jump_without_recording_it() {
        let mut g = guard();
        assert_eq!(g.check(&clip(1, THEIRS, 5, NOW), NOW), Verdict::Accept);

        // The attack: one clip claiming that device's id at the ceiling. Left unchecked it parks
        // the high water mark where no genuine clip can ever reach it, permanently and across
        // restarts.
        assert_eq!(g.check(&clip(2, THEIRS, u64::MAX, NOW), NOW), Verdict::SeqJump);

        // The mark must be untouched, so the device keeps syncing normally afterwards.
        assert_eq!(g.check(&clip(3, THEIRS, 6, NOW), NOW), Verdict::Accept);
    }

    #[test]
    fn a_first_clip_from_an_unknown_device_is_not_bounded() {
        let mut g = guard();
        // No mark to jump from. An honest peer that advanced a long way before this device was
        // added must not be locked out.
        assert_eq!(
            g.check(&clip(1, THEIRS, MAX_SEQ_JUMP * 4, NOW), NOW),
            Verdict::Accept
        );
    }

    #[test]
    fn the_device_map_is_bounded() {
        let mut g = guard();
        // Every clip carries a distinct, attacker chosen device id, which is what made this the
        // one collection in the tree that could grow without limit.
        for n in 0..u8::try_from(DEFAULT_DEVICE_CAPACITY * 3).expect("fits in a byte") {
            let mut device = [0u8; DEVICE_ID_LEN];
            device[0] = n;
            assert!(g.check(&clip(n, device, 1, NOW), NOW).is_accept());
        }
        assert_eq!(g.known_devices(), DEFAULT_DEVICE_CAPACITY);
    }

    #[test]
    fn sequence_numbers_are_tracked_per_device() {
        let mut g = guard();
        assert_eq!(g.check(&clip(1, THEIRS, 10, NOW), NOW), Verdict::Accept);
        // A different device starting at 1 is not a rollback.
        assert_eq!(g.check(&clip(2, OTHER, 1, NOW), NOW), Verdict::Accept);
        assert_eq!(g.known_devices(), 2);
    }

    #[test]
    fn drops_a_stale_live_clip() {
        let mut g = guard();
        let old = clip(1, THEIRS, 1, NOW - DEFAULT_MAX_AGE_MS - 1);
        assert_eq!(g.check(&old, NOW), Verdict::TooOld);
    }

    #[test]
    fn accepts_an_old_clip_when_the_relay_marks_it_retained() {
        let mut g = guard();
        let mut retained = clip(1, THEIRS, 1, NOW - 60 * 60 * 1000);
        retained.retained = true;
        assert_eq!(g.check(&retained, NOW), Verdict::Accept);
    }

    #[test]
    fn rejects_a_retained_clip_older_than_the_retention_period() {
        let mut g = guard();
        let mut ancient = clip(1, THEIRS, 1, NOW - RETENTION_MS - 1);
        ancient.retained = true;
        assert_eq!(g.check(&ancient, NOW), Verdict::TooOld);
    }

    #[test]
    fn tolerates_modest_clock_skew() {
        let mut g = guard();
        let slightly_ahead = clip(1, THEIRS, 1, NOW + 30_000);
        assert_eq!(g.check(&slightly_ahead, NOW), Verdict::Accept);
    }

    #[test]
    fn rejects_an_implausible_future_timestamp() {
        let mut g = guard();
        let way_ahead = clip(1, THEIRS, 1, NOW + DEFAULT_FUTURE_SKEW_MS + 1);
        assert_eq!(g.check(&way_ahead, NOW), Verdict::FromTheFuture);
    }

    #[test]
    fn a_clock_in_the_wrong_time_zone_still_syncs() {
        // The right local time on the clock face, the wrong zone underneath: hours off in UTC.
        let mut g = guard();
        let four_hours = 4 * 60 * 60 * 1000;
        assert_eq!(
            g.check(&clip(1, THEIRS, 1, NOW + four_hours), NOW),
            Verdict::Accept
        );
        assert_eq!(
            g.check(&clip(2, OTHER, 1, NOW - four_hours), NOW),
            Verdict::Accept
        );
    }

    #[test]
    fn a_restart_does_not_open_a_replay_window() {
        let mut before = guard();
        assert_eq!(before.check(&clip(1, THEIRS, 5, NOW), NOW), Verdict::Accept);
        let saved = before.memory();

        // A new process: without the memory, the same clip would be accepted a second time.
        let mut after = guard();
        after.restore(&saved);
        assert_eq!(
            after.check(&clip(1, THEIRS, 5, NOW), NOW),
            Verdict::Duplicate
        );
        assert_eq!(
            after.check(&clip(9, THEIRS, 4, NOW), NOW),
            Verdict::Rollback
        );
        assert_eq!(after.check(&clip(10, THEIRS, 6, NOW), NOW), Verdict::Accept);
    }

    #[test]
    fn restoring_never_lowers_what_is_known() {
        let mut g = guard();
        assert_eq!(g.check(&clip(1, THEIRS, 50, NOW), NOW), Verdict::Accept);
        g.restore(&Memory {
            highest_seq: vec![(THEIRS, 10)],
            recent: Vec::new(),
        });
        assert_eq!(g.check(&clip(2, THEIRS, 20, NOW), NOW), Verdict::Rollback);
    }

    #[test]
    fn a_rejected_clip_does_not_advance_state() {
        let mut g = guard();
        let stale = clip(1, THEIRS, 9, NOW - DEFAULT_MAX_AGE_MS - 1);
        assert_eq!(g.check(&stale, NOW), Verdict::TooOld);
        // Sequence 1 from that device must still be accepted: the rejected message must not have
        // raised the high water mark to 9.
        assert_eq!(g.check(&clip(2, THEIRS, 1, NOW), NOW), Verdict::Accept);
    }

    #[test]
    fn the_message_id_window_is_bounded() {
        let mut g = guard();
        for i in 0..300u32 {
            let incoming = Incoming {
                msg_id: (i.to_be_bytes().iter().copied().cycle().take(MSG_ID_LEN))
                    .collect::<Vec<u8>>()
                    .try_into()
                    .unwrap(),
                device_id: THEIRS,
                seq: u64::from(i) + 1,
                ts_ms: NOW,
                retained: false,
            };
            assert_eq!(g.check(&incoming, NOW), Verdict::Accept);
        }
        assert_eq!(g.seen.len(), DEFAULT_MSG_ID_CAPACITY);
    }

    #[test]
    fn verdict_reasons_are_log_safe_and_stable() {
        assert_eq!(Verdict::Accept.reason(), "accept");
        assert_eq!(Verdict::Rollback.reason(), "rollback");
        assert!(Verdict::Accept.is_accept());
        assert!(!Verdict::Duplicate.is_accept());
    }
}
