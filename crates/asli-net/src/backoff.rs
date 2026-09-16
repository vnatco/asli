//! Reconnect pacing.
//!
//! Full jitter, meaning a uniform draw over the whole interval rather than an exponential delay
//! with a small random addition. The purpose is not politeness, it is decorrelation: when the
//! relay restarts, every client in the fleet disconnects in the same second, and a narrow jittered
//! delay would bring them all back in the same second too.
//!
//! Randomness and time are parameters rather than ambient, so the tests are deterministic.
//!
//! # A note on the 4007 and 4008 floors
//!
//! `docs/PROTOCOL.md` section 13 describes 4007 and 4008 as raising the **cap**, while the close
//! code table in section 12.1 describes them as a **floor** ("back off with a 60 second floor",
//! "back off with a 1 hour floor"). Those two readings disagree, because a draw over `[0, cap]`
//! frequently lands below the floor. This implementation honours both by adding the floor to a
//! jittered draw that is still bounded by the cap, so a rate limited client waits at least its
//! floor and still decorrelates from its peers.

/// Base delay, doubled per attempt.
pub const BASE_MS: u64 = 500;
/// Normal ceiling for the jittered interval.
pub const CAP_MS: u64 = 30_000;
/// Ceiling after close code 4007.
pub const RATE_LIMITED_CAP_MS: u64 = 60_000;
/// Ceiling after close code 4008.
pub const QUOTA_CAP_MS: u64 = 3_600_000;
/// How long a connection must stay authenticated before the attempt counter resets.
pub const STABLE_MS: u64 = 60_000;

/// Reconnect pacing state.
#[derive(Debug, Clone)]
pub struct Backoff {
    attempt: u32,
    cap_ms: u64,
    floor_ms: u64,
    bypass_once: bool,
    authenticated_at_ms: Option<u64>,
}

impl Default for Backoff {
    fn default() -> Self {
        Self::new()
    }
}

impl Backoff {
    /// A fresh backoff, as if the client had just started.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            attempt: 0,
            cap_ms: CAP_MS,
            floor_ms: 0,
            bypass_once: false,
            authenticated_at_ms: None,
        }
    }

    /// How many delays have been handed out since the last reset.
    #[must_use]
    pub const fn attempt(&self) -> u32 {
        self.attempt
    }

    /// The current ceiling, which rises after a rate limit or quota close.
    #[must_use]
    pub const fn cap_ms(&self) -> u64 {
        self.cap_ms
    }

    /// The current floor, which a rate limit or quota close imposes.
    #[must_use]
    pub const fn floor_ms(&self) -> u64 {
        self.floor_ms
    }

    /// Records the close code the relay sent, which may change the pacing.
    pub const fn on_close(&mut self, code: u16) {
        match code {
            4007 => {
                self.cap_ms = RATE_LIMITED_CAP_MS;
                self.floor_ms = RATE_LIMITED_CAP_MS;
            }
            4008 => {
                self.cap_ms = QUOTA_CAP_MS;
                self.floor_ms = QUOTA_CAP_MS;
            }
            _ => {}
        }
        self.authenticated_at_ms = None;
    }

    /// Applies a server supplied `retry_after_ms` as a floor.
    ///
    /// The relay knows its own limits better than the client does, so this raises the floor but
    /// never lowers one already in force.
    pub const fn on_retry_after(&mut self, ms: u64) {
        if ms > self.floor_ms {
            self.floor_ms = ms;
        }
    }

    /// Notes that the connection authenticated. This starts the stability clock.
    ///
    /// The attempt counter deliberately does **not** reset here. Resetting on connect alone
    /// produces a tight loop against a relay that accepts a connection and immediately closes it.
    pub const fn on_authenticated(&mut self, now_ms: u64) {
        self.authenticated_at_ms = Some(now_ms);
    }

    /// Resets the pacing if the connection has been authenticated and stable long enough.
    ///
    /// Returns true when a reset happened, which callers may log.
    pub const fn note_stable(&mut self, now_ms: u64) -> bool {
        if let Some(since) = self.authenticated_at_ms {
            if now_ms.saturating_sub(since) >= STABLE_MS {
                self.attempt = 0;
                self.cap_ms = CAP_MS;
                self.floor_ms = 0;
                return true;
            }
        }
        false
    }

    /// Allows exactly one immediate retry, for an operating system network change.
    ///
    /// A tray app that waits thirty seconds after the laptop lid opens feels broken, and the
    /// network coming back is real information that the previous failure is stale.
    pub const fn on_network_change(&mut self) {
        self.bypass_once = true;
    }

    /// The delay before the next attempt, in milliseconds.
    ///
    /// `random` is any uniformly distributed value; only its remainder is used.
    pub const fn next_delay_ms(&mut self, random: u64) -> u64 {
        if self.bypass_once {
            self.bypass_once = false;
            return 0;
        }

        // Saturating shift, so a long outage cannot overflow into a tiny delay. Ord::min is
        // not const stable, hence the explicit comparison.
        let shift = if self.attempt > 31 { 31 } else { self.attempt };
        let exponential = BASE_MS.saturating_mul(1u64 << shift);
        let interval = if exponential < self.cap_ms {
            exponential
        } else {
            self.cap_ms
        };

        let jitter = random % (interval + 1);
        self.attempt = self.attempt.saturating_add(1);
        self.floor_ms.saturating_add(jitter)
    }

    /// The delay before the next attempt, drawing from the operating system CSPRNG.
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error::Crypto`] if the operating system generator fails.
    pub fn next_delay(&mut self) -> crate::Result<u64> {
        let bytes: [u8; 8] = asli_crypto::random::bytes()?;
        Ok(self.next_delay_ms(u64::from_be_bytes(bytes)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_first_delays_are_small_and_grow() {
        let mut b = Backoff::new();
        // Jitter is `random % (interval + 1)`, so a draw at or below the interval passes through
        // unchanged. Feeding the interval itself is therefore the deterministic way to observe the
        // top of each window.
        assert_eq!(b.next_delay_ms(500), 500);
        assert_eq!(b.next_delay_ms(1_000), 1_000);
        assert_eq!(b.next_delay_ms(2_000), 2_000);
        assert_eq!(b.next_delay_ms(4_000), 4_000);
    }

    #[test]
    fn a_zero_draw_is_allowed_which_is_what_full_jitter_means() {
        let mut b = Backoff::new();
        assert_eq!(b.next_delay_ms(0), 0);
        assert_eq!(b.next_delay_ms(0), 0);
        // The interval still grew underneath, which a draw at the new top shows.
        assert_eq!(b.next_delay_ms(2_000), 2_000);
    }

    #[test]
    fn delays_are_capped() {
        let mut b = Backoff::new();
        for _ in 0..40 {
            let delay = b.next_delay_ms(u64::MAX);
            assert!(delay <= CAP_MS, "delay {delay} exceeded the cap");
        }
        assert_eq!(
            b.next_delay_ms(CAP_MS),
            CAP_MS,
            "the window opens to the cap and no further"
        );
    }

    #[test]
    fn a_long_outage_does_not_overflow_into_a_tiny_delay() {
        let mut b = Backoff::new();
        for _ in 0..1000 {
            let delay = b.next_delay_ms(u64::MAX);
            assert!(delay <= CAP_MS, "delay {delay} exceeded the cap");
        }
    }

    #[test]
    fn rate_limiting_imposes_a_sixty_second_floor() {
        let mut b = Backoff::new();
        b.on_close(4007);
        assert_eq!(b.floor_ms(), RATE_LIMITED_CAP_MS);
        let delay = b.next_delay_ms(0);
        assert!(
            delay >= 60_000,
            "a rate limited client must wait at least a minute, got {delay}"
        );
    }

    #[test]
    fn quota_exhaustion_imposes_an_hour_floor() {
        let mut b = Backoff::new();
        b.on_close(4008);
        let delay = b.next_delay_ms(0);
        assert!(delay >= 3_600_000, "got {delay}");
    }

    #[test]
    fn retry_after_raises_the_floor_but_never_lowers_it() {
        let mut b = Backoff::new();
        b.on_retry_after(5_000);
        assert_eq!(b.floor_ms(), 5_000);
        b.on_retry_after(1_000);
        assert_eq!(
            b.floor_ms(),
            5_000,
            "a smaller hint must not shorten the wait"
        );
    }

    #[test]
    fn authenticating_alone_does_not_reset_the_attempt_counter() {
        // This is the loop that resetting on connect produces: a relay that accepts and
        // immediately closes would otherwise be hammered at the base delay forever.
        let mut b = Backoff::new();
        b.next_delay_ms(0);
        b.next_delay_ms(0);
        b.on_authenticated(1_000);
        assert_eq!(b.attempt(), 2);
        assert_eq!(
            b.next_delay_ms(2_000),
            2_000,
            "interval must not have shrunk"
        );
    }

    #[test]
    fn the_counter_resets_only_after_sixty_stable_seconds() {
        let mut b = Backoff::new();
        b.next_delay_ms(0);
        b.next_delay_ms(0);
        b.on_authenticated(1_000);

        assert!(!b.note_stable(1_000 + STABLE_MS - 1), "not stable yet");
        assert_eq!(b.attempt(), 2);

        assert!(b.note_stable(1_000 + STABLE_MS), "stable now");
        assert_eq!(b.attempt(), 0);
        assert_eq!(
            b.next_delay_ms(500),
            500,
            "pacing restarted from the base delay"
        );
    }

    #[test]
    fn a_stable_connection_clears_a_rate_limit_floor() {
        let mut b = Backoff::new();
        b.on_close(4007);
        b.on_authenticated(0);
        assert!(b.note_stable(STABLE_MS));
        assert_eq!(b.floor_ms(), 0);
        assert_eq!(b.cap_ms(), CAP_MS);
    }

    #[test]
    fn closing_stops_the_stability_clock() {
        let mut b = Backoff::new();
        b.on_authenticated(0);
        b.on_close(1001);
        assert!(
            !b.note_stable(STABLE_MS * 10),
            "a closed connection is not stable"
        );
    }

    #[test]
    fn a_network_change_bypasses_the_delay_exactly_once() {
        let mut b = Backoff::new();
        b.next_delay_ms(500);
        b.next_delay_ms(1_000);

        b.on_network_change();
        assert_eq!(b.next_delay_ms(u64::MAX), 0, "the lid just opened");
        // And the next failure returns to normal pacing, without having burned an attempt.
        assert_eq!(b.next_delay_ms(2_000), 2_000);
    }

    #[test]
    fn the_os_backed_draw_stays_within_bounds() {
        let mut b = Backoff::new();
        for _ in 0..20 {
            let delay = b.next_delay().expect("the OS generator works");
            assert!(delay <= CAP_MS);
        }
    }
}
