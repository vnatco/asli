//! The connection state machine.
//!
//! This is a pure function from (state, input) to state, with no I/O and no clock, so every
//! transition is testable directly rather than inferred from behaviour against a live relay.
//!
//! The reason it exists as a type at all is close codes 4002, 4003 and 4004. Those are permanent:
//! a bad signature, a room id that does not match the public key, and an unsupported protocol
//! version will all fail again on the next attempt. The specification requires them to be explicit
//! terminal states rather than an emergent property of a reconnect loop, because a client that
//! retries a bad signature once per second against the public relay is a self inflicted denial of
//! service.

use crate::envelope::{AuthFailCode, ErrorCode};

/// Why a connection ended permanently.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Fatal {
    /// The signature did not verify. The stored secret does not match the room.
    BadSignature,
    /// The room id is not the hash of the public key. A client bug or a corrupted keychain entry.
    RoomMismatch,
    /// The relay does not speak this protocol version.
    UnsupportedVersion,
}

impl Fatal {
    /// What to tell the user, in one sentence.
    #[must_use]
    pub const fn user_message(self) -> &'static str {
        match self {
            Self::BadSignature => {
                "This device's key was rejected. Re-join with the token from another device."
            }
            Self::RoomMismatch => {
                "The stored account is inconsistent. Re-join with the token from another device."
            }
            Self::UnsupportedVersion => "The relay is newer than this app. Please update Asli.",
        }
    }

    /// Maps a close code to a permanent reason, if it is one.
    #[must_use]
    pub const fn from_close_code(code: u16) -> Option<Self> {
        match code {
            4002 => Some(Self::BadSignature),
            4003 => Some(Self::RoomMismatch),
            4004 => Some(Self::UnsupportedVersion),
            _ => None,
        }
    }

    /// Maps an authentication failure code to a permanent reason, if it is one.
    #[must_use]
    pub const fn from_auth_fail(code: AuthFailCode) -> Option<Self> {
        match code {
            AuthFailCode::BadSignature => Some(Self::BadSignature),
            AuthFailCode::RoomMismatch => Some(Self::RoomMismatch),
            AuthFailCode::UnsupportedVersion => Some(Self::UnsupportedVersion),
            _ => None,
        }
    }
}

/// Where the connection is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum State {
    /// Not connected, and waiting out a backoff delay before trying again.
    Disconnected,
    /// A socket is being established.
    Connecting,
    /// The socket is open and the handshake is in flight.
    Authenticating,
    /// Authenticated and exchanging clips.
    Synced,
    /// The user paused sync. No reconnects are attempted.
    Paused,
    /// The relay is rate limiting or quota limiting this room.
    ///
    /// Distinct from [`State::Disconnected`] because the tray must say so: a user who copied
    /// something and saw nothing happen deserves the real reason.
    RateLimited,
    /// Permanently failed. No further attempts will be made without user action.
    Fatal(Fatal),
}

impl State {
    /// Whether clips can be sent right now.
    #[must_use]
    pub const fn can_send(self) -> bool {
        matches!(self, Self::Synced)
    }

    /// Whether the supervisor should attempt a connection.
    #[must_use]
    pub const fn wants_connection(self) -> bool {
        matches!(self, Self::Disconnected | Self::RateLimited)
    }

    /// A short label for the tray status line.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Disconnected => "Offline, retrying",
            // Dialling and handshaking are one thing to a person watching a tray icon.
            Self::Connecting | Self::Authenticating => "Connecting",
            Self::Synced => "Synced",
            Self::Paused => "Paused",
            Self::RateLimited => "Rate limited, retrying",
            Self::Fatal(_) => "Stopped",
        }
    }
}

/// What happened.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Input {
    /// The supervisor began dialling.
    Dial,
    /// The socket opened and the handshake started.
    SocketOpen,
    /// The relay accepted us.
    AuthOk,
    /// The relay rejected authentication.
    AuthFail(AuthFailCode),
    /// A non fatal error message arrived.
    RelayError(ErrorCode),
    /// The socket closed with this code.
    Closed(u16),
    /// The user asked to pause.
    Pause,
    /// The user asked to resume.
    Resume,
    /// The user asked to retry after a permanent failure, for example after re-joining.
    Reset,
}

/// Applies one input to one state.
///
/// Unknown combinations leave the state unchanged rather than panicking, because a relay or an
/// operating system can deliver events in an order this client did not anticipate, and a tray app
/// that aborts on surprise is worse than one that ignores it.
#[must_use]
pub fn next(state: State, input: Input) -> State {
    match (state, input) {
        // Two unrelated rules that happen to share an outcome: clearing a permanent failure after
        // the user re-joins, and resuming from a pause. Both must be matched before the catch all
        // arms below them, which would otherwise swallow them.
        (State::Fatal(_), Input::Reset) | (State::Paused, Input::Resume) => State::Disconnected,
        (State::Fatal(reason), _) => State::Fatal(reason),
        // Pausing wins from anywhere except a permanent failure, and while paused every
        // connectivity event is ignored rather than acted on.
        (_, Input::Pause) | (State::Paused, _) => State::Paused,

        (_, Input::AuthFail(code)) => match Fatal::from_auth_fail(code) {
            Some(reason) => State::Fatal(reason),
            None => State::Disconnected,
        },

        (_, Input::Closed(code)) => match Fatal::from_close_code(code) {
            Some(reason) => State::Fatal(reason),
            // 4007 and 4008 are transient but deserve their own visible state, since the user
            // needs to know why their copy did not arrive.
            None if code == 4007 || code == 4008 => State::RateLimited,
            None => State::Disconnected,
        },

        (State::Disconnected | State::RateLimited, Input::Dial) => State::Connecting,
        (State::Connecting, Input::SocketOpen) => State::Authenticating,
        // Reaching auth_ok clears a rate limited state as well, since the relay let us back in.
        (State::Authenticating | State::RateLimited, Input::AuthOk) => State::Synced,

        (State::Synced, Input::RelayError(ErrorCode::RateLimited | ErrorCode::QuotaExceeded)) => {
            State::RateLimited
        }

        // Everything else is a no op, including errors that do not change connectivity.
        (current, _) => current,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_happy_path_reaches_synced() {
        let mut s = State::Disconnected;
        s = next(s, Input::Dial);
        assert_eq!(s, State::Connecting);
        s = next(s, Input::SocketOpen);
        assert_eq!(s, State::Authenticating);
        s = next(s, Input::AuthOk);
        assert_eq!(s, State::Synced);
        assert!(s.can_send());
    }

    #[test]
    fn permanent_close_codes_are_terminal() {
        for (code, expected) in [
            (4002u16, Fatal::BadSignature),
            (4003, Fatal::RoomMismatch),
            (4004, Fatal::UnsupportedVersion),
        ] {
            let s = next(State::Synced, Input::Closed(code));
            assert_eq!(s, State::Fatal(expected), "close {code}");
            assert!(!s.wants_connection(), "close {code} must stop reconnecting");

            // And it stays terminal no matter what arrives next.
            assert_eq!(next(s, Input::Dial), s);
            assert_eq!(next(s, Input::SocketOpen), s);
            assert_eq!(next(s, Input::AuthOk), s);
            assert_eq!(next(s, Input::Closed(1001)), s);
        }
    }

    #[test]
    fn permanent_auth_fail_codes_are_terminal() {
        for (code, expected) in [
            (AuthFailCode::BadSignature, Fatal::BadSignature),
            (AuthFailCode::RoomMismatch, Fatal::RoomMismatch),
            (AuthFailCode::UnsupportedVersion, Fatal::UnsupportedVersion),
        ] {
            assert_eq!(
                next(State::Authenticating, Input::AuthFail(code)),
                State::Fatal(expected)
            );
        }
    }

    #[test]
    fn transient_auth_fail_codes_reconnect() {
        for code in [
            AuthFailCode::MalformedAuth,
            AuthFailCode::StaleNonce,
            AuthFailCode::AuthTimeout,
        ] {
            let s = next(State::Authenticating, Input::AuthFail(code));
            assert_eq!(s, State::Disconnected);
            assert!(s.wants_connection());
        }
    }

    #[test]
    fn transient_close_codes_reconnect() {
        for code in [1001u16, 1009, 1011, 4001, 4005, 4006, 4009, 4010] {
            assert_eq!(
                next(State::Synced, Input::Closed(code)),
                State::Disconnected,
                "close {code}"
            );
        }
    }

    #[test]
    fn rate_limiting_gets_its_own_state() {
        assert_eq!(next(State::Synced, Input::Closed(4007)), State::RateLimited);
        assert_eq!(next(State::Synced, Input::Closed(4008)), State::RateLimited);
        assert_eq!(
            next(State::Synced, Input::RelayError(ErrorCode::RateLimited)),
            State::RateLimited
        );
        assert_eq!(
            next(State::Synced, Input::RelayError(ErrorCode::QuotaExceeded)),
            State::RateLimited
        );
        // And it still wants to reconnect, unlike a permanent failure.
        assert!(State::RateLimited.wants_connection());
    }

    #[test]
    fn a_non_connectivity_error_does_not_change_state() {
        for code in [
            ErrorCode::Malformed,
            ErrorCode::UnknownType,
            ErrorCode::NoRetained,
            ErrorCode::MessageTooLarge,
            ErrorCode::NotAuthenticated,
        ] {
            assert_eq!(
                next(State::Synced, Input::RelayError(code)),
                State::Synced,
                "{code:?}"
            );
        }
    }

    #[test]
    fn pause_wins_from_every_live_state_and_resume_restarts() {
        for s in [
            State::Disconnected,
            State::Connecting,
            State::Authenticating,
            State::Synced,
            State::RateLimited,
        ] {
            assert_eq!(next(s, Input::Pause), State::Paused, "{s:?}");
        }
        assert_eq!(next(State::Paused, Input::Resume), State::Disconnected);
        // While paused, connectivity events are ignored.
        assert_eq!(next(State::Paused, Input::Closed(1001)), State::Paused);
        assert_eq!(next(State::Paused, Input::AuthOk), State::Paused);
    }

    #[test]
    fn pause_does_not_override_a_permanent_failure() {
        let fatal = State::Fatal(Fatal::BadSignature);
        assert_eq!(next(fatal, Input::Pause), fatal);
    }

    #[test]
    fn reset_clears_a_permanent_failure() {
        let fatal = State::Fatal(Fatal::RoomMismatch);
        assert_eq!(next(fatal, Input::Reset), State::Disconnected);
    }

    #[test]
    fn only_synced_can_send() {
        for s in [
            State::Disconnected,
            State::Connecting,
            State::Authenticating,
            State::Paused,
            State::RateLimited,
            State::Fatal(Fatal::BadSignature),
        ] {
            assert!(!s.can_send(), "{s:?}");
        }
        assert!(State::Synced.can_send());
    }

    #[test]
    fn every_state_has_a_label() {
        for s in [
            State::Disconnected,
            State::Connecting,
            State::Authenticating,
            State::Synced,
            State::Paused,
            State::RateLimited,
            State::Fatal(Fatal::BadSignature),
        ] {
            assert!(!s.label().is_empty(), "{s:?}");
        }
        assert!(!Fatal::BadSignature.user_message().is_empty());
    }
}
