//! Platform independent logic for Asli.
//!
//! This crate holds the parts that are easy to get wrong and hard to debug once they are tangled
//! up with an operating system: text normalization, loop prevention, and the checks that keep an
//! untrusted relay from replaying or rolling back clipboard history.
//!
//! It does no I/O and touches no clipboard, so every rule in it is tested directly rather than
//! inferred from behaviour on one machine. Time is always passed in by the caller, so the tests
//! are deterministic.
//!
//! # The three layers of loop prevention
//!
//! A clipboard sync tool that gets this wrong does not fail quietly. It sends the same text back
//! and forth until something breaks, and the competitor research is full of exactly that. So
//! there are three independent layers, and each covers a case the others miss:
//!
//! 1. **Device id**, in [`replay`]. Every clip carries the id of the device that sent it, inside
//!    the ciphertext. We drop our own. This catches the case where a device reconnects, fetches
//!    the stored clip and would otherwise rebroadcast its own message.
//! 2. **Content hash**, in [`echo`]. We record the hash of what we are about to write **before**
//!    writing it, and swallow the resulting change notification once. Entries expire, so copying
//!    the same text again on purpose still syncs.
//! 3. **Platform sequence number**, in the clipboard backends. Where the operating system gives us
//!    a counter (`changeCount` on macOS, `GetClipboardSequenceNumber` on Windows, the `XFixes`
//!    owner field on X11) we capture it at write time and ignore the matching event.
//!
//! Layer three is the most reliable and the least portable, layer two is the most portable, and
//! layer one is the only one that survives a hostile relay.

#![forbid(unsafe_code)]

pub mod echo;
pub mod normalize;
pub mod replay;

pub use echo::{hash, ContentHash, EchoGuard};
pub use normalize::{is_syncable, normalize, to_platform, LineEnding};
pub use replay::{Incoming, ReplayGuard, Verdict};
