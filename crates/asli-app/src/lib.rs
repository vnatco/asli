//! The Asli daemon and command line interface.
//!
//! This crate is the wiring. Every rule that matters lives somewhere else: the protocol in
//! `asli-net`, the sealing in `asli-crypto`, the loop prevention in `asli-core`, the platform
//! clipboard in `asli-clipboard`. What is left here is the part that is easy to get subtly wrong,
//! which is the order in which those pieces are called.
//!
//! # The ordering rule
//!
//! A received clip is written to the local clipboard only after its content hash has been
//! recorded in the echo guard. `asli-net` records it before handing over the action, so this
//! crate can simply write. Doing it the other way round leaves a window in which the platform
//! reports our own write as a user copy, and the two devices trade the same text forever. That
//! bug has shipped in most of the competing tools at least once.
//!
//! # Status
//!
//! Linux only so far, which is where the hard clipboard problems are. Adding macOS and Windows
//! means adding a backend behind [`clipboard_io::ClipboardIo`], not restructuring anything here.
//!
//! The tray, autostart and notifications are wired. Autostart on Windows and macOS returns a
//! clear error rather than reporting a success that will not survive a reboot.
//!
//! # No terminal in the onboarding path
//!
//! Joining is a screen in [`window`], because the promise is "paste one string on the other
//! machine" and an instruction to open a shell is not that. The command line equivalents remain
//! for people who prefer them.
//!
//! Three earlier mechanisms are gone. The join string was written to an HTML file and opened in a
//! browser, joining was a prompt from the desktop's own dialog program, and settings was a JSON
//! file handed to a text editor. They were three different applications appearing on screen, and
//! the first of them wrote the account key to disk.

#![forbid(unsafe_code)]

/// Words that stay lower case inside a Title Case label, unless first or last.
const MINOR_WORDS: [&str; 19] = [
    "a", "an", "the", "and", "but", "or", "nor", "for", "so", "yet", "as", "at", "by", "in", "of",
    "on", "to", "up", "via",
];

/// A short label in Title Case, the house style for every label, button and status in the
/// interface: each word capitalised except short minor words, which are capitalised only first or
/// last. Words that already hold a capital (names, `MB`) are left as they are.
#[must_use]
pub fn title_case(text: &str) -> String {
    let words: Vec<&str> = text.split(' ').collect();
    let last = words.len().saturating_sub(1);
    words
        .iter()
        .enumerate()
        .map(|(i, word)| {
            let bare = word
                .trim_matches(|c: char| !c.is_alphanumeric())
                .to_lowercase();
            let minor = bare == "is" || MINOR_WORDS.contains(&bare.as_str());
            if word.chars().any(char::is_uppercase) || (minor && i != 0 && i != last) {
                (*word).to_owned()
            } else {
                let mut chars = word.chars();
                chars.next().map_or_else(String::new, |first| {
                    first.to_uppercase().chain(chars).collect()
                })
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

#[cfg(test)]
mod title_case_tests {
    use super::title_case;

    #[test]
    fn labels_follow_the_house_style() {
        for (given, wanted) in [
            ("offline, retrying", "Offline, Retrying"),
            ("17 minutes ago", "17 Minutes Ago"),
            ("never", "Never"),
            ("add a device", "Add a Device"),
            ("history is off", "History is Off"),
            ("a minute ago", "A Minute Ago"),
            ("saved in ~/Downloads", "Saved in ~/Downloads"),
            ("show in folder", "Show in Folder"),
            ("3.4 MB sent", "3.4 MB Sent"),
            ("waiting for them to accept", "Waiting for Them to Accept"),
            ("what is this up to", "What is This up To"),
        ] {
            assert_eq!(title_case(given), wanted);
        }
    }

    #[test]
    fn versions_compare_as_numbers() {
        use super::version_key;
        assert!(version_key("0.1.10") > version_key("0.1.9"));
        assert!(version_key("0.2.0") > version_key("0.1.99"));
        assert_eq!(version_key("v1.2.3"), (1, 2, 3));
        assert_eq!(version_key(""), (0, 0, 0));
    }
}

/// This Asli's version, bumped with every change. Devices compare it to say which is newest.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// A version as numbers, for comparing: `0.1.12` is `(0, 1, 12)`. Unreadable parts count as 0,
/// so an empty or garbled version sorts as the oldest.
#[must_use]
pub fn version_key(version: &str) -> (u64, u64, u64) {
    let mut parts = version
        .trim()
        .trim_start_matches('v')
        .split('.')
        .map(|part| part.parse::<u64>().unwrap_or(0));
    (
        parts.next().unwrap_or(0),
        parts.next().unwrap_or(0),
        parts.next().unwrap_or(0),
    )
}

pub mod autostart;
pub mod cli;
pub mod clipboard_io;
pub mod config;
pub mod daemon;
pub mod devices;
pub mod direct;
pub mod enroll;
pub mod error;
pub mod history_store;
pub mod instance;
#[cfg(target_os = "macos")]
pub mod macos;
pub mod notify;
pub mod qr;
pub mod replay_store;
pub mod reveal;
pub mod secrets;
pub mod shortcut;
pub mod transfer;
pub mod tray;
pub mod window;

pub use error::{Error, Result};
