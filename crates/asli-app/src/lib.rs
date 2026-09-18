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

pub mod autostart;
pub mod cli;
pub mod clipboard_io;
pub mod config;
pub mod daemon;
pub mod error;
pub mod history_store;
pub mod instance;
pub mod notify;
pub mod qr;
pub mod secrets;
pub mod tray;
pub mod window;

pub use error::{Error, Result};
