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
//! The tray is not wired yet: the command line is the interface for now.

#![forbid(unsafe_code)]

pub mod clipboard_io;
pub mod config;
pub mod daemon;
pub mod error;
pub mod qr;
pub mod secrets;

pub use error::{Error, Result};
