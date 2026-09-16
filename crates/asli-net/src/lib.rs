//! Client transport for Asli.
//!
//! This crate is the middle of the client: it turns a clipboard change into a sealed frame on a
//! WebSocket, turns a received frame back into text to write, and keeps the connection alive
//! without ever giving up on its own.
//!
//! # Layering
//!
//! ```text
//! clipboard backend  ->  Session (sans I/O)  ->  client.rs  ->  relay
//!   asli-clipboard        seal, open, guards      WebSocket
//!                         asli-crypto, asli-core
//! ```
//!
//! [`session::Session`] holds every protocol rule and performs no I/O, so replay, rollback, stale
//! clips, oversize clips and the handshake are all tested against an in memory transport rather
//! than a live relay. [`client`] is the thin socket layer, [`state`] is the connection state
//! machine, and [`backoff`] is the reconnect pacing.
//!
//! # What this crate guarantees
//!
//! - The relay sees ciphertext, a room id, a message id and a nonce. Nothing else.
//! - A message that fails to decrypt or fails validation is discarded in silence, because a reply
//!   would confirm something to a relay that may be hostile.
//! - Close codes 4002, 4003 and 4004 end in a terminal state rather than a retry loop.
//! - Content is normalized once, before sealing, so the same text on Windows, macOS and Linux
//!   produces identical bytes and the receiver's loop prevention works at all.

#![forbid(unsafe_code)]

pub mod backoff;
pub mod client;
pub mod envelope;
pub mod error;
pub mod session;
pub mod state;

pub use backoff::Backoff;
pub use client::{ClientEvent, Disconnect, LocalEvent, ReceivedClip};
pub use envelope::{AuthFailCode, ErrorCode, Limits, Message};
pub use error::{Error, Result};
pub use session::{pump, Action, FakeTransport, Session, Transport};
pub use state::{Fatal, Input, State};
