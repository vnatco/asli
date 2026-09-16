//! Cryptography for Asli, an end to end encrypted clipboard sync tool.
//!
//! This crate holds everything that must be correct for the product's security claim to be true,
//! and nothing else. It does no I/O, opens no sockets, touches no clipboard and spawns no
//! threads, which is what makes it testable against fixed vectors.
//!
//! # The model
//!
//! One person owns several devices and one 32 byte root secret, moved between those devices as a
//! join token. Every key comes from that secret by domain separated HKDF:
//!
//! ```text
//! secret --> PRK --> sign_seed  --> Ed25519 key pair --> room_id = H(pub_key)
//!                --> enc_key[epoch] --> XChaCha20-Poly1305 for clipboard content
//! ```
//!
//! The relay learns the room id and the public key, and nothing else. It cannot decrypt content,
//! cannot forge a message, and holds no credential that would let it join the room.
//!
//! # What this crate does not defend against
//!
//! There is no forward secrecy: a secret that leaks decrypts every ciphertext an observer
//! archived, past and future. There is no device revocation in v1: the answer to a leaked secret
//! is a new account. The relay can still drop messages, delay them, and observe timing and padded
//! sizes. See `docs/THREAT_MODEL.md` for the full list, stated plainly.
//!
//! # Example
//!
//! ```
//! use asli_crypto::{clip, Identity};
//!
//! // Device A creates an account and renders the join token.
//! let a = Identity::generate()?;
//! let token = asli_crypto::token::encode(a.secret());
//!
//! // Device B joins with that one string.
//! let secret = asli_crypto::token::parse(&token)?;
//! let b = Identity::from_secret(&secret);
//! assert_eq!(a.room_id(), b.room_id());
//!
//! // Device A seals a clipboard event.
//! let inner = clip::Inner {
//!     content_type: clip::ContentType::Text,
//!     device_id: [1u8; clip::DEVICE_ID_LEN],
//!     seq: 1,
//!     ts_ms: 1_767_225_600_000,
//!     content: b"copied on the laptop".to_vec(),
//! };
//! let msg_id = [9u8; clip::MSG_ID_LEN];
//! let sealed = clip::seal(&a.enc_key(0), 0, &a.room_id_bytes(), &msg_id, &inner)?;
//!
//! // Device B opens it.
//! let opened = clip::open(
//!     &b.enc_key(0), 0, &b.room_id_bytes(), &msg_id, &sealed.nonce, &sealed.ciphertext,
//! )?;
//! assert_eq!(opened.content, b"copied on the laptop");
//! # Ok::<(), asli_crypto::Error>(())
//! ```

#![forbid(unsafe_code)]

pub mod auth;
pub mod base32;
pub mod chunk;
pub mod clip;
pub mod error;
pub mod identity;
pub mod kdf;
pub mod random;
pub mod token;

pub use error::{Error, Result};
pub use identity::Identity;
pub use kdf::Prk;

/// The cryptographic suite identifier announced during the handshake.
pub const SUITE: &str = "asli-v1";
