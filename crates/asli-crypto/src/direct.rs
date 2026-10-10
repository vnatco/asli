//! A file sent straight to a device on the same network, without the relay.
//!
//! The offer (see [`crate::file`]) can carry the sender's local addresses and a key made for that
//! one transfer, sealed to the receiver's box key, so only the device the file was offered to can
//! use it. The receiver connects to one of the addresses and the two speak in frames sealed under a
//! key derived from it:
//!
//! ```text
//! receiver -> sender   salt[16]                      (in the clear, once, first)
//! key                = HKDF-SHA256(salt, transfer_key, "asli/v2/file-direct")
//! either way          u32be(len) || XChaCha20-Poly1305(key, nonce, plaintext, aad = label || offer_id)
//! nonce              = u8(side) || u64be(counter) || zero[15]
//! ```
//!
//! `side` is 0 for what the receiver sends and 1 for what the sender sends, and each side counts
//! its own frames from zero, so a nonce never repeats under one key. The salt is fresh for every
//! connection, so a receiver that connects twice gets a new key the second time.
//!
//! The receiver's first frame is a hello, `u8(1) || offer_id`, which only the device holding the
//! transfer key can make. The sender answers with the file's pieces, one frame each, in order. The
//! receiver's last frame is `u8(state)`, 1 for kept and 2 for damaged, as in an acknowledgement.

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};
use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::clip::{NONCE_LEN, TAG_LEN};
use crate::error::{Error, Result};
use crate::file::OFFER_ID_LEN;
use crate::kdf::KEY_LEN;

/// Key derivation label, and the start of every frame's associated data.
pub const LABEL_DIRECT: &[u8] = b"asli/v2/file-direct";
/// Length of the salt the receiver opens a connection with.
pub const SALT_LEN: usize = 16;
/// What sealing adds to a frame's plaintext.
pub const FRAME_OVERHEAD: usize = TAG_LEN;

/// Which end of the connection a frame comes from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Side {
    /// The device the file goes to, which connects.
    Receiver,
    /// The device the file comes from, which listens.
    Sender,
}

impl Side {
    const fn code(self) -> u8 {
        match self {
            Self::Receiver => 0,
            Self::Sender => 1,
        }
    }

    const fn other(self) -> Self {
        match self {
            Self::Receiver => Self::Sender,
            Self::Sender => Self::Receiver,
        }
    }
}

/// One end of a direct connection: seals what it sends and opens what it receives, counting both.
pub struct Stream {
    cipher: XChaCha20Poly1305,
    aad: Vec<u8>,
    me: Side,
    sent: u64,
    received: u64,
}

impl std::fmt::Debug for Stream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Stream")
            .field("me", &self.me)
            .field("sent", &self.sent)
            .field("received", &self.received)
            .finish_non_exhaustive()
    }
}

impl Stream {
    /// One end of the connection for `offer_id`, keyed by the transfer key and the salt the
    /// receiver opened with.
    ///
    /// # Panics
    ///
    /// Never: 32 bytes is well within what HKDF can produce.
    #[must_use]
    pub fn new(
        transfer_key: &[u8; KEY_LEN],
        salt: &[u8; SALT_LEN],
        offer_id: &[u8; OFFER_ID_LEN],
        me: Side,
    ) -> Self {
        let hk = Hkdf::<Sha256>::new(Some(salt), transfer_key);
        let mut key = Zeroizing::new([0u8; KEY_LEN]);
        hk.expand(LABEL_DIRECT, key.as_mut())
            .expect("32 bytes is well within the HKDF output limit");
        let mut aad = Vec::with_capacity(LABEL_DIRECT.len() + OFFER_ID_LEN);
        aad.extend_from_slice(LABEL_DIRECT);
        aad.extend_from_slice(offer_id);
        Self {
            cipher: XChaCha20Poly1305::new(&Key::from(*key)),
            aad,
            me,
            sent: 0,
            received: 0,
        }
    }

    /// Seals the next frame this end sends.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Seal`] if encryption fails.
    pub fn seal(&mut self, plaintext: &[u8]) -> Result<Vec<u8>> {
        let nonce = nonce(self.me, self.sent);
        self.sent += 1;
        self.cipher
            .encrypt(
                &XNonce::from(nonce),
                Payload {
                    msg: plaintext,
                    aad: &self.aad,
                },
            )
            .map_err(|_| Error::Seal)
    }

    /// Opens the next frame from the other end. A frame that was altered, replayed, reordered or
    /// left out does not open.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Open`] for a frame that does not open as the next one.
    pub fn open(&mut self, sealed: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
        let nonce = nonce(self.me.other(), self.received);
        let plaintext = self
            .cipher
            .decrypt(
                &XNonce::from(nonce),
                Payload {
                    msg: sealed,
                    aad: &self.aad,
                },
            )
            .map_err(|_| Error::Open)?;
        self.received += 1;
        Ok(Zeroizing::new(plaintext))
    }
}

fn nonce(side: Side, counter: u64) -> [u8; NONCE_LEN] {
    let mut nonce = [0u8; NONCE_LEN];
    nonce[0] = side.code();
    nonce[1..9].copy_from_slice(&counter.to_be_bytes());
    nonce
}

/// The receiver's first frame.
#[must_use]
pub fn hello(offer_id: &[u8; OFFER_ID_LEN]) -> Vec<u8> {
    let mut out = Vec::with_capacity(1 + OFFER_ID_LEN);
    out.push(1);
    out.extend_from_slice(offer_id);
    out
}

/// Whether an opened first frame is the hello for `offer_id`.
#[must_use]
pub fn is_hello(plaintext: &[u8], offer_id: &[u8; OFFER_ID_LEN]) -> bool {
    plaintext.len() == 1 + OFFER_ID_LEN && plaintext[0] == 1 && plaintext[1..] == offer_id[..]
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: [u8; KEY_LEN] = [7u8; KEY_LEN];
    const SALT: [u8; SALT_LEN] = [3u8; SALT_LEN];
    const OFFER: [u8; OFFER_ID_LEN] = [5u8; OFFER_ID_LEN];

    #[test]
    fn frames_open_in_order_on_the_other_end_only() {
        let mut receiver = Stream::new(&KEY, &SALT, &OFFER, Side::Receiver);
        let mut sender = Stream::new(&KEY, &SALT, &OFFER, Side::Sender);
        let hi = receiver.seal(&hello(&OFFER)).expect("seals");
        assert!(is_hello(&sender.open(&hi).expect("opens"), &OFFER));

        let first = sender.seal(b"piece 0").expect("seals");
        let second = sender.seal(b"piece 1").expect("seals");
        assert!(receiver.open(&second).is_err(), "out of order");
        assert_eq!(&**receiver.open(&first).expect("opens"), b"piece 0");
        assert!(receiver.open(&first).is_err(), "replayed");
        assert_eq!(&**receiver.open(&second).expect("opens"), b"piece 1");

        // A frame the receiver sent cannot be reflected back at it as if from the sender.
        let mut echo = Stream::new(&KEY, &SALT, &OFFER, Side::Receiver);
        let mine = echo.seal(b"x").expect("seals");
        let mut fresh = Stream::new(&KEY, &SALT, &OFFER, Side::Receiver);
        assert!(fresh.open(&mine).is_err());
    }

    #[test]
    fn another_salt_offer_or_key_opens_nothing() {
        let mut receiver = Stream::new(&KEY, &SALT, &OFFER, Side::Receiver);
        let hi = receiver.seal(&hello(&OFFER)).expect("seals");
        for mut other in [
            Stream::new(&KEY, &[4u8; SALT_LEN], &OFFER, Side::Sender),
            Stream::new(&KEY, &SALT, &[6u8; OFFER_ID_LEN], Side::Sender),
            Stream::new(&[8u8; KEY_LEN], &SALT, &OFFER, Side::Sender),
        ] {
            assert!(other.open(&hi).is_err());
        }
        assert!(!is_hello(&hello(&[6u8; OFFER_ID_LEN]), &OFFER));
    }
}
