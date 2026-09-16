//! Key derivation.
//!
//! Every key in Asli comes from one 32 byte root secret through HKDF-SHA-256 with domain
//! separated labels. The root secret is never used as a key directly, which keeps a future
//! addition (rotation, per device keys, backups) from colliding with an existing use.
//!
//! ```text
//! PRK            = HKDF-Extract(salt = "asli/v1/root-salt", IKM = secret)
//! sign_seed      = HKDF-Expand(PRK, info = "asli/v1/device-sign", L = 32)
//! enc_key[epoch] = HKDF-Expand(PRK, info = "asli/v1/clip-enc" || u32be(epoch), L = 32)
//! ```
//!
//! `sign_seed` is epoch independent, so the room identity survives key rotation.

use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::error::{Error, Result};

/// HKDF-Extract salt. A constant, not a secret.
pub const LABEL_ROOT_SALT: &[u8] = b"asli/v1/root-salt";
/// HKDF-Expand info for the Ed25519 signing seed.
pub const LABEL_DEVICE_SIGN: &[u8] = b"asli/v1/device-sign";
/// HKDF-Expand info prefix for the clip encryption key. The epoch is appended as `u32be`.
pub const LABEL_CLIP_ENC: &[u8] = b"asli/v1/clip-enc";

/// Length of the root secret and of every derived key, in bytes.
pub const KEY_LEN: usize = 32;

/// A pseudo random key: the output of HKDF-Extract over the root secret.
///
/// Held in a [`Zeroizing`] wrapper so it is wiped when dropped. Note the honest limit: this
/// cannot recall copies the allocator, the scheduler, swap or a hibernation image already made.
pub struct Prk(Zeroizing<[u8; KEY_LEN]>);

impl Prk {
    /// Extracts a PRK from the 32 byte root secret.
    #[must_use]
    pub fn extract(secret: &[u8; KEY_LEN]) -> Self {
        let (prk, _) = Hkdf::<Sha256>::extract(Some(LABEL_ROOT_SALT), secret);
        let mut bytes = [0u8; KEY_LEN];
        bytes.copy_from_slice(prk.as_slice());
        Self(Zeroizing::new(bytes))
    }

    fn expand(&self, info: &[u8]) -> Zeroizing<[u8; KEY_LEN]> {
        let hk = Hkdf::<Sha256>::from_prk(self.0.as_ref()).expect("PRK length is always valid");
        let mut okm = Zeroizing::new([0u8; KEY_LEN]);
        hk.expand(info, okm.as_mut())
            .expect("32 bytes is well within the HKDF output limit");
        okm
    }

    /// Derives the Ed25519 signing seed. Independent of the epoch.
    ///
    /// # Panics
    ///
    /// Panics only if HKDF rejects a 32 byte output or a 32 byte PRK, neither of which can
    /// happen for fixed sizes this small. A panic here would mean the HKDF implementation
    /// changed its contract.
    #[must_use]
    pub fn sign_seed(&self) -> Zeroizing<[u8; KEY_LEN]> {
        self.expand(LABEL_DEVICE_SIGN)
    }

    /// Derives the clip encryption key for one epoch.
    ///
    /// # Panics
    ///
    /// Panics only if HKDF rejects a 32 byte output or a 32 byte PRK, neither of which can
    /// happen for fixed sizes this small.
    #[must_use]
    pub fn enc_key(&self, epoch: u32) -> Zeroizing<[u8; KEY_LEN]> {
        let mut info = [0u8; 16 + 4];
        info[..LABEL_CLIP_ENC.len()].copy_from_slice(LABEL_CLIP_ENC);
        info[LABEL_CLIP_ENC.len()..].copy_from_slice(&epoch.to_be_bytes());
        self.expand(&info)
    }

    /// Exposes the raw PRK bytes. Test vectors need this; nothing else should.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; KEY_LEN] {
        &self.0
    }
}

/// Copies a slice into a fixed size key array, checking the length.
///
/// # Errors
///
/// Returns [`Error::FieldLength`] if `bytes` is not exactly [`KEY_LEN`] long.
pub fn key_from_slice(field: &'static str, bytes: &[u8]) -> Result<[u8; KEY_LEN]> {
    if bytes.len() != KEY_LEN {
        return Err(Error::FieldLength {
            field,
            expected: KEY_LEN,
            got: bytes.len(),
        });
    }
    let mut out = [0u8; KEY_LEN];
    out.copy_from_slice(bytes);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_SECRET: [u8; 32] = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
        0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d,
        0x1e, 0x1f,
    ];

    #[test]
    fn epochs_produce_distinct_keys() {
        let prk = Prk::extract(&TEST_SECRET);
        let k0 = prk.enc_key(0);
        let k1 = prk.enc_key(1);
        assert_ne!(k0.as_ref(), k1.as_ref());
    }

    #[test]
    fn derivation_is_deterministic() {
        let a = Prk::extract(&TEST_SECRET);
        let b = Prk::extract(&TEST_SECRET);
        assert_eq!(a.as_bytes(), b.as_bytes());
        assert_eq!(a.sign_seed().as_ref(), b.sign_seed().as_ref());
        assert_eq!(a.enc_key(7).as_ref(), b.enc_key(7).as_ref());
    }

    #[test]
    fn sign_seed_differs_from_enc_key() {
        let prk = Prk::extract(&TEST_SECRET);
        assert_ne!(prk.sign_seed().as_ref(), prk.enc_key(0).as_ref());
    }

    #[test]
    fn a_different_secret_gives_different_keys() {
        let mut other = TEST_SECRET;
        other[31] ^= 0x01;
        let a = Prk::extract(&TEST_SECRET);
        let b = Prk::extract(&other);
        assert_ne!(a.sign_seed().as_ref(), b.sign_seed().as_ref());
    }

    #[test]
    fn key_from_slice_checks_length() {
        assert!(key_from_slice("k", &[0u8; 32]).is_ok());
        assert_eq!(
            key_from_slice("k", &[0u8; 31]),
            Err(Error::FieldLength {
                field: "k",
                expected: 32,
                got: 31
            })
        );
    }
}
