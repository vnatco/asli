//! The history key.
//!
//! History gets its own key, derived from the same root secret as everything else but under a
//! distinct label. Reusing the clip encryption key would mean one compromise unlocks both the
//! traffic and the archive, and it would tie the on disk format to the wire epoch, so rotating
//! one would silently invalidate the other.
//!
//! ```text
//! PRK         = HKDF-Extract(salt = "asli/v1/root-salt", IKM = secret)
//! history_key = HKDF-Expand(PRK, info = "asli/v1/history", L = 32)
//! ```
//!
//! The extract step matches `asli_crypto::kdf` exactly, deliberately: there is one PRK for the
//! account and every key hangs off it by label. The expand is done here rather than in
//! `asli-crypto` only because that crate's expand helper is private.

use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroizing;

/// HKDF-Extract salt, shared with every other key in the account. A constant, not a secret.
pub const LABEL_ROOT_SALT: &[u8] = b"asli/v1/root-salt";

/// HKDF-Expand info for the history key. Distinct from the clip and signing labels.
pub const LABEL_HISTORY: &[u8] = b"asli/v1/history";

/// Length of the root secret and of the derived key, in bytes.
pub const KEY_LEN: usize = 32;

/// Derives the history key from the account's root secret.
///
/// Held in a [`Zeroizing`] wrapper so it is wiped on drop, with the same honest caveat as the
/// rest of the project: that cannot recall copies the allocator, swap or a hibernation image
/// already made.
///
/// # Panics
///
/// Panics only if HKDF rejects a 32 byte PRK or a 32 byte output, neither of which can happen at
/// these fixed sizes. A panic here would mean HKDF changed its contract.
#[must_use]
pub fn derive(secret: &[u8; KEY_LEN]) -> Zeroizing<[u8; KEY_LEN]> {
    let (prk, _) = Hkdf::<Sha256>::extract(Some(LABEL_ROOT_SALT), secret);
    let hk = Hkdf::<Sha256>::from_prk(prk.as_slice()).expect("PRK length is always valid");

    let mut okm = Zeroizing::new([0u8; KEY_LEN]);
    hk.expand(LABEL_HISTORY, okm.as_mut())
        .expect("32 bytes is well within the HKDF output limit");
    okm
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECRET: [u8; 32] = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
        0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d,
        0x1e, 0x1f,
    ];

    #[test]
    fn derivation_is_deterministic() {
        assert_eq!(derive(&SECRET).as_ref(), derive(&SECRET).as_ref());
    }

    #[test]
    fn a_different_secret_gives_a_different_key() {
        let mut other = SECRET;
        other[31] ^= 0x01;
        assert_ne!(derive(&SECRET).as_ref(), derive(&other).as_ref());
    }

    #[test]
    fn the_history_key_is_not_the_clip_key() {
        // The whole point of a separate label. If these ever match, one compromise takes both
        // the traffic and the archive.
        let identity = asli_crypto::Identity::from_secret(&SECRET);
        for epoch in 0..4u32 {
            assert_ne!(
                derive(&SECRET).as_ref(),
                identity.enc_key(epoch).as_ref(),
                "history key collided with the clip key at epoch {epoch}"
            );
        }
    }

    #[test]
    fn the_history_key_is_not_the_signing_seed() {
        let prk = asli_crypto::Prk::extract(&SECRET);
        assert_ne!(derive(&SECRET).as_ref(), prk.sign_seed().as_ref());
    }
}
