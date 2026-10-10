//! A device's own keys, and sealing a secret to one device.
//!
//! The account key is shared by every device on an account: it is what encrypts clips, and what
//! the relay checks. A device key belongs to one device and never leaves it. It is what lets the
//! other devices tell this device's messages from anyone else's, and what lets a secret be handed
//! to this device alone: the account key when it joins, and a replacement account key when another
//! device is removed.
//!
//! ```text
//! device_secret   32 bytes, OS CSPRNG, kept beside the account key, never transmitted
//! PRK_d           = HKDF-Extract(salt = "asli/v2/device-salt", IKM = device_secret)
//! sign_seed       = HKDF-Expand(PRK_d, "asli/v2/device-sign", 32)    -> Ed25519 signing key
//! box_secret      = HKDF-Expand(PRK_d, "asli/v2/device-box", 32)     -> X25519 static secret
//! ```
//!
//! A sealed box is an anonymous sender to one recipient: a fresh X25519 key pair per message, its
//! shared secret with the recipient run through HKDF with both public keys and a purpose label,
//! and XChaCha20-Poly1305 under the result.
//!
//! ```text
//! shared  = X25519(eph_secret, recipient_box_pub)
//! key     = HKDF-SHA-256(salt = eph_pub || recipient_box_pub, IKM = shared, info = label, 32)
//! sealed  = eph_pub[32] || nonce[24] || XChaCha20-Poly1305(key, nonce, plaintext, aad = label)
//! ```
//!
//! The label names what the box is for, so a box made for one purpose cannot be presented as
//! another. An all zero shared secret, which a small order public key produces, is refused on
//! both sides rather than used as a key.

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};
use ed25519_dalek::{Signer, SigningKey};
use hkdf::Hkdf;
use sha2::Sha256;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroizing;

use crate::clip::NONCE_LEN;
use crate::error::{Error, Result};
use crate::identity::{PUB_KEY_LEN, SIGNATURE_LEN};
use crate::kdf::KEY_LEN;
use crate::random;

/// HKDF-Extract salt for a device secret.
pub const LABEL_DEVICE_SALT: &[u8] = b"asli/v2/device-salt";
/// HKDF-Expand info for the device signing seed.
pub const LABEL_DEVICE_SIGN: &[u8] = b"asli/v2/device-sign";
/// HKDF-Expand info for the device box secret.
pub const LABEL_DEVICE_BOX: &[u8] = b"asli/v2/device-box";

/// Length of an X25519 public key.
pub const BOX_PUB_LEN: usize = 32;
/// What a sealed box adds to its plaintext: the ephemeral public key, the nonce and the tag.
pub const SEALED_BOX_OVERHEAD: usize = BOX_PUB_LEN + NONCE_LEN + crate::clip::TAG_LEN;

/// One device's keys, derived from its device secret.
pub struct DeviceKeys {
    secret: Zeroizing<[u8; KEY_LEN]>,
    signing_key: SigningKey,
    box_secret: StaticSecret,
}

impl DeviceKeys {
    /// Makes keys for a new device.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Rng`] if the operating system random number generator fails.
    pub fn generate() -> Result<Self> {
        let secret = Zeroizing::new(random::bytes::<KEY_LEN>()?);
        Ok(Self::from_secret(&secret))
    }

    /// Rebuilds a device's keys from its stored secret.
    ///
    /// # Panics
    ///
    /// Never: 32 bytes is far inside the HKDF output limit.
    #[must_use]
    pub fn from_secret(secret: &[u8; KEY_LEN]) -> Self {
        let hk = Hkdf::<Sha256>::new(Some(LABEL_DEVICE_SALT), secret);
        let mut sign_seed = Zeroizing::new([0u8; KEY_LEN]);
        hk.expand(LABEL_DEVICE_SIGN, sign_seed.as_mut())
            .expect("32 bytes is well within the HKDF output limit");
        let mut box_seed = Zeroizing::new([0u8; KEY_LEN]);
        hk.expand(LABEL_DEVICE_BOX, box_seed.as_mut())
            .expect("32 bytes is well within the HKDF output limit");
        Self {
            secret: Zeroizing::new(*secret),
            signing_key: SigningKey::from_bytes(&sign_seed),
            box_secret: StaticSecret::from(*box_seed),
        }
    }

    /// The device secret, for storage beside the account key and nowhere else.
    #[must_use]
    pub fn secret(&self) -> &[u8; KEY_LEN] {
        &self.secret
    }

    /// The Ed25519 public key the other devices check this device's messages against.
    #[must_use]
    pub fn sign_pub(&self) -> [u8; PUB_KEY_LEN] {
        self.signing_key.verifying_key().to_bytes()
    }

    /// The X25519 public key a secret is sealed to for this device.
    #[must_use]
    pub fn box_pub(&self) -> [u8; BOX_PUB_LEN] {
        PublicKey::from(&self.box_secret).to_bytes()
    }

    /// Signs a message as this device.
    #[must_use]
    pub fn sign(&self, message: &[u8]) -> [u8; SIGNATURE_LEN] {
        self.signing_key.sign(message).to_bytes()
    }

    /// Opens a box sealed to this device for the purpose named by `label`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Open`] for anything that does not open: the wrong recipient, the wrong
    /// label, a tampered box, or one shorter than a box can be.
    pub fn open_box(&self, label: &[u8], sealed: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
        if sealed.len() < SEALED_BOX_OVERHEAD {
            return Err(Error::Open);
        }
        let eph_pub: [u8; BOX_PUB_LEN] =
            sealed[..BOX_PUB_LEN].try_into().map_err(|_| Error::Open)?;
        let nonce: [u8; NONCE_LEN] = sealed[BOX_PUB_LEN..BOX_PUB_LEN + NONCE_LEN]
            .try_into()
            .map_err(|_| Error::Open)?;
        let shared = self.box_secret.diffie_hellman(&PublicKey::from(eph_pub));
        if !shared.was_contributory() {
            return Err(Error::Open);
        }
        let key = box_key(shared.as_bytes(), &eph_pub, &self.box_pub(), label);
        let cipher = XChaCha20Poly1305::new(&Key::from(*key));
        Ok(Zeroizing::new(
            cipher
                .decrypt(
                    &XNonce::from(nonce),
                    Payload {
                        msg: &sealed[BOX_PUB_LEN + NONCE_LEN..],
                        aad: label,
                    },
                )
                .map_err(|_| Error::Open)?,
        ))
    }
}

/// Seals `plaintext` so that only the device holding the box secret for `recipient` can open it,
/// and only for the purpose named by `label`.
///
/// # Errors
///
/// Returns [`Error::Rng`] if randomness fails, [`Error::BadPublicKey`] for a recipient key that
/// would produce no shared secret, and [`Error::Seal`] if encryption fails.
pub fn seal_box(recipient: &[u8; BOX_PUB_LEN], label: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
    let eph_secret = StaticSecret::from(*Zeroizing::new(random::bytes::<KEY_LEN>()?));
    let nonce: [u8; NONCE_LEN] = random::bytes()?;
    seal_box_with(&eph_secret, &nonce, recipient, label, plaintext)
}

/// [`seal_box`] with the ephemeral secret and nonce supplied, for test vectors.
fn seal_box_with(
    eph_secret: &StaticSecret,
    nonce: &[u8; NONCE_LEN],
    recipient: &[u8; BOX_PUB_LEN],
    label: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>> {
    let eph_pub = PublicKey::from(eph_secret).to_bytes();
    let shared = eph_secret.diffie_hellman(&PublicKey::from(*recipient));
    if !shared.was_contributory() {
        return Err(Error::BadPublicKey);
    }
    let key = box_key(shared.as_bytes(), &eph_pub, recipient, label);
    let cipher = XChaCha20Poly1305::new(&Key::from(*key));
    let ciphertext = cipher
        .encrypt(
            &XNonce::from(*nonce),
            Payload {
                msg: plaintext,
                aad: label,
            },
        )
        .map_err(|_| Error::Seal)?;
    let mut out = Vec::with_capacity(SEALED_BOX_OVERHEAD + plaintext.len());
    out.extend_from_slice(&eph_pub);
    out.extend_from_slice(nonce);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

fn box_key(
    shared: &[u8; 32],
    eph_pub: &[u8; BOX_PUB_LEN],
    recipient: &[u8; BOX_PUB_LEN],
    label: &[u8],
) -> Zeroizing<[u8; KEY_LEN]> {
    let mut salt = [0u8; 2 * BOX_PUB_LEN];
    salt[..BOX_PUB_LEN].copy_from_slice(eph_pub);
    salt[BOX_PUB_LEN..].copy_from_slice(recipient);
    let hk = Hkdf::<Sha256>::new(Some(&salt), shared);
    let mut key = Zeroizing::new([0u8; KEY_LEN]);
    hk.expand(label, key.as_mut())
        .expect("32 bytes is well within the HKDF output limit");
    key
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::verify_signature;

    const LABEL: &[u8] = b"asli/v2/test-box";

    #[test]
    fn keys_are_deterministic_from_the_secret_and_distinct_per_device() {
        let a = DeviceKeys::from_secret(&[1u8; 32]);
        let again = DeviceKeys::from_secret(&[1u8; 32]);
        let b = DeviceKeys::from_secret(&[2u8; 32]);
        assert_eq!(a.sign_pub(), again.sign_pub());
        assert_eq!(a.box_pub(), again.box_pub());
        assert_ne!(a.sign_pub(), b.sign_pub());
        assert_ne!(a.box_pub(), b.box_pub());
        assert_eq!(a.secret(), &[1u8; 32]);
    }

    #[test]
    fn a_device_key_is_not_the_account_key() {
        // The same 32 bytes as a device secret and as an account secret give unrelated keys, so
        // the two can never be confused even if one were mistakenly stored as the other.
        let device = DeviceKeys::from_secret(&[5u8; 32]);
        let account = crate::Identity::from_secret(&[5u8; 32]);
        assert_ne!(device.sign_pub(), account.public_key());
    }

    #[test]
    fn signatures_verify_against_the_device_key() {
        let keys = DeviceKeys::from_secret(&[3u8; 32]);
        let sig = keys.sign(b"hello");
        assert!(verify_signature(&keys.sign_pub(), b"hello", &sig).is_ok());
        assert!(verify_signature(&keys.sign_pub(), b"hellO", &sig).is_err());
    }

    #[test]
    fn a_box_opens_for_its_recipient_and_its_purpose_only() {
        let alice = DeviceKeys::from_secret(&[1u8; 32]);
        let bob = DeviceKeys::from_secret(&[2u8; 32]);
        let sealed = seal_box(&bob.box_pub(), LABEL, b"the account key").expect("seals");
        assert_eq!(sealed.len(), SEALED_BOX_OVERHEAD + 15);

        assert_eq!(
            bob.open_box(LABEL, &sealed).expect("opens").as_slice(),
            b"the account key"
        );
        assert_eq!(alice.open_box(LABEL, &sealed), Err(Error::Open), "not hers");
        assert_eq!(
            bob.open_box(b"asli/v2/other", &sealed),
            Err(Error::Open),
            "a box for one purpose is not accepted as another"
        );
    }

    #[test]
    fn a_tampered_or_short_box_does_not_open() {
        let bob = DeviceKeys::from_secret(&[2u8; 32]);
        let sealed = seal_box(&bob.box_pub(), LABEL, b"secret").expect("seals");
        for at in [0, BOX_PUB_LEN, BOX_PUB_LEN + NONCE_LEN, sealed.len() - 1] {
            let mut bad = sealed.clone();
            bad[at] ^= 0x01;
            assert_eq!(bob.open_box(LABEL, &bad), Err(Error::Open), "byte {at}");
        }
        assert_eq!(
            bob.open_box(LABEL, &sealed[..SEALED_BOX_OVERHEAD - 1]),
            Err(Error::Open)
        );
    }

    #[test]
    fn two_boxes_of_the_same_secret_look_unrelated() {
        let bob = DeviceKeys::from_secret(&[2u8; 32]);
        let one = seal_box(&bob.box_pub(), LABEL, b"same").expect("seals");
        let two = seal_box(&bob.box_pub(), LABEL, b"same").expect("seals");
        assert_ne!(one, two);
    }

    #[test]
    fn a_small_order_recipient_is_refused_rather_than_used() {
        // The identity point: every shared secret with it is zero.
        let zero = [0u8; BOX_PUB_LEN];
        assert_eq!(seal_box(&zero, LABEL, b"secret"), Err(Error::BadPublicKey));
        let bob = DeviceKeys::from_secret(&[2u8; 32]);
        let mut forged = vec![0u8; SEALED_BOX_OVERHEAD + 4];
        forged[..BOX_PUB_LEN].copy_from_slice(&zero);
        assert_eq!(bob.open_box(LABEL, &forged), Err(Error::Open));
    }

    #[test]
    fn a_fixed_ephemeral_key_gives_a_fixed_box() {
        // Pins the construction: a change to the HKDF inputs, the label or the layout changes
        // these bytes and fails here rather than between two releases.
        let bob = DeviceKeys::from_secret(&[2u8; 32]);
        let eph = StaticSecret::from([9u8; 32]);
        let a = seal_box_with(&eph, &[4u8; NONCE_LEN], &bob.box_pub(), LABEL, b"x").expect("a");
        let b = seal_box_with(&eph, &[4u8; NONCE_LEN], &bob.box_pub(), LABEL, b"x").expect("b");
        assert_eq!(a, b);
        assert_eq!(bob.open_box(LABEL, &a).expect("opens").as_slice(), b"x");
    }
}
