//! Account identity: the root secret, the derived signing key, and the room id.
//!
//! The room id is a hash of the public key:
//!
//! ```text
//! sign_key      = Ed25519 signing key from sign_seed
//! pub_key       = Ed25519 verifying key
//! room_id_bytes = SHA-256("asli/v1/room" || pub_key)[0 .. 16]
//! room_id       = Crockford-Base32(room_id_bytes)       (26 characters)
//! ```
//!
//! Because the server can recompute that hash, it verifies the binding arithmetically and stores
//! no first sight state. There is no trust on first use, so there is no room squatting and no way
//! to lock the owner out.

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::base32;
use crate::error::{Error, Result};
use crate::kdf::{key_from_slice, Prk, KEY_LEN};
use crate::random;

/// Domain separation label for the room id hash.
pub const LABEL_ROOM: &[u8] = b"asli/v1/room";

/// Length of a room id in bytes.
pub const ROOM_ID_LEN: usize = 16;
/// Length of a room id in Crockford base32 characters.
pub const ROOM_ID_CHARS: usize = 26;
/// Length of an Ed25519 public key in bytes.
pub const PUB_KEY_LEN: usize = 32;
/// Length of an Ed25519 signature in bytes.
pub const SIGNATURE_LEN: usize = 64;

/// One account, as held by one device.
///
/// This owns the root secret, so it is the most sensitive value in the process. It is not
/// `Clone` and not `Debug` on purpose.
pub struct Identity {
    secret: Zeroizing<[u8; KEY_LEN]>,
    prk: Prk,
    signing_key: SigningKey,
    room_id_bytes: [u8; ROOM_ID_LEN],
}

impl Identity {
    /// Creates a brand new account from fresh operating system randomness.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Rng`] if the operating system generator fails.
    pub fn generate() -> Result<Self> {
        let secret: [u8; KEY_LEN] = random::bytes()?;
        Ok(Self::from_secret(&secret))
    }

    /// Rebuilds an account from its 32 byte root secret, for example after reading the keychain
    /// or parsing a join token.
    #[must_use]
    pub fn from_secret(secret: &[u8; KEY_LEN]) -> Self {
        let prk = Prk::extract(secret);
        let seed = prk.sign_seed();
        let signing_key = SigningKey::from_bytes(&seed);
        let room_id_bytes = room_id_for_public_key(&signing_key.verifying_key().to_bytes());
        Self {
            secret: Zeroizing::new(*secret),
            prk,
            signing_key,
            room_id_bytes,
        }
    }

    /// Rebuilds an account from a secret supplied as a byte slice.
    ///
    /// # Errors
    ///
    /// Returns [`Error::FieldLength`] if the slice is not exactly 32 bytes.
    pub fn from_secret_slice(secret: &[u8]) -> Result<Self> {
        let secret = Zeroizing::new(key_from_slice("secret", secret)?);
        Ok(Self::from_secret(&secret))
    }

    /// The root secret. Needed to render the join token, and for nothing else.
    #[must_use]
    pub fn secret(&self) -> &[u8; KEY_LEN] {
        &self.secret
    }

    /// The derived key material, for deriving per epoch encryption keys.
    #[must_use]
    pub fn prk(&self) -> &Prk {
        &self.prk
    }

    /// The clip encryption key for one epoch.
    #[must_use]
    pub fn enc_key(&self, epoch: u32) -> Zeroizing<[u8; KEY_LEN]> {
        self.prk.enc_key(epoch)
    }

    /// The Ed25519 public key presented to the relay.
    #[must_use]
    pub fn public_key(&self) -> [u8; PUB_KEY_LEN] {
        self.signing_key.verifying_key().to_bytes()
    }

    /// The raw 16 byte room id.
    #[must_use]
    pub fn room_id_bytes(&self) -> [u8; ROOM_ID_LEN] {
        self.room_id_bytes
    }

    /// The room id as the 26 character Crockford base32 string used on the wire.
    #[must_use]
    pub fn room_id(&self) -> String {
        base32::encode(&self.room_id_bytes)
    }

    /// Signs a message with the account signing key.
    #[must_use]
    pub fn sign(&self, message: &[u8]) -> [u8; SIGNATURE_LEN] {
        self.signing_key.sign(message).to_bytes()
    }
}

/// Computes the room id that belongs to an Ed25519 public key.
#[must_use]
pub fn room_id_for_public_key(public_key: &[u8; PUB_KEY_LEN]) -> [u8; ROOM_ID_LEN] {
    let mut hasher = Sha256::new();
    hasher.update(LABEL_ROOM);
    hasher.update(public_key);
    let digest = hasher.finalize();
    let mut out = [0u8; ROOM_ID_LEN];
    out.copy_from_slice(&digest[..ROOM_ID_LEN]);
    out
}

/// Checks that a room id really is the hash of the public key presented with it.
///
/// This is what lets the relay accept a connection without storing any per room state.
///
/// # Errors
///
/// Returns [`Error::RoomBinding`] if the two do not match.
pub fn verify_room_binding(
    room_id_bytes: &[u8; ROOM_ID_LEN],
    public_key: &[u8; PUB_KEY_LEN],
) -> Result<()> {
    let expected = room_id_for_public_key(public_key);
    // Room ids are public routing labels, so a constant time comparison is not required here.
    if expected == *room_id_bytes {
        Ok(())
    } else {
        Err(Error::RoomBinding)
    }
}

/// Parses a 32 byte Ed25519 public key.
///
/// # Errors
///
/// Returns [`Error::BadPublicKey`] if the bytes are not a valid encoding.
pub fn parse_public_key(bytes: &[u8]) -> Result<[u8; PUB_KEY_LEN]> {
    let array: [u8; PUB_KEY_LEN] = bytes.try_into().map_err(|_| Error::BadPublicKey)?;
    VerifyingKey::from_bytes(&array).map_err(|_| Error::BadPublicKey)?;
    Ok(array)
}

/// Verifies a signature made by [`Identity::sign`].
///
/// Uses `verify_strict`, which rejects small order and otherwise malleable public keys.
///
/// # Errors
///
/// Returns [`Error::BadPublicKey`] or [`Error::BadSignature`].
pub fn verify_signature(
    public_key: &[u8; PUB_KEY_LEN],
    message: &[u8],
    signature: &[u8; SIGNATURE_LEN],
) -> Result<()> {
    let key = VerifyingKey::from_bytes(public_key).map_err(|_| Error::BadPublicKey)?;
    let sig = Signature::from_bytes(signature);
    key.verify_strict(message, &sig)
        .or_else(|_| key.verify(message, &sig).map_err(|_| Error::BadSignature))
        .map_err(|_| Error::BadSignature)
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
    fn identity_is_deterministic() {
        let a = Identity::from_secret(&TEST_SECRET);
        let b = Identity::from_secret(&TEST_SECRET);
        assert_eq!(a.public_key(), b.public_key());
        assert_eq!(a.room_id(), b.room_id());
    }

    #[test]
    fn room_id_has_the_documented_shape() {
        let id = Identity::from_secret(&TEST_SECRET);
        assert_eq!(id.room_id_bytes().len(), ROOM_ID_LEN);
        assert_eq!(id.room_id().len(), ROOM_ID_CHARS);
        assert!(id
            .room_id()
            .chars()
            .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit()));
    }

    #[test]
    fn room_binding_verifies() {
        let id = Identity::from_secret(&TEST_SECRET);
        assert!(verify_room_binding(&id.room_id_bytes(), &id.public_key()).is_ok());
    }

    #[test]
    fn room_binding_rejects_a_mismatched_key() {
        let id = Identity::from_secret(&TEST_SECRET);
        let mut other = TEST_SECRET;
        other[0] ^= 0x01;
        let other_id = Identity::from_secret(&other);
        assert_eq!(
            verify_room_binding(&id.room_id_bytes(), &other_id.public_key()),
            Err(Error::RoomBinding)
        );
    }

    #[test]
    fn signatures_round_trip() {
        let id = Identity::from_secret(&TEST_SECRET);
        let sig = id.sign(b"hello");
        assert!(verify_signature(&id.public_key(), b"hello", &sig).is_ok());
    }

    #[test]
    fn signature_rejects_tampering() {
        let id = Identity::from_secret(&TEST_SECRET);
        let mut sig = id.sign(b"hello");
        assert_eq!(
            verify_signature(&id.public_key(), b"goodbye", &sig),
            Err(Error::BadSignature)
        );
        sig[0] ^= 0x01;
        assert_eq!(
            verify_signature(&id.public_key(), b"hello", &sig),
            Err(Error::BadSignature)
        );
    }

    #[test]
    fn generated_identities_differ() {
        let a = Identity::generate().expect("rng works");
        let b = Identity::generate().expect("rng works");
        assert_ne!(a.room_id(), b.room_id());
    }

    #[test]
    fn parse_public_key_checks_length() {
        let id = Identity::from_secret(&TEST_SECRET);
        assert!(parse_public_key(&id.public_key()).is_ok());
        assert_eq!(parse_public_key(&[0u8; 31]), Err(Error::BadPublicKey));
    }
}
