//! The relay handshake.
//!
//! The client proves it owns the account by signing a fresh server nonce. The relay stores only a
//! public key, so there is no stored credential that would let a compromised relay, a leaked log
//! line or a stolen backup join the room. This is the single most important difference from a
//! static shared token.
//!
//! The signed input is a fixed byte string, never JSON:
//!
//! ```text
//! sig_input = "asli/v1/auth" || u8(1) || u8(16) || room_id_bytes || u8(32) || pub_key
//!          || u8(32) || nonce_s || u8(16) || nonce_c || u64be(client_time_ms)
//! ```

use crate::error::Result;
use crate::identity::{
    verify_room_binding, verify_signature, Identity, PUB_KEY_LEN, ROOM_ID_LEN, SIGNATURE_LEN,
};

/// Domain separation label for the handshake signature.
pub const LABEL_AUTH: &[u8] = b"asli/v1/auth";
/// Length of the server challenge nonce in bytes.
pub const SERVER_NONCE_LEN: usize = 32;
/// Length of the client nonce in bytes.
pub const CLIENT_NONCE_LEN: usize = 16;
// Length prefixes written into the signed input, as `u8` constants so there is no runtime panic
// path. The compile time assertions keep them in step with the byte lengths they describe.
const ROOM_ID_LEN_U8: u8 = 16;
const PUB_KEY_LEN_U8: u8 = 32;
const SERVER_NONCE_LEN_U8: u8 = 32;
const CLIENT_NONCE_LEN_U8: u8 = 16;
const _: () = assert!(ROOM_ID_LEN_U8 as usize == ROOM_ID_LEN);
const _: () = assert!(PUB_KEY_LEN_U8 as usize == PUB_KEY_LEN);
const _: () = assert!(SERVER_NONCE_LEN_U8 as usize == SERVER_NONCE_LEN);
const _: () = assert!(CLIENT_NONCE_LEN_U8 as usize == CLIENT_NONCE_LEN);

/// Length of the signed input in bytes. Fixed in v1.
pub const SIG_INPUT_LEN: usize =
    12 + 1 + 1 + ROOM_ID_LEN + 1 + PUB_KEY_LEN + 1 + SERVER_NONCE_LEN + 1 + CLIENT_NONCE_LEN + 8;

/// Builds the exact bytes that get signed during the handshake.
#[must_use]
pub fn build_sig_input(
    version: u8,
    room_id_bytes: &[u8; ROOM_ID_LEN],
    public_key: &[u8; PUB_KEY_LEN],
    server_nonce: &[u8; SERVER_NONCE_LEN],
    client_nonce: &[u8; CLIENT_NONCE_LEN],
    client_time_ms: u64,
) -> [u8; SIG_INPUT_LEN] {
    let mut out = [0u8; SIG_INPUT_LEN];
    let mut at = 0;

    out[at..at + LABEL_AUTH.len()].copy_from_slice(LABEL_AUTH);
    at += LABEL_AUTH.len();

    out[at] = version;
    at += 1;

    out[at] = ROOM_ID_LEN_U8;
    at += 1;
    out[at..at + ROOM_ID_LEN].copy_from_slice(room_id_bytes);
    at += ROOM_ID_LEN;

    out[at] = PUB_KEY_LEN_U8;
    at += 1;
    out[at..at + PUB_KEY_LEN].copy_from_slice(public_key);
    at += PUB_KEY_LEN;

    out[at] = SERVER_NONCE_LEN_U8;
    at += 1;
    out[at..at + SERVER_NONCE_LEN].copy_from_slice(server_nonce);
    at += SERVER_NONCE_LEN;

    out[at] = CLIENT_NONCE_LEN_U8;
    at += 1;
    out[at..at + CLIENT_NONCE_LEN].copy_from_slice(client_nonce);
    at += CLIENT_NONCE_LEN;

    out[at..at + 8].copy_from_slice(&client_time_ms.to_be_bytes());
    at += 8;

    debug_assert_eq!(at, SIG_INPUT_LEN);
    out
}

/// Signs the handshake as the client.
#[must_use]
pub fn sign_auth(
    identity: &Identity,
    server_nonce: &[u8; SERVER_NONCE_LEN],
    client_nonce: &[u8; CLIENT_NONCE_LEN],
    client_time_ms: u64,
) -> [u8; SIGNATURE_LEN] {
    let input = build_sig_input(
        crate::clip::PROTOCOL_VERSION,
        &identity.room_id_bytes(),
        &identity.public_key(),
        server_nonce,
        client_nonce,
        client_time_ms,
    );
    identity.sign(&input)
}

/// Verifies the handshake as the relay would.
///
/// The caller is responsible for the two checks that need server state: that `server_nonce` was
/// the nonce issued to this connection, and that it has not already been used. Both must be
/// enforced, and the nonce must be invalidated on use whether verification succeeds or fails.
///
/// `client_time_ms` is advisory. It must never drive a security decision on the server; it exists
/// so that gross clock skew is diagnosable.
///
/// # Errors
///
/// Returns [`crate::Error::RoomBinding`] if the room id is not the hash of the public key, or
/// [`crate::Error::BadSignature`] if the signature does not verify.
pub fn verify_auth(
    room_id_bytes: &[u8; ROOM_ID_LEN],
    public_key: &[u8; PUB_KEY_LEN],
    server_nonce: &[u8; SERVER_NONCE_LEN],
    client_nonce: &[u8; CLIENT_NONCE_LEN],
    client_time_ms: u64,
    signature: &[u8; SIGNATURE_LEN],
) -> Result<()> {
    verify_room_binding(room_id_bytes, public_key)?;
    let input = build_sig_input(
        crate::clip::PROTOCOL_VERSION,
        room_id_bytes,
        public_key,
        server_nonce,
        client_nonce,
        client_time_ms,
    );
    verify_signature(public_key, &input, signature)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::Error;

    const TEST_SECRET: [u8; 32] = [5u8; 32];
    const NONCE_S: [u8; SERVER_NONCE_LEN] = [0xaa; SERVER_NONCE_LEN];
    const NONCE_C: [u8; CLIENT_NONCE_LEN] = [0xbb; CLIENT_NONCE_LEN];
    const NOW: u64 = 1_767_225_600_000;

    fn identity() -> Identity {
        Identity::from_secret(&TEST_SECRET)
    }

    #[test]
    fn handshake_round_trips() {
        let id = identity();
        let sig = sign_auth(&id, &NONCE_S, &NONCE_C, NOW);
        assert!(verify_auth(
            &id.room_id_bytes(),
            &id.public_key(),
            &NONCE_S,
            &NONCE_C,
            NOW,
            &sig
        )
        .is_ok());
    }

    #[test]
    fn sig_input_has_the_documented_length() {
        let id = identity();
        let input = build_sig_input(
            1,
            &id.room_id_bytes(),
            &id.public_key(),
            &NONCE_S,
            &NONCE_C,
            NOW,
        );
        assert_eq!(input.len(), 121);
        assert!(input.starts_with(LABEL_AUTH));
    }

    #[test]
    fn a_signature_for_another_server_nonce_fails() {
        let id = identity();
        let sig = sign_auth(&id, &NONCE_S, &NONCE_C, NOW);
        let other = [0xcc; SERVER_NONCE_LEN];
        assert_eq!(
            verify_auth(
                &id.room_id_bytes(),
                &id.public_key(),
                &other,
                &NONCE_C,
                NOW,
                &sig
            ),
            Err(Error::BadSignature)
        );
    }

    #[test]
    fn a_signature_for_another_time_fails() {
        let id = identity();
        let sig = sign_auth(&id, &NONCE_S, &NONCE_C, NOW);
        assert_eq!(
            verify_auth(
                &id.room_id_bytes(),
                &id.public_key(),
                &NONCE_S,
                &NONCE_C,
                NOW + 1,
                &sig
            ),
            Err(Error::BadSignature)
        );
    }

    #[test]
    fn a_mismatched_room_id_fails_before_signature_checking() {
        let id = identity();
        let sig = sign_auth(&id, &NONCE_S, &NONCE_C, NOW);
        let wrong_room = [0u8; ROOM_ID_LEN];
        assert_eq!(
            verify_auth(&wrong_room, &id.public_key(), &NONCE_S, &NONCE_C, NOW, &sig),
            Err(Error::RoomBinding)
        );
    }

    #[test]
    fn another_accounts_signature_fails() {
        let id = identity();
        let other = Identity::from_secret(&[6u8; 32]);
        let sig = sign_auth(&other, &NONCE_S, &NONCE_C, NOW);
        assert_eq!(
            verify_auth(
                &id.room_id_bytes(),
                &id.public_key(),
                &NONCE_S,
                &NONCE_C,
                NOW,
                &sig
            ),
            Err(Error::BadSignature)
        );
    }
}
