//! Known answer tests against the frozen vectors in `testdata/vectors.json`.
//!
//! These are the tests that stop an accidental wire format change. Every label, length prefix,
//! field order and truncation length in the v1 suite is pinned here. If one of these fails and
//! the change was deliberate, it is a protocol version bump, not a fixture update.

use asli_crypto::{auth, clip, identity, kdf, token};
use serde_json::Value;

fn unhex(s: &str) -> Vec<u8> {
    assert!(s.len() % 2 == 0, "hex string must have an even length");
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("valid hex"))
        .collect()
}

fn array<const N: usize>(s: &str) -> [u8; N] {
    unhex(s)
        .try_into()
        .expect("hex decodes to the right length")
}

fn vectors() -> Value {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../testdata/vectors.json");
    let raw = std::fs::read_to_string(path).expect("testdata/vectors.json is present");
    serde_json::from_str(&raw).expect("testdata/vectors.json is valid JSON")
}

fn hex_field<'a>(v: &'a Value, key: &str) -> &'a str {
    v.get(key)
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("vector field {key} is missing"))
}

#[test]
fn key_hierarchy_matches_the_frozen_vectors() {
    let v = vectors();
    let secret: [u8; 32] = array(hex_field(&v, "secret"));
    let prk = kdf::Prk::extract(&secret);

    assert_eq!(unhex(hex_field(&v, "prk")), prk.as_bytes());
    assert_eq!(unhex(hex_field(&v, "sign_seed")), prk.sign_seed().as_ref());
    assert_eq!(
        unhex(hex_field(&v, "enc_key_epoch_0")),
        prk.enc_key(0).as_ref()
    );
    assert_eq!(
        unhex(hex_field(&v, "enc_key_epoch_1")),
        prk.enc_key(1).as_ref()
    );
}

#[test]
fn identity_matches_the_frozen_vectors() {
    let v = vectors();
    let secret: [u8; 32] = array(hex_field(&v, "secret"));
    let id = identity::Identity::from_secret(&secret);

    assert_eq!(unhex(hex_field(&v, "pub_key")), id.public_key());
    assert_eq!(unhex(hex_field(&v, "room_id_bytes")), id.room_id_bytes());
    assert_eq!(hex_field(&v, "room_id"), id.room_id());
    assert_eq!(v["suite"].as_str().unwrap(), asli_crypto::SUITE);
}

#[test]
fn join_token_matches_the_frozen_vector() {
    let v = vectors();
    let secret: [u8; 32] = array(hex_field(&v, "secret"));
    let expected = hex_field(&v, "join_token");

    assert_eq!(token::encode(&secret).as_str(), expected);
    assert_eq!(*token::parse(expected).expect("parses"), secret);
}

#[test]
fn clip_sealing_matches_the_frozen_vector() {
    let v = vectors();
    let secret: [u8; 32] = array(hex_field(&v, "secret"));
    let id = identity::Identity::from_secret(&secret);
    let c = &v["clip"];

    let msg_id: [u8; 16] = array(hex_field(c, "msg_id"));
    let device_id: [u8; 16] = array(hex_field(c, "device_id"));
    let nonce: [u8; 24] = array(hex_field(c, "nonce"));
    let epoch = u32::try_from(c["epoch"].as_u64().unwrap()).unwrap();

    // The associated data is a fixed byte string, so it is pinned exactly.
    let aad = clip::build_aad(
        clip::PROTOCOL_VERSION,
        clip::TYPE_CLIP,
        epoch,
        &id.room_id_bytes(),
        &msg_id,
    );
    assert_eq!(unhex(hex_field(c, "aad")), aad);
    assert_eq!(aad.len(), clip::AAD_LEN);

    let inner = clip::Inner {
        content_type: clip::ContentType::Text,
        device_id,
        seq: c["seq"].as_u64().unwrap(),
        ts_ms: c["ts_ms"].as_u64().unwrap(),
        content: c["content_utf8"].as_str().unwrap().as_bytes().to_vec(),
    };

    let plaintext = clip::encode_inner(&inner);
    assert_eq!(
        plaintext.len(),
        usize::try_from(c["padded_plaintext_len"].as_u64().unwrap()).unwrap(),
        "padding bucket changed"
    );

    // Sealing with the fixed nonce must reproduce the frozen ciphertext byte for byte.
    let sealed = clip::seal_with_nonce(
        &id.enc_key(epoch),
        epoch,
        &id.room_id_bytes(),
        &msg_id,
        &nonce,
        &plaintext,
    )
    .expect("seals");
    assert_eq!(unhex(hex_field(c, "ciphertext")), sealed);

    // And opening the frozen ciphertext must return the original fields.
    let opened = clip::open(
        &id.enc_key(epoch),
        epoch,
        &id.room_id_bytes(),
        &msg_id,
        &nonce,
        &sealed,
    )
    .expect("opens");
    assert_eq!(opened, inner);
}

#[test]
fn auth_handshake_matches_the_frozen_vector() {
    let v = vectors();
    let secret: [u8; 32] = array(hex_field(&v, "secret"));
    let id = identity::Identity::from_secret(&secret);
    let a = &v["auth"];

    let nonce_s: [u8; 32] = array(hex_field(a, "nonce_s"));
    let nonce_c: [u8; 16] = array(hex_field(a, "nonce_c"));
    let client_time_ms = a["client_time_ms"].as_u64().unwrap();

    let sig_input = auth::build_sig_input(
        clip::PROTOCOL_VERSION,
        &id.room_id_bytes(),
        &id.public_key(),
        &nonce_s,
        &nonce_c,
        client_time_ms,
    );
    assert_eq!(unhex(hex_field(a, "sig_input")), sig_input);
    assert_eq!(sig_input.len(), auth::SIG_INPUT_LEN);

    // Ed25519 is deterministic, so the signature is pinned too.
    let signature = auth::sign_auth(&id, &nonce_s, &nonce_c, client_time_ms);
    assert_eq!(unhex(hex_field(a, "signature")), signature);

    let frozen: [u8; 64] = array(hex_field(a, "signature"));
    assert!(auth::verify_auth(
        &id.room_id_bytes(),
        &id.public_key(),
        &nonce_s,
        &nonce_c,
        client_time_ms,
        &frozen
    )
    .is_ok());
}
