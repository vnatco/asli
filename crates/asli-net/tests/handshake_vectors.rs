//! The handshake, checked against the frozen vectors.
//!
//! `testdata/vectors.json` pins the exact bytes of `sig_input` and the signature over it. This
//! test drives a real [`Session`] through a challenge carrying the frozen `nonce_s`, with the
//! client's nonce and timestamp pinned to the frozen values, and asserts the signature it produces
//! matches byte for byte.
//!
//! That makes it a cross implementation check, not just a regression test: the relay verifies the
//! same signature over the same reconstructed input, so if this test passes and the relay's
//! equivalent test passes, the Rust and Node sides agree about the wire format.

use asli_crypto::Identity;
use asli_net::envelope::{encode_b64, Message};
use asli_net::session::{Action, Session};

fn unhex(text: &str) -> Vec<u8> {
    assert!(text.len() % 2 == 0, "hex must have an even length");
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).expect("valid hex"))
        .collect()
}

fn vectors() -> serde_json::Value {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../testdata/vectors.json");
    let raw = std::fs::read_to_string(path).expect("testdata/vectors.json is present");
    serde_json::from_str(&raw).expect("vectors parse")
}

fn field<'a>(value: &'a serde_json::Value, key: &str) -> &'a str {
    value
        .get(key)
        .and_then(serde_json::Value::as_str)
        .unwrap_or_else(|| panic!("vector field {key} is missing"))
}

#[test]
fn the_client_reproduces_the_frozen_handshake() {
    let v = vectors();
    let auth_vector = &v["auth"];

    let secret: [u8; 32] = unhex(field(&v, "secret"))
        .try_into()
        .expect("32 byte secret");
    let nonce_s: [u8; 32] = unhex(field(auth_vector, "nonce_s"))
        .try_into()
        .expect("32 byte server nonce");
    let nonce_c: [u8; 16] = unhex(field(auth_vector, "nonce_c"))
        .try_into()
        .expect("16 byte client nonce");
    let client_time_ms = auth_vector["client_time_ms"]
        .as_u64()
        .expect("client_time_ms");

    let identity = Identity::from_secret(&secret);
    // The room id and public key are what the relay routes and verifies on, so pin them too.
    assert_eq!(identity.room_id(), field(&v, "room_id"));
    assert_eq!(identity.public_key().to_vec(), unhex(field(&v, "pub_key")));

    let mut session = Session::new(identity, [0xd0; 16], 0);
    session.pin_auth_inputs(nonce_c, client_time_ms);

    let hello = session.hello_frame().expect("hello");
    assert!(matches!(
        Message::parse(&hello).expect("hello parses"),
        Message::Hello(_)
    ));

    let challenge = format!(
        r#"{{"v":1,"type":"challenge","suite":"asli-v1","enc":"json","nonce_s":"{}","server_time_ms":1789459200000,"limits":{{"max_frame_bytes":1048576,"max_content_bytes":716800,"retain_max_bytes":65536,"msgs_per_sec":2,"room_bytes_per_day":52428800}}}}"#,
        encode_b64(&nonce_s)
    );

    let actions = session
        .handle_frame(&challenge, client_time_ms)
        .expect("challenge is accepted");
    let [Action::Send(auth_frame)] = actions.as_slice() else {
        panic!("a challenge must produce exactly one auth frame, got {actions:?}");
    };

    let Message::Auth(auth) = Message::parse(auth_frame).expect("auth parses") else {
        panic!("the reply to a challenge must be auth");
    };

    assert_eq!(auth.room, field(&v, "room_id"));
    assert_eq!(auth.pub_key, unhex(field(&v, "pub_key")));
    assert_eq!(auth.nonce_c, nonce_c.to_vec());
    assert_eq!(auth.client_time_ms, client_time_ms);
    assert_eq!(
        auth.sig,
        unhex(field(auth_vector, "signature")),
        "the signature must match the frozen vector byte for byte"
    );
}

#[test]
fn a_different_client_nonce_produces_a_different_signature() {
    // Guards against a signature that accidentally ignores one of its inputs, which would still
    // pass the vector test above if the ignored field happened to be constant there.
    let v = vectors();
    let auth_vector = &v["auth"];

    let secret: [u8; 32] = unhex(field(&v, "secret")).try_into().unwrap();
    let nonce_s: [u8; 32] = unhex(field(auth_vector, "nonce_s")).try_into().unwrap();
    let client_time_ms = auth_vector["client_time_ms"].as_u64().unwrap();

    let challenge = format!(
        r#"{{"v":1,"type":"challenge","suite":"asli-v1","enc":"json","nonce_s":"{}","server_time_ms":1,"limits":{{"max_frame_bytes":1048576,"max_content_bytes":716800,"retain_max_bytes":65536,"msgs_per_sec":2,"room_bytes_per_day":52428800}}}}"#,
        encode_b64(&nonce_s)
    );

    let mut signatures = Vec::new();
    for nonce_c in [[0x80u8; 16], [0x81u8; 16]] {
        let mut session = Session::new(Identity::from_secret(&secret), [0xd0; 16], 0);
        session.pin_auth_inputs(nonce_c, client_time_ms);
        session.hello_frame().unwrap();
        let actions = session.handle_frame(&challenge, client_time_ms).unwrap();
        let [Action::Send(frame)] = actions.as_slice() else {
            panic!("expected one auth frame")
        };
        let Message::Auth(auth) = Message::parse(frame).unwrap() else {
            panic!("expected auth")
        };
        signatures.push(auth.sig);
    }

    assert_ne!(
        signatures[0], signatures[1],
        "the client nonce must be covered by the signature"
    );
}
