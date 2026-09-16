//! Regenerates `testdata/vectors.json`, the frozen known answer vectors.
//!
//! Run from the repository root:
//!
//! ```sh
//! cargo run -p asli-crypto --example gen_vectors > testdata/vectors.json
//! ```
//!
//! Regenerating is a deliberate act. These vectors exist so that a change to a label, a length
//! prefix, a field order or a truncation length breaks the test suite loudly. If this file's
//! output changes, the wire format changed, and that is a protocol version bump.

use asli_crypto::{auth, clip, identity, kdf, token};

const SECRET: [u8; 32] = [
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
];
const MSG_ID: [u8; 16] = [
    0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf,
];
const DEVICE_ID: [u8; 16] = [
    0xd0, 0xd1, 0xd2, 0xd3, 0xd4, 0xd5, 0xd6, 0xd7, 0xd8, 0xd9, 0xda, 0xdb, 0xdc, 0xdd, 0xde, 0xdf,
];
const NONCE: [u8; 24] = [
    0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f,
    0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57,
];
const NONCE_S: [u8; 32] = [
    0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e, 0x6f,
    0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7a, 0x7b, 0x7c, 0x7d, 0x7e, 0x7f,
];
const NONCE_C: [u8; 16] = [
    0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f,
];
const SEQ: u64 = 7;
const TS_MS: u64 = 1_767_225_600_000;
const CLIENT_TIME_MS: u64 = 1_767_225_600_123;
const CONTENT: &[u8] = b"asli known answer vector";

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes
        .iter()
        .fold(String::with_capacity(bytes.len() * 2), |mut acc, byte| {
            let _ = write!(acc, "{byte:02x}");
            acc
        })
}

fn main() {
    let id = identity::Identity::from_secret(&SECRET);
    let prk = kdf::Prk::extract(&SECRET);

    let inner = clip::Inner {
        content_type: clip::ContentType::Text,
        device_id: DEVICE_ID,
        seq: SEQ,
        ts_ms: TS_MS,
        content: CONTENT.to_vec(),
    };
    let plaintext = clip::encode_inner(&inner);
    let aad = clip::build_aad(
        clip::PROTOCOL_VERSION,
        clip::TYPE_CLIP,
        0,
        &id.room_id_bytes(),
        &MSG_ID,
    );
    let ciphertext = clip::seal_with_nonce(
        &id.enc_key(0),
        0,
        &id.room_id_bytes(),
        &MSG_ID,
        &NONCE,
        &plaintext,
    )
    .expect("sealing the fixed vector cannot fail");

    let sig_input = auth::build_sig_input(
        clip::PROTOCOL_VERSION,
        &id.room_id_bytes(),
        &id.public_key(),
        &NONCE_S,
        &NONCE_C,
        CLIENT_TIME_MS,
    );
    let signature = auth::sign_auth(&id, &NONCE_S, &NONCE_C, CLIENT_TIME_MS);

    println!("{{");
    println!("  \"comment\": \"Frozen known answer vectors for the asli-v1 suite. Regenerate only when the wire format is deliberately changed, which is a protocol version bump. See docs/PROTOCOL.md.\",");
    println!("  \"suite\": \"{}\",", asli_crypto::SUITE);
    println!("  \"protocol_version\": {},", clip::PROTOCOL_VERSION);
    println!("  \"secret\": \"{}\",", hex(&SECRET));
    println!("  \"prk\": \"{}\",", hex(prk.as_bytes()));
    println!("  \"sign_seed\": \"{}\",", hex(prk.sign_seed().as_ref()));
    println!("  \"pub_key\": \"{}\",", hex(&id.public_key()));
    println!("  \"room_id_bytes\": \"{}\",", hex(&id.room_id_bytes()));
    println!("  \"room_id\": \"{}\",", id.room_id());
    println!(
        "  \"enc_key_epoch_0\": \"{}\",",
        hex(prk.enc_key(0).as_ref())
    );
    println!(
        "  \"enc_key_epoch_1\": \"{}\",",
        hex(prk.enc_key(1).as_ref())
    );
    println!("  \"join_token\": \"{}\",", token::encode(&SECRET).as_str());
    println!("  \"clip\": {{");
    println!("    \"epoch\": 0,");
    println!("    \"msg_id\": \"{}\",", hex(&MSG_ID));
    println!("    \"device_id\": \"{}\",", hex(&DEVICE_ID));
    println!("    \"seq\": {SEQ},");
    println!("    \"ts_ms\": {TS_MS},");
    println!(
        "    \"content_utf8\": \"{}\",",
        String::from_utf8_lossy(CONTENT)
    );
    println!("    \"nonce\": \"{}\",", hex(&NONCE));
    println!("    \"aad\": \"{}\",", hex(&aad));
    println!("    \"padded_plaintext_len\": {},", plaintext.len());
    println!("    \"ciphertext\": \"{}\"", hex(&ciphertext));
    println!("  }},");
    println!("  \"auth\": {{");
    println!("    \"nonce_s\": \"{}\",", hex(&NONCE_S));
    println!("    \"nonce_c\": \"{}\",", hex(&NONCE_C));
    println!("    \"client_time_ms\": {CLIENT_TIME_MS},");
    println!("    \"sig_input\": \"{}\",", hex(&sig_input));
    println!("    \"signature\": \"{}\"", hex(&signature));
    println!("  }}");
    println!("}}");
}
