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

use asli_crypto::chunk::{self, ChunkPos};
use asli_crypto::{announce, auth, clip, identity, kdf, token};

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

/// Fixed message id for the chunked vector, distinct from the single clip one.
const CHUNK_MSG_ID: [u8; 16] = [
    0xb0, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7, 0xb8, 0xb9, 0xba, 0xbb, 0xbc, 0xbd, 0xbe, 0xbf,
];
/// Four fixed nonces, so the whole chunked vector is reproducible.
///
/// Four rather than three on purpose: the payload pads to 512 bytes and splits at 128, which
/// yields `clip_begin`, two `clip_chunk` middles and `clip_end`, so every type code is covered and
/// interior is genuinely interior.
const CHUNK_NONCES: [[u8; 24]; 4] = [
    [
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e,
        0x1f, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
    ],
    [
        0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e,
        0x3f, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,
    ],
    [
        0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5a, 0x5b, 0x5c, 0x5d, 0x5e,
        0x5f, 0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67,
    ],
    [
        0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7a, 0x7b, 0x7c, 0x7d, 0x7e,
        0x7f, 0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87,
    ],
];
/// Small enough that a short image splits into exactly three chunks.
const CHUNK_BYTES: usize = 128;
/// Fixed image payload for the chunked vector. Not a real PNG: the crypto layer never parses it.
fn chunk_image() -> Vec<u8> {
    (0..300u32)
        .map(|i| u8::try_from(i % 251).unwrap_or(0))
        .collect()
}

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

    emit_chunked(&id);
    emit_announce(&id);

    println!("  \"auth\": {{");
    println!("    \"nonce_s\": \"{}\",", hex(&NONCE_S));
    println!("    \"nonce_c\": \"{}\",", hex(&NONCE_C));
    println!("    \"client_time_ms\": {CLIENT_TIME_MS},");
    println!("    \"sig_input\": \"{}\",", hex(&sig_input));
    println!("    \"signature\": \"{}\"", hex(&signature));
    println!("  }}");
    println!("}}");
}

/// Emits the chunked transfer vector.
///
/// Split out because it is a different job from the single clip vectors, and because `main` is
/// past the line limit with it inline.
fn emit_chunked(id: &identity::Identity) {
    // Chunked transfer. Sealed with fixed nonces so the whole stream is reproducible, which is
    // what makes a reordering or truncation regression break the suite rather than pass quietly.
    let chunk_inner = clip::Inner {
        content_type: clip::ContentType::ImagePng,
        device_id: DEVICE_ID,
        seq: SEQ,
        ts_ms: TS_MS,
        content: chunk_image(),
    };
    let chunk_plaintext = clip::encode_inner(&chunk_inner);
    let chunk_count = chunk::chunk_count_for(chunk_plaintext.len(), CHUNK_BYTES);

    println!("  \"chunked\": {{");
    println!("    \"epoch\": 0,");
    println!("    \"msg_id\": \"{}\",", hex(&CHUNK_MSG_ID));
    println!("    \"device_id\": \"{}\",", hex(&DEVICE_ID));
    println!("    \"seq\": {SEQ},");
    println!("    \"ts_ms\": {TS_MS},");
    println!("    \"content_type\": 2,");
    println!("    \"content\": \"{}\",", hex(&chunk_image()));
    println!("    \"chunk_bytes\": {CHUNK_BYTES},");
    println!("    \"chunk_count\": {chunk_count},");
    println!("    \"padded_plaintext_len\": {},", chunk_plaintext.len());
    println!("    \"chunks\": [");

    let pieces: Vec<&[u8]> = chunk_plaintext.chunks(CHUNK_BYTES).collect();
    assert_eq!(
        pieces.len(),
        CHUNK_NONCES.len(),
        "the fixed nonce table must match the chunk count"
    );
    for (index, piece) in pieces.iter().enumerate() {
        let idx = u32::try_from(index).expect("index fits");
        let pos = ChunkPos {
            idx,
            chunk_count,
            final_chunk: idx + 1 == chunk_count,
        };
        let nonce = CHUNK_NONCES[index];
        let aad = chunk::build_chunk_aad(
            chunk::PROTOCOL_VERSION,
            pos.type_code(),
            0,
            &id.room_id_bytes(),
            &CHUNK_MSG_ID,
            pos,
        );
        let ciphertext = chunk::seal_chunk_with_nonce(
            &id.enc_key(0),
            0,
            &id.room_id_bytes(),
            &CHUNK_MSG_ID,
            &nonce,
            pos,
            piece,
        )
        .expect("sealing the fixed chunk cannot fail");
        let comma = if index + 1 == pieces.len() { "" } else { "," };
        println!("      {{");
        println!("        \"idx\": {idx},");
        println!("        \"final\": {},", pos.final_chunk);
        println!("        \"type_code\": {},", pos.type_code());
        println!("        \"nonce\": \"{}\",", hex(&nonce));
        println!("        \"aad\": \"{}\",", hex(&aad));
        println!("        \"ciphertext\": \"{}\"", hex(&ciphertext));
        println!("      }}{comma}");
    }
    println!("    ]");
    println!("  }},");
}

/// Fixed message id for the announcement vector, distinct from the clip and chunked ones.
const ANNOUNCE_MSG_ID: [u8; 16] = [
    0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7, 0xc8, 0xc9, 0xca, 0xcb, 0xcc, 0xcd, 0xce, 0xcf,
];
/// Fixed nonce for the announcement vector.
const ANNOUNCE_NONCE: [u8; 24] = [
    0xe0, 0xe1, 0xe2, 0xe3, 0xe4, 0xe5, 0xe6, 0xe7, 0xe8, 0xe9, 0xea, 0xeb, 0xec, 0xed, 0xee, 0xef,
    0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7,
];

/// Emits the device announcement vector.
fn emit_announce(id: &identity::Identity) {
    let inner = announce::Announce {
        device_id: DEVICE_ID,
        ts_ms: TS_MS,
        name: "ThinkPad X1".to_owned(),
        os: "Windows 11".to_owned(),
    };
    let plaintext = announce::encode(&inner).expect("the fixed fields fit");
    let aad = clip::build_aad(
        clip::PROTOCOL_VERSION,
        announce::TYPE_ANNOUNCE,
        0,
        &id.room_id_bytes(),
        &ANNOUNCE_MSG_ID,
    );
    let ciphertext = announce::seal_with_nonce(
        &id.enc_key(0),
        0,
        &id.room_id_bytes(),
        &ANNOUNCE_MSG_ID,
        &ANNOUNCE_NONCE,
        &inner,
    )
    .expect("sealing the fixed announcement cannot fail");

    println!("  \"announce\": {{");
    println!("    \"epoch\": 0,");
    println!("    \"msg_id\": \"{}\",", hex(&ANNOUNCE_MSG_ID));
    println!("    \"device_id\": \"{}\",", hex(&DEVICE_ID));
    println!("    \"ts_ms\": {TS_MS},");
    println!("    \"name\": \"{}\",", inner.name);
    println!("    \"os\": \"{}\",", inner.os);
    println!("    \"nonce\": \"{}\",", hex(&ANNOUNCE_NONCE));
    println!("    \"aad\": \"{}\",", hex(&aad));
    println!("    \"plaintext\": \"{}\",", hex(&plaintext));
    println!("    \"ciphertext\": \"{}\"", hex(&ciphertext));
    println!("  }},");
}
