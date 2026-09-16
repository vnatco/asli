//! An externally checkable proof that the history file never holds plaintext and that a purge
//! leaves nothing behind.
//!
//! The in-crate unit tests assert both of these, but a test asserting its own correctness is a
//! weaker claim than bytes on disk that anything can inspect. So this writes its artefacts to a
//! directory the shell can grep afterwards:
//!
//! ```text
//! $ASLI_HISTORY_PROOF_DIR/
//!   history.bin        the live store, while populated
//!   evidence.bin       a byte for byte copy of it, kept after the purge
//! ```
//!
//! The copy matters. `clear` unlinks the file, so grepping after a purge would find nothing
//! whether or not the contents were ever encrypted, which proves only that deletion deletes. The
//! copy is what shows the file held ciphertext the whole time it existed.
//!
//! Run with the directory set, then grep it:
//!
//! ```sh
//! ASLI_HISTORY_PROOF_DIR=/tmp/proof cargo test -p asli-history --test purge_proof -- --nocapture
//! grep -c 'the-canary' /tmp/proof/evidence.bin
//! ```

use std::fs;
use std::path::PathBuf;

use asli_history::{Content, Limits, Store};

/// The string searched for afterwards. Distinctive enough that a hit cannot be a coincidence.
const CANARY: &str = "CANARY-PLAINTEXT-MUST-NOT-APPEAR-ON-DISK";

/// A second canary inside an image entry, so the proof covers both content types.
const IMAGE_CANARY: &[u8] = b"CANARY-IMAGE-BYTES-MUST-NOT-APPEAR";

#[test]
fn purge_leaves_no_plaintext_anywhere() {
    let dir: PathBuf = std::env::var("ASLI_HISTORY_PROOF_DIR").map_or_else(
        |_| std::env::temp_dir().join(format!("asli-purge-proof-{}", std::process::id())),
        PathBuf::from,
    );
    fs::create_dir_all(&dir).expect("proof directory");

    let path = dir.join("history.bin");
    let evidence = dir.join("evidence.bin");
    let _ = fs::remove_file(&path);
    let _ = fs::remove_file(&evidence);

    let secret = [0x5au8; 32];
    let mut store = Store::open(&path, &secret, Limits::default()).expect("opens");

    store
        .append(Content::Text(CANARY.to_owned()), false, 1_767_225_600_000)
        .expect("appends text");

    let mut png = b"\x89PNG\r\n\x1a\n".to_vec();
    png.extend_from_slice(IMAGE_CANARY);
    store
        .append(Content::ImagePng(png), false, 1_767_225_600_001)
        .expect("appends image");

    // A secret that is refused outright, to show it leaves no trace even before encryption.
    store
        .append(
            Content::Text(format!("{CANARY}-SENSITIVE")),
            true,
            1_767_225_600_002,
        )
        .expect("refuses");

    assert_eq!(store.len(), 2, "only the two non sensitive entries persist");
    assert!(path.exists(), "the store file should exist while populated");

    // Keep a copy of the live file, so the grep afterwards inspects what was actually on disk.
    fs::copy(&path, &evidence).expect("copies the live file aside");

    let live = fs::read(&evidence).expect("reads the evidence");
    assert!(
        !contains(&live, CANARY.as_bytes()),
        "the live file held the text canary in plaintext"
    );
    assert!(
        !contains(&live, IMAGE_CANARY),
        "the live file held the image canary in plaintext"
    );

    store.clear().expect("purges");

    assert!(!path.exists(), "the store file survived the purge");
    assert!(store.is_empty(), "entries survived the purge in memory");

    println!("proof directory: {}", dir.display());
    println!("evidence file:   {} bytes", live.len());
    println!("store file after purge: {}", path.exists());
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|w| w == needle)
}
