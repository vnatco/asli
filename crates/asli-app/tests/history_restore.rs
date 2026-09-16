//! The path behind clicking an entry in the History screen.
//!
//! # Why this exists
//!
//! The screen's promise is "click an entry and it goes back on the clipboard of every device".
//! That is four steps: the daemon records a clip, the screen lists what was recorded, the click
//! resolves a row index back to content, and the content is written to the clipboard. Every one
//! of those is a place where the wrong entry, or no entry, could come back.
//!
//! The window cannot be driven from a test: it needs an event loop and a display. So this drives
//! the two pieces underneath it, the real encrypted store and a clipboard that records instead of
//! writing, through exactly the sequence the click performs.
//!
//! Nothing here touches the real clipboard, the real configuration directory or the real keyring.
//! A test that wrote to the system clipboard would destroy whatever the person running it had
//! copied, which is a rude way to prove a point about clipboards.

use std::fs;
use std::path::PathBuf;

use asli_app::clipboard_io::{ClipboardIo as _, StubClipboard};
use asli_app::config::{Config, Paths};
use asli_app::history_store;
use asli_app::window::{HistoryContent, HistorySource as _};

/// A configuration directory of this test's own, removed afterwards.
struct Scratch {
    dir: PathBuf,
}

impl Scratch {
    fn new(name: &str) -> Self {
        let dir = std::env::temp_dir().join(format!("asli-history-{name}-{}", std::process::id()));
        fs::create_dir_all(&dir).expect("temp dir");
        Self { dir }
    }

    fn paths(&self) -> Paths {
        Paths {
            dir: self.dir.clone(),
        }
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.dir).ok();
    }
}

/// A configuration with history on and a small cap, so eviction is reachable.
fn config(entries: usize) -> Config {
    let mut config = Config::new_with_random_device_id().expect("config");
    config.keep_history = true;
    config.history_entries = entries;
    config
}

#[test]
fn clicking_a_row_puts_that_exact_entry_back_on_the_clipboard() {
    let scratch = Scratch::new("restore");
    let secret = [3u8; 32];
    let mut history =
        history_store::open(&scratch.paths(), &secret, &config(10)).expect("history opens");

    history.record(HistoryContent::Text("first thing".to_owned()), false, 1_000);
    history.record(
        HistoryContent::Text("second thing".to_owned()),
        false,
        2_000,
    );
    history.record(HistoryContent::Text("third thing".to_owned()), false, 3_000);

    // The screen draws this list top down, so row 0 is the newest.
    let rows = history.entries();
    assert_eq!(rows.len(), 3, "everything recorded should be listed");
    assert_eq!(rows[0].preview, "third thing", "newest first");
    assert_eq!(rows[2].preview, "first thing", "oldest last");

    // The click: resolve the row the person actually pointed at, not the newest one.
    let content = history.restore(1).expect("row 1 resolves");
    let clipboard = StubClipboard::default();
    match content {
        HistoryContent::Text(text) => clipboard.write_text(&text).expect("writes"),
        HistoryContent::ImagePng(_) => panic!("a text entry came back as an image"),
    }

    assert_eq!(
        clipboard.writes(),
        vec!["second thing".to_owned()],
        "the entry that was clicked must be the entry that lands on the clipboard"
    );
}

#[test]
fn an_image_entry_comes_back_as_an_image() {
    let scratch = Scratch::new("image");
    let secret = [4u8; 32];
    let mut history =
        history_store::open(&scratch.paths(), &secret, &config(10)).expect("history opens");

    let png = b"\x89PNG\r\n\x1a\nnot a real image but distinct bytes".to_vec();
    history.record(HistoryContent::ImagePng(png.clone()), false, 1_000);

    let rows = history.entries();
    assert!(rows[0].is_image, "an image must be listed as an image");
    assert!(
        rows[0].preview.is_empty(),
        "an image has no text preview to show"
    );

    let clipboard = StubClipboard::default();
    match history.restore(0).expect("resolves") {
        HistoryContent::ImagePng(bytes) => clipboard.write_image(&bytes).expect("writes"),
        HistoryContent::Text(_) => panic!("an image entry came back as text"),
    }

    assert_eq!(
        clipboard.images(),
        vec![png],
        "the bytes written must be the bytes stored, unchanged"
    );
}

#[test]
fn a_password_is_never_recorded_and_so_can_never_be_restored() {
    // The marker exists because a password manager asked for this clip to be left alone. A
    // history that kept it would undo the entire point of honouring the marker.
    let scratch = Scratch::new("sensitive");
    let secret = [5u8; 32];
    let mut history =
        history_store::open(&scratch.paths(), &secret, &config(10)).expect("history opens");

    history.record(HistoryContent::Text("hunter2".to_owned()), true, 1_000);
    history.record(HistoryContent::Text("ordinary".to_owned()), false, 2_000);

    let rows = history.entries();
    assert_eq!(rows.len(), 1, "only the ordinary clip should be kept");
    assert_eq!(rows[0].preview, "ordinary");

    assert!(
        !rows.iter().any(|row| row.preview.contains("hunter2")),
        "a concealed clip must not appear in the list in any form"
    );
}

#[test]
fn history_survives_a_restart_and_still_decrypts() {
    // The whole reason this is a file rather than a list in memory. If it did not survive, the
    // screen would be empty every morning and the feature would be pointless.
    let scratch = Scratch::new("restart");
    let secret = [6u8; 32];

    {
        let mut history =
            history_store::open(&scratch.paths(), &secret, &config(10)).expect("history opens");
        history.record(HistoryContent::Text("written before".to_owned()), false, 1);
    }

    let reopened =
        history_store::open(&scratch.paths(), &secret, &config(10)).expect("history reopens");
    let rows = reopened.entries();

    assert_eq!(
        rows.len(),
        1,
        "the entry must still be there after a restart"
    );
    assert_eq!(rows[0].preview, "written before");
    assert_eq!(
        reopened.restore(0),
        Some(HistoryContent::Text("written before".to_owned())),
        "and must still decrypt to what was stored"
    );
}

#[test]
fn a_file_from_another_account_is_discarded_rather_than_refused() {
    // Joining a different account leaves a file that will not decrypt. Refusing to start over it
    // would strand the person, so the store starts again instead.
    let scratch = Scratch::new("rekey");
    let first = [7u8; 32];
    let second = [8u8; 32];

    {
        let mut history =
            history_store::open(&scratch.paths(), &first, &config(10)).expect("history opens");
        history.record(
            HistoryContent::Text("belongs to the old account".to_owned()),
            false,
            1,
        );
    }

    let reopened = history_store::open(&scratch.paths(), &second, &config(10))
        .expect("a file it cannot read must not stop it opening");

    assert!(
        reopened.entries().is_empty(),
        "the previous account's entries must not be readable, or listed, under a new key"
    );
}

#[test]
fn forgetting_a_row_removes_that_row_and_no_other() {
    let scratch = Scratch::new("forget");
    let secret = [9u8; 32];
    let mut history =
        history_store::open(&scratch.paths(), &secret, &config(10)).expect("history opens");

    history.record(HistoryContent::Text("keep me".to_owned()), false, 1_000);
    history.record(HistoryContent::Text("remove me".to_owned()), false, 2_000);
    history.record(HistoryContent::Text("keep me too".to_owned()), false, 3_000);

    // Row 1 is "remove me": newest first puts "keep me too" at 0.
    assert!(history.forget(1), "forgetting an existing row reports true");

    let rows = history.entries();
    assert_eq!(rows.len(), 2);
    assert!(
        !rows.iter().any(|row| row.preview == "remove me"),
        "the forgotten row must be gone"
    );
    assert!(
        rows.iter().any(|row| row.preview == "keep me"),
        "and the others must not be"
    );

    assert!(
        !history.forget(99),
        "forgetting a row that is not there reports false rather than panicking"
    );
}

#[test]
fn turning_history_off_forgets_what_was_already_there() {
    // Turning it off and leaving the file behind would be the wrong reading of the switch:
    // somebody turning it off wants the record gone, not frozen.
    let scratch = Scratch::new("disable");
    let secret = [10u8; 32];
    let mut history =
        history_store::open(&scratch.paths(), &secret, &config(10)).expect("history opens");

    history.record(
        HistoryContent::Text("recorded earlier".to_owned()),
        false,
        1,
    );
    assert_eq!(history.entries().len(), 1);

    history.set_enabled(false);
    assert!(
        history.entries().is_empty(),
        "turning it off must clear what was kept"
    );

    history.record(HistoryContent::Text("after".to_owned()), false, 2);
    assert!(
        history.entries().is_empty(),
        "and nothing further may be recorded while it is off"
    );
}
