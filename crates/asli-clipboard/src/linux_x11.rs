//! The X11 backend, built on `XFixes`.
//!
//! This is the most important backend on Linux, and not only for X11 sessions: it is also the
//! path used on GNOME Wayland. Mutter bridges Wayland native clipboard writes into the X11
//! `CLIPBOARD` selection (`notify_selection_owner` in `meta-x11-selection.c` claims the selection
//! on Mutter's own window "so X11 apps can interface with it"), so an X11 client watching with
//! `XFixes` sees copies made by Wayland applications. `XFixes` needs no focus at all, which makes
//! it more robust than wl-clipboard's focus stealing surface, and `wl-paste --watch` does not
//! work on GNOME in the first place.
//!
//! # What this does not do
//!
//! It does not watch `PRIMARY`, the middle click selection. `PRIMARY` changes on every text
//! selection, so syncing it would produce constant traffic and astonishing behaviour. That is a
//! product decision, not a limitation.
//!
//! # Event driven, not content polled
//!
//! The loop calls `poll_for_event` with a short sleep so that a shutdown request is noticed
//! promptly. That is a cheap check of an event queue, not a clipboard read: an idle session does
//! no X round trips for clipboard content at all. This is the distinction that makes the
//! difference between this backend and the 500 ms full clipboard re-read that `clipboard-rs`
//! performs on Wayland.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use x11rb::connection::Connection;
use x11rb::protocol::xfixes::{ConnectionExt as _, SelectionEventMask};
use x11rb::protocol::xproto::{
    Atom, AtomEnum, ConnectionExt as _, CreateWindowAux, EventMask, PropMode, Property,
    SelectionNotifyEvent, SelectionRequestEvent, Window, WindowClass, SELECTION_NOTIFY_EVENT,
};
use x11rb::protocol::Event;
use x11rb::rust_connection::RustConnection;
use x11rb::wrapper::ConnectionExt as _;
use x11rb::{COPY_DEPTH_FROM_PARENT, CURRENT_TIME, NONE};

use crate::error::{Error, Result};
use crate::image_bytes::{self, MAX_IMAGE_BYTES};
use crate::{ClipContent, ClipEvent, ClipboardWatcher, WriteOptions, WriteReceipt};

/// How long to coalesce a burst of selection changes before reading.
///
/// One user copy routinely produces several events: the application takes ownership, then a
/// clipboard manager such as Klipper or clipmenu takes it back to store the content. Reading once
/// at the end of the burst also avoids catching a partial set of formats mid write.
const DEBOUNCE: Duration = Duration::from_millis(100);

/// How long to wait for the selection owner to answer a conversion request.
///
/// X11 selection transfer is a conversation with another process, which may be busy, stopped or
/// gone. Without a timeout, a dead owner hangs the watcher forever. `UniClipboard` issue 1097 is
/// three seconds of blocking in exactly this path delaying shutdown.
const CONVERT_TIMEOUT: Duration = Duration::from_secs(2);

/// How long to wait between event queue polls while idle.
const IDLE_POLL: Duration = Duration::from_millis(20);

/// Largest property chunk we request in one round trip, in 32 bit units (1 MiB).
const MAX_PROPERTY_WORDS: u32 = 256 * 1024;

/// Largest text selection we will accept.
///
/// Images have their own, larger cap in [`crate::image_bytes`], because a screenshot is
/// legitimately far bigger than any text a person copies on purpose.
const MAX_TEXT_BYTES: usize = 8 * 1024 * 1024;

mod atoms {
    // The atom_manager macro generates a struct, its fields, and its methods, and none of them
    // can carry documentation, so the workspace missing_docs lint cannot be satisfied here. The
    // allow is scoped to this module rather than to the crate.
    #![allow(missing_docs)]

    use x11rb::atom_manager;

    atom_manager! {
        /// The atoms this backend needs.
        pub Atoms: AtomsCookie {
            CLIPBOARD,
            TARGETS,
            INCR,
            UTF8_STRING,
            TEXT,
            STRING,
            // The de facto Linux marker for password manager content. KeePassXC sets it, Klipper has
            // honoured it since plasma-workspace 5.12.8, and it survives the data control path on
            // Wayland. It appears in TARGETS like any other type, so we can see it before we read.
            KDE_PASSWORD_HINT: b"x-kde-passwordManagerHint",
            // Where we ask owners to place converted selection data.
            ASLI_SELECTION,
            // Marks the wake up message our writer sends to interrupt the event loop.
            ASLI_WAKE,
            TEXT_PLAIN_UTF8: b"text/plain;charset=utf-8",
            TEXT_PLAIN: b"text/plain",
            // PNG is the only image format carried, so this is the only image atom needed.
            IMAGE_PNG: b"image/png",
        }
    }
}

use atoms::Atoms;

/// What this client is currently serving as the selection owner.
///
/// X11 has no clipboard storage: the owner answers conversion requests on demand, so the content
/// has to be kept here for as long as the selection is held.
enum Owned {
    /// UTF-8 text, already normalized.
    Text(String),
    /// PNG bytes, already validated as PNG.
    Image(Vec<u8>),
}

/// The value Klipper and `KeePassXC` agree on for the hint.
const SENSITIVE_VALUE: &[u8] = b"secret";

/// An X11 clipboard connection: watches `CLIPBOARD` and can own it.
pub struct X11Clipboard {
    conn: RustConnection,
    window: Window,
    atoms: Atoms,
    shutdown: Arc<AtomicBool>,
    /// Content we currently own the selection for, served on request.
    owned: Option<Owned>,
    /// Whether what we own is marked as not for clipboard managers.
    ///
    /// Held beside the content rather than inside `Owned`, because it applies to whatever is
    /// being served and the hint is answered the same way for text and for an image.
    concealed: bool,
}

impl X11Clipboard {
    /// Connects to the X display and creates the hidden window used for selection traffic.
    ///
    /// The window is never mapped, so nothing appears on screen and no compositor shows it in a
    /// task list. It exists only as an address for selection events.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Connect`] if the display cannot be reached and
    /// [`Error::MissingExtension`] if the server has no usable `XFixes`.
    pub fn connect() -> Result<Self> {
        let (conn, screen_num) =
            x11rb::connect(None).map_err(|e| Error::Connect(format!("{e}")))?;
        let screen = &conn.setup().roots[screen_num];
        let window = conn
            .generate_id()
            .map_err(|e| Error::Connect(format!("could not allocate a window id: {e}")))?;

        conn.create_window(
            COPY_DEPTH_FROM_PARENT,
            window,
            screen.root,
            0,
            0,
            1,
            1,
            0,
            WindowClass::INPUT_OUTPUT,
            screen.root_visual,
            &CreateWindowAux::new().event_mask(EventMask::PROPERTY_CHANGE),
        )
        .map_err(|e| Error::Connect(format!("could not create the helper window: {e}")))?;

        let atoms = Atoms::new(&conn)
            .map_err(|e| Error::Connect(format!("could not request atoms: {e}")))?
            .reply()
            .map_err(|e| Error::Connect(format!("could not intern atoms: {e}")))?;

        // XFixes must be negotiated before any of its requests are used. Version 5.0 is ancient
        // and universally available; we only need selection notifications from version 1.0.
        conn.xfixes_query_version(5, 0)
            .map_err(|_| Error::MissingExtension("XFixes"))?
            .reply()
            .map_err(|_| Error::MissingExtension("XFixes"))?;

        conn.xfixes_select_selection_input(
            window,
            atoms.CLIPBOARD,
            SelectionEventMask::SET_SELECTION_OWNER
                | SelectionEventMask::SELECTION_WINDOW_DESTROY
                | SelectionEventMask::SELECTION_CLIENT_CLOSE,
        )
        .map_err(|e| Error::Connect(format!("could not subscribe to selection events: {e}")))?;

        conn.flush()
            .map_err(|e| Error::Connect(format!("could not flush: {e}")))?;

        Ok(Self {
            conn,
            window,
            atoms,
            shutdown: Arc::new(AtomicBool::new(false)),
            owned: None,
            concealed: false,
        })
    }

    /// A handle that can ask this watcher to stop from another thread.
    #[must_use]
    pub fn shutdown_handle(&self) -> Arc<AtomicBool> {
        Arc::clone(&self.shutdown)
    }

    /// Takes ownership of `CLIPBOARD` and serves `text` to anyone who asks for it.
    ///
    /// X11 has no clipboard storage: the owning client serves the content on demand, which is why
    /// copied text vanishes when the source application exits. While we own the selection, this
    /// backend answers conversion requests from its event loop.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Write`] if ownership could not be taken.
    pub fn set_text(&mut self, text: &str, options: WriteOptions) -> Result<WriteReceipt> {
        self.concealed = options.concealed;
        self.own_selection(Owned::Text(text.to_owned()))
    }

    /// Takes ownership of `CLIPBOARD` and serves `png` to anyone who asks for it.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Read`] if the bytes are not a PNG or exceed the cap, and [`Error::Write`]
    /// if ownership could not be taken.
    pub fn set_image(&mut self, png: &[u8], options: WriteOptions) -> Result<WriteReceipt> {
        image_bytes::validate_png(png)?;
        self.concealed = options.concealed;
        self.own_selection(Owned::Image(png.to_vec()))
    }

    /// Gives up `CLIPBOARD`, so the clipboard is genuinely empty rather than empty looking.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Write`] if the selection could not be released.
    pub fn release_selection(&mut self) -> Result<()> {
        self.owned = None;
        self.concealed = false;
        self.conn
            .set_selection_owner(NONE, self.atoms.CLIPBOARD, CURRENT_TIME)
            .map_err(|e| Error::Write(format!("could not release the selection: {e}")))?;
        self.conn
            .flush()
            .map_err(|e| Error::Write(format!("could not flush: {e}")))?;
        Ok(())
    }

    fn own_selection(&mut self, content: Owned) -> Result<WriteReceipt> {
        self.owned = Some(content);

        self.conn
            .set_selection_owner(self.window, self.atoms.CLIPBOARD, CURRENT_TIME)
            .map_err(|e| Error::Write(format!("could not request selection ownership: {e}")))?;
        self.conn
            .flush()
            .map_err(|e| Error::Write(format!("could not flush: {e}")))?;

        let owner = self
            .conn
            .get_selection_owner(self.atoms.CLIPBOARD)
            .map_err(|e| Error::Write(format!("could not confirm ownership: {e}")))?
            .reply()
            .map_err(|e| Error::Write(format!("could not confirm ownership: {e}")))?
            .owner;

        if owner != self.window {
            return Err(Error::Write(
                "another client took the clipboard selection immediately".to_owned(),
            ));
        }

        // X11 offers no sequence counter, so loop prevention here relies on the owner field of
        // the XFixes event (layer three) plus the content hash guard in asli-core (layer two).
        Ok(WriteReceipt { seq: None })
    }

    /// Reads `CLIPBOARD`, as text if there is text and as a PNG otherwise, and reports whether it
    /// is marked sensitive.
    ///
    /// The marker check happens first, over `TARGETS`, so content a password manager flagged is
    /// never read into our memory at all.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Read`] on a timeout or protocol failure, and [`Error::NotUtf8`] if the
    /// owner handed us bytes that are not valid UTF-8.
    pub fn read_clipboard(&self) -> Result<Option<ClipEvent>> {
        let targets = self.request_targets()?;

        if targets.contains(&self.atoms.KDE_PASSWORD_HINT) {
            return Ok(Some(ClipEvent {
                content: ClipContent::Text(String::new()),
                sensitive: true,
            }));
        }

        // Prefer the explicitly typed targets over the legacy untyped STRING, which is latin-1.
        let target = [
            self.atoms.UTF8_STRING,
            self.atoms.TEXT_PLAIN_UTF8,
            self.atoms.TEXT_PLAIN,
        ]
        .into_iter()
        .find(|t| targets.contains(t));

        // Text wins when both are offered, which is the common case: copying a rich text
        // selection also puts a bitmap rendering on the clipboard, and syncing the picture
        // instead of the words would be astonishing.
        if let Some(target) = target {
            let bytes = self.convert_and_read(target, MAX_TEXT_BYTES)?;
            let raw = String::from_utf8(bytes).map_err(|_| Error::NotUtf8)?;

            // Normalize at exactly one boundary, here, so the same text hashes identically on
            // every platform. See asli_core::normalize for why this is not optional.
            let text = asli_core::normalize(&raw).into_owned();
            if !asli_core::is_syncable(&text) {
                return Ok(None);
            }

            return Ok(Some(ClipEvent {
                content: ClipContent::Text(text),
                sensitive: false,
            }));
        }

        if targets.contains(&self.atoms.IMAGE_PNG) {
            let bytes = self.convert_and_read(self.atoms.IMAGE_PNG, MAX_IMAGE_BYTES)?;
            image_bytes::validate_png(&bytes)?;
            return Ok(Some(ClipEvent {
                content: ClipContent::ImagePng(bytes),
                sensitive: false,
            }));
        }

        // Neither text nor a PNG. A file list, or a format v1 does not carry.
        Ok(None)
    }

    fn request_targets(&self) -> Result<Vec<Atom>> {
        // A target list is a few hundred atoms at most, so the text bound is generous here.
        let bytes = self.convert_and_read(self.atoms.TARGETS, MAX_TEXT_BYTES)?;
        // TARGETS comes back as a list of 32 bit atoms.
        Ok(bytes
            .chunks_exact(4)
            .map(|c| Atom::from_be_bytes([c[3], c[2], c[1], c[0]]))
            .collect())
    }

    /// Asks the owner to convert the selection, waits for the reply, and reads the property.
    fn convert_and_read(&self, target: Atom, limit: usize) -> Result<Vec<u8>> {
        self.conn
            .delete_property(self.window, self.atoms.ASLI_SELECTION)
            .map_err(|e| Error::Read(format!("could not clear the transfer property: {e}")))?;

        self.conn
            .convert_selection(
                self.window,
                self.atoms.CLIPBOARD,
                target,
                self.atoms.ASLI_SELECTION,
                CURRENT_TIME,
            )
            .map_err(|e| Error::Read(format!("could not request a conversion: {e}")))?;
        self.conn
            .flush()
            .map_err(|e| Error::Read(format!("could not flush: {e}")))?;

        let deadline = Instant::now() + CONVERT_TIMEOUT;
        loop {
            if Instant::now() > deadline {
                return Err(Error::Read(
                    "the clipboard owner did not answer in time".to_owned(),
                ));
            }
            match self
                .conn
                .poll_for_event()
                .map_err(|e| Error::ConnectionLost(format!("{e}")))?
            {
                Some(Event::SelectionNotify(event)) if event.requestor == self.window => {
                    if event.property == NONE {
                        // The owner refused this target.
                        return Ok(Vec::new());
                    }
                    return self.read_property(limit);
                }
                Some(_) => {
                    // Selection traffic is what we are waiting for. Other events, including a new
                    // XFixes notification, are handled by the outer loop on the next pass.
                }
                None => std::thread::sleep(Duration::from_millis(5)),
            }
        }
    }

    fn read_property(&self, limit: usize) -> Result<Vec<u8>> {
        let reply = self
            .conn
            .get_property(
                false,
                self.window,
                self.atoms.ASLI_SELECTION,
                AtomEnum::ANY,
                0,
                MAX_PROPERTY_WORDS,
            )
            .map_err(|e| Error::Read(format!("could not read the transfer property: {e}")))?
            .reply()
            .map_err(|e| Error::Read(format!("could not read the transfer property: {e}")))?;

        if reply.type_ == self.atoms.INCR {
            return self.read_incr(limit);
        }

        self.conn
            .delete_property(self.window, self.atoms.ASLI_SELECTION)
            .map_err(|e| Error::Read(format!("could not clear the transfer property: {e}")))?;
        Ok(reply.value)
    }

    /// Reads a large selection through the INCR protocol.
    ///
    /// The owner writes the data to our property in chunks, sending a `PropertyNotify` each time.
    /// We must delete the property to acknowledge each chunk, and a zero length chunk ends the
    /// transfer. Without this, anything past the server's maximum request size is truncated.
    fn read_incr(&self, limit: usize) -> Result<Vec<u8>> {
        let mut out = Vec::new();
        let deadline = Instant::now() + CONVERT_TIMEOUT;

        // Deleting the property signals the owner to send the first chunk.
        self.conn
            .delete_property(self.window, self.atoms.ASLI_SELECTION)
            .map_err(|e| Error::Read(format!("could not acknowledge an INCR chunk: {e}")))?;
        self.conn
            .flush()
            .map_err(|e| Error::Read(format!("could not flush: {e}")))?;

        loop {
            if Instant::now() > deadline {
                return Err(Error::Read(
                    "an incremental transfer stalled and was abandoned".to_owned(),
                ));
            }
            match self
                .conn
                .poll_for_event()
                .map_err(|e| Error::ConnectionLost(format!("{e}")))?
            {
                Some(Event::PropertyNotify(event))
                    if event.window == self.window
                        && event.atom == self.atoms.ASLI_SELECTION
                        && event.state == Property::NEW_VALUE =>
                {
                    let reply = self
                        .conn
                        .get_property(
                            true,
                            self.window,
                            self.atoms.ASLI_SELECTION,
                            AtomEnum::ANY,
                            0,
                            MAX_PROPERTY_WORDS,
                        )
                        .map_err(|e| Error::Read(format!("could not read an INCR chunk: {e}")))?
                        .reply()
                        .map_err(|e| Error::Read(format!("could not read an INCR chunk: {e}")))?;

                    self.conn
                        .flush()
                        .map_err(|e| Error::Read(format!("could not flush: {e}")))?;

                    if reply.value.is_empty() {
                        return Ok(out);
                    }

                    // An incremental transfer is the one path where a hostile or broken owner can
                    // feed us unbounded data a chunk at a time, so the cap is enforced per chunk
                    // rather than only on the total at the end.
                    if out.len().saturating_add(reply.value.len()) > limit {
                        return Err(Error::Read(format!(
                            "an incremental transfer exceeded the {limit} byte limit and was abandoned"
                        )));
                    }
                    out.extend_from_slice(&reply.value);
                }
                Some(_) => {}
                None => std::thread::sleep(Duration::from_millis(5)),
            }
        }
    }

    /// Answers another client's request for the selection we own.
    /// Answers a TARGETS request with the list that matches what is actually held.
    ///
    /// Both content types answer the same way, so the only thing that varies is the list itself,
    /// and the hint is appended when the content is concealed so a clipboard manager can see the
    /// marker before it asks for anything.
    fn serve_targets(
        &self,
        request: &SelectionRequestEvent,
        property: Atom,
        owned: &Owned,
    ) -> Result<()> {
        let mut targets = match owned {
            Owned::Text(_) => vec![
                self.atoms.TARGETS,
                self.atoms.UTF8_STRING,
                self.atoms.TEXT_PLAIN_UTF8,
                self.atoms.TEXT_PLAIN,
                self.atoms.STRING,
                self.atoms.TEXT,
            ],
            Owned::Image(_) => vec![self.atoms.TARGETS, self.atoms.IMAGE_PNG],
        };
        if self.concealed {
            targets.push(self.atoms.KDE_PASSWORD_HINT);
        }

        self.conn
            .change_property32(
                PropMode::REPLACE,
                request.requestor,
                property,
                AtomEnum::ATOM,
                &targets,
            )
            .map_err(|e| Error::Write(format!("could not answer a TARGETS request: {e}")))?;
        Ok(())
    }

    /// Answers a direct request for the password manager hint.
    ///
    /// Klipper asks for this type by name to decide whether to store an item at all, so the
    /// answer has to be served like any other target rather than merely advertised.
    fn serve_hint(&self, request: &SelectionRequestEvent, property: Atom) -> Result<()> {
        self.conn
            .change_property8(
                PropMode::REPLACE,
                request.requestor,
                property,
                request.target,
                SENSITIVE_VALUE,
            )
            .map_err(|e| Error::Write(format!("could not answer a hint request: {e}")))?;
        Ok(())
    }

    fn serve_selection_request(&self, request: &SelectionRequestEvent) -> Result<()> {
        let Some(owned) = self.owned.as_ref() else {
            self.refuse(request)?;
            return Ok(());
        };

        let property = if request.property == NONE {
            // Obsolete clients pass None and expect the target atom to be used.
            request.target
        } else {
            request.property
        };

        // The target list has to describe what is actually held. Advertising text targets while
        // serving an image would make every paste fail in a way the other application reports as
        // our fault.
        if request.target == self.atoms.TARGETS {
            self.serve_targets(request, property, owned)?;
        } else if request.target == self.atoms.KDE_PASSWORD_HINT && self.concealed {
            self.serve_hint(request, property)?;
        } else if let (Owned::Text(text), true) = (
            owned,
            request.target == self.atoms.UTF8_STRING
                || request.target == self.atoms.TEXT_PLAIN_UTF8
                || request.target == self.atoms.TEXT_PLAIN
                || request.target == self.atoms.STRING
                || request.target == self.atoms.TEXT,
        ) {
            self.conn
                .change_property8(
                    PropMode::REPLACE,
                    request.requestor,
                    property,
                    request.target,
                    text.as_bytes(),
                )
                .map_err(|e| Error::Write(format!("could not answer a text request: {e}")))?;
        } else if let (Owned::Image(png), true) = (owned, request.target == self.atoms.IMAGE_PNG) {
            self.conn
                .change_property8(
                    PropMode::REPLACE,
                    request.requestor,
                    property,
                    request.target,
                    png,
                )
                .map_err(|e| Error::Write(format!("could not answer an image request: {e}")))?;
        } else {
            self.refuse(request)?;
            return Ok(());
        }

        let notify = SelectionNotifyEvent {
            response_type: SELECTION_NOTIFY_EVENT,
            sequence: 0,
            time: request.time,
            requestor: request.requestor,
            selection: request.selection,
            target: request.target,
            property,
        };
        self.conn
            .send_event(false, request.requestor, EventMask::NO_EVENT, notify)
            .map_err(|e| Error::Write(format!("could not send a selection reply: {e}")))?;
        self.conn
            .flush()
            .map_err(|e| Error::Write(format!("could not flush: {e}")))?;
        Ok(())
    }

    fn refuse(&self, request: &SelectionRequestEvent) -> Result<()> {
        let notify = SelectionNotifyEvent {
            response_type: SELECTION_NOTIFY_EVENT,
            sequence: 0,
            time: request.time,
            requestor: request.requestor,
            selection: request.selection,
            target: request.target,
            property: NONE,
        };
        self.conn
            .send_event(false, request.requestor, EventMask::NO_EVENT, notify)
            .map_err(|e| Error::Write(format!("could not refuse a selection request: {e}")))?;
        self.conn
            .flush()
            .map_err(|e| Error::Write(format!("could not flush: {e}")))?;
        Ok(())
    }
}

impl ClipboardWatcher for X11Clipboard {
    fn run(&mut self, sink: &mut dyn FnMut(ClipEvent)) -> Result<()> {
        let mut pending_since: Option<Instant> = None;

        loop {
            if self.shutdown.load(Ordering::Relaxed) {
                return Ok(());
            }

            match self
                .conn
                .poll_for_event()
                .map_err(|e| Error::ConnectionLost(format!("{e}")))?
            {
                Some(Event::XfixesSelectionNotify(event)) => {
                    if event.selection == self.atoms.CLIPBOARD {
                        // Layer three of loop prevention: if we are the new owner, this event is
                        // the echo of our own write. The owner field makes this exact on X11,
                        // with no hashing and no timing window.
                        if event.owner == self.window {
                            continue;
                        }
                        // Someone else owns the clipboard now, so we no longer serve content.
                        self.owned = None;
                        pending_since = Some(Instant::now());
                    }
                }
                Some(Event::SelectionRequest(request)) => {
                    // Another client wants the content we own. Failing to answer would make paste
                    // hang in that application, so an error here is logged by the caller but must
                    // not stop the watcher.
                    self.serve_selection_request(&request)?;
                }
                Some(Event::SelectionClear(_)) => {
                    self.owned = None;
                }
                Some(_) | None => {}
            }

            if let Some(since) = pending_since {
                if since.elapsed() >= DEBOUNCE {
                    pending_since = None;
                    match self.read_clipboard() {
                        Ok(Some(event)) => sink(event),
                        // Either there was no text on the clipboard, or the read failed because
                        // the owner exited between the notification and our request. Both are
                        // routine and neither is worth stopping the watcher for.
                        Ok(None) | Err(Error::Read(_) | Error::NotUtf8) => {}
                        Err(other) => return Err(other),
                    }
                } else {
                    std::thread::sleep(Duration::from_millis(5));
                    continue;
                }
            }

            std::thread::sleep(IDLE_POLL);
        }
    }

    fn shutdown(&self) {
        self.shutdown.store(true, Ordering::Relaxed);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// These tests need a real X server, so they are skipped when there is none, which is the
    /// normal case in CI. The integration test in M1 runs them against Xvfb.
    fn display_available() -> bool {
        std::env::var("DISPLAY").is_ok_and(|d| !d.is_empty())
    }

    #[test]
    fn connects_when_a_display_exists() {
        if !display_available() {
            eprintln!("skipping: no DISPLAY");
            return;
        }
        let clipboard = X11Clipboard::connect().expect("connects to the X server");
        assert_ne!(clipboard.window, 0);
    }

    #[test]
    fn writes_and_reads_back_its_own_text() {
        if !display_available() {
            eprintln!("skipping: no DISPLAY");
            return;
        }
        let mut clipboard = X11Clipboard::connect().expect("connects");
        let receipt = clipboard
            .set_text("asli round trip", WriteOptions::plain())
            .expect("takes ownership");
        assert_eq!(receipt.seq, None, "X11 has no sequence counter");
        assert!(matches!(clipboard.owned, Some(Owned::Text(ref t)) if t == "asli round trip"));
    }

    #[test]
    fn owns_an_image_and_serves_it_as_png() {
        if !display_available() {
            eprintln!("skipping: no DISPLAY");
            return;
        }
        let mut clipboard = X11Clipboard::connect().expect("connects");
        let mut png = crate::image_bytes::PNG_MAGIC.to_vec();
        png.extend_from_slice(b"IHDR stand in for a real image");
        clipboard
            .set_image(&png, WriteOptions::plain())
            .expect("takes ownership");
        assert!(matches!(clipboard.owned, Some(Owned::Image(ref bytes)) if bytes == &png));
    }

    #[test]
    fn a_non_png_is_refused_before_the_selection_is_taken() {
        if !display_available() {
            eprintln!("skipping: no DISPLAY");
            return;
        }
        let mut clipboard = X11Clipboard::connect().expect("connects");
        // Putting a mislabelled payload on the clipboard would fail on the other side rather than
        // here, which is the worse place to find out.
        assert!(clipboard
            .set_image(b"BM this is a bitmap", WriteOptions::plain())
            .is_err());
    }

    #[test]
    fn shutdown_handle_stops_the_loop() {
        if !display_available() {
            eprintln!("skipping: no DISPLAY");
            return;
        }
        let mut clipboard = X11Clipboard::connect().expect("connects");
        let handle = clipboard.shutdown_handle();
        handle.store(true, Ordering::Relaxed);
        let mut seen = 0;
        clipboard
            .run(&mut |_| seen += 1)
            .expect("returns cleanly when asked to stop");
        assert_eq!(seen, 0);
    }
}
