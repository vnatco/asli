//! Owning the platform clipboard from a daemon.
//!
//! The platform backends in `asli-clipboard` present a blocking `run` loop that borrows the
//! connection mutably, and a `set_text` that also borrows it mutably. A single connection
//! therefore cannot watch and write at the same time. That is not an oversight in those backends:
//! X11 and Wayland both require the client that owns the selection to stay alive and answer
//! requests, so writing is a long lived responsibility rather than a single call.
//!
//! So this module runs two connections. One watches and never writes. The other writes and then
//! serves the selection, and is interrupted through its shutdown flag whenever new content
//! arrives. The cost is one extra connection to the display server, which is cheap, and the
//! benefit is that neither loop has to be restructured.
//!
//! The write side only runs its event loop while it owns the selection, so an idle device does no
//! clipboard work at all on that connection.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{Receiver, Sender};
use std::sync::{mpsc, Arc, Mutex};
use std::thread;

use asli_clipboard::{ClipContent, ClipEvent, ClipboardWatcher, WriteOptions};

use crate::error::Result;

/// Somewhere a received clip can be written.
///
/// A trait rather than a concrete type so the daemon loop can be tested without a display server,
/// which is what makes the "never echo our own write" test possible in CI.
pub trait ClipboardIo: Send + Sync {
    /// Writes text to the system clipboard.
    ///
    /// The caller must already have recorded the content hash in the echo guard. `asli-net` does
    /// this before it hands over the clip, so this is a plain write.
    ///
    /// # Errors
    ///
    /// Returns an error if the write could not be handed to the platform.
    fn write_text(&self, text: &str) -> Result<()>;

    /// Writes a PNG image to the system clipboard.
    ///
    /// Same contract as [`ClipboardIo::write_text`]: the hash is already in the echo guard, so the
    /// clipboard change this causes will be recognised as ours and not sent back out.
    ///
    /// Defaulted so a platform without image support, or a test double that only cares about
    /// text, does not have to implement it. The default refuses rather than silently succeeding,
    /// because a write that reports success and does nothing is how a person ends up pasting the
    /// wrong thing with no idea why.
    ///
    /// # Errors
    ///
    /// Returns an error if the write could not be handed to the platform.
    fn write_image(&self, png: &[u8]) -> Result<()> {
        let _ = png;
        Err(crate::Error::Clipboard(asli_clipboard::Error::NoBackend(
            "this clipboard has no image support".to_owned(),
        )))
    }

    /// A short description for the status output.
    fn describe(&self) -> String;
}

/// A clipboard that records writes instead of performing them.
#[derive(Debug, Default)]
pub struct StubClipboard {
    writes: Mutex<Vec<String>>,
    images: Mutex<Vec<Vec<u8>>>,
}

impl StubClipboard {
    /// Everything written so far, oldest first.
    ///
    /// # Panics
    ///
    /// Panics if a previous test thread poisoned the lock, which is a test failure anyway.
    #[must_use]
    pub fn writes(&self) -> Vec<String> {
        self.writes.lock().expect("stub clipboard lock").clone()
    }

    /// Every image written so far, oldest first.
    ///
    /// # Panics
    ///
    /// Panics if a previous test thread poisoned the lock.
    #[must_use]
    pub fn images(&self) -> Vec<Vec<u8>> {
        self.images.lock().expect("stub clipboard lock").clone()
    }
}

impl ClipboardIo for StubClipboard {
    fn write_text(&self, text: &str) -> Result<()> {
        self.writes
            .lock()
            .expect("stub clipboard lock")
            .push(text.to_owned());
        Ok(())
    }

    fn write_image(&self, png: &[u8]) -> Result<()> {
        self.images
            .lock()
            .expect("stub clipboard lock")
            .push(png.to_vec());
        Ok(())
    }

    fn describe(&self) -> String {
        "stub, for tests".to_owned()
    }
}

/// What a running clipboard pair reports upward.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Observed {
    /// Someone copied text.
    Text(String),
    /// Someone copied an image, already normalized to PNG by the backend.
    Image(Vec<u8>),
    /// Someone copied content their application marked as a password, and it was not read.
    Sensitive,
}

/// Work handed to the writer thread.
///
/// The writer used to take a plain `String`. It cannot any more: an image is bytes, and encoding
/// it into a string to fit the old channel would mean guessing at the other end whether a payload
/// was text or an encoded image, which is exactly the sort of ambiguity that produces a corrupted
/// paste.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Write {
    Text(String),
    Image(Vec<u8>),
}

/// Handle to the writer thread.
pub struct LinuxClipboard {
    to_writer: Sender<Write>,
    interrupt: Arc<AtomicBool>,
    description: String,
}

impl LinuxClipboard {
    /// Queues one write and wakes the writer.
    ///
    /// Queue first, then interrupt, so the writer always finds work waiting when its loop returns.
    /// The reverse order races: the loop could return, find nothing, and block again.
    fn queue(&self, work: Write) {
        let _ = self.to_writer.send(work);
        self.interrupt.store(true, Ordering::Relaxed);
    }
}

impl ClipboardIo for LinuxClipboard {
    fn write_text(&self, text: &str) -> Result<()> {
        self.queue(Write::Text(text.to_owned()));
        Ok(())
    }

    fn write_image(&self, png: &[u8]) -> Result<()> {
        self.queue(Write::Image(png.to_vec()));
        Ok(())
    }

    fn describe(&self) -> String {
        self.description.clone()
    }
}

/// Starts watching and writing, using whichever backend this session supports.
///
/// Returns the write handle and a channel of observations. Both threads live for the process.
///
/// # Errors
///
/// Returns [`crate::Error::Clipboard`] if no backend can be started, which happens on GNOME
/// Wayland without `XWayland` and on river, where no protocol exposes the clipboard at all.
#[cfg(any(target_os = "linux", target_os = "windows"))]
pub fn start() -> Result<(LinuxClipboard, Receiver<Observed>)> {
    use asli_clipboard::session::{self, Env};

    let env = Env::from_process();
    let plan = session::plan(&env)?;

    let (tx, rx) = mpsc::channel();
    let watcher_backend = plan.backend;

    thread::Builder::new()
        .name("asli-clipboard-watch".to_owned())
        .spawn(move || {
            let mut backend = match connect(watcher_backend) {
                Ok(backend) => backend,
                Err(err) => {
                    eprintln!("{}", log_line("clipboard_watch_failed", &err.to_string()));
                    return;
                }
            };
            let result = backend.run(&mut |event: ClipEvent| {
                let observed = if event.sensitive {
                    Observed::Sensitive
                } else {
                    match event.content {
                        ClipContent::Text(text) => Observed::Text(text),
                        ClipContent::ImagePng(png) => Observed::Image(png),
                        // ClipContent is non exhaustive. A content type added later is dropped
                        // here rather than sent as something it is not.
                        _ => return,
                    }
                };
                let _ = tx.send(observed);
            });
            if let Err(err) = result {
                eprintln!("{}", log_line("clipboard_watch_ended", &err.to_string()));
            }
        })
        .map_err(crate::Error::Io)?;

    // The writer connects here rather than inside its thread, because the interrupt has to be the
    // clipboard's own shutdown flag: that is the only flag its run loop checks.
    let writer = connect(watcher_backend)?;
    let interrupt = writer.shutdown_flag();
    let (to_writer, from_daemon) = mpsc::channel::<Write>();

    thread::Builder::new()
        .name("asli-clipboard-write".to_owned())
        .spawn(move || writer_loop(writer, &from_daemon))
        .map_err(crate::Error::Io)?;

    Ok((
        LinuxClipboard {
            to_writer,
            interrupt,
            description: format!("{:?} ({})", plan.backend, plan.note),
        },
        rx,
    ))
}

/// The writer thread: take ownership of the selection, then serve it until new content arrives.
#[cfg(any(target_os = "linux", target_os = "windows"))]
fn writer_loop(mut clipboard: AnyClipboard, inbox: &Receiver<Write>) {
    let interrupt = clipboard.shutdown_flag();

    while let Ok(work) = inbox.recv() {
        // Drain anything queued behind it: the clipboard is last write wins, so only the newest
        // matters. This is also why a large image queued behind a newer text copy is discarded
        // rather than written and immediately overwritten.
        let mut latest = work;
        while let Ok(newer) = inbox.try_recv() {
            latest = newer;
        }

        let outcome = match &latest {
            Write::Text(text) => clipboard.set_text(text),
            Write::Image(png) => clipboard.set_image(png),
        };
        if let Err(err) = outcome {
            eprintln!("{}", log_line("clipboard_write_failed", &err.to_string()));
            continue;
        }

        // Serve the selection until the next write interrupts us. Without this the content
        // disappears the moment another application asks for it, which on X11 and Wayland alike is
        // what "the clipboard is empty after the app that copied it exits" means.
        interrupt.store(false, Ordering::Relaxed);
        if let Err(err) = clipboard.run(&mut |_| {}) {
            eprintln!("{}", log_line("clipboard_serve_ended", &err.to_string()));
            return;
        }
    }
}

/// One connection, whichever protocol this session speaks.
#[cfg(target_os = "linux")]
enum AnyClipboard {
    Wayland(Box<asli_clipboard::linux_wayland::WaylandClipboard>),
    X11(Box<asli_clipboard::linux_x11::X11Clipboard>),
}

/// The same idea on Windows, where there is exactly one mechanism.
#[cfg(target_os = "windows")]
enum AnyClipboard {
    Windows(Box<asli_clipboard::windows::WindowsClipboard>),
}

#[cfg(target_os = "windows")]
impl AnyClipboard {
    fn set_text(&mut self, text: &str) -> asli_clipboard::Result<()> {
        match self {
            Self::Windows(clipboard) => clipboard.set_text(text, WriteOptions::plain()).map(|_| ()),
        }
    }

    /// Writes an image, where the platform backend supports it.
    ///
    /// The Windows backend reads images but does not yet offer a write path, so this reports that
    /// plainly instead of dropping the clip. A received image that silently never appears is worse
    /// than one that explains itself in the log.
    fn set_image(&mut self, png: &[u8]) -> asli_clipboard::Result<()> {
        let _ = png;
        match self {
            Self::Windows(_) => Err(asli_clipboard::Error::Write(
                "writing images is not implemented on Windows yet".to_owned(),
            )),
        }
    }

    fn run(&mut self, sink: &mut dyn FnMut(ClipEvent)) -> asli_clipboard::Result<()> {
        match self {
            Self::Windows(clipboard) => clipboard.run(sink),
        }
    }

    fn shutdown_flag(&self) -> Arc<AtomicBool> {
        match self {
            Self::Windows(clipboard) => clipboard.shutdown_handle(),
        }
    }
}

#[cfg(target_os = "windows")]
fn connect(backend: asli_clipboard::session::Backend) -> asli_clipboard::Result<AnyClipboard> {
    use asli_clipboard::session::Backend;

    match backend {
        Backend::Windows => asli_clipboard::windows::WindowsClipboard::connect()
            .map(|clipboard| AnyClipboard::Windows(Box::new(clipboard))),
        other => Err(asli_clipboard::Error::NoBackend(format!(
            "this build has no connector for the {other:?} backend on this platform"
        ))),
    }
}

#[cfg(target_os = "linux")]
impl AnyClipboard {
    fn set_text(&mut self, text: &str) -> asli_clipboard::Result<()> {
        match self {
            Self::Wayland(clipboard) => clipboard.set_text(text, WriteOptions::plain()).map(|_| ()),
            Self::X11(clipboard) => clipboard.set_text(text, WriteOptions::plain()).map(|_| ()),
        }
    }

    /// Writes a PNG, offering it as `image/png` for as long as this connection owns the selection.
    fn set_image(&mut self, png: &[u8]) -> asli_clipboard::Result<()> {
        match self {
            Self::Wayland(clipboard) => clipboard.set_image(png, WriteOptions::plain()).map(|_| ()),
            Self::X11(clipboard) => clipboard.set_image(png, WriteOptions::plain()).map(|_| ()),
        }
    }

    fn run(&mut self, sink: &mut dyn FnMut(ClipEvent)) -> asli_clipboard::Result<()> {
        match self {
            Self::Wayland(clipboard) => clipboard.run(sink),
            Self::X11(clipboard) => clipboard.run(sink),
        }
    }

    fn shutdown_flag(&self) -> Arc<AtomicBool> {
        match self {
            Self::Wayland(clipboard) => clipboard.shutdown_handle(),
            Self::X11(clipboard) => clipboard.shutdown_handle(),
        }
    }
}

#[cfg(target_os = "linux")]
fn connect(backend: asli_clipboard::session::Backend) -> asli_clipboard::Result<AnyClipboard> {
    use asli_clipboard::session::Backend;

    match backend {
        Backend::WaylandDataControl => {
            match asli_clipboard::linux_wayland::WaylandClipboard::connect() {
                Ok(clipboard) => Ok(AnyClipboard::Wayland(Box::new(clipboard))),
                // GNOME advertises no data control protocol at all, and the session planner
                // routes it here through XWayland instead. Falling back rather than failing keeps
                // that path working.
                Err(asli_clipboard::Error::NoProtocol(_)) => {
                    asli_clipboard::linux_x11::X11Clipboard::connect()
                        .map(|clipboard| AnyClipboard::X11(Box::new(clipboard)))
                }
                Err(other) => Err(other),
            }
        }
        Backend::X11 => asli_clipboard::linux_x11::X11Clipboard::connect()
            .map(|clipboard| AnyClipboard::X11(Box::new(clipboard))),
        // Backend is non exhaustive and gains a variant per platform. Anything this build has no
        // connector for is named rather than quietly treated as X11, which would fail later and
        // further from the cause.
        other => Err(asli_clipboard::Error::NoBackend(format!(
            "this build has no connector for the {other:?} backend on this platform"
        ))),
    }
}

/// One structured log line. Never carries clipboard content, only a reason.
#[must_use]
pub fn log_line(event: &str, detail: &str) -> String {
    format!(r#"{{"event":"{event}","detail":{}}}"#, quote(detail))
}

fn quote(text: &str) -> String {
    let mut out = String::with_capacity(text.len() + 2);
    out.push('"');
    for ch in text.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push(' '),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_stub_records_writes_in_order() {
        let stub = StubClipboard::default();
        stub.write_text("one").expect("writes");
        stub.write_text("two").expect("writes");
        assert_eq!(stub.writes(), vec!["one".to_owned(), "two".to_owned()]);
    }

    #[test]
    fn log_lines_are_json_and_carry_no_content() {
        let line = log_line(
            "clipboard_write_failed",
            "another client holds the selection",
        );
        assert!(line.starts_with('{') && line.ends_with('}'));
        assert!(line.contains("clipboard_write_failed"));
    }

    #[test]
    fn log_lines_escape_hostile_detail() {
        let line = log_line("x", "he said \"hello\"\nand left");
        assert!(
            !line.contains('\n'),
            "a newline would break line based logs"
        );
        assert!(line.contains("\\\""));
    }
}
