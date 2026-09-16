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

use asli_clipboard::{ClipContent, ClipEvent, ClipboardWatcher};

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

    /// A short description for the status output.
    fn describe(&self) -> String;
}

/// A clipboard that records writes instead of performing them.
#[derive(Debug, Default)]
pub struct StubClipboard {
    writes: Mutex<Vec<String>>,
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
}

impl ClipboardIo for StubClipboard {
    fn write_text(&self, text: &str) -> Result<()> {
        self.writes
            .lock()
            .expect("stub clipboard lock")
            .push(text.to_owned());
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
    /// Someone copied content their application marked as a password, and it was not read.
    Sensitive,
}

/// Handle to the writer thread.
pub struct LinuxClipboard {
    to_writer: Sender<String>,
    interrupt: Arc<AtomicBool>,
    description: String,
}

impl ClipboardIo for LinuxClipboard {
    fn write_text(&self, text: &str) -> Result<()> {
        // Queue first, then interrupt, so the writer always finds work waiting when its loop
        // returns. The reverse order races: the loop could return, find nothing, and block again.
        let _ = self.to_writer.send(text.to_owned());
        self.interrupt.store(true, Ordering::Relaxed);
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
                        // Images are v1.1. Ignoring them here keeps the daemon honest about what
                        // it supports rather than sending an empty clip.
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
    let (to_writer, from_daemon) = mpsc::channel::<String>();

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
fn writer_loop(mut clipboard: AnyClipboard, inbox: &Receiver<String>) {
    let interrupt = clipboard.shutdown_flag();

    while let Ok(text) = inbox.recv() {
        // Drain anything queued behind it: the clipboard is last write wins, so only the newest
        // matters.
        let mut latest = text;
        while let Ok(newer) = inbox.try_recv() {
            latest = newer;
        }

        if let Err(err) = clipboard.set_text(&latest) {
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
            Self::Windows(clipboard) => clipboard.set_text(text).map(|_| ()),
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
            Self::Wayland(clipboard) => clipboard.set_text(text).map(|_| ()),
            Self::X11(clipboard) => clipboard.set_text(text).map(|_| ()),
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
