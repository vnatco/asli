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

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{Receiver, Sender};
use std::sync::{mpsc, Arc, Mutex};
use std::thread;
use std::time::Duration;

#[cfg(not(target_os = "macos"))]
use asli_clipboard::ClipboardWatcher;
use asli_clipboard::{ClipContent, ClipEvent, WriteOptions};

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

    /// Writes text marked so clipboard history, cloud sync and third party managers leave it
    /// alone, then clears it after `clear_after` if it is still on the clipboard.
    ///
    /// Defaulted to a refusal. A caller that believes it wrote a protected secret and did not is
    /// worse off than one told plainly that the platform cannot express it.
    ///
    /// # Errors
    ///
    /// Returns an error if the platform cannot mark content, or the write failed.
    fn write_text_concealed(&self, text: &str, clear_after: Duration) -> Result<()> {
        let _ = (text, clear_after);
        Err(crate::Error::Clipboard(asli_clipboard::Error::NoBackend(
            "this clipboard cannot mark content as concealed".to_owned(),
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
    concealed: Mutex<Vec<String>>,
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

    /// Everything written with the concealment markers, oldest first.
    ///
    /// # Panics
    ///
    /// Panics if a previous test thread poisoned the lock.
    #[must_use]
    pub fn concealed(&self) -> Vec<String> {
        self.concealed.lock().expect("stub clipboard lock").clone()
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

    fn write_text_concealed(&self, text: &str, _clear_after: Duration) -> Result<()> {
        self.concealed
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
    /// Text carrying the markers that keep it out of clipboard history, cloud sync and third
    /// party managers. Used for the join token, which is the account key in full.
    TextConcealed(String),
    /// Clear the clipboard, but only if nothing has been copied since the given generation.
    ///
    /// The condition is the point: clearing unconditionally would destroy whatever the person
    /// copied in the meantime.
    ClearIfUnchanged(String, u64),
}

/// Handle to the writer thread.
pub struct SystemClipboard {
    to_writer: Sender<Write>,
    interrupt: Arc<AtomicBool>,
    description: String,
    /// Bumped by every clipboard change, ours or anyone else's.
    ///
    /// A scheduled clear carries the generation it was scheduled at, so anything copied since
    /// makes it stale and it is dropped rather than destroying that copy.
    generation: Arc<AtomicU64>,
}

impl SystemClipboard {
    /// Queues one write and wakes the writer.
    ///
    /// Queue first, then interrupt, so the writer always finds work waiting when its loop returns.
    /// The reverse order races: the loop could return, find nothing, and block again.
    fn queue(&self, work: Write) {
        // A clear must not bump the generation, or it would invalidate itself in flight.
        if !matches!(work, Write::ClearIfUnchanged(..)) {
            self.generation.fetch_add(1, Ordering::Relaxed);
        }
        let _ = self.to_writer.send(work);
        self.interrupt.store(true, Ordering::Relaxed);
    }
}

impl ClipboardIo for SystemClipboard {
    fn write_text(&self, text: &str) -> Result<()> {
        self.queue(Write::Text(text.to_owned()));
        Ok(())
    }

    fn write_image(&self, png: &[u8]) -> Result<()> {
        self.queue(Write::Image(png.to_vec()));
        Ok(())
    }

    fn write_text_concealed(&self, text: &str, clear_after: Duration) -> Result<()> {
        self.queue(Write::TextConcealed(text.to_owned()));

        // A detached timer rather than a blocking wait: the caller is a tray menu handler and must
        // return immediately.
        let sender = self.to_writer.clone();
        let interrupt = Arc::clone(&self.interrupt);
        let owned = text.to_owned();
        // Captured after the queue above bumped it, so this is the generation of our own write.
        let scheduled_for = self.generation.load(Ordering::Relaxed);
        thread::Builder::new()
            .name("asli-token-clear".to_owned())
            .spawn(move || {
                thread::sleep(clear_after);
                let _ = sender.send(Write::ClearIfUnchanged(owned, scheduled_for));
                interrupt.store(true, Ordering::Relaxed);
            })
            .map_err(crate::Error::Io)?;
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
pub fn start() -> Result<(SystemClipboard, Receiver<Observed>)> {
    use asli_clipboard::session::{self, Env};

    let env = Env::from_process();
    let plan = session::plan(&env)?;

    let (tx, rx) = mpsc::channel();
    let watcher_backend = plan.backend;

    // The writer connects here rather than inside its thread, because the interrupt has to be the
    // clipboard's own shutdown flag: that is the only flag its run loop checks.
    let writer = connect(watcher_backend)?;
    let watcher_seed = watcher_for(&writer);

    // Shared by the watcher and the writer. An external copy has to bump this too, or a pending
    // clear would still fire and wipe out what the person just copied.
    let generation = Arc::new(AtomicU64::new(0));
    let watcher_generation = Arc::clone(&generation);

    thread::Builder::new()
        .name("asli-clipboard-watch".to_owned())
        .spawn(move || {
            let connected = watcher_seed.map_or_else(|| connect(watcher_backend), Ok);
            let mut backend = match connected {
                Ok(backend) => backend,
                Err(err) => {
                    eprintln!("{}", log_line("clipboard_watch_failed", &err.to_string()));
                    return;
                }
            };
            let result = backend.run(&mut |event: ClipEvent| {
                if let Some(observed) = to_observed(event, &watcher_generation) {
                    let _ = tx.send(observed);
                }
            });
            if let Err(err) = result {
                eprintln!("{}", log_line("clipboard_watch_ended", &err.to_string()));
            }
        })
        .map_err(crate::Error::Io)?;

    let interrupt = writer.shutdown_flag();
    let (to_writer, from_daemon) = mpsc::channel::<Write>();

    let writer_generation = Arc::clone(&generation);
    thread::Builder::new()
        .name("asli-clipboard-write".to_owned())
        .spawn(move || writer_loop(writer, &from_daemon, &writer_generation))
        .map_err(crate::Error::Io)?;

    Ok((
        SystemClipboard {
            to_writer,
            interrupt,
            description: format!("{:?} ({})", plan.backend, plan.note),
            generation,
        },
        rx,
    ))
}

/// Turns a backend event into what the daemon is told, and marks a real copy.
///
/// A real copy bumps the generation, so any clear scheduled before it is stale.
///
/// Concealed content is the exception, and it has to be, or the token clear can never fire.
/// Copying the token writes it marked, the platform hands it straight back through the watcher as
/// sensitive, and bumping here would invalidate the clear that was scheduled microseconds earlier.
/// The token then sits on the clipboard forever, which is exactly the leak the clear exists to
/// close. A concealed observation is either our own marked write or a password manager's copy, and
/// neither is a user copy that a pending clear would destroy.
fn to_observed(event: ClipEvent, generation: &AtomicU64) -> Option<Observed> {
    let observed = if event.sensitive {
        Observed::Sensitive
    } else {
        match event.content {
            ClipContent::Text(text) => Observed::Text(text),
            ClipContent::ImagePng(png) => Observed::Image(png),
            // ClipContent is non exhaustive. A content type added later is dropped here rather
            // than sent as something it is not.
            _ => return None,
        }
    };

    if !matches!(observed, Observed::Sensitive) {
        generation.fetch_add(1, Ordering::Relaxed);
    }
    Some(observed)
}

/// Performs one write. Returns the outcome, and whether it was a release of the clipboard.
fn apply_write(
    clipboard: &mut AnyClipboard,
    work: &Write,
    generation: &AtomicU64,
) -> (asli_clipboard::Result<()>, bool) {
    match work {
        Write::Text(text) => (clipboard.set_text(text), false),
        Write::Image(png) => (clipboard.set_image(png), false),
        Write::TextConcealed(text) => (clipboard.set_text_concealed(text), false),
        Write::ClearIfUnchanged(_, scheduled_for) => {
            // Only clear if nothing has been copied since. The generation counter is the signal:
            // every write bumps it, and the watcher bumps it when an external copy takes the
            // clipboard away from us. A stale clear is dropped, because wrongly clearing
            // someone's clipboard is far worse than a token lingering a while.
            if *scheduled_for == generation.load(Ordering::Relaxed) {
                // Release, never write an empty string. Writing empty keeps us owning the
                // selection, so the clipboard still advertises text while serving zero bytes.
                (clipboard.release(), true)
            } else {
                (Ok(()), false)
            }
        }
    }
}

/// The writer thread: take ownership of the selection, then serve it until new content arrives.
#[cfg(any(target_os = "linux", target_os = "windows"))]
fn writer_loop(mut clipboard: AnyClipboard, inbox: &Receiver<Write>, generation: &Arc<AtomicU64>) {
    let interrupt = clipboard.shutdown_flag();

    while let Ok(work) = inbox.recv() {
        // Drain anything queued behind it: the clipboard is last write wins, so only the newest
        // matters. This is also why a large image queued behind a newer text copy is discarded
        // rather than written and immediately overwritten.
        let mut latest = work;
        while let Ok(newer) = inbox.try_recv() {
            latest = newer;
        }

        let (outcome, released) = apply_write(&mut clipboard, &latest, generation);

        if let Err(err) = outcome {
            eprintln!("{}", log_line("clipboard_write_failed", &err.to_string()));
            continue;
        }

        // After a release there is nothing to serve, and re-entering the loop would keep us
        // registered as the owner, which is the other half of why an emptied clipboard still
        // advertised four text types.
        if released || !clipboard.must_serve() {
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

/// macOS, where there is exactly one mechanism, the polled pasteboard.
#[cfg(target_os = "macos")]
enum AnyClipboard {
    Macos(Box<asli_clipboard::macos::MacosClipboard>),
}

#[cfg(target_os = "macos")]
impl AnyClipboard {
    fn set_text(&mut self, text: &str) -> asli_clipboard::Result<()> {
        match self {
            Self::Macos(clipboard) => clipboard.set_text(text, WriteOptions::plain()).map(|_| ()),
        }
    }

    /// Writes text with the nspasteboard.org concealed marker beside it.
    fn set_text_concealed(&mut self, text: &str) -> asli_clipboard::Result<()> {
        match self {
            Self::Macos(clipboard) => clipboard
                .set_text(text, WriteOptions::concealed())
                .map(|_| ()),
        }
    }

    fn set_image(&mut self, png: &[u8]) -> asli_clipboard::Result<()> {
        match self {
            Self::Macos(clipboard) => clipboard.set_image(png, WriteOptions::plain()).map(|_| ()),
        }
    }

    fn release(&mut self) -> asli_clipboard::Result<()> {
        match self {
            Self::Macos(clipboard) => clipboard.release_selection(),
        }
    }
}

/// Everything that touches the macOS pasteboard, driven from the main thread.
///
/// `AppKit` is not thread safe, and polling `NSPasteboard` off the main thread is a documented
/// crash in a competing tool. So on macOS there is no watcher thread and no writer thread. The
/// daemon queues writes into a channel exactly as on the other platforms, and this drains that
/// channel and polls the change counter in one place, every [`MacPump::INTERVAL`], on whichever
/// thread calls [`MacPump::tick`]. The application calls it from the main thread only.
#[cfg(target_os = "macos")]
pub struct MacPump {
    clipboard: AnyClipboard,
    inbox: Receiver<Write>,
    observed: Sender<Observed>,
    generation: Arc<AtomicU64>,
    _activity: asli_clipboard::macos::BackgroundActivity,
}

#[cfg(target_os = "macos")]
impl MacPump {
    /// How often [`MacPump::tick`] should run. The rate the established macOS clipboard utilities
    /// poll at.
    pub const INTERVAL: Duration = asli_clipboard::macos::POLL_INTERVAL;

    /// Applies the newest queued write, then checks whether somebody else copied.
    ///
    /// Writes first, so a clip that arrived during the last interval reaches the pasteboard
    /// before the next poll, and the poll then recognises it as ours by its change count.
    pub fn tick(&mut self) {
        // Last write wins, exactly as on the other platforms.
        let mut latest = None;
        while let Ok(work) = self.inbox.try_recv() {
            latest = Some(work);
        }
        if let Some(work) = latest {
            let (outcome, _released) = apply_write(&mut self.clipboard, &work, &self.generation);
            if let Err(err) = outcome {
                eprintln!("{}", log_line("clipboard_write_failed", &err.to_string()));
            }
        }

        let AnyClipboard::Macos(clipboard) = &mut self.clipboard;
        match clipboard.poll_once() {
            Ok(Some(event)) => {
                if let Some(observed) = to_observed(event, &self.generation) {
                    let _ = self.observed.send(observed);
                }
            }
            Ok(None) => {}
            Err(err) => eprintln!("{}", log_line("clipboard_watch_failed", &err.to_string())),
        }
    }

    /// Runs [`MacPump::tick`] forever on the calling thread, for the headless daemon.
    pub fn run_blocking(mut self) -> ! {
        loop {
            self.tick();
            thread::sleep(Self::INTERVAL);
        }
    }
}

/// Starts the macOS clipboard. Call on the main thread, and keep calling [`MacPump::tick`] there.
///
/// # Errors
///
/// Currently infallible on macOS, and returns `Result` to match the other platforms.
#[cfg(target_os = "macos")]
pub fn start() -> Result<(SystemClipboard, Receiver<Observed>, MacPump)> {
    let clipboard = asli_clipboard::macos::MacosClipboard::connect()?;
    let permission = asli_clipboard::macos::MacosClipboard::permission();
    let (tx, rx) = mpsc::channel();
    let (to_writer, from_daemon) = mpsc::channel::<Write>();
    let generation = Arc::new(AtomicU64::new(0));

    Ok((
        SystemClipboard {
            to_writer,
            // Nothing blocks on macOS, so there is nothing to interrupt. The flag exists so the
            // queueing code is the same on every platform.
            interrupt: Arc::new(AtomicBool::new(false)),
            description: format!(
                "NSPasteboard, polled every {} ms (read permission: {})",
                MacPump::INTERVAL.as_millis(),
                permission.label()
            ),
            generation: Arc::clone(&generation),
        },
        rx,
        MacPump {
            clipboard: AnyClipboard::Macos(Box::new(clipboard)),
            inbox: from_daemon,
            observed: tx,
            generation,
            _activity: asli_clipboard::macos::begin_background_activity(),
        },
    ))
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

    /// Writes text with the three Windows exclusion formats set.
    fn set_text_concealed(&mut self, text: &str) -> asli_clipboard::Result<()> {
        match self {
            Self::Windows(clipboard) => clipboard
                .set_text(text, WriteOptions::concealed())
                .map(|_| ()),
        }
    }

    /// Writes an image as PNG and as a bitmap, so old and new applications can both paste it.
    fn set_image(&mut self, png: &[u8]) -> asli_clipboard::Result<()> {
        match self {
            Self::Windows(clipboard) => clipboard.set_image(png, WriteOptions::plain()).map(|_| ()),
        }
    }

    /// Empties the clipboard.
    fn release(&mut self) -> asli_clipboard::Result<()> {
        match self {
            Self::Windows(clipboard) => clipboard.release_selection(),
        }
    }

    /// Windows keeps clipboard data itself once it is written, so there is nothing to serve.
    ///
    /// Entering the watch loop to serve, as X11 and Wayland must, would block this thread in the
    /// clipboard listener until somebody copied something locally, and every clip received in the
    /// meantime would wait behind it.
    #[allow(clippy::unused_self)]
    const fn must_serve(&self) -> bool {
        false
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

/// The watcher, when it has to be made from the writer rather than connected on its own.
///
/// On Windows the watcher recognises the writer's changes by the clipboard sequence number the
/// writer recorded, so the two must share it. Without that, every received clip came back through
/// the watcher as a local copy: the session's hash guard stopped it being sent, but it was logged
/// as sent and recorded in the history a second time.
#[cfg(target_os = "windows")]
#[allow(clippy::unnecessary_wraps)] // Same signature as on Linux, where there is nothing to share.
fn watcher_for(writer: &AnyClipboard) -> Option<AnyClipboard> {
    match writer {
        AnyClipboard::Windows(clipboard) => {
            Some(AnyClipboard::Windows(Box::new(clipboard.sibling())))
        }
    }
}

/// On X11 and Wayland the watcher needs a connection of its own, made on its own thread, and it
/// recognises our writes by owner and by content hash instead.
#[cfg(target_os = "linux")]
const fn watcher_for(_writer: &AnyClipboard) -> Option<AnyClipboard> {
    None
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

    /// Writes text with the concealment markers the platform offers.
    fn set_text_concealed(&mut self, text: &str) -> asli_clipboard::Result<()> {
        match self {
            Self::Wayland(clipboard) => clipboard
                .set_text(text, WriteOptions::concealed())
                .map(|_| ()),
            Self::X11(clipboard) => clipboard
                .set_text(text, WriteOptions::concealed())
                .map(|_| ()),
        }
    }

    /// Writes a PNG, offering it as `image/png` for as long as this connection owns the selection.
    fn release(&mut self) -> asli_clipboard::Result<()> {
        match self {
            Self::Wayland(clipboard) => clipboard.release_selection(),
            Self::X11(clipboard) => clipboard.release_selection(),
        }
    }

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

    /// Neither X11 nor Wayland stores clipboard content, so whoever wrote it must keep answering.
    #[allow(clippy::unused_self)]
    const fn must_serve(&self) -> bool {
        true
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

#[cfg(test)]
mod conceal_tests {
    use super::*;

    #[test]
    fn a_concealed_write_is_recorded_as_concealed_not_plain() {
        let stub = StubClipboard::default();
        stub.write_text_concealed("asli1_TOKEN", Duration::from_secs(90))
            .expect("stub accepts concealed writes");

        assert_eq!(stub.concealed(), vec!["asli1_TOKEN".to_owned()]);
        assert!(
            stub.writes().is_empty(),
            "a concealed write must not fall back to a plain one, which is how a key ends up in \
             clipboard history"
        );
    }

    #[test]
    fn the_default_refuses_rather_than_writing_unmarked() {
        struct TextOnly;
        impl ClipboardIo for TextOnly {
            fn write_text(&self, _text: &str) -> Result<()> {
                Ok(())
            }
            fn describe(&self) -> String {
                "text only".to_owned()
            }
        }

        // The default must fail closed. Writing the key unmarked while reporting success is worse
        // than reporting that the platform cannot do it.
        let err = TextOnly
            .write_text_concealed("asli1_TOKEN", Duration::from_secs(90))
            .expect_err("the default implementation must refuse");
        assert!(err.to_string().contains("concealed"));
    }
}
