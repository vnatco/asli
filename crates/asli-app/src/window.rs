//! The window.
//!
//! # Why there is one at all
//!
//! There were three improvised mechanisms before this. The join string was written to an HTML file
//! and opened in a browser, joining was a zenity prompt, and settings was a JSON file handed to
//! whatever editor the desktop had registered. Each of those put a different application on
//! screen, none of them ours, and the HTML one wrote the account key to disk with a cleanup timer
//! that a restart could outlive. This replaces all three, and deletes that file path entirely.
//!
//! # When it exists
//!
//! Not until somebody asks for it. The event loop runs on the main thread from startup because
//! every platform requires that, but no window is constructed until a tray item or a first run
//! calls [`open`], and closing it drops it again. An idle device pays for a tray icon and a
//! socket, not for a user interface.
//!
//! # Which thread owns what
//!
//! The window is owned by the main thread and never leaves it. The daemon runs on a worker with
//! its own runtime, and the tray runs on another. Both reach the window the same way, by posting
//! onto the event loop with [`slint::invoke_from_event_loop`], so nothing here is shared across
//! threads and nothing here needs a lock. Status is pulled on a timer that only runs while the
//! window is visible, rather than pushed from the daemon, because a pull costs nothing when
//! nobody is looking.

use std::cell::RefCell;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use slint::{
    ComponentHandle as _, Image, Model as _, ModelRc, Rgba8Pixel, SharedPixelBuffer, VecModel,
};

use asli_crypto::{token, Identity};

use crate::clipboard_io::{log_line, ClipboardIo};
use crate::config::{Config, Paths};
use crate::daemon::{Controls, Status};
use crate::error::{Error, Result};
use crate::{notify, qr, secrets, tray};

// The markup, compiled in a crate of its own.
//
// It lives there rather than here because Slint's generated code carries an inner
// `allow(unsafe_code)`, and this crate's `#![forbid(unsafe_code)]` would overrule it and fail the
// build. Keeping the generated code at arm's length is what lets every hand written crate in this
// project keep the stronger annotation.
pub use asli_ui::{AppWindow, DeviceRow, HistoryRow, Screen, SyncState, TokenCheck};

/// How long the join string stays on the clipboard before it clears itself.
///
/// Long enough to paste into another machine, short enough that it is not still sitting there an
/// hour later.
const TOKEN_CLEAR_AFTER: Duration = Duration::from_secs(90);

/// How often the visible window refreshes its status.
const REFRESH: Duration = Duration::from_millis(900);

/// The size caps offered, as bytes and as the label beside them.
const SIZE_CAPS: [(usize, &str); 4] = [
    (256 * 1024, "256 KB"),
    (700 * 1024, "700 KB"),
    (1024 * 1024, "1 MB"),
    (4 * 1024 * 1024, "4 MB"),
];

/// The history lengths offered, matching the labels in the markup.
const RETENTIONS: [usize; 4] = [25, 50, 100, 250];

// ---------------------------------------------------------------------------------------------
// The history wiring point
// ---------------------------------------------------------------------------------------------

/// Where the History screen gets its rows.
///
/// # The wiring point
///
/// This is the single seam between the window and stored history, and it is a trait because
/// `asli-history` is a separate crate on its own schedule. [`MemoryHistory`] below satisfies it
/// with a list that lives as long as the process, which is enough to build and use the screen.
///
/// Swapping in the real store is one implementation of this trait over `asli_history::Store`, and
/// the shapes were chosen to line up with it deliberately: [`HistoryEntry`] carries the same
/// fields as `asli_history::Summary`, and [`HistoryContent`] the same variants as
/// `asli_history::Content`. Nothing else in this module needs to change.
pub trait HistorySource: Send {
    /// Whether history is being recorded at all. A person who turned it off should be told that,
    /// not shown an empty list that looks like a bug.
    fn enabled(&self) -> bool;

    /// The entries, newest first.
    fn entries(&self) -> Vec<HistoryEntry>;

    /// The full content of one entry, by position in [`HistorySource::entries`].
    fn restore(&self, index: usize) -> Option<HistoryContent>;

    /// Records one entry, newest first.
    ///
    /// Called by the daemon for both directions: what this device copied and what arrived from
    /// another one. `sensitive` means the platform marked the clip as a password, and such a clip
    /// must never be kept. `from` is the device it came from, this one included.
    fn record(&mut self, content: HistoryContent, sensitive: bool, ts_ms: u64, from: [u8; 16]);

    /// Forgets one entry. Returns whether there was one there.
    fn forget(&mut self, index: usize) -> bool;

    /// Forgets everything.
    fn clear(&mut self);

    /// Turns recording on or off. Turning it off forgets what was already there.
    fn set_enabled(&mut self, enabled: bool);

    /// Changes how many entries are kept, dropping any excess immediately.
    fn set_limit(&mut self, limit: usize);

    /// A number that changes whenever the entries do, so an open window knows to redraw.
    ///
    /// The daemon records into the history from another thread while the window is showing it,
    /// and without something to compare, a copy made or received while the list was open only
    /// appeared after navigating away and back.
    fn revision(&self) -> u64;
}

/// One row, with no content attached.
///
/// Mirrors `asli_history::Summary`: enough to draw a list without decrypting more than necessary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HistoryEntry {
    /// The first part of the text, or empty for an image.
    pub preview: String,
    /// Whether this is an image rather than text.
    pub is_image: bool,
    /// When it was captured, milliseconds since the Unix epoch.
    pub ts_ms: u64,
    /// Size of the full content in bytes.
    pub bytes: usize,
    /// The device it came from, or all zeros where that is not known.
    pub from: [u8; 16],
    /// Stable for the life of the entry, so an image's thumbnail is decoded once, not on every
    /// redraw of the list.
    pub key: [u8; 16],
}

/// The full content of one entry. Mirrors `asli_history::Content`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HistoryContent {
    /// UTF-8 text.
    Text(String),
    /// A PNG image, and only ever a PNG.
    ImagePng(Vec<u8>),
}

/// A history that lives in memory for as long as the process does.
///
/// The placeholder behind [`HistorySource`]. It is honest about what it is: nothing here is
/// written to disk, so a restart loses it, which is why the screen says so.
#[derive(Debug, Default)]
pub struct MemoryHistory {
    entries: Vec<(HistoryEntry, HistoryContent)>,
    enabled: bool,
    limit: usize,
    revision: u64,
    /// Hands out entry keys.
    next_key: u64,
}

impl MemoryHistory {
    /// A new, empty history.
    #[must_use]
    pub const fn new(enabled: bool, limit: usize) -> Self {
        Self {
            entries: Vec::new(),
            enabled,
            limit,
            revision: 0,
            next_key: 0,
        }
    }

    /// Records one entry, newest first, dropping the oldest past the limit.
    ///
    /// Secrets are never recorded. A clip the platform marked as concealed is a password manager
    /// handing over a password, and writing that into a list on disk would undo the entire point
    /// of the marker.
    pub fn push(&mut self, content: HistoryContent, sensitive: bool, ts_ms: u64, from: [u8; 16]) {
        if !self.enabled || sensitive {
            return;
        }

        // A repeat moves to the top rather than appearing twice, as it does in the encrypted
        // store, so restoring an entry or copying the same thing again does not grow the list.
        self.entries.retain(|(_, existing)| *existing != content);

        let (preview, is_image, bytes) = match &content {
            HistoryContent::Text(text) => (preview_of(text), false, text.len()),
            HistoryContent::ImagePng(png) => (String::new(), true, png.len()),
        };

        self.next_key = self.next_key.wrapping_add(1);
        let mut key = [0u8; 16];
        key[..8].copy_from_slice(&self.next_key.to_be_bytes());
        self.entries.insert(
            0,
            (
                HistoryEntry {
                    preview,
                    is_image,
                    ts_ms,
                    bytes,
                    from,
                    key,
                },
                content,
            ),
        );
        self.entries.truncate(self.limit.max(1));
        self.revision = self.revision.wrapping_add(1);
    }
}

impl HistorySource for MemoryHistory {
    fn enabled(&self) -> bool {
        self.enabled
    }

    fn entries(&self) -> Vec<HistoryEntry> {
        self.entries
            .iter()
            .map(|(entry, _)| entry.clone())
            .collect()
    }

    fn restore(&self, index: usize) -> Option<HistoryContent> {
        self.entries.get(index).map(|(_, content)| content.clone())
    }

    fn record(&mut self, content: HistoryContent, sensitive: bool, ts_ms: u64, from: [u8; 16]) {
        self.push(content, sensitive, ts_ms, from);
    }

    fn forget(&mut self, index: usize) -> bool {
        if index < self.entries.len() {
            self.entries.remove(index);
            self.revision = self.revision.wrapping_add(1);
            return true;
        }
        false
    }

    fn clear(&mut self) {
        self.entries.clear();
        self.revision = self.revision.wrapping_add(1);
    }

    /// Turning history off and leaving the previous entries in place would be the wrong reading
    /// of the switch: somebody turning it off wants the list gone, not frozen.
    fn set_enabled(&mut self, enabled: bool) {
        self.enabled = enabled;
        if !enabled {
            self.clear();
        }
    }

    fn set_limit(&mut self, limit: usize) {
        self.limit = limit.max(1);
        self.entries.truncate(self.limit);
        self.revision = self.revision.wrapping_add(1);
    }

    fn revision(&self) -> u64 {
        // Enabled is part of what the screen shows, so flipping it counts as a change too.
        self.revision.wrapping_mul(2) | u64::from(self.enabled)
    }
}

/// The first line of a clip, shortened, for a list row.
fn preview_of(text: &str) -> String {
    let first = text.lines().next().unwrap_or("").trim();
    let mut out: String = first.chars().take(120).collect();
    if first.chars().count() > 120 {
        out.push('\u{2026}');
    }
    out
}

// ---------------------------------------------------------------------------------------------
// What the window is allowed to touch
// ---------------------------------------------------------------------------------------------

/// A history shared between the daemon, which records into it, and the window, which shows it.
///
/// The daemon holds one of these too. That is why [`HistorySource`] lives in this module rather
/// than beside the window code that draws it: there is one seam, and both sides use it.
pub type SharedHistory = Arc<Mutex<dyn HistorySource + Send>>;

/// Everything the window acts on.
///
/// Installed once before the event loop starts, and read from the main thread thereafter.
pub struct Context {
    /// Where configuration and state live.
    pub paths: Paths,
    /// Pause, status and the retained request, shared with the daemon.
    pub controls: Controls,
    /// Somewhere to write a restored clip.
    pub io: Arc<dyn ClipboardIo>,
    /// The history behind the History screen.
    pub history: Arc<Mutex<dyn HistorySource + Send>>,
}

static CONTEXT: OnceLock<Context> = OnceLock::new();

thread_local! {
    /// The live window, or nothing when it is closed. Main thread only.
    static WINDOW: RefCell<Option<AppWindow>> = const { RefCell::new(None) };

    /// The refresh timer, which only ticks while a window exists.
    static TIMER: RefCell<Option<slint::Timer>> = const { RefCell::new(None) };
}

/// The Wayland application id, which must match the desktop entry's basename exactly.
///
/// Also the X11 `WM_CLASS`. Changing it without renaming `packaging/linux/asli.desktop` silently
/// costs the window its icon, which is why they are named in the same comment.
const APP_ID: &str = "asli";

/// Installs what the window acts on. Call once, on the main thread, before [`run_event_loop`].
///
/// # Errors
///
/// Returns [`Error::ConfigDir`] if called more than once, which would mean two different sets of
/// paths and controls were in play and the window could act on the wrong one.
pub fn install(context: Context) -> Result<()> {
    CONTEXT
        .set(context)
        .map_err(|_| Error::ConfigDir("the window was installed twice".to_owned()))?;

    // The toolkit otherwise creates its platform lazily, on the first window or when the loop
    // starts. Until then there is no event loop to hand work to, so everything scheduled before
    // the loop runs, the first run window and on Windows the tray itself, failed with "the
    // platform does not provide an event loop" and simply never happened.
    slint::BackendSelector::new()
        .select()
        .map_err(|err| Error::ConfigDir(format!("no display available: {err}")))
}

/// Runs the event loop on the calling thread, which must be the main one.
///
/// Returns when [`quit`] is called, not when the last window closes: the daemon outlives every
/// window, and a person closing one means "go away", never "stop syncing".
///
/// # Errors
///
/// Returns [`Error::ConfigDir`] if the platform refuses to start an event loop, which on Linux
/// means neither a Wayland nor an X11 display could be opened.
pub fn run_event_loop() -> Result<()> {
    slint::run_event_loop_until_quit()
        .map_err(|err| Error::ConfigDir(format!("no display available: {err}")))
}

/// Ends the event loop. Safe to call from any thread.
pub fn quit() {
    let _ = slint::invoke_from_event_loop(|| {
        let _ = slint::quit_event_loop();
    });
}

/// Opens the window on a screen. Safe to call from any thread.
///
/// This is the whole public surface the tray needs: every menu item is one of these.
pub fn open(screen: Screen) {
    if slint::invoke_from_event_loop(move || show(screen)).is_err() {
        eprintln!(
            "{}",
            log_line("window_failed", "the event loop is not running")
        );
        notify::action_failed("Could not open the window", "the display is not available");
    }
}

/// Opens the window where a person most likely wants it, which is the list of what they copied.
///
/// Raised by clicking the tray icon rather than by a menu item, so it names no screen of its own
/// beyond that. It does not check whether an account exists either: [`show`] already sends
/// everything to first run while there is none, and duplicating that rule here would mean two
/// places to disagree.
pub fn open_default() {
    open(Screen::History);
}

/// Which screen a tray menu item leads to.
#[must_use]
pub const fn screen_for(command: tray::Command) -> Option<Screen> {
    match command {
        tray::Command::ShowToken => Some(Screen::Token),
        tray::Command::Join => Some(Screen::Join),
        tray::Command::Settings => Some(Screen::Settings),
        tray::Command::History => Some(Screen::History),
        tray::Command::Status => Some(Screen::Status),
        _ => None,
    }
}

// ---------------------------------------------------------------------------------------------
// Building and showing
// ---------------------------------------------------------------------------------------------

/// Shows the window on `screen`, building it if this is the first time.
fn show(screen: Screen) {
    // A handle is taken out of the slot and the borrow released before anything is done with the
    // window. Holding the borrow across `refresh` and `show` would turn any callback the toolkit
    // happens to dispatch from inside them into a panic rather than a warning, and a tray
    // application that dies when a menu item is clicked twice is worse than one with no window.
    // A weak handle rather than the window itself: the generated type is not `Clone`, and taking
    // a weak one is the toolkit's own way of referring to a window from outside it.
    let handle = WINDOW.with_borrow_mut(|slot| {
        if slot.is_none() {
            match build() {
                Ok(window) => *slot = Some(window),
                Err(err) => {
                    eprintln!("{}", log_line("window_failed", &err.to_string()));
                    notify::action_failed("Could not open the window", &err.to_string());
                }
            }
        }
        slot.as_ref().map(slint::ComponentHandle::as_weak)
    });

    let Some(window) = handle.and_then(|handle| handle.upgrade()) else {
        return;
    };

    refresh(&window);
    // With no account there is nowhere to navigate to, so first run takes the whole window
    // regardless of which menu item was clicked. Join is the exception: it is how first run is
    // left.
    window.set_screen(if window.get_has_account() || screen == Screen::Join {
        screen
    } else {
        Screen::FirstRun
    });

    let already_open = window.window().is_visible();
    if already_open && wayland_session() {
        // Wayland refuses a focus request that does not carry an activation token, and the tray's
        // click reaches us without one. A window shown afresh, though, is given focus. So an open
        // window is closed and shown again, which puts it in front where a focus request would be
        // ignored.
        let _ = window.hide();
    }

    if let Err(err) = window.show() {
        eprintln!("{}", log_line("window_failed", &err.to_string()));
        return;
    }
    if already_open && !wayland_session() {
        bring_to_front(&window);
    }
    start_timer();
}

/// Un-minimizes the window and asks for focus, for a click on the tray icon when it is already
/// open somewhere behind other windows. Showing an open window again does neither by itself.
fn bring_to_front(window: &AppWindow) {
    use slint::winit_030::WinitWindowAccessor as _;
    window.window().with_winit_window(|winit| {
        winit.set_minimized(false);
        winit.focus_window();
    });
}

/// Whether this is a Wayland session, where only a freshly shown window gets focus.
fn wayland_session() -> bool {
    cfg!(target_os = "linux") && std::env::var_os("WAYLAND_DISPLAY").is_some()
}

/// The interface face for this platform, when the platform's own default is not the one the
/// design names.
fn ui_font() -> &'static str {
    if cfg!(target_os = "windows") {
        // Windows 11 ships the variable Segoe that the design is drawn in. Windows 10 has only
        // the older face, which is close enough and always present.
        let windir = std::env::var_os("WINDIR").map_or_else(
            || std::path::PathBuf::from(r"C:\Windows"),
            std::path::PathBuf::from,
        );
        if windir.join("Fonts").join("SegUIVar.ttf").exists() {
            "Segoe UI Variable Text"
        } else {
            "Segoe UI"
        }
    } else {
        // The system face: Noto Sans on most Linux desktops, San Francisco on macOS.
        ""
    }
}

/// Hides the window and stops everything that was running for it.
///
/// The window is hidden rather than dropped. Dropping it here would mean destroying it from
/// inside one of its own callbacks, which is how a close button turns into a crash. What matters
/// for an idle device is that no window is built until somebody asks, and that still holds: this
/// only runs after one has been opened.
fn hide() {
    TIMER.with_borrow_mut(|slot| {
        if let Some(timer) = slot.take() {
            timer.stop();
        }
    });
    WINDOW.with_borrow(|slot| {
        if let Some(window) = slot.as_ref() {
            let _ = window.hide();
        }
    });
}

/// Refreshes status while the window is visible, and not otherwise.
fn start_timer() {
    TIMER.with_borrow_mut(|slot| {
        if slot.is_some() {
            return;
        }
        let timer = slint::Timer::default();
        timer.start(slint::TimerMode::Repeated, REFRESH, || {
            WINDOW.with_borrow(|window| {
                if let Some(window) = window.as_ref() {
                    refresh_status(window);
                    refresh_history_if_stale(window);
                    track_maximized(window);
                }
            });
        });
        *slot = Some(timer);
    });
}

/// Shows a short confirmation at the bottom of the open window.
fn toast(text: &str, good: bool) {
    WINDOW.with_borrow(|window| {
        if let Some(window) = window.as_ref() {
            window.invoke_show_toast(text.into(), good);
        }
    });
}

/// Attaches the three callbacks that create or replace the account on this device.
///
/// Separate from [`build`] because these are the only callbacks that change what this device is,
/// rather than what it is showing, and both of them end by replacing the running process.
fn wire_account(window: &AppWindow) {
    let handle = window.as_weak();
    window.on_create_account(move || {
        let Some(window) = handle.upgrade() else {
            return;
        };
        window.set_create_error(String::new().into());
        window.set_creating(true);
        // Deferred a moment, so the busy state is on screen before the work that it describes.
        let handle = window.as_weak();
        slint::Timer::single_shot(Duration::from_millis(60), move || {
            let Some(window) = handle.upgrade() else {
                return;
            };
            match create_account() {
                // The daemon was started without an identity, so it has to be restarted onto the
                // one that now exists. The new process opens this window on Status.
                Ok(()) => restart_self(Welcome::Created),
                Err(err) => {
                    eprintln!("{}", log_line("create_failed", &err.to_string()));
                    window.set_creating(false);
                    window.set_create_error(err.to_string().into());
                }
            }
        });
    });

    let handle = window.as_weak();
    window.on_check_token(move |raw| {
        if let Some(window) = handle.upgrade() {
            window.set_join_error(String::new().into());
            window.set_join_check(check_token(raw.as_str()));
        }
    });

    let handle = window.as_weak();
    window.on_join_account(move |raw| {
        let Some(window) = handle.upgrade() else {
            return;
        };
        window.set_join_error(String::new().into());
        window.set_join_busy(true);
        let handle = window.as_weak();
        slint::Timer::single_shot(Duration::from_millis(60), move || {
            let Some(window) = handle.upgrade() else {
                return;
            };
            match join_account(raw.as_str()) {
                Ok(room_id) => {
                    eprintln!("{}", log_line("joined", &format!("room {room_id}")));
                    restart_self(Welcome::Joined);
                }
                Err(err) => {
                    window.set_join_busy(false);
                    let reason = err.to_string();
                    eprintln!("{}", log_line("join_failed", &reason));
                    window.set_join_error(format!("Couldn't join: {reason}").into());
                }
            }
        });
    });
}

/// Attaches the title bar's controls. The window has no frame from the desktop, so moving,
/// minimising and maximising it are ours to do.
fn wire_frame(window: &AppWindow) {
    use slint::winit_030::WinitWindowAccessor as _;

    let handle = window.as_weak();
    window.on_start_drag(move |x, y| {
        if let Some(window) = handle.upgrade() {
            window.window().with_winit_window(|winit| {
                // Refused only when the pointer is not actually pressed, which is harmless.
                let _ = winit.drag_window();
            });
            // The desktop takes the pointer for the move and never reports the release to us.
            // Without one, the title bar kept the pointer grabbed after the move ended, and
            // every later click anywhere in the window landed on it and started another drag.
            window
                .window()
                .dispatch_event(slint::platform::WindowEvent::PointerReleased {
                    position: slint::LogicalPosition::new(x, y),
                    button: slint::platform::PointerEventButton::Left,
                });
        }
    });

    // Minimise goes to the tray, like close: the tray is where this application lives, and a
    // minimised window only sat in the taskbar as a second way back to the same place.
    window.on_minimize_window(hide);

    let handle = window.as_weak();
    window.on_toggle_maximize(move || {
        if let Some(window) = handle.upgrade() {
            let maximized = window
                .window()
                .with_winit_window(|winit| {
                    let wanted = !winit.is_maximized();
                    winit.set_maximized(wanted);
                    wanted
                })
                .unwrap_or(false);
            window.set_is_maximized(maximized);
        }
    });
}

/// Follows a maximise made by the desktop rather than by our button, such as a double click or
/// a keyboard shortcut, so the corners and the edge match.
fn track_maximized(window: &AppWindow) {
    use slint::winit_030::WinitWindowAccessor as _;
    if let Some(maximized) = window
        .window()
        .with_winit_window(slint::winit_030::winit::window::Window::is_maximized)
    {
        if window.get_is_maximized() != maximized {
            window.set_is_maximized(maximized);
        }
    }
}

/// Builds the window and attaches every callback.
fn build() -> Result<AppWindow> {
    // The Wayland app id, declared once, here rather than in `install`.
    //
    // It has to land after the toolkit's platform is initialised and before the first surface is
    // created. `install` runs too early: there is no platform yet, the call fails with "no Slint
    // platform was initialized", and the surface then announces no app id at all. A compositor
    // with no name to match cannot find the installed desktop entry, and the window falls back to
    // a generic icon whatever the icon theme holds.
    //
    // Once per process, because only the first window's surface reads it.
    static APP_ID_ONCE: std::sync::Once = std::sync::Once::new();
    APP_ID_ONCE.call_once(|| {
        if let Err(err) = slint::set_xdg_app_id(APP_ID) {
            // Never fatal. Elsewhere this is unnecessary or unsupported, and a window wearing the
            // wrong icon is worth strictly more than no window.
            eprintln!("{}", log_line("app_id_failed", &err.to_string()));
        }
    });

    let window = AppWindow::new().map_err(|err| Error::ConfigDir(err.to_string()))?;
    window.set_ui_font(ui_font().into());

    let handle = window.as_weak();
    window.on_open_screen(move |screen| {
        if let Some(window) = handle.upgrade() {
            refresh(&window);
            if screen == Screen::Join {
                // A fresh form each time, not whatever was left in it last time.
                window.set_join_input(String::new().into());
                window.set_join_check(check_token(""));
                window.set_join_error(String::new().into());
            }
            window.set_screen(screen);
        }
    });

    window.on_hide_window(hide);

    wire_account(&window);
    wire_frame(&window);

    window.on_copy_token(copy_token);
    window.on_restore_entry(restore_entry);
    window.on_copy_entry(copy_entry);
    window.on_forget_entry(forget_entry);
    window.on_clear_history(clear_history);
    window.on_set_paused(set_paused);
    window.on_retry_now(retry_now);
    window.on_request_retained(request_retained);
    window.on_copy_diagnostics(copy_diagnostics);

    let handle = window.as_weak();
    window.on_save_settings(move || {
        if let Some(window) = handle.upgrade() {
            save_settings(&window);
        }
    });

    let handle = window.as_weak();
    window.on_revert_settings(move || {
        if let Some(window) = handle.upgrade() {
            load_settings(&window);
        }
    });

    // The switches apply immediately. A switch that needs a separate save does not feel like a
    // switch, and these three are all cheap and reversible.
    let handle = window.as_weak();
    window.on_set_notifications(move |on| {
        if let Some(window) = handle.upgrade() {
            apply(&window, |config| config.notifications = on);
            if let Some(context) = CONTEXT.get() {
                context
                    .controls
                    .settings
                    .notifications
                    .store(on, std::sync::atomic::Ordering::Relaxed);
            }
        }
    });

    let handle = window.as_weak();
    window.on_set_autostart(move |on| {
        let Some(window) = handle.upgrade() else {
            return;
        };
        // Reported rather than assumed: the stored preference and the actual entry disagree
        // exactly when something went wrong, which is the moment it matters.
        match crate::autostart::set_enabled(on) {
            Ok(()) => {
                apply(&window, |config| config.autostart = on);
                window.set_autostart_detail(
                    crate::autostart::describe_location()
                        .unwrap_or_else(|err| err.to_string())
                        .into(),
                );
            }
            Err(err) => {
                window.set_autostart(!on);
                window.set_autostart_detail(format!("could not change this: {err}").into());
            }
        }
    });

    let handle = window.as_weak();
    window.on_set_keep_history(move |on| {
        let Some(window) = handle.upgrade() else {
            return;
        };
        apply(&window, |config| config.keep_history = on);
        with_history(|history| history.set_enabled(on));
        refresh_history(&window);
    });

    // Closing with the title bar button hides rather than quits, for the same reason Escape does.
    let handle = window.as_weak();
    window.window().on_close_requested(move || {
        let _ = handle;
        hide();
        slint::CloseRequestResponse::HideWindow
    });

    load_settings(&window);
    Ok(window)
}

// ---------------------------------------------------------------------------------------------
// Filling the screens
// ---------------------------------------------------------------------------------------------

/// Refreshes everything that does not change on a timer.
fn refresh(window: &AppWindow) {
    let Some(context) = CONTEXT.get() else {
        return;
    };

    let account = secrets::load(&context.paths).ok().flatten();
    window.set_has_account(account.is_some());

    if let Some((secret, _)) = &account {
        let identity = Identity::from_secret(secret);
        window.set_room_id(short(&identity.room_id()).into());

        let token = token::encode(secret);
        window.set_token(token.as_str().into());
        match qr_image(token.as_str()) {
            Ok(image) => window.set_qr(image),
            Err(err) => eprintln!("{}", log_line("qr_failed", &err.to_string())),
        }
    } else {
        window.set_token(String::new().into());
        window.set_room_id(String::new().into());
    }

    if let Ok(config) = context.paths.load_config() {
        window.set_device_id(short(&config.device_id).into());
        window.set_relay_url_live(config.relay_url.clone().into());
    }
    window.set_clipboard_backend(context.io.describe().into());

    refresh_history(window);
    refresh_status(window);
}

/// How the connection is shown: the state that colours everything, its label and one line of
/// detail.
#[derive(Debug, Clone, PartialEq)]
struct Presented {
    state: SyncState,
    label: String,
    detail: String,
    connections: String,
}

/// Turns what the daemon believes into what the Status screen, the sidebar and the History
/// banner say. Pure, so every state can be tested without a window.
fn present(status: &Status, paused: bool, relay_host: &str, now_ms: u64) -> Presented {
    let devices = |n: u32| {
        if n == 1 {
            "1 device".to_owned()
        } else {
            format!("{n} devices")
        }
    };
    if paused {
        return Presented {
            state: SyncState::Offline,
            label: "Paused".to_owned(),
            detail: "Paused by you. Nothing is sent or received until you resume.".to_owned(),
            connections: devices(status.peers),
        };
    }
    let state = status.state.as_str();
    if state == "Synced" {
        let online = match status.peers {
            0 | 1 => "Only this device is online".to_owned(),
            n => format!("{} online", devices(n)),
        };
        let last = match status.last_sync_ms {
            Some(_) => format!(
                "last clip {}",
                tray::relative_time(status.last_sync_ms, now_ms)
            ),
            None => "no clips yet".to_owned(),
        };
        return Presented {
            state: SyncState::Connected,
            label: "Synced".to_owned(),
            detail: format!("{online} \u{b7} {last}"),
            connections: devices(status.peers.max(1)),
        };
    }
    if state == "Connecting" && status.attempt <= 1 {
        return Presented {
            state: SyncState::Connecting,
            label: "Connecting\u{2026}".to_owned(),
            detail: format!("Reaching {relay_host}"),
            connections: "negotiating\u{2026}".to_owned(),
        };
    }
    if state == "Connecting" {
        return Presented {
            state: SyncState::Connecting,
            label: "Connecting\u{2026}".to_owned(),
            detail: format!("Reaching {relay_host}, attempt {}", status.attempt),
            connections: "negotiating\u{2026}".to_owned(),
        };
    }
    if let Some(reason) = state
        .strip_prefix("Rejected: ")
        .or_else(|| state.strip_prefix("Stopped: "))
    {
        return Presented {
            state: SyncState::Error,
            label: "Stopped syncing".to_owned(),
            detail: format!("{reason}. Restart Asli after fixing this."),
            connections: devices(0),
        };
    }
    let retry = status.retry_at_ms.map_or_else(String::new, |at| {
        let seconds = at.saturating_sub(now_ms).div_ceil(1000);
        if seconds == 0 {
            " Retrying now.".to_owned()
        } else {
            format!(" Retrying in {seconds}s.")
        }
    });
    Presented {
        state: SyncState::Error,
        label: "Connection failed".to_owned(),
        detail: format!("Couldn't reach {relay_host}.{retry}"),
        connections: devices(0),
    }
}

/// Refreshes the parts the daemon changes underneath us.
fn refresh_status(window: &AppWindow) {
    let Some(context) = CONTEXT.get() else {
        return;
    };
    let status = context.controls.status.get();
    let paused = context.controls.is_paused();
    let now = asli_net::client::now_ms();
    let config = context.paths.load_config().ok();
    let relay_host = config
        .as_ref()
        .map_or_else(String::new, |config| host_of(&config.relay_url));

    let shown = present(&status, paused, &relay_host, now);
    window.set_sync_state(shown.state);
    window.set_state_label(shown.label.into());
    window.set_state_detail(shown.detail.into());
    window.set_paused(paused);
    window.set_stat_connections(shown.connections.into());
    window.set_stat_last_sync(tray::relative_time(status.last_sync_ms, now).into());
    window.set_stat_skipped(
        match status.skipped {
            0 => "0".to_owned(),
            1 => "1 clip".to_owned(),
            n => format!("{n} clips"),
        }
        .into(),
    );
    window.set_has_retained(status.has_retained && !paused);

    let Some(config) = config else {
        return;
    };
    // Connected, whether or not sync is paused: a paused device still holds its connection.
    let connected = status.state == "Synced";
    let this = crate::devices::Listed {
        id: config.device_id.clone(),
        name: crate::devices::display_name(&config.device_name),
        os: crate::devices::this_os(),
        last_seen_ms: None,
        online: connected,
        this_device: true,
    };
    let rows: Vec<DeviceRow> = context
        .controls
        .devices
        .list(&this)
        .into_iter()
        .map(|device| DeviceRow {
            name: device.name.into(),
            os: device.os.into(),
            id: short(&device.id).into(),
            seen: if device.online {
                "now".to_owned()
            } else if device.this_device {
                "offline".to_owned()
            } else {
                tray::relative_time(device.last_seen_ms, now)
            }
            .into(),
            online: device.online,
            this_device: device.this_device,
        })
        .collect();
    set_rows(&window.get_devices(), rows, |model| {
        window.set_devices(model);
    });
}

/// Replaces a list's rows in place when only their contents changed, so a redraw every second
/// does not rebuild the list under the pointer.
fn set_rows<T: Clone + PartialEq + 'static>(
    current: &ModelRc<T>,
    rows: Vec<T>,
    replace: impl FnOnce(ModelRc<T>),
) {
    if current.row_count() == rows.len() {
        for (index, row) in rows.into_iter().enumerate() {
            if current.row_data(index).as_ref() != Some(&row) {
                current.set_row_data(index, row);
            }
        }
    } else {
        replace(ModelRc::new(VecModel::from(rows)));
    }
}

thread_local! {
    /// The history revision the list was last drawn from, and when. Main thread only.
    static HISTORY_DRAWN: std::cell::Cell<Option<(u64, std::time::Instant)>> =
        const { std::cell::Cell::new(None) };

    /// Decoded thumbnails and image sizes, by entry, so an image is decoded once rather than on
    /// every redraw. Main thread only, and dropped with the entries it describes.
    static THUMBNAILS: RefCell<std::collections::HashMap<[u8; 16], Thumbnail>> =
        RefCell::new(std::collections::HashMap::new());
}

/// An image entry's thumbnail and its size in pixels.
#[derive(Clone)]
struct Thumbnail {
    image: Option<Image>,
    width: u32,
    height: u32,
}

/// Redraws the list when the history changed since it was drawn, and every half minute anyway,
/// because each row says how long ago it was copied and "just now" goes stale by itself.
fn refresh_history_if_stale(window: &AppWindow) {
    const AGES: Duration = Duration::from_secs(30);
    let Some(context) = CONTEXT.get() else {
        return;
    };
    let Some(revision) = context
        .history
        .lock()
        .ok()
        .map(|history| history.revision())
    else {
        return;
    };
    match HISTORY_DRAWN.get() {
        Some((drawn, at)) if drawn == revision => {
            // Nothing new, only older: the rows are rewritten in place rather than the list
            // rebuilt under somebody who has scrolled down it.
            if at.elapsed() >= AGES {
                refresh_history(window);
            }
        }
        _ => refresh_history(window),
    }
}

/// Rebuilds the history list.
fn refresh_history(window: &AppWindow) {
    let Some(context) = CONTEXT.get() else {
        return;
    };
    let (enabled, revision, entries) = {
        let Ok(history) = context.history.lock() else {
            return;
        };
        (history.enabled(), history.revision(), history.entries())
    };

    window.set_history_enabled(enabled);
    HISTORY_DRAWN.set(Some((revision, std::time::Instant::now())));

    let own = context
        .paths
        .load_config()
        .ok()
        .and_then(|config| config.device_id_bytes().ok());
    let now = asli_net::client::now_ms();

    // Thumbnails for entries that are gone are dropped with them.
    THUMBNAILS.with_borrow_mut(|cache| {
        cache.retain(|key, _| entries.iter().any(|entry| entry.key == *key));
    });

    let rows: Vec<HistoryRow> = entries
        .iter()
        .enumerate()
        .map(|(index, entry)| {
            let source = if entry.from == [0u8; 16] {
                None
            } else if Some(entry.from) == own {
                Some("from this device".to_owned())
            } else {
                Some(format!(
                    "from {}",
                    context
                        .controls
                        .devices
                        .name_of(&entry.from)
                        .unwrap_or_else(|| "another device".to_owned())
                ))
            };
            let thumbnail = entry.is_image.then(|| thumbnail(context, index, entry.key));
            let mut meta = vec![
                tray::relative_time(Some(entry.ts_ms), now),
                human_bytes(entry.bytes),
            ];
            if let Some(thumbnail) = &thumbnail {
                if thumbnail.width > 0 {
                    meta.push(format!("{} \u{d7} {}", thumbnail.width, thumbnail.height));
                }
            }
            meta.extend(source);
            let preview = if entry.is_image {
                "Image".to_owned()
            } else {
                entry.preview.clone()
            };
            HistoryRow {
                mono: !entry.is_image && looks_like_code(&preview),
                preview: preview.into(),
                meta: meta.join(" \u{b7} ").into(),
                is_image: entry.is_image,
                has_thumb: thumbnail.as_ref().is_some_and(|t| t.image.is_some()),
                thumb: thumbnail.and_then(|t| t.image).unwrap_or_default(),
            }
        })
        .collect();

    let empty = rows.is_empty();
    set_rows(&window.get_history(), rows, |model| {
        window.set_history(model);
    });
    window.set_history_note(
        if enabled && !empty {
            "Stored on this device only, encrypted with your account key."
        } else {
            ""
        }
        .into(),
    );
}

/// An image entry's thumbnail, from the cache or decoded now.
fn thumbnail(context: &Context, index: usize, key: [u8; 16]) -> Thumbnail {
    if let Some(cached) = THUMBNAILS.with_borrow(|cache| cache.get(&key).cloned()) {
        return cached;
    }
    let png = context
        .history
        .lock()
        .ok()
        .and_then(|history| history.restore(index));
    let made = match png {
        Some(HistoryContent::ImagePng(png)) => make_thumbnail(&png),
        _ => Thumbnail {
            image: None,
            width: 0,
            height: 0,
        },
    };
    THUMBNAILS.with_borrow_mut(|cache| cache.insert(key, made.clone()));
    made
}

/// Decodes a PNG and shrinks it to a square thumbnail, cropped to fill like the design's cover.
fn make_thumbnail(png: &[u8]) -> Thumbnail {
    // Twice the 50 px it is drawn at, for high density displays.
    const SIDE: u32 = 100;
    let failed = Thumbnail {
        image: None,
        width: 0,
        height: 0,
    };
    let mut decoder = png::Decoder::new(std::io::Cursor::new(png));
    decoder.set_transformations(png::Transformations::normalize_to_color8());
    let Ok(mut reader) = decoder.read_info() else {
        return failed;
    };
    let Some(size) = reader.output_buffer_size() else {
        return failed;
    };
    let mut buffer = vec![0u8; size];
    let Ok(frame) = reader.next_frame(&mut buffer) else {
        return failed;
    };
    let (width, height) = (frame.width, frame.height);
    let channels = match frame.color_type {
        png::ColorType::Rgba => 4,
        png::ColorType::Rgb => 3,
        png::ColorType::GrayscaleAlpha => 2,
        _ => 1,
    };
    if width == 0 || height == 0 {
        return failed;
    }

    // The largest centred square, sampled down by averaging each target pixel's block.
    let crop = width.min(height);
    let (left, top) = ((width - crop) / 2, (height - crop) / 2);
    let mut out = SharedPixelBuffer::<Rgba8Pixel>::new(SIDE, SIDE);
    let line = frame.line_size;
    for (i, pixel) in out.make_mut_slice().iter_mut().enumerate() {
        let (tx, ty) = (
            u32::try_from(i).unwrap_or(0) % SIDE,
            u32::try_from(i).unwrap_or(0) / SIDE,
        );
        let (x0, x1) = (
            left + tx * crop / SIDE,
            left + ((tx + 1) * crop / SIDE).max(tx * crop / SIDE + 1),
        );
        let (y0, y1) = (
            top + ty * crop / SIDE,
            top + ((ty + 1) * crop / SIDE).max(ty * crop / SIDE + 1),
        );
        // At most a few samples per axis: a thumbnail needs no more, and a huge screenshot
        // must not stall the window.
        let step_x = ((x1 - x0) / 4).max(1);
        let step_y = ((y1 - y0) / 4).max(1);
        let (mut sum, mut count) = ([0u32; 4], 0u32);
        let mut y = y0;
        while y < y1.min(height) {
            let mut x = x0;
            while x < x1.min(width) {
                let at = y as usize * line + x as usize * channels;
                let px = &buffer[at..at + channels];
                let rgba = match channels {
                    4 => [px[0], px[1], px[2], px[3]],
                    3 => [px[0], px[1], px[2], 255],
                    2 => [px[0], px[0], px[0], px[1]],
                    _ => [px[0], px[0], px[0], 255],
                };
                for (total, value) in sum.iter_mut().zip(rgba) {
                    *total += u32::from(value);
                }
                count += 1;
                x += step_x;
            }
            y += step_y;
        }
        let count = count.max(1);
        let avg = |c: usize| u8::try_from(sum[c] / count).unwrap_or(255);
        *pixel = Rgba8Pixel {
            r: avg(0),
            g: avg(1),
            b: avg(2),
            a: avg(3),
        };
    }
    round_corners(&mut out, 18.0);
    Thumbnail {
        image: Some(Image::from_rgba8(out)),
        width,
        height,
    }
}

/// Makes a thumbnail's corners transparent, antialiased, to the design's 9 px at 50 px.
///
/// The window cannot do this itself: the software renderer clips to a rectangle and ignores the
/// corner radius, so a thumbnail inside a rounded frame kept its square corners.
fn round_corners(image: &mut SharedPixelBuffer<Rgba8Pixel>, radius: f32) {
    let columns = image.width();
    #[allow(clippy::cast_precision_loss)]
    let (right, bottom) = (columns as f32, image.height() as f32);
    for (index, pixel) in image.make_mut_slice().iter_mut().enumerate() {
        let index = u32::try_from(index).unwrap_or(0);
        #[allow(clippy::cast_precision_loss)]
        let (px, py) = (
            (index % columns) as f32 + 0.5,
            (index / columns) as f32 + 0.5,
        );
        let dx = (radius - px).max(px - (right - radius)).max(0.0);
        let dy = (radius - py).max(py - (bottom - radius)).max(0.0);
        // Coverage across the last pixel of the curve, for a smooth edge.
        let coverage = (radius + 0.5 - dx.hypot(dy)).clamp(0.0, 1.0);
        if coverage < 1.0 {
            // The buffer is not premultiplied, so only alpha is scaled.
            #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
            let alpha = (f32::from(pixel.a) * coverage).round() as u8;
            pixel.a = alpha;
        }
    }
}

/// Whether a clip reads better in the monospaced face: a URL, a path, or a line of code.
fn looks_like_code(text: &str) -> bool {
    let text = text.trim();
    text.contains("://")
        || text.starts_with('/')
        || text.starts_with("~/")
        || (text.len() > 2 && text.as_bytes()[1] == b':' && text.as_bytes()[2] == b'\\')
        || text.ends_with(';')
        || text.ends_with('{')
        || text.starts_with("$ ")
}

/// Loads configuration into the Settings screen.
fn load_settings(window: &AppWindow) {
    let Some(context) = CONTEXT.get() else {
        return;
    };
    let Ok(config) = context.paths.load_config() else {
        return;
    };

    window.set_relay_url(config.relay_url.clone().into());
    window.set_saved_relay_url(config.relay_url.clone().into());
    let name = crate::devices::display_name(&config.device_name);
    window.set_device_name(name.clone().into());
    window.set_saved_device_name(name.into());
    window.set_notifications(config.notifications);
    window.set_keep_history(config.keep_history);

    let (cap_index, exact) = nearest_cap(config.max_content_bytes);
    window.set_size_cap_index(cap_index);
    window.set_saved_size_cap_index(cap_index);
    let retention = nearest_retention(config.history_entries);
    window.set_retention_index(retention);
    window.set_saved_retention_index(retention);

    window.set_settings_note(
        if exact {
            String::new()
        } else {
            // A configuration edited by hand can hold a size this list cannot express. Silently
            // rounding it on the next save would change behaviour nobody asked to change.
            format!(
                "The size cap in the file is {}, which is not one of these. Saving changes it to {}.",
                human_bytes(config.max_content_bytes),
                SIZE_CAPS[usize::try_from(cap_index).unwrap_or(0)].1
            )
        }
        .into(),
    );

    // Reported from the system, not from the file, for the same reason the command line does it.
    window.set_autostart(crate::autostart::is_enabled().unwrap_or(config.autostart));
    window.set_autostart_detail(
        crate::autostart::describe_location()
            .unwrap_or_else(|err| err.to_string())
            .into(),
    );
}

/// Writes the Settings screen back to the configuration file.
fn save_settings(window: &AppWindow) {
    let relay = window.get_relay_url().trim().to_owned();
    let cap = SIZE_CAPS[usize::try_from(window.get_size_cap_index())
        .unwrap_or(1)
        .min(3)]
    .0;
    let retention_index = window.get_retention_index();
    let entries = RETENTIONS[usize::try_from(retention_index).unwrap_or(2).min(3)];
    // Stored empty when it is the computer's own name, so renaming the computer renames this.
    let typed = window.get_device_name().trim().to_owned();
    let name = if typed == crate::devices::default_name() {
        String::new()
    } else {
        typed.chars().take(64).collect()
    };

    let mut relay_changed = false;
    let mut name_changed = false;
    let mut limit_changed = false;
    apply(window, |config| {
        relay_changed = config.relay_url != relay;
        name_changed = config.device_name != name;
        limit_changed = config.history_entries != entries;
        relay.clone_into(&mut config.relay_url);
        config.max_content_bytes = cap;
        config.history_entries = entries;
        config.device_name.clone_from(&name);
    });

    if let Some(context) = CONTEXT.get() {
        let live = &context.controls.settings;
        live.max_content_bytes
            .store(cap, std::sync::atomic::Ordering::Relaxed);
        if relay_changed {
            live.reconnect
                .store(true, std::sync::atomic::Ordering::Relaxed);
        }
        if name_changed {
            live.announce
                .store(true, std::sync::atomic::Ordering::Relaxed);
        }
    }
    with_history(|history| history.set_limit(entries));

    let shown_name = crate::devices::display_name(&name);
    window.set_relay_url(relay.clone().into());
    window.set_saved_relay_url(relay.into());
    window.set_device_name(shown_name.clone().into());
    window.set_saved_device_name(shown_name.into());
    window.set_saved_size_cap_index(window.get_size_cap_index());
    window.set_saved_retention_index(retention_index);
    window.invoke_settings_saved();

    // Stated because it is true and not obvious. A setting that claims to have applied when it
    // has not is how a person concludes the application ignores them.
    window.set_settings_note(
        match (relay_changed, limit_changed) {
            (true, true) => {
                "Reconnecting to the new relay now. The history length applies when Asli next \
                 starts."
            }
            (true, false) => "Reconnecting to the new relay now.",
            (false, true) => "The history length applies when Asli next starts.",
            (false, false) => "",
        }
        .into(),
    );
    refresh_status(window);
}

/// Reads, changes and writes the configuration, reporting a failure rather than losing it.
fn apply(window: &AppWindow, change: impl FnOnce(&mut Config)) {
    let Some(context) = CONTEXT.get() else {
        return;
    };
    let Ok(mut config) = context.paths.load_config() else {
        window.set_settings_note("Could not read the configuration file.".into());
        return;
    };

    change(&mut config);

    if let Err(err) = context.paths.save_config(&config) {
        eprintln!("{}", log_line("settings_failed", &err.to_string()));
        window.set_settings_note(format!("Could not save: {err}").into());
    }
}

// ---------------------------------------------------------------------------------------------
// The actions behind the buttons
// ---------------------------------------------------------------------------------------------

/// Creates an account on this device.
fn create_account() -> Result<()> {
    let context = CONTEXT.get().ok_or(Error::NoAccount)?;
    // Never over an account that exists, or one that may exist behind a locked keychain. First run
    // is the only screen that offers this, and it can be shown while the keychain is unreadable.
    if secrets::load(&context.paths)?.is_some() {
        return Err(Error::AccountExists);
    }
    let identity = Identity::generate()?;
    secrets::store(&context.paths, identity.secret())?;
    eprintln!(
        "{}",
        log_line("created", &format!("room {}", identity.room_id()))
    );
    Ok(())
}

/// Stores the account behind a join string, returning the room it belongs to.
fn join_account(raw: &str) -> Result<String> {
    let context = CONTEXT.get().ok_or(Error::NoAccount)?;
    let secret = token::parse(raw.trim())?;
    let identity = Identity::from_secret(&secret);
    secrets::store(&context.paths, identity.secret())?;
    // The devices of the account this one is leaving mean nothing in the new one.
    context.controls.devices.clear();
    Ok(identity.room_id())
}

/// What the join field says about what has been typed so far.
///
/// The parser distinguishes a wrong prefix from a bad checksum from a truncated string, so the
/// field names the mistake that was actually made. "Invalid" would leave a person retyping a
/// string that was never the problem.
fn check_token(raw: &str) -> TokenCheck {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return TokenCheck {
            valid: false,
            invalid: false,
            message: String::new().into(),
        };
    }

    match token::parse(trimmed) {
        Ok(_) => TokenCheck {
            valid: true,
            invalid: false,
            message: "This is a valid join string.".into(),
        },
        Err(err) => TokenCheck {
            valid: false,
            invalid: true,
            message: explain(&err).into(),
        },
    }
}

/// Turns a parse failure into something worth reading.
fn explain(err: &asli_crypto::Error) -> String {
    match err {
        asli_crypto::Error::TokenPrefix => {
            "This does not look like an Asli join string. It should start with asli1_.".to_owned()
        }
        asli_crypto::Error::TokenLength => {
            "This looks cut off. Copy the whole string, including the end.".to_owned()
        }
        asli_crypto::Error::TokenAlphabet => {
            "There are characters here that cannot appear in a join string. Copy it again rather \
             than typing it."
                .to_owned()
        }
        asli_crypto::Error::TokenChecksum => {
            "This is mistyped or incomplete. One character somewhere is wrong.".to_owned()
        }
        asli_crypto::Error::TokenVersion(version) => format!(
            "This join string is format version {version}, which this version of Asli does not \
             understand. Update Asli on both devices."
        ),
        other => other.to_string(),
    }
}

/// Copies the join string, marked so clipboard history and cloud sync leave it alone.
fn copy_token() {
    let Some(context) = CONTEXT.get() else {
        return;
    };
    let Ok(Some((secret, _))) = secrets::load(&context.paths) else {
        toast("No account on this device yet", false);
        return;
    };

    let token = token::encode(&secret);
    match context
        .io
        .write_text_concealed(token.as_str(), TOKEN_CLEAR_AFTER)
    {
        Ok(()) => {
            eprintln!(
                "{}",
                log_line("token_copied", "marked as concealed, clears in 90 seconds")
            );
            WINDOW.with_borrow(|window| {
                if let Some(window) = window.as_ref() {
                    window.invoke_token_was_copied();
                }
            });
            toast(
                "Copied. It clears itself from the clipboard in 90 seconds.",
                true,
            );
        }
        Err(err) => {
            eprintln!("{}", log_line("token_copy_failed", &err.to_string()));
            toast(&format!("Couldn't copy: {err}"), false);
        }
    }
}

/// Puts a history entry back on the clipboard, which syncs it to every device.
///
/// Written as a copy, not as an arrival. An arrival must not go back out, but putting an old clip
/// back on every device is the entire point of this screen, and the watcher cannot be relied on
/// to report it: every platform recognises our own writes and ignores them.
fn restore_entry(index: i32) {
    put_back(index, true);
}

/// Puts a history entry on this device's clipboard only, without sending it anywhere.
fn copy_entry(index: i32) {
    put_back(index, false);
}

/// The two ways back onto the clipboard: to every device, or to this one alone.
fn put_back(index: i32, everywhere: bool) {
    let Some(context) = CONTEXT.get() else {
        return;
    };
    let Ok(index) = usize::try_from(index) else {
        return;
    };

    let clip = context
        .history
        .lock()
        .ok()
        .and_then(|history| history.restore(index));

    let Some(clip) = clip else {
        toast("That entry is no longer there", false);
        return;
    };

    let result = match (&clip, everywhere) {
        (HistoryContent::Text(text), true) => context.io.write_text_as_copy(text),
        (HistoryContent::ImagePng(png), true) => context.io.write_image_as_copy(png),
        (HistoryContent::Text(text), false) => context.io.write_text(text),
        (HistoryContent::ImagePng(png), false) => context.io.write_image(png),
    };

    match result {
        // Never the content, only its size. A log line holding a clip would put every copied
        // password into the journal.
        Ok(()) => {
            eprintln!(
                "{}",
                log_line(
                    if everywhere {
                        "restored"
                    } else {
                        "copied_locally"
                    },
                    &match &clip {
                        HistoryContent::Text(text) => format!("text, {}", human_bytes(text.len())),
                        HistoryContent::ImagePng(png) => {
                            format!("image, {}", human_bytes(png.len()))
                        }
                    }
                )
            );
            let paused = context.controls.is_paused();
            toast(
                match (everywhere, paused) {
                    (true, false) => "Sent to your devices",
                    (true, true) => "Copied here. Sync is paused, so it went nowhere else.",
                    (false, _) => "Copied on this device",
                },
                true,
            );
        }
        Err(err) => {
            eprintln!("{}", log_line("restore_failed", &err.to_string()));
            toast(&format!("Couldn't copy that: {err}"), false);
        }
    }
}

/// Forgets one entry.
fn forget_entry(index: i32) {
    let Ok(index) = usize::try_from(index) else {
        return;
    };
    with_history(|history| {
        history.forget(index);
    });
    WINDOW.with_borrow(|window| {
        if let Some(window) = window.as_ref() {
            refresh_history(window);
        }
    });
}

/// Forgets everything.
fn clear_history() {
    with_history(|history| history.clear());
    WINDOW.with_borrow(|window| {
        if let Some(window) = window.as_ref() {
            refresh_history(window);
        }
    });
    toast("History cleared", true);
}

/// Pauses or resumes syncing.
fn set_paused(paused: bool) {
    let Some(context) = CONTEXT.get() else {
        return;
    };
    context
        .controls
        .paused
        .store(paused, std::sync::atomic::Ordering::Relaxed);
    eprintln!(
        "{}",
        log_line(if paused { "paused" } else { "resumed" }, "from the window")
    );
    // The window shows it, so no notification on top.
    WINDOW.with_borrow(|window| {
        if let Some(window) = window.as_ref() {
            refresh_status(window);
        }
    });
}

/// Cuts the wait before the next connection attempt short.
fn retry_now() {
    let Some(context) = CONTEXT.get() else {
        return;
    };
    let state = context.controls.status.get().state;
    if state.starts_with("Stopped") || state.starts_with("Rejected") {
        toast(
            "Syncing stopped for good. Restart Asli to try again.",
            false,
        );
        return;
    }
    context
        .controls
        .settings
        .reconnect
        .store(true, std::sync::atomic::Ordering::Relaxed);
    toast("Retrying now", true);
}

/// Asks the daemon for the clip the relay is holding.
fn request_retained() {
    let Some(context) = CONTEXT.get() else {
        return;
    };
    if context.controls.status.get().has_retained {
        context.controls.request_retained();
        eprintln!("{}", log_line("paste_retained", "requested from the relay"));
        toast("Fetching the stored clip", true);
    } else {
        toast("The relay has nothing new for this device", false);
    }
}

/// Copies diagnostics, which is the only text this application writes that it did not receive.
fn copy_diagnostics() {
    let Some(context) = CONTEXT.get() else {
        return;
    };
    let Ok(config) = context.paths.load_config() else {
        return;
    };

    let text = tray::diagnostics(&config, &context.controls.status.get(), &context.paths);
    if let Err(err) = context.io.write_text(&text) {
        eprintln!("{}", log_line("diagnostics_failed", &err.to_string()));
        toast(&format!("Couldn't copy diagnostics: {err}"), false);
    } else {
        toast("Diagnostics copied", true);
    }
}

/// Why the process restarted itself, so the new one can open the window and say so.
#[derive(Debug, Clone, Copy)]
enum Welcome {
    Created,
    Joined,
}

/// Set on the restarted process, naming what just happened. Read once at startup.
pub const WELCOME_ENV: &str = "ASLI_WELCOME";

/// Opens the window on Status after a restart onto a new account, with a line saying what
/// happened. Does nothing on an ordinary start.
pub fn welcome_after_restart() {
    let Some(reason) = std::env::var_os(WELCOME_ENV) else {
        return;
    };
    // Not passed on to anything this process starts later.
    std::env::remove_var(WELCOME_ENV);
    let text = match reason.to_str() {
        Some("created") => "Account created. Add your other devices with the join string.",
        Some("joined") => "Joined. Syncing starts as soon as the relay answers.",
        _ => return,
    };
    let _ = slint::invoke_from_event_loop(move || {
        show(Screen::Status);
        toast(text, true);
    });
}

/// Restarts this process so the daemon picks up the account that was just stored.
///
/// The daemon takes its identity by value and the connection holds a session built from it, so
/// there is no way to swap accounts on a live connection. Rather than leave somebody wondering
/// why nothing happened, the process replaces itself, and the new one opens this window again.
#[cfg(unix)]
fn restart_self(welcome: Welcome) {
    use std::os::unix::process::CommandExt as _;

    let Ok(exe) = std::env::current_exe() else {
        eprintln!(
            "{}",
            log_line("restart_failed", "could not find this executable")
        );
        return;
    };
    let args: Vec<String> = std::env::args().skip(1).collect();

    eprintln!("{}", log_line("restarting", "onto the account just stored"));
    // exec replaces the image, so nothing after this runs unless it failed.
    let err = std::process::Command::new(exe)
        .args(args)
        .env(crate::instance::RESTART_ENV, "1")
        .env(WELCOME_ENV, welcome.as_str())
        .exec();
    eprintln!("{}", log_line("restart_failed", &err.to_string()));
}

/// Windows has no `exec`, so the replacement is started as a new process and this one exits.
///
/// The replacement waits for the single instance lock, which this process holds until it is gone,
/// because [`crate::instance::RESTART_ENV`] tells it a handover is under way.
#[cfg(not(unix))]
fn restart_self(welcome: Welcome) {
    let Ok(exe) = std::env::current_exe() else {
        eprintln!(
            "{}",
            log_line("restart_failed", "could not find this executable")
        );
        return;
    };
    let args: Vec<String> = std::env::args().skip(1).collect();

    eprintln!("{}", log_line("restarting", "onto the account just stored"));
    match std::process::Command::new(exe)
        .args(args)
        .env(crate::instance::RESTART_ENV, "1")
        .env(WELCOME_ENV, welcome.as_str())
        .spawn()
    {
        Ok(_) => crate::cli::exit_removing_tray(0),
        Err(err) => {
            eprintln!("{}", log_line("restart_failed", &err.to_string()));
            notify::action_failed("Restart Asli to use the new account", &err.to_string());
        }
    }
}

impl Welcome {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Created => "created",
            Self::Joined => "joined",
        }
    }
}

// ---------------------------------------------------------------------------------------------
// Small shared pieces
// ---------------------------------------------------------------------------------------------

/// Runs something against the history, doing nothing if the lock is poisoned.
fn with_history(action: impl FnOnce(&mut (dyn HistorySource + Send))) {
    let Some(context) = CONTEXT.get() else {
        return;
    };
    let Ok(mut guard) = context.history.lock() else {
        return;
    };
    action(&mut *guard);
}

/// The QR, as an image the window can draw: rounded modules, at four times the 175 px it is
/// shown at, so it stays sharp at any display scale.
fn qr_image(token: &str) -> Result<Image> {
    const SIDE: u32 = 700;
    let pixels = qr::render_modules(token, SIDE)?;
    let mut buffer = SharedPixelBuffer::<Rgba8Pixel>::new(SIDE, SIDE);
    buffer.make_mut_bytes().copy_from_slice(&pixels);
    Ok(Image::from_rgba8(buffer))
}

/// The closest offered size cap, and whether it was an exact match.
fn nearest_cap(bytes: usize) -> (i32, bool) {
    if let Some(index) = SIZE_CAPS.iter().position(|(value, _)| *value == bytes) {
        return (i32::try_from(index).unwrap_or(1), true);
    }
    let index = SIZE_CAPS
        .iter()
        .enumerate()
        .min_by_key(|(_, (value, _))| value.abs_diff(bytes))
        .map_or(1, |(index, _)| index);
    (i32::try_from(index).unwrap_or(1), false)
}

/// The closest offered history length.
fn nearest_retention(entries: usize) -> i32 {
    let index = RETENTIONS
        .iter()
        .enumerate()
        .min_by_key(|(_, value)| value.abs_diff(entries))
        .map_or(2, |(index, _)| index);
    i32::try_from(index).unwrap_or(2)
}

/// A size a person can read.
fn human_bytes(bytes: usize) -> String {
    #[allow(clippy::cast_precision_loss)]
    let value = bytes as f64;
    if bytes >= 1024 * 1024 {
        format!("{:.1} MB", value / (1024.0 * 1024.0))
    } else if bytes >= 1024 {
        format!("{:.0} KB", value / 1024.0)
    } else {
        format!("{bytes} bytes")
    }
}

/// The first part of an identifier, which is all a status screen needs.
fn short(id: &str) -> String {
    id.chars().take(12).collect()
}

/// The host out of a relay URL, so the status screen shows a name rather than a URL.
fn host_of(url: &str) -> String {
    url.split_once("://")
        .map_or(url, |(_, rest)| rest)
        .split('/')
        .next()
        .unwrap_or(url)
        .to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_valid_token_reads_as_valid() {
        let secret = [7u8; 32];
        let token = token::encode(&secret);
        let check = check_token(token.as_str());
        assert!(check.valid, "a token we just encoded must parse");
        assert!(!check.invalid);
    }

    #[test]
    fn an_empty_field_is_neither_right_nor_wrong() {
        // A field that turns red before anything has been typed is telling somebody off for not
        // having started yet.
        let check = check_token("   ");
        assert!(!check.valid);
        assert!(!check.invalid);
        assert!(check.message.is_empty());
    }

    #[test]
    fn each_mistake_is_named_separately() {
        // The whole reason for inline validation: these are four different problems and only one
        // of them means the string was never an Asli token.
        let prefix = check_token("hello there");
        let cut = check_token("asli1_ABC");

        assert!(prefix.invalid && cut.invalid);
        assert!(
            prefix.message.contains("asli1_"),
            "a wrong prefix should say what the prefix is, got {}",
            prefix.message
        );
        assert!(
            cut.message.contains("cut off") || cut.message.contains("incomplete"),
            "a short string should say it is short, got {}",
            cut.message
        );
        assert_ne!(
            prefix.message, cut.message,
            "two different mistakes must not produce the same advice"
        );
    }

    #[test]
    fn a_secret_never_appears_in_a_message() {
        let secret = [9u8; 32];
        let token = token::encode(&secret);
        let mutated = format!("{}X", &token.as_str()[..token.as_str().len() - 1]);
        let check = check_token(&mutated);
        assert!(
            !check.message.contains(&mutated),
            "the failure message must not echo the string back"
        );
    }

    #[test]
    fn history_keeps_newest_first_and_honours_its_limit() {
        let mut history = MemoryHistory::new(true, 2);
        history.record(HistoryContent::Text("first".to_owned()), false, 1, [0; 16]);
        history.record(HistoryContent::Text("second".to_owned()), false, 2, [0; 16]);
        history.record(HistoryContent::Text("third".to_owned()), false, 3, [0; 16]);

        let entries = history.entries();
        assert_eq!(entries.len(), 2, "the limit must be enforced");
        assert_eq!(entries[0].preview, "third", "newest first");
        assert_eq!(
            history.restore(0),
            Some(HistoryContent::Text("third".to_owned()))
        );
    }

    #[test]
    fn a_concealed_clip_is_never_recorded() {
        // The marker exists because a password manager asked for this clip to be left alone.
        // Recording it into a list would undo exactly that.
        let mut history = MemoryHistory::new(true, 10);
        history.record(HistoryContent::Text("hunter2".to_owned()), true, 1, [0; 16]);
        assert!(history.entries().is_empty(), "a secret must not be kept");
    }

    #[test]
    fn every_change_moves_the_revision_so_an_open_list_redraws() {
        let mut history = MemoryHistory::new(true, 10);
        let mut seen = vec![history.revision()];
        let mut changed = |history: &MemoryHistory| {
            let now = history.revision();
            assert!(
                !seen.contains(&now),
                "a change left the revision where it was"
            );
            seen.push(now);
        };

        history.record(HistoryContent::Text("one".to_owned()), false, 1, [0; 16]);
        changed(&history);
        history.record(HistoryContent::Text("two".to_owned()), false, 2, [0; 16]);
        changed(&history);
        assert!(history.forget(0));
        changed(&history);
        history.clear();
        changed(&history);
        history.set_enabled(false);
        changed(&history);
    }

    #[test]
    fn turning_history_off_forgets_what_was_there() {
        let mut history = MemoryHistory::new(true, 10);
        history.record(
            HistoryContent::Text("something".to_owned()),
            false,
            1,
            [0; 16],
        );
        history.set_enabled(false);
        assert!(
            history.entries().is_empty(),
            "turning it off means the list goes, not that it freezes"
        );
        history.record(HistoryContent::Text("more".to_owned()), false, 2, [0; 16]);
        assert!(history.entries().is_empty(), "and nothing more is kept");
    }

    #[test]
    fn a_size_the_list_cannot_express_is_reported_rather_than_rounded_silently() {
        let (index, exact) = nearest_cap(700 * 1024);
        assert_eq!(index, 1);
        assert!(exact, "a value from the list is exact");

        let (_, exact) = nearest_cap(123_456);
        assert!(
            !exact,
            "a hand edited value must be flagged, not rounded quietly"
        );
    }

    fn status(state: &str) -> Status {
        Status {
            state: state.to_owned(),
            ..Status::default()
        }
    }

    #[test]
    fn each_connection_state_reads_as_the_design_names_it() {
        let now = 1_000_000;
        let mut synced = status("Synced");
        synced.peers = 2;
        let shown = present(&synced, false, "asli.vnat.dev", now);
        assert_eq!(shown.state, SyncState::Connected);
        assert_eq!(shown.label, "Synced");
        assert!(
            shown.detail.starts_with("2 devices online"),
            "{}",
            shown.detail
        );
        assert_eq!(shown.connections, "2 devices");

        let paused = present(&synced, true, "asli.vnat.dev", now);
        assert_eq!(paused.state, SyncState::Offline);
        assert_eq!(paused.label, "Paused");

        let mut connecting = status("Connecting");
        connecting.attempt = 3;
        let shown = present(&connecting, false, "asli.vnat.dev", now);
        assert_eq!(shown.state, SyncState::Connecting);
        assert!(shown.detail.contains("attempt 3"), "{}", shown.detail);

        let mut offline = status("Offline, retrying");
        offline.retry_at_ms = Some(now + 23_500);
        let shown = present(&offline, false, "asli.vnat.dev", now);
        assert_eq!(shown.state, SyncState::Error);
        assert_eq!(shown.label, "Connection failed");
        assert!(shown.detail.contains("Retrying in 24s"), "{}", shown.detail);

        let stopped = present(
            &status("Rejected: BAD_SIGNATURE"),
            false,
            "asli.vnat.dev",
            now,
        );
        assert_eq!(stopped.state, SyncState::Error);
        assert!(stopped.detail.contains("BAD_SIGNATURE"));
    }

    #[test]
    fn one_device_alone_is_not_called_devices() {
        let mut alone = status("Synced");
        alone.peers = 1;
        let shown = present(&alone, false, "asli.vnat.dev", 0);
        assert_eq!(shown.connections, "1 device");
        assert!(
            shown.detail.starts_with("Only this device"),
            "{}",
            shown.detail
        );
    }

    #[test]
    fn urls_and_paths_are_shown_in_the_monospaced_face() {
        assert!(looks_like_code("wss://asli.vnat.dev/v1"));
        assert!(looks_like_code("~/Projects/Asli"));
        assert!(looks_like_code(r"C:\Users\me"));
        assert!(!looks_like_code("Replay protection now survives restarts."));
    }

    #[test]
    fn a_thumbnail_keeps_the_image_size_and_rounds_its_corners() {
        let mut png_bytes = Vec::new();
        {
            let mut encoder = png::Encoder::new(&mut png_bytes, 300, 200);
            encoder.set_color(png::ColorType::Rgba);
            encoder.set_depth(png::BitDepth::Eight);
            let mut writer = encoder.write_header().expect("header");
            writer
                .write_image_data(&vec![200u8; 300 * 200 * 4])
                .expect("data");
        }
        let thumbnail = make_thumbnail(&png_bytes);
        assert_eq!((thumbnail.width, thumbnail.height), (300, 200));
        let image = thumbnail.image.expect("decoded");
        let buffer = image.to_rgba8().expect("pixels");
        let pixels = buffer.as_slice();
        assert_eq!(pixels[0].a, 0, "the corner is cut away");
        assert!(pixels[50 * 100 + 50].a > 150, "the middle is kept");
    }

    #[test]
    fn a_relay_url_shows_as_a_host() {
        assert_eq!(host_of("wss://asli.vnat.dev/v1"), "asli.vnat.dev");
        assert_eq!(host_of("asli.vnat.dev"), "asli.vnat.dev");
    }
}
