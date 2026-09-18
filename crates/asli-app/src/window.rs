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

use slint::{ComponentHandle as _, Image, ModelRc, Rgba8Pixel, SharedPixelBuffer, VecModel};

use asli_crypto::{token, Identity};

use crate::clipboard_io::{log_line, ClipboardIo};
use crate::config::{Config, Paths};
use crate::daemon::Controls;
use crate::error::{Error, Result};
use crate::{notify, qr, secrets, tray};

// The markup, compiled in a crate of its own.
//
// It lives there rather than here because Slint's generated code carries an inner
// `allow(unsafe_code)`, and this crate's `#![forbid(unsafe_code)]` would overrule it and fail the
// build. Keeping the generated code at arm's length is what lets every hand written crate in this
// project keep the stronger annotation.
pub use asli_ui::{AppWindow, HistoryRow, Screen, TokenCheck};

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
    /// must never be kept.
    fn record(&mut self, content: HistoryContent, sensitive: bool, ts_ms: u64);

    /// Forgets one entry. Returns whether there was one there.
    fn forget(&mut self, index: usize) -> bool;

    /// Forgets everything.
    fn clear(&mut self);

    /// Turns recording on or off. Turning it off forgets what was already there.
    fn set_enabled(&mut self, enabled: bool);

    /// Changes how many entries are kept, dropping any excess immediately.
    fn set_limit(&mut self, limit: usize);
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
}

impl MemoryHistory {
    /// A new, empty history.
    #[must_use]
    pub const fn new(enabled: bool, limit: usize) -> Self {
        Self {
            entries: Vec::new(),
            enabled,
            limit,
        }
    }

    /// Records one entry, newest first, dropping the oldest past the limit.
    ///
    /// Secrets are never recorded. A clip the platform marked as concealed is a password manager
    /// handing over a password, and writing that into a list on disk would undo the entire point
    /// of the marker.
    pub fn push(&mut self, content: HistoryContent, sensitive: bool, ts_ms: u64) {
        if !self.enabled || sensitive {
            return;
        }

        let (preview, is_image, bytes) = match &content {
            HistoryContent::Text(text) => (preview_of(text), false, text.len()),
            HistoryContent::ImagePng(png) => (String::new(), true, png.len()),
        };

        self.entries.insert(
            0,
            (
                HistoryEntry {
                    preview,
                    is_image,
                    ts_ms,
                    bytes,
                },
                content,
            ),
        );
        self.entries.truncate(self.limit.max(1));
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

    fn record(&mut self, content: HistoryContent, sensitive: bool, ts_ms: u64) {
        self.push(content, sensitive, ts_ms);
    }

    fn forget(&mut self, index: usize) -> bool {
        if index < self.entries.len() {
            self.entries.remove(index);
            return true;
        }
        false
    }

    fn clear(&mut self) {
        self.entries.clear();
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
    // regardless of which menu item was clicked.
    window.set_screen(if window.get_has_account() {
        screen
    } else {
        Screen::FirstRun
    });

    if let Err(err) = window.show() {
        eprintln!("{}", log_line("window_failed", &err.to_string()));
        return;
    }
    start_timer();
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
                }
            });
        });
        *slot = Some(timer);
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
        match create_account() {
            Ok(()) => {
                refresh(&window);
                window.set_screen(Screen::Token);
                // The daemon was started without an identity, so it has to be restarted onto the
                // one that now exists. The window goes with it and comes back on the next click.
                restart_self();
            }
            Err(err) => {
                eprintln!("{}", log_line("create_failed", &err.to_string()));
                notify::action_failed("Could not create an account", &err.to_string());
            }
        }
    });

    let handle = window.as_weak();
    window.on_check_token(move |raw| {
        if let Some(window) = handle.upgrade() {
            window.set_join_check(check_token(raw.as_str()));
        }
    });

    let handle = window.as_weak();
    window.on_join_account(move |raw| {
        let Some(window) = handle.upgrade() else {
            return;
        };
        window.set_join_busy(true);
        match join_account(raw.as_str()) {
            Ok(room_id) => {
                eprintln!("{}", log_line("joined", &format!("room {room_id}")));
                notify::joined(&room_id);
                restart_self();
            }
            Err(err) => {
                window.set_join_busy(false);
                let reason = err.to_string();
                eprintln!("{}", log_line("join_failed", &reason));
                window.set_join_check(TokenCheck {
                    valid: false,
                    invalid: true,
                    message: reason.into(),
                });
            }
        }
    });
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

    let handle = window.as_weak();
    window.on_open_screen(move |screen| {
        if let Some(window) = handle.upgrade() {
            refresh(&window);
            window.set_screen(screen);
        }
    });

    window.on_hide_window(hide);

    wire_account(&window);

    window.on_copy_token(copy_token);
    window.on_restore_entry(restore_entry);
    window.on_forget_entry(forget_entry);
    window.on_clear_history(clear_history);
    window.on_set_paused(set_paused);
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
        window.set_relay_host(host_of(&config.relay_url).into());
    }
    window.set_clipboard_backend(context.io.describe().into());

    refresh_history(window);
    refresh_status(window);
}

/// Refreshes the parts the daemon changes underneath us.
fn refresh_status(window: &AppWindow) {
    let Some(context) = CONTEXT.get() else {
        return;
    };
    let status = context.controls.status.get();

    window.set_connection(
        if status.state.is_empty() {
            "Offline".to_owned()
        } else {
            status.state.clone()
        }
        .into(),
    );
    window.set_peers(i32::try_from(status.peers).unwrap_or(i32::MAX));
    window
        .set_last_sync(tray::relative_time(status.last_sync_ms, asli_net::client::now_ms()).into());
    window.set_skipped(status.skipped.to_string().into());
    window.set_has_retained(status.has_retained);
    window.set_paused(context.controls.is_paused());
    window.set_last_error(status.last_error.clone().unwrap_or_default().into());
}

/// Rebuilds the history list.
fn refresh_history(window: &AppWindow) {
    let Some(context) = CONTEXT.get() else {
        return;
    };
    let Ok(history) = context.history.lock() else {
        return;
    };

    window.set_history_enabled(history.enabled());

    let now = asli_net::client::now_ms();
    let rows: Vec<HistoryRow> = history
        .entries()
        .into_iter()
        .map(|entry| HistoryRow {
            preview: entry.preview.into(),
            kind: if entry.is_image { "IMAGE" } else { "TEXT" }.into(),
            age: tray::relative_time(Some(entry.ts_ms), now).into(),
            size: human_bytes(entry.bytes).into(),
            is_image: entry.is_image,
        })
        .collect();

    let empty = rows.is_empty();
    window.set_history(ModelRc::new(VecModel::from(rows)));
    window.set_history_note(
        if history.enabled() && !empty {
            // Said plainly rather than hidden, because a list that silently empties on restart
            // looks like data loss.
            "Kept in memory only for now, so restarting Asli clears this."
        } else {
            ""
        }
        .into(),
    );
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
    window.set_notifications(config.notifications);
    window.set_keep_history(config.keep_history);

    let (cap_index, exact) = nearest_cap(config.max_content_bytes);
    window.set_size_cap_index(cap_index);
    window.set_retention_index(nearest_retention(config.history_entries));

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
    window.set_settings_dirty(false);
}

/// Writes the Settings screen back to the configuration file.
fn save_settings(window: &AppWindow) {
    let relay = window.get_relay_url().to_string();
    let cap = SIZE_CAPS[usize::try_from(window.get_size_cap_index())
        .unwrap_or(1)
        .min(3)]
    .0;
    let entries = RETENTIONS[usize::try_from(window.get_retention_index())
        .unwrap_or(2)
        .min(3)];

    apply(window, |config| {
        relay.clone_into(&mut config.relay_url);
        config.max_content_bytes = cap;
        config.history_entries = entries;
    });

    with_history(|history| history.set_limit(entries));
    window.set_settings_dirty(false);

    // Both halves are stated because both are true and neither is obvious. A setting that claims
    // to have applied when it has not is how a person concludes the application ignores them.
    window.set_settings_note(
        "Saved. The relay address takes effect when Asli next connects, and the history length \
         when it next starts."
            .into(),
    );
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
        notify::action_failed("No account on this device", "Create or join one first");
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
            notify::token_copied(TOKEN_CLEAR_AFTER.as_secs());
        }
        Err(err) => {
            eprintln!("{}", log_line("token_copy_failed", &err.to_string()));
            notify::token_copy_failed(&err.to_string());
        }
    }
}

/// Puts a history entry back on the clipboard, which syncs it to every device.
///
/// Written as a copy, not as an arrival. An arrival must not go back out, but putting an old clip
/// back on every device is the entire point of this screen, and the watcher cannot be relied on
/// to report it: every platform recognises our own writes and ignores them.
fn restore_entry(index: i32) {
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
        notify::action_failed("Could not restore that", "the entry is no longer there");
        return;
    };

    let result = match &clip {
        HistoryContent::Text(text) => context.io.write_text_as_copy(text),
        HistoryContent::ImagePng(png) => context.io.write_image_as_copy(png),
    };

    match result {
        // Never the content, only its size. A log line holding a clip would put every copied
        // password into the journal.
        Ok(()) => eprintln!(
            "{}",
            log_line(
                "restored",
                &match &clip {
                    HistoryContent::Text(text) => format!("text, {}", human_bytes(text.len())),
                    HistoryContent::ImagePng(png) => format!("image, {}", human_bytes(png.len())),
                }
            )
        ),
        Err(err) => {
            eprintln!("{}", log_line("restore_failed", &err.to_string()));
            notify::action_failed("Could not restore that", &err.to_string());
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
    notify::sync_paused(paused);
}

/// Asks the daemon for the clip the relay is holding.
fn request_retained() {
    let Some(context) = CONTEXT.get() else {
        return;
    };
    if context.controls.status.get().has_retained {
        context.controls.request_retained();
        eprintln!("{}", log_line("paste_retained", "requested from the relay"));
        notify::retained_requested();
    } else {
        notify::retained_unavailable();
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
        notify::diagnostics_failed(&err.to_string());
    } else {
        notify::diagnostics_copied();
    }
}

/// Restarts this process so the daemon picks up the account that was just stored.
///
/// The daemon takes its identity by value and the connection holds a session built from it, so
/// there is no way to swap accounts on a live connection. Rather than leave somebody wondering
/// why nothing happened, the process replaces itself.
#[cfg(unix)]
fn restart_self() {
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
        .exec();
    eprintln!("{}", log_line("restart_failed", &err.to_string()));
}

/// Windows has no `exec`, so the replacement is started as a new process and this one exits.
///
/// The replacement waits for the single instance lock, which this process holds until it is gone,
/// because [`crate::instance::RESTART_ENV`] tells it a handover is under way.
#[cfg(not(unix))]
fn restart_self() {
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
        .spawn()
    {
        Ok(_) => std::process::exit(0),
        Err(err) => {
            eprintln!("{}", log_line("restart_failed", &err.to_string()));
            notify::action_failed("Restart Asli to use the new account", &err.to_string());
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

/// The QR, as an image the window can draw.
fn qr_image(token: &str) -> Result<Image> {
    let (span, pixels) = qr::render_rgba(token)?;
    let mut buffer = SharedPixelBuffer::<Rgba8Pixel>::new(span, span);
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
        history.record(HistoryContent::Text("first".to_owned()), false, 1);
        history.record(HistoryContent::Text("second".to_owned()), false, 2);
        history.record(HistoryContent::Text("third".to_owned()), false, 3);

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
        history.record(HistoryContent::Text("hunter2".to_owned()), true, 1);
        assert!(history.entries().is_empty(), "a secret must not be kept");
    }

    #[test]
    fn turning_history_off_forgets_what_was_there() {
        let mut history = MemoryHistory::new(true, 10);
        history.record(HistoryContent::Text("something".to_owned()), false, 1);
        history.set_enabled(false);
        assert!(
            history.entries().is_empty(),
            "turning it off means the list goes, not that it freezes"
        );
        history.record(HistoryContent::Text("more".to_owned()), false, 2);
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

    #[test]
    fn a_relay_url_shows_as_a_host() {
        assert_eq!(host_of("wss://asli.vnat.dev/v1"), "asli.vnat.dev");
        assert_eq!(host_of("asli.vnat.dev"), "asli.vnat.dev");
    }
}
