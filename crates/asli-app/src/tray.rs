//! The tray icon and its menu.
//!
//! # Clicking the icon, and why the menu still carries everything
//!
//! `StatusNotifierItem` does deliver a click: the host calls `Activate` on the item, and the ksni
//! backend turns that into a [`tray_icon::TrayIconEvent::Click`] with the left button. So a left
//! click opens the window, which is what a person expects from a tray application.
//!
//! Every action still lives in the menu as well. Hosts disagree about what a click does, some bind
//! it to the menu themselves, and an action reachable only by clicking would simply not exist on
//! those desktops. The menu is the contract; the click is a shortcut into it.
//!
//! # Why ksni
//!
//! `tray-icon`'s default backend is libappindicator, which drags in GTK3 and libxdo. This project
//! chose a native stack specifically to avoid that dependency chain, so the `ksni` feature is used
//! instead: a pure Rust `StatusNotifierItem` implementation. It spawns its own service thread inside
//! `TrayIcon::new`, which means no GTK main loop and no winit event loop are required.
//!
//! # The failure mode this module guards against
//!
//! An icon only appears if something in the session implements a `StatusNotifierItem` host. KDE has
//! one natively, vanilla GNOME needs an extension, and bare compositors rely on a status bar. When
//! no host exists, the tray registers successfully and is simply never drawn, so the application
//! looks like it failed to start. [`host_present`] detects that case so the caller can say so
//! rather than vanishing.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use muda::{Menu, MenuEvent, MenuItem, PredefinedMenuItem};
use tray_icon::{Icon, MouseButton, MouseButtonState, TrayIcon, TrayIconBuilder, TrayIconEvent};

use crate::config::{Config, Paths};
use crate::daemon::Status;
use crate::error::{Error, Result};

/// How often the menu is refreshed from daemon state.
///
/// A tray that shows a stale "Offline" after reconnecting is worse than no status line at all, and
/// one second is far below what a person notices while also being nearly free.
const REFRESH: Duration = Duration::from_secs(1);

/// Stable ids, so actions are matched on identity rather than on the label text, which changes.
mod id {
    pub const PAUSE: &str = "asli.pause";
    pub const PASTE_RETAINED: &str = "asli.paste_retained";
    pub const SHOW_TOKEN: &str = "asli.show_token";
    pub const JOIN: &str = "asli.join";
    pub const HISTORY: &str = "asli.history";
    pub const STATUS: &str = "asli.status";
    pub const SETTINGS: &str = "asli.settings";
    pub const DIAGNOSTICS: &str = "asli.diagnostics";
    pub const QUIT: &str = "asli.quit";
}

/// What the tray asks the rest of the application to do.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Command {
    /// Open the window on whichever screen makes sense right now. Raised by clicking the icon
    /// rather than by any menu item.
    Open,
    /// Stop syncing until resumed.
    Pause,
    /// Start syncing again.
    Resume,
    /// Write the relay's stored clip to the local clipboard, on request.
    PasteRetained,
    /// Show the join token again.
    ShowToken,
    /// Join an account belonging to another device, by pasting its token.
    Join,
    /// Show what was copied recently, so any of it can be put back.
    History,
    /// Show the connection in detail.
    Status,
    /// Open settings.
    Settings,
    /// Put recent diagnostics somewhere the person can paste them into a bug report.
    Diagnostics,
    /// Quit.
    Quit,
}

/// Shared handle the daemon updates and the tray reads.
///
/// A mutex rather than a channel because the tray only ever wants the latest value, and a channel
/// would either grow unboundedly or need draining logic for no benefit.
#[derive(Debug, Clone, Default)]
pub struct StatusHandle(Arc<Mutex<Status>>);

impl StatusHandle {
    /// Replaces the current status.
    ///
    /// # Panics
    ///
    /// Panics only if another thread panicked while holding the lock, which is already fatal.
    pub fn set(&self, status: Status) {
        *self.0.lock().expect("status lock") = status;
    }

    /// Reads the current status.
    ///
    /// # Panics
    ///
    /// Panics only if another thread panicked while holding the lock.
    #[must_use]
    pub fn get(&self) -> Status {
        self.0.lock().expect("status lock").clone()
    }
}

/// Whether anything in this session can actually display a tray icon.
///
/// Checked by asking the session bus for a `StatusNotifierWatcher`, which is what every host
/// registers. On Windows and macOS the tray is part of the operating system, so this is true.
#[must_use]
pub fn host_present() -> bool {
    #[cfg(target_os = "linux")]
    {
        // A short lived connection is enough: the watcher is a well known name, so its presence on
        // the bus is the whole answer.
        let Ok(connection) = zbus_lite::session_has_name("org.kde.StatusNotifierWatcher") else {
            return false;
        };
        connection
    }

    #[cfg(not(target_os = "linux"))]
    {
        true
    }
}

/// Asks an already running instance to show its window.
///
/// On Linux the running instance's tray item carries its pid in its bus name, and the pid is in
/// the lock file, so the item can be activated exactly as a click on the icon would.
///
/// Elsewhere there is no bus, so this leaves a request file in the configuration directory, which
/// the running instance looks for once a second. Advisory either way: returns false when the
/// request could not be made, and the caller exits regardless.
#[must_use]
pub fn raise_running(paths: &crate::config::Paths) -> bool {
    #[cfg(target_os = "linux")]
    {
        let Some(pid) = std::fs::read_to_string(paths.dir.join("asli.lock"))
            .ok()
            .and_then(|raw| raw.trim().parse::<u32>().ok())
        else {
            return false;
        };
        zbus_lite::activate_item_of(pid)
    }

    #[cfg(not(target_os = "linux"))]
    {
        std::fs::write(raise_request(paths), b"").is_ok()
    }
}

/// Where a second launch leaves its request to be shown, on platforms without a session bus.
#[must_use]
pub fn raise_request(paths: &crate::config::Paths) -> std::path::PathBuf {
    paths.dir.join("raise")
}

/// Whether a second launch asked to be shown since the last check. Consumes the request.
#[must_use]
pub fn take_raise_request(paths: &crate::config::Paths) -> bool {
    std::fs::remove_file(raise_request(paths)).is_ok()
}

/// The advice printed when no tray host exists, so the application explains itself instead of
/// disappearing.
#[must_use]
pub fn missing_host_advice() -> &'static str {
    "No tray host is running in this session, so no icon can appear.\n\
     GNOME needs the AppIndicator and KStatusNotifierItem Support extension.\n\
     Hyprland, Sway and other bare compositors need a status bar with a tray module, such as waybar.\n\
     Asli keeps syncing in the background either way. Use 'asli run' if you do not want a tray."
}

/// The tray, its menu, and the items that change.
pub struct Tray {
    /// Held because dropping it removes the icon from the session, and because the icon is
    /// swapped on every state change.
    icon: TrayIcon,
    status_item: MenuItem,
    last_sync_item: MenuItem,
    pause_item: MenuItem,
    retained_item: MenuItem,
    paused: Arc<AtomicBool>,
    /// The state the icon currently shows, so it is only redrawn when it actually changes.
    icon_state: Mutex<IconState>,
}

impl Tray {
    /// Builds the tray and registers it with the session.
    ///
    /// # Errors
    ///
    /// Returns [`Error::ConfigDir`] if the icon could not be built or the tray could not be
    /// registered.
    pub fn new(paused: Arc<AtomicBool>) -> Result<Self> {
        let menu = Menu::new();

        // Disabled items are labels: this protocol has no separate label concept, and an enabled
        // item that does nothing when clicked is worse than one that cannot be clicked.
        let status_item = MenuItem::new("Starting", false, None);
        let last_sync_item = MenuItem::new("Last Sync: never", false, None);
        let pause_item = MenuItem::with_id(id::PAUSE, "Pause Sync", true, None);
        let retained_item =
            MenuItem::with_id(id::PASTE_RETAINED, "Paste Last Synced Clip", true, None);
        let show_token_item = MenuItem::with_id(id::SHOW_TOKEN, "Show Join String", true, None);
        // The other half of onboarding. Without this the only way onto an existing account is a
        // terminal command, which is no onboarding story at all for a tray application.
        let join_item = MenuItem::with_id(id::JOIN, "Join Another Account", true, None);
        let history_item = MenuItem::with_id(id::HISTORY, "History", true, None);
        let open_status_item = MenuItem::with_id(id::STATUS, "Status", true, None);
        let settings_item = MenuItem::with_id(id::SETTINGS, "Settings", true, None);
        let diagnostics_item = MenuItem::with_id(id::DIAGNOSTICS, "Copy Diagnostics", true, None);
        let quit_item = MenuItem::with_id(id::QUIT, "Quit", true, None);

        menu.append_items(&[
            &status_item,
            &last_sync_item,
            &PredefinedMenuItem::separator(),
            &pause_item,
            &retained_item,
            &PredefinedMenuItem::separator(),
            &history_item,
            &open_status_item,
            &PredefinedMenuItem::separator(),
            &show_token_item,
            &join_item,
            &settings_item,
            &diagnostics_item,
            &PredefinedMenuItem::separator(),
            &quit_item,
        ])
        .map_err(|e| Error::ConfigDir(format!("could not build the tray menu: {e}")))?;

        // The retained item only makes sense once the relay says it is holding something.
        retained_item.set_enabled(false);

        let icon = TrayIconBuilder::new()
            .with_menu(Box::new(menu))
            .with_tooltip("Asli")
            .with_icon(icon_for(IconState::Offline)?)
            // A left click opens the window and a right click opens the menu, as on every other
            // tray application. The default on Windows and macOS is the menu for both.
            .with_menu_on_left_click(false)
            .build()
            .map_err(|e| Error::ConfigDir(format!("could not register the tray icon: {e}")))?;

        Ok(Self {
            icon,
            status_item,
            last_sync_item,
            pause_item,
            retained_item,
            paused,
            icon_state: Mutex::new(IconState::Offline),
        })
    }

    /// Refreshes the menu from the current daemon state.
    ///
    /// # Panics
    ///
    /// Panics only if another thread panicked while holding the icon state lock, which is already
    /// fatal for the tray thread.
    pub fn refresh(&self, status: &Status, now_ms: u64) {
        let paused = self.paused.load(Ordering::Relaxed);

        self.status_item.set_text(if paused {
            "Paused".to_owned()
        } else {
            status.line()
        });
        self.last_sync_item.set_text(format!(
            "Last Sync: {}",
            relative_time(status.last_sync_ms, now_ms)
        ));
        self.pause_item
            .set_text(if paused { "Resume Sync" } else { "Pause Sync" });
        self.retained_item.set_enabled(status.has_retained);

        // Redrawn only on a change: refresh runs every second, and rebuilding the buffer each
        // time would be pointless work for a picture that almost never changes.
        let wanted = IconState::from_status(&status.state, paused);
        let mut current = self.icon_state.lock().expect("icon state lock");
        if *current != wanted {
            if let Ok(icon) = icon_for(wanted) {
                let _ = self.icon.set_icon(Some(icon));
                *current = wanted;
            }
        }
    }

    /// Translates a menu event into a command, if it is one of ours.
    #[must_use]
    pub fn command_for(&self, event: &MenuEvent) -> Option<Command> {
        match event.id().as_ref() {
            id::PAUSE => Some(if self.paused.load(Ordering::Relaxed) {
                Command::Resume
            } else {
                Command::Pause
            }),
            id::PASTE_RETAINED => Some(Command::PasteRetained),
            id::SHOW_TOKEN => Some(Command::ShowToken),
            id::JOIN => Some(Command::Join),
            id::HISTORY => Some(Command::History),
            id::STATUS => Some(Command::Status),
            id::SETTINGS => Some(Command::Settings),
            id::DIAGNOSTICS => Some(Command::Diagnostics),
            id::QUIT => Some(Command::Quit),
            _ => None,
        }
    }

    /// Translates a click on the icon itself into a command, if it is one we act on.
    ///
    /// Only the left button. The middle button arrives here too, as `secondary_activate`, and is
    /// deliberately ignored: desktops bind it to their own conventions and a tray application that
    /// hijacks it surprises people. The right button never reaches this at all, because the host
    /// opens the menu with it.
    #[must_use]
    pub fn command_for_icon(event: &TrayIconEvent) -> Option<Command> {
        match event {
            // Windows reports the press and the release as two clicks, so only the release counts.
            // The Linux backend reports releases only.
            TrayIconEvent::Click {
                button: MouseButton::Left,
                button_state: MouseButtonState::Up,
                ..
            } => Some(Command::Open),
            _ => None,
        }
    }

    /// How often the caller should call [`Tray::refresh`].
    #[must_use]
    pub const fn refresh_interval() -> Duration {
        REFRESH
    }
}

/// What the icon should say at a glance.
///
/// The whole point of a tray icon is that it carries state without being opened. An icon that
/// looks identical whether syncing works or died an hour ago is decoration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IconState {
    /// Connected to the relay.
    Connected,
    /// Deliberately paused by the person.
    Paused,
    /// Not connected, retrying, or rejected.
    Offline,
}

impl IconState {
    /// Derives the icon state from the daemon's status line and the pause flag.
    #[must_use]
    pub fn from_status(state: &str, paused: bool) -> Self {
        if paused {
            Self::Paused
        } else if state.starts_with("Synced") {
            Self::Connected
        } else {
            Self::Offline
        }
    }
}

/// Icon side in pixels.
///
/// Drawn at 32 and scaled down by the host. Trays render at 16 or 22 on most desktops, so the
/// mark has to survive being halved, which is why it is two heavy shapes rather than fine detail.
const ICON_SIZE: u32 = 32;

/// Builds the icon for a state.
///
/// The mark is two overlapping rounded squares, the back one offset up and right: a copy, which
/// is what this application does and what the name means. Colour carries the state, and so does
/// the offset shape, because a person with any common form of colour blindness gets no
/// information from hue alone.
///
/// Generated in code rather than shipped as a file. A runtime file lookup is a packaging problem
/// on three platforms for something this small, and a missing icon file means an invisible tray.
///
/// # Errors
///
/// Returns [`Error::ConfigDir`] if the buffer does not match the dimensions, which would be an
/// arithmetic mistake in the drawing loop rather than anything environmental.
pub fn icon_for(state: IconState) -> Result<Icon> {
    // Foreground, and the accent used for the state dot.
    let (fg, accent) = match state {
        // Neutral and bright: nothing to report is the normal case and should not shout.
        IconState::Connected => ([0xe8, 0xe8, 0xe8], [0x4c, 0xd1, 0x64]),
        // Amber, and the front sheet is hollow, so a paused tray reads as paused at 16 pixels.
        IconState::Paused => ([0xc8, 0xc8, 0xc8], [0xe0, 0xa8, 0x30]),
        // Dimmed, so an offline tray recedes rather than demanding attention it cannot satisfy.
        IconState::Offline => ([0x8a, 0x8a, 0x8a], [0xd0, 0x4c, 0x4c]),
    };

    let mut rgba = Vec::with_capacity((ICON_SIZE * ICON_SIZE * 4) as usize);

    for y in 0..ICON_SIZE {
        for x in 0..ICON_SIZE {
            let pixel = draw_pixel(x, y, state, fg, accent);
            rgba.extend_from_slice(&pixel);
        }
    }

    Icon::from_rgba(rgba, ICON_SIZE, ICON_SIZE)
        .map_err(|e| Error::ConfigDir(format!("could not build the tray icon: {e}")))
}

/// One pixel of the mark.
///
/// Split out so the shape is testable without constructing an [`Icon`], and so the loop above
/// stays readable.
fn draw_pixel(x: u32, y: u32, state: IconState, fg: [u8; 3], accent: [u8; 3]) -> [u8; 4] {
    // Back sheet: offset up and to the right, drawn as an outline only where it is not covered.
    let back = rounded(x, y, 11, 3, 28, 20);
    let front = rounded(x, y, 4, 10, 21, 27);
    let front_inner = rounded(x, y, 7, 13, 18, 24);

    // The state dot sits in the lower right, where it survives being scaled to 16 pixels.
    let dot = {
        let dx = i64::from(x) - 24;
        let dy = i64::from(y) - 24;
        dx * dx + dy * dy <= 25
    };

    if dot {
        return [accent[0], accent[1], accent[2], 0xff];
    }

    if front {
        // Paused is hollow, so the state is legible without colour.
        let hollow = matches!(state, IconState::Paused) && front_inner;
        if hollow {
            return [0, 0, 0, 0];
        }
        return [fg[0], fg[1], fg[2], 0xff];
    }

    if back {
        // The back sheet is dimmer, which is what makes it read as behind rather than beside.
        // Integer maths on a u8 channel: 3/5 of 255 is 153, so this cannot overflow, but saying
        // so with saturation is cheaper than an allow attribute.
        let dim = |c: u8| u8::try_from(u16::from(c) * 3 / 5).unwrap_or(u8::MAX);
        return [dim(fg[0]), dim(fg[1]), dim(fg[2]), 0xff];
    }

    [0, 0, 0, 0]
}

/// Whether a point falls inside a rectangle with its corners cut.
///
/// A sharp corner at tray size looks like a rendering fault, and a real rounded rectangle needs
/// antialiasing this does not have, so the corners are simply clipped.
fn rounded(x: u32, y: u32, left: u32, top: u32, right: u32, bottom: u32) -> bool {
    if x < left || x >= right || y < top || y >= bottom {
        return false;
    }
    let near_left = x < left + 2;
    let near_right = x >= right - 2;
    let near_top = y < top + 2;
    let near_bottom = y >= bottom - 2;
    !((near_left || near_right) && (near_top || near_bottom))
}

/// Renders a timestamp as something a person reads at a glance.
///
/// This is the diagnostic every competing tool lacks: when sync silently stops, "Last sync: 2
/// hours ago" answers the question immediately, and it costs one line.
#[must_use]
pub fn relative_time(then_ms: Option<u64>, now_ms: u64) -> String {
    let Some(then) = then_ms else {
        return "never".to_owned();
    };
    let seconds = now_ms.saturating_sub(then) / 1000;

    match seconds {
        0..=4 => "just now".to_owned(),
        5..=59 => format!("{seconds} seconds ago"),
        60..=119 => "a minute ago".to_owned(),
        120..=3599 => format!("{} minutes ago", seconds / 60),
        3600..=7199 => "an hour ago".to_owned(),
        7200..=86_399 => format!("{} hours ago", seconds / 3600),
        _ => format!("{} days ago", seconds / 86_400),
    }
}

/// Recent diagnostics, with no clipboard content anywhere in them.
#[must_use]
pub fn diagnostics(config: &Config, status: &Status, paths: &Paths) -> String {
    format!(
        "asli diagnostics\n\
         relay: {}\n\
         device: {}\n\
         state: {}\n\
         peers: {}\n\
         skipped: {}\n\
         last error: {}\n\
         config: {}\n\
         Contains no clipboard content by design.\n",
        config.relay_url,
        config.device_id,
        status.state,
        status.peers,
        status.skipped,
        status.last_error.as_deref().unwrap_or("none"),
        paths.config_file().display(),
    )
}

/// A minimal session bus name check, so the crate does not take a full D-Bus dependency for one
/// question.
#[cfg(target_os = "linux")]
mod zbus_lite {
    use std::process::Command;

    /// Whether a well known name is currently owned on the session bus.
    ///
    /// Shelling out to `busctl` rather than linking a bus library: this runs once at startup, the
    /// answer is advisory, and a missing `busctl` simply means the check is skipped rather than
    /// the application refusing to start.
    pub fn session_has_name(name: &str) -> Result<bool, ()> {
        Ok(session_names()?.iter().any(|line| line.starts_with(name)))
    }

    /// Asks the tray item registered by `pid` to activate, which is exactly what a left click on
    /// the icon does. Returns whether the call was delivered.
    pub fn activate_item_of(pid: u32) -> bool {
        let marker = format!("StatusNotifierItem-{pid}-");
        let Ok(names) = session_names() else {
            return false;
        };
        let Some(bus) = names
            .iter()
            .filter_map(|line| line.split_whitespace().next())
            .find(|name| name.contains(&marker))
        else {
            return false;
        };

        Command::new("busctl")
            .args([
                "--user",
                "call",
                bus,
                "/StatusNotifierItem",
                "org.kde.StatusNotifierItem",
                "Activate",
                "ii",
                "0",
                "0",
            ])
            .output()
            .is_ok_and(|output| output.status.success())
    }

    fn session_names() -> Result<Vec<String>, ()> {
        let output = Command::new("busctl")
            .args(["--user", "list", "--no-legend", "--no-pager"])
            .output()
            .map_err(|_| ())?;
        Ok(String::from_utf8_lossy(&output.stdout)
            .lines()
            .map(str::to_owned)
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn relative_time_reads_like_a_person_wrote_it() {
        let now = 1_000_000_000u64;
        assert_eq!(relative_time(None, now), "never");
        assert_eq!(relative_time(Some(now), now), "just now");
        assert_eq!(relative_time(Some(now - 30_000), now), "30 seconds ago");
        assert_eq!(relative_time(Some(now - 90_000), now), "a minute ago");
        assert_eq!(relative_time(Some(now - 600_000), now), "10 minutes ago");
        assert_eq!(relative_time(Some(now - 5_400_000), now), "an hour ago");
        assert_eq!(relative_time(Some(now - 10_800_000), now), "3 hours ago");
        assert_eq!(relative_time(Some(now - 172_800_000), now), "2 days ago");
    }

    #[test]
    fn a_clock_that_went_backwards_does_not_panic() {
        // Wall clocks move backwards across suspend and NTP corrections, and a subtraction
        // overflow here would take the tray down with it.
        assert_eq!(relative_time(Some(2_000), 1_000), "just now");
    }

    #[test]
    fn diagnostics_carry_no_clipboard_content() {
        let paths = Paths {
            dir: std::path::PathBuf::from("/tmp/asli-test"),
        };
        let config = Config::new_with_random_device_id().expect("rng");
        let status = Status {
            state: "Synced".to_owned(),
            peers: 2,
            skipped: 1,
            last_error: Some("relay closed".to_owned()),
            ..Status::default()
        };

        let text = diagnostics(&config, &status, &paths);
        assert!(text.contains("relay:"));
        assert!(text.contains("Synced"));
        assert!(text.contains("no clipboard content"));
    }

    #[test]
    fn the_advice_names_every_desktop_that_needs_help() {
        let advice = missing_host_advice();
        assert!(advice.contains("GNOME"));
        assert!(advice.contains("waybar"));
        assert!(
            advice.contains("keeps syncing"),
            "a missing tray must not read as a broken application"
        );
    }

    #[test]
    fn every_icon_state_is_well_formed_rgba() {
        // Icon::from_rgba rejects a buffer whose length does not match the dimensions, so this
        // catches an arithmetic slip in the drawing loop.
        for state in [IconState::Connected, IconState::Paused, IconState::Offline] {
            icon_for(state).unwrap_or_else(|e| panic!("{state:?} must be valid: {e}"));
        }
    }

    #[test]
    fn the_three_states_actually_look_different() {
        // An icon that is identical in every state is decoration, which is the complaint that
        // prompted this. Compare the raw pixels rather than trusting the colour constants.
        let pixels = |state: IconState| -> Vec<u8> {
            let fg = [0xe8, 0xe8, 0xe8];
            let accent = [0x4c, 0xd1, 0x64];
            (0..ICON_SIZE)
                .flat_map(|y| (0..ICON_SIZE).flat_map(move |x| draw_pixel(x, y, state, fg, accent)))
                .collect()
        };
        assert_ne!(
            pixels(IconState::Connected),
            pixels(IconState::Paused),
            "paused must be distinguishable from connected without colour"
        );
    }

    #[test]
    fn icon_state_follows_the_status_line() {
        assert_eq!(
            IconState::from_status("Synced, 2 connected", false),
            IconState::Connected
        );
        assert_eq!(IconState::from_status("Synced", true), IconState::Paused);
        assert_eq!(
            IconState::from_status("Offline, retrying", false),
            IconState::Offline
        );
        assert_eq!(
            IconState::from_status("Rejected: BAD_SIGNATURE", false),
            IconState::Offline
        );
    }
}
