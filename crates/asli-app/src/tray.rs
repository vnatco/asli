//! The tray icon and its menu.
//!
//! # Why everything is in the menu
//!
//! On Linux the tray is the `StatusNotifierItem` D-Bus protocol, which delivers no click events to
//! applications. There is no such thing as "left click opens a popup" here. So every action lives
//! in the menu, and the same menu is used on all three platforms so behaviour never diverges.
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
use tray_icon::{Icon, TrayIcon, TrayIconBuilder};

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
    pub const SETTINGS: &str = "asli.settings";
    pub const DIAGNOSTICS: &str = "asli.diagnostics";
    pub const QUIT: &str = "asli.quit";
}

/// What the tray asks the rest of the application to do.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Command {
    /// Stop syncing until resumed.
    Pause,
    /// Start syncing again.
    Resume,
    /// Write the relay's stored clip to the local clipboard, on request.
    PasteRetained,
    /// Show the join token again.
    ShowToken,
    /// Open the settings file.
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
    /// Held because dropping it removes the icon from the session.
    _icon: TrayIcon,
    status_item: MenuItem,
    last_sync_item: MenuItem,
    pause_item: MenuItem,
    retained_item: MenuItem,
    paused: Arc<AtomicBool>,
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
        let last_sync_item = MenuItem::new("Last sync: never", false, None);
        let pause_item = MenuItem::with_id(id::PAUSE, "Pause sync", true, None);
        let retained_item =
            MenuItem::with_id(id::PASTE_RETAINED, "Paste last synced clip", true, None);
        let show_token_item = MenuItem::with_id(id::SHOW_TOKEN, "Show join string", true, None);
        let settings_item = MenuItem::with_id(id::SETTINGS, "Settings", true, None);
        let diagnostics_item = MenuItem::with_id(id::DIAGNOSTICS, "Copy diagnostics", true, None);
        let quit_item = MenuItem::with_id(id::QUIT, "Quit", true, None);

        menu.append_items(&[
            &status_item,
            &last_sync_item,
            &PredefinedMenuItem::separator(),
            &pause_item,
            &retained_item,
            &PredefinedMenuItem::separator(),
            &show_token_item,
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
            .with_icon(default_icon()?)
            .build()
            .map_err(|e| Error::ConfigDir(format!("could not register the tray icon: {e}")))?;

        Ok(Self {
            _icon: icon,
            status_item,
            last_sync_item,
            pause_item,
            retained_item,
            paused,
        })
    }

    /// Refreshes the menu from the current daemon state.
    pub fn refresh(&self, status: &Status, now_ms: u64) {
        let paused = self.paused.load(Ordering::Relaxed);

        self.status_item.set_text(if paused {
            "Paused".to_owned()
        } else {
            status.line()
        });
        self.last_sync_item.set_text(format!(
            "Last sync: {}",
            relative_time(status.last_sync_ms, now_ms)
        ));
        self.pause_item
            .set_text(if paused { "Resume sync" } else { "Pause sync" });
        self.retained_item.set_enabled(status.has_retained);
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
            id::SETTINGS => Some(Command::Settings),
            id::DIAGNOSTICS => Some(Command::Diagnostics),
            id::QUIT => Some(Command::Quit),
            _ => None,
        }
    }

    /// How often the caller should call [`Tray::refresh`].
    #[must_use]
    pub const fn refresh_interval() -> Duration {
        REFRESH
    }
}

/// A small solid icon drawn in code.
///
/// Shipping a PNG would mean finding it at runtime, which is a packaging problem on three
/// platforms for something that is 16 by 16 pixels. The shape is deliberately simple: a rounded
/// square, which reads as "clipboard" at tray size better than any detail would.
fn default_icon() -> Result<Icon> {
    const SIZE: u32 = 32;
    let mut rgba = Vec::with_capacity((SIZE * SIZE * 4) as usize);

    for y in 0..SIZE {
        for x in 0..SIZE {
            // Corners are cut so the square reads as rounded at tray size, where the icon is
            // often 16 pixels across and a sharp corner looks like a rendering artefact.
            let near_x = !(7..SIZE - 7).contains(&x);
            let near_y = !(7..SIZE - 7).contains(&y);
            let corner = near_x && near_y;
            let edge = !(4..SIZE - 4).contains(&x) || !(4..SIZE - 4).contains(&y);
            let inside = !edge && !corner;

            if inside {
                rgba.extend_from_slice(&[0xe8, 0xe8, 0xe8, 0xff]);
            } else if corner {
                rgba.extend_from_slice(&[0, 0, 0, 0]);
            } else {
                rgba.extend_from_slice(&[0x9a, 0x9a, 0x9a, 0xff]);
            }
        }
    }

    Icon::from_rgba(rgba, SIZE, SIZE)
        .map_err(|e| Error::ConfigDir(format!("could not build the tray icon: {e}")))
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

/// Opens the settings file in whatever the desktop uses for text.
///
/// A settings window is a whole user interface for six values, and the file is already documented,
/// human readable JSON. This is the smaller honest version of that feature.
///
/// # Errors
///
/// Returns [`Error::Io`] if the opener could not be started.
pub fn open_settings(paths: &Paths) -> Result<()> {
    let path = paths.config_file();

    #[cfg(target_os = "linux")]
    let opener = "xdg-open";
    #[cfg(target_os = "macos")]
    let opener = "open";
    #[cfg(target_os = "windows")]
    let opener = "explorer";

    std::process::Command::new(opener)
        .arg(&path)
        .spawn()
        .map(|_| ())
        .map_err(Error::Io)
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
        let output = Command::new("busctl")
            .args(["--user", "list", "--no-legend", "--no-pager"])
            .output()
            .map_err(|_| ())?;

        let listing = String::from_utf8_lossy(&output.stdout);
        Ok(listing.lines().any(|line| line.starts_with(name)))
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
    fn the_icon_is_well_formed_rgba() {
        // Icon::from_rgba rejects a buffer whose length does not match the dimensions, so this
        // catches an arithmetic slip in the drawing loop.
        default_icon().expect("the built in icon must always be valid");
    }
}
