//! Starting at login.
//!
//! A clipboard sync tool that has to be started by hand is a clipboard sync tool that is off when
//! you need it. So this is a real feature rather than a stored preference, and it is verified by
//! reading back what was written rather than by assuming the write worked.
//!
//! Each platform has exactly one sanctioned mechanism and they share nothing, so there is no
//! common abstraction worth inventing. Linux is implemented. Windows and macOS return a clear
//! error saying so, because silently reporting success for something that will not happen is the
//! failure people only discover after their machine reboots.

use crate::error::{Error, Result};

/// Whether autostart is currently enabled for this user.
///
/// # Errors
///
/// Returns [`Error::Io`] if the state could not be determined, and [`Error::ConfigDir`] on a
/// platform where this is not implemented yet.
pub fn is_enabled() -> Result<bool> {
    platform::is_enabled()
}

/// Turns autostart on or off, and confirms the result.
///
/// Idempotent: enabling twice writes the same entry, disabling something already absent succeeds.
///
/// # Errors
///
/// Returns [`Error::Io`] if the entry could not be written or removed, or [`Error::ConfigDir`] on
/// a platform where this is not implemented yet.
pub fn set_enabled(enabled: bool) -> Result<()> {
    platform::set_enabled(enabled)?;

    // Read back rather than trust the write. The whole point of this module is that the setting
    // is true after a reboot, and the cheapest way to be wrong about that is to never look.
    let observed = platform::is_enabled()?;
    if observed == enabled {
        Ok(())
    } else {
        Err(Error::ConfigDir(format!(
            "autostart was set to {enabled} but reads back as {observed}"
        )))
    }
}

/// Where the autostart entry lives, for the status output.
///
/// # Errors
///
/// Returns [`Error::ConfigDir`] if the location cannot be determined.
pub fn describe_location() -> Result<String> {
    platform::describe_location()
}

#[cfg(target_os = "linux")]
mod platform {
    use std::fs;
    use std::path::{Path, PathBuf};

    use crate::error::{Error, Result};

    /// Filename of the desktop entry. The same basename as the application entry and the window's
    /// app id, and the name `setup.sh --uninstall` removes, so there is one name for one job.
    const ENTRY: &str = "asli.desktop";

    /// What earlier builds called it. Removed whenever the setting is applied, or a machine that
    /// ran one of them would start Asli twice at login.
    const LEGACY_ENTRY: &str = "dev.vnat.asli.desktop";

    /// The autostart directory for this user, from the environment.
    ///
    /// Only the public wrappers read the environment. Everything below takes the directory as an
    /// argument, which is what lets the tests run in parallel: they pass a path instead of
    /// mutating a process global that the other test is also using.
    fn autostart_dir() -> Result<PathBuf> {
        let base = std::env::var_os("XDG_CONFIG_HOME").map_or_else(
            || {
                std::env::var_os("HOME")
                    .map(|home| PathBuf::from(home).join(".config"))
                    .ok_or_else(|| {
                        Error::ConfigDir("neither XDG_CONFIG_HOME nor HOME is set".to_owned())
                    })
            },
            |dir| Ok(PathBuf::from(dir)),
        )?;
        Ok(base.join("autostart"))
    }

    /// The path of the running binary, so the entry survives being installed anywhere.
    fn executable() -> Result<String> {
        let path = std::env::current_exe().map_err(Error::Io)?;
        Ok(path.display().to_string())
    }

    fn contents(exe: &str) -> String {
        format!(
            "[Desktop Entry]\n\
             Type=Application\n\
             Name=Asli\n\
             Comment=Encrypted clipboard sync across your own machines\n\
             Exec={exe} tray\n\
             Icon=asli\n\
             Terminal=false\n\
             Categories=Utility;\n\
             X-GNOME-Autostart-enabled=true\n"
        )
    }

    fn is_enabled_in(dir: &Path) -> bool {
        dir.join(ENTRY).exists()
    }

    fn set_enabled_in(dir: &Path, enabled: bool, exe: &str) -> Result<()> {
        let legacy = dir.join(LEGACY_ENTRY);
        if legacy.exists() {
            fs::remove_file(&legacy).map_err(Error::Io)?;
        }

        let path = dir.join(ENTRY);
        if enabled {
            fs::create_dir_all(dir).map_err(Error::Io)?;
            fs::write(&path, contents(exe)).map_err(Error::Io)?;
        } else if path.exists() {
            fs::remove_file(&path).map_err(Error::Io)?;
        }
        Ok(())
    }

    pub fn is_enabled() -> Result<bool> {
        Ok(is_enabled_in(&autostart_dir()?))
    }

    pub fn set_enabled(enabled: bool) -> Result<()> {
        set_enabled_in(&autostart_dir()?, enabled, &executable()?)
    }

    pub fn describe_location() -> Result<String> {
        Ok(autostart_dir()?.join(ENTRY).display().to_string())
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        /// A scratch directory per test. No environment variable is touched, so these run in
        /// parallel with each other and with everything else in the crate.
        fn scratch(tag: &str) -> PathBuf {
            let nanos = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.as_nanos());
            let dir = std::env::temp_dir().join(format!("asli-autostart-{tag}-{nanos}"));
            fs::create_dir_all(&dir).expect("scratch dir");
            dir
        }

        #[test]
        fn enabling_writes_a_valid_entry_and_disabling_removes_it() {
            let dir = scratch("write");

            set_enabled_in(&dir, true, "/usr/bin/asli").expect("enables");
            let path = dir.join(ENTRY);
            assert!(path.exists(), "the entry must exist after enabling");

            let text = fs::read_to_string(&path).expect("reads back");
            assert!(text.starts_with("[Desktop Entry]"));
            assert!(text.contains("Type=Application"));
            assert!(text.contains("X-GNOME-Autostart-enabled=true"));
            assert!(
                text.contains("Terminal=false"),
                "a tray app must not open a terminal at login"
            );
            assert!(text.contains(" tray\n"), "login should start the tray");
            assert!(is_enabled_in(&dir));

            set_enabled_in(&dir, false, "/usr/bin/asli").expect("disables");
            assert!(!path.exists());
            assert!(!is_enabled_in(&dir));

            let _ = fs::remove_dir_all(dir);
        }

        #[test]
        fn enabling_twice_is_idempotent() {
            let dir = scratch("idempotent");

            set_enabled_in(&dir, true, "/usr/bin/asli").expect("enables");
            let first = fs::read_to_string(dir.join(ENTRY)).expect("reads");
            set_enabled_in(&dir, true, "/usr/bin/asli").expect("enables again");
            let second = fs::read_to_string(dir.join(ENTRY)).expect("reads");
            assert_eq!(first, second);

            // And disabling something already absent is not an error.
            set_enabled_in(&dir, false, "/usr/bin/asli").expect("disables");
            set_enabled_in(&dir, false, "/usr/bin/asli").expect("disabling twice is fine");

            let _ = fs::remove_dir_all(dir);
        }

        #[test]
        fn the_old_entry_name_is_removed_so_login_starts_one_copy() {
            let dir = scratch("legacy");
            fs::write(dir.join(LEGACY_ENTRY), "[Desktop Entry]\n").expect("writes legacy");

            set_enabled_in(&dir, true, "/usr/bin/asli").expect("enables");
            assert!(dir.join(ENTRY).exists());
            assert!(!dir.join(LEGACY_ENTRY).exists());

            let _ = fs::remove_dir_all(dir);
        }

        #[test]
        fn the_entry_points_at_the_binary_it_was_written_by() {
            let dir = scratch("exec");
            set_enabled_in(&dir, true, "/opt/asli/bin/asli").expect("enables");
            let text = fs::read_to_string(dir.join(ENTRY)).expect("reads");
            assert!(
                text.contains("Exec=/opt/asli/bin/asli tray"),
                "an installed binary must not be started from wherever it was built"
            );
            let _ = fs::remove_dir_all(dir);
        }
    }
}

#[cfg(target_os = "windows")]
mod platform {
    use crate::error::{Error, Result};

    /// The sanctioned mechanism is a value under
    /// `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` holding the quoted executable path.
    pub fn is_enabled() -> Result<bool> {
        Err(not_implemented())
    }

    pub fn set_enabled(_enabled: bool) -> Result<()> {
        Err(not_implemented())
    }

    pub fn describe_location() -> Result<String> {
        Ok(
            r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run\Asli (not implemented yet)"
                .to_owned(),
        )
    }

    fn not_implemented() -> Error {
        Error::ConfigDir(
            "autostart is not implemented on Windows yet. Add a shortcut to the Startup folder in the meantime"
                .to_owned(),
        )
    }
}

#[cfg(target_os = "macos")]
mod platform {
    use crate::error::{Error, Result};

    /// The sanctioned mechanism is a LaunchAgent plist in `~/Library/LaunchAgents`.
    pub fn is_enabled() -> Result<bool> {
        Err(not_implemented())
    }

    pub fn set_enabled(_enabled: bool) -> Result<()> {
        Err(not_implemented())
    }

    pub fn describe_location() -> Result<String> {
        Ok("~/Library/LaunchAgents/dev.vnat.asli.plist (not implemented yet)".to_owned())
    }

    fn not_implemented() -> Error {
        Error::ConfigDir(
            "autostart is not implemented on macOS yet. Add Asli under System Settings, General, Login Items in the meantime"
                .to_owned(),
        )
    }
}
