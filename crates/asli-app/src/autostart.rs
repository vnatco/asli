//! Starting at login.
//!
//! A clipboard sync tool that has to be started by hand is a clipboard sync tool that is off when
//! you need it. So this is a real feature rather than a stored preference, and it is verified by
//! reading back what was written rather than by assuming the write worked.
//!
//! Each platform has exactly one sanctioned mechanism and they share nothing, so there is no
//! common abstraction worth inventing: an XDG autostart entry on Linux, the `Run` key on Windows,
//! and a launchd agent on macOS.

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
    use std::os::windows::process::CommandExt as _;
    use std::path::{Path, PathBuf};
    use std::process::{Command, Output};

    use crate::error::{Error, Result};

    /// The per user key Windows reads at login. No administrator rights are needed to write it,
    /// and Settings, Apps, Startup lists and toggles what is here.
    const RUN_KEY: &str = r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run";
    const VALUE: &str = "Asli";

    /// `CREATE_NO_WINDOW`. `reg.exe` is a console program, and started from the windowed binary
    /// without this it flashes a console window on screen.
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;

    /// Runs `reg.exe`, the same tool a person would use, so no registry library is needed.
    fn reg(args: &[&str]) -> Result<Output> {
        Command::new("reg")
            .args(args)
            .creation_flags(CREATE_NO_WINDOW)
            .output()
            .map_err(Error::Io)
    }

    /// What login should start: the windowed binary when it sits beside this one, since the
    /// console one would open a console window at every login.
    fn launch_target() -> Result<PathBuf> {
        let exe = std::env::current_exe().map_err(Error::Io)?;
        Ok(windowed_sibling(&exe).unwrap_or(exe))
    }

    fn windowed_sibling(exe: &Path) -> Option<PathBuf> {
        let sibling = exe.with_file_name("asliw.exe");
        sibling.exists().then_some(sibling)
    }

    pub fn is_enabled() -> Result<bool> {
        // reg query exits 1 when the value does not exist, which is the answer rather than a
        // failure.
        Ok(reg(&["query", RUN_KEY, "/v", VALUE])?.status.success())
    }

    pub fn set_enabled(enabled: bool) -> Result<()> {
        let output = if enabled {
            let command = format!("\"{}\" tray", launch_target()?.display());
            reg(&[
                "add", RUN_KEY, "/v", VALUE, "/t", "REG_SZ", "/d", &command, "/f",
            ])?
        } else {
            if !is_enabled()? {
                return Ok(());
            }
            reg(&["delete", RUN_KEY, "/v", VALUE, "/f"])?
        };

        if output.status.success() {
            Ok(())
        } else {
            Err(Error::ConfigDir(format!(
                "reg.exe could not update {RUN_KEY}: {}",
                String::from_utf8_lossy(&output.stderr).trim()
            )))
        }
    }

    #[allow(clippy::unnecessary_wraps)] // Same signature on every platform; Linux can fail.
    pub fn describe_location() -> Result<String> {
        Ok(format!(r"{RUN_KEY}\{VALUE}"))
    }
}

#[cfg(target_os = "macos")]
mod platform {
    use std::path::PathBuf;

    use super::launch_agent;
    use crate::error::{Error, Result};

    /// `~/Library/LaunchAgents`, which launchd reads for this user at login.
    fn agents_dir() -> Result<PathBuf> {
        std::env::var_os("HOME")
            .map(|home| PathBuf::from(home).join("Library/LaunchAgents"))
            .ok_or_else(|| Error::ConfigDir("HOME is not set".to_owned()))
    }

    pub fn is_enabled() -> Result<bool> {
        Ok(launch_agent::is_enabled_in(&agents_dir()?))
    }

    pub fn set_enabled(enabled: bool) -> Result<()> {
        let exe = std::env::current_exe().map_err(Error::Io)?;
        launch_agent::set_enabled_in(&agents_dir()?, enabled, &exe.display().to_string())
    }

    pub fn describe_location() -> Result<String> {
        Ok(agents_dir()?.join(launch_agent::FILE).display().to_string())
    }
}

/// The macOS login item, as a launchd agent.
///
/// A property list in `~/Library/LaunchAgents` is read by launchd at every login. Written and not
/// loaded: loading it now would start a second copy beside the one already running, which the
/// single instance lock would only turn away again. It takes effect at the next login, which is
/// what the setting means.
///
/// Pure file handling, so it is compiled and tested on every platform even though only macOS
/// uses it.
#[cfg(any(target_os = "macos", test))]
mod launch_agent {
    use std::fs;
    use std::path::Path;

    use crate::error::{Error, Result};

    /// The job label, which launchd requires to be unique, in reverse DNS form.
    pub const LABEL: &str = "dev.vnat.asli";
    /// The file launchd reads. Named after the label, which is the convention.
    pub const FILE: &str = "dev.vnat.asli.plist";

    /// Escapes text for an XML element body.
    fn xml(text: &str) -> String {
        text.replace('&', "&amp;")
            .replace('<', "&lt;")
            .replace('>', "&gt;")
    }

    pub fn contents(exe: &str) -> String {
        format!(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
             <!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n\
             <plist version=\"1.0\">\n\
             <dict>\n\
             \t<key>Label</key>\n\
             \t<string>{LABEL}</string>\n\
             \t<key>ProgramArguments</key>\n\
             \t<array>\n\
             \t\t<string>{}</string>\n\
             \t\t<string>tray</string>\n\
             \t</array>\n\
             \t<key>RunAtLoad</key>\n\
             \t<true/>\n\
             \t<key>KeepAlive</key>\n\
             \t<false/>\n\
             \t<key>ProcessType</key>\n\
             \t<string>Interactive</string>\n\
             \t<key>LimitLoadToSessionType</key>\n\
             \t<string>Aqua</string>\n\
             </dict>\n\
             </plist>\n",
            xml(exe)
        )
    }

    pub fn is_enabled_in(dir: &Path) -> bool {
        dir.join(FILE).exists()
    }

    pub fn set_enabled_in(dir: &Path, enabled: bool, exe: &str) -> Result<()> {
        let path = dir.join(FILE);
        if enabled {
            fs::create_dir_all(dir).map_err(Error::Io)?;
            fs::write(&path, contents(exe)).map_err(Error::Io)?;
        } else if path.exists() {
            fs::remove_file(&path).map_err(Error::Io)?;
        }
        Ok(())
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        fn scratch(tag: &str) -> std::path::PathBuf {
            let dir = std::env::temp_dir()
                .join(format!("asli-launch-agent-{tag}-{}", std::process::id()));
            let _ = fs::remove_dir_all(&dir);
            dir
        }

        #[test]
        fn the_agent_starts_the_tray_at_login_and_is_not_restarted_after_quit() {
            let text = contents("/Applications/Asli.app/Contents/MacOS/asli");
            assert!(text.contains("<string>dev.vnat.asli</string>"));
            assert!(text.contains(
                "<string>/Applications/Asli.app/Contents/MacOS/asli</string>\n\t\t<string>tray</string>"
            ));
            assert!(text.contains("<key>RunAtLoad</key>\n\t<true/>"));
            assert!(
                text.contains("<key>KeepAlive</key>\n\t<false/>"),
                "Quit from the menu must stay quit"
            );
        }

        #[test]
        fn a_path_cannot_break_out_of_its_element() {
            let text = contents("/Users/a&b/<odd>/asli");
            assert!(text.contains("<string>/Users/a&amp;b/&lt;odd&gt;/asli</string>"));
        }

        #[test]
        fn enabling_and_disabling_write_and_remove_the_file() {
            let dir = scratch("toggle");
            set_enabled_in(&dir, true, "/usr/local/bin/asli").expect("enables");
            assert!(is_enabled_in(&dir));
            set_enabled_in(&dir, true, "/usr/local/bin/asli").expect("enables twice");
            set_enabled_in(&dir, false, "/usr/local/bin/asli").expect("disables");
            assert!(!is_enabled_in(&dir));
            set_enabled_in(&dir, false, "/usr/local/bin/asli").expect("disables twice");
            let _ = fs::remove_dir_all(dir);
        }
    }
}
