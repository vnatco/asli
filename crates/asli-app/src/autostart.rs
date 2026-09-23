//! Starting at login.
//!
//! A clipboard sync tool that has to be started by hand is a clipboard sync tool that is off when
//! you need it. So this is a real feature rather than a stored preference, and it is verified by
//! reading back what was written rather than by assuming the write worked.
//!
//! Each platform has exactly one sanctioned mechanism and they share nothing, so there is no
//! common abstraction worth inventing: an XDG autostart entry on Linux, a Startup folder shortcut
//! on Windows, and a launchd agent on macOS.

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

/// Whether the entry exists but starts a binary that is no longer there.
///
/// Happens when the program moves: a new install location, or an entry first written by a build
/// run from a source tree that has since been cleaned. Existence alone said "enabled", so the
/// entry was never rewritten and login quietly started nothing.
///
/// # Errors
///
/// Returns an error if the entry could not be read.
pub fn target_missing() -> Result<bool> {
    Ok(platform::target()?.is_some_and(|target| !std::path::Path::new(&target).exists()))
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

    /// Quotes a program path for an `Exec=` line, per the desktop entry specification.
    ///
    /// A path with a space in it otherwise splits into two arguments, and a `%` starts a field
    /// code. Inside quotes, the quote, backtick, dollar sign and backslash are escaped, and then
    /// every backslash is doubled once more, because the whole value is itself an escaped string.
    pub(super) fn exec_quote(path: &str) -> String {
        const RESERVED: &[char] = &[
            ' ', '\t', '\n', '"', '\'', '\\', '>', '<', '~', '|', '&', ';', '$', '*', '?', '#',
            '(', ')', '`',
        ];
        let percent_safe = path.replace('%', "%%");
        if !path.contains(RESERVED) {
            return percent_safe;
        }
        let mut quoted = String::from("\"");
        for c in percent_safe.chars() {
            match c {
                '"' | '`' | '$' => {
                    quoted.push_str("\\\\");
                    quoted.push(c);
                }
                '\\' => quoted.push_str("\\\\\\\\"),
                other => quoted.push(other),
            }
        }
        quoted.push('"');
        quoted
    }

    /// Reverses [`exec_quote`] for the program part of an `Exec=` line this module wrote.
    pub(super) fn exec_unquote(field: &str) -> String {
        let Some(inner) = field.strip_prefix('"').and_then(|f| f.strip_suffix('"')) else {
            return field.replace("%%", "%");
        };
        let mut out = String::new();
        let mut chars = inner.chars();
        while let Some(c) = chars.next() {
            if c == '\\' {
                // Value level escape, then argument level escape: two or four backslashes.
                let mut run = 1;
                while chars.as_str().starts_with('\\') && run < 4 {
                    chars.next();
                    run += 1;
                }
                if run == 4 {
                    out.push('\\');
                } else if let Some(next) = chars.next() {
                    out.push(next);
                }
            } else {
                out.push(c);
            }
        }
        out.replace("%%", "%")
    }

    fn contents(exe: &str) -> String {
        format!(
            "[Desktop Entry]\n\
             Type=Application\n\
             Name=Asli\n\
             Comment=Encrypted clipboard sync across your own machines\n\
             Exec={} tray\n\
             Icon=asli\n\
             Terminal=false\n\
             Categories=Utility;\n\
             X-GNOME-Autostart-enabled=true\n",
            exec_quote(exe)
        )
    }

    fn target_in(dir: &Path) -> Option<String> {
        let text = fs::read_to_string(dir.join(ENTRY)).ok()?;
        let exec = text.lines().find_map(|line| line.strip_prefix("Exec="))?;
        let program = exec.strip_suffix(" tray").unwrap_or(exec);
        Some(exec_unquote(program))
    }

    pub fn target() -> Result<Option<String>> {
        Ok(target_in(&autostart_dir()?))
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
        fn a_path_with_spaces_or_percent_survives_the_exec_line() {
            for path in [
                "/opt/asli/bin/asli",
                "/home/a b/My Apps/asli",
                "/home/x/100%/asli",
                "/home/q\"uote/$HOME/asli",
                "/home/back\\slash/asli",
            ] {
                let dir = scratch("quote");
                set_enabled_in(&dir, true, path).expect("enables");
                assert_eq!(
                    target_in(&dir).as_deref(),
                    Some(path),
                    "round trip for {path}"
                );
                let _ = fs::remove_dir_all(dir);
            }
            assert_eq!(exec_quote("/home/a b/asli"), "\"/home/a b/asli\"");
            assert_eq!(exec_quote("/opt/asli"), "/opt/asli");
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

    use super::{shortcut, startup_approved};
    use crate::error::{Error, Result};

    /// The shortcut Explorer opens at login, in this user's Startup folder.
    const LNK: &str = "Asli.lnk";

    /// Where an earlier build put the entry. Explorer enumerated it at logon and started it only
    /// for other applications, so it is removed whenever the setting is applied rather than left
    /// behind looking like it works.
    const RUN_KEY: &str = r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run";
    const RUN_VALUE: &str = "Asli";
    const APPROVED_RUN_KEY: &str =
        r"HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run";

    /// Explorer's record of which Startup folder shortcuts it will actually open. Only ever read,
    /// never written: a shortcut with no value here starts normally, and Task Manager writes one
    /// when the owner switches the entry off.
    const APPROVED_FOLDER_KEY: &str =
        r"HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\StartupFolder";

    /// `CREATE_NO_WINDOW`. `reg.exe` and `powershell.exe` are console programs, and started from
    /// the windowed binary without this they flash a console window on screen.
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;

    /// Runs `reg.exe`, the same tool a person would use, so no registry library is needed.
    fn reg(args: &[&str]) -> Result<Output> {
        Command::new("reg")
            .args(args)
            .creation_flags(CREATE_NO_WINDOW)
            .output()
            .map_err(Error::Io)
    }

    /// Runs a PowerShell script, which is how the shortcut is written and read.
    ///
    /// A `.lnk` is a COM object, not a text file, and `WScript.Shell` is the scripted way in to
    /// the same `IShellLink` a person gets from the Explorer right click menu. Shipped with every
    /// supported Windows, so this stays true to the rest of the module: use the tool that is
    /// already there rather than take a dependency.
    fn powershell(script: &str) -> Result<Output> {
        Command::new("powershell")
            .args(["-NoProfile", "-NonInteractive", "-Command", script])
            .creation_flags(CREATE_NO_WINDOW)
            .output()
            .map_err(Error::Io)
    }

    /// This user's Startup folder.
    fn startup_dir() -> Result<PathBuf> {
        std::env::var_os("APPDATA")
            .map(|appdata| {
                PathBuf::from(appdata).join(r"Microsoft\Windows\Start Menu\Programs\Startup")
            })
            .ok_or_else(|| Error::ConfigDir("APPDATA is not set".to_owned()))
    }

    fn shortcut_path() -> Result<PathBuf> {
        Ok(startup_dir()?.join(LNK))
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
        if !shortcut_path()?.exists() {
            return Ok(false);
        }
        // A shortcut the owner switched off in Task Manager is still in the folder, and login
        // still ignores it. Report what Windows will do, not what the folder alone suggests.
        let output = reg(&["query", APPROVED_FOLDER_KEY, "/v", LNK])?;
        if !output.status.success() {
            return Ok(true);
        }
        let text = String::from_utf8_lossy(&output.stdout);
        Ok(startup_approved::reads_as_enabled(&text, LNK))
    }

    /// Removes the registry entries an earlier build wrote, so no machine keeps a dead one.
    fn remove_run_entries() -> Result<()> {
        for key in [RUN_KEY, APPROVED_RUN_KEY] {
            if reg(&["query", key, "/v", RUN_VALUE])?.status.success() {
                let output = reg(&["delete", key, "/v", RUN_VALUE, "/f"])?;
                if !output.status.success() {
                    return Err(Error::ConfigDir(format!(
                        "reg.exe could not remove {key}\\{RUN_VALUE}: {}",
                        String::from_utf8_lossy(&output.stderr).trim()
                    )));
                }
            }
        }
        Ok(())
    }

    pub fn set_enabled(enabled: bool) -> Result<()> {
        remove_run_entries()?;

        let path = shortcut_path()?;
        if enabled {
            let target = launch_target()?;
            let working = target.parent().unwrap_or(&target);
            std::fs::create_dir_all(startup_dir()?).map_err(Error::Io)?;
            let script = shortcut::create_script(
                &path.display().to_string(),
                &target.display().to_string(),
                &working.display().to_string(),
            );
            let output = powershell(&script)?;
            if !output.status.success() || !path.exists() {
                return Err(Error::ConfigDir(format!(
                    "could not write {}: {}",
                    path.display(),
                    String::from_utf8_lossy(&output.stderr).trim()
                )));
            }
        } else if path.exists() {
            std::fs::remove_file(&path).map_err(Error::Io)?;
        }
        Ok(())
    }

    pub fn describe_location() -> Result<String> {
        Ok(shortcut_path()?.display().to_string())
    }

    /// The program the shortcut opens, read back out of the `.lnk`.
    pub fn target() -> Result<Option<String>> {
        let path = shortcut_path()?;
        if !path.exists() {
            return Ok(None);
        }
        let output = powershell(&shortcut::read_script(&path.display().to_string()))?;
        if !output.status.success() {
            return Ok(None);
        }
        let target = String::from_utf8_lossy(&output.stdout).trim().to_owned();
        Ok((!target.is_empty()).then_some(target))
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
        // Resolved, because the command may have been run through the ~/.local/bin link, and the
        // agent should start the binary inside the bundle, not a link that may be removed.
        let exe = std::env::current_exe().map_err(Error::Io)?;
        let exe = std::fs::canonicalize(&exe).unwrap_or(exe);
        launch_agent::set_enabled_in(
            &agents_dir()?,
            enabled,
            &exe.display().to_string(),
            &log_file()?,
        )
    }

    /// Where the agent sends the output of a copy started at login.
    ///
    /// `~/Library/Logs` is where a user's applications log on macOS, and launchd will write there
    /// without any help. It matters more here than anywhere else: a copy started at login has no
    /// terminal, and a menu bar application that fails to appear leaves nothing at all to read.
    pub fn log_file() -> Result<String> {
        std::env::var_os("HOME")
            .map(|home| {
                PathBuf::from(home)
                    .join("Library/Logs/Asli/asli.log")
                    .display()
                    .to_string()
            })
            .ok_or_else(|| Error::ConfigDir("HOME is not set".to_owned()))
    }

    pub fn target() -> Result<Option<String>> {
        Ok(launch_agent::target_in(&agents_dir()?))
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

    pub fn contents(exe: &str, log: &str) -> String {
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
             \t<key>StandardOutPath</key>\n\
             \t<string>{1}</string>\n\
             \t<key>StandardErrorPath</key>\n\
             \t<string>{1}</string>\n\
             </dict>\n\
             </plist>\n",
            xml(exe),
            xml(log)
        )
    }

    pub fn is_enabled_in(dir: &Path) -> bool {
        dir.join(FILE).exists()
    }

    /// The program the agent starts: the first string of `ProgramArguments`, unescaped.
    pub fn target_in(dir: &Path) -> Option<String> {
        let text = fs::read_to_string(dir.join(FILE)).ok()?;
        let after = text.split("<key>ProgramArguments</key>").nth(1)?;
        let start = after.find("<string>")? + "<string>".len();
        let end = after[start..].find("</string>")? + start;
        Some(
            after[start..end]
                .replace("&lt;", "<")
                .replace("&gt;", ">")
                .replace("&amp;", "&"),
        )
    }

    pub fn set_enabled_in(dir: &Path, enabled: bool, exe: &str, log: &str) -> Result<()> {
        let path = dir.join(FILE);
        if enabled {
            fs::create_dir_all(dir).map_err(Error::Io)?;
            // launchd creates the file but not the directory above it, and a path it cannot open
            // is dropped in silence, which is the one thing this is here to prevent.
            if let Some(parent) = Path::new(log).parent() {
                fs::create_dir_all(parent).map_err(Error::Io)?;
            }
            fs::write(&path, contents(exe, log)).map_err(Error::Io)?;
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
            let text = contents(
                "/Applications/Asli.app/Contents/MacOS/asli",
                "/Users/v/Library/Logs/Asli/asli.log",
            );
            assert!(text.contains("<string>dev.vnat.asli</string>"));
            assert!(text.contains(
                "<string>/Applications/Asli.app/Contents/MacOS/asli</string>\n\t\t<string>tray</string>"
            ));
            assert!(text.contains("<key>RunAtLoad</key>\n\t<true/>"));
            assert!(
                text.contains("<key>KeepAlive</key>\n\t<false/>"),
                "Quit from the menu must stay quit"
            );
            // A copy started at login has no terminal. Without these, a menu bar application that
            // never appears leaves nothing at all to read, which is how one lost morning went.
            assert!(text.contains(
                "<key>StandardOutPath</key>\n\t<string>/Users/v/Library/Logs/Asli/asli.log</string>"
            ));
            assert!(text.contains(
                "<key>StandardErrorPath</key>\n\t<string>/Users/v/Library/Logs/Asli/asli.log</string>"
            ));
        }

        #[test]
        fn a_path_cannot_break_out_of_its_element() {
            let text = contents(
                "/Users/a&b/<odd>/asli",
                "/Users/a&b/Library/Logs/Asli/asli.log",
            );
            assert!(text.contains("<string>/Users/a&amp;b/&lt;odd&gt;/asli</string>"));
            assert!(text.contains("<string>/Users/a&amp;b/Library/Logs/Asli/asli.log</string>"));
        }

        #[test]
        fn the_target_reads_back_as_written() {
            let dir = scratch("target");
            let log = dir.join("Logs/asli.log");
            set_enabled_in(
                &dir,
                true,
                "/Users/a&b/Apps/Asli.app/Contents/MacOS/asli",
                &log.display().to_string(),
            )
            .expect("enables");
            assert!(
                log.parent().is_some_and(std::path::Path::exists),
                "launchd does not create the directory, so enabling must"
            );
            assert_eq!(
                target_in(&dir).as_deref(),
                Some("/Users/a&b/Apps/Asli.app/Contents/MacOS/asli")
            );
            let _ = fs::remove_dir_all(dir);
        }

        #[test]
        fn enabling_and_disabling_write_and_remove_the_file() {
            let dir = scratch("toggle");
            let log = dir.join("Logs/asli.log").display().to_string();
            set_enabled_in(&dir, true, "/usr/local/bin/asli", &log).expect("enables");
            assert!(is_enabled_in(&dir));
            set_enabled_in(&dir, true, "/usr/local/bin/asli", &log).expect("enables twice");
            set_enabled_in(&dir, false, "/usr/local/bin/asli", &log).expect("disables");
            assert!(!is_enabled_in(&dir));
            set_enabled_in(&dir, false, "/usr/local/bin/asli", &log).expect("disables twice");
            let _ = fs::remove_dir_all(dir);
        }
    }
}

/// Explorer's record of which startup entries the owner has switched off.
///
/// Under `...\Explorer\StartupApproved\` Explorer keeps one binary value per entry: the first
/// byte says whether the entry is on, and the remaining eleven are the time it was last switched
/// off. The low bit of the first byte is the off switch, since Task Manager writes `03` when the
/// owner turns an app off and `02` when they turn it back on.
///
/// Only read, never written. A fresh entry has no value here and starts anyway, and writing one
/// is no substitute for an entry Explorer will honour: a `Run` value with a byte identical to a
/// working application's was still skipped at logon, twice, which is why autostart is a Startup
/// folder shortcut now. Reading it is what makes `asli autostart` report what Windows will do
/// rather than what the entry's presence alone suggests.
///
/// Pure text handling, so it is compiled and tested on every platform even though only Windows
/// uses it.
#[cfg(any(target_os = "windows", test))]
mod startup_approved {
    /// Reads a `reg query ... /v <value>` listing of a `REG_BINARY` value.
    ///
    /// Anything unreadable counts as enabled: the `Run` value is there, and a listing this could
    /// not parse is no reason to tell the owner their setting is off.
    pub fn reads_as_enabled(listing: &str, value: &str) -> bool {
        let Some(hex) = listing
            .lines()
            .map(str::trim)
            .filter_map(|line| line.strip_prefix(value))
            .find(|rest| rest.starts_with(char::is_whitespace))
            .and_then(|rest| rest.split_whitespace().next_back())
        else {
            return true;
        };
        match u8::from_str_radix(hex.get(..2).unwrap_or(""), 16) {
            Ok(first) => first & 1 == 0,
            Err(_) => true,
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn task_manager_switching_the_app_off_reads_as_off() {
            let off = "\r\nHKEY_CURRENT_USER\\...\\StartupApproved\\StartupFolder\r\n    \
                       Asli.lnk    REG_BINARY    03000000EEFC1B8A2FA5DC01\r\n\r\n";
            assert!(!reads_as_enabled(off, "Asli.lnk"));

            let on = "\r\n    Asli.lnk    REG_BINARY    020000000000000000000000\r\n";
            assert!(reads_as_enabled(on, "Asli.lnk"));
        }

        #[test]
        fn an_unreadable_listing_does_not_claim_the_setting_is_off() {
            for listing in [
                "",
                "\r\nHKEY_CURRENT_USER\\...\\Run\r\n",
                "    Asli    REG_BINARY",
            ] {
                assert!(reads_as_enabled(listing, "Asli"), "for {listing:?}");
            }
        }

        #[test]
        fn another_entry_whose_name_starts_the_same_is_not_mistaken_for_ours() {
            let other = "\r\n    AsliOther    REG_BINARY    030000000000000000000000\r\n";
            assert!(reads_as_enabled(other, "Asli"));
        }
    }
}

/// The PowerShell that writes and reads the Startup folder shortcut.
///
/// Pure text handling, so it is compiled and tested on every platform even though only Windows
/// uses it.
#[cfg(any(target_os = "windows", test))]
mod shortcut {
    /// Quotes a path as a single quoted PowerShell string.
    ///
    /// Single quotes because PowerShell expands `$` and treats the backtick as an escape inside
    /// double quotes, and a Windows path is full of neither but a user name can hold anything. In
    /// a single quoted string the only character with a meaning is the quote itself, which is
    /// written twice.
    pub fn ps_quote(text: &str) -> String {
        format!("'{}'", text.replace('\'', "''"))
    }

    /// Creates the shortcut, pointing at the binary with the `tray` argument.
    pub fn create_script(lnk: &str, target: &str, working: &str) -> String {
        format!(
            "$ErrorActionPreference = 'Stop'; \
             $s = (New-Object -ComObject WScript.Shell).CreateShortcut({}); \
             $s.TargetPath = {}; \
             $s.Arguments = 'tray'; \
             $s.WorkingDirectory = {}; \
             $s.Description = 'Encrypted clipboard sync across your own machines'; \
             $s.Save()",
            ps_quote(lnk),
            ps_quote(target),
            ps_quote(working)
        )
    }

    /// Prints the program the shortcut opens, and nothing else.
    pub fn read_script(lnk: &str) -> String {
        format!(
            "$ErrorActionPreference = 'Stop'; \
             Write-Output (New-Object -ComObject WScript.Shell).CreateShortcut({}).TargetPath",
            ps_quote(lnk)
        )
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn the_shortcut_starts_the_tray_from_its_own_directory() {
            let script = create_script(
                r"C:\Users\v\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\Asli.lnk",
                r"C:\Users\v\AppData\Local\Programs\Asli\asliw.exe",
                r"C:\Users\v\AppData\Local\Programs\Asli",
            );
            assert!(script
                .contains(r"$s.TargetPath = 'C:\Users\v\AppData\Local\Programs\Asli\asliw.exe'"));
            assert!(
                script.contains("$s.Arguments = 'tray'"),
                "login should start the tray"
            );
            assert!(script.contains("$s.Save()"));
            assert!(
                script.contains("$ErrorActionPreference = 'Stop'"),
                "a failure must not exit zero and look like success"
            );
        }

        #[test]
        fn a_quote_in_a_user_name_cannot_end_the_string_early() {
            assert_eq!(
                ps_quote(r"C:\Users\o'brien\asliw.exe"),
                r"'C:\Users\o''brien\asliw.exe'"
            );
            let script = create_script(r"C:\a'b.lnk", r"C:\o'dd\asliw.exe", r"C:\o'dd");
            assert!(script.contains(r"'C:\o''dd\asliw.exe'"));
            assert_eq!(script.matches("$s.Save()").count(), 1);
        }

        #[test]
        fn reading_prints_the_target_and_nothing_else() {
            let script = read_script(r"C:\Startup\Asli.lnk");
            assert!(script.contains(".TargetPath"));
            assert!(!script.contains("Save"));
        }
    }
}
