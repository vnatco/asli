//! Windows shortcuts: the one place Asli writes a `.lnk`, and checks one.
//!
//! Every shortcut Asli puts on a Windows machine comes from here: the Startup folder entry that
//! starts it at login, written through [`crate::autostart`], and the Start menu entry, which the
//! installer and `setup.ps1` ask for with `asli shortcut create`.
//!
//! The installer used to write the Start menu entry itself, with NSIS's `CreateShortcut`. On the
//! owner's Windows 11 that produced a link carrying an environment variable data block,
//! `%USERPROFILE%\AppData\Local\Programs\Asli\asliw.exe`, filled in only in its ANSI half. Windows
//! prefers that block to the absolute path stored beside it, could not resolve it, and the entry
//! failed with "Windows can't find" and showed no icon. The Startup shortcut written here through
//! `WScript.Shell` had no such block and worked, so this now writes both, and [`check`] reads
//! every link back byte by byte and refuses one with an environment block, or whose target or
//! icon is not on disk. That check runs after every write, at the end of the install, and in the
//! build script, so this kind of link cannot ship again without something saying so.

#[cfg(target_os = "windows")]
use std::path::{Path, PathBuf};

#[cfg(target_os = "windows")]
use crate::error::{Error, Result};

/// The program a shortcut should start: the windowed binary when it sits beside this one, since
/// the console one would open a console window beside the tray.
///
/// # Errors
///
/// Returns [`Error::Io`] if the running executable cannot be located.
#[cfg(target_os = "windows")]
pub fn windowed_target() -> Result<PathBuf> {
    let exe = std::env::current_exe().map_err(Error::Io)?;
    let sibling = exe.with_file_name("asliw.exe");
    Ok(if sibling.exists() { sibling } else { exe })
}

/// Writes a shortcut at `lnk` that starts `target` with the `tray` argument, then checks it.
///
/// # Errors
///
/// Returns [`Error::Shortcut`] if the shortcut could not be written, or was written but does not
/// pass [`check`].
#[cfg(target_os = "windows")]
pub fn create(lnk: &Path, target: &Path) -> Result<()> {
    let working = target.parent().unwrap_or(target);
    if let Some(dir) = lnk.parent() {
        std::fs::create_dir_all(dir).map_err(Error::Io)?;
    }
    // Removed first, because `CreateShortcut` on an existing file loads it and edits it: a link
    // left by an earlier installer, environment block and all, would otherwise survive the rewrite.
    if lnk.exists() {
        std::fs::remove_file(lnk).map_err(Error::Io)?;
    }
    let output = powershell(&script::create(
        &lnk.display().to_string(),
        &target.display().to_string(),
        &working.display().to_string(),
    ))?;
    if !output.status.success() || !lnk.exists() {
        return Err(Error::Shortcut(format!(
            "could not write {}: {}",
            lnk.display(),
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }
    check(lnk).map(|_| ())
}

/// The program a shortcut opens, as the shell resolves it, or `None` if there is no readable
/// shortcut at `lnk`.
///
/// # Errors
///
/// Returns [`Error::Io`] if PowerShell could not be started.
#[cfg(target_os = "windows")]
pub fn target(lnk: &Path) -> Result<Option<String>> {
    if !lnk.exists() {
        return Ok(None);
    }
    let output = powershell(&script::read_target(&lnk.display().to_string()))?;
    if !output.status.success() {
        return Ok(None);
    }
    let target = String::from_utf8_lossy(&output.stdout).trim().to_owned();
    Ok((!target.is_empty()).then_some(target))
}

/// Checks a shortcut the way Explorer will use it, and returns the program it starts.
///
/// # Errors
///
/// Returns [`Error::Shortcut`] naming the fault if the file is not a readable shortcut, carries an
/// environment variable block for its target or its icon, has an icon location with no path, or
/// names a target or an icon that is not on disk.
#[cfg(target_os = "windows")]
pub fn check(lnk: &Path) -> Result<PathBuf> {
    let fail = |why: String| Error::Shortcut(format!("{}: {why}", lnk.display()));

    let bytes = std::fs::read(lnk).map_err(|err| fail(format!("could not be read: {err}")))?;
    let facts =
        lnk::inspect(&bytes).map_err(|err| fail(format!("is not a readable shortcut: {err}")))?;
    if facts.target_environment_block {
        return Err(fail(
            "names its target through an environment variable block, which Windows prefers to \
             the path and may be unable to resolve"
                .to_owned(),
        ));
    }
    if facts.icon_environment_block {
        return Err(fail(
            "names its icon through an environment variable block, which Windows may be unable \
             to resolve"
                .to_owned(),
        ));
    }

    let target = target(lnk)?.ok_or_else(|| fail("names no target".to_owned()))?;
    if !Path::new(&target).is_file() {
        return Err(fail(format!("points at {target}, which is not there")));
    }

    if let Some(icon) = facts.icon_location {
        if icon.is_empty() {
            return Err(fail("has an icon location with no path".to_owned()));
        }
        if !Path::new(&icon).is_file() {
            return Err(fail(format!(
                "takes its icon from {icon}, which is not there"
            )));
        }
    }
    Ok(PathBuf::from(target))
}

/// Runs a PowerShell script, which is how a shortcut is written and read.
///
/// A `.lnk` is a COM object, not a text file, and `WScript.Shell` is the scripted way in to the
/// same `IShellLink` a person gets from the Explorer right click menu. Shipped with every
/// supported Windows, so no dependency is taken for it.
#[cfg(target_os = "windows")]
fn powershell(script: &str) -> Result<std::process::Output> {
    use std::os::windows::process::CommandExt as _;

    /// `CREATE_NO_WINDOW`. PowerShell is a console program, and started from the windowed binary
    /// without this it flashes a console window on screen.
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;

    std::process::Command::new("powershell")
        .args(["-NoProfile", "-NonInteractive", "-Command", script])
        .creation_flags(CREATE_NO_WINDOW)
        .output()
        .map_err(Error::Io)
}

/// The PowerShell that writes and reads a shortcut.
///
/// Pure text handling, so it is compiled and tested on every platform even though only Windows
/// uses it.
#[cfg(any(target_os = "windows", test))]
mod script {
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
    ///
    /// The icon location is set to the target itself, index 0, which is the Asli icon compiled
    /// into it. Left unset, `WScript.Shell` stores `,0`: an index with no path.
    pub fn create(lnk: &str, target: &str, working: &str) -> String {
        format!(
            "$ErrorActionPreference = 'Stop'; \
             $s = (New-Object -ComObject WScript.Shell).CreateShortcut({}); \
             $s.TargetPath = {}; \
             $s.Arguments = 'tray'; \
             $s.WorkingDirectory = {}; \
             $s.IconLocation = {}; \
             $s.Description = 'Encrypted clipboard sync across your own machines'; \
             $s.Save()",
            ps_quote(lnk),
            ps_quote(target),
            ps_quote(working),
            ps_quote(&format!("{target},0"))
        )
    }

    /// Prints the program the shortcut opens, and nothing else.
    pub fn read_target(lnk: &str) -> String {
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
        fn the_shortcut_starts_the_tray_from_its_own_directory_with_its_own_icon() {
            let script = create(
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
            assert!(
                script.contains(
                    r"$s.IconLocation = 'C:\Users\v\AppData\Local\Programs\Asli\asliw.exe,0'"
                ),
                "an unset icon location is stored as ',0', with no path"
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
            let script = create(r"C:\a'b.lnk", r"C:\o'dd\asliw.exe", r"C:\o'dd");
            assert!(script.contains(r"'C:\o''dd\asliw.exe'"));
            assert!(script.contains(r"'C:\o''dd\asliw.exe,0'"));
            assert_eq!(script.matches("$s.Save()").count(), 1);
        }

        #[test]
        fn reading_prints_the_target_and_nothing_else() {
            let script = read_target(r"C:\Startup\Asli.lnk");
            assert!(script.contains(".TargetPath"));
            assert!(!script.contains("Save"));
        }
    }
}

/// Reads the parts of a `.lnk` file that decide whether Explorer can use it, following the Shell
/// Link Binary File Format ([MS-SHLLINK]).
///
/// Pure byte handling, so it is compiled and tested on every platform even though only Windows
/// uses it.
///
/// [MS-SHLLINK]: https://learn.microsoft.com/openspecs/windows_protocols/ms-shllink/
#[cfg(any(target_os = "windows", test))]
mod lnk {
    /// The fixed header, and the class id every shell link carries at offset 4.
    const HEADER_SIZE: usize = 0x4C;
    const LINK_CLSID: [u8; 16] = [
        0x01, 0x14, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x46,
    ];

    // LinkFlags, at offset 0x14.
    const HAS_TARGET_ID_LIST: u32 = 0x0000_0001;
    const HAS_LINK_INFO: u32 = 0x0000_0002;
    const HAS_NAME: u32 = 0x0000_0004;
    const HAS_RELATIVE_PATH: u32 = 0x0000_0008;
    const HAS_WORKING_DIR: u32 = 0x0000_0010;
    const HAS_ARGUMENTS: u32 = 0x0000_0020;
    const HAS_ICON_LOCATION: u32 = 0x0000_0040;
    const IS_UNICODE: u32 = 0x0000_0080;
    const HAS_EXP_STRING: u32 = 0x0000_0200;
    const HAS_EXP_ICON: u32 = 0x0000_4000;

    // Extra data block signatures.
    const ENVIRONMENT_BLOCK: u32 = 0xA000_0001;
    const ICON_ENVIRONMENT_BLOCK: u32 = 0xA000_0007;

    /// What a link says about where its target and icon are.
    #[derive(Debug, Default, PartialEq, Eq)]
    pub struct Facts {
        /// The target is named through an environment variable block.
        pub target_environment_block: bool,
        /// The icon is named through an environment variable block.
        pub icon_environment_block: bool,
        /// The icon location string, when the link has one.
        pub icon_location: Option<String>,
    }

    fn take(bytes: &[u8], at: usize, len: usize) -> Result<&[u8], String> {
        at.checked_add(len)
            .and_then(|end| bytes.get(at..end))
            .ok_or_else(|| format!("ends early, at byte {at} of {}", bytes.len()))
    }

    fn u16_at(bytes: &[u8], at: usize) -> Result<usize, String> {
        let b = take(bytes, at, 2)?;
        Ok(usize::from(u16::from_le_bytes([b[0], b[1]])))
    }

    fn u32_at(bytes: &[u8], at: usize) -> Result<u32, String> {
        let b = take(bytes, at, 4)?;
        Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    }

    fn len32_at(bytes: &[u8], at: usize) -> Result<usize, String> {
        usize::try_from(u32_at(bytes, at)?).map_err(|_| "a length does not fit".to_owned())
    }

    pub fn inspect(bytes: &[u8]) -> Result<Facts, String> {
        if len32_at(bytes, 0)? != HEADER_SIZE || take(bytes, 4, 16)? != LINK_CLSID {
            return Err("no shell link header".to_owned());
        }
        let flags = u32_at(bytes, 0x14)?;
        let mut at = HEADER_SIZE;

        if flags & HAS_TARGET_ID_LIST != 0 {
            at += 2 + u16_at(bytes, at)?;
        }
        if flags & HAS_LINK_INFO != 0 {
            // The size counts its own four bytes.
            at += len32_at(bytes, at)?;
        }

        let mut icon_location = None;
        for field in [
            HAS_NAME,
            HAS_RELATIVE_PATH,
            HAS_WORKING_DIR,
            HAS_ARGUMENTS,
            HAS_ICON_LOCATION,
        ] {
            if flags & field == 0 {
                continue;
            }
            let count = u16_at(bytes, at)?;
            at += 2;
            let text = if flags & IS_UNICODE != 0 {
                let raw = take(bytes, at, count * 2)?;
                at += count * 2;
                let units: Vec<u16> = raw
                    .as_chunks::<2>()
                    .0
                    .iter()
                    .map(|pair| u16::from_le_bytes(*pair))
                    .collect();
                String::from_utf16_lossy(&units)
            } else {
                let raw = take(bytes, at, count)?;
                at += count;
                raw.iter().map(|&b| char::from(b)).collect()
            };
            if field == HAS_ICON_LOCATION {
                // Some writers count a terminating NUL into the string, Wine's among them.
                icon_location = Some(text.trim_end_matches('\0').to_owned());
            }
        }

        let mut facts = Facts {
            target_environment_block: flags & HAS_EXP_STRING != 0,
            icon_environment_block: flags & HAS_EXP_ICON != 0,
            icon_location,
        };
        // Extra data blocks, each a size and a signature, until one smaller than a block, which
        // is the terminal block. A file may also simply end here.
        while at + 4 <= bytes.len() {
            let size = len32_at(bytes, at)?;
            if size < 8 {
                break;
            }
            match u32_at(bytes, at + 4)? {
                ENVIRONMENT_BLOCK => facts.target_environment_block = true,
                ICON_ENVIRONMENT_BLOCK => facts.icon_environment_block = true,
                _ => {}
            }
            at += size;
        }
        Ok(facts)
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        /// Builds a link: header, then optional ID list and link info, then the given strings
        /// (as UTF-16 when `unicode`), then extra data blocks by signature.
        fn link(
            extra_flags: u32,
            strings: &[(u32, &str)],
            unicode: bool,
            blocks: &[u32],
        ) -> Vec<u8> {
            let mut flags = extra_flags;
            for (field, _) in strings {
                flags |= field;
            }
            if unicode {
                flags |= IS_UNICODE;
            }
            let mut out = vec![0_u8; HEADER_SIZE];
            out[0] = 0x4C;
            out[4..20].copy_from_slice(&LINK_CLSID);
            out[0x14..0x18].copy_from_slice(&flags.to_le_bytes());
            if flags & HAS_TARGET_ID_LIST != 0 {
                out.extend_from_slice(&6_u16.to_le_bytes());
                out.extend_from_slice(&[1, 2, 3, 4, 0, 0]);
            }
            if flags & HAS_LINK_INFO != 0 {
                out.extend_from_slice(&12_u32.to_le_bytes());
                out.extend_from_slice(&[9; 8]);
            }
            let mut sorted = strings.to_vec();
            sorted.sort_by_key(|(field, _)| *field);
            for (_, text) in sorted {
                if unicode {
                    let units: Vec<u16> = text.encode_utf16().collect();
                    out.extend_from_slice(&u16::try_from(units.len()).unwrap().to_le_bytes());
                    for unit in units {
                        out.extend_from_slice(&unit.to_le_bytes());
                    }
                } else {
                    out.extend_from_slice(&u16::try_from(text.len()).unwrap().to_le_bytes());
                    out.extend_from_slice(text.as_bytes());
                }
            }
            for signature in blocks {
                // A block of 0x314 bytes, as the environment blocks are, mostly zero.
                let mut block = vec![0_u8; 0x314];
                block[0..4].copy_from_slice(&0x314_u32.to_le_bytes());
                block[4..8].copy_from_slice(&signature.to_le_bytes());
                block[8..20].copy_from_slice(b"%USERPROFILE");
                out.extend_from_slice(&block);
            }
            out.extend_from_slice(&[0, 0, 0, 0]);
            out
        }

        const ICON: &str = r"C:\Users\v\AppData\Local\Programs\Asli\asliw.exe";

        #[test]
        fn a_plain_link_passes_and_its_icon_is_read() {
            let bytes = link(
                HAS_TARGET_ID_LIST | HAS_LINK_INFO,
                &[
                    (HAS_NAME, "Encrypted clipboard sync"),
                    (HAS_WORKING_DIR, r"C:\Users\v\AppData\Local\Programs\Asli"),
                    (HAS_ARGUMENTS, "tray"),
                    (HAS_ICON_LOCATION, ICON),
                ],
                true,
                &[0xA000_0003],
            );
            assert_eq!(
                inspect(&bytes),
                Ok(Facts {
                    target_environment_block: false,
                    icon_environment_block: false,
                    icon_location: Some(ICON.to_owned()),
                })
            );
        }

        #[test]
        fn an_environment_block_for_the_target_is_found() {
            // The link NSIS wrote on the owner's Windows 11: the block is there even though the
            // flag that announces it is not always set.
            let bytes = link(
                HAS_LINK_INFO,
                &[(HAS_ARGUMENTS, "tray")],
                true,
                &[ENVIRONMENT_BLOCK],
            );
            assert!(inspect(&bytes).expect("parses").target_environment_block);

            let flagged = link(HAS_EXP_STRING, &[], true, &[]);
            assert!(inspect(&flagged).expect("parses").target_environment_block);
        }

        #[test]
        fn an_environment_block_for_the_icon_is_found() {
            let bytes = link(
                0,
                &[(HAS_ICON_LOCATION, ICON)],
                true,
                &[ICON_ENVIRONMENT_BLOCK],
            );
            let facts = inspect(&bytes).expect("parses");
            assert!(facts.icon_environment_block);
            assert!(!facts.target_environment_block);
        }

        #[test]
        fn an_icon_location_with_no_path_reads_as_empty() {
            let bytes = link(0, &[(HAS_ICON_LOCATION, "")], true, &[]);
            assert_eq!(
                inspect(&bytes).expect("parses").icon_location.as_deref(),
                Some("")
            );
        }

        #[test]
        fn a_terminating_nul_counted_into_the_icon_path_is_dropped() {
            let bytes = link(0, &[(HAS_ICON_LOCATION, "C:\\a\\asliw.exe\0")], true, &[]);
            assert_eq!(
                inspect(&bytes).expect("parses").icon_location.as_deref(),
                Some(r"C:\a\asliw.exe")
            );
        }

        #[test]
        fn an_ansi_link_is_read_too() {
            let bytes = link(0, &[(HAS_ICON_LOCATION, r"C:\a\asliw.exe")], false, &[]);
            assert_eq!(
                inspect(&bytes).expect("parses").icon_location.as_deref(),
                Some(r"C:\a\asliw.exe")
            );
        }

        #[test]
        fn anything_else_is_refused_rather_than_passed() {
            assert!(inspect(b"").is_err());
            assert!(inspect(&[0_u8; 0x60]).is_err(), "no header");
            let whole = link(0, &[(HAS_ICON_LOCATION, ICON)], true, &[]);
            assert!(inspect(&whole[..HEADER_SIZE + 10]).is_err(), "cut short");
        }
    }
}
