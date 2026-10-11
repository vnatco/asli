//! Showing a received file in the system's file manager, selected, without opening the file, and
//! opening a web page in the default browser.
//!
//! Asli never opens a file another device sent. Showing its folder is the safe way to hand it to
//! the person: the file manager shows it, and what happens next is their choice.

use std::path::Path;
use std::process::Command;

/// Opens the folder holding `path` in the file manager, with the file selected where the system
/// can do that.
///
/// # Errors
///
/// Returns a sentence when the file is gone or no file manager could be started.
pub fn show_in_folder(path: &Path) -> Result<(), String> {
    if !path.exists() {
        return Err("the file is no longer there".to_owned());
    }
    reveal(path)
}

/// Opens a web address in the default browser. Only ever called with addresses Asli itself names,
/// never one that arrived from another device.
///
/// # Errors
///
/// Returns a sentence when no browser could be started.
pub fn open_in_browser(url: &str) -> Result<(), String> {
    #[cfg(target_os = "windows")]
    let mut command = {
        let mut command = Command::new("explorer.exe");
        command.arg(url);
        command
    };
    #[cfg(target_os = "macos")]
    let mut command = {
        let mut command = Command::new("open");
        command.arg(url);
        command
    };
    #[cfg(not(any(target_os = "windows", target_os = "macos")))]
    let mut command = {
        let mut command = Command::new("xdg-open");
        command.arg(url);
        command
    };
    command.spawn().map(drop).map_err(|err| err.to_string())
}

#[cfg(target_os = "windows")]
fn reveal(path: &Path) -> Result<(), String> {
    // Explorer takes the switch and the path as one argument, and returns a failure code even
    // when it worked, so only a failure to start counts.
    let mut select = std::ffi::OsString::from("/select,");
    select.push(path.as_os_str());
    Command::new("explorer.exe")
        .arg(select)
        .spawn()
        .map(drop)
        .map_err(|err| err.to_string())
}

#[cfg(target_os = "macos")]
fn reveal(path: &Path) -> Result<(), String> {
    Command::new("open")
        .arg("-R")
        .arg(path)
        .spawn()
        .map(drop)
        .map_err(|err| err.to_string())
}

#[cfg(not(any(target_os = "windows", target_os = "macos")))]
fn reveal(path: &Path) -> Result<(), String> {
    // The freedesktop file manager interface selects the file; every common desktop's file
    // manager provides it. Without it, opening the folder is the next best thing.
    let uri = file_uri(path);
    let selected = Command::new("dbus-send")
        .args([
            "--session",
            "--print-reply",
            "--dest=org.freedesktop.FileManager1",
            "--type=method_call",
            "/org/freedesktop/FileManager1",
            "org.freedesktop.FileManager1.ShowItems",
        ])
        .arg(format!("array:string:{uri}"))
        .arg("string:")
        .output()
        .is_ok_and(|out| out.status.success());
    if selected {
        return Ok(());
    }
    let folder = path.parent().unwrap_or(path);
    Command::new("xdg-open")
        .arg(folder)
        .spawn()
        .map(drop)
        .map_err(|err| err.to_string())
}

/// A `file://` URI for a path, with everything but unreserved characters and `/` escaped.
#[cfg(not(any(target_os = "windows", target_os = "macos")))]
fn file_uri(path: &Path) -> String {
    use std::fmt::Write as _;
    use std::os::unix::ffi::OsStrExt as _;
    let mut uri = String::from("file://");
    for &byte in path.as_os_str().as_bytes() {
        if byte.is_ascii_alphanumeric() || b"/-_.~".contains(&byte) {
            uri.push(char::from(byte));
        } else {
            let _ = write!(uri, "%{byte:02X}");
        }
    }
    uri
}

#[cfg(all(test, not(any(target_os = "windows", target_os = "macos"))))]
mod tests {
    #[test]
    fn a_path_becomes_an_escaped_file_uri() {
        assert_eq!(
            super::file_uri(std::path::Path::new("/home/a b/r,é.pdf")),
            "file:///home/a%20b/r%2C%C3%A9.pdf"
        );
    }
}
