//! Files dropped on the Asli window under Wayland.
//!
//! winit, which gives Asli its window, implements drag and drop on Windows, macOS and X11 but not on
//! Wayland. There a drag over the window was offered to a client that never answered, so the drag
//! hung in place until it timed out. This crate answers it: it joins winit's own Wayland
//! connection, takes the seat's data device, accepts a list of files when one is dragged over
//! Asli's window, and reads the files' paths when it is dropped.
//!
//! # The one unsafe call
//!
//! Joining winit's connection means adopting the `wl_display` pointer winit hands out, which the
//! Wayland library can only take on trust. It lives here, in a crate of its own, so every other
//! crate keeps `#![forbid(unsafe_code)]`, and the call carries its safety argument where it is
//! made.

#![deny(unsafe_code)]

#[cfg(target_os = "linux")]
mod wayland;

#[cfg(target_os = "linux")]
pub use wayland::DropTarget;

/// What happened to a drag over the window.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DropEvent {
    /// Files are being dragged over the window.
    Entered,
    /// The drag left the window without dropping.
    Left,
    /// Files were dropped on the window. Local paths only; anything else in the list is left out.
    Dropped(Vec<std::path::PathBuf>),
    /// Something was dropped, but the list of files could not be read from the program it came
    /// from.
    Unreadable,
}

#[cfg(unix)]
/// The paths a `text/uri-list` names, local files only: comments, blank lines and anything that
/// is not a `file://` URI are skipped, and percent escapes are decoded.
#[must_use]
pub fn paths_from_uri_list(list: &str) -> Vec<std::path::PathBuf> {
    list.lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .filter_map(|uri| {
            let rest = uri.strip_prefix("file://")?;
            // `file:///path` has an empty host; `file://localhost/path` names this machine.
            let path = rest.strip_prefix("localhost").unwrap_or(rest);
            if !path.starts_with('/') {
                return None;
            }
            percent_decode(path).map(std::path::PathBuf::from)
        })
        .collect()
}

#[cfg(unix)]
fn percent_decode(text: &str) -> Option<std::ffi::OsString> {
    use std::os::unix::ffi::OsStringExt as _;
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            let hex = std::str::from_utf8(bytes.get(i + 1..i + 3)?).ok()?;
            out.push(u8::from_str_radix(hex, 16).ok()?);
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    Some(std::ffi::OsString::from_vec(out))
}

#[cfg(all(test, unix))]
mod tests {
    use super::paths_from_uri_list;
    use std::path::PathBuf;

    #[test]
    fn a_uri_list_becomes_local_paths() {
        let list = "# from Dolphin\r\nfile:///home/a/Report%20final.pdf\r\nfile://localhost/tmp/x%C3%A9.txt\r\n\r\nhttps://example.com/not-a-file\r\nfile://otherhost/share/y\r\n";
        assert_eq!(
            paths_from_uri_list(list),
            vec![
                PathBuf::from("/home/a/Report final.pdf"),
                PathBuf::from("/tmp/xé.txt"),
            ]
        );
    }
}
