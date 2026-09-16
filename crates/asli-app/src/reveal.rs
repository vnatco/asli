//! Showing the join token on screen.
//!
//! # Why this exists
//!
//! The token used to be printed to stdout. That works for `asli show` in a terminal and is
//! useless from a tray menu, which has no terminal attached: the QR went into a log file nobody
//! reads, so clicking "Show join string" looked like a button that did nothing.
//!
//! # Why HTML rather than a PNG
//!
//! A PNG of the QR cannot carry the token text or the warning that goes with it, and both matter:
//! the token is the fallback when a camera is not to hand, and the warning is the only thing
//! standing between a person and pasting their account key into a chat window. A single page
//! carries all three. It also sidesteps the image viewer question entirely, which is real here:
//! on this machine the registered handler for `image/png` is a browser anyway.
//!
//! # Why not a window of our own
//!
//! Drawing a window means a GUI toolkit, and this project deliberately has none. A page opened
//! with the desktop's own opener costs nothing and works on all three platforms.
//!
//! # Handling of the file
//!
//! Written to the cache directory with owner only permissions, and deleted after a short delay.
//! The token is the account key in full, so it is never written world readable and never left
//! behind.

use std::fs;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::thread;
use std::time::Duration;

use crate::error::{Error, Result};
use crate::qr;

/// How long the page stays on disk before it is removed.
///
/// Long enough to scan a QR without hurrying, short enough that a forgotten file is not a
/// permanent copy of the key.
const LIFETIME: Duration = Duration::from_secs(180);

/// Builds the page, opens it, and schedules its removal.
///
/// # Errors
///
/// Returns [`Error::Io`] if the file cannot be written or the opener cannot be started, and
/// [`Error::Qr`] if the token cannot be encoded.
pub fn show_token(token: &str, cache_dir: &Path) -> Result<PathBuf> {
    let svg = qr::render_svg(token)?;
    let page = page_html(token, &svg);

    fs::create_dir_all(cache_dir).map_err(Error::Io)?;
    let path = cache_dir.join("join.html");
    write_owner_only(&path, page.as_bytes())?;

    open(&path)?;
    schedule_removal(path.clone());
    Ok(path)
}

/// Writes a file only the owner can read.
///
/// The permissions are set at creation rather than afterwards, because a file that is briefly
/// world readable is world readable.
fn write_owner_only(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut options = fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);

    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }

    let mut file = options.open(path).map_err(Error::Io)?;
    file.write_all(bytes).map_err(Error::Io)?;
    file.flush().map_err(Error::Io)
}

/// Removes the page after [`LIFETIME`], so the key is not left on disk.
fn schedule_removal(path: PathBuf) {
    let _ = thread::Builder::new()
        .name("asli-reveal-cleanup".to_owned())
        .spawn(move || {
            thread::sleep(LIFETIME);
            let _ = fs::remove_file(&path);
        });
}

/// Hands the page to the desktop's own opener.
fn open(path: &Path) -> Result<()> {
    #[cfg(target_os = "linux")]
    let opener = "xdg-open";
    #[cfg(target_os = "macos")]
    let opener = "open";
    #[cfg(target_os = "windows")]
    let opener = "explorer";

    std::process::Command::new(opener)
        .arg(path)
        .spawn()
        .map(|_| ())
        .map_err(Error::Io)
}

/// The page itself: QR, token, and the warning, with no network references of any kind.
///
/// Everything is inline. A page that fetched a font or a stylesheet would leak the fact that a
/// key was displayed, and would render as unstyled text offline.
fn page_html(token: &str, qr_svg: &str) -> String {
    format!(
        "<!doctype html>\n\
<html lang=\"en\">\n\
<head>\n\
<meta charset=\"utf-8\">\n\
<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n\
<title>Asli join string</title>\n\
<style>\n\
  :root {{ color-scheme: light dark; }}\n\
  body {{ font-family: system-ui, sans-serif; margin: 0; padding: 2rem 1rem;\n\
         display: flex; flex-direction: column; align-items: center; gap: 1.25rem; }}\n\
  h1 {{ font-size: 1.1rem; font-weight: 600; margin: 0; letter-spacing: 0.02em; }}\n\
  .qr {{ background: #fff; padding: 1rem; border-radius: 12px; line-height: 0; }}\n\
  .qr svg {{ width: min(60vw, 280px); height: auto; }}\n\
  code {{ font-family: ui-monospace, monospace; font-size: 0.95rem; word-break: break-all;\n\
          text-align: center; max-width: 34rem; display: block; padding: 0.75rem 1rem;\n\
          border: 1px solid rgba(128,128,128,0.4); border-radius: 8px; }}\n\
  .warn {{ max-width: 34rem; font-size: 0.9rem; line-height: 1.5; opacity: 0.85; text-align: center; }}\n\
  .warn strong {{ opacity: 1; }}\n\
</style>\n\
</head>\n\
<body>\n\
<h1>Scan this on your other device</h1>\n\
<div class=\"qr\">{qr_svg}</div>\n\
<code>{token}</code>\n\
<p class=\"warn\"><strong>Anyone who sees this has your clipboard.</strong> Do not send it over\n\
chat or email. Scanning the QR is safest. Copying it marks it so clipboard history and cloud sync\n\
skip it, but software that ignores those markers can still read it.</p>\n\
<p class=\"warn\">Or run <code>asli join &lt;token&gt;</code> on the other device. This page deletes\n\
itself in three minutes.</p>\n\
</body>\n\
</html>\n"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    const TOKEN: &str = "asli1_0123456789ABCDEFGHJKMNPQRSTVWXYZ0123456789ABCDEFGHJKMNPQ";

    #[test]
    fn the_page_carries_the_token_the_qr_and_the_warning() {
        let svg = qr::render_svg(TOKEN).expect("renders");
        let html = page_html(TOKEN, &svg);

        assert!(html.contains(TOKEN), "the token must be readable as text");
        assert!(html.contains("<svg"), "the QR must be inline");
        assert!(
            html.contains("has your clipboard"),
            "the warning is not optional"
        );
    }

    #[test]
    fn the_page_references_nothing_over_the_network() {
        // A page that fetched anything would tell a third party that a key was displayed.
        //
        // The one permitted occurrence of a URL is the SVG namespace, which is an identifier
        // rather than an address: no renderer ever retrieves it. Everything else must be absent.
        let svg = qr::render_svg(TOKEN).expect("renders");
        let html = page_html(TOKEN, &svg);

        let fetching = html
            .replace("xmlns=\"http://www.w3.org/2000/svg\"", "")
            .replace("http://www.w3.org/2000/svg", "");

        assert!(!fetching.contains("http://"), "no plain http references");
        assert!(!fetching.contains("https://"), "no https references");
        assert!(
            !fetching.contains("src="),
            "nothing is loaded into the page"
        );
        assert!(!fetching.contains("@import"), "no imported stylesheets");
    }

    #[test]
    fn the_file_is_written_owner_only() {
        let dir = std::env::temp_dir().join(format!("asli-reveal-test-{}", std::process::id()));
        fs::create_dir_all(&dir).expect("temp dir");
        let path = dir.join("join.html");
        write_owner_only(&path, b"secret").expect("writes");

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let mode = fs::metadata(&path).expect("stat").permissions().mode();
            assert_eq!(mode & 0o777, 0o600, "the key must not be world readable");
        }

        fs::remove_file(&path).ok();
        fs::remove_dir(&dir).ok();
    }
}
