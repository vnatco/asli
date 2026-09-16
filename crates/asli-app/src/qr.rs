//! Rendering the join token as a QR code in the terminal.
//!
//! The QR is the primary way to move the key between devices, and the copy button is the
//! secondary one. That ordering is deliberate: this application synchronises the clipboard, so
//! putting the root key on the clipboard hands it to our own watcher, to the relay's retained
//! slot, to Windows Cloud Clipboard, and to every clipboard history tool the person runs.
//!
//! The QR is never written to a file. It exists on screen, for as long as the person is looking
//! at it, and nowhere else.

use std::fmt::Write as _;

use fast_qr::QRBuilder;

use crate::error::{Error, Result};

/// Renders a QR code as text, using half block characters so it stays square in a terminal.
///
/// # Errors
///
/// Returns [`Error::Qr`] if the payload cannot be encoded, which for a join token means the token
/// was malformed.
pub fn render(payload: &str) -> Result<String> {
    let code = QRBuilder::new(payload)
        .build()
        .map_err(|e| Error::Qr(format!("{e:?}")))?;

    let size = code.size;
    let dark = |x: usize, y: usize| -> bool {
        if x >= size || y >= size {
            // The quiet zone around the symbol is light, and every reader needs it to exist.
            return false;
        }
        code.data[y * size + x].value()
    };

    // Two rows are drawn per line with an upper half block, which makes the modules square in a
    // terminal whose cells are roughly twice as tall as they are wide.
    let quiet = 2usize;
    let span = size + quiet * 2;
    let mut out = String::new();

    let mut row = 0;
    while row < span {
        for col in 0..span {
            let top = dark(col.wrapping_sub(quiet), row.wrapping_sub(quiet));
            let bottom = dark(col.wrapping_sub(quiet), (row + 1).wrapping_sub(quiet));
            out.push(match (top, bottom) {
                (true, true) => '\u{2588}',
                (true, false) => '\u{2580}',
                (false, true) => '\u{2584}',
                (false, false) => ' ',
            });
        }
        out.push('\n');
        row += 2;
    }

    Ok(out)
}

/// Renders the same QR as inline SVG, for display outside a terminal.
///
/// The half block rendering above is for a terminal and is unreadable anywhere else. A tray menu
/// has no terminal, so the reveal page needs a form a browser can draw. SVG rather than PNG
/// because it stays sharp at any size, needs no encoder, and embeds directly in the page with no
/// second file to write or clean up.
///
/// # Errors
///
/// Returns [`Error::Qr`] if the payload cannot be encoded.
pub fn render_svg(payload: &str) -> Result<String> {
    let code = QRBuilder::new(payload)
        .build()
        .map_err(|e| Error::Qr(format!("{e:?}")))?;

    let size = code.size;
    // Every reader needs the quiet zone, and four modules is what the specification asks for.
    let quiet = 4usize;
    let span = size + quiet * 2;

    let mut modules = String::new();
    for y in 0..size {
        for x in 0..size {
            if code.data[y * size + x].value() {
                let cx = x + quiet;
                let cy = y + quiet;
                // Adjacent rectangles share edges, which some renderers hairline. Drawing each
                // module one hundredth larger closes the seam without shifting the grid.
                let _ = write!(
                    modules,
                    "<rect x=\"{cx}\" y=\"{cy}\" width=\"1.01\" height=\"1.01\"/>"
                );
            }
        }
    }

    Ok(format!(
        "<svg xmlns=\"http://www.w3.org/2000/svg\" viewBox=\"0 0 {span} {span}\" \
shape-rendering=\"crispEdges\" role=\"img\" aria-label=\"Join token QR code\">\
<rect width=\"{span}\" height=\"{span}\" fill=\"#fff\"/>\
<g fill=\"#000\">{modules}</g></svg>"
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn renders_something_square_and_non_empty() {
        let text = render("asli1_TESTTOKENVALUE").expect("renders");
        let lines: Vec<&str> = text.lines().collect();
        assert!(
            lines.len() > 8,
            "expected a real symbol, got {} lines",
            lines.len()
        );

        let width = lines[0].chars().count();
        assert!(width > 8);
        for line in &lines {
            assert_eq!(
                line.chars().count(),
                width,
                "every row must be the same width"
            );
        }
    }

    #[test]
    fn contains_dark_modules() {
        let text = render("asli1_TESTTOKENVALUE").expect("renders");
        assert!(
            text.chars()
                .any(|c| c == '\u{2588}' || c == '\u{2580}' || c == '\u{2584}'),
            "a QR with no dark modules is not a QR"
        );
    }

    #[test]
    fn a_long_token_still_encodes() {
        // Real join tokens are 64 characters.
        let token = format!("asli1_{}", "0123456789ABCDEFGHJKMNPQRSTVWXYZ".repeat(2));
        assert!(render(&token).is_ok());
    }

    #[test]
    fn the_svg_is_self_contained_and_has_modules() {
        let svg = render_svg("asli1_TESTTOKENVALUE").expect("renders");
        assert!(svg.starts_with("<svg"));
        assert!(svg.ends_with("</svg>"));
        assert!(svg.contains("<rect"), "a QR with no modules is not a QR");
        // Nothing fetched: a page that loaded anything would leak that a key was displayed.
        assert!(!svg.contains("href"));
    }

    #[test]
    fn the_svg_keeps_the_quiet_zone() {
        // Without the margin many readers simply fail, and the failure looks like a bad camera.
        let svg = render_svg("asli1_TESTTOKENVALUE").expect("renders");
        let view = svg
            .split("viewBox=\"")
            .nth(1)
            .and_then(|s| s.split('"').next());
        let span: usize = view
            .expect("viewBox")
            .split_whitespace()
            .nth(2)
            .expect("width")
            .parse()
            .expect("number");
        assert!(
            span >= 21 + 8,
            "expected a quiet zone on both sides, got {span}"
        );
    }
}
