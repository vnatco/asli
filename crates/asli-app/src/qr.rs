//! Rendering the join token as a QR code, for a terminal and for the window.
//!
//! The QR is the primary way to move the key between devices, and the copy button is the
//! secondary one. That ordering is deliberate: this application synchronises the clipboard, so
//! putting the root key on the clipboard hands it to our own watcher, to the relay's retained
//! slot, to Windows Cloud Clipboard, and to every clipboard history tool the person runs.
//!
//! The QR is never written to a file. It exists on screen, for as long as the person is looking
//! at it, and nowhere else.

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

/// Renders the same QR as raw RGBA pixels, one pixel per module, for drawing in the window.
///
/// The half block form above is for a terminal and is unreadable anywhere else. This returns the
/// symbol at its natural size and lets the window scale it up with nearest neighbour sampling,
/// which keeps the module edges hard. Scaling here instead would mean shipping a larger buffer to
/// say the same thing.
///
/// The symbol is always drawn dark on white regardless of the application's theme, because a QR
/// inverted to suit a dark background is unreadable to most cameras.
///
/// Returns the side length in pixels, including the quiet zone, and the pixel data.
///
/// # Errors
///
/// Returns [`Error::Qr`] if the payload cannot be encoded.
pub fn render_rgba(payload: &str) -> Result<(u32, Vec<u8>)> {
    let code = QRBuilder::new(payload)
        .build()
        .map_err(|e| Error::Qr(format!("{e:?}")))?;

    let size = code.size;
    // Four modules, the same quiet zone the specification asks for and the SVG form uses.
    let quiet = 4usize;
    let span = size + quiet * 2;

    let mut pixels = vec![0xffu8; span * span * 4];
    for y in 0..size {
        for x in 0..size {
            if code.data[y * size + x].value() {
                let offset = ((y + quiet) * span + (x + quiet)) * 4;
                pixels[offset] = 0;
                pixels[offset + 1] = 0;
                pixels[offset + 2] = 0;
                pixels[offset + 3] = 0xff;
            }
        }
    }

    let span =
        u32::try_from(span).map_err(|_| Error::Qr("symbol is implausibly large".to_owned()))?;
    Ok((span, pixels))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rgba_is_square_opaque_and_has_a_quiet_zone() {
        let (span, pixels) = render_rgba("asli1_TESTTOKENVALUE").expect("renders");
        let span_usize = span as usize;

        assert_eq!(
            pixels.len(),
            span_usize * span_usize * 4,
            "the buffer must describe a square of exactly this side"
        );
        assert!(
            pixels.as_chunks::<4>().0.iter().all(|px| px[3] == 0xff),
            "every pixel must be opaque, or the white ground shows through as grey"
        );

        // The corner sits inside the quiet zone, which is what a reader looks for first.
        assert_eq!(
            &pixels[0..4],
            &[0xff, 0xff, 0xff, 0xff],
            "the quiet zone is light"
        );

        assert!(
            pixels.as_chunks::<4>().0.iter().any(|px| px[0] == 0),
            "a symbol with no dark modules is not a symbol"
        );
    }

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
}
