//! Text normalization.
//!
//! Every platform hands us slightly different bytes for the same copy. Windows appends a NUL to
//! `CF_UNICODETEXT` and uses CRLF, some Windows applications prepend a UTF-8 BOM, and macOS and
//! Linux do neither. If we hash what the platform gave us, the same text hashes differently on
//! each machine, the loop guard misses, and the clipboard ping pongs between two devices with the
//! text growing on every hop. That is not hypothetical: it is Deskflow issue 10139.
//!
//! So there is exactly one rule: normalize first, then hash, then send. The receiving side
//! converts back to the local convention when it writes.

use std::borrow::Cow;

/// The line ending convention a platform expects when we write to its clipboard.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LineEnding {
    /// Carriage return plus line feed. Windows.
    Crlf,
    /// Line feed. macOS and Linux.
    Lf,
}

impl LineEnding {
    /// The convention for the platform this binary was built for.
    #[must_use]
    pub const fn native() -> Self {
        if cfg!(windows) {
            Self::Crlf
        } else {
            Self::Lf
        }
    }
}

/// Normalizes clipboard text into the form that goes on the wire and into the hash.
///
/// Three changes, and deliberately no more:
///
/// 1. Strip a leading UTF-8 BOM.
/// 2. Strip a single trailing NUL, which Windows adds to `CF_UNICODETEXT`.
/// 3. Convert CRLF and lone CR to LF.
///
/// What it does **not** do is trim surrounding whitespace. People copy indentation and trailing
/// newlines on purpose, and trimming makes pasting into a terminal behave differently from the
/// source. We hash exactly what we send.
#[must_use]
pub fn normalize(input: &str) -> Cow<'_, str> {
    let mut text = input;

    if let Some(stripped) = text.strip_prefix('\u{feff}') {
        text = stripped;
    }
    if let Some(stripped) = text.strip_suffix('\0') {
        text = stripped;
    }

    if text.contains('\r') {
        let mut out = String::with_capacity(text.len());
        let mut chars = text.chars().peekable();
        while let Some(ch) = chars.next() {
            if ch == '\r' {
                // Consume the LF of a CRLF pair, and map a lone CR to LF as well.
                if chars.peek() == Some(&'\n') {
                    chars.next();
                }
                out.push('\n');
            } else {
                out.push(ch);
            }
        }
        return Cow::Owned(out);
    }

    // `text` is either `input` itself or a subslice of it, so borrowing is always correct here.
    Cow::Borrowed(text)
}

/// Converts normalized text back to a platform's convention, for writing to the clipboard.
#[must_use]
pub fn to_platform(text: &str, ending: LineEnding) -> Cow<'_, str> {
    match ending {
        LineEnding::Lf => Cow::Borrowed(text),
        LineEnding::Crlf => {
            if text.contains('\n') {
                Cow::Owned(text.replace('\n', "\r\n"))
            } else {
                Cow::Borrowed(text)
            }
        }
    }
}

/// Whether a clipboard event is worth syncing at all.
///
/// Empty and whitespace only payloads are almost always an intermediate state while an
/// application sets several formats in sequence, not something a person intended to copy.
#[must_use]
pub fn is_syncable(text: &str) -> bool {
    !text.trim().is_empty()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strips_a_bom() {
        assert_eq!(normalize("\u{feff}hello"), "hello");
        // Only a leading one, and only one.
        assert_eq!(normalize("hello\u{feff}"), "hello\u{feff}");
    }

    #[test]
    fn strips_one_trailing_nul() {
        assert_eq!(normalize("hello\0"), "hello");
        assert_eq!(normalize("hello\0\0"), "hello\0");
    }

    #[test]
    fn normalizes_line_endings() {
        assert_eq!(normalize("a\r\nb"), "a\nb");
        assert_eq!(normalize("a\rb"), "a\nb");
        assert_eq!(normalize("a\nb"), "a\nb");
        assert_eq!(normalize("a\r\n\r\nb"), "a\n\nb");
        assert_eq!(normalize("a\r\n"), "a\n");
    }

    #[test]
    fn keeps_meaningful_whitespace() {
        assert_eq!(normalize("    indented"), "    indented");
        assert_eq!(normalize("trailing newline\n"), "trailing newline\n");
        assert_eq!(normalize("  spaced  "), "  spaced  ");
    }

    #[test]
    fn the_same_text_from_three_platforms_normalizes_identically() {
        let windows = "\u{feff}line one\r\nline two\r\n\0";
        let macos = "line one\nline two\n";
        let linux = "line one\nline two\n";
        assert_eq!(normalize(windows), normalize(macos));
        assert_eq!(normalize(macos), normalize(linux));
    }

    #[test]
    fn round_trips_through_a_platform_conversion() {
        let original = "a\r\nb\r\nc";
        let normalized = normalize(original);
        assert_eq!(normalized, "a\nb\nc");
        assert_eq!(to_platform(&normalized, LineEnding::Crlf), original);
        assert_eq!(to_platform(&normalized, LineEnding::Lf), "a\nb\nc");
    }

    #[test]
    fn handles_unicode_without_mangling_it() {
        let text = "emoji: 🙂 georgian: ასლი cjk: 日本語";
        assert_eq!(normalize(text), text);
        assert_eq!(to_platform(text, LineEnding::Crlf), text);
    }

    #[test]
    fn rejects_empty_and_whitespace_only() {
        assert!(!is_syncable(""));
        assert!(!is_syncable("   "));
        assert!(!is_syncable("\n\n"));
        assert!(!is_syncable("\t \r\n"));
        assert!(is_syncable("x"));
        assert!(is_syncable("  x  "));
    }

    #[test]
    fn borrows_when_nothing_changes() {
        let input = "nothing to do here";
        assert!(matches!(normalize(input), Cow::Borrowed(_)));
    }
}
