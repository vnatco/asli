//! The join token: the one string a person moves between their devices.
//!
//! ```text
//! payload  = u8(1) || secret[32]
//! checksum = SHA-256("asli/v1/join-check" || payload)[0 .. 3]
//! token    = "asli1_" || Crockford-Base32(payload || checksum)
//! ```
//!
//! Design notes, because each choice here was deliberate:
//!
//! - There is no account id in the token. The room id is derivable from the secret, so carrying
//!   it would be pure length. Those characters buy a checksum instead, which catches a mistyped
//!   or truncated string immediately rather than failing later as a confusing connection error.
//! - Crockford base32 is uppercase, excludes I, L, O and U, survives case mangling by chat
//!   clients, can be read aloud, and lands in the QR alphanumeric mode.
//! - It is not a URL. A bare token does not tempt anyone to paste it into a browser address bar,
//!   where it would be sent to a search engine, or into a chat client that unfurls links.

use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::base32;
use crate::error::{Error, Result};
use crate::kdf::KEY_LEN;

/// Human visible prefix. The digit is the token format version.
pub const TOKEN_PREFIX: &str = "asli1_";
/// Current token format version byte.
pub const TOKEN_VERSION: u8 = 1;
/// Domain separation label for the token checksum.
pub const LABEL_JOIN_CHECK: &[u8] = b"asli/v1/join-check";
/// Length of the checksum in bytes.
pub const CHECKSUM_LEN: usize = 3;
/// Length of the encoded body in base32 characters.
pub const TOKEN_BODY_CHARS: usize = 58;
/// Total token length in characters, including the prefix.
pub const TOKEN_CHARS: usize = TOKEN_PREFIX.len() + TOKEN_BODY_CHARS;

fn checksum(payload: &[u8]) -> [u8; CHECKSUM_LEN] {
    let mut hasher = Sha256::new();
    hasher.update(LABEL_JOIN_CHECK);
    hasher.update(payload);
    let digest = hasher.finalize();
    let mut out = [0u8; CHECKSUM_LEN];
    out.copy_from_slice(&digest[..CHECKSUM_LEN]);
    out
}

/// Renders the join token for a root secret.
///
/// The returned string is secret material. Callers must treat it as such: suppress it in the
/// clipboard watcher before writing it to the clipboard, and clear it afterwards.
#[must_use]
pub fn encode(secret: &[u8; KEY_LEN]) -> Zeroizing<String> {
    let mut payload = Zeroizing::new(Vec::with_capacity(1 + KEY_LEN + CHECKSUM_LEN));
    payload.push(TOKEN_VERSION);
    payload.extend_from_slice(secret);
    let sum = checksum(&payload);
    payload.extend_from_slice(&sum);

    let mut token = Zeroizing::new(String::with_capacity(TOKEN_CHARS));
    token.push_str(TOKEN_PREFIX);
    token.push_str(&base32::encode(&payload));
    token
}

/// `str::strip_prefix`, ignoring ASCII case, and safe on any input.
///
/// Works in characters rather than bytes, so no input can ask for a slice that splits one.
///
/// Returns the remainder after the prefix, or `None` when the input does not start with it.
fn strip_prefix_ignore_ascii_case<'a>(input: &'a str, prefix: &str) -> Option<&'a str> {
    let end = input
        .char_indices()
        .nth(prefix.chars().count())
        .map_or(input.len(), |(at, _)| at);
    let head = input.get(..end)?;
    head.eq_ignore_ascii_case(prefix).then(|| &input[end..])
}

/// Parses a join token back into the root secret.
///
/// Parsing is strict about structure and tolerant about presentation: surrounding whitespace is
/// stripped, the prefix match is case insensitive, and hyphens inside the body are ignored.
///
/// # Errors
///
/// Each failure mode is distinct so the user interface can say exactly what is wrong:
/// [`Error::TokenPrefix`], [`Error::TokenAlphabet`], [`Error::TokenLength`],
/// [`Error::TokenVersion`] or [`Error::TokenChecksum`].
pub fn parse(input: &str) -> Result<Zeroizing<[u8; KEY_LEN]>> {
    let trimmed = input.trim();

    // Split on a character boundary, never a byte offset. Slicing a `str` at byte 6 panics when
    // byte 6 lands inside a multi byte character, and this runs on every keystroke in the join
    // field: one pasted emoji would have taken the window down with it.
    let Some(body) = strip_prefix_ignore_ascii_case(trimmed, TOKEN_PREFIX) else {
        return Err(Error::TokenPrefix);
    };

    let decoded = Zeroizing::new(base32::decode(body)?);
    if decoded.len() != 1 + KEY_LEN + CHECKSUM_LEN {
        return Err(Error::TokenLength);
    }

    let version = decoded[0];
    if version != TOKEN_VERSION {
        return Err(Error::TokenVersion(version));
    }

    let (payload, sum) = decoded.split_at(1 + KEY_LEN);
    if checksum(payload) != sum {
        return Err(Error::TokenChecksum);
    }

    let mut secret = Zeroizing::new([0u8; KEY_LEN]);
    secret.copy_from_slice(&payload[1..]);
    Ok(secret)
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_SECRET: [u8; 32] = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
        0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d,
        0x1e, 0x1f,
    ];

    #[test]
    fn round_trips() {
        let token = encode(&TEST_SECRET);
        let parsed = parse(&token).expect("parses");
        assert_eq!(*parsed, TEST_SECRET);
    }

    #[test]
    fn has_the_documented_length() {
        let token = encode(&TEST_SECRET);
        assert_eq!(token.len(), TOKEN_CHARS, "token is {}", token.as_str());
        assert!(token.starts_with(TOKEN_PREFIX));
    }

    #[test]
    fn tolerates_presentation_differences() {
        let token = encode(&TEST_SECRET);
        assert_eq!(
            *parse(&format!("  {}  ", token.as_str())).unwrap(),
            TEST_SECRET
        );
        assert_eq!(
            *parse(&format!("\n{}\n", token.as_str())).unwrap(),
            TEST_SECRET
        );
        assert_eq!(*parse(&token.to_lowercase()).unwrap(), TEST_SECRET);
    }

    #[test]
    fn rejects_a_missing_or_wrong_prefix() {
        let token = encode(&TEST_SECRET);
        let body = &token[TOKEN_PREFIX.len()..];
        assert_eq!(parse(body), Err(Error::TokenPrefix));
        assert_eq!(parse(&format!("clip://{body}")), Err(Error::TokenPrefix));
        assert_eq!(parse(""), Err(Error::TokenPrefix));
    }

    #[test]
    fn rejects_a_truncated_token() {
        let token = encode(&TEST_SECRET);
        let short = &token[..token.len() - 4];
        assert_eq!(parse(short), Err(Error::TokenLength));
    }

    #[test]
    fn rejects_a_mistyped_character() {
        let token = encode(&TEST_SECRET);
        let mut chars: Vec<char> = token.chars().collect();
        // Flip a character in the body to another valid alphabet symbol.
        let idx = TOKEN_PREFIX.len() + 5;
        chars[idx] = if chars[idx] == 'Z' { 'Y' } else { 'Z' };
        let mutated: String = chars.into_iter().collect();
        assert_eq!(parse(&mutated), Err(Error::TokenChecksum));
    }

    #[test]
    fn rejects_an_unknown_version() {
        let mut payload = vec![2u8];
        payload.extend_from_slice(&TEST_SECRET);
        let sum = checksum(&payload);
        payload.extend_from_slice(&sum);
        let token = format!("{TOKEN_PREFIX}{}", base32::encode(&payload));
        assert_eq!(parse(&token), Err(Error::TokenVersion(2)));
    }

    #[test]
    fn rejects_invalid_characters() {
        let token = encode(&TEST_SECRET);
        let mutated = format!("{}!{}", &token[..10], &token[11..]);
        assert_eq!(parse(&mutated), Err(Error::TokenAlphabet));
    }

    #[test]
    fn different_secrets_give_different_tokens() {
        let mut other = TEST_SECRET;
        other[31] ^= 0x01;
        assert_ne!(*encode(&TEST_SECRET), *encode(&other));
    }
}

#[cfg(test)]
mod boundary_tests {
    use super::*;

    #[test]
    fn a_pasted_character_cannot_crash_the_parser() {
        // Every one of these used to reach a byte slice that split a character in half.
        for input in [
            "a\u{1F600}\u{1F600}",
            "\u{1F600}",
            "asli\u{1F600}",
            "\u{00E9}\u{00E9}\u{00E9}\u{00E9}",
            "asli1_\u{1F600}",
            "\u{202E}asli1_",
            "",
            "     ",
        ] {
            // The only requirement is that it returns rather than panics.
            let _ = parse(input);
        }
    }

    #[test]
    fn the_prefix_is_still_matched_case_insensitively() {
        let secret = [7u8; KEY_LEN];
        let token = encode(&secret);
        let upper = token.to_uppercase();
        assert_eq!(*parse(&token).expect("round trip"), secret);
        assert_eq!(*parse(&upper).expect("upper case round trip"), secret);
        assert!(matches!(parse("xxxx1_abc"), Err(Error::TokenPrefix)));
    }
}
