//! Crockford base32, used for the room id and the join token.
//!
//! Crockford's alphabet is uppercase, excludes the ambiguous letters I, L, O and U, and lands in
//! the QR alphanumeric mode, which is denser than byte mode. Decoding is tolerant: lowercase is
//! accepted, and the classic confusions (I, L to 1, and O to 0) are folded, so a token read aloud
//! or retyped still works.
//!
//! We do not implement Crockford's optional check symbol. The join token carries its own 24 bit
//! checksum instead, which covers the whole payload rather than a single character.

use crate::error::{Error, Result};

const ALPHABET: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

/// Encodes bytes as uppercase Crockford base32, without padding.
#[must_use]
pub fn encode(input: &[u8]) -> String {
    let mut out = String::with_capacity(input.len().div_ceil(5) * 8);
    let mut buffer: u16 = 0;
    let mut bits: u8 = 0;

    for &byte in input {
        buffer = (buffer << 8) | u16::from(byte);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            let index = ((buffer >> bits) & 0x1f) as usize;
            out.push(ALPHABET[index] as char);
        }
    }

    if bits > 0 {
        let index = ((buffer << (5 - bits)) & 0x1f) as usize;
        out.push(ALPHABET[index] as char);
    }

    out
}

/// Decodes Crockford base32 into bytes.
///
/// Hyphens are ignored, lowercase is accepted, and the letters I, L and O are folded onto 1, 1
/// and 0 respectively.
///
/// # Errors
///
/// Returns [`Error::TokenAlphabet`] if the input contains a character outside the alphabet, or
/// [`Error::TokenLength`] if the input ends mid byte with non zero trailing bits, which is what a
/// truncated string looks like.
pub fn decode(input: &str) -> Result<Vec<u8>> {
    let mut out = Vec::with_capacity(input.len() * 5 / 8);
    let mut buffer: u16 = 0;
    let mut bits: u8 = 0;

    for ch in input.chars() {
        if ch == '-' {
            continue;
        }
        let value = symbol_value(ch)?;
        buffer = (buffer << 5) | u16::from(value);
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            let byte = ((buffer >> bits) & 0xff) as u8;
            out.push(byte);
        }
    }

    // Any leftover bits must be the zero padding the encoder produced. Non zero leftovers mean the
    // string was truncated or tampered with, so report that rather than blaming the alphabet: the
    // difference is what lets the user interface say "this looks cut off" instead of "bad
    // characters".
    if bits > 0 && (buffer & ((1 << bits) - 1)) != 0 {
        return Err(Error::TokenLength);
    }

    Ok(out)
}

fn symbol_value(ch: char) -> Result<u8> {
    let upper = ch.to_ascii_uppercase();
    match upper {
        '0' | 'O' => Ok(0),
        '1' | 'I' | 'L' => Ok(1),
        '2'..='9' => Ok(upper as u8 - b'0'),
        'A'..='H' => Ok(upper as u8 - b'A' + 10),
        'J' | 'K' => Ok(upper as u8 - b'J' + 18),
        'M' | 'N' => Ok(upper as u8 - b'M' + 20),
        'P'..='T' => Ok(upper as u8 - b'P' + 22),
        'V'..='Z' => Ok(upper as u8 - b'V' + 27),
        _ => Err(Error::TokenAlphabet),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_arbitrary_lengths() {
        for len in 0..40usize {
            let bytes: Vec<u8> = (0..len)
                .map(|i| u8::try_from((i * 7 + 3) % 256).unwrap())
                .collect();
            let encoded = encode(&bytes);
            let decoded = decode(&encoded).expect("decodes");
            assert_eq!(bytes, decoded, "round trip failed at length {len}");
        }
    }

    #[test]
    fn encodes_known_values() {
        // 16 zero bytes is 128 bits, which is 26 base32 characters.
        assert_eq!(encode(&[0u8; 16]).len(), 26);
        assert_eq!(encode(&[0u8; 16]), "0".repeat(26));
        assert_eq!(encode(b"foobar"), "CSQPYRK1E8");
    }

    #[test]
    fn folds_ambiguous_characters() {
        // O folds to 0, and I and L fold to 1, so these must decode identically. Eight characters
        // is exactly five bytes, so there are no trailing bits to worry about here.
        assert_eq!(decode("OI000000").unwrap(), decode("01000000").unwrap());
        assert_eq!(decode("LI000000").unwrap(), decode("11000000").unwrap());
        assert_eq!(decode("oi000000").unwrap(), decode("01000000").unwrap());
    }

    #[test]
    fn rejects_non_canonical_trailing_bits() {
        // Four characters carry twenty bits, so four bits are left over. Non zero leftovers mean
        // the string was cut short.
        assert_eq!(decode("000Z"), Err(Error::TokenLength));
        // Zero leftovers are the encoder's own padding and must be accepted.
        assert!(decode("0000").is_ok());
    }

    #[test]
    fn accepts_lowercase_and_hyphens() {
        assert_eq!(decode("csqpyrk1e8").unwrap(), b"foobar");
        assert_eq!(decode("CSQP-YRK1-E8").unwrap(), b"foobar");
    }

    #[test]
    fn rejects_invalid_characters() {
        assert_eq!(decode("AB!CD"), Err(Error::TokenAlphabet));
        assert_eq!(decode("AB CD"), Err(Error::TokenAlphabet));
    }
}
