//! Image handling that is the same on every platform.
//!
//! Two reasons this is its own module rather than sitting inside each backend.
//!
//! The first is the cap. A clipboard image is not a few kilobytes: a screenshot of a large display
//! is routinely tens of megabytes, and the failure mode when nobody bounds it is spectacular.
//! `ClipCascade` issue 165 is 54 GB of resident memory after one large copy, and Barrier freezes
//! all input until it is killed when an 85 MB image arrives. So the cap is checked before the
//! bytes are read, not after, and every backend uses the same one.
//!
//! The second is that PNG is the only image format on the wire. Deskflow carries BMP and that is
//! precisely why images pasted from macOS arrive corrupted on Windows: two platforms disagreeing
//! about a bitmap layout with no canonical form in between. One format, converted at exactly one
//! boundary, removes the entire class of bug. The conversion helpers live here so they can be
//! tested on any machine, rather than only on the platform that needs them.

use crate::error::{Error, Result};

/// Largest image we will accept from the clipboard, before reading it.
///
/// Sized to hold a full screenshot of a large display while still refusing anything that looks
/// like a mistake. The relay caps content far lower than this, so a big image is skipped with a
/// reason rather than silently failing later.
pub const MAX_IMAGE_BYTES: usize = 16 * 1024 * 1024;

/// The eight byte PNG signature, from the PNG specification.
pub const PNG_MAGIC: [u8; 8] = [0x89, b'P', b'N', b'G', 0x0d, 0x0a, 0x1a, 0x0a];

/// Whether a buffer really is a PNG.
///
/// Clipboard sources are not always honest about what they offer. Checking the signature costs
/// eight bytes of comparison and stops a mislabelled blob from travelling to another machine
/// under a type that will not open there.
#[must_use]
pub fn is_png(bytes: &[u8]) -> bool {
    bytes.len() > PNG_MAGIC.len() && bytes[..PNG_MAGIC.len()] == PNG_MAGIC
}

/// Checks a length against the cap before anything is allocated for it.
///
/// # Errors
///
/// Returns [`Error::Read`] naming both sizes, because a user whose copy vanished deserves to be
/// told why rather than left guessing.
pub fn check_size(len: usize) -> Result<()> {
    if len > MAX_IMAGE_BYTES {
        return Err(Error::Read(format!(
            "image is {len} bytes, over the {MAX_IMAGE_BYTES} byte limit, so it was skipped"
        )));
    }
    Ok(())
}

/// Validates a buffer that a source handed us as PNG.
///
/// # Errors
///
/// Returns [`Error::Read`] if it is over the cap or is not actually a PNG.
pub fn validate_png(bytes: &[u8]) -> Result<()> {
    check_size(bytes.len())?;
    if !is_png(bytes) {
        return Err(Error::Read(
            "the source offered image/png but the bytes are not a PNG".to_owned(),
        ));
    }
    Ok(())
}

/// Size of the BMP file header that a DIB lacks.
const BMP_FILE_HEADER_LEN: u32 = 14;

/// Builds the file header that turns a bare DIB into a parsable BMP.
///
/// Windows puts a device independent bitmap on the clipboard without the 14 byte file header that
/// starts a `.bmp` file, because in a clipboard there is no file. Every decoder expects that
/// header, so it has to be reconstructed before the bytes can be re-encoded as PNG.
///
/// The pixel offset is the header plus the info header plus the colour table, and the colour table
/// size is the part that is easy to get wrong: it depends on the bit depth and on whether the info
/// header declares a palette explicitly.
///
/// This is pure byte arithmetic, which is why it lives here and is tested on every platform rather
/// than only on the one that calls it.
///
/// # Errors
///
/// Returns [`Error::Read`] if the buffer is too short to contain an info header, or declares one
/// whose size makes no sense.
pub fn bmp_file_header_for_dib(dib: &[u8]) -> Result<[u8; 14]> {
    // BITMAPINFOHEADER is 40 bytes, and its first field is its own size. Anything shorter than
    // that cannot be a DIB at all.
    if dib.len() < 40 {
        return Err(Error::Read(format!(
            "a device independent bitmap needs at least 40 header bytes, got {}",
            dib.len()
        )));
    }

    let header_size = u32::from_le_bytes([dib[0], dib[1], dib[2], dib[3]]);
    if header_size < 12 || header_size as usize > dib.len() {
        return Err(Error::Read(format!(
            "the bitmap declares a {header_size} byte header, which does not fit its {} bytes",
            dib.len()
        )));
    }

    let bit_count = u16::from_le_bytes([dib[14], dib[15]]);
    let declared_colours = u32::from_le_bytes([dib[32], dib[33], dib[34], dib[35]]);

    // A palette exists only at 8 bits per pixel and below. Above that the pixels are direct
    // colour, and a non zero count there is an optimisation hint, not a table.
    let palette_entries = if bit_count <= 8 {
        if declared_colours == 0 {
            1u32 << bit_count
        } else {
            declared_colours
        }
    } else {
        0
    };

    let palette_bytes = palette_entries.saturating_mul(4);
    let pixel_offset = BMP_FILE_HEADER_LEN
        .saturating_add(header_size)
        .saturating_add(palette_bytes);
    let file_size = BMP_FILE_HEADER_LEN.saturating_add(
        u32::try_from(dib.len())
            .map_err(|_| Error::Read("bitmap is implausibly large".to_owned()))?,
    );

    let mut header = [0u8; 14];
    header[0] = b'B';
    header[1] = b'M';
    header[2..6].copy_from_slice(&file_size.to_le_bytes());
    // Bytes 6 to 10 are two reserved 16 bit fields, both zero.
    header[10..14].copy_from_slice(&pixel_offset.to_le_bytes());
    Ok(header)
}

/// A serialized `DWORD` of zero, the payload Windows reads as "no" for the two history and cloud
/// clipboard formats.
///
/// Defined here rather than in the Windows backend so the byte layout is exercised by tests that
/// run on every platform, instead of only compiling on one.
pub const DWORD_ZERO: [u8; 4] = [0, 0, 0, 0];

/// Whether a write carrying these options needs the platform concealment markers.
///
/// Trivial today, but it is the single place that decides, so a backend cannot drift into writing
/// an unmarked secret by reading the flag slightly differently.
#[must_use]
pub const fn needs_concealment(concealed: bool) -> bool {
    concealed
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The smallest thing that passes the signature check, for tests that do not care about
    /// pixels.
    fn png_like() -> Vec<u8> {
        let mut bytes = PNG_MAGIC.to_vec();
        bytes.extend_from_slice(b"IHDR and whatever follows");
        bytes
    }

    #[test]
    fn a_real_signature_is_recognised() {
        assert!(is_png(&png_like()));
    }

    #[test]
    fn other_formats_are_rejected() {
        assert!(!is_png(b"BM this is a bitmap"));
        assert!(!is_png(b"GIF89a"));
        assert!(!is_png(b"\xff\xd8\xff jpeg"));
        assert!(!is_png(b""));
    }

    #[test]
    fn the_signature_alone_is_not_enough() {
        // Exactly the magic and nothing else is not a usable image, and treating it as one would
        // send an empty file to another machine.
        assert!(!is_png(&PNG_MAGIC));
    }

    #[test]
    fn the_cap_is_checked_before_anything_is_allocated() {
        assert!(check_size(0).is_ok());
        assert!(check_size(MAX_IMAGE_BYTES).is_ok());
        let err = check_size(MAX_IMAGE_BYTES + 1).expect_err("over the cap");
        // The message must name the sizes: a silently dropped copy is the complaint every
        // competitor in this space collects.
        let text = err.to_string();
        assert!(text.contains(&(MAX_IMAGE_BYTES + 1).to_string()));
        assert!(text.contains(&MAX_IMAGE_BYTES.to_string()));
    }

    #[test]
    fn validation_covers_both_the_cap_and_the_format() {
        assert!(validate_png(&png_like()).is_ok());
        assert!(validate_png(b"not a png at all").is_err());
        assert!(validate_png(&vec![0u8; MAX_IMAGE_BYTES + 1]).is_err());
    }

    /// A 40 byte `BITMAPINFOHEADER` with the given bit depth and declared palette size.
    fn info_header(bit_count: u16, declared_colours: u32) -> Vec<u8> {
        let mut dib = vec![0u8; 40];
        dib[0..4].copy_from_slice(&40u32.to_le_bytes());
        dib[14..16].copy_from_slice(&bit_count.to_le_bytes());
        dib[32..36].copy_from_slice(&declared_colours.to_le_bytes());
        dib
    }

    #[test]
    fn a_direct_colour_bitmap_has_no_palette() {
        let dib = info_header(32, 0);
        let header = bmp_file_header_for_dib(&dib).expect("valid");
        assert_eq!(&header[0..2], b"BM");
        // 14 byte file header plus the 40 byte info header, and nothing else.
        assert_eq!(
            u32::from_le_bytes([header[10], header[11], header[12], header[13]]),
            54
        );
    }

    #[test]
    fn an_eight_bit_bitmap_gets_a_full_palette_when_none_is_declared() {
        let dib = info_header(8, 0);
        let header = bmp_file_header_for_dib(&dib).expect("valid");
        // 14 + 40 + 256 entries of 4 bytes.
        assert_eq!(
            u32::from_le_bytes([header[10], header[11], header[12], header[13]]),
            14 + 40 + 256 * 4
        );
    }

    #[test]
    fn a_declared_palette_size_wins_over_the_bit_depth_default() {
        let dib = info_header(8, 16);
        let header = bmp_file_header_for_dib(&dib).expect("valid");
        assert_eq!(
            u32::from_le_bytes([header[10], header[11], header[12], header[13]]),
            14 + 40 + 16 * 4
        );
    }

    #[test]
    fn a_colour_count_above_eight_bits_is_a_hint_not_a_table() {
        // 24 and 32 bit bitmaps sometimes declare a count. Treating it as a palette would offset
        // the pixel data and produce a picture of noise.
        let dib = info_header(24, 256);
        let header = bmp_file_header_for_dib(&dib).expect("valid");
        assert_eq!(
            u32::from_le_bytes([header[10], header[11], header[12], header[13]]),
            54
        );
    }

    #[test]
    fn the_file_size_counts_the_header_we_are_adding() {
        let dib = info_header(32, 0);
        let header = bmp_file_header_for_dib(&dib).expect("valid");
        assert_eq!(
            u32::from_le_bytes([header[2], header[3], header[4], header[5]]),
            14 + 40
        );
    }

    #[test]
    fn nonsense_input_is_refused_rather_than_guessed_at() {
        assert!(bmp_file_header_for_dib(&[]).is_err());
        assert!(bmp_file_header_for_dib(&[0u8; 39]).is_err());

        // A header claiming to be bigger than the buffer it lives in.
        let mut dib = info_header(32, 0);
        dib[0..4].copy_from_slice(&9999u32.to_le_bytes());
        assert!(bmp_file_header_for_dib(&dib).is_err());
    }

    #[test]
    fn a_dword_of_zero_is_four_zero_bytes() {
        // Windows reads this payload as "do not include" for CanIncludeInClipboardHistory and
        // CanUploadToCloudClipboard. Any other length or value means something else entirely.
        assert_eq!(DWORD_ZERO.len(), 4);
        assert_eq!(u32::from_le_bytes(DWORD_ZERO), 0);
        assert_eq!(
            u32::from_be_bytes(DWORD_ZERO),
            0,
            "zero reads the same either way"
        );
    }

    #[test]
    fn concealment_is_decided_in_one_place() {
        assert!(needs_concealment(true));
        assert!(!needs_concealment(false));
    }
}
