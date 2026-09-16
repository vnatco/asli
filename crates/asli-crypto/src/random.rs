//! Randomness.
//!
//! Every random byte in Asli comes from the operating system CSPRNG. There is no fallback: if the
//! OS generator fails we return [`Error::Rng`] and the caller aborts the operation. Falling back
//! to a user space PRNG, a counter or a timestamp would be worse than failing, because a repeated
//! nonce breaks the AEAD.

use crate::error::{Error, Result};

/// Fills `buf` with bytes from the operating system CSPRNG.
///
/// # Errors
///
/// Returns [`Error::Rng`] if the operating system generator is unavailable. Treat this as fatal.
pub fn fill(buf: &mut [u8]) -> Result<()> {
    getrandom::getrandom(buf).map_err(|_| Error::Rng)
}

/// Returns `N` fresh bytes from the operating system CSPRNG.
///
/// # Errors
///
/// Returns [`Error::Rng`] if the operating system generator is unavailable.
pub fn bytes<const N: usize>() -> Result<[u8; N]> {
    let mut out = [0u8; N];
    fill(&mut out)?;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn produces_different_values() {
        let a: [u8; 32] = bytes().expect("rng works");
        let b: [u8; 32] = bytes().expect("rng works");
        assert_ne!(a, b, "two draws must not collide");
        assert_ne!(a, [0u8; 32], "output must not be all zeros");
    }
}
