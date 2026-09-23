//! Where the account key lives.
//!
//! The key belongs in the operating system keychain. On Linux that is the Secret Service, and the
//! honest problem is that a bare Hyprland or Sway session frequently has no Secret Service
//! provider running at all. That is not an exotic edge case, it is a normal tiling setup, so a
//! missing keychain must not be a crash and must not be silent either.
//!
//! So: try the keychain, and if it is unavailable fall back to a file that only the owner can
//! read, then say so plainly in `asli status`. The fallback protects against another user on the
//! same machine and against casual inspection. It does not protect against someone imaging the
//! disk, and the status output says exactly that rather than implying otherwise.

use std::fs;
use std::io::Write as _;
use std::path::Path;

use zeroize::Zeroizing;

use crate::config::Paths;
use crate::error::{Error, Result};

/// Keychain service name.
const SERVICE: &str = "asli";

/// The keychain service name, optionally suffixed.
///
/// `ASLI_CONFIG_DIR` isolates the configuration but not the account, because the keychain is
/// global to the user. Without a matching override, two instances on one machine fight over the
/// same entry, which blocks the multi instance testing that finds loop bugs and blocks anyone who
/// wants a second account. The default is unchanged, so existing installs keep their key.
fn service_name() -> String {
    match std::env::var("ASLI_KEYRING_SUFFIX") {
        Ok(suffix) if !suffix.is_empty() => format!("{SERVICE}-{suffix}"),
        _ => SERVICE.to_owned(),
    }
}
/// Keychain entry name within the service.
const ACCOUNT: &str = "account";

/// Where the key for this install actually ended up.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Store {
    /// The operating system keychain.
    Keychain,
    /// A file in the configuration directory, readable only by this user.
    ///
    /// Used when no keychain is available, which on Linux means no Secret Service provider is
    /// running in this session.
    File,
}

impl Store {
    /// A short description for the status output. Honest about the tradeoff.
    #[must_use]
    pub const fn describe(self) -> &'static str {
        match self {
            Self::Keychain => "OS keychain",
            Self::File => {
                "file in the config directory, owner only (no keychain in this session, so this is \
                 less secure: it protects against other users, not against disk imaging)"
            }
        }
    }
}

/// Stores the account key, preferring the keychain.
///
/// The key is written as Crockford base32 rather than raw bytes, because the string API is the
/// one every keychain backend supports identically.
///
/// # Errors
///
/// Returns [`Error::SecretStore`] only if both the keychain and the file fallback fail.
pub fn store(paths: &Paths, secret: &[u8; 32]) -> Result<Store> {
    let encoded = Zeroizing::new(asli_crypto::base32::encode(secret));

    if let Ok(entry) = keyring::Entry::new(&service_name(), ACCOUNT) {
        match entry.set_password(&encoded) {
            Ok(()) => {
                // A previous run may have left a file fallback behind. Two copies of the key is
                // one copy too many, and the one being dropped is overwritten, not just unlinked.
                let _ = shred_secret_file(&paths.secret_file());
                return Ok(Store::Keychain);
            }
            // A keychain that is there but locked must not be bypassed. The key would go to the
            // file, the keychain would keep the old one, and since the keychain is read first,
            // the next start would silently use the old account.
            Err(keyring::Error::NoStorageAccess(err)) => {
                return Err(Error::KeychainLocked(err.to_string()));
            }
            Err(_) => {}
        }
    }

    write_secret_file(paths, &encoded)?;
    Ok(Store::File)
}

/// Loads the account key, if this device has one.
///
/// # Errors
///
/// Returns [`Error::Parse`] if a stored value exists but is not a valid key.
pub fn load(paths: &Paths) -> Result<Option<(Zeroizing<[u8; 32]>, Store)>> {
    let mut locked = None;
    if let Ok(entry) = keyring::Entry::new(&service_name(), ACCOUNT) {
        match entry.get_password() {
            Ok(encoded) => {
                let secret = decode(&encoded)?;
                return Ok(Some((secret, Store::Keychain)));
            }
            // Locked, or a prompt dismissed or denied. There may be a key in there.
            Err(keyring::Error::NoStorageAccess(err)) => locked = Some(err.to_string()),
            // No entry, or no keychain service at all: both mean nothing is stored there.
            Err(_) => {}
        }
    }

    let path = paths.secret_file();
    if path.exists() {
        let encoded = Zeroizing::new(fs::read_to_string(&path)?);
        let secret = decode(encoded.trim())?;
        return Ok(Some((secret, Store::File)));
    }

    match locked {
        Some(detail) => Err(Error::KeychainLocked(detail)),
        None => Ok(None),
    }
}

/// Removes the account key from wherever it is.
///
/// This is v1's device revocation: there is no way to revoke one device, so the answer to a
/// leaked key is a new account and re-onboarding the devices you still trust.
///
/// # Errors
///
/// Returns [`Error::Io`] if the fallback file exists and cannot be removed.
pub fn wipe(paths: &Paths) -> Result<()> {
    if let Ok(entry) = keyring::Entry::new(&service_name(), ACCOUNT) {
        // Nothing there, or no keychain at all, is success. A locked keychain is not: reporting
        // the account forgotten while the key is still stored would defeat the one way v1 has of
        // revoking a leaked key.
        if let Err(keyring::Error::NoStorageAccess(err)) = entry.delete_credential() {
            return Err(Error::KeychainLocked(err.to_string()));
        }
    }
    shred_secret_file(&paths.secret_file())?;
    Ok(())
}

/// Removes the key file, overwriting its bytes first.
///
/// `remove_file` unlinks and no more: on ext4 and APFS the blocks holding the base32 encoded
/// account key stay intact until something else claims them, so a sold laptop or an old backup
/// still yields the key to anyone who carves free space. The history store already shreds for
/// exactly this reason, and the key is worth more than the history it protects.
fn shred_secret_file(path: &Path) -> Result<()> {
    let Ok(metadata) = fs::metadata(path) else {
        return Ok(()); // Nothing there, which is the desired end state.
    };

    if let Ok(mut file) = fs::OpenOptions::new().write(true).open(path) {
        let len = usize::try_from(metadata.len()).unwrap_or(0);
        let _ = file.write_all(&vec![0u8; len]);
        let _ = file.sync_all();
    }
    fs::remove_file(path)?;
    Ok(())
}

/// Reports which store an account would be written to, without creating one.
///
/// A keychain that answers "no such entry" has still answered, which is what we are asking.
#[must_use]
pub fn available_store() -> Store {
    let keychain_answers = keyring::Entry::new(&service_name(), ACCOUNT)
        .is_ok_and(|entry| matches!(entry.get_password(), Ok(_) | Err(keyring::Error::NoEntry)));

    if keychain_answers {
        Store::Keychain
    } else {
        Store::File
    }
}

fn decode(encoded: &str) -> Result<Zeroizing<[u8; 32]>> {
    let bytes = Zeroizing::new(
        asli_crypto::base32::decode(encoded)
            .map_err(|_| Error::Parse("the stored account key is not valid".to_owned()))?,
    );
    let array: [u8; 32] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| Error::Parse("the stored account key is the wrong length".to_owned()))?;
    Ok(Zeroizing::new(array))
}

fn write_secret_file(paths: &Paths, encoded: &str) -> Result<()> {
    use std::io::Write as _;

    let path = paths.secret_file();
    let failed = |e: std::io::Error| {
        Error::SecretStore(format!(
            "no keychain was available and {} could not be written: {e}",
            path.display()
        ))
    };

    // Written to a temporary file and renamed over the target, so the key file is either the old
    // contents or the new ones. Truncating in place and then writing left a window in which a
    // crash, an OOM kill or a power cut yielded an empty key file, and there is no second copy:
    // that window loses the account outright.
    let tmp = path.with_extension("tmp");
    // Created owner only from the first byte. Writing first and restricting afterwards left a
    // moment where the file was readable by other users, and a handle opened then stays open.
    let mut options = fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    let mut file = options.open(&tmp).map_err(failed)?;
    file.write_all(encoded.as_bytes()).map_err(failed)?;
    file.sync_all().map_err(failed)?;
    drop(file);
    owner_only(&tmp)?;
    fs::rename(&tmp, &path).map_err(failed)?;
    // Still applied, for a file that already existed with wider permissions.
    owner_only(&path)?;
    Ok(())
}

#[cfg(unix)]
fn owner_only(path: &std::path::Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt as _;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    Ok(())
}

#[cfg(not(unix))]
#[allow(clippy::unnecessary_wraps)] // Same signature as the Unix version, which can fail.
fn owner_only(_path: &std::path::Path) -> Result<()> {
    // The file sits in the user profile, whose access control is owner only by default.
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn paths_in(dir: &std::path::Path) -> Paths {
        Paths {
            dir: dir.to_path_buf(),
        }
    }

    fn scratch() -> std::path::PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos());
        let path = std::env::temp_dir().join(format!("asli-secret-test-{nanos}"));
        fs::create_dir_all(&path).expect("temp dir");
        path
    }

    #[test]
    fn the_file_fallback_round_trips() {
        let dir = scratch();
        let paths = paths_in(&dir);
        let secret = [7u8; 32];

        write_secret_file(&paths, &asli_crypto::base32::encode(&secret)).expect("writes");
        let file = fs::read_to_string(paths.secret_file()).expect("reads");
        let decoded = decode(file.trim()).expect("decodes");
        assert_eq!(*decoded, secret);

        let _ = fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn the_fallback_file_is_owner_only() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = scratch();
        let paths = paths_in(&dir);
        write_secret_file(&paths, &asli_crypto::base32::encode(&[1u8; 32])).expect("writes");
        let mode = fs::metadata(paths.secret_file())
            .expect("stat")
            .permissions()
            .mode();
        assert_eq!(
            mode & 0o777,
            0o600,
            "the key file must not be readable by others"
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_corrupt_stored_key_is_an_error_not_a_panic() {
        assert!(decode("not a key").is_err());
        assert!(decode("").is_err());
        // Right alphabet, wrong length.
        assert!(decode(&asli_crypto::base32::encode(&[0u8; 8])).is_err());
    }

    #[test]
    fn the_store_description_admits_the_fallback_is_weaker() {
        assert!(Store::File.describe().contains("less secure"));
        assert_eq!(Store::Keychain.describe(), "OS keychain");
    }
}
