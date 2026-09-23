//! Configuration and persisted state.
//!
//! Two files, deliberately separated by how often they change. `config.json` is settings a person
//! edits and the app rarely touches. `state.json` holds the per device sequence counter, which
//! changes on every copy.
//!
//! The sequence counter has to survive restarts. Peers reject any clip whose sequence is at or
//! below the highest they have already seen from this device, because that is what catches a relay
//! replaying an old message. So a counter that resets to zero on restart would make every clip
//! from this device look like a rollback attempt, and sync would appear to work until it silently
//! stopped.

use std::fs;
use std::io::Write as _;
use std::path::{Path, PathBuf};

use directories::ProjectDirs;
use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

/// The public relay the app ships pointed at.
pub const DEFAULT_RELAY_URL: &str = "wss://asli.vnat.dev/v1";

/// Largest clipboard payload this device will send, in bytes.
///
/// The relay announces its own limit during the handshake and that one wins when it is smaller.
/// This local cap exists so an enormous copy is skipped with an explanation before it is
/// encrypted, rather than after.
pub const DEFAULT_MAX_CONTENT_BYTES: usize = 700 * 1024;

/// Settings, as stored in `config.json`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// Relay to connect to. Self-hosters change this.
    pub relay_url: String,
    /// Largest payload to send, in bytes.
    pub max_content_bytes: usize,
    /// Whether to show a notification when a clip arrives.
    pub notifications: bool,
    /// Whether to start at login. Not yet implemented, stored so the setting survives.
    pub autostart: bool,
    /// This device's id, as 32 lowercase hex characters.
    ///
    /// Stable for the life of the install. It identifies the device to the other devices in the
    /// room, inside the ciphertext, and never to the relay.
    pub device_id: String,
    /// Whether to keep a local history of what was copied.
    ///
    /// Defaulted rather than required, because this field arrived after the first release and a
    /// configuration written before it must still load. The same applies to the field below.
    #[serde(default = "default_keep_history")]
    pub keep_history: bool,
    /// How many history entries to keep, oldest dropped first.
    #[serde(default = "default_history_entries")]
    pub history_entries: usize,
    /// What this device calls itself to the others on the account. Empty means the computer's
    /// own name.
    #[serde(default)]
    pub device_name: String,
}

/// History is on by default, which is what every comparable tool does and what makes the feature
/// discoverable. It records nothing a password manager marked as concealed.
fn default_keep_history() -> bool {
    true
}

/// A hundred entries: enough to find yesterday's copy, small enough to stay cheap.
fn default_history_entries() -> usize {
    100
}

impl Config {
    /// Builds a configuration with a fresh random device id.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Crypto`] if the operating system random number generator fails.
    pub fn new_with_random_device_id() -> Result<Self> {
        let device_id: [u8; 16] = asli_crypto::random::bytes()?;
        Ok(Self {
            relay_url: DEFAULT_RELAY_URL.to_owned(),
            max_content_bytes: DEFAULT_MAX_CONTENT_BYTES,
            notifications: false,
            autostart: true,
            device_id: hex(&device_id),
            keep_history: default_keep_history(),
            history_entries: default_history_entries(),
            device_name: String::new(),
        })
    }

    /// The device id as bytes.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Parse`] if the stored value is not 32 hex characters.
    pub fn device_id_bytes(&self) -> Result<[u8; 16]> {
        unhex(&self.device_id)
            .ok_or_else(|| Error::Parse("device_id is not 32 hexadecimal characters".to_owned()))
    }
}

/// The per device counter, as stored in `state.json`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct State {
    /// Highest sequence number this device has used.
    pub seq: u64,
}

/// Where everything for this install lives.
#[derive(Debug, Clone)]
pub struct Paths {
    /// Directory holding the configuration, state and the fallback key file.
    pub dir: PathBuf,
}

impl Paths {
    /// Resolves the per user configuration directory, creating it if needed.
    ///
    /// # Errors
    ///
    /// Returns [`Error::ConfigDir`] if the platform has no such directory or it cannot be created.
    pub fn resolve() -> Result<Self> {
        // An override exists so the tests never touch a developer's real configuration.
        let dir = if let Some(dir) = std::env::var_os("ASLI_CONFIG_DIR") {
            PathBuf::from(dir)
        } else {
            ProjectDirs::from("dev", "vnat", "asli")
                .ok_or_else(|| {
                    Error::ConfigDir("no home directory for this user was found".to_owned())
                })?
                .config_dir()
                .to_path_buf()
        };

        fs::create_dir_all(&dir)
            .map_err(|e| Error::ConfigDir(format!("{}: {e}", dir.display())))?;
        // The directory too, not only the files in it. On a distribution whose home directories
        // are world readable, the default here would list every file this application keeps.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let _ = fs::set_permissions(&dir, fs::Permissions::from_mode(0o700));
        }
        Ok(Self { dir })
    }

    /// Path of the settings file.
    #[must_use]
    pub fn config_file(&self) -> PathBuf {
        self.dir.join("config.json")
    }

    /// Path of the state file.
    #[must_use]
    pub fn state_file(&self) -> PathBuf {
        self.dir.join("state.json")
    }

    /// Directory for disposable files, such as the rendered join page.
    ///
    /// Deliberately not the configuration directory. A page showing the account key is throwaway
    /// and is deleted shortly after it is opened, so it has no business sitting beside settings
    /// that are meant to persist.
    ///
    /// The `ASLI_CONFIG_DIR` override is honoured here too, so a test that redirects the
    /// configuration never writes into a real cache directory either.
    #[must_use]
    pub fn cache_dir(&self) -> PathBuf {
        if std::env::var_os("ASLI_CONFIG_DIR").is_some() {
            return self.dir.join("cache");
        }
        ProjectDirs::from("dev", "vnat", "asli").map_or_else(
            || self.dir.join("cache"),
            |dirs| dirs.cache_dir().to_path_buf(),
        )
    }

    /// Path of the fallback key file, used only when no keychain is available.
    #[must_use]
    pub fn secret_file(&self) -> PathBuf {
        self.dir.join("secret.key")
    }

    /// Loads the settings, creating them with defaults on first run.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Io`] or [`Error::Parse`] if the file exists but cannot be used.
    pub fn load_config(&self) -> Result<Config> {
        let path = self.config_file();
        if !path.exists() {
            let config = Config::new_with_random_device_id()?;
            self.save_config(&config)?;
            return Ok(config);
        }
        let raw = fs::read_to_string(&path)?;
        serde_json::from_str(&raw).map_err(|e| Error::Parse(format!("{}: {e}", path.display())))
    }

    /// Writes the settings.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Io`] if the file cannot be written.
    pub fn save_config(&self, config: &Config) -> Result<()> {
        let json = serde_json::to_string_pretty(config)
            .map_err(|e| Error::Parse(format!("could not serialize the configuration: {e}")))?;
        write_atomically(&self.config_file(), json.as_bytes(), 0o600)
    }

    /// Loads the persisted sequence counter, defaulting to zero.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Parse`] if the file exists but is not valid.
    pub fn load_state(&self) -> Result<State> {
        let path = self.state_file();
        if !path.exists() {
            return Ok(State::default());
        }
        let raw = fs::read_to_string(&path)?;
        serde_json::from_str(&raw).map_err(|e| Error::Parse(format!("{}: {e}", path.display())))
    }

    /// Writes the sequence counter.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Io`] if the file cannot be written.
    pub fn save_state(&self, state: State) -> Result<()> {
        let json = serde_json::to_string(&state)
            .map_err(|e| Error::Parse(format!("could not serialize the state: {e}")))?;
        write_atomically(&self.state_file(), json.as_bytes(), 0o600)
    }
}

/// Writes a file through a temporary file and a rename, so a crash cannot leave a half written
/// config behind.
pub(crate) fn write_atomically(path: &Path, bytes: &[u8], mode: u32) -> Result<()> {
    // One writer at a time. Two threads write the same file, the sequence reservation from both
    // the clipboard bridge and the connection loop, and with one shared temporary name they could
    // interleave into an empty file, which then stops the daemon starting.
    static WRITING: std::sync::Mutex<()> = std::sync::Mutex::new(());
    let _one_at_a_time = WRITING
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);

    let tmp = path.with_extension("tmp");
    {
        // Created with the mode already on it. Writing first and restricting afterwards left the
        // finished, fsynced contents readable by every other user on the machine for a moment,
        // and this runs on every copy, so a moment repeated hundreds of times a day is a window.
        let mut file = create_private(&tmp, mode)?;
        file.write_all(bytes)?;
        file.sync_all()?;
    }
    set_owner_only(&tmp, mode)?;
    fs::rename(&tmp, path)?;
    Ok(())
}

/// Creates a file that is owner only from the moment it exists.
///
/// The mode is passed to `open`, so there is no instant at which the file is both present and
/// readable by anyone else. Truncates, because every caller rewrites the whole file.
#[cfg(unix)]
fn create_private(path: &Path, mode: u32) -> Result<fs::File> {
    use std::os::unix::fs::OpenOptionsExt as _;
    Ok(fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(mode)
        .open(path)?)
}

#[cfg(not(unix))]
fn create_private(path: &Path, _mode: u32) -> Result<fs::File> {
    // Windows and macOS inherit the user profile's access control, which is owner only by default.
    Ok(fs::File::create(path)?)
}

/// Restricts a file to its owner. Everything this application writes is either a secret or a hint
/// about one.
#[cfg(unix)]
fn set_owner_only(path: &Path, mode: u32) -> Result<()> {
    use std::os::unix::fs::PermissionsExt as _;
    fs::set_permissions(path, fs::Permissions::from_mode(mode))?;
    Ok(())
}

#[cfg(not(unix))]
#[allow(clippy::unnecessary_wraps)] // Same signature as the Unix version, which can fail.
fn set_owner_only(_path: &Path, _mode: u32) -> Result<()> {
    // Windows and macOS inherit the user profile's access control, which is owner only by default.
    Ok(())
}

/// Lowercase hexadecimal, for the device id.
#[must_use]
pub fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes
        .iter()
        .fold(String::with_capacity(bytes.len() * 2), |mut acc, byte| {
            let _ = write!(acc, "{byte:02x}");
            acc
        })
}

/// Parses exactly 16 bytes of lowercase or uppercase hexadecimal.
#[must_use]
pub fn unhex(text: &str) -> Option<[u8; 16]> {
    if text.len() != 32 {
        return None;
    }
    let mut out = [0u8; 16];
    for (i, slot) in out.iter_mut().enumerate() {
        *slot = u8::from_str_radix(text.get(i * 2..i * 2 + 2)?, 16).ok()?;
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_paths() -> (Paths, tempdir::TempDir) {
        let dir = tempdir::TempDir::new();
        (
            Paths {
                dir: dir.path().to_path_buf(),
            },
            dir,
        )
    }

    /// A minimal temporary directory, so the crate needs no extra dependency for two tests.
    mod tempdir {
        use std::path::{Path, PathBuf};

        pub struct TempDir(PathBuf);

        impl TempDir {
            pub fn new() -> Self {
                let nanos = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map_or(0, |d| d.as_nanos());
                let path = std::env::temp_dir().join(format!(
                    "asli-test-{nanos}-{:?}",
                    std::thread::current().id()
                ));
                std::fs::create_dir_all(&path).expect("temp dir");
                Self(path)
            }

            pub fn path(&self) -> &Path {
                &self.0
            }
        }

        impl Drop for TempDir {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.0);
            }
        }
    }

    #[test]
    fn config_round_trips() {
        let (paths, _guard) = temp_paths();
        let config = Config::new_with_random_device_id().expect("rng");
        paths.save_config(&config).expect("saves");
        let loaded = paths.load_config().expect("loads");
        assert_eq!(config, loaded);
    }

    #[test]
    fn first_run_creates_a_config_with_a_device_id() {
        let (paths, _guard) = temp_paths();
        let config = paths.load_config().expect("creates");
        assert_eq!(config.relay_url, DEFAULT_RELAY_URL);
        assert_eq!(config.device_id.len(), 32);
        assert!(config.device_id_bytes().is_ok());
        assert!(paths.config_file().exists());
    }

    #[test]
    fn two_devices_get_different_ids() {
        let a = Config::new_with_random_device_id().expect("rng");
        let b = Config::new_with_random_device_id().expect("rng");
        assert_ne!(a.device_id, b.device_id);
    }

    #[test]
    fn state_round_trips_and_defaults_to_zero() {
        let (paths, _guard) = temp_paths();
        assert_eq!(paths.load_state().expect("default"), State { seq: 0 });
        paths.save_state(State { seq: 41 }).expect("saves");
        assert_eq!(paths.load_state().expect("loads"), State { seq: 41 });
    }

    #[test]
    fn rejects_an_unknown_config_field() {
        let (paths, _guard) = temp_paths();
        std::fs::write(paths.config_file(), r#"{"relay_url":"x","surprise":1}"#).expect("write");
        assert!(matches!(paths.load_config(), Err(Error::Parse(_))));
    }

    #[test]
    fn hex_round_trips() {
        let bytes = [
            0u8, 1, 2, 250, 255, 16, 32, 64, 128, 7, 9, 11, 13, 15, 17, 19,
        ];
        assert_eq!(unhex(&hex(&bytes)), Some(bytes));
        assert_eq!(unhex("short"), None);
        assert_eq!(unhex(&"z".repeat(32)), None);
    }

    #[cfg(unix)]
    #[test]
    fn written_files_are_owner_only() {
        use std::os::unix::fs::PermissionsExt as _;
        let (paths, _guard) = temp_paths();
        paths.save_state(State { seq: 1 }).expect("saves");
        let mode = std::fs::metadata(paths.state_file())
            .expect("stat")
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600, "state file must not be world readable");
    }
}
