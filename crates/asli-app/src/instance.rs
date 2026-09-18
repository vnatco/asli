//! One daemon per configuration directory.
//!
//! Two copies of the daemon on one machine each open their own relay connection, watch the
//! clipboard independently and keep their own echo guard, so every copy is announced twice and the
//! room reports a device that does not exist. Launching twice is still a normal thing for a person
//! to do, so a second copy must exit quietly rather than fail.
//!
//! The guard is an operating system file lock on `asli.lock` in the configuration directory. The
//! lock is released by the kernel when the process ends, however it ends, so there is no stale pid
//! to detect and no race between checking and claiming. Keying it to the configuration directory
//! keeps isolated test instances, each with its own `ASLI_CONFIG_DIR`, independent of each other
//! and of the real one.

use std::fs::{File, OpenOptions, TryLockError};
use std::io::Write as _;
use std::time::{Duration, Instant};

use crate::config::Paths;
use crate::error::{Error, Result};

/// Set by a process that replaces itself, so the new process waits for the old one to let go.
///
/// On Unix the replacement is an `exec` and the lock is released before the new image runs. On
/// Windows it is a new process started while the old one is still exiting, so without a wait the
/// replacement would find the lock held and exit, and nothing would be running at all.
pub const RESTART_ENV: &str = "ASLI_RESTARTED";

/// How long a replacement process waits for its predecessor to exit.
const RESTART_WAIT: Duration = Duration::from_secs(10);

/// Holds the lock for as long as it lives. Keep it alive for the life of the daemon.
#[derive(Debug)]
pub struct Guard {
    _file: File,
}

/// What happened when this process tried to become the running instance.
#[derive(Debug)]
pub enum Claim {
    /// This process is now the only daemon for this configuration directory.
    Acquired(Guard),
    /// Another daemon already holds the directory.
    AlreadyRunning,
}

/// Tries to become the one running daemon for these paths.
///
/// # Errors
///
/// Returns [`Error::Io`] if the lock file cannot be opened, or if locking fails for a reason other
/// than another process holding it.
pub fn claim(paths: &Paths) -> Result<Claim> {
    let path = paths.dir.join("asli.lock");
    let mut file = OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(&path)
        .map_err(|e| Error::ConfigDir(format!("{}: {e}", path.display())))?;

    let deadline = std::env::var_os(RESTART_ENV).map(|_| Instant::now() + RESTART_WAIT);

    loop {
        match file.try_lock() {
            Ok(()) => break,
            Err(TryLockError::WouldBlock) => match deadline {
                Some(deadline) if Instant::now() < deadline => {
                    std::thread::sleep(Duration::from_millis(100));
                }
                _ => return Ok(Claim::AlreadyRunning),
            },
            Err(TryLockError::Error(err)) => return Err(Error::Io(err)),
        }
    }

    // The pid is informational, for a person looking at the directory. The lock is the truth.
    // Written through the locked handle, because on Windows a second handle may not write to a
    // range locked by the first.
    let _ = file.set_len(0);
    let _ = writeln!(file, "{}", std::process::id());

    Ok(Claim::Acquired(Guard { _file: file }))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_paths(name: &str) -> Paths {
        let dir = std::env::temp_dir().join(format!("asli-instance-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("creates the directory");
        Paths { dir }
    }

    #[test]
    fn a_second_claim_is_refused_while_the_first_is_held() {
        let paths = temp_paths("held");
        let first = claim(&paths).expect("first claim");
        assert!(matches!(first, Claim::Acquired(_)));
        assert!(matches!(
            claim(&paths).expect("second claim"),
            Claim::AlreadyRunning
        ));
        drop(first);
        let _ = std::fs::remove_dir_all(&paths.dir);
    }

    #[test]
    fn the_lock_is_free_again_once_the_holder_is_gone() {
        let paths = temp_paths("released");
        drop(claim(&paths).expect("first claim"));
        assert!(matches!(
            claim(&paths).expect("second claim"),
            Claim::Acquired(_)
        ));
        let _ = std::fs::remove_dir_all(&paths.dir);
    }

    #[test]
    fn separate_directories_do_not_block_each_other() {
        let a = temp_paths("dir-a");
        let b = temp_paths("dir-b");
        let first = claim(&a).expect("claim a");
        assert!(matches!(claim(&b).expect("claim b"), Claim::Acquired(_)));
        drop(first);
        let _ = std::fs::remove_dir_all(&a.dir);
        let _ = std::fs::remove_dir_all(&b.dir);
    }
}
