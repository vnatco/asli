//! What this device has already accepted, saved so replay protection survives a restart.
//!
//! The relay is untrusted, and the defence against it re-sending old clips is the message id and
//! the per device sequence number inside each clip. Those used to live in memory only, so every
//! restart forgot them, and a tight two minute freshness window had to stand in for them, which
//! made sync depend on every device's clock being right. Saved here, they protect a device from
//! its first second, and the freshness window can be a loose sanity bound instead.
//!
//! The file names the room it belongs to. Memory from another account is ignored rather than
//! trusted, so joining a different account starts clean.

use std::fs;

use asli_core::ReplayMemory;
use serde::{Deserialize, Serialize};

use crate::config::{hex, unhex, write_atomically, Paths};
use crate::error::Result;

const FILE: &str = "replay.json";

#[derive(Debug, Serialize, Deserialize)]
struct Stored {
    room: String,
    highest_seq: Vec<(String, u64)>,
    recent: Vec<String>,
}

/// Loads what was accepted in `room` before. Anything missing, unreadable or belonging to another
/// room is an empty memory: the worst that costs is the protection a first run would have had.
#[must_use]
pub fn load(paths: &Paths, room: &str) -> ReplayMemory {
    let Ok(raw) = fs::read_to_string(paths.dir.join(FILE)) else {
        return ReplayMemory::default();
    };
    let Ok(stored) = serde_json::from_str::<Stored>(&raw) else {
        return ReplayMemory::default();
    };
    if stored.room != room {
        return ReplayMemory::default();
    }
    ReplayMemory {
        highest_seq: stored
            .highest_seq
            .iter()
            .filter_map(|(device, seq)| Some((unhex(device)?, *seq)))
            .collect(),
        recent: stored.recent.iter().filter_map(|id| unhex(id)).collect(),
    }
}

/// Saves what has been accepted in `room`, replacing the previous file atomically.
///
/// # Errors
///
/// Returns an error if the file could not be written.
pub fn save(paths: &Paths, room: &str, memory: &ReplayMemory) -> Result<()> {
    let stored = Stored {
        room: room.to_owned(),
        highest_seq: memory
            .highest_seq
            .iter()
            .map(|(device, seq)| (hex(device), *seq))
            .collect(),
        recent: memory.recent.iter().map(|id| hex(id)).collect(),
    };
    let json = serde_json::to_string(&stored)
        .map_err(|e| crate::Error::Parse(format!("could not serialize the replay memory: {e}")))?;
    write_atomically(&paths.dir.join(FILE), json.as_bytes(), 0o600)
}

/// Forgets it, with the account.
pub fn wipe(paths: &Paths) {
    let _ = fs::remove_file(paths.dir.join(FILE));
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch(tag: &str) -> Paths {
        let dir = std::env::temp_dir().join(format!("asli-replay-{tag}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).expect("scratch dir");
        Paths { dir }
    }

    #[test]
    fn memory_round_trips_for_its_own_room_only() {
        let paths = scratch("round");
        let memory = ReplayMemory {
            highest_seq: vec![([7u8; 16], 42)],
            recent: vec![[9u8; 16], [8u8; 16]],
        };
        save(&paths, "ROOM1", &memory).expect("saves");
        assert_eq!(load(&paths, "ROOM1"), memory);
        assert_eq!(load(&paths, "ROOM2"), ReplayMemory::default());
        wipe(&paths);
        assert_eq!(load(&paths, "ROOM1"), ReplayMemory::default());
        let _ = fs::remove_dir_all(paths.dir);
    }
}
