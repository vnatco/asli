//! The devices on this account, as far as this one knows.
//!
//! # Where the list comes from
//!
//! The relay cannot see devices. It counts connections, and it forwards sealed messages it cannot
//! read. So each device says who it is in a sealed announcement: its id, a name and its operating
//! system, sent when it connects and again whenever the number of connections in the room
//! changes. This module keeps what those announcements said, and when each was last heard.
//!
//! # Who is online
//!
//! Nothing says when a device leaves. What arrives is a smaller connection count, and every
//! device still there answers it by announcing again. So a device counts as online while this one
//! is connected and has heard from it since the count last went down. One that has not announced
//! since then is taken to be the one that left.
//!
//! # What is kept on disk
//!
//! Names, operating systems and when each device was last heard, in a small file beside the
//! configuration, so "last seen two days ago" survives a restart. It is tagged with the account
//! it belongs to and starts over when that changes, because the devices of an account this one
//! has left mean nothing here.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use serde::{Deserialize, Serialize};

use crate::clipboard_io::log_line;
use crate::config::{hex, Paths};

/// The file the list lives in, beside the configuration.
const FILE: &str = "devices.json";

/// How many other devices are remembered. Far more than any one person has, and a cap all the
/// same, so a hostile member of the room cannot grow the file without bound.
const MAX_DEVICES: usize = 64;

/// One device, as last announced.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Device {
    /// The device's name, as it calls itself.
    pub name: String,
    /// Its operating system, as it describes itself.
    pub os: String,
    /// When it last announced itself, in milliseconds since the Unix epoch.
    pub last_seen_ms: u64,
}

/// What is on disk.
#[derive(Debug, Default, Serialize, Deserialize)]
struct Stored {
    /// The account these devices belong to.
    room: String,
    /// Keyed by device id in hex.
    devices: BTreeMap<String, Device>,
}

/// One row of the list, ready to show.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Listed {
    /// Device id in hex.
    pub id: String,
    /// Its name.
    pub name: String,
    /// Its operating system.
    pub os: String,
    /// When it was last heard from, or `None` for this device.
    pub last_seen_ms: Option<u64>,
    /// Whether it is connected right now, as far as this device can tell.
    pub online: bool,
    /// Whether it is this device.
    pub this_device: bool,
}

/// The shared list: the daemon writes it, the window reads it.
#[derive(Debug, Clone, Default)]
pub struct DevicesHandle(Arc<Mutex<Registry>>);

#[derive(Debug, Default)]
struct Registry {
    paths: Option<Paths>,
    stored: Stored,
    /// Whether this device is connected to the relay right now.
    connected: bool,
    /// The last connection count the relay reported.
    peers: u32,
    /// When the count last went down. Devices not heard from since are taken to have left.
    last_departure_ms: u64,
}

impl DevicesHandle {
    /// Loads the list for this account, starting over if the file belongs to another one.
    pub fn load(&self, paths: &Paths, room: &str) {
        let path = paths.dir.join(FILE);
        let stored = std::fs::read(&path)
            .ok()
            .and_then(|bytes| serde_json::from_slice::<Stored>(&bytes).ok())
            .filter(|stored| stored.room == room)
            .unwrap_or_else(|| Stored {
                room: room.to_owned(),
                devices: BTreeMap::new(),
            });
        if let Ok(mut registry) = self.0.lock() {
            registry.paths = Some(paths.clone());
            registry.stored = stored;
        }
    }

    /// Records an announcement.
    pub fn heard(&self, device_id: &[u8; 16], name: &str, os: &str, now_ms: u64) {
        let Ok(mut registry) = self.0.lock() else {
            return;
        };
        let id = hex(device_id);
        let device = Device {
            name: name.to_owned(),
            os: os.to_owned(),
            last_seen_ms: now_ms,
        };
        let changed = registry
            .stored
            .devices
            .get(&id)
            .is_none_or(|known| known.name != device.name || known.os != device.os);
        registry.stored.devices.insert(id, device);
        registry.evict();
        // Written when something a person would notice changed, not on every repeat of the same
        // announcement, which happens every time anyone in the room connects.
        if changed {
            registry.save();
        }
    }

    /// Records that this device connected or lost its connection.
    pub fn set_connected(&self, connected: bool, peers: u32, now_ms: u64) {
        let Ok(mut registry) = self.0.lock() else {
            return;
        };
        if registry.connected && !connected {
            // Last seen is when the connection ended for everyone still listed as online, since
            // that is the last moment this device could have known they were there.
            let departure = registry.last_departure_ms;
            for device in registry.stored.devices.values_mut() {
                if device.last_seen_ms >= departure {
                    device.last_seen_ms = now_ms;
                }
            }
            registry.save();
        }
        registry.connected = connected;
        registry.peers = peers;
        if connected {
            registry.last_departure_ms = now_ms;
        }
    }

    /// Records a new connection count.
    pub fn presence(&self, peers: u32, now_ms: u64) {
        let Ok(mut registry) = self.0.lock() else {
            return;
        };
        if peers < registry.peers {
            // Everyone online until now was seen until now. The ones still here announce again
            // straight away and move past this; the one that left stays at it, which is when it
            // was last known to be here.
            let since = registry.last_departure_ms;
            let seen = now_ms.saturating_sub(1);
            for device in registry.stored.devices.values_mut() {
                if device.last_seen_ms >= since {
                    device.last_seen_ms = device.last_seen_ms.max(seen);
                }
            }
            registry.last_departure_ms = now_ms;
        }
        registry.peers = peers;
    }

    /// Forgets every other device. For joining a different account.
    pub fn clear(&self) {
        if let Ok(mut registry) = self.0.lock() {
            registry.stored.devices.clear();
            registry.save();
        }
    }

    /// The list, this device first, then online devices, then the rest by when they were seen.
    #[must_use]
    pub fn list(&self, this: &Listed) -> Vec<Listed> {
        let Ok(registry) = self.0.lock() else {
            return vec![this.clone()];
        };
        let mut others: Vec<Listed> = registry
            .stored
            .devices
            .iter()
            .filter(|(id, _)| **id != this.id)
            .map(|(id, device)| Listed {
                id: id.clone(),
                name: device.name.clone(),
                os: device.os.clone(),
                last_seen_ms: Some(device.last_seen_ms),
                online: registry.connected && device.last_seen_ms >= registry.last_departure_ms,
                this_device: false,
            })
            .collect();
        others.sort_by(|a, b| {
            b.online
                .cmp(&a.online)
                .then(b.last_seen_ms.cmp(&a.last_seen_ms))
        });
        let mut all = Vec::with_capacity(others.len() + 1);
        all.push(this.clone());
        all.extend(others);
        all
    }

    /// The name a device announced, if this one has heard of it.
    #[must_use]
    pub fn name_of(&self, device_id: &[u8; 16]) -> Option<String> {
        let registry = self.0.lock().ok()?;
        registry
            .stored
            .devices
            .get(&hex(device_id))
            .map(|device| device.name.clone())
    }
}

impl Registry {
    /// Drops the devices heard from longest ago, past the cap.
    fn evict(&mut self) {
        while self.stored.devices.len() > MAX_DEVICES {
            let Some(oldest) = self
                .stored
                .devices
                .iter()
                .min_by_key(|(_, device)| device.last_seen_ms)
                .map(|(id, _)| id.clone())
            else {
                return;
            };
            self.stored.devices.remove(&oldest);
        }
    }

    fn save(&self) {
        let Some(paths) = &self.paths else {
            return;
        };
        let Ok(bytes) = serde_json::to_vec_pretty(&self.stored) else {
            return;
        };
        // Owner only, and atomically: this names every machine on the account, its operating
        // system and when it was last seen, which is a precise description of the owner's setup.
        if let Err(err) = crate::config::write_atomically(&paths.dir.join(FILE), &bytes, 0o600) {
            eprintln!("{}", log_line("devices_save_failed", &err.to_string()));
        }
    }
}

/// The name this device goes by when nobody has given it one: the computer's own name.
#[must_use]
pub fn default_name() -> String {
    let name = computer_name();
    let name = name.trim();
    if name.is_empty() {
        "This computer".to_owned()
    } else {
        name.to_owned()
    }
}

/// The name this device announces: the one set in Settings, or the computer's own.
#[must_use]
pub fn display_name(configured: &str) -> String {
    let configured = configured.trim();
    if configured.is_empty() {
        default_name()
    } else {
        configured.to_owned()
    }
}

#[cfg(target_os = "linux")]
fn computer_name() -> String {
    std::fs::read_to_string("/proc/sys/kernel/hostname")
        .or_else(|_| std::fs::read_to_string("/etc/hostname"))
        .unwrap_or_default()
}

#[cfg(target_os = "windows")]
fn computer_name() -> String {
    std::env::var("COMPUTERNAME").unwrap_or_default()
}

#[cfg(target_os = "macos")]
fn computer_name() -> String {
    // The name shown in Sharing settings, "Anna's MacBook Pro", rather than the network host
    // name, which is the same thing mangled into a DNS label.
    command_output("scutil", &["--get", "ComputerName"])
}

#[cfg(not(any(target_os = "linux", target_os = "windows", target_os = "macos")))]
fn computer_name() -> String {
    String::new()
}

/// This device's operating system, as a person would name it: "Windows 11", "macOS 15",
/// "Fedora Linux 42".
#[must_use]
pub fn this_os() -> String {
    static OS: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    OS.get_or_init(detect_os).clone()
}

#[cfg(target_os = "linux")]
fn detect_os() -> String {
    // PRETTY_NAME can be long ("Debian GNU/Linux 13 (trixie)"), so NAME and VERSION_ID are
    // preferred and PRETTY_NAME is only the fallback.
    let release = std::fs::read_to_string("/etc/os-release")
        .or_else(|_| std::fs::read_to_string("/usr/lib/os-release"))
        .unwrap_or_default();
    let field = |key: &str| {
        release.lines().find_map(|line| {
            line.strip_prefix(key)
                .and_then(|rest| rest.strip_prefix('='))
                .map(|value| value.trim().trim_matches('"').to_owned())
        })
    };
    match (field("NAME"), field("VERSION_ID"), field("PRETTY_NAME")) {
        (Some(name), Some(version), _) => format!("{name} {version}"),
        (Some(name), None, _) => name,
        (None, _, Some(pretty)) => pretty,
        _ => "Linux".to_owned(),
    }
}

#[cfg(target_os = "windows")]
fn detect_os() -> String {
    // "Microsoft Windows [Version 10.0.22631.4037]". Windows 11 still calls itself 10.0 and is
    // told apart by its build number, which starts at 22000.
    let output = command_output("cmd", &["/c", "ver"]);
    let build = output
        .split(['[', ']'])
        .nth(1)
        .and_then(|version| version.split('.').nth(2))
        .and_then(|build| build.trim().parse::<u32>().ok());
    match build {
        Some(build) if build >= 22000 => "Windows 11".to_owned(),
        Some(_) => "Windows 10".to_owned(),
        None => "Windows".to_owned(),
    }
}

#[cfg(target_os = "macos")]
fn detect_os() -> String {
    let version = command_output("sw_vers", &["-productVersion"]);
    let major = version.trim().split('.').next().unwrap_or("").to_owned();
    if major.is_empty() {
        "macOS".to_owned()
    } else {
        format!("macOS {major}")
    }
}

#[cfg(not(any(target_os = "linux", target_os = "windows", target_os = "macos")))]
fn detect_os() -> String {
    std::env::consts::OS.to_owned()
}

/// Runs a short command and returns what it printed, or nothing if it failed.
#[cfg(any(target_os = "windows", target_os = "macos"))]
fn command_output(program: &str, args: &[&str]) -> String {
    let mut command = std::process::Command::new(program);
    command.args(args);
    // No console window flashing up behind the tray for a version check.
    #[cfg(target_os = "windows")]
    {
        use std::os::windows::process::CommandExt as _;
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        command.creation_flags(CREATE_NO_WINDOW);
    }
    command
        .output()
        .ok()
        .filter(|output| output.status.success())
        .map(|output| String::from_utf8_lossy(&output.stdout).trim().to_owned())
        .unwrap_or_default()
}

/// Forgets the device list, with the account.
///
/// It names every machine on the account, its operating system and when it was last seen, which
/// describes the owner's setup and outlives the account it belonged to.
pub fn wipe(paths: &Paths) {
    let _ = std::fs::remove_file(paths.dir.join(FILE));
}

#[cfg(test)]
mod tests {
    use super::*;

    fn this() -> Listed {
        Listed {
            id: hex(&[1u8; 16]),
            name: "here".to_owned(),
            os: "Linux".to_owned(),
            last_seen_ms: None,
            online: true,
            this_device: true,
        }
    }

    #[test]
    fn this_device_comes_first_and_is_never_listed_twice() {
        let devices = DevicesHandle::default();
        devices.set_connected(true, 2, 1_000);
        devices.heard(&[1u8; 16], "echo of me", "Linux", 1_100);
        devices.heard(&[2u8; 16], "laptop", "macOS 15", 1_200);
        let list = devices.list(&this());
        assert_eq!(
            list.len(),
            2,
            "our own id must not appear as a second device"
        );
        assert!(list[0].this_device);
        assert_eq!(list[1].name, "laptop");
        assert!(list[1].online);
    }

    #[test]
    fn a_device_that_does_not_answer_a_departure_is_the_one_that_left() {
        let devices = DevicesHandle::default();
        devices.set_connected(true, 3, 1_000);
        devices.heard(&[2u8; 16], "stays", "Linux", 1_100);
        devices.heard(&[3u8; 16], "leaves", "Linux", 1_100);
        devices.presence(2, 2_000);
        // Everyone still in the room re-announces on the lower count.
        devices.heard(&[2u8; 16], "stays", "Linux", 2_050);
        let list = devices.list(&this());
        let stays = list.iter().find(|d| d.name == "stays").expect("listed");
        let leaves = list.iter().find(|d| d.name == "leaves").expect("listed");
        assert!(stays.online);
        assert!(!leaves.online);
        assert_eq!(
            leaves.last_seen_ms,
            Some(1_999),
            "last seen is when it left, not when it last announced"
        );
        assert_eq!(list[1].name, "stays", "online devices sort first");
    }

    #[test]
    fn nobody_is_online_while_this_device_is_not_connected() {
        let devices = DevicesHandle::default();
        devices.set_connected(true, 2, 1_000);
        devices.heard(&[2u8; 16], "laptop", "Linux", 1_100);
        devices.set_connected(false, 0, 5_000);
        let list = devices.list(&this());
        assert!(!list[1].online);
        assert_eq!(
            list[1].last_seen_ms,
            Some(5_000),
            "last seen is when this device lost the connection, not the last announcement"
        );
    }

    #[test]
    fn the_list_is_capped() {
        let devices = DevicesHandle::default();
        for i in 0..(MAX_DEVICES + 10) {
            let mut id = [0u8; 16];
            id[0] = u8::try_from(i).unwrap_or(0);
            id[1] = 9;
            devices.heard(&id, "d", "Linux", u64::try_from(i).unwrap_or(0));
        }
        assert_eq!(devices.list(&this()).len(), MAX_DEVICES + 1);
    }

    #[test]
    fn a_blank_name_falls_back_to_the_computer_name() {
        assert_eq!(display_name("  Work laptop "), "Work laptop");
        assert!(!display_name("   ").is_empty());
    }
}
