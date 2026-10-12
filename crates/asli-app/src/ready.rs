//! What Home shows about sending: the files dropped on the window, ready to go to any device, and
//! how sending stands for each device.
//!
//! Kept apart from the window so it can be tested without one. The window owns one [`Ready`] and
//! one [`Moments`], and asks [`device_sends`] how each device's row should look.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use crate::transfer::{Direction, Listed, Stage};

/// How long a device's row shows how its last sending ended before it offers Send File again.
pub const MOMENT: Duration = Duration::from_millis(1800);

/// Files dropped on the window, waiting to be sent to one device or several.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Ready {
    files: Vec<PathBuf>,
    sent_to: Vec<[u8; 16]>,
}

impl Ready {
    /// Adds dropped files, leaving out folders and files already in the group. Returns how many
    /// were left out because they are not files.
    pub fn add(&mut self, paths: Vec<PathBuf>) -> usize {
        let mut skipped = 0;
        for path in paths {
            if !path.is_file() {
                skipped += 1;
            } else if !self.files.contains(&path) {
                self.files.push(path);
            }
        }
        skipped
    }

    /// The files, in the order they were dropped.
    #[must_use]
    pub fn files(&self) -> &[PathBuf] {
        &self.files
    }

    /// Whether there is anything ready to send.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.files.is_empty()
    }

    /// Their size together, as far as it can be read now.
    #[must_use]
    pub fn total_bytes(&self) -> u64 {
        self.files
            .iter()
            .filter_map(|path| std::fs::metadata(path).ok())
            .map(|metadata| metadata.len())
            .sum()
    }

    /// Records that the group was sent to a device, so its button says so.
    pub fn sent(&mut self, device: [u8; 16]) {
        if !self.sent_to.contains(&device) {
            self.sent_to.push(device);
        }
    }

    /// Whether the group was sent to a device already.
    #[must_use]
    pub fn was_sent_to(&self, device: &[u8; 16]) -> bool {
        self.sent_to.contains(device)
    }

    /// Takes a file out of the group.
    pub fn remove(&mut self, path: &Path) {
        self.files.retain(|kept| kept != path);
    }

    /// Empties the group: the person is done with it.
    pub fn clear(&mut self) {
        self.files.clear();
        self.sent_to.clear();
    }
}

/// How sending to one device stands.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum DeviceSend {
    /// Nothing on its way: the row offers Send File.
    Idle,
    /// Offered and waiting for someone there to accept, or still being read here first.
    Waiting {
        /// How many files.
        files: u32,
    },
    /// On its way.
    Sending {
        /// How many files are under way, accepted or not.
        files: u32,
        /// How far, from 0 to 1, over every file under way.
        progress: f32,
    },
    /// Just ended: shown for a moment, then the row is idle again.
    Ended(Ending),
}

/// How the last sending to a device ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ending {
    /// Every file arrived.
    Sent,
    /// Someone there turned it down.
    Declined,
    /// Called off, here or there.
    Cancelled,
    /// It broke off.
    Failed,
}

/// How sending stands for every device that has anything under way. A device missing from the
/// map is idle, apart from the moment after an ending, which [`Moments`] adds.
#[must_use]
pub fn device_sends(listed: &[Listed], preparing: &[[u8; 16]]) -> HashMap<[u8; 16], DeviceSend> {
    let mut out: HashMap<[u8; 16], (u32, u32, u64, u64)> = HashMap::new();
    for device in preparing {
        out.entry(*device).or_default().0 += 1;
    }
    for t in listed.iter().filter(|t| t.direction == Direction::Sending) {
        match t.stage {
            Stage::Offered => out.entry(t.device_id).or_default().0 += 1,
            Stage::Moving(done) => {
                let entry = out.entry(t.device_id).or_default();
                entry.1 += 1;
                entry.2 += u64::from(done);
                entry.3 += t.chunks.max(1);
            }
            _ => {}
        }
    }
    out.into_iter()
        .map(|(device, (waiting, moving, done, chunks))| {
            let state = if moving == 0 {
                DeviceSend::Waiting { files: waiting }
            } else {
                #[allow(clippy::cast_precision_loss)]
                let progress = (done as f32 / chunks.max(1) as f32).clamp(0.0, 1.0);
                DeviceSend::Sending {
                    files: waiting + moving,
                    progress,
                }
            };
            (device, state)
        })
        .collect()
}

/// How the newest finished sending to a device ended, if any did.
fn last_ending(listed: &[Listed], device: &[u8; 16]) -> Option<Ending> {
    // Listed newest first.
    listed
        .iter()
        .filter(|t| t.direction == Direction::Sending && t.device_id == *device)
        .find_map(|t| match t.stage {
            Stage::Done(_) => Some(Ending::Sent),
            Stage::Declined => Some(Ending::Declined),
            Stage::Cancelled => Some(Ending::Cancelled),
            Stage::Failed(_) => Some(Ending::Failed),
            Stage::Offered | Stage::Moving(_) => None,
        })
}

/// Notices when a device's sending ends, and keeps how it ended on its row for a moment.
#[derive(Debug, Default)]
pub struct Moments {
    busy: Vec<[u8; 16]>,
    showing: HashMap<[u8; 16], (Instant, Ending)>,
    /// When it last looked. An ending that happened while nobody was looking, the window closed
    /// for an hour say, is old news, not a moment to show.
    looked: Option<Instant>,
}

impl Moments {
    /// Folds the moment after an ending into `sends`, and forgets moments that are over.
    pub fn apply(
        &mut self,
        sends: &mut HashMap<[u8; 16], DeviceSend>,
        listed: &[Listed],
        now: Instant,
    ) {
        if self
            .looked
            .is_some_and(|looked| now.saturating_duration_since(looked) > MOMENT)
        {
            self.busy.clear();
        }
        self.looked = Some(now);
        for device in std::mem::take(&mut self.busy) {
            if !sends.contains_key(&device) {
                if let Some(ending) = last_ending(listed, &device) {
                    self.showing.insert(device, (now + MOMENT, ending));
                }
            }
        }
        self.busy = sends.keys().copied().collect();
        self.showing
            .retain(|device, (until, _)| *until > now && !sends.contains_key(device));
        for (device, (_, ending)) in &self.showing {
            sends.insert(*device, DeviceSend::Ended(*ending));
        }
    }

    /// Whether a moment is still showing, so the window keeps redrawing until it ends.
    #[must_use]
    pub fn any(&self) -> bool {
        !self.showing.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MAC: [u8; 16] = [1; 16];
    const PC: [u8; 16] = [2; 16];

    fn sending(device: [u8; 16], stage: Stage, chunks: u64) -> Listed {
        Listed {
            id: [0; 16],
            direction: Direction::Sending,
            peer: String::new(),
            device_id: device,
            name: "f".to_owned(),
            size: 1,
            chunks,
            stage,
        }
    }

    #[test]
    fn each_device_shows_its_own_sending() {
        let listed = vec![
            sending(MAC, Stage::Offered, 4),
            sending(PC, Stage::Moving(1), 4),
            sending(PC, Stage::Offered, 4),
            sending(PC, Stage::Done(None), 4),
        ];
        let sends = device_sends(&listed, &[]);
        assert_eq!(sends[&MAC], DeviceSend::Waiting { files: 1 });
        assert_eq!(
            sends[&PC],
            DeviceSend::Sending {
                files: 2,
                progress: 0.25
            }
        );
        // A file still being read here already shows its device as waiting.
        assert_eq!(
            device_sends(&[], &[MAC])[&MAC],
            DeviceSend::Waiting { files: 1 }
        );
    }

    #[test]
    fn an_ending_shows_for_a_moment_then_the_row_is_idle() {
        let start = Instant::now();
        let mut moments = Moments::default();
        let under_way = vec![sending(MAC, Stage::Moving(2), 4)];
        let mut sends = device_sends(&under_way, &[]);
        moments.apply(&mut sends, &under_way, start);

        let declined = vec![sending(MAC, Stage::Declined, 4)];
        let mut sends = device_sends(&declined, &[]);
        moments.apply(&mut sends, &declined, start + Duration::from_millis(100));
        assert_eq!(sends[&MAC], DeviceSend::Ended(Ending::Declined));

        let mut sends = device_sends(&declined, &[]);
        moments.apply(
            &mut sends,
            &declined,
            start + MOMENT + Duration::from_secs(1),
        );
        assert!(!sends.contains_key(&MAC));
        assert!(!moments.any());
    }

    #[test]
    fn a_group_keeps_files_once_and_remembers_where_it_went() {
        let dir = std::env::temp_dir().join(format!("asli-ready-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let file = dir.join("a.txt");
        std::fs::write(&file, b"hello").expect("writes");
        let mut ready = Ready::default();
        assert_eq!(ready.add(vec![file.clone(), file.clone(), dir.clone()]), 1);
        assert_eq!(ready.files(), std::slice::from_ref(&file));
        assert_eq!(ready.total_bytes(), 5);
        ready.sent(MAC);
        assert!(ready.was_sent_to(&MAC) && !ready.was_sent_to(&PC));
        ready.clear();
        assert!(ready.is_empty() && !ready.was_sent_to(&MAC));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn an_ending_while_nobody_looked_is_not_shown_later() {
        let start = Instant::now();
        let mut moments = Moments::default();
        let under_way = vec![sending(MAC, Stage::Moving(2), 4)];
        let mut sends = device_sends(&under_way, &[]);
        moments.apply(&mut sends, &under_way, start);

        // The window was closed for an hour, and the file arrived meanwhile.
        let done = vec![sending(MAC, Stage::Done(None), 4)];
        let mut sends = device_sends(&done, &[]);
        moments.apply(&mut sends, &done, start + Duration::from_secs(3600));
        assert!(!sends.contains_key(&MAC));
        assert!(!moments.any());
    }
}
