//! The daemon: clipboard in, relay out, relay in, clipboard out.
//!
//! Everything here is sequencing. The protocol rules live in `asli-net`, the platform rules in
//! `asli-clipboard`, and the loop prevention in `asli-core`. What this module owns is the order of
//! operations and the decision about what to do when something fails.
//!
//! # The sequence counter
//!
//! Peers reject any clip whose per device sequence is at or below the highest they have already
//! seen from that device, because that is exactly what a relay replaying an old message looks
//! like. A counter that went backwards after a crash would therefore make every later clip from
//! this device look like an attack, and sync would appear to be running while silently dropping
//! everything.
//!
//! Persisting on every copy would be a file write per keystroke-sized event. So instead the
//! daemon reserves a block of counters, writes the top of that block to disk before using any of
//! it, and allocates from the block in memory. A crash loses the unused remainder of the block,
//! which is harmless, and can never reuse a number, which is the part that matters.

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::mpsc::Receiver;
use std::sync::{Arc, Mutex};

use asli_crypto::Identity;
use asli_net::client::{self, ClientEvent, Disconnect};
use asli_net::session::Action;
use asli_net::{Backoff, DeviceInfo, LocalEvent, Session};
use tokio::sync::mpsc;
use zeroize::Zeroizing;

use crate::clipboard_io::{log_line, ClipboardIo, Observed};
use crate::config::{Config, Paths, State};
use crate::devices::DevicesHandle;
use crate::error::Result;
use crate::notify;
use crate::tray::StatusHandle;
use crate::window::{HistoryContent, SharedHistory};

/// Everything the tray shares with the daemon.
///
/// Pausing has to reach two places: the outbound path, so copies stop leaving this machine, and
/// the inbound path, so arriving clips stop overwriting the local clipboard. A flag checked in
/// both is the whole mechanism, and it is deliberately not a disconnect: staying connected means
/// resuming is instant and the relay's connection count stays honest.
#[derive(Debug, Clone, Default)]
pub struct Controls {
    /// Set while sync is paused.
    pub paused: Arc<AtomicBool>,
    /// Latest status, published for the tray menu.
    pub status: StatusHandle,
    /// Set when the person asks for the relay's stored clip.
    ///
    /// A flag rather than a channel because the request has no payload and only the most recent
    /// one matters: asking twice before the daemon looks should fetch once, not twice.
    pub retained_wanted: Arc<AtomicBool>,
    /// Set from the moment the person asks for the stored clip until it arrives or is refused.
    ///
    /// A stored clip that turns up unasked is only offered, never written, so it cannot overwrite
    /// something copied here seconds earlier. One that was asked for must be written, and without
    /// this the two could not be told apart, so the button never did anything.
    pub retained_pending: Arc<AtomicBool>,
    /// Settings the window can change while the daemon runs. See [`LiveSettings`].
    pub settings: LiveSettings,
    /// The other devices on this account, as their announcements describe them.
    pub devices: DevicesHandle,
    /// What the window sends to the other devices through the live connection.
    pub outbox: Outbox,
    /// Files on their way to or from the other devices.
    pub transfers: crate::transfer::Transfers,
}

/// The window's way into the live connection, for what it asks to send to the other devices.
///
/// For now that is a new account key, which removes a device or retires a key that once appeared
/// in an old style join token. The new key is kept here, and only stored once the relay confirms
/// it has passed the key on, so a key that never reached anyone is never the one this device
/// moves to.
#[derive(Debug, Clone, Default)]
pub struct Outbox(Arc<Mutex<OutboxState>>);

#[derive(Default)]
struct OutboxState {
    tx: Option<mpsc::Sender<LocalEvent>>,
    rekey: Option<PendingRekey>,
    note: Option<String>,
    next_token: u64,
}

impl std::fmt::Debug for OutboxState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OutboxState")
            .field("connected", &self.tx.is_some())
            .field("rekey_pending", &self.rekey.is_some())
            .finish_non_exhaustive()
    }
}

/// A new account key on its way to the other devices.
struct PendingRekey {
    token: u64,
    secret: Zeroizing<[u8; 32]>,
    /// The devices the new key is sealed to.
    keep: Vec<[u8; 16]>,
    /// The devices left out, which are forgotten once the move is done.
    removing: Vec<[u8; 16]>,
}

impl PendingRekey {
    fn event(&self) -> LocalEvent {
        LocalEvent::Rekey {
            keep: self.keep.clone(),
            secret: asli_net::client::HandedSecret(self.secret.clone()),
            token: self.token,
        }
    }
}

impl Outbox {
    fn attach(&self, tx: mpsc::Sender<LocalEvent>) {
        if let Ok(mut state) = self.0.lock() {
            state.tx = Some(tx);
        }
    }

    /// Replaces the account key, sealing the new one to the devices in `keep` and leaving every
    /// other device out. This device moves to the new key once the relay has passed it on.
    ///
    /// # Errors
    ///
    /// Returns a sentence for the window when another replacement is under way, the daemon is not
    /// running, or randomness fails.
    pub fn replace_key(
        &self,
        keep: Vec<[u8; 16]>,
        removing: Vec<[u8; 16]>,
    ) -> std::result::Result<(), String> {
        let mut state = self
            .0
            .lock()
            .map_err(|_| "Asli is shutting down.".to_owned())?;
        if state.rekey.is_some() {
            return Err("A key change is already under way.".to_owned());
        }
        let tx = state
            .tx
            .clone()
            .ok_or_else(|| "Asli is not connected yet.".to_owned())?;
        let secret =
            Zeroizing::new(asli_crypto::random::bytes::<32>().map_err(|err| err.to_string())?);
        state.next_token += 1;
        let pending = PendingRekey {
            token: state.next_token,
            secret,
            keep,
            removing,
        };
        tx.try_send(pending.event())
            .map_err(|_| "Asli is busy. Try again in a moment.".to_owned())?;
        state.rekey = Some(pending);
        state.note = None;
        Ok(())
    }

    /// Whether a key change is waiting for the relay.
    #[must_use]
    pub fn rekey_pending(&self) -> bool {
        self.0.lock().is_ok_and(|state| state.rekey.is_some())
    }

    /// Why the last key change did not happen, once.
    #[must_use]
    pub fn take_note(&self) -> Option<String> {
        self.0.lock().ok().and_then(|mut state| state.note.take())
    }

    fn take_rekey(&self, token: u64) -> Option<PendingRekey> {
        let mut state = self.0.lock().ok()?;
        if state
            .rekey
            .as_ref()
            .is_some_and(|pending| pending.token == token)
        {
            state.rekey.take()
        } else {
            None
        }
    }

    fn fail_rekey(&self, token: u64, reason: &str) {
        if let Ok(mut state) = self.0.lock() {
            if state
                .rekey
                .as_ref()
                .is_some_and(|pending| pending.token == token)
            {
                state.rekey = None;
                state.note = Some(format!("The key was not changed: {reason}."));
            }
        }
    }

    /// A new connection is up: a key change the last one sent without the relay confirming it is
    /// sent again. Never dropped: the relay may already have passed it on, and the devices that
    /// got it have moved, so this device must follow them, not stay behind on the old key. The
    /// devices that have moved are no longer in the old room to see it twice.
    fn resend_pending(&self) {
        if let Ok(state) = self.0.lock() {
            if let (Some(pending), Some(tx)) = (&state.rekey, &state.tx) {
                let _ = tx.try_send(pending.event());
            }
        }
    }
}

/// The settings that take effect at once, shared between the window and the daemon.
///
/// The daemon used to copy these out of the configuration when it started, so the Settings screen
/// saved a change to disk and the running daemon went on using the old value until a restart: the
/// notifications switch did nothing, and a new relay address was ignored however long one waited.
#[derive(Debug, Clone, Default)]
pub struct LiveSettings {
    /// Whether an arriving clip raises a notification.
    pub notifications: Arc<AtomicBool>,
    /// Largest copy this device sends, in bytes.
    pub max_content_bytes: Arc<AtomicUsize>,
    /// Set when the relay address changed, so the daemon drops its connection and reconnects to
    /// the new one straight away. Also set by Retry now, which cuts a wait between attempts
    /// short.
    pub reconnect: Arc<AtomicBool>,
    /// Set when this device's name changed, so it announces the new one to the others.
    pub announce: Arc<AtomicBool>,
}

impl LiveSettings {
    /// Takes the current values from the configuration.
    pub fn load(&self, config: &Config) {
        self.notifications
            .store(config.notifications, Ordering::Relaxed);
        self.max_content_bytes
            .store(config.max_content_bytes, Ordering::Relaxed);
    }

    fn notifications(&self) -> bool {
        self.notifications.load(Ordering::Relaxed)
    }
}

impl Controls {
    /// Whether sync is currently paused.
    #[must_use]
    pub fn is_paused(&self) -> bool {
        self.paused.load(Ordering::Relaxed)
    }

    /// Asks the daemon to fetch the relay's stored clip on its next pass.
    pub fn request_retained(&self) {
        self.retained_pending.store(true, Ordering::Relaxed);
        self.retained_wanted.store(true, Ordering::Relaxed);
    }

    /// Takes the pending request, if there is one, clearing it.
    #[must_use]
    pub fn take_retained_request(&self) -> bool {
        self.retained_wanted.swap(false, Ordering::Relaxed)
    }
}

/// Whether the person has been told this run that the clock is wrong.
static CLOCK_SKEW_TOLD: AtomicBool = AtomicBool::new(false);

/// How many sequence numbers to reserve at a time.
///
/// Large enough that the file is written rarely, small enough that the numbers stay meaningful.
pub const SEQ_RESERVATION: u64 = 1000;

/// What the daemon believes right now, for the status line and for diagnostics.
#[derive(Debug, Clone, Default)]
pub struct Status {
    /// Human readable connection state.
    pub state: String,
    /// Connections in the room. Never a device count, because the relay cannot see devices.
    pub peers: u32,
    /// When a clip last arrived or was sent, in milliseconds since the epoch.
    pub last_sync_ms: Option<u64>,
    /// Clips skipped for being too large.
    pub skipped: u64,
    /// Whether the relay is holding a stored clip this device has not fetched.
    pub has_retained: bool,
    /// Last error worth showing, never containing clipboard content.
    pub last_error: Option<String>,
    /// Connection attempts since the last one that succeeded, counting the one under way.
    pub attempt: u32,
    /// When the next attempt starts, while waiting between attempts.
    pub retry_at_ms: Option<u64>,
}

impl Status {
    /// The tray style status line.
    #[must_use]
    pub fn line(&self) -> String {
        match self.peers {
            0 => self.state.clone(),
            n => format!("{}, {n} connected", self.state),
        }
    }
}

/// Applies one protocol action. Shared by the live client and by the tests.
///
/// Returns whether anything was written to the clipboard, which the loop prevention test asserts
/// on directly.
pub fn on_action(action: &Action, io: &dyn ClipboardIo, status: &mut Status, now_ms: u64) -> bool {
    match action {
        Action::Authenticated {
            peers,
            has_retained,
            ..
        } => {
            "Synced".clone_into(&mut status.state);
            status.peers = *peers;
            status.has_retained = *has_retained;
            false
        }
        Action::Clip {
            text,
            retained,
            ts_ms,
            ..
        } => apply_clip(text, *retained, *ts_ms, io, status, now_ms),
        Action::Image { png, ts_ms, .. } => apply_image(png, *ts_ms, io, status, now_ms),
        Action::Presence { peers } => {
            status.peers = *peers;
            false
        }
        Action::RelayError { code, .. } => {
            status.last_error = Some(format!("{code:?}"));
            false
        }
        Action::AuthFailed(code) => {
            status.state = format!("Rejected: {}", code.as_str());
            false
        }
        // Sends are performed by the transport, and Action is non exhaustive, so anything else
        // is deliberately ignored rather than matched one by one.
        _ => false,
    }
}

/// Applies one client event from the live socket.
pub fn on_client_event(
    event: &ClientEvent,
    io: &dyn ClipboardIo,
    status: &mut Status,
    now_ms: u64,
) -> bool {
    match event {
        ClientEvent::Authenticated {
            peers,
            has_retained,
            ..
        } => {
            "Synced".clone_into(&mut status.state);
            status.peers = *peers;
            status.has_retained = *has_retained;
            false
        }
        ClientEvent::Clip(clip) => {
            // The relay stores the last clip, so once a live one has arrived, what it holds is
            // the clip just received, and offering it again would offer nothing new.
            if !clip.retained {
                status.has_retained = false;
            }
            apply_clip(&clip.text, clip.retained, clip.ts_ms, io, status, now_ms)
        }
        ClientEvent::Image { png, ts_ms, .. } => apply_image(png, *ts_ms, io, status, now_ms),
        ClientEvent::Presence { peers } => {
            status.peers = *peers;
            false
        }
        ClientEvent::RelayError { code, .. } => {
            status.last_error = Some(format!("{code:?}"));
            false
        }
        ClientEvent::ClockSkew { skew_ms } => {
            status.last_error = Some(format!(
                "this computer's clock is about {} hours off; past a day, clips will be dropped",
                skew_ms.unsigned_abs().div_ceil(60 * 60 * 1000)
            ));
            // Once per run. It is reported again on every reconnect, and a notification each time
            // would be noise about something that has not changed.
            if !CLOCK_SKEW_TOLD.swap(true, Ordering::Relaxed) {
                notify::clock_skew(*skew_ms);
            }
            false
        }
        ClientEvent::ClipSkipped { got, limit } => {
            status.skipped = status.skipped.saturating_add(1);
            // Never silent, and never merely logged. A copy that vanished with no explanation is
            // the single most common complaint against every tool in this category, and a log
            // line is invisible to someone running this from a tray.
            eprintln!(
                "{}",
                log_line(
                    "clip_skipped_too_large",
                    &format!("{got} bytes exceeds the relay limit of {limit} bytes"),
                )
            );
            notify::clip_too_large(*got, *limit);
            false
        }
        _ => false,
    }
}

/// One log line per protocol event worth knowing about. Sizes and counts only, never content.
///
/// The daemon previously logged four lines for an entire session, which made a stall impossible to
/// diagnose after the fact.
fn log_event(event: &ClientEvent) {
    match event {
        ClientEvent::Authenticated { peers, .. } => {
            eprintln!(
                "{}",
                log_line("authenticated", &format!("{peers} connected in this room"))
            );
        }
        ClientEvent::Clip(clip) => {
            eprintln!(
                "{}",
                log_line(
                    "clip_received",
                    &format!(
                        "{} bytes{}",
                        clip.text.len(),
                        if clip.retained { ", retained" } else { "" }
                    )
                )
            );
        }
        ClientEvent::Image { png, .. } => {
            eprintln!(
                "{}",
                log_line("image_received", &format!("{} bytes", png.len()))
            );
        }
        ClientEvent::Presence { peers } => {
            eprintln!("{}", log_line("presence", &format!("{peers} connected")));
        }
        ClientEvent::Dropped { reason, retained } => {
            eprintln!(
                "{}",
                log_line(
                    "clip_dropped",
                    &format!("{reason}{}", if *retained { ", stored clip" } else { "" })
                )
            );
        }
        ClientEvent::ClockSkew { skew_ms } => {
            eprintln!(
                "{}",
                log_line(
                    "clock_skew",
                    &format!("the relay's clock is {skew_ms} ms ahead of this one")
                )
            );
        }
        _ => {}
    }
}

/// Size of the clip an event carries, for the notification body. Never the content itself.
fn clip_len(event: &ClientEvent) -> usize {
    match event {
        ClientEvent::Clip(clip) => clip.text.len(),
        ClientEvent::Image { png, .. } => png.len(),
        _ => 0,
    }
}

/// Whether an event carried an image, so the right notification wording is used.
const fn is_image(event: &ClientEvent) -> bool {
    matches!(event, ClientEvent::Image { .. })
}

/// Records a clip that reached the clipboard, so it can be put back later.
///
/// A retained clip is deliberately not recorded here. It was not written to the clipboard, only
/// offered, and a history holding something the person never received would offer to restore a
/// clip they have never seen.
fn record(history: &SharedHistory, event: &ClientEvent, now_ms: u64) {
    let (content, from) = match event {
        ClientEvent::Clip(clip) if !clip.retained => {
            (HistoryContent::Text(clip.text.clone()), clip.device_id)
        }
        ClientEvent::Image { png, device_id, .. } => {
            (HistoryContent::ImagePng(png.clone()), *device_id)
        }
        _ => return,
    };

    if let Ok(mut history) = history.lock() {
        history.record(content, false, now_ms, from);
    }
}

/// Keeps the device list in step with the connection: who announced, and how many are here.
fn track_devices(event: &ClientEvent, devices: &DevicesHandle, now_ms: u64) {
    match event {
        ClientEvent::Authenticated { peers, .. } => devices.set_connected(true, *peers, now_ms),
        ClientEvent::Presence { peers } => devices.presence(*peers, now_ms),
        ClientEvent::Device(device) => devices.heard_card(device, now_ms),
        ClientEvent::Peer(peer) => {
            eprintln!(
                "{}",
                log_line(
                    "device_announced",
                    &crate::config::hex(&peer.device_id)[..12]
                )
            );
            devices.heard(&peer.device_id, &peer.name, &peer.os, now_ms);
        }
        _ => {}
    }
}

/// Handles one event from a live connection.
///
/// Extracted from the connection loop because judging an event is a different job from deciding
/// when to reconnect, and keeping them together made the loop long enough to hide either one.
fn on_live_event(
    event: &ClientEvent,
    io: &dyn ClipboardIo,
    controls: &Controls,
    status: &mut Status,
    connected_once: &Arc<AtomicBool>,
    history: &SharedHistory,
) {
    let notifications = controls.settings.notifications();
    let now = client::now_ms();

    // Pausing must also stop arriving content from overwriting the local clipboard. Dropping it
    // here rather than disconnecting keeps resume instant. Images are paused too: an image that
    // landed while paused would be just as unwelcome as text.
    if controls.is_paused() && matches!(event, ClientEvent::Clip(_) | ClientEvent::Image { .. }) {
        return;
    }

    log_event(event);
    track_devices(event, &controls.devices, now);
    if answer_retained_request(event, io, controls, status, history, now) {
        controls.status.set(status.clone());
        return;
    }
    if matches!(event, ClientEvent::Authenticated { .. }) {
        // Recorded at the moment the handshake succeeds, so the next attempt after a drop is
        // logged as a reconnection rather than a first connection.
        connected_once.store(true, Ordering::Relaxed);
    }

    if on_client_event(event, io, status, now) {
        // Recorded only when the clip actually reached the clipboard. A write that failed is not
        // history, and listing it would offer to restore something that was never there.
        record(history, event, now);

        if is_image(event) {
            notify::image_received(notifications, clip_len(event));
        } else {
            notify::clip_received(notifications, clip_len(event));
        }
    }
    controls.status.set(status.clone());
}

/// Handles the stored clip the person asked for, or its refusal. Returns true when it did.
fn answer_retained_request(
    event: &ClientEvent,
    io: &dyn ClipboardIo,
    controls: &Controls,
    status: &mut Status,
    history: &SharedHistory,
    now: u64,
) -> bool {
    let asked = || controls.retained_pending.swap(false, Ordering::Relaxed);
    match event {
        ClientEvent::Clip(clip) if clip.retained && asked() => {
            status.has_retained = false;
            // Written as a live clip would be: this is exactly what the person asked for.
            if apply_clip(&clip.text, false, clip.ts_ms, io, status, now) {
                if let Ok(mut history) = history.lock() {
                    history.record(
                        HistoryContent::Text(clip.text.clone()),
                        false,
                        now,
                        clip.device_id,
                    );
                }
                eprintln!("{}", log_line("paste_retained", "written to the clipboard"));
                notify::retained_pasted(clip.text.len());
            }
            true
        }
        ClientEvent::Dropped {
            reason,
            retained: true,
        } if asked() => {
            status.has_retained = false;
            notify::retained_nothing_new(reason);
            true
        }
        _ => false,
    }
}

/// The one place a received image reaches the clipboard.
///
/// A chunked image only ever arrives fully reassembled and verified, so there is no partial state
/// to handle here. There is also no retained variant: the relay does not store anything above its
/// retain cap, and an image is far above it.
fn apply_image(
    png: &[u8],
    ts_ms: u64,
    io: &dyn ClipboardIo,
    status: &mut Status,
    now_ms: u64,
) -> bool {
    match io.write_image(png) {
        Ok(()) => {
            status.last_sync_ms = Some(now_ms.max(ts_ms));
            true
        }
        Err(err) => {
            status.last_error = Some(err.to_string());
            eprintln!("{}", log_line("image_write_failed", &err.to_string()));
            false
        }
    }
}

/// The one place a received clip reaches the clipboard.
fn apply_clip(
    text: &str,
    retained: bool,
    ts_ms: u64,
    io: &dyn ClipboardIo,
    status: &mut Status,
    now_ms: u64,
) -> bool {
    if retained {
        // A stored clip is history, not news. Writing it on connect would overwrite something the
        // person may have copied here seconds ago, so it is offered rather than applied.
        status.has_retained = true;
        return false;
    }

    match io.write_text(text) {
        Ok(()) => {
            status.last_sync_ms = Some(now_ms.max(ts_ms));
            true
        }
        Err(err) => {
            status.last_error = Some(err.to_string());
            eprintln!("{}", log_line("clipboard_write_failed", &err.to_string()));
            false
        }
    }
}

/// Reserves a block of sequence numbers and returns the first one to use.
///
/// # Errors
///
/// Returns [`crate::Error::Io`] if the reservation could not be persisted, which must be fatal:
/// running without it risks reusing numbers.
pub fn reserve_sequence(paths: &Paths) -> Result<u64> {
    let state = paths.load_state()?;
    let base = state.seq;
    paths.save_state(State {
        seq: base.saturating_add(SEQ_RESERVATION),
    })?;
    Ok(base)
}

/// Raises the persisted reservation to at least `ceiling`, never lowering it.
///
/// Two places raise it: the clipboard bridge before a long lived connection runs through its
/// block, and the connection loop after each disconnect. They do not know about each other, so
/// neither may overwrite a higher value the other already wrote.
///
/// # Errors
///
/// Returns [`crate::Error::Io`] or [`crate::Error::Parse`] if the state cannot be read or written.
pub fn raise_reservation(paths: &Paths, ceiling: u64) -> Result<()> {
    if paths.load_state()?.seq < ceiling {
        paths.save_state(State { seq: ceiling })?;
    }
    Ok(())
}

/// Runs the daemon until the process is asked to stop.
///
/// # Errors
///
/// Returns an error only for conditions that cannot be retried, such as being unable to persist
/// the sequence counter. Connection failures are retried forever by design, because a tray app
/// that quietly gives up is the failure mode users report most.
pub async fn run(
    paths: &Paths,
    config: &Config,
    account: crate::secrets::Account,
    io: Arc<dyn ClipboardIo>,
    observed: Receiver<Observed>,
    controls: Controls,
    history: SharedHistory,
) -> Result<()> {
    let device_id = config.device_id_bytes()?;
    let seq = reserve_sequence(paths)?;
    let identity = account.identity;
    let room = identity.room_id();
    let room_bytes = identity.room_id_bytes();
    let keys = KeyContext {
        paths: paths.clone(),
        device_secret: Zeroizing::new(*account.device.secret()),
    };
    let mut session = Session::new(identity, device_id, seq);
    // This device's own keys: it signs its card with them, and a new account key is sealed to
    // them when another device removes someone.
    session.set_device_keys(account.device);
    // Who this device is, as the others will list it. Sent sealed after every handshake.
    session.set_device_info(DeviceInfo {
        name: crate::devices::display_name(&config.device_name),
        os: crate::devices::this_os(),
    });
    controls.devices.load(paths, &room);
    // The keys every device was pinned to in earlier runs, so a card naming another key for one of
    // them is refused from the first rather than after this run has seen the real one.
    session.restore_known(controls.devices.pinned());
    // The clipboard layer already recognises our own writes. See the method for why this matters.
    session.leave_echoes_to_caller();

    // What earlier runs accepted, so a relay cannot replay an old clip into the gap a restart
    // would otherwise open.
    let memory = crate::replay_store::load(paths, &room);
    session.restore_replay(&memory);
    let replay = ReplaySaver {
        paths: paths.clone(),
        room,
        sink: Arc::new(std::sync::Mutex::new(memory.clone())),
        saved: memory,
    };
    session.share_replay_memory(Arc::clone(&replay.sink));

    // The watcher thread is blocking, so it gets its own bridge into the async side.
    // Room for a window of file pieces beside the clipboard's own traffic.
    let (local_tx, mut local_rx) = mpsc::channel::<LocalEvent>(64);
    controls.outbox.attach(local_tx.clone());
    controls.transfers.attach(
        local_tx.clone(),
        &keys.device_secret,
        device_id,
        room_bytes,
        controls.devices.clone(),
    );
    controls.transfers.load_shelf(paths.dir.join("shelf.json"));
    controls
        .transfers
        .set_same_network_only(config.same_network_only);
    let rekey_watch = spawn_rekey_watch(paths, controls.clone());
    let pacer = {
        let transfers = controls.transfers.clone();
        tokio::spawn(async move {
            let mut every = tokio::time::interval(std::time::Duration::from_millis(50));
            loop {
                every.tick().await;
                transfers.tick();
            }
        })
    };
    // The bridge consumes its sender, and the retained pump needs one of its own.
    let local_tx_for_retained = local_tx.clone();
    spawn_clipboard_bridge(
        observed,
        local_tx,
        Bridge {
            cap: Arc::clone(&controls.settings.max_content_bytes),
            paused: Arc::clone(&controls.paused),
            history: Arc::clone(&history),
            paths: paths.clone(),
            seq_base: seq,
            own_id: device_id,
        },
    )?;

    let result = run_connection_loop(
        paths,
        config,
        session,
        controls,
        io,
        LocalChannel {
            rx: &mut local_rx,
            tx_for_retained: local_tx_for_retained,
        },
        Sinks {
            history,
            replay,
            keys,
        },
    )
    .await;
    rekey_watch.abort();
    pacer.abort();
    result
}

/// Where a key change asked for from the command line waits for the running daemon.
#[must_use]
pub fn rekey_request_path(paths: &Paths) -> std::path::PathBuf {
    paths.dir.join("rekey-request.json")
}

/// A key change asked for from the command line: the devices to remove, by id in hex. Empty means
/// replace the key and keep everyone.
#[derive(Debug, Default, serde::Serialize, serde::Deserialize)]
pub struct RekeyRequest {
    /// Devices to leave out of the new key.
    pub remove: Vec<String>,
}

/// Where a file transfer asked for from the command line waits for the running daemon.
#[must_use]
pub fn transfer_request_path(paths: &Paths) -> std::path::PathBuf {
    paths.dir.join("transfer-request.json")
}

/// Where the running daemon describes the transfers for `asli transfers`.
#[must_use]
pub fn transfer_status_path(paths: &Paths) -> std::path::PathBuf {
    paths.dir.join("transfers.json")
}

/// A file transfer asked for from the command line.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TransferRequest {
    /// Offer a file to a device, by id in hex.
    Send {
        /// The device.
        device: String,
        /// The file.
        path: std::path::PathBuf,
    },
    /// Accept an offered file into a folder.
    Accept {
        /// The offer, by id in hex.
        offer: String,
        /// Where to keep it.
        folder: std::path::PathBuf,
    },
    /// Turn an offered file down.
    Decline {
        /// The offer, by id in hex.
        offer: String,
    },
    /// Call a transfer off.
    Cancel {
        /// The offer, by id in hex.
        offer: String,
    },
    /// Put a file on this device's shelf.
    Shelve {
        /// The file.
        path: std::path::PathBuf,
    },
    /// Take an item off a shelf: this device's when `device` is absent.
    Unshelve {
        /// The device whose shelf it is on, by id in hex.
        device: Option<String>,
        /// The item, by id in hex.
        item: String,
    },
    /// Fetch an item from another device's shelf.
    Take {
        /// The device, by id in hex.
        device: String,
        /// The item, by id in hex.
        item: String,
    },
}

/// Where the running daemon describes the shelves for `asli shelf`.
#[must_use]
pub fn shelf_status_path(paths: &Paths) -> std::path::PathBuf {
    paths.dir.join("shelf-status.json")
}

/// One item as `asli shelf` prints it.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct ShelfStatus {
    /// The device it is on, in hex, or empty for this one.
    pub device_id: String,
    /// That device's name.
    pub device: String,
    /// The item, in hex.
    pub item: String,
    /// The file's name.
    pub name: String,
    /// Its size in bytes.
    pub size: u64,
    /// When it comes off the shelf, in milliseconds since the epoch.
    pub expires_ms: u64,
}

/// One transfer as `asli transfers` prints it.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct TransferStatus {
    /// Its offer id in hex.
    pub id: String,
    /// `sending` or `receiving`.
    pub direction: String,
    /// The other device.
    pub peer: String,
    /// The file's name.
    pub name: String,
    /// Its size in bytes.
    pub size: u64,
    /// Where it stands, in words.
    pub stage: String,
}

fn act_on_transfer_request(request: TransferRequest, controls: &Controls) {
    let offer = |hex: &str| crate::devices::id_bytes(hex);
    let outcome = match request {
        TransferRequest::Send { device, path } => match crate::devices::id_bytes(&device) {
            Some(to) => controls.transfers.send(&path, to),
            None => Err("no such device".to_owned()),
        },
        TransferRequest::Accept { offer: id, folder } => match offer(&id) {
            Some(id) => controls.transfers.accept(&id, &folder),
            None => Err("no such offer".to_owned()),
        },
        TransferRequest::Decline { offer: id } => {
            if let Some(id) = offer(&id) {
                controls.transfers.decline(&id);
            }
            Ok(())
        }
        TransferRequest::Cancel { offer: id } => {
            if let Some(id) = offer(&id) {
                controls.transfers.cancel(&id);
            }
            Ok(())
        }
        TransferRequest::Shelve { path } => controls.transfers.shelve(&path),
        TransferRequest::Unshelve { device, item } => {
            match (device.as_deref().map(offer), offer(&item)) {
                (None, Some(item)) => {
                    controls.transfers.unshelve(&item);
                    Ok(())
                }
                (Some(Some(device)), Some(item)) => controls.transfers.take_off(device, item),
                _ => Err("no such item".to_owned()),
            }
        }
        TransferRequest::Take { device, item } => match (offer(&device), offer(&item)) {
            (Some(device), Some(item)) => controls.transfers.take(device, item),
            _ => Err("no such item".to_owned()),
        },
    };
    if let Err(why) = outcome {
        eprintln!("{}", log_line("transfer_request_refused", &why));
    }
}

/// Writes the transfers for `asli transfers` to read.
fn write_transfer_status(paths: &Paths, controls: &Controls) {
    let list: Vec<TransferStatus> = controls
        .transfers
        .list()
        .into_iter()
        .map(|t| TransferStatus {
            id: crate::config::hex(&t.id),
            direction: match t.direction {
                crate::transfer::Direction::Sending => "sending",
                crate::transfer::Direction::Receiving => "receiving",
            }
            .to_owned(),
            peer: t.peer,
            name: t.name,
            size: t.size,
            stage: crate::transfer::describe(&t.stage, t.chunks),
        })
        .collect();
    if let Ok(bytes) = serde_json::to_vec_pretty(&list) {
        let _ = crate::config::write_atomically(&transfer_status_path(paths), &bytes, 0o600);
    }
    let (mine, theirs) = controls.transfers.shelf();
    let shelf: Vec<ShelfStatus> = mine
        .into_iter()
        .chain(theirs)
        .map(|item| ShelfStatus {
            device_id: item
                .device_id
                .map(|id| crate::config::hex(&id))
                .unwrap_or_default(),
            device: item.device,
            item: crate::config::hex(&item.item_id),
            name: item.name,
            size: item.size,
            expires_ms: item.expires_ms,
        })
        .collect();
    if let Ok(bytes) = serde_json::to_vec_pretty(&shelf) {
        let _ = crate::config::write_atomically(&shelf_status_path(paths), &bytes, 0o600);
    }
}

/// Picks up a key change or a file transfer asked for from the command line and carries it out,
/// exactly as the window's buttons do, and keeps the transfer list on disk for the command line.
fn spawn_rekey_watch(paths: &Paths, controls: Controls) -> tokio::task::JoinHandle<()> {
    let path = rekey_request_path(paths);
    let transfer_path = transfer_request_path(paths);
    let paths = paths.clone();
    // Ones left over from before this run are stale: nobody is waiting on them any more.
    let _ = std::fs::remove_file(&path);
    let _ = std::fs::remove_file(&transfer_path);
    tokio::spawn(async move {
        let mut shown = u64::MAX;
        loop {
            tokio::time::sleep(std::time::Duration::from_millis(500)).await;
            if let Ok(bytes) = std::fs::read(&transfer_path) {
                let _ = std::fs::remove_file(&transfer_path);
                match serde_json::from_slice::<TransferRequest>(&bytes) {
                    Ok(request) => act_on_transfer_request(request, &controls),
                    Err(_) => eprintln!("{}", log_line("transfer_request_invalid", "ignored")),
                }
            }
            let revision = controls.transfers.revision();
            if revision != shown {
                shown = revision;
                write_transfer_status(&paths, &controls);
            }
            let Ok(bytes) = std::fs::read(&path) else {
                continue;
            };
            let _ = std::fs::remove_file(&path);
            let Ok(request) = serde_json::from_slice::<RekeyRequest>(&bytes) else {
                eprintln!("{}", log_line("rekey_request_invalid", "ignored"));
                continue;
            };
            let removing: Vec<[u8; 16]> = request
                .remove
                .iter()
                .filter_map(|id| crate::devices::id_bytes(id))
                .collect();
            let keep = controls.devices.keyed_except(&removing);
            match controls.outbox.replace_key(keep, removing) {
                Ok(()) => eprintln!("{}", log_line("rekey_requested", "from the command line")),
                Err(note) => eprintln!("{}", log_line("rekey_refused", &note)),
            }
        }
    })
}

/// What the daemon needs to move this device to a new account key.
struct KeyContext {
    paths: Paths,
    /// This device's own key, stored again beside the new account key.
    device_secret: Zeroizing<[u8; 32]>,
}

/// Acts on what concerns the account itself rather than the clipboard: a new account key, from
/// this device or another, and being removed.
fn on_account_event(
    event: &ClientEvent,
    keys: &KeyContext,
    controls: &Controls,
    history: &SharedHistory,
) {
    match event {
        ClientEvent::Connected { conn_id } => {
            controls.outbox.resend_pending();
            controls.transfers.connected(conn_id);
        }
        ClientEvent::Message { kind, body } => {
            if let Some((from, name, bytes)) = controls.transfers.on_message(*kind, body) {
                notify::file_offered(&from, &name, bytes);
                crate::window::open_from_any_thread(crate::window::Screen::Status);
            }
        }
        ClientEvent::RelayError {
            code: asli_net::envelope::ErrorCode::QuotaExceeded,
            ..
        } => controls.transfers.over_quota(),
        ClientEvent::Sent { token } => {
            if let Some(pending) = controls.outbox.take_rekey(*token) {
                move_to_new_key(
                    keys,
                    &pending.secret,
                    controls,
                    history,
                    &pending.removing,
                    crate::window::Welcome::Rekeyed,
                );
            }
        }
        ClientEvent::NotSent {
            token: Some(token),
            reason,
        } => controls.outbox.fail_rekey(*token, reason),
        ClientEvent::Rekeyed { secret, by, kept } => {
            let who = controls
                .devices
                .name_of(by)
                .unwrap_or_else(|| "another device".to_owned());
            eprintln!("{}", log_line("key_replaced_by", &who));
            // Whoever the new key did not go to was left out of the account, apart from the
            // device that made it.
            let left_out: Vec<[u8; 16]> = controls
                .devices
                .keyed_except(kept)
                .into_iter()
                .filter(|device| device != by)
                .collect();
            move_to_new_key(
                keys,
                &secret.0,
                controls,
                history,
                &left_out,
                crate::window::Welcome::KeyChangedElsewhere,
            );
        }
        ClientEvent::RemovedBy { by } => {
            let who = controls
                .devices
                .name_of(by)
                .unwrap_or_else(|| "another device".to_owned());
            eprintln!("{}", log_line("removed_by", &who));
            if let Err(err) = crate::secrets::wipe(&keys.paths) {
                eprintln!("{}", log_line("wipe_failed", &err.to_string()));
            }
            controls.devices.clear();
            notify::action_failed(
                "This device was removed from your Asli account",
                &format!("{who} removed it. Join again with a code if that was a mistake."),
            );
            crate::window::restart_for(crate::window::Welcome::Removed);
        }
        _ => {}
    }
}

/// Stores a new account key beside this device's own key, carries the device list and the
/// history over to it, and restarts onto it.
fn move_to_new_key(
    keys: &KeyContext,
    new_secret: &[u8; 32],
    controls: &Controls,
    history: &SharedHistory,
    forget: &[[u8; 16]],
    welcome: crate::window::Welcome,
) {
    if let Err(err) = crate::secrets::store(&keys.paths, new_secret, &keys.device_secret) {
        eprintln!("{}", log_line("key_store_failed", &err.to_string()));
        notify::action_failed("Asli could not save the new account key", &err.to_string());
        return;
    }
    // A key made by a device and handed over sealed has never been in an old style token.
    if let Ok(mut config) = keys.paths.load_config() {
        config.key_never_exported = true;
        if let Err(err) = keys.paths.save_config(&config) {
            eprintln!("{}", log_line("config_save_failed", &err.to_string()));
        }
    }
    for device in forget {
        controls.devices.forget(device);
    }
    let room = Identity::from_secret(new_secret).room_id();
    controls.devices.move_to_room(&room);
    if let Ok(mut history) = history.lock() {
        history.rekey(new_secret);
    }
    eprintln!("{}", log_line("key_replaced", &format!("room {room}")));
    crate::window::restart_for(welcome);
}

/// Saves the replay memory whenever the session has learned something new.
struct ReplaySaver {
    paths: Paths,
    room: String,
    /// Where the session publishes what it has accepted.
    sink: Arc<std::sync::Mutex<asli_core::ReplayMemory>>,
    /// What is on disk, so an unchanged memory is not written again.
    saved: asli_core::ReplayMemory,
}

impl ReplaySaver {
    fn save_if_changed(&mut self) {
        let Ok(current) = self.sink.lock().map(|memory| memory.clone()) else {
            return;
        };
        if current == self.saved {
            return;
        }
        match crate::replay_store::save(&self.paths, &self.room, &current) {
            Ok(()) => self.saved = current,
            Err(err) => eprintln!("{}", log_line("replay_save_failed", &err.to_string())),
        }
    }
}

/// What the clipboard bridge needs besides its two channels.
struct Bridge {
    /// Largest copy this device sends, in bytes.
    /// Read on every copy, so a change in Settings applies to the next one.
    cap: Arc<AtomicUsize>,
    /// Set while sync is paused.
    paused: Arc<AtomicBool>,
    /// Where this device's own copies are recorded.
    history: SharedHistory,
    /// Where the sequence reservation lives.
    paths: Paths,
    /// The first sequence number this process was given.
    seq_base: u64,
    /// This device's id, recorded as the source of its own copies.
    own_id: [u8; 16],
}

/// Counts sequence numbers this process may have used, and says when to reserve more.
///
/// An upper bound, not an exact count: a copy the session then drops as an echo or as too large
/// uses no number but is counted anyway, which only means reserving a little early.
#[derive(Debug, Clone, Copy)]
struct SequenceWatch {
    /// Highest number that may have been used.
    issued: u64,
    /// Highest number reserved on disk.
    ceiling: u64,
}

impl SequenceWatch {
    /// Reserve again when fewer than this many numbers are left in the block.
    const MARGIN: u64 = SEQ_RESERVATION / 10;

    const fn new(base: u64) -> Self {
        Self {
            issued: base,
            ceiling: base.saturating_add(SEQ_RESERVATION),
        }
    }

    /// Accounts for one more copy. Returns the new ceiling to persist when one is due.
    fn issue(&mut self) -> Option<u64> {
        self.issued = self.issued.saturating_add(1);
        if self.issued.saturating_add(Self::MARGIN) >= self.ceiling {
            self.ceiling = self.ceiling.saturating_add(SEQ_RESERVATION);
            Some(self.ceiling)
        } else {
            None
        }
    }
}

/// Bridges the blocking watcher thread into the async side, dropping what must not be sent.
///
/// # Errors
///
/// Returns [`crate::Error::Io`] if the thread could not be spawned.
fn spawn_clipboard_bridge(
    observed: Receiver<Observed>,
    local_tx: mpsc::Sender<LocalEvent>,
    bridge: Bridge,
) -> Result<()> {
    let Bridge {
        cap,
        paused,
        history,
        paths,
        seq_base,
        own_id,
    } = bridge;

    std::thread::Builder::new()
        .name("asli-clip-bridge".to_owned())
        .spawn(move || {
            let mut sequence = SequenceWatch::new(seq_base);
            while let Ok(event) = observed.recv() {
                // Every copy handed on may use one sequence number, so the reservation on disk
                // is raised before this process could run past it. Otherwise a connection that
                // stays up for more than a block of copies, then ends without a clean disconnect,
                // restarts below numbers it already used, and every peer drops its clips as
                // replays until it catches up.
                if matches!(event, Observed::Text(_) | Observed::Image(_)) {
                    if let Some(ceiling) = sequence.issue() {
                        if let Err(err) = raise_reservation(&paths, ceiling) {
                            eprintln!("{}", log_line("reservation_failed", &err.to_string()));
                        }
                    }
                }

                // Pause stops copies leaving this machine at the earliest point they can be
                // stopped, before they are sealed rather than after.
                if paused.load(Ordering::Relaxed) {
                    continue;
                }
                match event {
                    Observed::Text(text) => {
                        let cap = cap.load(Ordering::Relaxed);
                        if text.len() > cap {
                            eprintln!(
                                "{}",
                                log_line(
                                    "clip_skipped_too_large",
                                    &format!(
                                        "{} bytes exceeds the local cap of {cap} bytes",
                                        text.len()
                                    ),
                                )
                            );
                            notify::clip_too_large(text.len(), cap);
                            continue;
                        }
                        let bytes = text.len();
                        // Recorded before it is sent, because the send consumes it. What this
                        // device copies belongs in its own history just as much as what arrives.
                        if let Ok(mut history) = history.lock() {
                            history.record(
                                HistoryContent::Text(text.clone()),
                                false,
                                client::now_ms(),
                                own_id,
                            );
                        }
                        if local_tx.blocking_send(LocalEvent::Text(text)).is_err() {
                            return;
                        }
                        // Queued, not sent: the session still drops an echo of our own write
                        // and anything over the relay's limit, and a log line claiming a send
                        // that never happened is how a false diagnosis starts.
                        eprintln!("{}", log_line("clip_queued", &format!("{bytes} bytes")));
                    }
                    Observed::Image(png) => {
                        let cap = cap.load(Ordering::Relaxed);
                        if png.len() > cap {
                            eprintln!(
                                "{}",
                                log_line(
                                    "image_skipped_too_large",
                                    &format!(
                                        "{} bytes exceeds the local cap of {cap} bytes",
                                        png.len()
                                    ),
                                )
                            );
                            notify::clip_too_large(png.len(), cap);
                            continue;
                        }
                        let bytes = png.len();
                        if let Ok(mut history) = history.lock() {
                            history.record(
                                HistoryContent::ImagePng(png.clone()),
                                false,
                                client::now_ms(),
                                own_id,
                            );
                        }
                        if local_tx.blocking_send(LocalEvent::Image(png)).is_err() {
                            return;
                        }
                        eprintln!("{}", log_line("image_queued", &format!("{bytes} bytes")));
                    }
                    Observed::Sensitive => {
                        // Never recorded, and there is nothing to record: the watcher does not
                        // hand over the content of a clip the source marked as a password.
                        eprintln!(
                            "{}",
                            log_line(
                                "clip_skipped_sensitive",
                                "the source marked it as a password"
                            )
                        );
                        // Always notified. Being told once is how a person learns this is
                        // deliberate rather than a bug.
                        notify::clip_sensitive();
                    }
                }
            }
        })
        .map_err(crate::Error::Io)?;

    Ok(())
}

/// Both ends of the channel carrying what this device originates.
///
/// They travel together because they are the same channel: the receiver is what the connection
/// pumps, and the sender is how the tray's retained request joins the same queue as a copy.
struct LocalChannel<'a> {
    /// Local events on their way to the socket.
    rx: &'a mut mpsc::Receiver<LocalEvent>,
    /// Used by the retained pump, which raises a request while a connection is live.
    tx_for_retained: mpsc::Sender<LocalEvent>,
}

/// Where the connection loop reports, beyond the clipboard itself.
///
/// The two travel together because they are the same decision made twice: what happens to a clip
/// once it has arrived, beyond being pasted. One tells the person, the other remembers it.
struct Sinks {
    /// Where arriving clips are recorded so they can be put back later.
    history: SharedHistory,
    /// Where what has been accepted is saved, so replay protection survives a restart.
    replay: ReplaySaver,
    /// What moving to a new account key needs.
    keys: KeyContext,
}

/// Watches for a retained fetch raised by the tray and puts it on the local queue.
///
/// A separate task because the tray raises the request from another thread at an arbitrary moment,
/// while the connection loop is parked in `select!`. Polling a flag is enough: this fires at most
/// once per menu click, so the quarter second granularity is invisible.
fn spawn_retained_pump(
    tx: mpsc::Sender<LocalEvent>,
    wanted: Arc<AtomicBool>,
    announce: Arc<AtomicBool>,
    paths: Paths,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(std::time::Duration::from_millis(250)).await;
            if wanted.swap(false, Ordering::Relaxed)
                && tx.send(LocalEvent::FetchRetained).await.is_err()
            {
                return;
            }
            // A new name from Settings, told to the other devices straight away rather than at
            // the next reconnect.
            if announce.swap(false, Ordering::Relaxed) {
                let name = paths
                    .load_config()
                    .map(|config| config.device_name)
                    .unwrap_or_default();
                let info = DeviceInfo {
                    name: crate::devices::display_name(&name),
                    os: crate::devices::this_os(),
                };
                if tx.send(LocalEvent::DeviceInfo(info)).await.is_err() {
                    return;
                }
            }
        }
    })
}

/// Records why syncing stopped for good, where the tray and the window will show it, and says so.
///
/// Before this the reason was set on a local and the daemon returned, the application quit, and a
/// person saw the icon simply vanish, with the reason nowhere at all.
fn stop_with(controls: &Controls, status: &mut Status, reason: &str) {
    reason.clone_into(&mut status.state);
    status.peers = 0;
    controls.status.set(status.clone());
    notify::action_failed("Asli stopped syncing", reason);
}

/// Decides what a finished connection means. Returns true when syncing has stopped for good.
///
/// Permanent refusals stop, because retrying a bad signature or an unsupported version every few
/// seconds against a public relay is a self inflicted denial of service. Everything else is
/// retried.
fn judge_outcome(
    outcome: asli_net::Result<Disconnect>,
    backoff: &mut Backoff,
    controls: &Controls,
    status: &mut Status,
) -> bool {
    match outcome {
        Ok(Disconnect::LocalChannelClosed) => {
            eprintln!("{}", log_line("stopping", "the clipboard watcher ended"));
            stop_with(controls, status, "Stopped: the clipboard watcher ended");
            return true;
        }
        Ok(Disconnect::AuthFailed(code)) if code.is_permanent() => {
            eprintln!("{}", log_line("auth_failed", code.as_str()));
            stop_with(controls, status, &format!("Rejected: {}", code.as_str()));
            return true;
        }
        Ok(Disconnect::Close(code)) => {
            backoff.on_close(code);
            if let Some(fatal) = asli_net::Fatal::from_close_code(code) {
                eprintln!("{}", log_line("fatal_close", fatal.user_message()));
                stop_with(controls, status, fatal.user_message());
                return true;
            }
            "Offline, retrying".clone_into(&mut status.state);
        }
        Ok(other) => {
            "Offline, retrying".clone_into(&mut status.state);
            eprintln!("{}", log_line("disconnected", &format!("{other:?}")));
        }
        Err(err) => {
            "Offline, retrying".clone_into(&mut status.state);
            eprintln!("{}", log_line("connection_failed", &err.to_string()));
        }
    }
    false
}

/// Connects, pumps, and reconnects forever.
///
/// Split from [`run`] so each half stays readable: this one owns the retry policy, the other owns
/// setup.
async fn run_connection_loop(
    paths: &Paths,
    config: &Config,
    mut session: Session,
    controls: Controls,
    io: Arc<dyn ClipboardIo>,
    local: LocalChannel<'_>,
    sinks: Sinks,
) -> Result<()> {
    let LocalChannel {
        rx: local_rx,
        tx_for_retained: local_tx_for_retained,
    } = local;
    let Sinks {
        history,
        mut replay,
        keys,
    } = sinks;
    let mut backoff = Backoff::new();
    let mut status = Status {
        state: "Connecting".to_owned(),
        ..Status::default()
    };
    // Shared rather than a local, because the event sink is a closure the borrow checker will not
    // let write to a local this loop also reads.
    let connected_once = Arc::new(AtomicBool::new(false));

    loop {
        // Read afresh on every attempt, so a relay changed in Settings is the one connected to.
        let url = paths
            .load_config()
            .map_or_else(|_| config.relay_url.clone(), |live| live.relay_url);
        "Connecting".clone_into(&mut status.state);
        status.attempt = status.attempt.saturating_add(1);
        status.retry_at_ms = None;
        eprintln!(
            "{}",
            log_line(
                if connected_once.load(Ordering::Relaxed) {
                    "reconnecting"
                } else {
                    "connecting"
                },
                &url
            )
        );

        controls.status.set(status.clone());

        // A request raised by the tray while the previous connection was down cannot be carried
        // over: the relay tells us on each handshake whether it still holds anything, so a stale
        // request would ask for something that may no longer exist.
        controls.retained_pending.store(false, Ordering::Relaxed);
        if controls.take_retained_request() {
            eprintln!(
                "{}",
                log_line(
                    "paste_retained",
                    "dropped because the connection restarted before it could be sent"
                )
            );
        }

        // A request raised while this connection is live is carried by the socket itself.
        let retained_pump = spawn_retained_pump(
            local_tx_for_retained.clone(),
            Arc::clone(&controls.retained_wanted),
            Arc::clone(&controls.settings.announce),
            paths.clone(),
        );

        let reconnect = Arc::clone(&controls.settings.reconnect);
        reconnect.store(false, Ordering::Relaxed);
        // When this connection authenticated, so its stability can reset the pacing afterwards.
        let authenticated_at = std::cell::Cell::new(None);
        let mut on_event = |event: ClientEvent| {
            if matches!(event, ClientEvent::Authenticated { .. }) {
                authenticated_at.set(Some(client::now_ms()));
                status.attempt = 0;
            }
            on_account_event(&event, &keys, &controls, &history);
            on_live_event(
                &event,
                io.as_ref(),
                &controls,
                &mut status,
                &connected_once,
                &history,
            );
            // Saved as soon as a clip is accepted, not at disconnect: a crash must not open the
            // window this exists to close.
            replay.save_if_changed();
        };
        let connection = client::run_once(&url, &mut session, local_rx, &mut on_event);
        // A relay changed in Settings ends this connection now rather than whenever it next
        // drops, which could be days.
        let outcome = tokio::select! {
            outcome = connection => outcome,
            () = wait_for(&reconnect) => {
                eprintln!("{}", log_line("reconnecting", "the relay address changed"));
                Ok(Disconnect::Eof)
            }
        };

        retained_pump.abort();
        controls.devices.set_connected(false, 0, client::now_ms());
        controls.transfers.disconnected();

        // A connection that authenticated and then stayed up resets the pacing, including a floor
        // a rate limit or quota close imposed. Nothing did before, so after a handful of drops
        // every reconnect for the rest of the process waited the full thirty seconds, and after
        // a single quota close, an hour, sleep and wake included.
        if let Some(at) = authenticated_at.get() {
            backoff.on_authenticated(at);
            if backoff.note_stable(client::now_ms()) {
                eprintln!(
                    "{}",
                    log_line("backoff_reset", "the last connection was stable")
                );
            }
        }

        // Whatever happened, the counter this connection reached must survive it.
        let _ = raise_reservation(paths, session.seq().saturating_add(SEQ_RESERVATION));

        if judge_outcome(outcome, &mut backoff, &controls, &mut status) {
            return Ok(());
        }

        wait_to_retry(&mut backoff, &controls, &mut status, &reconnect).await?;
    }
}

/// Waits out the pause before the next attempt, publishing when it ends.
///
/// # Errors
///
/// Returns the backoff's error if it has given up, which it only does for a pacing it cannot
/// represent.
async fn wait_to_retry(
    backoff: &mut Backoff,
    controls: &Controls,
    status: &mut Status,
    reconnect: &AtomicBool,
) -> Result<()> {
    let delay = backoff.next_delay()?;
    status.retry_at_ms = Some(client::now_ms().saturating_add(delay));
    controls.status.set(status.clone());

    // The reason and the delay together, because "it worked for a week then stopped" is the
    // defining complaint in this category and a log that omits why is no help at all.
    eprintln!(
        "{}",
        log_line(
            "disconnected",
            &format!("{}, retrying in {delay} ms", status.state)
        )
    );
    // Asked for, so at once. The backoff is for failures, and this is not one. Retry now in the
    // window sets the same flag, and cuts a wait already under way short.
    if !reconnect.swap(false, Ordering::Relaxed) {
        tokio::select! {
            () = tokio::time::sleep(std::time::Duration::from_millis(delay)) => {}
            () = wait_for(reconnect) => {
                eprintln!("{}", log_line("retrying", "asked to retry now"));
            }
        }
        reconnect.store(false, Ordering::Relaxed);
    }
    Ok(())
}

/// Resolves once `flag` is set. A quarter second of polling is invisible for a settings change.
async fn wait_for(flag: &AtomicBool) {
    while !flag.load(Ordering::Relaxed) {
        tokio::time::sleep(std::time::Duration::from_millis(250)).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::clipboard_io::StubClipboard;

    fn retained_clip(text: &str) -> ClientEvent {
        ClientEvent::Clip(client::ReceivedClip {
            device_id: [9; 16],
            text: text.to_owned(),
            ts_ms: 1_000,
            retained: true,
        })
    }

    fn memory_history() -> SharedHistory {
        Arc::new(std::sync::Mutex::new(crate::window::MemoryHistory::new(
            true, 10,
        )))
    }

    #[test]
    fn a_stored_clip_that_was_asked_for_is_written() {
        let stub = StubClipboard::default();
        let controls = Controls::default();
        let mut status = Status {
            has_retained: true,
            ..Status::default()
        };
        controls.request_retained();

        let handled = answer_retained_request(
            &retained_clip("from the relay"),
            &stub,
            &controls,
            &mut status,
            &memory_history(),
            2_000,
        );
        assert!(handled);
        assert_eq!(stub.writes(), vec!["from the relay".to_owned()]);
        assert!(
            !status.has_retained,
            "the button goes once the clip is here"
        );
    }

    #[test]
    fn a_stored_clip_that_was_not_asked_for_is_left_to_the_offer() {
        let stub = StubClipboard::default();
        let controls = Controls::default();
        let mut status = Status::default();

        let handled = answer_retained_request(
            &retained_clip("from the relay"),
            &stub,
            &controls,
            &mut status,
            &memory_history(),
            2_000,
        );
        assert!(!handled);
        assert!(stub.writes().is_empty());
    }

    #[test]
    fn asking_for_our_own_stored_clip_ends_the_request_instead_of_leaving_it_open() {
        let stub = StubClipboard::default();
        let controls = Controls::default();
        let mut status = Status {
            has_retained: true,
            ..Status::default()
        };
        controls.request_retained();

        let handled = answer_retained_request(
            &ClientEvent::Dropped {
                reason: "own_device",
                retained: true,
            },
            &stub,
            &controls,
            &mut status,
            &memory_history(),
            2_000,
        );
        assert!(handled);
        assert!(!status.has_retained);
        assert!(!controls.retained_pending.load(Ordering::Relaxed));
    }

    #[test]
    fn the_reservation_is_raised_before_a_long_connection_runs_past_it() {
        let mut watch = SequenceWatch::new(5_000);
        let mut raised = Vec::new();
        for _ in 0..(3 * SEQ_RESERVATION) {
            if let Some(ceiling) = watch.issue() {
                raised.push(ceiling);
            }
            assert!(
                watch.issued < watch.ceiling,
                "a number was used that is not reserved on disk"
            );
        }
        assert_eq!(raised, vec![7_000, 8_000, 9_000]);
    }

    #[test]
    fn raising_the_reservation_never_lowers_it() {
        let dir = std::env::temp_dir().join(format!("asli-reserve-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("scratch dir");
        let paths = Paths { dir: dir.clone() };

        raise_reservation(&paths, 9_000).expect("raises");
        raise_reservation(&paths, 4_000).expect("does not lower");
        assert_eq!(paths.load_state().expect("reads").seq, 9_000);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn a_live_clip_is_written_once() {
        let stub = StubClipboard::default();
        let mut status = Status::default();
        let action = Action::Clip {
            device_id: [9; 16],
            text: "from the laptop".to_owned(),
            ts_ms: 1_000,
            retained: false,
        };
        assert!(on_action(&action, &stub, &mut status, 2_000));
        assert_eq!(stub.writes(), vec!["from the laptop".to_owned()]);
        assert!(status.last_sync_ms.is_some());
    }

    #[test]
    fn a_retained_clip_is_offered_not_applied() {
        let stub = StubClipboard::default();
        let mut status = Status::default();
        let action = Action::Clip {
            device_id: [9; 16],
            text: "yesterday's copy".to_owned(),
            ts_ms: 1,
            retained: true,
        };
        assert!(!on_action(&action, &stub, &mut status, 2_000));
        assert!(
            stub.writes().is_empty(),
            "a stored clip must not clobber the local clipboard"
        );
        assert!(status.has_retained);
    }

    #[test]
    fn a_received_image_reaches_the_clipboard() {
        let stub = StubClipboard::default();
        let mut status = Status::default();
        let png = vec![0x89, b'P', b'N', b'G', 1, 2, 3];
        let action = Action::Image {
            device_id: [9; 16],
            png: png.clone(),
            ts_ms: 1_000,
        };
        assert!(on_action(&action, &stub, &mut status, 2_000));
        assert_eq!(stub.images(), vec![png]);
        assert!(
            stub.writes().is_empty(),
            "an image must not be written through the text path"
        );
        assert!(status.last_sync_ms.is_some());
    }

    #[test]
    fn a_failed_image_write_is_recorded_rather_than_swallowed() {
        struct Failing;
        impl ClipboardIo for Failing {
            fn write_text(&self, _text: &str) -> Result<()> {
                Ok(())
            }
            fn write_image(&self, _png: &[u8]) -> Result<()> {
                Err(crate::Error::SecretStore("no image support".to_owned()))
            }
            fn describe(&self) -> String {
                "failing".to_owned()
            }
        }

        let mut status = Status::default();
        let action = Action::Image {
            device_id: [9; 16],
            png: vec![1, 2, 3],
            ts_ms: 0,
        };
        assert!(!on_action(&action, &Failing, &mut status, 0));
        assert!(status.last_error.is_some());
    }

    #[test]
    fn a_retained_request_is_taken_exactly_once() {
        let controls = Controls::default();
        assert!(
            !controls.take_retained_request(),
            "nothing is pending until it is asked for"
        );

        controls.request_retained();
        // Asking twice before the daemon looks must still fetch once, which is the whole reason
        // this is a flag rather than a queue.
        controls.request_retained();

        assert!(controls.take_retained_request());
        assert!(
            !controls.take_retained_request(),
            "taking it must clear it, or the daemon would refetch on every pass"
        );
    }

    #[test]
    fn presence_updates_the_status_line() {
        let stub = StubClipboard::default();
        let mut status = Status {
            state: "Synced".to_owned(),
            ..Status::default()
        };
        on_action(&Action::Presence { peers: 3 }, &stub, &mut status, 0);
        assert_eq!(status.line(), "Synced, 3 connected");
    }

    #[test]
    fn the_status_line_omits_a_zero_count() {
        let status = Status {
            state: "Offline, retrying".to_owned(),
            ..Status::default()
        };
        assert_eq!(status.line(), "Offline, retrying");
    }

    #[test]
    fn a_failed_write_is_recorded_rather_than_swallowed() {
        struct Failing;
        impl ClipboardIo for Failing {
            fn write_text(&self, _text: &str) -> Result<()> {
                Err(crate::Error::SecretStore("no clipboard".to_owned()))
            }
            fn describe(&self) -> String {
                "failing".to_owned()
            }
        }

        let mut status = Status::default();
        let action = Action::Clip {
            device_id: [9; 16],
            text: "x".to_owned(),
            ts_ms: 0,
            retained: false,
        };
        assert!(!on_action(&action, &Failing, &mut status, 0));
        assert!(status.last_error.is_some());
    }
}
