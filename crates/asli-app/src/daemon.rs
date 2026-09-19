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

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::Receiver;
use std::sync::Arc;

use asli_crypto::Identity;
use asli_net::client::{self, ClientEvent, Disconnect};
use asli_net::session::Action;
use asli_net::{Backoff, LocalEvent, Session};
use tokio::sync::mpsc;

use crate::clipboard_io::{log_line, ClipboardIo, Observed};
use crate::config::{Config, Paths, State};
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
}

impl Controls {
    /// Whether sync is currently paused.
    #[must_use]
    pub fn is_paused(&self) -> bool {
        self.paused.load(Ordering::Relaxed)
    }

    /// Asks the daemon to fetch the relay's stored clip on its next pass.
    pub fn request_retained(&self) {
        self.retained_wanted.store(true, Ordering::Relaxed);
    }

    /// Takes the pending request, if there is one, clearing it.
    #[must_use]
    pub fn take_retained_request(&self) -> bool {
        self.retained_wanted.swap(false, Ordering::Relaxed)
    }
}

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
        } => apply_clip(text, *retained, *ts_ms, io, status, now_ms),
        Action::Image { png, ts_ms } => apply_image(png, *ts_ms, io, status, now_ms),
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
            apply_clip(&clip.text, clip.retained, clip.ts_ms, io, status, now_ms)
        }
        ClientEvent::Image { png, ts_ms } => apply_image(png, *ts_ms, io, status, now_ms),
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
                "this computer's clock is {} s off, so clips are being dropped",
                skew_ms.unsigned_abs() / 1000
            ));
            notify::clock_skew(*skew_ms);
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
        ClientEvent::Dropped { reason } => {
            eprintln!("{}", log_line("clip_dropped", reason));
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
    let content = match event {
        ClientEvent::Clip(clip) if !clip.retained => HistoryContent::Text(clip.text.clone()),
        ClientEvent::Image { png, .. } => HistoryContent::ImagePng(png.clone()),
        _ => return,
    };

    if let Ok(mut history) = history.lock() {
        history.record(content, false, now_ms);
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
    notifications: bool,
    history: &SharedHistory,
) {
    let now = client::now_ms();

    // Pausing must also stop arriving content from overwriting the local clipboard. Dropping it
    // here rather than disconnecting keeps resume instant. Images are paused too: an image that
    // landed while paused would be just as unwelcome as text.
    if controls.is_paused() && matches!(event, ClientEvent::Clip(_) | ClientEvent::Image { .. }) {
        return;
    }

    log_event(event);
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
    identity: Identity,
    io: Arc<dyn ClipboardIo>,
    observed: Receiver<Observed>,
    controls: Controls,
    history: SharedHistory,
) -> Result<()> {
    let device_id = config.device_id_bytes()?;
    let seq = reserve_sequence(paths)?;
    let session = Session::new(identity, device_id, seq);

    // The watcher thread is blocking, so it gets its own bridge into the async side.
    let (local_tx, mut local_rx) = mpsc::channel::<LocalEvent>(16);
    let notifications = config.notifications;
    // The bridge consumes its sender, and the retained pump needs one of its own.
    let local_tx_for_retained = local_tx.clone();
    spawn_clipboard_bridge(
        observed,
        local_tx,
        Bridge {
            cap: config.max_content_bytes,
            paused: Arc::clone(&controls.paused),
            history: Arc::clone(&history),
            paths: paths.clone(),
            seq_base: seq,
        },
    )?;

    run_connection_loop(
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
            notifications,
            history,
        },
    )
    .await
}

/// What the clipboard bridge needs besides its two channels.
struct Bridge {
    /// Largest copy this device sends, in bytes.
    cap: usize,
    /// Set while sync is paused.
    paused: Arc<AtomicBool>,
    /// Where this device's own copies are recorded.
    history: SharedHistory,
    /// Where the sequence reservation lives.
    paths: Paths,
    /// The first sequence number this process was given.
    seq_base: u64,
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
    /// Whether an arriving clip raises a notification.
    notifications: bool,
    /// Where arriving clips are recorded so they can be put back later.
    history: SharedHistory,
}

/// Watches for a retained fetch raised by the tray and puts it on the local queue.
///
/// A separate task because the tray raises the request from another thread at an arbitrary moment,
/// while the connection loop is parked in `select!`. Polling a flag is enough: this fires at most
/// once per menu click, so the quarter second granularity is invisible.
fn spawn_retained_pump(
    tx: mpsc::Sender<LocalEvent>,
    wanted: Arc<AtomicBool>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(std::time::Duration::from_millis(250)).await;
            if wanted.swap(false, Ordering::Relaxed)
                && tx.send(LocalEvent::FetchRetained).await.is_err()
            {
                return;
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
        notifications,
        history,
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
        let url = config.relay_url.clone();
        "Connecting".clone_into(&mut status.state);
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
        );

        let outcome = client::run_once(&url, &mut session, local_rx, &mut |event| {
            on_live_event(
                &event,
                io.as_ref(),
                &controls,
                &mut status,
                &connected_once,
                notifications,
                &history,
            );
        })
        .await;

        retained_pump.abort();

        // Whatever happened, the counter this connection reached must survive it.
        let _ = raise_reservation(paths, session.seq().saturating_add(SEQ_RESERVATION));

        if judge_outcome(outcome, &mut backoff, &controls, &mut status) {
            return Ok(());
        }

        controls.status.set(status.clone());

        let delay = backoff.next_delay()?;
        // The reason and the delay together, because "it worked for a week then stopped" is the
        // defining complaint in this category and a log that omits why is no help at all.
        eprintln!(
            "{}",
            log_line(
                "disconnected",
                &format!("{}, retrying in {delay} ms", status.state)
            )
        );
        tokio::time::sleep(std::time::Duration::from_millis(delay)).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::clipboard_io::StubClipboard;

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
            text: "x".to_owned(),
            ts_ms: 0,
            retained: false,
        };
        assert!(!on_action(&action, &Failing, &mut status, 0));
        assert!(status.last_error.is_some());
    }
}
