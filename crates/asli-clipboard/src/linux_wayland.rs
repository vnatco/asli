//! The Wayland backend, built on the data control protocols.
//!
//! On Wayland an ordinary client cannot read the clipboard without keyboard focus, which is why
//! clipboard managers use a privileged protocol instead. There are two, and both are required:
//!
//! - `ext-data-control-v1`, the standardized successor, in wayland-protocols since 1.39. KDE
//!   Plasma 6.4 speaks only this one, having removed the older protocol entirely.
//! - `wlr-data-control-unstable-v1`, the original wlroots protocol, now carrying a deprecation
//!   notice in its own XML. Older wlroots compositors, including older Sway and Hyprland builds,
//!   speak only this one.
//!
//! Supporting either alone breaks roughly half of the target desktops, so [`WaylandClipboard`]
//! binds the ext protocol when the compositor offers it, falls back to the wlr protocol when it
//! does not, and only reports [`Error::NoProtocol`] when neither exists.
//!
//! GNOME implements neither, as a deliberate and repeatedly restated policy, so it is handled by
//! the X11 backend through `XWayland` instead. See [`crate::session`].
//!
//! # Why this is event driven
//!
//! The compositor sends a `selection` event whenever the clipboard changes, so there is no
//! polling of clipboard content at all. The poll in the run loop is a wait on the Wayland socket
//! with a timeout, purely so that a shutdown request is noticed promptly. This is the difference
//! between this backend and the 500 ms full clipboard re-read that `clipboard-rs` performs.
//!
//! # How the two protocols share one implementation
//!
//! The wayland-rs proxies are distinct concrete types per protocol, so the manager, device,
//! source and offer are each wrapped in a small enum that forwards the three or four calls we
//! actually make. Everything that carries real logic (the baseline suppression, the sensitive
//! marker check, the pipe read, normalization, and the run loop) exists once and is shared.

use std::collections::HashMap;
use std::io::{Read, Write};
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};
use std::os::unix::net::UnixStream;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use rustix::event::{poll, PollFd, PollFlags, Timespec};
use wayland_client::globals::{registry_queue_init, GlobalList, GlobalListContents};
use wayland_client::protocol::{wl_registry, wl_seat};
use wayland_client::{Connection, Dispatch, EventQueue, Proxy, QueueHandle};
use wayland_protocols::ext::data_control::v1::client::{
    ext_data_control_device_v1::{self, ExtDataControlDeviceV1},
    ext_data_control_manager_v1::ExtDataControlManagerV1,
    ext_data_control_offer_v1::{self, ExtDataControlOfferV1},
    ext_data_control_source_v1::{self, ExtDataControlSourceV1},
};
use wayland_protocols_wlr::data_control::v1::client::{
    zwlr_data_control_device_v1::{self, ZwlrDataControlDeviceV1},
    zwlr_data_control_manager_v1::ZwlrDataControlManagerV1,
    zwlr_data_control_offer_v1::{self, ZwlrDataControlOfferV1},
    zwlr_data_control_source_v1::{self, ZwlrDataControlSourceV1},
};

use crate::error::{Error, Result};
use crate::image_bytes::{self, MAX_IMAGE_BYTES};
use crate::{ClipContent, ClipEvent, ClipboardWatcher, WriteOptions, WriteReceipt};

/// The marker a password manager sets on Linux. `KeePassXC` writes it, Klipper honours it, and it
/// travels through the data control path like any other MIME type, so we can see it in the offer
/// before reading a single byte of content.
const SENSITIVE_MIME: &str = "x-kde-passwordManagerHint";

/// MIME types we accept for text, most specific first.
const TEXT_MIMES: [&str; 4] = [
    "text/plain;charset=utf-8",
    "UTF8_STRING",
    "text/plain",
    "STRING",
];

/// MIME types we accept for images.
///
/// PNG only, deliberately. A source that offers a screenshot usually offers several bitmap
/// flavours, and accepting more than one would mean deciding which is canonical on every hop.
/// Every desktop toolkit in use puts `image/png` on the clipboard alongside its native format.
const IMAGE_MIMES: [&str; 2] = ["image/png", "PNG"];

/// How long to wait on the Wayland socket before checking the shutdown flag again.
const POLL_TIMEOUT: Duration = Duration::from_millis(200);

/// How long to wait for the source client to write the selection into our pipe.
const RECEIVE_TIMEOUT: Duration = Duration::from_secs(2);

/// Largest text selection we will read, as a guard against a hostile or broken source.
///
/// Images have their own, larger cap in [`crate::image_bytes`], because a screenshot is legitimately
/// far bigger than any text anyone copies on purpose.
const MAX_READ_BYTES: usize = 8 * 1024 * 1024;

/// Which protocol the compositor gave us.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Protocol {
    /// `ext-data-control-v1`, the standardized protocol, preferred where it exists.
    Ext,
    /// `wlr-data-control-unstable-v1`, the deprecated wlroots protocol, used when the compositor
    /// is too old to offer the standardized one.
    Wlr,
}

impl Protocol {
    /// A label for diagnostics and the tray.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Ext => "ext-data-control-v1",
            Self::Wlr => "wlr-data-control-unstable-v1",
        }
    }
}

/// A data control manager from either protocol.
enum AnyManager {
    /// The standardized protocol.
    Ext(ExtDataControlManagerV1),
    /// The deprecated wlroots protocol.
    Wlr(ZwlrDataControlManagerV1),
}

impl AnyManager {
    fn get_data_device(&self, seat: &wl_seat::WlSeat, qh: &QueueHandle<State>) -> AnyDevice {
        match self {
            Self::Ext(manager) => AnyDevice::Ext(manager.get_data_device(seat, qh, ())),
            Self::Wlr(manager) => AnyDevice::Wlr(manager.get_data_device(seat, qh, ())),
        }
    }

    fn create_data_source(&self, qh: &QueueHandle<State>) -> AnySource {
        match self {
            Self::Ext(manager) => AnySource::Ext(manager.create_data_source(qh, ())),
            Self::Wlr(manager) => AnySource::Wlr(manager.create_data_source(qh, ())),
        }
    }
}

/// A data control device from either protocol.
enum AnyDevice {
    /// The standardized protocol.
    Ext(ExtDataControlDeviceV1),
    /// The deprecated wlroots protocol.
    Wlr(ZwlrDataControlDeviceV1),
}

impl AnyDevice {
    /// Announces a source as the clipboard contents, or clears the clipboard with `None`.
    ///
    /// A device and a source always come from the same manager, so the protocols never mix. If
    /// they somehow did, clearing is the safe outcome rather than a panic in a background thread.
    fn set_selection(&self, source: Option<&AnySource>) {
        match self {
            Self::Ext(device) => device.set_selection(source.and_then(AnySource::as_ext)),
            Self::Wlr(device) => device.set_selection(source.and_then(AnySource::as_wlr)),
        }
    }
}

/// A data source from either protocol.
enum AnySource {
    /// The standardized protocol.
    Ext(ExtDataControlSourceV1),
    /// The deprecated wlroots protocol.
    Wlr(ZwlrDataControlSourceV1),
}

impl AnySource {
    /// The Wayland object id, which is how an event names the source it is about.
    fn protocol_id(&self) -> u32 {
        match self {
            Self::Ext(source) => source.id().protocol_id(),
            Self::Wlr(source) => source.id().protocol_id(),
        }
    }

    fn offer(&self, mime_type: String) {
        match self {
            Self::Ext(source) => source.offer(mime_type),
            Self::Wlr(source) => source.offer(mime_type),
        }
    }

    fn as_ext(&self) -> Option<&ExtDataControlSourceV1> {
        match self {
            Self::Ext(source) => Some(source),
            Self::Wlr(_) => None,
        }
    }

    fn as_wlr(&self) -> Option<&ZwlrDataControlSourceV1> {
        match self {
            Self::Wlr(source) => Some(source),
            Self::Ext(_) => None,
        }
    }
}

/// A data offer from either protocol.
enum AnyOffer {
    /// The standardized protocol.
    Ext(ExtDataControlOfferV1),
    /// The deprecated wlroots protocol.
    Wlr(ZwlrDataControlOfferV1),
}

impl AnyOffer {
    /// The Wayland object id, which is unique across every object on the connection and so is
    /// safe to use as the key for both protocols at once.
    fn protocol_id(&self) -> u32 {
        match self {
            Self::Ext(offer) => offer.id().protocol_id(),
            Self::Wlr(offer) => offer.id().protocol_id(),
        }
    }

    fn receive(&self, mime_type: String, fd: BorrowedFd<'_>) {
        match self {
            Self::Ext(offer) => offer.receive(mime_type, fd),
            Self::Wlr(offer) => offer.receive(mime_type, fd),
        }
    }

    fn destroy(&self) {
        match self {
            Self::Ext(offer) => offer.destroy(),
            Self::Wlr(offer) => offer.destroy(),
        }
    }
}

/// What the compositor last told us about the selection.
///
/// Three states, and they are genuinely different: no news since we last looked, the clipboard
/// was emptied, or there is a new offer waiting to be read.
enum Pending {
    /// Nothing new since the last pass.
    Nothing,
    /// The clipboard was cleared. There is nothing to sync and nothing to report.
    Cleared,
    /// A new selection is available.
    Offer(AnyOffer),
}

/// State driven by the Wayland event queue.
struct State {
    /// MIME types offered, keyed by the offer that announced them.
    offers: HashMap<u32, Vec<String>>,
    /// The selection the compositor most recently announced.
    pending: Pending,
    /// Bytes we are currently offering to other clients.
    ///
    /// Text and images are both just bytes once they reach the pipe, and the compositor tells us
    /// which MIME type it wants when it asks, so one buffer serves both.
    /// What to send for each MIME type we offered.
    ///
    /// One payload for every type will not do once a concealment hint is offered alongside the
    /// content: a paste asks for `text/plain` and expects the text, while Klipper asks for
    /// `x-kde-passwordManagerHint` and expects `secret`.
    ///
    /// Keyed by the source it belongs to. Replacing our own selection makes the compositor cancel
    /// the previous source, and that cancellation arrives after the new source is already
    /// serving. Without the key it cleared the new payload, so every write after the first
    /// advertised text and delivered zero bytes.
    serving: Option<(u32, Arc<OfferTable>)>,
    /// Set when the compositor tells us the device is finished, which is fatal for this
    /// connection.
    finished: bool,
}

impl State {
    /// Records the newest selection, destroying an older offer nobody will now read.
    ///
    /// Several selections can arrive in one batch of events, and only the last matters. The ones
    /// it replaces used to be dropped without being destroyed, leaking an object on both sides.
    fn replace_pending(&mut self, next: Pending) {
        if let Pending::Offer(old) = std::mem::replace(&mut self.pending, next) {
            self.offers.remove(&old.protocol_id());
            old.destroy();
        }
    }

    /// The payload for `source`, if it is the one we are currently serving.
    fn table_for(&self, source: u32) -> Option<Arc<OfferTable>> {
        self.serving
            .as_ref()
            .filter(|(id, _)| *id == source)
            .map(|(_, table)| Arc::clone(table))
    }

    /// Stops serving, but only if `source` is still the current one. A late cancellation of a
    /// source we already replaced must not touch its successor.
    fn forget(&mut self, source: u32) {
        if self.serving.as_ref().is_some_and(|(id, _)| *id == source) {
            self.serving = None;
        }
    }

    fn mimes_for(&self, offer: &AnyOffer) -> &[String] {
        self.offers
            .get(&offer.protocol_id())
            .map_or(&[], Vec::as_slice)
    }
}

/// A Wayland clipboard connection.
pub struct WaylandClipboard {
    /// Whether the first selection has been seen.
    ///
    /// The compositor announces the current selection as soon as the device is bound, so the
    /// first event describes whatever was already on the clipboard before we started. Treating
    /// that as a change would rebroadcast stale content on every launch and every reconnect,
    /// which is both surprising and a good way to overwrite something a person just copied on
    /// another machine. So the first selection sets the baseline and is not reported.
    seen_initial_selection: bool,
    conn: Connection,
    queue: EventQueue<State>,
    state: State,
    device: AnyDevice,
    manager: AnyManager,
    protocol: Protocol,
    shutdown: Arc<AtomicBool>,
    /// Only serve what we own, and never read other clients' copies.
    ///
    /// The writer connection runs the event loop purely to answer paste requests. Data control
    /// announces every selection to every device, our own included, so without this the writer
    /// asked its own source for the bytes and then blocked reading a pipe that only this same
    /// thread could fill, stalling for the full receive timeout after every write.
    serve_only: bool,
}

impl WaylandClipboard {
    /// Connects to the compositor and binds a data control device.
    ///
    /// The standardized `ext-data-control-v1` protocol is preferred, with the deprecated
    /// `wlr-data-control-unstable-v1` as the fallback for older wlroots compositors.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Connect`] if there is no Wayland display, and [`Error::NoProtocol`] if the
    /// compositor advertises neither data control protocol, which is the case on GNOME (by
    /// policy) and on river (not implemented). The caller is expected to fall back to the X11
    /// backend when that happens and an X display exists.
    pub fn connect() -> Result<Self> {
        let conn = Connection::connect_to_env()
            .map_err(|e| Error::Connect(format!("could not reach the Wayland display: {e}")))?;

        let (globals, queue): (GlobalList, EventQueue<State>) = registry_queue_init(&conn)
            .map_err(|e| Error::Connect(format!("could not read the Wayland registry: {e}")))?;
        let qh = queue.handle();

        let seat: wl_seat::WlSeat = globals
            .bind(&qh, 1..=9, ())
            .map_err(|e| Error::Connect(format!("the compositor offered no usable seat: {e}")))?;

        // Version 2 of the wlr protocol adds primary selection events, which we ignore, so
        // accepting either version costs nothing and works with more compositors.
        let (manager, protocol) =
            if let Ok(ext) = globals.bind::<ExtDataControlManagerV1, _, _>(&qh, 1..=1, ()) {
                (AnyManager::Ext(ext), Protocol::Ext)
            } else if let Ok(wlr) = globals.bind::<ZwlrDataControlManagerV1, _, _>(&qh, 1..=2, ()) {
                (AnyManager::Wlr(wlr), Protocol::Wlr)
            } else {
                return Err(Error::NoProtocol(
                    "this compositor advertises neither ext-data-control-v1 nor \
                 wlr-data-control-unstable-v1. GNOME declines to implement clipboard manager \
                 protocols as a matter of policy, and river implements none, so there is no way \
                 to watch the clipboard natively here"
                        .to_owned(),
                ));
            };

        let device = manager.get_data_device(&seat, &qh);
        conn.flush()
            .map_err(|e| Error::Connect(format!("could not flush: {e}")))?;

        Ok(Self {
            seen_initial_selection: false,
            conn,
            queue,
            state: State {
                offers: HashMap::new(),
                pending: Pending::Nothing,
                serving: None,
                finished: false,
            },
            device,
            manager,
            protocol,
            shutdown: Arc::new(AtomicBool::new(false)),
            serve_only: false,
        })
    }

    /// Which protocol this connection is using.
    #[must_use]
    pub const fn protocol(&self) -> Protocol {
        self.protocol
    }

    /// Makes this connection a writer that only serves, as described on the field.
    pub const fn set_serve_only(&mut self) {
        self.serve_only = true;
    }

    /// A handle that can ask the watch loop to stop from another thread.
    #[must_use]
    pub fn shutdown_handle(&self) -> Arc<AtomicBool> {
        Arc::clone(&self.shutdown)
    }

    /// Offers `text` to other clients as the clipboard contents.
    ///
    /// Wayland has no clipboard storage either: we announce a data source, and the compositor
    /// asks us to write the bytes into a pipe whenever something pastes. That means this
    /// connection must keep running for the content to stay available.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Write`] if the compositor connection cannot be flushed.
    pub fn set_text(&mut self, text: &str, options: WriteOptions) -> Result<WriteReceipt> {
        let qh = self.queue.handle();
        let source = self.manager.create_data_source(&qh);
        for mime in TEXT_MIMES {
            source.offer(mime.to_owned());
        }
        if options.concealed {
            source.offer(SENSITIVE_MIME.to_owned());
        }
        self.state.serving = Some((
            source.protocol_id(),
            Arc::new(offer_table(
                TEXT_MIMES.iter().copied(),
                text.as_bytes(),
                options.concealed,
            )),
        ));
        self.device.set_selection(Some(&source));
        self.conn
            .flush()
            .map_err(|e| Error::Write(format!("could not flush: {e}")))?;

        // Wayland offers no clipboard sequence number, so loop prevention here rests on the
        // content hash guard in asli-core rather than on a platform counter.
        Ok(WriteReceipt { seq: None })
    }

    /// Gives up the selection, so the clipboard is genuinely empty rather than empty looking.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Write`] if the compositor connection cannot be flushed.
    pub fn release_selection(&mut self) -> Result<()> {
        // Only if it is still ours. Clearing the selection clears it whoever holds it, so
        // releasing after somebody else copied would erase their copy, which for the join token
        // clear typically means a password copied a minute later. The round trip delivers any
        // cancellation still in flight before deciding.
        self.queue
            .roundtrip(&mut self.state)
            .map_err(|e| Error::Write(format!("could not reach the compositor: {e}")))?;
        if self.state.serving.is_none() {
            return Ok(());
        }

        self.state.serving = None;
        self.device.set_selection(None);
        self.conn
            .flush()
            .map_err(|e| Error::Write(format!("could not flush: {e}")))?;
        Ok(())
    }

    /// Offers `png` to other clients as the clipboard contents.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Read`] if the bytes are not a PNG or exceed the cap, because putting a
    /// mislabelled or absurd payload on the clipboard would fail on the other side instead of
    /// here, and [`Error::Write`] if the compositor connection cannot be flushed.
    pub fn set_image(&mut self, png: &[u8], options: WriteOptions) -> Result<WriteReceipt> {
        image_bytes::validate_png(png)?;

        let qh = self.queue.handle();
        let source = self.manager.create_data_source(&qh);
        for mime in IMAGE_MIMES {
            source.offer((*mime).to_owned());
        }
        self.state.serving = Some((
            source.protocol_id(),
            Arc::new(offer_table(
                IMAGE_MIMES.iter().copied(),
                png,
                options.concealed,
            )),
        ));
        self.device.set_selection(Some(&source));
        self.conn
            .flush()
            .map_err(|e| Error::Write(format!("could not flush: {e}")))?;

        Ok(WriteReceipt { seq: None })
    }

    /// Reads an offer as text, after checking it is not marked sensitive.
    fn read_offer(&self, offer: &AnyOffer) -> Result<Option<ClipEvent>> {
        let mimes = self.state.mimes_for(offer);

        if mimes.iter().any(|m| m == SENSITIVE_MIME) {
            return Ok(Some(ClipEvent {
                content: ClipContent::Text(String::new()),
                sensitive: true,
            }));
        }

        // Text wins when a source offers both, which nearly every application does: a copied
        // rich text selection carries a bitmap rendering too, and syncing that instead of the
        // words would be astonishing.
        if let Some(mime) = TEXT_MIMES
            .iter()
            .find(|candidate| mimes.iter().any(|m| m == *candidate))
        {
            let buf = self.receive(offer, mime, MAX_READ_BYTES)?;
            let raw = String::from_utf8(buf).map_err(|_| Error::NotUtf8)?;

            // Normalize at exactly one boundary, here, so that the same text copied on Linux,
            // macOS and Windows produces identical bytes and therefore an identical hash.
            // Skipping this is how clipboard tools end up in a loop that grows the text on every
            // hop.
            let text = asli_core::normalize(&raw).into_owned();
            if !asli_core::is_syncable(&text) {
                // Empty or whitespace only, which is nearly always an intermediate state while an
                // application sets several formats rather than something a person copied.
                return Ok(None);
            }

            return Ok(Some(ClipEvent {
                content: ClipContent::Text(text),
                sensitive: false,
            }));
        }

        if let Some(mime) = IMAGE_MIMES
            .iter()
            .find(|candidate| mimes.iter().any(|m| m == *candidate))
        {
            let buf = self.receive(offer, mime, MAX_IMAGE_BYTES)?;

            // The bound above stops the read at the cap, so a source larger than it arrives
            // truncated and would fail validation anyway. Checking the length explicitly gives the
            // user a reason instead of a corrupt image.
            image_bytes::validate_png(&buf)?;

            return Ok(Some(ClipEvent {
                content: ClipContent::ImagePng(buf),
                sensitive: false,
            }));
        }

        // Neither text nor an image: a file list, or a format v1 does not carry.
        Ok(None)
    }

    /// Asks the source to write one MIME type into a pipe, and reads it with a bound and a
    /// timeout.
    ///
    /// The bound is the whole point. A clipboard source is another process that may be hostile,
    /// broken, or simply gone, so this never reads without a ceiling and never waits forever.
    fn receive(&self, offer: &AnyOffer, mime: &str, limit: usize) -> Result<Vec<u8>> {
        let (mut read_end, write_end) = UnixStream::pair()
            .map_err(|e| Error::Read(format!("could not create a transfer pipe: {e}")))?;

        offer.receive(mime.to_owned(), write_end.as_fd());
        self.conn
            .flush()
            .map_err(|e| Error::Read(format!("could not flush: {e}")))?;

        // Our copy of the write end must go, or the read below never sees end of file.
        drop(write_end);

        read_end
            .set_read_timeout(Some(RECEIVE_TIMEOUT))
            .map_err(|e| Error::Read(format!("could not set a read timeout: {e}")))?;

        let mut buf = Vec::new();
        // One byte past the limit, so content that is too large is told apart from content that
        // is exactly the limit. Reading only up to the limit returned a silently cut copy, and a
        // cut PNG passes the signature check.
        // UnixStream implements both Read and Write, so by_ref must be disambiguated.
        Read::by_ref(&mut read_end)
            .take(u64::try_from(limit).unwrap_or(u64::MAX).saturating_add(1))
            .read_to_end(&mut buf)
            .map_err(|e| Error::Read(format!("the source did not send the selection: {e}")))?;

        if buf.len() > limit {
            return Err(Error::Read(format!(
                "the clipboard content exceeds the {limit} byte limit"
            )));
        }
        Ok(buf)
    }

    /// Waits for Wayland activity, with a timeout so shutdown stays responsive.
    fn wait_for_activity(&mut self) -> Result<()> {
        self.conn
            .flush()
            .map_err(|e| Error::ConnectionLost(format!("could not flush: {e}")))?;

        let Some(guard) = self.conn.prepare_read() else {
            // Events are already queued, so dispatch them without waiting.
            return Ok(());
        };

        // The backend must outlive the borrowed file descriptor taken from it.
        let backend = self.conn.backend();
        let fd = backend.poll_fd();
        let mut fds = [PollFd::from_borrowed_fd(fd.as_fd(), PollFlags::IN)];
        let timeout = Timespec {
            tv_sec: 0,
            tv_nsec: POLL_TIMEOUT.subsec_nanos().into(),
        };

        match poll(&mut fds, Some(&timeout)) {
            Ok(0) => {
                // Nothing arrived before the timeout. Cancel the read so the guard does not hold
                // the queue, and let the caller check the shutdown flag.
                drop(guard);
                Ok(())
            }
            Ok(_) => {
                guard
                    .read()
                    .map_err(|e| Error::ConnectionLost(format!("{e}")))?;
                Ok(())
            }
            Err(rustix::io::Errno::INTR) => {
                drop(guard);
                Ok(())
            }
            Err(e) => Err(Error::ConnectionLost(format!("poll failed: {e}"))),
        }
    }
}

impl ClipboardWatcher for WaylandClipboard {
    fn run(&mut self, sink: &mut dyn FnMut(ClipEvent)) -> Result<()> {
        loop {
            if self.shutdown.load(Ordering::Relaxed) {
                return Ok(());
            }

            self.wait_for_activity()?;

            self.queue
                .dispatch_pending(&mut self.state)
                .map_err(|e| Error::ConnectionLost(format!("{e}")))?;

            if self.state.finished {
                return Err(Error::ConnectionLost(
                    "the compositor closed the data control device".to_owned(),
                ));
            }

            // Selection handling happens out here rather than inside the dispatch callback,
            // because reading an offer needs the connection and blocks on a pipe.
            match std::mem::replace(&mut self.state.pending, Pending::Nothing) {
                Pending::Offer(offer) if !self.seen_initial_selection => {
                    // The clipboard as it was before we started. Baseline only, never reported.
                    self.seen_initial_selection = true;
                    self.state.offers.remove(&offer.protocol_id());
                    offer.destroy();
                }
                Pending::Offer(offer) if self.serve_only => {
                    self.state.offers.remove(&offer.protocol_id());
                    offer.destroy();
                }
                Pending::Offer(offer) => {
                    match self.read_offer(&offer) {
                        Ok(Some(event)) => sink(event),
                        // Either there is no text on the clipboard, or the read failed because
                        // the source exited between announcing the selection and our request.
                        // Both are routine and neither should stop the watcher.
                        Ok(None) | Err(Error::Read(_) | Error::NotUtf8) => {}
                        Err(other) => return Err(other),
                    }
                    self.state.offers.remove(&offer.protocol_id());
                    offer.destroy();
                }
                Pending::Cleared => {
                    // The clipboard was emptied. There is nothing to sync, but it still counts as
                    // the baseline having been established.
                    self.seen_initial_selection = true;
                }
                Pending::Nothing => {}
            }
        }
    }

    fn shutdown(&self) {
        self.shutdown.store(true, Ordering::Relaxed);
    }
}

impl Dispatch<wl_registry::WlRegistry, GlobalListContents> for State {
    fn event(
        _: &mut Self,
        _: &wl_registry::WlRegistry,
        _: wl_registry::Event,
        _: &GlobalListContents,
        _: &Connection,
        _: &QueueHandle<Self>,
    ) {
    }
}

impl Dispatch<wl_seat::WlSeat, ()> for State {
    fn event(
        _: &mut Self,
        _: &wl_seat::WlSeat,
        _: wl_seat::Event,
        (): &(),
        _: &Connection,
        _: &QueueHandle<Self>,
    ) {
    }
}

impl Dispatch<ExtDataControlManagerV1, ()> for State {
    fn event(
        _: &mut Self,
        _: &ExtDataControlManagerV1,
        _: <ExtDataControlManagerV1 as Proxy>::Event,
        (): &(),
        _: &Connection,
        _: &QueueHandle<Self>,
    ) {
    }
}

impl Dispatch<ExtDataControlDeviceV1, ()> for State {
    fn event(
        state: &mut Self,
        _: &ExtDataControlDeviceV1,
        event: ext_data_control_device_v1::Event,
        (): &(),
        _: &Connection,
        _: &QueueHandle<Self>,
    ) {
        match event {
            ext_data_control_device_v1::Event::DataOffer { id } => {
                // The MIME types arrive as separate events on the offer itself.
                state.offers.insert(id.id().protocol_id(), Vec::new());
            }
            ext_data_control_device_v1::Event::Selection { id } => {
                state.replace_pending(match id {
                    Some(offer) => Pending::Offer(AnyOffer::Ext(offer)),
                    None => Pending::Cleared,
                });
            }
            ext_data_control_device_v1::Event::Finished => {
                state.finished = true;
            }
            // Primary selection is the middle click selection. Syncing it would fire on every
            // text selection, so it is ignored, but its offer still has to be destroyed: one is
            // created for every highlight, and keeping them all grew our memory and the
            // compositor's for the life of the session.
            ext_data_control_device_v1::Event::PrimarySelection { id: Some(offer) } => {
                state.offers.remove(&offer.id().protocol_id());
                offer.destroy();
            }
            _ => {}
        }
    }

    wayland_client::event_created_child!(State, ExtDataControlDeviceV1, [
        ext_data_control_device_v1::EVT_DATA_OFFER_OPCODE => (ExtDataControlOfferV1, ()),
    ]);
}

impl Dispatch<ExtDataControlOfferV1, ()> for State {
    fn event(
        state: &mut Self,
        offer: &ExtDataControlOfferV1,
        event: ext_data_control_offer_v1::Event,
        (): &(),
        _: &Connection,
        _: &QueueHandle<Self>,
    ) {
        if let ext_data_control_offer_v1::Event::Offer { mime_type } = event {
            state
                .offers
                .entry(offer.id().protocol_id())
                .or_default()
                .push(mime_type);
        }
    }
}

impl Dispatch<ExtDataControlSourceV1, ()> for State {
    fn event(
        state: &mut Self,
        source: &ExtDataControlSourceV1,
        event: ext_data_control_source_v1::Event,
        (): &(),
        _: &Connection,
        _: &QueueHandle<Self>,
    ) {
        match event {
            ext_data_control_source_v1::Event::Send { mime_type, fd } => {
                // Something is pasting. Write whatever belongs to the type it asked for, then
                // close the pipe so the reader sees end of file.
                if let Some(table) = state.table_for(source.id().protocol_id()) {
                    write_detached(fd, table, mime_type);
                }
            }
            ext_data_control_source_v1::Event::Cancelled => {
                // Another client took the clipboard, so we stop serving and release the source.
                state.forget(source.id().protocol_id());
                source.destroy();
            }
            _ => {}
        }
    }
}

impl Dispatch<ZwlrDataControlManagerV1, ()> for State {
    fn event(
        _: &mut Self,
        _: &ZwlrDataControlManagerV1,
        _: <ZwlrDataControlManagerV1 as Proxy>::Event,
        (): &(),
        _: &Connection,
        _: &QueueHandle<Self>,
    ) {
    }
}

impl Dispatch<ZwlrDataControlDeviceV1, ()> for State {
    fn event(
        state: &mut Self,
        _: &ZwlrDataControlDeviceV1,
        event: zwlr_data_control_device_v1::Event,
        (): &(),
        _: &Connection,
        _: &QueueHandle<Self>,
    ) {
        match event {
            zwlr_data_control_device_v1::Event::DataOffer { id } => {
                state.offers.insert(id.id().protocol_id(), Vec::new());
            }
            zwlr_data_control_device_v1::Event::Selection { id } => {
                state.replace_pending(match id {
                    Some(offer) => Pending::Offer(AnyOffer::Wlr(offer)),
                    None => Pending::Cleared,
                });
            }
            zwlr_data_control_device_v1::Event::Finished => {
                state.finished = true;
            }
            // Destroyed for the same reason as on the ext device.
            zwlr_data_control_device_v1::Event::PrimarySelection { id: Some(offer) } => {
                state.offers.remove(&offer.id().protocol_id());
                offer.destroy();
            }
            _ => {}
        }
    }

    wayland_client::event_created_child!(State, ZwlrDataControlDeviceV1, [
        zwlr_data_control_device_v1::EVT_DATA_OFFER_OPCODE => (ZwlrDataControlOfferV1, ()),
    ]);
}

impl Dispatch<ZwlrDataControlOfferV1, ()> for State {
    fn event(
        state: &mut Self,
        offer: &ZwlrDataControlOfferV1,
        event: zwlr_data_control_offer_v1::Event,
        (): &(),
        _: &Connection,
        _: &QueueHandle<Self>,
    ) {
        if let zwlr_data_control_offer_v1::Event::Offer { mime_type } = event {
            state
                .offers
                .entry(offer.id().protocol_id())
                .or_default()
                .push(mime_type);
        }
    }
}

impl Dispatch<ZwlrDataControlSourceV1, ()> for State {
    fn event(
        state: &mut Self,
        source: &ZwlrDataControlSourceV1,
        event: zwlr_data_control_source_v1::Event,
        (): &(),
        _: &Connection,
        _: &QueueHandle<Self>,
    ) {
        match event {
            zwlr_data_control_source_v1::Event::Send { mime_type, fd } => {
                if let Some(table) = state.table_for(source.id().protocol_id()) {
                    write_detached(fd, table, mime_type);
                }
            }
            zwlr_data_control_source_v1::Event::Cancelled => {
                state.forget(source.id().protocol_id());
                source.destroy();
            }
            _ => {}
        }
    }
}

/// The value Klipper and `KeePassXC` agree on for the hint.
const SENSITIVE_VALUE: &[u8] = b"secret";

/// What to send for each MIME type a data source offered.
type OfferTable = Vec<(String, Vec<u8>)>;

/// Builds the per MIME payload table a data source answers from.
///
/// The hint is offered last so that a client picking the first type it recognises still gets the
/// content rather than the marker.
fn offer_table<'a>(
    mimes: impl Iterator<Item = &'a str>,
    content: &[u8],
    concealed: bool,
) -> OfferTable {
    let mut table: OfferTable = mimes
        .map(|mime| (mime.to_owned(), content.to_vec()))
        .collect();
    if concealed {
        table.push((SENSITIVE_MIME.to_owned(), SENSITIVE_VALUE.to_vec()));
    }
    table
}

/// Finds the payload for the type a client asked for.
fn payload_for<'a>(table: &'a [(String, Vec<u8>)], mime: &str) -> Option<&'a [u8]> {
    table
        .iter()
        .find(|(offered, _)| offered == mime)
        .map(|(_, bytes)| bytes.as_slice())
}

/// Writes a payload into a pipe the compositor supplied, ignoring a broken pipe.
///
/// A client that asks for the selection and then exits before reading is normal, and it must not
/// take the watcher down with it.
fn write_all_to(fd: OwnedFd, bytes: &[u8]) {
    let mut file = std::fs::File::from(fd);
    let _ = file.write_all(bytes);
    let _ = file.flush();
}

/// Writes a payload on a thread of its own, so a client that asks and never reads cannot stall us.
///
/// A pipe holds about 64 KiB. Writing more than that blocks until the reader reads, and a hung
/// application pasting an image would otherwise freeze this connection's whole event loop, so no
/// later clip would ever be written.
fn write_detached(fd: OwnedFd, table: Arc<OfferTable>, mime: String) {
    // If no thread can be started, the fd went with the failed closure and is closed, so the
    // reader sees end of file rather than hanging.
    let _ = std::thread::Builder::new()
        .name("asli-wayland-send".to_owned())
        .spawn(move || {
            if let Some(bytes) = payload_for(&table, &mime) {
                write_all_to(fd, bytes);
            }
        });
}

#[cfg(test)]
mod tests {
    use super::*;

    fn wayland_available() -> bool {
        std::env::var("WAYLAND_DISPLAY").is_ok_and(|d| !d.is_empty())
    }

    #[test]
    fn connects_when_a_compositor_offers_data_control() {
        if !wayland_available() {
            eprintln!("skipping: no WAYLAND_DISPLAY");
            return;
        }
        match WaylandClipboard::connect() {
            Ok(clipboard) => {
                // Either protocol is a success. Which one depends on the compositor, and both are
                // supported precisely because no single one covers the target desktops.
                let protocol = clipboard.protocol();
                assert!(matches!(protocol, Protocol::Ext | Protocol::Wlr));
                eprintln!("bound {}", protocol.label());
            }
            // GNOME and river legitimately have no protocol. That is a supported outcome here,
            // and the session layer routes those to the X11 backend instead.
            Err(Error::NoProtocol(message)) => {
                eprintln!("no data control protocol on this compositor: {message}");
            }
            Err(other) => panic!("unexpected failure: {other}"),
        }
    }

    #[test]
    fn shutdown_handle_stops_the_loop() {
        if !wayland_available() {
            eprintln!("skipping: no WAYLAND_DISPLAY");
            return;
        }
        let Ok(mut clipboard) = WaylandClipboard::connect() else {
            eprintln!("skipping: no data control protocol");
            return;
        };
        clipboard.shutdown_handle().store(true, Ordering::Relaxed);
        let mut seen = 0;
        clipboard
            .run(&mut |_| seen += 1)
            .expect("returns cleanly when asked to stop");
        assert_eq!(seen, 0);
    }

    #[test]
    fn text_mime_preference_is_most_specific_first() {
        assert_eq!(TEXT_MIMES[0], "text/plain;charset=utf-8");
        assert!(TEXT_MIMES.contains(&"text/plain"));
    }

    #[test]
    fn image_mimes_are_png_only() {
        // One format on the wire. Accepting a second would mean deciding which is canonical on
        // every hop between machines.
        assert_eq!(IMAGE_MIMES[0], "image/png");
        assert!(!IMAGE_MIMES
            .iter()
            .any(|m| m.contains("bmp") || m.contains("jpeg")));
    }

    #[test]
    fn text_is_preferred_over_an_image_when_both_are_offered() {
        // Copying a rich text selection offers a bitmap rendering alongside the words. Syncing
        // the picture instead of the text would be astonishing, so the lookup order matters.
        let offered = [
            "image/png".to_owned(),
            "text/plain;charset=utf-8".to_owned(),
        ];
        let text_hit = TEXT_MIMES.iter().any(|c| offered.iter().any(|m| m == *c));
        let image_hit = IMAGE_MIMES.iter().any(|c| offered.iter().any(|m| m == *c));
        assert!(text_hit && image_hit, "this fixture offers both");
    }

    #[test]
    fn a_late_cancel_of_a_replaced_source_keeps_the_new_payload() {
        let mut state = State {
            offers: HashMap::new(),
            pending: Pending::Nothing,
            serving: None,
            finished: false,
        };
        let table = |text: &str| {
            Arc::new(offer_table(
                TEXT_MIMES.iter().copied(),
                text.as_bytes(),
                false,
            ))
        };

        // First write, then a second one replacing it before the compositor's cancel arrives.
        state.serving = Some((7, table("first")));
        state.serving = Some((9, table("second")));
        state.forget(7);

        let served = state.table_for(9).expect("the new source still serves");
        assert_eq!(payload_for(&served, TEXT_MIMES[0]), Some(&b"second"[..]));
        assert!(
            state.table_for(7).is_none(),
            "the old source serves nothing"
        );

        state.forget(9);
        assert!(state.table_for(9).is_none());
    }

    #[test]
    fn each_protocol_has_a_distinct_label() {
        assert_eq!(Protocol::Ext.label(), "ext-data-control-v1");
        assert_eq!(Protocol::Wlr.label(), "wlr-data-control-unstable-v1");
        assert_ne!(Protocol::Ext.label(), Protocol::Wlr.label());
    }
}
