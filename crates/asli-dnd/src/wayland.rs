//! The Wayland side: the seat's data device, on winit's own connection.

use std::io::Read as _;
use std::os::fd::AsFd as _;
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::time::Duration;

use slint::winit_030::winit::raw_window_handle::{HasDisplayHandle as _, RawDisplayHandle};
use slint::winit_030::WinitWindowAccessor as _;
use wayland_client::protocol::wl_data_device::{self, WlDataDevice};
use wayland_client::protocol::wl_data_device_manager::{DndAction, WlDataDeviceManager};
use wayland_client::protocol::wl_data_offer::{self, WlDataOffer};
use wayland_client::protocol::wl_registry::{self, WlRegistry};
use wayland_client::protocol::wl_seat::WlSeat;
use wayland_client::{event_created_child, Connection, Dispatch, EventQueue, Proxy, QueueHandle};

use crate::DropEvent;

/// The type a file manager offers a dragged list of files as.
const URI_LIST: &str = "text/uri-list";

/// How long to wait for the source to hand over the list of dropped files.
const READ_TIMEOUT: Duration = Duration::from_secs(2);

/// Largest list of dropped files read, which is thousands of paths.
const MAX_LIST_BYTES: u64 = 1024 * 1024;

/// Listens for files dragged over the window.
pub struct DropTarget {
    conn: Connection,
    queue: EventQueue<State>,
    state: State,
}

#[derive(Default)]
struct State {
    manager: Option<WlDataDeviceManager>,
    seat: Option<WlSeat>,
    device: Option<WlDataDevice>,
    /// Offers announced and the types each one offers, until entered, dropped or replaced.
    offers: Vec<(WlDataOffer, Vec<String>)>,
    /// The offer over the window now, if it carries a list of files.
    current: Option<WlDataOffer>,
    events: Vec<DropEvent>,
}

impl DropTarget {
    /// Starts listening for files dragged over the window, when it is on Wayland. Returns `None`
    /// anywhere else, where winit reports drops itself, or when the compositor offers no data
    /// device.
    #[must_use]
    pub fn attach(window: &slint::Window) -> Option<Self> {
        let display =
            window.with_winit_window(|winit| match winit.display_handle().ok()?.as_raw() {
                RawDisplayHandle::Wayland(handle) => Some(handle.display.as_ptr()),
                _ => None,
            })??;
        // SAFETY: `from_foreign_display` needs the display to stay alive as long as the backend.
        // It is winit's, owned by the event loop of Slint's winit backend, which is created once
        // per process and never torn down while the process runs; the drop target is kept for the
        // life of the process as well. The backend is in guest mode, so dropping it never closes
        // winit's connection.
        #[allow(unsafe_code)]
        let backend =
            unsafe { wayland_backend::client::Backend::from_foreign_display(display.cast()) };
        let conn = Connection::from_backend(backend);
        let mut queue = conn.new_event_queue();
        let qh = queue.handle();
        let mut state = State::default();
        let _registry = conn.display().get_registry(&qh, ());
        queue.roundtrip(&mut state).ok()?;
        let (manager, seat) = (state.manager.clone()?, state.seat.clone()?);
        state.device = Some(manager.get_data_device(&seat, &qh, ()));
        conn.flush().ok()?;
        Some(Self { conn, queue, state })
    }

    /// What happened since the last call. Cheap when nothing did; call it often.
    pub fn poll(&mut self) -> Vec<DropEvent> {
        let _ = self.queue.dispatch_pending(&mut self.state);
        if self
            .state
            .events
            .iter()
            .any(|e| matches!(e, DropEvent::Dropped(_)))
        {
            // Answers to the drop went out during dispatch; they must reach the compositor now.
            let _ = self.conn.flush();
        }
        std::mem::take(&mut self.state.events)
    }
}

impl State {
    fn types_of(&self, offer: &WlDataOffer) -> Option<&Vec<String>> {
        self.offers
            .iter()
            .find(|(known, _)| known == offer)
            .map(|(_, types)| types)
    }

    fn forget(&mut self, offer: &WlDataOffer) {
        self.offers.retain(|(known, _)| known != offer);
        offer.destroy();
    }

    /// Reads the dropped list of files and tells the source the drop is done.
    fn take_drop(&mut self, conn: &Connection) {
        let Some(offer) = self.current.take() else {
            return;
        };
        let paths = read_uri_list(conn, &offer);
        if offer.version() >= 3 {
            offer.finish();
        }
        self.forget(&offer);
        self.events
            .push(paths.map_or(DropEvent::Unreadable, DropEvent::Dropped));
    }
}

fn read_uri_list(conn: &Connection, offer: &WlDataOffer) -> Option<Vec<PathBuf>> {
    let (read_end, write_end) = UnixStream::pair().ok()?;
    offer.receive(URI_LIST.to_owned(), write_end.as_fd());
    drop(write_end);
    conn.flush().ok()?;
    read_end.set_read_timeout(Some(READ_TIMEOUT)).ok()?;
    let mut list = Vec::new();
    read_end.take(MAX_LIST_BYTES).read_to_end(&mut list).ok()?;
    Some(crate::paths_from_uri_list(&String::from_utf8_lossy(&list)))
}

impl Dispatch<WlRegistry, ()> for State {
    fn event(
        state: &mut Self,
        registry: &WlRegistry,
        event: wl_registry::Event,
        (): &(),
        _: &Connection,
        qh: &QueueHandle<Self>,
    ) {
        if let wl_registry::Event::Global {
            name,
            interface,
            version,
        } = event
        {
            if interface == WlDataDeviceManager::interface().name && state.manager.is_none() {
                state.manager = Some(registry.bind(name, version.min(3), qh, ()));
            } else if interface == WlSeat::interface().name && state.seat.is_none() {
                state.seat = Some(registry.bind(name, version.min(5), qh, ()));
            }
        }
    }
}

impl Dispatch<WlDataDeviceManager, ()> for State {
    fn event(
        _: &mut Self,
        _: &WlDataDeviceManager,
        _: <WlDataDeviceManager as Proxy>::Event,
        (): &(),
        _: &Connection,
        _: &QueueHandle<Self>,
    ) {
    }
}

impl Dispatch<WlSeat, ()> for State {
    fn event(
        _: &mut Self,
        _: &WlSeat,
        _: <WlSeat as Proxy>::Event,
        (): &(),
        _: &Connection,
        _: &QueueHandle<Self>,
    ) {
    }
}

impl Dispatch<WlDataOffer, ()> for State {
    fn event(
        state: &mut Self,
        offer: &WlDataOffer,
        event: wl_data_offer::Event,
        (): &(),
        _: &Connection,
        _: &QueueHandle<Self>,
    ) {
        if let wl_data_offer::Event::Offer { mime_type } = event {
            if let Some((_, types)) = state.offers.iter_mut().find(|(known, _)| known == offer) {
                types.push(mime_type);
            }
        }
    }
}

impl Dispatch<WlDataDevice, ()> for State {
    fn event(
        state: &mut Self,
        _: &WlDataDevice,
        event: wl_data_device::Event,
        (): &(),
        conn: &Connection,
        _: &QueueHandle<Self>,
    ) {
        match event {
            wl_data_device::Event::DataOffer { id } => state.offers.push((id, Vec::new())),
            wl_data_device::Event::Enter { serial, id, .. } => {
                let Some(offer) = id else {
                    return;
                };
                let files = state
                    .types_of(&offer)
                    .is_some_and(|types| types.iter().any(|t| t == URI_LIST));
                if files {
                    offer.accept(serial, Some(URI_LIST.to_owned()));
                    if offer.version() >= 3 {
                        offer.set_actions(DndAction::Copy, DndAction::Copy);
                    }
                    state.current = Some(offer);
                    state.events.push(DropEvent::Entered);
                } else {
                    // Not files: say no at once, so the drag is not left waiting on this window.
                    offer.accept(serial, None);
                    state.forget(&offer);
                }
                let _ = conn.flush();
            }
            wl_data_device::Event::Leave => {
                if let Some(offer) = state.current.take() {
                    state.forget(&offer);
                    state.events.push(DropEvent::Left);
                }
            }
            wl_data_device::Event::Drop => state.take_drop(conn),
            // The clipboard, which this does not handle: Asli watches it on its own connection.
            wl_data_device::Event::Selection { id: Some(offer) } => state.forget(&offer),
            _ => {}
        }
    }

    event_created_child!(State, WlDataDevice, [
        wl_data_device::EVT_DATA_OFFER_OPCODE => (WlDataOffer, ()),
    ]);
}
