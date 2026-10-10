//! Adding a device to an account, from both ends.
//!
//! The device already on the account makes a join code and waits in the meeting room the code
//! names; the new device types the code and asks to join there. The person approves the request on
//! the first device after checking both show the same six digit comparison code, and the account key
//! crosses sealed to the new device alone. `asli_crypto::enroll` has the construction and the
//! reasons; this module runs the two conversations, each on a thread of its own with its own
//! connection, so neither the window nor the running daemon waits on them.
//!
//! The relay keeps nothing for a room, so a request sent while the other side is between
//! connections would be lost. The new device therefore asks again every few seconds until it is
//! answered, and the approving device recognises a repeat by its request id.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use asli_crypto::device::DeviceKeys;
use asli_crypto::enroll::{self, JoinCode, JoinRequest, REQUEST_ID_LEN};
use asli_net::client::{self, ClientEvent, LocalEvent, MsgKind};
use asli_net::session::Session;
use tokio::sync::mpsc;
use zeroize::Zeroizing;

use crate::clipboard_io::log_line;

/// How often the new device repeats its request while waiting.
const ASK_EVERY: Duration = Duration::from_secs(4);

/// How long to wait before reconnecting after the meeting connection drops.
const RECONNECT_AFTER: Duration = Duration::from_secs(2);

/// Most requests one code collects. More is someone else trying, and the person has seen enough.
const MAX_REQUESTS: usize = 8;

/// Token of the answer the approving device sends, to know when the relay has read it.
const ANSWER_TOKEN: u64 = 1;

// ---------------------------------------------------------------------------------------------
// The device already on the account
// ---------------------------------------------------------------------------------------------

/// A device asking to join, as the approving device sees it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Asking {
    /// Its request id, which approving or declining names.
    pub request_id: [u8; REQUEST_ID_LEN],
    /// What it says it is called.
    pub name: String,
    /// What it says it runs.
    pub os: String,
    /// The six digits it shows, which the person compares.
    pub comparison: String,
}

/// How an invitation ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InviteOutcome {
    /// A device was approved and the account key sent to it. Carries its name.
    Approved(String),
    /// The request was turned down.
    Declined,
    /// Ten minutes passed, or the person closed it.
    Expired,
    /// Something went wrong that the person needs to know about.
    Failed(String),
}

/// What the window shows while an invitation is open.
#[derive(Debug, Clone, Default)]
pub struct InviteView {
    /// Whether the meeting connection is up, so requests can arrive.
    pub listening: bool,
    /// Devices asking, oldest first.
    pub asking: Vec<Asking>,
    /// Set once it is over.
    pub outcome: Option<InviteOutcome>,
}

#[derive(Debug, Clone, Copy)]
enum InviteCommand {
    Approve([u8; REQUEST_ID_LEN]),
    Decline([u8; REQUEST_ID_LEN]),
}

/// An open invitation: a join code, and the conversation behind it.
pub struct Invitation {
    code: Zeroizing<String>,
    expires_at_ms: u64,
    view: Arc<Mutex<InviteView>>,
    commands: mpsc::UnboundedSender<InviteCommand>,
    cancel: Arc<AtomicBool>,
}

/// What the approving device needs to answer a request.
pub struct Approver {
    /// The relay both devices meet on.
    pub relay_url: String,
    /// This device's own keys, whose fingerprint the code carries.
    pub device: DeviceKeys,
    /// The account key, which the approval hands over.
    pub account_secret: Zeroizing<[u8; 32]>,
    /// Whether the account key has never been shown in an old style join token.
    pub never_exported: bool,
}

impl Invitation {
    /// Makes a join code and starts waiting for the device that types it.
    ///
    /// # Errors
    ///
    /// Returns an error if randomness fails or the thread cannot be started.
    pub fn open(approver: Approver) -> crate::error::Result<Self> {
        let code = JoinCode::generate(&approver.device)?;
        let text = code.encode();
        let expires_at_ms = client::now_ms() + enroll::CODE_LIFETIME_MS;
        let view = Arc::new(Mutex::new(InviteView::default()));
        let cancel = Arc::new(AtomicBool::new(false));
        let (commands, command_rx) = mpsc::unbounded_channel();

        let thread_view = Arc::clone(&view);
        let thread_cancel = Arc::clone(&cancel);
        std::thread::Builder::new()
            .name("asli-invite".to_owned())
            .spawn(move || {
                let outcome = run_invitation(
                    &code,
                    &approver,
                    expires_at_ms,
                    &thread_view,
                    command_rx,
                    &thread_cancel,
                );
                eprintln!("{}", log_line("invite_closed", &format!("{outcome:?}")));
                if let Ok(mut view) = thread_view.lock() {
                    view.listening = false;
                    view.outcome = Some(outcome);
                }
            })
            .map_err(crate::error::Error::Io)?;

        Ok(Self {
            code: text,
            expires_at_ms,
            view,
            commands,
            cancel,
        })
    }

    /// The join code to show.
    #[must_use]
    pub fn code(&self) -> &str {
        &self.code
    }

    /// When the code stops working, in milliseconds since the Unix epoch.
    #[must_use]
    pub const fn expires_at_ms(&self) -> u64 {
        self.expires_at_ms
    }

    /// What to show now.
    #[must_use]
    pub fn view(&self) -> InviteView {
        self.view
            .lock()
            .map(|view| view.clone())
            .unwrap_or_default()
    }

    /// Approves one request: the account key goes to that device.
    pub fn approve(&self, request_id: [u8; REQUEST_ID_LEN]) {
        let _ = self.commands.send(InviteCommand::Approve(request_id));
    }

    /// Turns one request down.
    pub fn decline(&self, request_id: [u8; REQUEST_ID_LEN]) {
        let _ = self.commands.send(InviteCommand::Decline(request_id));
    }

    /// Closes the invitation. The code stops working at once.
    pub fn close(&self) {
        self.cancel.store(true, Ordering::Relaxed);
    }
}

impl Drop for Invitation {
    fn drop(&mut self) {
        self.close();
    }
}

/// What the event handler and the answer pump share for one invitation.
#[derive(Default)]
struct Shared {
    /// Requests as received, for the keys an approval is sealed to.
    requests: Vec<JoinRequest>,
    /// The answer chosen, and its frame body, until the relay confirms reading it.
    answer: Option<(MsgKind, Vec<u8>, InviteOutcome)>,
    /// Set once the relay has read the answer.
    confirmed: bool,
}

fn run_invitation(
    code: &JoinCode,
    approver: &Approver,
    expires_at_ms: u64,
    view: &Arc<Mutex<InviteView>>,
    mut command_rx: mpsc::UnboundedReceiver<InviteCommand>,
    cancel: &Arc<AtomicBool>,
) -> InviteOutcome {
    let Ok(runtime) = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    else {
        return InviteOutcome::Failed("could not start".to_owned());
    };
    let meeting = code.meeting();
    let room = meeting.room_id_bytes();
    // A meeting session has no device id worth announcing and no device information, so it sends
    // nothing of its own: no card, no announcement, no clip.
    let mut session = Session::new(meeting, [0u8; 16], 0);
    let shared = Arc::new(Mutex::new(Shared::default()));

    runtime.block_on(async {
        loop {
            let over = || cancel.load(Ordering::Relaxed) || client::now_ms() >= expires_at_ms;
            if over() {
                return InviteOutcome::Expired;
            }
            let (local_tx, mut local_rx) = mpsc::channel::<LocalEvent>(8);

            let mut on_event = |event: ClientEvent| match event {
                ClientEvent::Authenticated { .. } => set_listening(view, true),
                ClientEvent::Message {
                    kind: MsgKind::JoinRequest,
                    body,
                } => take_request(code, &room, &body, &shared, view),
                ClientEvent::Sent { token } if token == ANSWER_TOKEN => {
                    if let Ok(mut shared) = shared.lock() {
                        shared.confirmed = true;
                    }
                }
                _ => {}
            };

            // Sends what the person decides, again after a reconnect if the relay never confirmed
            // it, and ends the connection once it has, or when the code expires or is closed.
            let pump = async {
                let resend = shared
                    .lock()
                    .ok()
                    .and_then(|s| s.answer.as_ref().map(|(kind, body, _)| (*kind, body.clone())));
                if let Some((kind, body)) = resend {
                    let _ = local_tx.send(answer_event(kind, body)).await;
                }
                loop {
                    let done = shared.lock().map_or(true, |s| s.confirmed);
                    if done || over() {
                        return;
                    }
                    tokio::select! {
                        () = tokio::time::sleep(Duration::from_millis(250)) => {}
                        command = command_rx.recv() => {
                            let Some(command) = command else { return };
                            if let Some((kind, body)) = decide(command, approver, &room, &shared) {
                                let _ = local_tx.send(answer_event(kind, body)).await;
                            }
                        }
                    }
                }
            };

            let result = tokio::select! {
                result = client::run_once(&approver.relay_url, &mut session, &mut local_rx, &mut on_event) => Some(result),
                () = pump => None,
            };
            set_listening(view, false);

            if let Ok(shared) = shared.lock() {
                if shared.confirmed {
                    if let Some((_, _, outcome)) = &shared.answer {
                        return outcome.clone();
                    }
                }
            }
            if result.is_none() && over() {
                return InviteOutcome::Expired;
            }
            if let Some(Err(err)) = result {
                eprintln!("{}", log_line("invite_connection", &err.to_string()));
            }
            tokio::time::sleep(RECONNECT_AFTER).await;
        }
    })
}

fn answer_event(kind: MsgKind, body: Vec<u8>) -> LocalEvent {
    LocalEvent::Message {
        kind,
        body,
        to: None,
        token: Some(ANSWER_TOKEN),
    }
}

/// Records a request the first time its id is seen, and shows it.
fn take_request(
    code: &JoinCode,
    room: &[u8; 16],
    body: &[u8],
    shared: &Arc<Mutex<Shared>>,
    view: &Arc<Mutex<InviteView>>,
) {
    let Ok(request) = JoinRequest::decode(body, room) else {
        return;
    };
    let Ok(mut shared) = shared.lock() else {
        return;
    };
    if shared.answer.is_some()
        || shared.requests.len() >= MAX_REQUESTS
        || shared
            .requests
            .iter()
            .any(|known| known.request_id == request.request_id)
    {
        return;
    }
    let asking = Asking {
        request_id: request.request_id,
        name: request.name.clone(),
        os: request.os.clone(),
        comparison: code.comparison_code(&request),
    };
    eprintln!("{}", log_line("join_requested", &asking.os));
    shared.requests.push(request);
    if let Ok(mut view) = view.lock() {
        view.asking.push(asking);
    }
}

/// Turns the person's decision into the answer to send. Only the first decision counts: the code
/// is single use, so once a device has been answered nothing else is.
fn decide(
    command: InviteCommand,
    approver: &Approver,
    room: &[u8; 16],
    shared: &Arc<Mutex<Shared>>,
) -> Option<(MsgKind, Vec<u8>)> {
    let mut shared = shared.lock().ok()?;
    if shared.answer.is_some() {
        return None;
    }
    let (kind, body, outcome) = match command {
        InviteCommand::Approve(id) => {
            let request = shared.requests.iter().find(|r| r.request_id == id)?;
            let body = enroll::grant(
                &approver.device,
                room,
                request,
                &approver.account_secret,
                approver.never_exported,
            )
            .ok()?;
            (
                MsgKind::JoinGrant,
                body,
                InviteOutcome::Approved(request.name.clone()),
            )
        }
        InviteCommand::Decline(id) => {
            let body = enroll::decline(&approver.device, room, &id).ok()?;
            (MsgKind::JoinDecline, body, InviteOutcome::Declined)
        }
    };
    shared.answer = Some((kind, body.clone(), outcome));
    Some((kind, body))
}

fn set_listening(view: &Arc<Mutex<InviteView>>, listening: bool) {
    if let Ok(mut view) = view.lock() {
        view.listening = listening;
    }
}

// ---------------------------------------------------------------------------------------------
// The new device
// ---------------------------------------------------------------------------------------------

/// How asking to join ended.
pub enum JoinOutcome {
    /// Approved: the account key, and whether it has never been in an old style token.
    Granted {
        /// The account key.
        secret: Zeroizing<[u8; 32]>,
        /// Whether it has never been shown in an old style join token.
        never_exported: bool,
    },
    /// The other device turned it down.
    Declined,
    /// Ten minutes passed, or the person gave up.
    Expired,
    /// Something went wrong that the person needs to know about.
    Failed(String),
}

impl std::fmt::Debug for JoinOutcome {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Granted { .. } => f.write_str("Granted"),
            Self::Declined => f.write_str("Declined"),
            Self::Expired => f.write_str("Expired"),
            Self::Failed(why) => write!(f, "Failed({why})"),
        }
    }
}

/// What the new device shows while it waits.
#[derive(Debug, Default)]
pub struct JoinView {
    /// Whether the meeting connection is up and the request has gone out.
    pub asked: bool,
    /// Set once it is over.
    pub outcome: Option<JoinOutcome>,
}

/// A request to join, waiting for its answer.
pub struct JoinAttempt {
    comparison: String,
    view: Arc<Mutex<JoinView>>,
    cancel: Arc<AtomicBool>,
}

/// Who is asking.
pub struct Joiner {
    /// The relay both devices meet on.
    pub relay_url: String,
    /// This device's own keys, which the account key will be sealed to.
    pub device: DeviceKeys,
    /// The id this device will use on the account.
    pub device_id: [u8; 16],
    /// What to call it.
    pub name: String,
    /// What it runs.
    pub os: String,
}

impl JoinAttempt {
    /// Starts asking to join with a code that has already been parsed.
    ///
    /// # Errors
    ///
    /// Returns an error if randomness fails or the thread cannot be started.
    pub fn start(code: JoinCode, joiner: Joiner) -> crate::error::Result<Self> {
        let request = JoinRequest {
            request_id: asli_crypto::random::bytes()?,
            device_id: joiner.device_id,
            sign_pub: joiner.device.sign_pub(),
            box_pub: joiner.device.box_pub(),
            ts_ms: client::now_ms(),
            name: asli_crypto::announce::truncate_utf8(&joiner.name, 64).to_owned(),
            os: asli_crypto::announce::truncate_utf8(&joiner.os, 64).to_owned(),
        };
        let comparison = code.comparison_code(&request);
        let view = Arc::new(Mutex::new(JoinView::default()));
        let cancel = Arc::new(AtomicBool::new(false));

        let thread_view = Arc::clone(&view);
        let thread_cancel = Arc::clone(&cancel);
        std::thread::Builder::new()
            .name("asli-join".to_owned())
            .spawn(move || {
                let outcome = run_join(&code, &joiner, &request, &thread_view, &thread_cancel);
                eprintln!("{}", log_line("join_closed", &format!("{outcome:?}")));
                if let Ok(mut view) = thread_view.lock() {
                    view.outcome = Some(outcome);
                }
            })
            .map_err(crate::error::Error::Io)?;

        Ok(Self {
            comparison,
            view,
            cancel,
        })
    }

    /// The six digits this device shows, which the approving device must show too.
    #[must_use]
    pub fn comparison(&self) -> &str {
        &self.comparison
    }

    /// Whether the request has gone out.
    #[must_use]
    pub fn asked(&self) -> bool {
        self.view.lock().is_ok_and(|view| view.asked)
    }

    /// Takes the outcome once there is one. Returns it once.
    #[must_use]
    pub fn take_outcome(&self) -> Option<JoinOutcome> {
        self.view
            .lock()
            .ok()
            .and_then(|mut view| view.outcome.take())
    }

    /// Gives up waiting.
    pub fn cancel(&self) {
        self.cancel.store(true, Ordering::Relaxed);
    }
}

impl Drop for JoinAttempt {
    fn drop(&mut self) {
        self.cancel();
    }
}

fn run_join(
    code: &JoinCode,
    joiner: &Joiner,
    request: &JoinRequest,
    view: &Arc<Mutex<JoinView>>,
    cancel: &Arc<AtomicBool>,
) -> JoinOutcome {
    let Ok(runtime) = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    else {
        return JoinOutcome::Failed("could not start".to_owned());
    };
    let meeting = code.meeting();
    let room = meeting.room_id_bytes();
    let Ok(body) = request.encode(&joiner.device, &room) else {
        return JoinOutcome::Failed("could not sign the request".to_owned());
    };
    let mut session = Session::new(meeting, [0u8; 16], 0);
    let gives_up_at = client::now_ms() + enroll::CODE_LIFETIME_MS;
    let outcome: Arc<Mutex<Option<JoinOutcome>>> = Arc::new(Mutex::new(None));

    runtime.block_on(async {
        loop {
            let over = || cancel.load(Ordering::Relaxed) || client::now_ms() >= gives_up_at;
            if over() {
                return JoinOutcome::Expired;
            }
            let (local_tx, mut local_rx) = mpsc::channel::<LocalEvent>(8);

            let mut on_event = |event: ClientEvent| {
                let found = match event {
                    ClientEvent::Message {
                        kind: MsgKind::JoinGrant,
                        body,
                    } => enroll::open_grant(code, &room, &joiner.device, &request.request_id, &body)
                        .ok()
                        .map(|granted| JoinOutcome::Granted {
                            secret: granted.secret,
                            never_exported: granted.never_exported,
                        }),
                    ClientEvent::Message {
                        kind: MsgKind::JoinDecline,
                        body,
                    } => enroll::is_decline_for(code, &room, &request.request_id, &body)
                        .then_some(JoinOutcome::Declined),
                    _ => None,
                };
                if let Some(found) = found {
                    if let Ok(mut slot) = outcome.lock() {
                        slot.get_or_insert(found);
                    }
                }
            };

            // Asks, and asks again, until answered: the approving device may connect after this
            // one, or reconnect, and the relay keeps nothing for it.
            let asker = async {
                loop {
                    let answered = outcome.lock().map_or(true, |slot| slot.is_some());
                    if answered || over() {
                        return;
                    }
                    // Queued, not awaited: before the handshake it waits in the channel and goes out
                    // as soon as the connection is ready, and a full channel only means one is
                    // already waiting.
                    let queued = local_tx.try_send(LocalEvent::Message {
                        kind: MsgKind::JoinRequest,
                        body: body.clone(),
                        to: None,
                        token: None,
                    });
                    if queued.is_ok() {
                        if let Ok(mut view) = view.lock() {
                            view.asked = true;
                        }
                    }
                    for _ in 0..(ASK_EVERY.as_millis() / 250) {
                        let answered = outcome.lock().map_or(true, |slot| slot.is_some());
                        if answered || over() {
                            return;
                        }
                        tokio::time::sleep(Duration::from_millis(250)).await;
                    }
                }
            };

            let result = tokio::select! {
                result = client::run_once(&joiner.relay_url, &mut session, &mut local_rx, &mut on_event) => Some(result),
                () = asker => None,
            };
            if let Some(done) = outcome.lock().ok().and_then(|mut slot| slot.take()) {
                return done;
            }
            if result.is_none() && over() {
                return JoinOutcome::Expired;
            }
            if let Some(Err(err)) = result {
                eprintln!("{}", log_line("join_connection", &err.to_string()));
            }
            tokio::time::sleep(RECONNECT_AFTER).await;
        }
    })
}
