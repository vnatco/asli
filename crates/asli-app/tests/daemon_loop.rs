//! The loop prevention test.
//!
//! Two devices share one account. One copies, the other receives and writes. The write must not
//! come back out again. Every competing tool in this space has shipped that bug at least once,
//! and the symptom is two machines trading the same text until something falls over, so it is
//! worth asserting directly rather than trusting the layering.

use asli_app::clipboard_io::StubClipboard;
use asli_app::daemon::{on_action, Status};
use asli_crypto::Identity;
use asli_net::envelope::{AuthOk, Challenge, Limits, Message};
use asli_net::session::{pump, Action, FakeTransport, Session};

const NOW_MS: u64 = 1_767_225_600_000;
const DEVICE_A: [u8; 16] = [0xaa; 16];
const DEVICE_B: [u8; 16] = [0xbb; 16];
const SECRET: [u8; 32] = [42u8; 32];

fn limits() -> Limits {
    Limits {
        max_frame_bytes: 1024 * 1024,
        max_content_bytes: 700 * 1024,
        retain_max_bytes: 64 * 1024,
        msgs_per_sec: 2,
        room_bytes_per_day: 50 * 1024 * 1024,
    }
}

fn challenge_frame() -> String {
    Message::Challenge(Challenge {
        v: 1,
        suite: asli_crypto::SUITE.to_owned(),
        enc: "json".to_owned(),
        nonce_s: vec![7u8; 32],
        server_time_ms: NOW_MS,
        limits: limits(),
    })
    .to_frame()
    .expect("challenge serializes")
}

fn auth_ok_frame() -> String {
    Message::AuthOk(AuthOk {
        v: 1,
        conn_id: "c1".to_owned(),
        peers: 2,
        has_retained: false,
        stored_at: None,
    })
    .to_frame()
    .expect("auth_ok serializes")
}

/// Brings a session all the way to ready, the way a real relay would.
fn ready_session(device_id: [u8; 16]) -> (Session, FakeTransport) {
    let identity = Identity::from_secret(&SECRET);
    let mut session = Session::new(identity, device_id, 0);
    let mut transport = FakeTransport::default();

    let hello = session.hello_frame().expect("hello");
    assert!(hello.contains("hello"), "the first frame is hello");

    transport.deliver(challenge_frame());
    transport.deliver(auth_ok_frame());
    let actions = pump(&mut session, &mut transport, NOW_MS).expect("handshake");

    assert!(
        actions
            .iter()
            .any(|a| matches!(a, Action::Authenticated { .. })),
        "the handshake should have completed, got {actions:?}"
    );
    assert!(session.is_ready());

    (session, transport)
}

#[test]
fn a_local_copy_leaves_as_ciphertext() {
    let (mut session, _transport) = ready_session(DEVICE_A);

    let frame = session
        .observe_local("the quick brown fox", NOW_MS)
        .expect("seals")
        .expect("there is something to send");

    assert!(
        !frame.contains("the quick brown fox"),
        "the plaintext must never appear on the wire"
    );

    let message = Message::parse(&frame).expect("parses");
    match message {
        Message::Clip(clip) => {
            assert_eq!(clip.v, 1);
            assert_eq!(clip.msg_id.len(), 16);
            assert_eq!(clip.n.len(), 24);
            assert!(!clip.ct.is_empty());
        }
        other => panic!("expected a clip, got {other:?}"),
    }
}

#[test]
fn a_received_clip_is_written_once_and_never_echoed() {
    // Device B copies something.
    let (mut sender, _sender_transport) = ready_session(DEVICE_B);
    let outgoing = sender
        .observe_local("copied on the other machine", NOW_MS)
        .expect("seals")
        .expect("something to send");

    // Device A receives it.
    let (mut receiver, mut transport) = ready_session(DEVICE_A);
    transport.deliver(outgoing);
    let actions = pump(&mut receiver, &mut transport, NOW_MS).expect("pump");

    let clipboard = StubClipboard::default();
    let mut status = Status::default();
    let mut written = 0;
    for action in &actions {
        if on_action(action, &clipboard, &mut status, NOW_MS) {
            written += 1;
        }
    }

    assert_eq!(written, 1, "exactly one write, got actions {actions:?}");
    assert_eq!(
        clipboard.writes(),
        vec!["copied on the other machine".to_owned()]
    );

    // The platform now reports our own write as a clipboard change. This is the moment the loop
    // would start.
    let echo = receiver
        .observe_local("copied on the other machine", NOW_MS + 5)
        .expect("no error");
    assert!(
        echo.is_none(),
        "writing a received clip must not send it straight back out"
    );
}

#[test]
fn an_identical_re_copy_inside_the_echo_window_still_syncs() {
    let (mut session, _transport) = ready_session(DEVICE_A);

    let first = session.observe_local("repeat me", NOW_MS).expect("seals");
    assert!(first.is_some(), "the first copy goes out");

    // Copying the same text twice in a row is a normal thing people do, and both copies must
    // reach the other machine. This used to fail: observe_local recorded what it sent into the
    // same echo guard it checks, so the second copy looked like an echo of the first. The guard
    // is only for suppressing the clipboard event our own write causes, which is seeded on the
    // receive path instead.
    let immediate = session
        .observe_local("repeat me", NOW_MS + 50)
        .expect("seals");
    assert!(
        immediate.is_some(),
        "a deliberate re-copy inside the echo window must still sync"
    );

    let later = session
        .observe_local("repeat me", NOW_MS + 60_000)
        .expect("seals");
    assert!(later.is_some(), "and so must one after the window");
}

#[test]
fn our_own_clip_coming_back_from_the_relay_is_ignored() {
    let (mut session, mut transport) = ready_session(DEVICE_A);

    let frame = session
        .observe_local("mine", NOW_MS)
        .expect("seals")
        .expect("something to send");

    // A relay that fails to exclude the sender, or a malicious one that replays, sends it back.
    transport.deliver(frame);
    let actions = pump(&mut session, &mut transport, NOW_MS).expect("pump");

    let clipboard = StubClipboard::default();
    let mut status = Status::default();
    for action in &actions {
        on_action(action, &clipboard, &mut status, NOW_MS);
    }

    assert!(
        clipboard.writes().is_empty(),
        "a clip from our own device id must never be applied, got {actions:?}"
    );
}

#[test]
fn a_clip_over_the_relay_limit_is_refused_locally() {
    let (mut session, _transport) = ready_session(DEVICE_A);

    let huge = "x".repeat(700 * 1024 + 1);
    let result = session.observe_local(&huge, NOW_MS);

    assert!(
        matches!(result, Err(asli_net::Error::ContentTooLarge { .. })),
        "oversize content should be refused with a reason, got {result:?}"
    );
}
