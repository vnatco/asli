//! Round trips a clip between two clients through a real relay.
//!
//! Everything else in this crate is tested against `FakeTransport`, which is the right default:
//! it makes replay, rollback and staleness testable with no sockets. But it cannot tell us
//! whether `connect_async` negotiates TLS correctly, whether a reverse proxy tunnels the upgrade,
//! or whether the relay on the other side agrees with us about the wire format. This does.
//!
//! ```sh
//! cargo run -p asli-net --example live_relay -- wss://asli.vnat.dev/v1
//! ```
//!
//! It creates a throwaway account, so it never touches a real one, and it prints no clipboard
//! content beyond the short marker it generated itself.

use std::time::Duration;

use asli_crypto::Identity;
use asli_net::{client, ClientEvent, LocalEvent, Session};
use tokio::sync::mpsc;

const DEFAULT_URL: &str = "wss://asli.vnat.dev/v1";

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let local = tokio::task::LocalSet::new();
    local.run_until(run()).await;
}

async fn run() {
    let url = std::env::args()
        .nth(1)
        .unwrap_or_else(|| DEFAULT_URL.to_owned());
    println!("relay: {url}");

    // One account, two devices, which is exactly the real topology.
    let identity = Identity::generate().expect("rng works");
    let room = identity.room_id();
    println!("throwaway room: {room}");

    let sender_identity = Identity::from_secret(identity.secret());
    let receiver_identity = Identity::from_secret(identity.secret());

    let mut sender = Session::new(sender_identity, [0xaa; 16], 1);
    let mut receiver = Session::new(receiver_identity, [0xbb; 16], 1);

    let marker = format!("asli live check {}", client::now_ms());

    let (sender_tx, mut sender_rx) = mpsc::channel::<LocalEvent>(4);
    let (_receiver_tx, mut receiver_rx) = mpsc::channel::<LocalEvent>(4);

    let (report_tx, mut report_rx) = mpsc::channel::<String>(8);

    // The receiver connects first, so it is already in the room when the clip is sent. Nothing in
    // the protocol requires that, but it keeps this check about the round trip rather than about
    // retention.
    let receiver_url = url.clone();
    let receiver_report = report_tx.clone();
    let receiver_task = tokio::task::spawn_local(async move {
        let mut on_event = |event: ClientEvent| match event {
            ClientEvent::Authenticated { peers, .. } => {
                let _ = receiver_report.try_send(format!("receiver authenticated, peers={peers}"));
            }
            ClientEvent::Clip(clip) => {
                let _ = receiver_report.try_send(format!("CLIP:{}", clip.text));
            }
            ClientEvent::Presence { peers } => {
                let _ = receiver_report.try_send(format!("receiver sees peers={peers}"));
            }
            other => {
                let _ = receiver_report.try_send(format!("receiver event: {other:?}"));
            }
        };
        client::run_once(
            &receiver_url,
            &mut receiver,
            &mut receiver_rx,
            &mut on_event,
        )
        .await
    });

    tokio::time::sleep(Duration::from_secs(2)).await;

    let sender_url = url.clone();
    let sender_report = report_tx.clone();
    let sender_marker = marker.clone();
    let sender_task = tokio::task::spawn_local(async move {
        let mut on_event = |event: ClientEvent| match event {
            ClientEvent::Authenticated { peers, .. } => {
                let _ = sender_report.try_send(format!("sender authenticated, peers={peers}"));
            }
            ClientEvent::Clip(_) => {
                // The relay must exclude the sender. Seeing our own clip here is a failure.
                let _ = sender_report.try_send("SENDER_ECHO".to_owned());
            }
            other => {
                let _ = sender_report.try_send(format!("sender event: {other:?}"));
            }
        };
        let send_later = async {
            tokio::time::sleep(Duration::from_secs(2)).await;
            let _ = sender_tx.send(LocalEvent::Text(sender_marker)).await;
        };
        let (result, ()) = tokio::join!(
            client::run_once(&sender_url, &mut sender, &mut sender_rx, &mut on_event),
            send_later
        );
        result
    });

    let (delivered, echoed) = collect_outcome(&mut report_rx, &marker).await;

    sender_task.abort();
    receiver_task.abort();

    println!();
    println!("delivered to the other device: {delivered}");
    println!("sender excluded from its own clip: {}", !echoed);
    if delivered && !echoed {
        println!("LIVE RELAY: PASS");
    } else {
        println!("LIVE RELAY: FAIL");
        std::process::exit(1);
    }
}

/// Watches the two clients report in, and decides whether the round trip worked.
///
/// Split out because setting up two clients and judging the result are separate jobs, and the
/// judging half is the part worth reading on its own.
async fn collect_outcome(report_rx: &mut mpsc::Receiver<String>, marker: &str) -> (bool, bool) {
    let mut delivered = false;
    let mut echoed = false;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(25);

    while tokio::time::Instant::now() < deadline {
        match tokio::time::timeout(Duration::from_secs(3), report_rx.recv()).await {
            Ok(Some(line)) => {
                if let Some(text) = line.strip_prefix("CLIP:") {
                    println!("receiver got a clip, matches: {}", text == marker);
                    delivered = text == marker;
                    if delivered {
                        break;
                    }
                } else if line == "SENDER_ECHO" {
                    echoed = true;
                    println!("sender received its own clip, which it must not");
                } else {
                    println!("{line}");
                }
            }
            Ok(None) => break,
            Err(_) => {}
        }
    }

    // Give the sender a moment to reveal an echo that arrived after delivery.
    tokio::time::sleep(Duration::from_millis(500)).await;
    while let Ok(line) = report_rx.try_recv() {
        if line == "SENDER_ECHO" {
            echoed = true;
        }
    }

    (delivered, echoed)
}
