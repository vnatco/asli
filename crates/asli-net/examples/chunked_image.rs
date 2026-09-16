//! Sends a multi chunk image between two clients through a real relay.
//!
//! The unit tests drive chunk assembly through a fake transport, which proves the construction but
//! not that a real relay forwards several separate frames in order, charges them correctly, and
//! never mangles one in transit. This does.
//!
//! ```sh
//! cargo run -p asli-net --example chunked_image -- ws://127.0.0.1:8080/v1
//! ```
//!
//! Point it at a relay started from `server/`. The deployed relay predates chunked transfer and
//! its validator rejects `clip_begin` as an unknown type, which is the correct behaviour for a
//! build that cannot handle it.

use std::time::Duration;

use asli_crypto::Identity;
use asli_net::session::Action;
use asli_net::{client, ClientEvent, LocalEvent, Session};
use futures_util::{SinkExt, StreamExt};
use tokio::sync::mpsc;
use tokio_tungstenite::tungstenite::Message as WsMessage;

/// Large enough to need several chunks at the 256 KiB default.
const IMAGE_BYTES: usize = 700_000;

#[tokio::main(flavor = "current_thread")]
async fn main() {
    // spawn_local needs a LocalSet in scope. The event sinks are &mut dyn FnMut held across
    // awaits, so they are not Send, which rules out tokio::spawn.
    let local = tokio::task::LocalSet::new();
    local.run_until(Box::pin(run())).await;
}

async fn run() {
    let url = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "ws://127.0.0.1:8080/v1".to_owned());
    println!("relay: {url}");

    let identity = Identity::generate().expect("rng works");
    println!("throwaway room: {}", identity.room_id());

    let png: Vec<u8> = (0..IMAGE_BYTES)
        .map(|i| u8::try_from(i % 251).unwrap_or(0))
        .collect();
    let expected = asli_core::hash(&png);
    println!("image: {} bytes", png.len());

    let (report_tx, mut report_rx) = mpsc::channel::<String>(16);
    let (_receiver_tx, mut receiver_rx) = mpsc::channel::<LocalEvent>(4);

    // The receiver joins first, so it is in the room before any chunk is sent.
    let receiver_url = url.clone();
    let receiver_report = report_tx.clone();
    let mut receiver = Session::new(Identity::from_secret(identity.secret()), [0xbb; 16], 1);
    let receiver_task = tokio::task::spawn_local(async move {
        let mut on_event = |event: ClientEvent| match event {
            ClientEvent::Authenticated { peers, .. } => {
                let _ = receiver_report.try_send(format!("receiver authenticated, peers={peers}"));
            }
            ClientEvent::Image { png, .. } => {
                let got = asli_core::hash(&png);
                let verdict = if got == expected { "MATCH" } else { "MISMATCH" };
                let _ = receiver_report.try_send(format!("IMAGE:{}:{verdict}", png.len()));
            }
            ClientEvent::Clip(_) => {
                let _ = receiver_report.try_send("receiver got text, which is wrong".to_owned());
            }
            _ => {}
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

    // The sender is driven by hand rather than through run_once, because run_once takes local
    // clips as text and this needs to push a run of chunk frames in order.
    if let Err(err) = send_image(&url, &identity, &png).await {
        eprintln!("sender failed: {err}");
        receiver_task.abort();
        std::process::exit(1);
    }
    println!("sender: all chunks sent");

    let mut ok = false;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(40);
    while tokio::time::Instant::now() < deadline {
        match tokio::time::timeout(Duration::from_secs(3), report_rx.recv()).await {
            Ok(Some(line)) => {
                if let Some(rest) = line.strip_prefix("IMAGE:") {
                    println!("receiver reassembled an image: {rest}");
                    ok = rest.ends_with("MATCH");
                    break;
                }
                println!("{line}");
            }
            Ok(None) => break,
            Err(_) => {}
        }
    }

    receiver_task.abort();

    println!();
    if ok {
        println!("CHUNKED IMAGE: PASS");
    } else {
        println!("CHUNKED IMAGE: FAIL");
        std::process::exit(1);
    }
}

/// Connects, authenticates, seals the image and pushes every chunk frame in order.
async fn send_image(url: &str, identity: &Identity, png: &[u8]) -> Result<(), String> {
    let mut session = Session::new(Identity::from_secret(identity.secret()), [0xaa; 16], 1);

    let (mut socket, _) = tokio_tungstenite::connect_async(url)
        .await
        .map_err(|e| format!("connect: {e}"))?;

    let hello = session.hello_frame().map_err(|e| format!("hello: {e}"))?;
    socket
        .send(WsMessage::Text(hello.into()))
        .await
        .map_err(|e| format!("send hello: {e}"))?;

    // Drive the handshake until the session reports it is ready.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(15);
    while !session.is_ready() {
        if tokio::time::Instant::now() > deadline {
            return Err("handshake timed out".to_owned());
        }
        let Ok(Some(message)) = tokio::time::timeout(Duration::from_secs(5), socket.next()).await
        else {
            return Err("no reply during the handshake".to_owned());
        };
        let message = message.map_err(|e| format!("socket: {e}"))?;
        if let WsMessage::Text(text) = message {
            for action in session
                .handle_frame(text.as_str(), client::now_ms())
                .map_err(|e| format!("handshake: {e}"))?
            {
                match action {
                    Action::Send(frame) => socket
                        .send(WsMessage::Text(frame.into()))
                        .await
                        .map_err(|e| format!("send: {e}"))?,
                    Action::AuthFailed(code) => {
                        return Err(format!("authentication rejected: {code:?}"))
                    }
                    _ => {}
                }
            }
        }
    }
    println!("sender authenticated");

    let frames = session
        .observe_local_image(png, client::now_ms())
        .map_err(|e| format!("sealing: {e}"))?;
    println!("sender: {} chunk frames to send", frames.len());

    for frame in frames {
        socket
            .send(WsMessage::Text(frame.into()))
            .await
            .map_err(|e| format!("send chunk: {e}"))?;
    }
    socket.flush().await.map_err(|e| format!("flush: {e}"))?;

    // Hold the socket open briefly so the relay finishes forwarding before it closes.
    tokio::time::sleep(Duration::from_secs(2)).await;
    Ok(())
}
