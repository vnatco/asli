//! Acts as a second device on an existing account, for soak testing.
//!
//! `live_relay.rs` creates its own throwaway account, which is right for proving the transport
//! works but useless for testing a running daemon: the two would never share a room. This joins
//! the account a daemon is already using, so the daemon sees a real peer and we can watch what
//! actually crosses the relay.
//!
//! ```sh
//! cargo run -p asli-net --example peer -- <join-token> [relay-url] [--send-every-secs N]
//! ```
//!
//! It prints one line per received clip with a size and a hash prefix, never the content, and
//! optionally sends its own clips on a timer so the daemon's receive path gets exercised too.

use std::time::Duration;

use asli_crypto::{token, Identity};
use asli_net::{client, ClientEvent, Session};
use tokio::sync::mpsc;

const DEFAULT_URL: &str = "wss://asli.vnat.dev/v1";

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let local = tokio::task::LocalSet::new();
    // Boxed because the event enum grew with image support and the composed future is now large
    // enough that keeping it on the stack is wasteful.
    Box::pin(local.run_until(run())).await;
}

async fn run() {
    let mut args = std::env::args().skip(1);
    let Some(join_token) = args.next() else {
        eprintln!("usage: peer <join-token> [relay-url] [--send-every-secs N]");
        std::process::exit(2);
    };

    let rest: Vec<String> = args.collect();
    let url = rest
        .iter()
        .find(|a| a.starts_with("ws"))
        .cloned()
        .unwrap_or_else(|| DEFAULT_URL.to_owned());
    let send_every = rest
        .iter()
        .position(|a| a == "--send-every-secs")
        .and_then(|i| rest.get(i + 1))
        .and_then(|v| v.parse::<u64>().ok());

    let secret = match token::parse(&join_token) {
        Ok(secret) => secret,
        Err(err) => {
            eprintln!("bad join token: {err}");
            std::process::exit(2);
        }
    };

    let identity = Identity::from_secret(&secret);
    println!("peer joining room {}", identity.room_id());
    println!("relay {url}");

    // A device id the daemon will never use, so neither side mistakes the other for itself.
    let mut session = Session::new(identity, [0xfe; 16], 1);

    let (tx, mut rx) = mpsc::channel::<String>(8);

    if let Some(secs) = send_every {
        println!("peer will send a clip every {secs}s");
        tokio::task::spawn_local(async move {
            let mut n = 0u32;
            loop {
                tokio::time::sleep(Duration::from_secs(secs)).await;
                n += 1;
                let text = format!("peer clip {n}");
                // Logged so a soak can tell the difference between "sent nothing" and
                // "sent but the other side never wrote it to the clipboard".
                println!("peer sending #{n}: {} bytes", text.len());
                if tx.send(text).await.is_err() {
                    return;
                }
            }
        });
    }

    let mut received = 0u32;
    let mut on_event = |event: ClientEvent| match event {
        ClientEvent::Authenticated { peers, .. } => {
            println!("peer authenticated, {peers} connected");
        }
        ClientEvent::Clip(clip) => {
            received += 1;
            let digest = asli_core::hash(clip.text.as_bytes());
            println!(
                "peer received #{received}: {} bytes, hash {:02x}{:02x}{:02x}{:02x}, retained={}",
                clip.text.len(),
                digest[0],
                digest[1],
                digest[2],
                digest[3],
                clip.retained
            );
        }
        ClientEvent::Presence { peers } => println!("peer sees {peers} connected"),
        other => println!("peer event: {other:?}"),
    };

    match client::run_once(&url, &mut session, &mut rx, &mut on_event).await {
        Ok(reason) => println!("peer disconnected: {reason:?}"),
        Err(err) => {
            eprintln!("peer failed: {err}");
            std::process::exit(1);
        }
    }
}
