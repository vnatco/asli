//! Puts a PNG on the clipboard through the backend, so the write path can be checked with
//! `wl-paste`.
//!
//! ```sh
//! cargo run -p asli-clipboard --example put_image -- /path/to/file.png
//! ```
//!
//! Wayland has no clipboard storage: the owner serves the bytes on demand, so this has to keep
//! running for the content to stay available. It exits when stdin closes.

fn main() {
    let Some(path) = std::env::args().nth(1) else {
        eprintln!("usage: put_image <file.png>");
        std::process::exit(2);
    };

    let png = match std::fs::read(&path) {
        Ok(bytes) => bytes,
        Err(err) => {
            eprintln!("could not read {path}: {err}");
            std::process::exit(1);
        }
    };
    println!("read {} bytes from {path}", png.len());

    #[cfg(target_os = "linux")]
    {
        use asli_clipboard::linux_wayland::WaylandClipboard;
        use asli_clipboard::ClipboardWatcher;

        let mut clipboard = match WaylandClipboard::connect() {
            Ok(clipboard) => clipboard,
            Err(err) => {
                eprintln!("could not connect: {err}");
                std::process::exit(1);
            }
        };

        if let Err(err) = clipboard.set_image(&png) {
            eprintln!("could not offer the image: {err}");
            std::process::exit(1);
        }
        println!("offering image/png, waiting so the compositor can request it");

        let shutdown = clipboard.shutdown_handle();
        std::thread::spawn(move || {
            let mut line = String::new();
            let _ = std::io::stdin().read_line(&mut line);
            shutdown.store(true, std::sync::atomic::Ordering::Relaxed);
        });

        // The run loop is what answers the compositor's request for the bytes.
        if let Err(err) = clipboard.run(&mut |_| {}) {
            eprintln!("watcher stopped: {err}");
        }
    }

    #[cfg(not(target_os = "linux"))]
    {
        eprintln!("this example only supports Linux so far");
        std::process::exit(1);
    }
}
