//! Manual smoke test for the clipboard backends on Linux, Windows and macOS.
//!
//! Run it, then copy something in any application and watch the events arrive:
//!
//! ```sh
//! cargo run -p asli-clipboard --example watch
//! ```
//!
//! By default it prints the size and a short hash prefix rather than the content, because the
//! project rule is that clipboard content never reaches a log. Pass `--show-content` when you are
//! debugging and know what is on your clipboard:
//!
//! ```sh
//! cargo run -p asli-clipboard --example watch -- --show-content
//! ```
//!
//! Press Enter to stop.

#[cfg(target_os = "linux")]
use std::sync::atomic::{AtomicBool, Ordering};
#[cfg(target_os = "linux")]
use std::sync::Arc;

#[cfg(target_os = "linux")]
use asli_clipboard::session::Backend;
use asli_clipboard::session::{self, Env};
use asli_clipboard::{ClipContent, ClipEvent, ClipboardWatcher};

fn main() {
    let show_content = std::env::args().any(|a| a == "--show-content");

    let env = Env::from_process();
    println!("desktop: {}", env.desktop_label());
    println!("session: {:?}", env.kind());

    let plan = match session::plan(&env) {
        Ok(plan) => plan,
        Err(err) => {
            eprintln!("cannot watch the clipboard here: {err}");
            std::process::exit(1);
        }
    };

    println!("backend: {:?}", plan.backend);
    println!("note:    {}", plan.note);
    if plan.degraded {
        println!("         (this is a compatibility path, not the preferred one)");
    }

    #[cfg(target_os = "linux")]
    run_linux(plan.backend, show_content);

    #[cfg(target_os = "windows")]
    run_windows(show_content);

    #[cfg(target_os = "macos")]
    run_macos(show_content);

    #[cfg(not(any(target_os = "linux", target_os = "windows", target_os = "macos")))]
    {
        let _ = show_content;
        eprintln!("this example supports Linux, Windows and macOS");
        std::process::exit(1);
    }
}

/// Polls on the main thread, which is where the application polls too.
#[cfg(target_os = "macos")]
fn run_macos(show_content: bool) {
    use asli_clipboard::macos::MacosClipboard;

    println!("read permission: {}", MacosClipboard::permission().label());
    let mut watcher = MacosClipboard::connect().unwrap_or_else(|err| {
        eprintln!("could not start: {err}");
        std::process::exit(1);
    });

    std::thread::spawn(|| {
        let mut line = String::new();
        let _ = std::io::stdin().read_line(&mut line);
        std::process::exit(0);
    });

    println!();
    println!("watching. copy something in another application. press Enter to stop.");

    let mut count = 0u32;
    if let Err(err) = watcher.run(&mut |event| {
        count += 1;
        report(count, &event, show_content);
    }) {
        eprintln!("watcher stopped: {err}");
        std::process::exit(1);
    }
}

#[cfg(target_os = "windows")]
fn run_windows(show_content: bool) {
    let mut watcher = asli_clipboard::windows::WindowsClipboard::connect().unwrap_or_else(|err| {
        eprintln!("could not start: {err}");
        std::process::exit(1);
    });

    // The listener blocks until the next clipboard change, so a flag would only be noticed then.
    // Exiting outright is fine for a smoke test.
    std::thread::spawn(|| {
        let mut line = String::new();
        let _ = std::io::stdin().read_line(&mut line);
        std::process::exit(0);
    });

    println!();
    println!("watching. copy something in another application. press Enter to stop.");

    let mut count = 0u32;
    if let Err(err) = watcher.run(&mut |event| {
        count += 1;
        report(count, &event, show_content);
    }) {
        eprintln!("watcher stopped: {err}");
        std::process::exit(1);
    }
}

#[cfg(target_os = "linux")]
fn run_linux(backend: Backend, show_content: bool) {
    use asli_clipboard::linux_wayland::WaylandClipboard;
    use asli_clipboard::linux_x11::X11Clipboard;

    let (mut watcher, shutdown): (Box<dyn ClipboardWatcher>, Arc<AtomicBool>) = match backend {
        Backend::WaylandDataControl => match WaylandClipboard::connect() {
            Ok(wayland) => {
                println!("protocol: {}", wayland.protocol().label());
                let handle = wayland.shutdown_handle();
                (Box::new(wayland), handle)
            }
            Err(err) => {
                println!("wayland data control unavailable: {err}");
                println!("falling back to the X11 backend through XWayland");
                let x11 = X11Clipboard::connect().unwrap_or_else(|err| {
                    eprintln!("could not connect to X either: {err}");
                    std::process::exit(1);
                });
                let handle = x11.shutdown_handle();
                (Box::new(x11), handle)
            }
        },
        Backend::X11 => {
            let x11 = X11Clipboard::connect().unwrap_or_else(|err| {
                eprintln!("could not connect: {err}");
                std::process::exit(1);
            });
            let handle = x11.shutdown_handle();
            (Box::new(x11), handle)
        }
        // Backend is non_exhaustive, so a backend added later compiles here rather than breaking
        // the build. This helper is Linux only by construction: the whole function is behind a
        // target_os gate.
        other => {
            eprintln!("this example does not drive the {other:?} backend");
            std::process::exit(1);
        }
    };

    stop_on_enter(&shutdown);

    println!();
    println!("watching. copy something in another application.");

    let mut count = 0u32;
    let result = watcher.run(&mut |event| {
        count += 1;
        report(count, &event, show_content);
    });

    match result {
        Ok(()) => println!("stopped after {count} events"),
        Err(err) => {
            eprintln!("watcher stopped: {err}");
            std::process::exit(1);
        }
    }
}

fn report(count: u32, event: &ClipEvent, show_content: bool) {
    if event.sensitive {
        println!("[{count}] skipped: the source marked this as a password");
        return;
    }
    match &event.content {
        ClipContent::Text(text) => {
            let digest = asli_core::hash(text.as_bytes());
            print!(
                "[{count}] text, {} bytes, hash {:02x}{:02x}{:02x}{:02x}",
                text.len(),
                digest[0],
                digest[1],
                digest[2],
                digest[3]
            );
            if show_content {
                let preview: String = text.chars().take(60).collect();
                print!(", content: {preview:?}");
            }
            println!();
        }
        ClipContent::ImagePng(bytes) => println!("[{count}] png, {} bytes", bytes.len()),
        other => println!("[{count}] {}, {} bytes", other.kind_label(), other.len()),
    }
}

/// Stops the watcher when a line arrives on stdin, so the example needs no signal handling crate.
#[cfg(target_os = "linux")]
fn stop_on_enter(flag: &Arc<AtomicBool>) {
    let flag = Arc::clone(flag);
    std::thread::spawn(move || {
        let mut line = String::new();
        let _ = std::io::stdin().read_line(&mut line);
        flag.store(true, Ordering::Relaxed);
    });
}
