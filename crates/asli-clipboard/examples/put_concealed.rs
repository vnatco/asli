//! Writes clipboard content marked as not for clipboard managers, and holds it.
//!
//! The Wayland data source has to stay alive to answer paste requests, so this keeps running
//! until it is stopped. Used to verify the marker reaches the clipboard for real:
//!
//! ```sh
//! cargo run -p asli-clipboard --example put_concealed -- "some text"
//! wl-paste --list-types
//! ```

use asli_clipboard::session::{self, Backend, Env};
use asli_clipboard::WriteOptions;

fn main() {
    let text = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "concealed test".to_owned());

    #[cfg(target_os = "linux")]
    {
        let env = Env::from_process();
        let plan = session::plan(&env).unwrap_or_else(|err| {
            eprintln!("no usable backend: {err}");
            std::process::exit(1);
        });

        match plan.backend {
            Backend::WaylandDataControl => {
                let mut clipboard = asli_clipboard::linux_wayland::WaylandClipboard::connect()
                    .unwrap_or_else(|err| {
                        eprintln!("connect failed: {err}");
                        std::process::exit(1);
                    });
                clipboard
                    .set_text(&text, WriteOptions::concealed())
                    .unwrap_or_else(|err| {
                        eprintln!("write failed: {err}");
                        std::process::exit(1);
                    });
                println!("wrote {} bytes, concealed, via wayland", text.len());
                // The source must stay alive to answer requests for the types it offered.
                serve(&mut clipboard);
            }
            Backend::X11 => {
                let mut clipboard = asli_clipboard::linux_x11::X11Clipboard::connect()
                    .unwrap_or_else(|err| {
                        eprintln!("connect failed: {err}");
                        std::process::exit(1);
                    });
                clipboard
                    .set_text(&text, WriteOptions::concealed())
                    .unwrap_or_else(|err| {
                        eprintln!("write failed: {err}");
                        std::process::exit(1);
                    });
                println!("wrote {} bytes, concealed, via x11", text.len());
                serve_x11(&mut clipboard);
            }
            _ => {
                eprintln!("unsupported backend: {:?}", plan.backend);
                std::process::exit(1);
            }
        }
    }

    #[cfg(not(target_os = "linux"))]
    {
        let _ = text;
        eprintln!("this example is Linux only");
        std::process::exit(1);
    }
}

#[cfg(target_os = "linux")]
fn serve(clipboard: &mut asli_clipboard::linux_wayland::WaylandClipboard) {
    use asli_clipboard::ClipboardWatcher;
    let _ = clipboard.run(&mut |_| {});
}

#[cfg(target_os = "linux")]
fn serve_x11(clipboard: &mut asli_clipboard::linux_x11::X11Clipboard) {
    use asli_clipboard::ClipboardWatcher;
    let _ = clipboard.run(&mut |_| {});
}
