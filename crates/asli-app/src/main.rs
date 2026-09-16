//! The `asli` command.
//!
//! Create or join an account, run the daemon with or without a tray, ask what it thinks is going
//! on, and start over if the key leaks.

#![forbid(unsafe_code)]

use std::sync::Arc;

use asli_app::clipboard_io::log_line;
use asli_app::config::{Config, Paths};
use asli_app::daemon::Controls;
use asli_app::error::{Error, Result};
use asli_app::{autostart, daemon, qr, secrets, tray};
use asli_crypto::{token, Identity};
use clap::{Parser, Subcommand};

/// One clipboard, every machine.
#[derive(Debug, Parser)]
#[command(
    name = "asli",
    version,
    about = "Encrypted clipboard sync across your own machines"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Create a new account on this device and show the join token.
    Create {
        /// Replace an existing account instead of refusing.
        #[arg(long)]
        force: bool,
    },
    /// Join an account that already exists, using its token.
    Join {
        /// The token from `asli create`, starting with `asli1_`.
        token: String,
    },
    /// Run the daemon in the foreground, with no tray.
    Run,
    /// Run the daemon with a tray icon. This is what launching at login starts.
    Tray,
    /// Turn starting at login on or off.
    Autostart {
        /// `on` or `off`. Omit to show the current setting.
        state: Option<String>,
    },
    /// Show what this device is configured to do.
    Status,
    /// Forget the account on this device.
    Reset,
    /// Show the join token for the account already on this device.
    Show,
}

/// How long the join token stays on the clipboard before it clears itself.
///
/// Long enough to paste into another machine's prompt, short enough that it is not still sitting
/// there an hour later.
const TOKEN_CLEAR_AFTER: std::time::Duration = std::time::Duration::from_secs(90);

fn main() {
    if let Err(err) = dispatch() {
        eprintln!("error: {err}");
        std::process::exit(1);
    }
}

fn dispatch() -> Result<()> {
    let cli = Cli::parse();
    let paths = Paths::resolve()?;

    match cli.command {
        Command::Create { force } => create(&paths, force),
        Command::Join { token } => join(&paths, &token),
        Command::Run => run(&paths, false),
        Command::Tray => run(&paths, true),
        Command::Autostart { state } => autostart_command(&paths, state.as_deref()),
        Command::Status => status(&paths),
        Command::Reset => reset(&paths),
        Command::Show => show(&paths),
    }
}

fn create(paths: &Paths, force: bool) -> Result<()> {
    if !force && secrets::load(paths)?.is_some() {
        return Err(Error::AccountExists);
    }

    let identity = Identity::generate()?;
    let store = secrets::store(paths, identity.secret())?;
    let config = paths.load_config()?;

    println!("Account created.");
    println!("Key stored in: {}", store.describe());
    println!("Room id:       {}", identity.room_id());
    println!();
    present_token(identity.secret())?;
    println!("Relay:         {}", config.relay_url);
    Ok(())
}

fn join(paths: &Paths, raw: &str) -> Result<()> {
    let secret = token::parse(raw)?;
    let identity = Identity::from_secret(&secret);
    let store = secrets::store(paths, identity.secret())?;
    let config = paths.load_config()?;

    println!("Joined.");
    println!("Key stored in: {}", store.describe());
    println!("Room id:       {}", identity.room_id());
    println!("Relay:         {}", config.relay_url);
    println!();
    println!("Run 'asli run' here and on your other devices.");
    Ok(())
}

fn show(paths: &Paths) -> Result<()> {
    let (secret, _store) = secrets::load(paths)?.ok_or(Error::NoAccount)?;
    present_token(&secret)
}

/// Prints the QR first and the token second, with the warning that matters.
fn present_token(secret: &[u8; 32]) -> Result<()> {
    let token = token::encode(secret);

    println!("{}", qr::render(&token)?);
    println!("  {}", token.as_str());
    println!();
    println!("Scan this on your other devices, or paste the token with 'asli join <token>'.");
    println!("Anyone who has it has your clipboard. Do not send it over chat or email.");
    println!("Scanning the QR is safest. Copying it from the tray marks it so clipboard");
    println!("history and cloud sync skip it, and clears it after 90 seconds, but any");
    println!("software that ignores those markers can still read it.");
    Ok(())
}

fn status(paths: &Paths) -> Result<()> {
    let config = paths.load_config()?;
    let account = secrets::load(paths)?;

    println!("Config:        {}", paths.config_file().display());
    println!("Relay:         {}", config.relay_url);
    println!("Device id:     {}", config.device_id);
    println!("Size cap:      {} bytes", config.max_content_bytes);
    println!("Next sequence: {}", paths.load_state()?.seq);

    if let Some((secret, store)) = &account {
        let identity = Identity::from_secret(secret);
        println!("Account:       yes");
        println!("Room id:       {}", identity.room_id());
        println!("Key stored in: {}", store.describe());
    } else {
        println!("Account:       none yet. Run 'asli create' or 'asli join <token>'");
        println!("Key store:     {}", secrets::available_store().describe());
    }

    #[cfg(target_os = "linux")]
    {
        use asli_clipboard::session::{self, Env};
        let env = Env::from_process();
        println!("Desktop:       {}", env.desktop_label());
        println!("Session:       {:?}", env.kind());
        match session::plan(&env) {
            Ok(plan) => {
                println!("Backend:       {:?}", plan.backend);
                println!("Note:          {}", plan.note);
                if plan.degraded {
                    println!("               (compatibility path, not the preferred one)");
                }
            }
            Err(err) => println!("Backend:       unavailable: {err}"),
        }
    }

    println!();
    println!("Live connection state is reported by the running daemon. Start it with 'asli run'.");
    Ok(())
}

fn reset(paths: &Paths) -> Result<()> {
    secrets::wipe(paths)?;
    println!("Account forgotten on this device.");
    println!();
    println!("This is how revocation works in v1: there is no way to remove one device from an");
    println!("account, so if the key leaked, run 'asli create' here and re-join your other");
    println!("devices with the new token. The old room is then abandoned.");
    Ok(())
}

/// Turns starting at login on or off, and reports what actually happened.
fn autostart_command(paths: &Paths, state: Option<&str>) -> Result<()> {
    let mut config = paths.load_config()?;

    match state {
        None => {}
        Some("on") => {
            autostart::set_enabled(true)?;
            config.autostart = true;
            paths.save_config(&config)?;
        }
        Some("off") => {
            autostart::set_enabled(false)?;
            config.autostart = false;
            paths.save_config(&config)?;
        }
        Some(other) => {
            return Err(Error::Parse(format!(
                "expected 'on' or 'off', got '{other}'"
            )))
        }
    }

    // Report the observed state, not the stored preference. Those disagree exactly when something
    // went wrong, which is the moment it matters.
    match autostart::is_enabled() {
        Ok(enabled) => println!("Start at login: {}", if enabled { "on" } else { "off" }),
        Err(err) => println!("Start at login: unknown ({err})"),
    }
    println!("Entry:         {}", autostart::describe_location()?);
    Ok(())
}

fn run(paths: &Paths, with_tray: bool) -> Result<()> {
    let config = paths.load_config()?;
    let (secret, store) = secrets::load(paths)?.ok_or(Error::NoAccount)?;
    let identity = Identity::from_secret(&secret);

    eprintln!(
        "{}",
        log_line("starting", &format!("room {}", identity.room_id()))
    );
    eprintln!("{}", log_line("key_store", store.describe()));

    // The stored preference is applied on every start, so an entry deleted by hand comes back and
    // one turned off stays off. Failure is reported and not fatal: a machine that cannot write an
    // autostart entry can still sync.
    if let Err(err) = apply_autostart(&config) {
        eprintln!("{}", log_line("autostart_failed", &err.to_string()));
    }

    #[cfg(target_os = "linux")]
    {
        use asli_app::clipboard_io::ClipboardIo as _;

        let (clipboard, observed) = asli_app::clipboard_io::start()?;
        eprintln!("{}", log_line("clipboard", &clipboard.describe()));

        let controls = Controls::default();
        let io: Arc<dyn asli_app::clipboard_io::ClipboardIo> = Arc::new(clipboard);

        if with_tray {
            start_tray(paths, &config, &controls, &io)?;
        }

        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(Error::Io)?;

        runtime.block_on(async {
            tokio::select! {
                result = daemon::run(paths, &config, identity, Arc::clone(&io), observed, controls.clone()) => result,
                _ = tokio::signal::ctrl_c() => {
                    eprintln!("{}", log_line("stopping", "interrupted"));
                    Ok(())
                }
            }
        })
    }

    #[cfg(not(target_os = "linux"))]
    {
        let _ = (config, identity, with_tray);
        eprintln!("The daemon supports Linux only so far.");
        Ok(())
    }
}

/// Applies the stored autostart preference, if the platform supports it.
fn apply_autostart(config: &Config) -> Result<()> {
    match autostart::is_enabled() {
        Ok(current) if current == config.autostart => Ok(()),
        Ok(_) => autostart::set_enabled(config.autostart),
        // Unsupported platforms report clearly rather than pretending, and must not stop the
        // daemon from starting.
        Err(err) => Err(err),
    }
}

/// Builds the tray on a thread of its own and runs its menu loop there.
///
/// The tray must be constructed on the thread that owns it. `TrayIcon` and every `muda` menu item
/// hold `Rc<RefCell<..>>` internally and are therefore not `Send`, so they cannot be built here
/// and moved. Only `Send` values cross the boundary: the paths, the configuration, the pause flag
/// and the status handle.
///
/// The ksni backend spawns its own service thread inside `TrayIcon::new`, so this thread exists
/// only to poll menu events and refresh the labels. There is no GTK or winit event loop involved.
#[cfg(target_os = "linux")]
fn start_tray(
    paths: &Paths,
    config: &Config,
    controls: &Controls,
    io: &Arc<dyn asli_app::clipboard_io::ClipboardIo>,
) -> Result<()> {
    if !tray::host_present() {
        // Refusing to start would be worse: syncing works perfectly well with no icon. Saying so
        // is what stops this looking like a crash.
        eprintln!(
            "{}",
            log_line("tray_host_missing", "no StatusNotifierItem host")
        );
        eprintln!("{}", tray::missing_host_advice());
    }

    let paths = paths.clone();
    let config = config.clone();
    let controls = controls.clone();
    let io = Arc::clone(io);

    // Construction happens on the worker, so its outcome has to come back over a channel for the
    // caller to report a failed registration rather than discovering it never happened.
    let (ready_tx, ready_rx) = std::sync::mpsc::channel::<std::result::Result<(), String>>();

    std::thread::Builder::new()
        .name("asli-tray".to_owned())
        .spawn(move || {
            let tray = match tray::Tray::new(Arc::clone(&controls.paused)) {
                Ok(tray) => {
                    let _ = ready_tx.send(Ok(()));
                    tray
                }
                Err(err) => {
                    let _ = ready_tx.send(Err(err.to_string()));
                    return;
                }
            };

            let events = muda::MenuEvent::receiver();
            loop {
                let status = controls.status.get();
                tray.refresh(&status, asli_net::client::now_ms());

                // A timeout rather than a blocking receive, because the labels have to refresh
                // even when nobody touches the menu.
                if let Ok(event) = events.recv_timeout(tray::Tray::refresh_interval()) {
                    if let Some(command) = tray.command_for(&event) {
                        if handle_command(command, &paths, &config, &controls, io.as_ref()) {
                            return;
                        }
                    }
                }
            }
        })
        .map_err(Error::Io)?;

    match ready_rx.recv() {
        Ok(Ok(())) => {
            eprintln!("{}", log_line("tray", "registered"));
            Ok(())
        }
        Ok(Err(detail)) => Err(Error::ConfigDir(detail)),
        Err(_) => Err(Error::ConfigDir(
            "the tray thread ended before it reported a result".to_owned(),
        )),
    }
}

/// Acts on a tray command. Returns true when the application should exit.
#[cfg(target_os = "linux")]
fn handle_command(
    command: tray::Command,
    paths: &Paths,
    config: &Config,
    controls: &Controls,
    io: &dyn asli_app::clipboard_io::ClipboardIo,
) -> bool {
    use std::sync::atomic::Ordering;

    match command {
        tray::Command::Pause => {
            controls.paused.store(true, Ordering::Relaxed);
            eprintln!("{}", log_line("paused", "by the tray menu"));
        }
        tray::Command::Resume => {
            controls.paused.store(false, Ordering::Relaxed);
            eprintln!("{}", log_line("resumed", "by the tray menu"));
        }
        tray::Command::PasteRetained => {
            // The relay holds the stored clip, and only the daemon's connection can ask for it, so
            // this raises a request the daemon picks up on its next pass rather than reaching into
            // a socket owned by another thread.
            //
            // It is an explicit action on purpose. The protocol delivers a retained clip with
            // retained set, and writing that automatically on connect would overwrite something
            // copied on this machine seconds earlier.
            if controls.status.get().has_retained {
                controls.request_retained();
                eprintln!("{}", log_line("paste_retained", "requested from the relay"));
            } else {
                eprintln!(
                    "{}",
                    log_line("paste_retained", "the relay is not holding a stored clip")
                );
            }
        }
        tray::Command::ShowToken => match secrets::load(paths) {
            Ok(Some((secret, _))) => {
                if let Err(err) = present_token(&secret) {
                    eprintln!("{}", log_line("show_token_failed", &err.to_string()));
                }
                // Copying the key is a deliberate action, so it is marked: out of clipboard
                // history, out of cloud sync, ignored by other clipboard managers. It clears
                // itself shortly afterwards, but only if it is still the thing on the clipboard.
                let token = asli_crypto::token::encode(&secret);
                match io.write_text_concealed(token.as_str(), TOKEN_CLEAR_AFTER) {
                    Ok(()) => eprintln!(
                        "{}",
                        log_line("token_copied", "marked as concealed, clears in 90 seconds")
                    ),
                    Err(err) => eprintln!("{}", log_line("token_copy_failed", &err.to_string())),
                }
            }
            Ok(None) => eprintln!(
                "{}",
                log_line("show_token_failed", "no account on this device")
            ),
            Err(err) => eprintln!("{}", log_line("show_token_failed", &err.to_string())),
        },
        tray::Command::Settings => {
            if let Err(err) = tray::open_settings(paths) {
                eprintln!("{}", log_line("settings_failed", &err.to_string()));
            }
        }
        tray::Command::Diagnostics => {
            let text = tray::diagnostics(config, &controls.status.get(), paths);
            // Diagnostics go onto the clipboard so they can be pasted into a bug report, which is
            // the only reason this application ever writes something it did not receive.
            if let Err(err) = io.write_text(&text) {
                eprintln!("{}", log_line("diagnostics_failed", &err.to_string()));
            } else {
                eprintln!("{}", log_line("diagnostics", "copied to the clipboard"));
            }
        }
        tray::Command::Quit => {
            eprintln!("{}", log_line("stopping", "quit from the tray menu"));
            // The daemon owns the process lifetime, and there is no clean cross thread shutdown
            // path into its select loop yet, so this exits directly.
            std::process::exit(0);
        }
    }
    false
}
