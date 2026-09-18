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
use asli_app::{autostart, daemon, instance, notify, qr, secrets, tray};
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
    /// Run the daemon in the foreground, with no tray and no window.
    Run,
    /// Run the daemon with a tray icon and a window. This is what launching at login starts.
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
    // Kept for people who prefer a shell. The window is the path that does not require one.

    println!("Joined.");
    println!("Key stored in: {}", store.describe());
    println!("Room id:       {}", identity.room_id());
    println!("Relay:         {}", config.relay_url);
    println!();
    println!("Run 'asli tray' here and on your other devices.");
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
    println!("Scanning the QR is safest. Copying it from the window marks it so clipboard");
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
    println!(
        "History:       {}",
        if config.keep_history { "on" } else { "off" }
    );
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
    println!("Live connection state is reported by the running daemon. Start it with 'asli tray'.");
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

/// Runs the daemon, with a tray and a window or without either.
///
/// # Which thread runs what
///
/// With a tray, the window owns the main thread. Every platform requires a user interface event
/// loop to run there, so the daemon moves to a worker with its own runtime and the tray to another
/// of its own. Without a tray this is a headless daemon and the main thread runs it directly, as
/// it always did.
fn run(paths: &Paths, with_tray: bool) -> Result<()> {
    // Held until this function returns, and released by the operating system if the process ends
    // any other way, including the direct exit behind Quit.
    let _instance = match instance::claim(paths)? {
        instance::Claim::Acquired(guard) => guard,
        instance::Claim::AlreadyRunning => {
            // Launching twice is normal, so this is a clean exit and not an error. The courtesy is
            // to bring the running one forward, which is what the person was trying to reach.
            let raised = with_tray && tray::raise_running(paths);
            eprintln!(
                "{}",
                log_line(
                    "already_running",
                    if raised {
                        "asked the running instance to show its window"
                    } else {
                        "another instance is running for this configuration"
                    }
                )
            );
            return Ok(());
        }
    };

    let config = paths.load_config()?;

    // The stored preference is applied on every start, so an entry deleted by hand comes back and
    // one turned off stays off. Failure is reported and not fatal: a machine that cannot write an
    // autostart entry can still sync.
    if let Err(err) = apply_autostart(&config) {
        eprintln!("{}", log_line("autostart_failed", &err.to_string()));
    }

    #[cfg(target_os = "linux")]
    {
        use asli_app::clipboard_io::ClipboardIo as _;
        use asli_app::window::{self, MemoryHistory, Screen, SharedHistory};

        let (clipboard, observed) = asli_app::clipboard_io::start()?;
        eprintln!("{}", log_line("clipboard", &clipboard.describe()));

        let controls = Controls::default();
        let io: Arc<dyn asli_app::clipboard_io::ClipboardIo> = Arc::new(clipboard);
        let account = secrets::load(paths)?;

        // A tray with no account must not simply exit: that is indistinguishable from a crash,
        // and the second machine has just been installed precisely in order to join. Without a
        // tray there is nowhere to show first run, so the old refusal still stands.
        if !with_tray && account.is_none() {
            return Err(Error::NoAccount);
        }

        if let Some((_, store)) = &account {
            eprintln!("{}", log_line("key_store", store.describe()));
        }

        // The encrypted store when there is an account key to seal it with, and a list that lives
        // only as long as the process when there is not. First run has no key yet, and a history
        // written now that nothing could decrypt later is worse than no history at all.
        let history: SharedHistory = match &account {
            Some((secret, _)) => match asli_app::history_store::open(paths, secret, &config) {
                Ok(store) => Arc::new(std::sync::Mutex::new(store)),
                Err(err) => {
                    // Never fatal. Syncing is the product and remembering is the convenience, so
                    // a history that will not open costs the history and not the daemon.
                    eprintln!("{}", log_line("history_failed", &err.to_string()));
                    Arc::new(std::sync::Mutex::new(MemoryHistory::new(
                        config.keep_history,
                        config.history_entries,
                    )))
                }
            },
            None => Arc::new(std::sync::Mutex::new(MemoryHistory::new(
                config.keep_history,
                config.history_entries,
            ))),
        };

        let identity = account.map(|(secret, _)| Identity::from_secret(&secret));
        if let Some(identity) = &identity {
            eprintln!(
                "{}",
                log_line("starting", &format!("room {}", identity.room_id()))
            );
        }

        if !with_tray {
            let Some(identity) = identity else {
                return Err(Error::NoAccount);
            };
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .map_err(Error::Io)?;

            return runtime.block_on(async {
                tokio::select! {
                    result = daemon::run(paths, &config, identity, Arc::clone(&io), observed, controls.clone(), Arc::clone(&history)) => result,
                    _ = tokio::signal::ctrl_c() => {
                        eprintln!("{}", log_line("stopping", "interrupted"));
                        Ok(())
                    }
                }
            });
        }

        window::install(window::Context {
            paths: paths.clone(),
            controls: controls.clone(),
            io: Arc::clone(&io),
            history: Arc::clone(&history),
        })?;
        start_tray(paths, &config, &controls, &io)?;

        match identity {
            Some(identity) => {
                start_daemon(paths, &config, identity, &io, observed, &controls, &history)?;
            }
            // Nothing to connect to yet, so the window opens on first run instead. The daemon
            // starts on the next launch, which happens by itself once an account exists.
            None => window::open(Screen::FirstRun),
        }

        // Blocks until the window asks to quit. Not until the last window closes: the daemon
        // outlives every window, and closing one means "go away", never "stop syncing".
        window::run_event_loop()
    }

    #[cfg(not(target_os = "linux"))]
    {
        let _ = (config, with_tray);
        eprintln!("The daemon supports Linux only so far.");
        Ok(())
    }
}

/// Runs the daemon on a worker thread, leaving the main one for the window.
#[cfg(target_os = "linux")]
fn start_daemon(
    paths: &Paths,
    config: &Config,
    identity: Identity,
    io: &Arc<dyn asli_app::clipboard_io::ClipboardIo>,
    observed: std::sync::mpsc::Receiver<asli_app::clipboard_io::Observed>,
    controls: &Controls,
    history: &asli_app::window::SharedHistory,
) -> Result<()> {
    let paths = paths.clone();
    let config = config.clone();
    let io = Arc::clone(io);
    let controls = controls.clone();
    let history = Arc::clone(history);

    std::thread::Builder::new()
        .name("asli-daemon".to_owned())
        .spawn(move || {
            let runtime = match tokio::runtime::Builder::new_current_thread().enable_all().build() {
                Ok(runtime) => runtime,
                Err(err) => {
                    eprintln!("{}", log_line("daemon_failed", &err.to_string()));
                    return;
                }
            };

            let result = runtime.block_on(async {
                tokio::select! {
                    result = daemon::run(&paths, &config, identity, io, observed, controls, history) => result,
                    _ = tokio::signal::ctrl_c() => {
                        eprintln!("{}", log_line("stopping", "interrupted"));
                        Ok(())
                    }
                }
            });

            if let Err(err) = result {
                eprintln!("{}", log_line("daemon_failed", &err.to_string()));
            }
            // Whether it stopped cleanly or not, there is nothing left to sync, so the window
            // should not sit there implying otherwise.
            asli_app::window::quit();
        })
        .map_err(Error::Io)?;

    Ok(())
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
            // Short enough that a click feels immediate, long enough that an idle tray is not
            // spinning. The labels are still refreshed once per interval, not once per tick.
            const POLL: std::time::Duration = std::time::Duration::from_millis(80);

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

            let menu_events = muda::MenuEvent::receiver();
            // Clicking the icon arrives here, not on the menu channel. Nothing read this before,
            // which is why a left click did nothing at all.
            let icon_events = tray_icon::TrayIconEvent::receiver();

            loop {
                let status = controls.status.get();
                tray.refresh(&status, asli_net::client::now_ms());

                // Both channels are drained on a short tick. Blocking on the menu channel for a
                // whole interval, which is what this did before, would leave a click on the icon
                // unread until somebody happened to open the menu.
                let deadline = std::time::Instant::now() + tray::Tray::refresh_interval();
                while std::time::Instant::now() < deadline {
                    if let Ok(event) = menu_events.recv_timeout(POLL) {
                        if let Some(command) = tray.command_for(&event) {
                            if handle_command(command, &paths, &config, &controls, io.as_ref()) {
                                return;
                            }
                        }
                    }
                    if let Ok(event) = icon_events.try_recv() {
                        if let Some(command) = tray::Tray::command_for_icon(&event) {
                            if handle_command(command, &paths, &config, &controls, io.as_ref()) {
                                return;
                            }
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
///
/// Most items now open a screen rather than doing something of their own. That is the point of
/// having a window: a menu item that performs an invisible action is indistinguishable from one
/// that does nothing, which is exactly how these behaved before.
#[cfg(target_os = "linux")]
fn handle_command(
    command: tray::Command,
    paths: &Paths,
    config: &Config,
    controls: &Controls,
    io: &dyn asli_app::clipboard_io::ClipboardIo,
) -> bool {
    use std::sync::atomic::Ordering;

    if let Some(screen) = asli_app::window::screen_for(command) {
        asli_app::window::open(screen);
        return false;
    }

    match command {
        // The window decides which screen this lands on, because only it knows whether an account
        // exists yet, and that changes while the process is running: first run creates one.
        tray::Command::Open => asli_app::window::open_default(),
        tray::Command::Pause => {
            controls.paused.store(true, Ordering::Relaxed);
            eprintln!("{}", log_line("paused", "by the tray menu"));
            notify::sync_paused(true);
        }
        tray::Command::Resume => {
            controls.paused.store(false, Ordering::Relaxed);
            eprintln!("{}", log_line("resumed", "by the tray menu"));
            notify::sync_paused(false);
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
                notify::retained_requested();
            } else {
                eprintln!(
                    "{}",
                    log_line("paste_retained", "the relay is not holding a stored clip")
                );
                notify::retained_unavailable();
            }
        }
        tray::Command::Diagnostics => {
            let text = tray::diagnostics(config, &controls.status.get(), paths);
            // Diagnostics go onto the clipboard so they can be pasted into a bug report, which is
            // the only reason this application ever writes something it did not receive.
            if let Err(err) = io.write_text(&text) {
                eprintln!("{}", log_line("diagnostics_failed", &err.to_string()));
                notify::diagnostics_failed(&err.to_string());
            } else {
                eprintln!("{}", log_line("diagnostics", "copied to the clipboard"));
                notify::diagnostics_copied();
            }
        }
        tray::Command::Quit => {
            eprintln!("{}", log_line("stopping", "quit from the tray menu"));
            // The daemon owns the process lifetime, and there is no clean cross thread shutdown
            // path into its select loop yet, so this exits directly.
            std::process::exit(0);
        }
        // Handled above by opening a screen.
        tray::Command::ShowToken
        | tray::Command::Join
        | tray::Command::History
        | tray::Command::Status
        | tray::Command::Settings => {}
    }
    false
}
