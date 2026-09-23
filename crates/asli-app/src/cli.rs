//! The `asli` command.
//!
//! Create or join an account, run the daemon with or without a tray, ask what it thinks is going
//! on, and start over if the key leaks.
//!
//! Lives in the library rather than in `main.rs` so that two binaries can share it. On Windows
//! `asli.exe` is a console program for use from a terminal, and `asliw.exe` is the same program
//! linked as a windowed one, which is what launching at login starts, so that no console window
//! appears beside the tray.

use std::sync::Arc;

use crate::clipboard_io::log_line;
use crate::config::{Config, Paths};
use crate::daemon::Controls;
use crate::error::{Error, Result};
use crate::{autostart, daemon, instance, notify, qr, secrets, tray};
use asli_crypto::{token, Identity};
use zeroize::Zeroizing;
use clap::{Parser, Subcommand};

/// One clipboard, every machine.
#[derive(Debug, Parser)]
#[command(
    name = "asli",
    version,
    about = "Encrypted clipboard sync across your own machines"
)]
struct Cli {
    /// What to do. With none, Asli starts in the tray, which is what opening the app from Finder,
    /// Launchpad, the Start menu or a file manager does: none of those pass any arguments.
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Create a new account on this device and show the join token.
    Create {
        /// Replace an existing account instead of refusing.
        #[arg(long)]
        force: bool,
    },
    /// Join an account that already exists. Reads the token from stdin, never from the command
    /// line: `/proc/<pid>/cmdline` is world readable, so an argument would hand the account key
    /// to any other local user, and shells record it in their history besides.
    Join {
        /// Accepted only so that the old form can be refused with an explanation rather than a
        /// bare parser error. Never used. Clap would otherwise print the rejected argument, and
        /// the rejected argument is the account key.
        #[arg(hide = true)]
        token: Option<String>,
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

/// Parses the command line and runs it, exiting with status 1 on failure.
pub fn main() {
    if let Err(err) = dispatch() {
        eprintln!("error: {err}");
        // Started at login or from a launcher there is no terminal, and on Windows the windowed
        // binary has no stderr at all, so a failure to start would otherwise be completely
        // invisible: the app would simply never appear.
        if !std::io::IsTerminal::is_terminal(&std::io::stderr()) {
            notify::action_failed("Asli could not start", &err.to_string());
        }
        std::process::exit(1);
    }
}

fn dispatch() -> Result<()> {
    let cli = Cli::parse();
    let paths = Paths::resolve()?;

    match cli.command.unwrap_or(Command::Tray) {
        Command::Create { force } => create(&paths, force),
        Command::Join { token } => join(&paths, token.is_some()),
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

/// Reads the join token from stdin.
///
/// Never from `argv`. On Linux `/proc/<pid>/cmdline` is world readable, so a token passed as an
/// argument is readable by every other user on the machine for as long as the process lives, and
/// the shell writes it to its history file besides. The token is the account key in full: those
/// two are not acceptable places for it.
///
/// Typing is not hidden. The threat being closed here is a token at rest in a history file or
/// visible in a process list, not someone reading the screen, and the token is already on display
/// on the device that produced it. Hiding it would only make a mistyped character invisible.
fn read_token() -> Result<Zeroizing<String>> {
    use std::io::{BufRead, IsTerminal, Write};

    let stdin = std::io::stdin();
    if stdin.is_terminal() {
        print!("Paste the join token (starts with 'asli1_'): ");
        std::io::stdout().flush()?;
    }

    let mut line = Zeroizing::new(String::new());
    if stdin.lock().read_line(&mut line)? == 0 {
        return Err(Error::NoToken);
    }
    Ok(line)
}

fn join(paths: &Paths, token_in_argv: bool) -> Result<()> {
    if token_in_argv {
        return Err(Error::TokenInArgv);
    }
    let raw = read_token()?;
    let secret = token::parse(&raw)?;
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
    println!("Scan this on your other devices, or run 'asli join' there and paste it when asked.");
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
        println!("Account:       none yet. Run 'asli create' or 'asli join'");
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

    #[cfg(target_os = "macos")]
    {
        use asli_clipboard::macos::{MacosClipboard, SETTINGS_URL};
        let permission = MacosClipboard::permission();
        println!("Pasteboard:    read permission {}", permission.label());
        if !permission.may_read_in_background() {
            // Receiving still works, so this is a degraded mode, and the fix is one setting.
            println!(
                "               copies made on this Mac will not be sent until it is allowed:"
            );
            println!("               System Settings, Privacy and Security, Paste from Other Apps");
            println!("               open \"{SETTINGS_URL}\"");
        }
    }

    println!();
    println!("Live connection state is reported by the running daemon. Start it with 'asli tray'.");
    Ok(())
}

fn reset(paths: &Paths) -> Result<()> {
    secrets::wipe(paths)?;
    crate::replay_store::wipe(paths);

    // The archive and the device list go too. Both are readable with the key this command exists
    // to abandon: the history is sealed under a key derived from the same root secret, and the
    // device list names every machine on the account. Forgetting the key and leaving either in
    // place answers only half of "the key leaked".
    if let Err(err) = crate::history_store::wipe(paths) {
        eprintln!("{}", log_line("history_wipe_failed", &err.to_string()));
    }
    crate::devices::wipe(paths);

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

    #[cfg(any(target_os = "linux", target_os = "windows", target_os = "macos"))]
    {
        use crate::clipboard_io::ClipboardIo as _;
        use crate::window::{self, Screen};

        #[cfg(not(target_os = "macos"))]
        let (clipboard, observed) = crate::clipboard_io::start()?;
        // On macOS the pasteboard belongs to the main thread, so it comes back as a pump that
        // this thread keeps turning rather than as threads of its own.
        #[cfg(target_os = "macos")]
        let (clipboard, observed, pump) = crate::clipboard_io::start()?;
        eprintln!("{}", log_line("clipboard", &clipboard.describe()));

        let controls = Controls::default();
        controls.settings.load(&config);
        let io: Arc<dyn crate::clipboard_io::ClipboardIo> = Arc::new(clipboard);
        let account = load_account_patiently(paths)?;

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
        let history = open_history(paths, &config, account.as_ref().map(|(secret, _)| secret));

        let identity = account.map(|(secret, _)| Identity::from_secret(&secret));
        if let Some(identity) = &identity {
            eprintln!(
                "{}",
                log_line("starting", &format!("room {}", identity.room_id()))
            );
        }

        #[cfg(target_os = "macos")]
        if !with_tray {
            let identity = identity.ok_or(Error::NoAccount)?;
            run_headless_on_macos(
                paths, &config, identity, io, observed, controls, history, pump,
            );
        }

        #[cfg(not(target_os = "macos"))]
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
        #[cfg(target_os = "macos")]
        start_pump(pump);

        match identity {
            Some(identity) => {
                start_daemon(paths, &config, identity, &io, observed, &controls, &history)?;
                // Straight after creating or joining an account, the window this process
                // replaced comes back on Status and says what happened.
                window::welcome_after_restart();
            }
            // Nothing to connect to yet, so the window opens on first run instead. The daemon
            // starts on the next launch, which happens by itself once an account exists.
            None => window::open(Screen::FirstRun),
        }

        // Blocks until the window asks to quit. Not until the last window closes: the daemon
        // outlives every window, and closing one means "go away", never "stop syncing".
        window::run_event_loop()
    }

    #[cfg(not(any(target_os = "linux", target_os = "windows", target_os = "macos")))]
    {
        let _ = (config, with_tray);
        eprintln!("The daemon is not wired up on this platform. Linux, Windows and macOS are.");
        Ok(())
    }
}

/// `asli run` on macOS: the daemon on a worker, the pasteboard pump on this thread, and the
/// process ending when the daemon does.
///
/// The other platforms run the daemon on the main thread here. macOS cannot, because the main
/// thread is the only one allowed to touch the pasteboard.
#[cfg(target_os = "macos")]
#[allow(clippy::too_many_arguments, clippy::needless_pass_by_value)]
fn run_headless_on_macos(
    paths: &Paths,
    config: &Config,
    identity: Identity,
    io: Arc<dyn crate::clipboard_io::ClipboardIo>,
    observed: std::sync::mpsc::Receiver<crate::clipboard_io::Observed>,
    controls: Controls,
    history: crate::window::SharedHistory,
    pump: crate::clipboard_io::MacPump,
) -> ! {
    let paths = paths.clone();
    let config = config.clone();
    let spawned = std::thread::Builder::new()
        .name("asli-daemon".to_owned())
        .spawn(move || {
            let code =
                match headless_daemon(&paths, &config, identity, io, observed, &controls, &history)
                {
                    Ok(()) => 0,
                    Err(err) => {
                        eprintln!("error: {err}");
                        1
                    }
                };
            std::process::exit(code);
        });
    if let Err(err) = spawned {
        eprintln!("error: could not start the daemon: {err}");
        std::process::exit(1);
    }
    pump.run_blocking()
}

/// The headless daemon on macOS, run on a worker because the main thread polls the pasteboard.
#[cfg(target_os = "macos")]
fn headless_daemon(
    paths: &Paths,
    config: &Config,
    identity: Identity,
    io: Arc<dyn crate::clipboard_io::ClipboardIo>,
    observed: std::sync::mpsc::Receiver<crate::clipboard_io::Observed>,
    controls: &Controls,
    history: &crate::window::SharedHistory,
) -> Result<()> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(Error::Io)?;

    runtime.block_on(async {
        tokio::select! {
            result = daemon::run(paths, config, identity, io, observed, controls.clone(), Arc::clone(history)) => result,
            _ = tokio::signal::ctrl_c() => {
                eprintln!("{}", log_line("stopping", "interrupted"));
                Ok(())
            }
        }
    })
}

/// Turns the macOS pasteboard pump from the main thread, on a timer inside the window's event loop.
#[cfg(target_os = "macos")]
fn start_pump(mut pump: crate::clipboard_io::MacPump) {
    let timer = slint::Timer::default();
    timer.start(
        slint::TimerMode::Repeated,
        crate::clipboard_io::MacPump::INTERVAL,
        move || pump.tick(),
    );
    // Dropping a timer stops it, and this one must run for the life of the process.
    std::mem::forget(timer);
}

/// Loads the account key, waiting a while for a keychain that is still locked.
///
/// At login the keychain is often unlocked a few seconds after the applications that start with
/// the session, and on an automatic login it may stay locked until the person unlocks it. Treating
/// that as "no account" showed first run and offered to create a new account over the real one.
fn load_account_patiently(
    paths: &Paths,
) -> Result<Option<(zeroize::Zeroizing<[u8; 32]>, secrets::Store)>> {
    const PATIENCE: std::time::Duration = std::time::Duration::from_secs(60);
    const STEP: std::time::Duration = std::time::Duration::from_secs(3);

    let started = std::time::Instant::now();
    loop {
        match secrets::load(paths) {
            Err(Error::KeychainLocked(detail)) if started.elapsed() < PATIENCE => {
                if started.elapsed() < STEP {
                    eprintln!(
                        "{}",
                        log_line("keychain_locked", &format!("waiting for it: {detail}"))
                    );
                }
                std::thread::sleep(STEP);
            }
            other => return other,
        }
    }
}

/// The encrypted history when there is an account key to seal it with, and a list that lives
/// only as long as the process when there is not. First run has no key yet, and a history written
/// then that nothing could decrypt later is worse than no history at all.
#[cfg(any(target_os = "linux", target_os = "windows", target_os = "macos"))]
fn open_history(
    paths: &Paths,
    config: &Config,
    secret: Option<&zeroize::Zeroizing<[u8; 32]>>,
) -> crate::window::SharedHistory {
    let in_memory = || -> crate::window::SharedHistory {
        Arc::new(std::sync::Mutex::new(crate::window::MemoryHistory::new(
            config.keep_history,
            config.history_entries,
        )))
    };
    let Some(secret) = secret else {
        return in_memory();
    };
    match crate::history_store::open(paths, secret, config) {
        Ok(store) => Arc::new(std::sync::Mutex::new(store)),
        Err(err) => {
            // Never fatal. Syncing is the product and remembering is the convenience, so a
            // history that will not open costs the history and not the daemon.
            eprintln!("{}", log_line("history_failed", &err.to_string()));
            in_memory()
        }
    }
}

/// Runs the daemon on a worker thread, leaving the main one for the window.
#[cfg(any(target_os = "linux", target_os = "windows", target_os = "macos"))]
fn start_daemon(
    paths: &Paths,
    config: &Config,
    identity: Identity,
    io: &Arc<dyn crate::clipboard_io::ClipboardIo>,
    observed: std::sync::mpsc::Receiver<crate::clipboard_io::Observed>,
    controls: &Controls,
    history: &crate::window::SharedHistory,
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

            let status = controls.status.clone();
            let result = runtime.block_on(async {
                tokio::select! {
                    result = daemon::run(&paths, &config, identity, io, observed, controls, history) => Some(result),
                    _ = tokio::signal::ctrl_c() => None,
                }
            });

            match result {
                // Interrupted from a terminal: the person asked for the whole thing to stop.
                None => {
                    eprintln!("{}", log_line("stopping", "interrupted"));
                    crate::window::quit();
                }
                // The daemon has already published why it stopped. The tray stays, so the reason
                // is visible and Quit is one click away. Quitting here instead made the icon
                // vanish with no explanation, which reads exactly like a crash.
                Some(Ok(())) => {}
                Some(Err(err)) => {
                    eprintln!("{}", log_line("daemon_failed", &err.to_string()));
                    let mut current = status.get();
                    current.state = format!("Stopped: {err}");
                    current.peers = 0;
                    status.set(current);
                    crate::notify::action_failed("Asli stopped syncing", &err.to_string());
                }
            }
        })
        .map_err(Error::Io)?;

    Ok(())
}

/// Applies the stored autostart preference, if the platform supports it.
fn apply_autostart(config: &Config) -> Result<()> {
    // An isolated instance, as used for testing, has its own configuration but shares the login
    // entry with the real install. Letting it apply its own fresh default would put the real
    // entry back after it was turned off, pointing at whatever test binary was running.
    if std::env::var_os("ASLI_CONFIG_DIR").is_some() {
        return Ok(());
    }

    match autostart::is_enabled() {
        // Enabled, but pointing at a binary that has since moved or been deleted: point it here.
        Ok(true) if config.autostart && autostart::target_missing().unwrap_or(false) => {
            autostart::set_enabled(true)
        }
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
    io: &Arc<dyn crate::clipboard_io::ClipboardIo>,
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
                                drop(tray);
                                std::process::exit(0);
                            }
                        }
                    }
                    if let Ok(event) = icon_events.try_recv() {
                        if let Some(command) = tray::Tray::command_for_icon(&event) {
                            if handle_command(command, &paths, &config, &controls, io.as_ref()) {
                                drop(tray);
                                std::process::exit(0);
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

/// Builds the tray on the main thread, inside the window's event loop, and polls it from there.
///
/// On Windows the tray is a hidden window of its own, and a window only receives messages on a
/// thread that pumps them. The Slint event loop is exactly such a pump, so the tray is created
/// from inside it, and a timer on the same thread drains the menu and click channels. A tray built
/// on a thread of its own, as on Linux, would register an icon whose menu never opens.
///
/// macOS is stricter still: a status item may only be created on the main thread, after the
/// application has finished launching, which is exactly when this closure runs.
#[cfg(any(target_os = "windows", target_os = "macos"))]
fn start_tray(
    paths: &Paths,
    config: &Config,
    controls: &Controls,
    io: &Arc<dyn crate::clipboard_io::ClipboardIo>,
) -> Result<()> {
    let paths = paths.clone();
    let config = config.clone();
    let controls = controls.clone();
    let io = Arc::clone(io);

    // A request left while no instance was running is stale, and must not open a window now.
    let _ = tray::take_raise_request(&paths);

    // Its own timer, so a second launch still brings the window forward if the tray could not be
    // created at all.
    let raise_paths = paths.clone();
    let raise = slint::Timer::default();
    raise.start(
        slint::TimerMode::Repeated,
        tray::Tray::refresh_interval(),
        move || {
            // Somebody launched Asli again, and this is the copy they were looking for.
            if tray::take_raise_request(&raise_paths) {
                crate::window::open_default();
            }
        },
    );
    std::mem::forget(raise);

    slint::invoke_from_event_loop(move || {
        // A menu bar application: no Dock icon and no entry in the application switcher. The
        // installed bundle says so in its Info.plist, but a binary run straight from a terminal
        // has no bundle, and the window would otherwise put a Dock icon up the first time it
        // opens.
        #[cfg(target_os = "macos")]
        crate::macos::become_accessory();

        match tray::Tray::new(Arc::clone(&controls.paused)) {
            Ok(tray) => {
                eprintln!("{}", log_line("tray", "registered"));
                MAIN_TRAY.with_borrow_mut(|slot| *slot = Some(tray));
            }
            Err(err) => {
                // Syncing works without an icon, so this is reported and not fatal.
                eprintln!("{}", log_line("tray_failed", &err.to_string()));
                return;
            }
        }

        let menu_events = muda::MenuEvent::receiver();
        let icon_events = tray_icon::TrayIconEvent::receiver();
        let mut refreshed_at: Option<std::time::Instant> = None;

        let timer = slint::Timer::default();
        timer.start(
            slint::TimerMode::Repeated,
            std::time::Duration::from_millis(80),
            move || {
                // Commands are collected while the tray is borrowed and acted on after, so that
                // Quit can take the tray out of its slot to drop it.
                let commands = MAIN_TRAY.with_borrow(|slot| {
                    let Some(tray) = slot.as_ref() else {
                        return Vec::new();
                    };
                    if refreshed_at.is_none_or(|at| at.elapsed() >= tray::Tray::refresh_interval())
                    {
                        tray.refresh(&controls.status.get(), asli_net::client::now_ms());
                        refreshed_at = Some(std::time::Instant::now());
                    }
                    let mut commands = Vec::new();
                    while let Ok(event) = menu_events.try_recv() {
                        commands.extend(tray.command_for(&event));
                    }
                    while let Ok(event) = icon_events.try_recv() {
                        commands.extend(tray::Tray::command_for_icon(&event));
                    }
                    commands
                });

                for command in commands {
                    if handle_command(command, &paths, &config, &controls, io.as_ref()) {
                        exit_removing_tray(0);
                    }
                }
            },
        );
        // Dropping a timer stops it, and this one must run for the life of the process.
        std::mem::forget(timer);
    })
    .map_err(|err| Error::ConfigDir(format!("could not schedule the tray: {err}")))
}

#[cfg(any(target_os = "windows", target_os = "macos"))]
thread_local! {
    /// The tray on Windows and macOS, which lives on the main thread. Kept where the exit path
    /// can reach it, because exiting without dropping it leaves a dead icon behind on Windows.
    static MAIN_TRAY: std::cell::RefCell<Option<tray::Tray>> = const { std::cell::RefCell::new(None) };
}

/// Removes the tray icon, then ends the process. Call on the main thread.
///
/// Every deliberate exit goes through here: Quit, and the restart after joining an account, which
/// would otherwise leave two icons side by side, one of them dead.
#[cfg(any(target_os = "windows", target_os = "macos"))]
pub(crate) fn exit_removing_tray(code: i32) -> ! {
    drop(MAIN_TRAY.with_borrow_mut(Option::take));
    std::process::exit(code)
}

/// Acts on a tray command. Returns true when the application should exit.
///
/// Most items now open a screen rather than doing something of their own. That is the point of
/// having a window: a menu item that performs an invisible action is indistinguishable from one
/// that does nothing, which is exactly how these behaved before.
#[cfg(any(target_os = "linux", target_os = "windows", target_os = "macos"))]
fn handle_command(
    command: tray::Command,
    paths: &Paths,
    config: &Config,
    controls: &Controls,
    io: &dyn crate::clipboard_io::ClipboardIo,
) -> bool {
    use std::sync::atomic::Ordering;

    if let Some(screen) = crate::window::screen_for(command) {
        crate::window::open(screen);
        return false;
    }

    match command {
        // The window decides which screen this lands on, because only it knows whether an account
        // exists yet, and that changes while the process is running: first run creates one.
        tray::Command::Open => crate::window::open_default(),
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
            // The caller exits, once it has dropped the tray. Exiting here skipped that, and on
            // Windows the icon of a process that no longer exists stays in the notification area
            // until the mouse happens to pass over it.
            return true;
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
