//! The `asli` command.
//!
//! The tray is not wired yet, so this is the whole interface: create or join an account, run the
//! daemon, ask what it thinks is going on, and start over if the key leaks.

#![forbid(unsafe_code)]

use std::sync::Arc;

use asli_app::clipboard_io::log_line;
use asli_app::config::Paths;
use asli_app::error::{Error, Result};
use asli_app::{daemon, qr, secrets};
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
    /// Run the daemon in the foreground.
    Run,
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
        Command::Run => run(&paths),
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
    println!("Copying it puts it on the clipboard this app synchronises, so prefer the QR.");
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

fn run(paths: &Paths) -> Result<()> {
    let config = paths.load_config()?;
    let (secret, store) = secrets::load(paths)?.ok_or(Error::NoAccount)?;
    let identity = Identity::from_secret(&secret);

    eprintln!(
        "{}",
        log_line("starting", &format!("room {}", identity.room_id()))
    );
    eprintln!("{}", log_line("key_store", store.describe()));

    #[cfg(target_os = "linux")]
    {
        use asli_app::clipboard_io::ClipboardIo as _;

        let (clipboard, observed) = asli_app::clipboard_io::start()?;
        eprintln!("{}", log_line("clipboard", &clipboard.describe()));

        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(Error::Io)?;

        runtime.block_on(async {
            tokio::select! {
                result = daemon::run(paths, &config, identity, Arc::new(clipboard), observed) => result,
                _ = tokio::signal::ctrl_c() => {
                    eprintln!("{}", log_line("stopping", "interrupted"));
                    Ok(())
                }
            }
        })
    }

    #[cfg(not(target_os = "linux"))]
    {
        let _ = (config, identity);
        eprintln!("The daemon supports Linux only so far.");
        Ok(())
    }
}
