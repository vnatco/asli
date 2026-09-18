# Building Asli

> **Status.** Linux builds, installs and runs. Windows builds with the MSVC toolchain and is being
> verified on real hardware; macOS is not yet wired up beyond its clipboard backend. The platform
> table in the README is the current word on each.

## 1. Node.js is not required

Building the client needs Rust and nothing else from the language ecosystem. There is no webview, no
bundler, no `npm install` step and no `node_modules` anywhere near the client.

Node.js is needed only if you want to run the **relay server** locally. The setup scripts offer that
explicitly behind `--with-server` (`-WithServer` on Windows), and say so rather than installing Node
silently.

## 2. Prerequisites

Rust comes from [rustup](https://rustup.rs) on every platform. The application crate needs Rust 1.92
or newer, because the window toolkit does; the library crates build with 1.82.

| Platform | What you need |
|---|---|
| **Arch Linux** | `base-devel` and Rust. No GTK, no appindicator, no libxdo. At runtime, a D-Bus session for the tray |
| **Debian and Ubuntu** | `build-essential`, `pkg-config` and Rust |
| **Fedora** | the `c-development` group and Rust |
| **macOS** | Xcode Command Line Tools (`xcode-select --install`) and Rust |
| **Windows** | Microsoft C++ Build Tools (the "Desktop development with C++" workload) and Rust on the MSVC toolchain. No WebView2 |

## 3. The setup scripts

One command per operating system, the same flags, idempotent, and loud about anything missing with
the exact command that fixes it.

```
./setup.sh              # macOS and Linux
.\setup.ps1             # Windows
```

| `setup.sh` | `setup.ps1` | Effect |
|---|---|---|
| `--build-only` | `-BuildOnly` | Check prerequisites and build. Install nothing |
| `--install` | `-Install` | Build, then install the binary, the application entry or Start menu shortcut, and turn on launch at login |
| `--with-server` | `-WithServer` | Also install the relay's dependencies, which is the only path that touches Node.js |
| `--uninstall` | `-Uninstall` | Remove what `--install` put in place. The account key in your keychain is left alone |
| `--dry-run` | `-DryRun` | Print every command that would run, and run none of them |
| `--help` | `Get-Help .\setup.ps1` | Print the flags |

With no flag the scripts build and run the test suite. `--build-only` and `--install` skip the tests.

Where things land:

| | Linux | Windows |
|---|---|---|
| Binary | `~/.local/bin/asli` (`ASLI_INSTALL_DIR` overrides) | `%LOCALAPPDATA%\Programs\Asli\` (`ASLI_INSTALL_DIR` overrides) |
| Menu entry | `~/.local/share/applications/asli.desktop` and the icon beside it in `hicolor` | Start menu shortcut |
| Launch at login | `~/.config/autostart/asli.desktop` | `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`, value `Asli` |

## 4. Building by hand

```
cargo build --release -p asli-app
```

The binary is `target/release/asli` (`asli.exe` on Windows). On Linux it is a single file whose only
runtime requirement is a D-Bus session for the tray.

On Windows, add `--features windowed` to also get `asliw.exe`, the identical program linked as a
windowed application, so that starting it at login does not open a console. `asli.exe` is the one to
use from a terminal, and the only one whose log you can see. The setup script builds both.

## 5. Tests, and why they are not enough

```
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

For the relay:

```
cd server
npm ci
npm test
npm run lint
```

`testdata/vectors.json` holds the frozen crypto vectors. Any change to a label, a length prefix or a
field order breaks them loudly, which is the point.

A green suite has never been what found the real bugs in this project. Every one of them was found
by running the program. So also run it:

```
cargo run -p asli-net --example live_relay -- wss://asli.vnat.dev/v1
cargo run -p asli-clipboard --example watch -- --show-content
cargo run -p asli-app -- status
```

The first proves TLS, the handshake and a round trip against a real relay. The second prints one
line per clipboard change, which is the quickest way to see what a desktop actually delivers.

To act as a second device without a second machine, point the peer harness at an account's join
token:

```
cargo run --release -p asli-net --example peer -- <join-token> --send-every-secs 5
```

Isolated instances keep tests away from a real account: set `ASLI_CONFIG_DIR` to a scratch directory
and `ASLI_KEYRING_SUFFIX` to any name, and the instance gets its own configuration, its own keychain
entry and its own single instance lock.

## 6. Checking the Windows build from Linux

With [llvm-mingw](https://github.com/mstorsjo/llvm-mingw) unpacked anywhere and its `bin` on `PATH`,
the Windows target can be linted, and even linked, without a Windows machine and without root:

```
rustup target add x86_64-pc-windows-gnullvm
export CC_x86_64_pc_windows_gnullvm=x86_64-w64-mingw32-clang
export AR_x86_64_pc_windows_gnullvm=llvm-ar
export CARGO_TARGET_X86_64_PC_WINDOWS_GNULLVM_LINKER=x86_64-w64-mingw32-clang
cargo clippy --workspace --all-targets --features asli-app/windowed \
    --target x86_64-pc-windows-gnullvm -- -D warnings
```

That proves the code compiles for Windows and nothing more. No Win32 call executes. Releases are
built on Windows with the MSVC toolchain.

## 7. Running the relay locally

With Docker, which is how self hosters are expected to run it:

```
cd server
docker compose up
```

The compose file includes Caddy for automatic HTTPS. Without Docker:

```
cd server
npm ci
npm start
```

The relay is one process, needs no database and writes nothing to disk. Point a client at it by
setting the relay URL in Settings, or `relay_url` in the configuration file that `asli status`
prints.

## 8. Before a pull request

There is no hosted CI. Run the three commands in section 5 on every platform you touched, say in the
pull request which platforms you actually ran it on, and if your change makes a document inaccurate,
fix the document in the same pull request.
