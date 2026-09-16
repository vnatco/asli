# Building Asli

> **Status.** Only the `asli-crypto` crate exists so far. The commands in "Building what exists
> today" work now. `setup.sh`, `setup.ps1`, the client application and the relay server are **not
> yet** written, and their sections below describe the agreed design rather than something you can
> run.

## 1. Node.js is not required

Building the client needs Rust and nothing else from the language ecosystem. There is no webview, no
bundler, no `npm install` step and no `node_modules` anywhere near the client.

Node.js is needed only if you want to run the **relay server** locally. The setup scripts will offer
that explicitly behind `--with-server`, and will say so rather than installing Node silently.

## 2. Prerequisites

Rust comes from [rustup](https://rustup.rs) on every platform. The native stack keeps the rest of the
list short, which is one of the reasons it was chosen over a webview toolkit.

| Platform | What you need |
|---|---|
| **Arch Linux** | `base-devel` and Rust. With the `ksni` tray backend there is no GTK, no appindicator and no libxdo requirement at build time, and only a running D-Bus session at runtime |
| **Debian and Ubuntu** | `build-essential`, `pkg-config` and Rust |
| **Fedora** | the `c-development` group and Rust |
| **macOS** | Xcode Command Line Tools (`xcode-select --install`) and Rust |
| **Windows** | Microsoft C++ Build Tools (the "Desktop development with C++" workload) and Rust on the MSVC toolchain. **No WebView2 requirement**, which removes a whole class of failures on locked down or stripped Windows installs |

For comparison, the same application built on Tauri would need
`webkit2gtk-4.1 base-devel curl wget file openssl appmenu-gtk-module libappindicator-gtk3 librsvg xdotool`
on Arch. That difference is the point.

If you run the relay locally you also need Node.js 24 LTS or newer, or Docker.

## 3. Building what exists today

```
git clone <repo-url>
cd asli
cargo test --workspace
```

That builds and tests `asli-crypto`: key derivation, identity and room ids, the join token, AEAD
sealing and opening, and the handshake signature. It has no system dependencies beyond a C toolchain
for the transitive build scripts, and it runs on all three platforms and in CI.

Useful variants:

```
cargo test -p asli-crypto               # just the crypto crate
cargo test -p asli-crypto -- --nocapture
cargo doc --open -p asli-crypto         # the crate docs are the crypto tour
cargo fmt --all --check
cargo clippy --all-targets -- -D warnings
```

## 4. The setup scripts (not yet)

Planned: one command per operating system, identical flags, identical output, idempotent, and loud
about anything missing with the exact command that fixes it.

```
./setup.sh          # macOS and Linux
.\setup.ps1         # Windows
```

| Flag | Effect |
|---|---|
| `--build-only` | Install prerequisites if missing and build the release binary. Do not install the app |
| `--install` | Build, then install the binary and the desktop or launch agent entry, and offer to enable launch at login |
| `--with-server` | Also set up what is needed to run the relay locally, which is the only path that touches Node.js |
| `--uninstall` | Remove the installed binary, the autostart entry and the configuration file. The keychain entry is removed only after an explicit confirmation |
| `--dry-run` | Print every command that would run, and run none of them |
| `--help` | Print the flags and exit |

Rules the scripts follow: never install a package manager, never invoke `sudo` without printing
exactly what is about to run and why, never leave a half finished state, and detect the distribution
rather than guessing.

## 5. Building the client manually (not yet)

Once `asli-app` exists:

```
cargo build --release -p asli-app
```

The binary lands in `target/release/`. On Linux it is a single file whose only runtime requirement
is a D-Bus session for the tray.

Cross compilation notes, planned for the release workflow rather than for day to day work: macOS
builds one binary per architecture rather than a universal one, because size is a stated constraint,
and Linux artifacts are built on Ubuntu 22.04 for the glibc baseline, never on `ubuntu-latest`.

## 6. Running the tests

| Command | What it covers | Status |
|---|---|---|
| `cargo test --workspace` | Everything in Rust, including the crypto known answer tests and the negative tests that must fail closed | Works today for `asli-crypto` |
| `cargo test -p asli-crypto` | Key derivation, room binding, join token parsing failures, AEAD tamper detection, padding buckets | Works today |
| `python3 scripts/interop-libsodium.py` | Verifies our ciphertext with libsodium, so the "libsodium compatible" claim is proven rather than assumed. Needs PyNaCl | **Not yet** |
| `testdata/vectors.json` | The frozen known answer vectors, shared by the Rust tests and the interop script. Any change to a label, a length prefix or a field order breaks these loudly, which is the point | **Not yet** |
| Integration test | Starts the relay and two headless clients, asserts a round trip and asserts the sender does not receive its own message | **Not yet** |

## 7. Running the relay locally (not yet)

With Docker, which is how the public relay runs and how self hosters are expected to run it:

```
cd server
docker compose up
```

The published compose file is byte identical to the one the public relay uses, so self hosting is a
genuinely first class path rather than a documented afterthought. It includes Caddy for automatic
HTTPS.

Without Docker:

```
cd server
npm ci
npm start
```

The relay is one process, needs no database and writes nothing to disk. Point a client at it by
setting the relay URL in Settings.

## 8. Continuous integration

Every push and pull request runs, on Windows, macOS and Ubuntu: `cargo fmt --check`,
`cargo clippy --all-targets -- -D warnings`, `cargo test --workspace`, the crypto vectors with the
libsodium interop check, the server lint and tests on Node 24 and 26, the integration test,
`shellcheck` on `setup.sh`, `PSScriptAnalyzer` on `setup.ps1`, and `cargo audit` with `npm audit`.

A pull request that is red on any of those will not be merged. If your change makes a document
inaccurate, fix the document in the same pull request.
