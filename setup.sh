#!/usr/bin/env bash
#
# Asli setup script for macOS and Linux.
#
# Installs what is missing, builds, and optionally installs the binary. It is idempotent: running
# it twice is safe and the second run does almost nothing. It never half succeeds. If something is
# missing that we cannot install for you, it stops and prints the exact command to fix it.
#
# Usage: ./setup.sh [--build-only] [--install] [--with-server] [--uninstall] [--dry-run] [--help]

set -euo pipefail

BUILD_ONLY=0
DO_INSTALL=0
WITH_SERVER=0
DO_UNINSTALL=0
DRY_RUN=0

readonly INSTALL_DIR="${ASLI_INSTALL_DIR:-$HOME/.local/bin}"
readonly REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Colors, but only when attached to a terminal, so logs stay readable when piped.
if [ -t 1 ]; then
    BOLD=$'\033[1m'; RED=$'\033[31m'; GREEN=$'\033[32m'; YELLOW=$'\033[33m'; RESET=$'\033[0m'
else
    BOLD=''; RED=''; GREEN=''; YELLOW=''; RESET=''
fi

info()  { printf '%s==>%s %s\n' "$BOLD" "$RESET" "$*"; }
ok()    { printf '%s  ok%s %s\n' "$GREEN" "$RESET" "$*"; }
warn()  { printf '%s warn%s %s\n' "$YELLOW" "$RESET" "$*" >&2; }
die()   { printf '%serror%s %s\n' "$RED" "$RESET" "$*" >&2; exit 1; }

run() {
    if [ "$DRY_RUN" -eq 1 ]; then
        printf '  would run: %s\n' "$*"
    else
        "$@"
    fi
}

usage() {
    cat <<'EOF'
Asli setup, for macOS and Linux.

Usage: ./setup.sh [options]

Options:
  --build-only    Install prerequisites and build. Do not install the binary.
  --install       Build, then install the binary into ~/.local/bin (override with ASLI_INSTALL_DIR).
  --with-server   Also set up the relay server, which is the only part that needs Node.js.
  --uninstall     Remove an installed binary and its autostart entry. Does not touch your keychain.
  --dry-run       Print what would happen and change nothing.
  --help          Show this text.

With no options, it installs prerequisites, builds, and runs the test suite.

Building the client does NOT require Node.js. Node is needed only for the relay server,
which is what --with-server sets up.
EOF
}

while [ $# -gt 0 ]; do
    case "$1" in
        --build-only) BUILD_ONLY=1 ;;
        --install) DO_INSTALL=1 ;;
        --with-server) WITH_SERVER=1 ;;
        --uninstall) DO_UNINSTALL=1 ;;
        --dry-run) DRY_RUN=1 ;;
        --help|-h) usage; exit 0 ;;
        *) die "unknown option: $1. Run ./setup.sh --help for the list." ;;
    esac
    shift
done

detect_os() {
    case "$(uname -s)" in
        Darwin) echo "macos" ;;
        Linux)  echo "linux" ;;
        *) die "unsupported operating system: $(uname -s). Asli targets Windows, macOS and Linux; on Windows use setup.ps1." ;;
    esac
}

detect_distro() {
    if [ -r /etc/os-release ]; then
        # shellcheck disable=SC1091
        . /etc/os-release
        echo "${ID_LIKE:-${ID:-unknown}}"
    else
        echo "unknown"
    fi
}

# Prints the package manager install command for this distro, or nothing if we do not know it.
linux_packages() {
    local distro="$1"
    case "$distro" in
        *arch*)   echo "sudo pacman -S --needed base-devel pkgconf" ;;
        *debian*|*ubuntu*) echo "sudo apt-get install -y build-essential pkg-config" ;;
        *fedora*|*rhel*)   echo "sudo dnf install -y @c-development pkgconf-pkg-config" ;;
        *) echo "" ;;
    esac
}

ensure_rust() {
    if command -v cargo >/dev/null 2>&1; then
        ok "Rust is present ($(cargo --version))"
        return
    fi
    if [ -x "$HOME/.cargo/bin/cargo" ]; then
        # shellcheck disable=SC1091
        . "$HOME/.cargo/env"
        ok "Rust found in ~/.cargo/bin"
        return
    fi

    info "Rust is not installed. Installing it with rustup (this is a user level install, no root needed)."
    if [ "$DRY_RUN" -eq 1 ]; then
        printf '  would run: curl --proto =https --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal --component rustfmt --component clippy\n'
        return
    fi
    command -v curl >/dev/null 2>&1 || die "curl is required to install Rust. Install curl, then run this script again."
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs |
        sh -s -- -y --profile minimal --component rustfmt --component clippy ||
        die "rustup install failed. Install Rust manually from https://rustup.rs and run this script again."
    # shellcheck disable=SC1091
    . "$HOME/.cargo/env"
    ok "Rust installed ($(cargo --version))"
}

ensure_macos_tools() {
    if xcode-select -p >/dev/null 2>&1; then
        ok "Xcode command line tools are present"
    else
        warn "Xcode command line tools are missing."
        printf '  Run this, complete the dialog, then run this script again:\n    xcode-select --install\n'
        die "missing prerequisite: Xcode command line tools"
    fi
}

ensure_linux_tools() {
    local distro cmd
    distro="$(detect_distro)"

    if command -v cc >/dev/null 2>&1 && command -v pkg-config >/dev/null 2>&1; then
        ok "C toolchain and pkg-config are present"
        return
    fi

    cmd="$(linux_packages "$distro")"
    warn "A C toolchain is required to build (Rust links against the system linker)."
    if [ -n "$cmd" ]; then
        printf '  Run this, then run this script again:\n    %s\n' "$cmd"
    else
        printf '  Your distribution (%s) is not one we have a package list for.\n' "$distro"
        printf '  Install a C compiler and pkg-config using your package manager, then run this script again.\n'
    fi
    die "missing prerequisite: C toolchain"
}

ensure_node() {
    if command -v node >/dev/null 2>&1; then
        ok "Node.js is present ($(node --version)), which the relay server needs"
    else
        warn "Node.js is not installed, and the relay server needs it."
        printf '  Install Node.js 24 LTS or newer from https://nodejs.org or your package manager,\n'
        printf '  then run: ./setup.sh --with-server\n'
        die "missing prerequisite: Node.js (only needed for --with-server)"
    fi
}

do_uninstall() {
    local target="$INSTALL_DIR/asli"
    if [ -e "$target" ]; then
        info "Removing $target"
        run rm -f "$target"
        ok "binary removed"
    else
        ok "nothing installed at $target"
    fi

    local autostart="$HOME/.config/autostart/asli.desktop"
    if [ -e "$autostart" ]; then
        info "Removing autostart entry $autostart"
        run rm -f "$autostart"
        ok "autostart entry removed"
    fi

    local agent="$HOME/Library/LaunchAgents/app.asli.plist"
    if [ -e "$agent" ]; then
        info "Removing launch agent $agent"
        run rm -f "$agent"
        ok "launch agent removed"
    fi

    printf '\n'
    info "Uninstall complete."
    printf '  Your account key is still in your OS keychain. Nothing here deleted it.\n'
    printf '  To remove it as well, open the tray menu before uninstalling and choose Reset account,\n'
    printf '  or delete the "asli" entry from your keychain by hand.\n'
}

main() {
    local os
    os="$(detect_os)"

    printf '%sAsli setup%s (%s)\n\n' "$BOLD" "$RESET" "$os"
    [ "$DRY_RUN" -eq 1 ] && info "Dry run: nothing will be changed."

    if [ "$DO_UNINSTALL" -eq 1 ]; then
        do_uninstall
        exit 0
    fi

    info "Checking prerequisites"
    case "$os" in
        macos) ensure_macos_tools ;;
        linux) ensure_linux_tools ;;
    esac
    ensure_rust
    [ "$WITH_SERVER" -eq 1 ] && ensure_node

    printf '\n'
    info "Building"
    run cargo build --release --workspace || die "the build failed. The output above says why."
    ok "build finished"

    printf '\n'
    info "Running tests"
    run cargo test --workspace || die "tests failed. Please open an issue with the output above."
    ok "tests passed"

    if [ "$WITH_SERVER" -eq 1 ]; then
        printf '\n'
        if [ -d "$REPO_ROOT/server" ]; then
            info "Setting up the relay server"
            run sh -c "cd '$REPO_ROOT/server' && npm ci"
            ok "server dependencies installed. Start it with: cd server && npm start"
        else
            warn "The relay server is not in this repository yet, so there is nothing to set up."
            printf '  The server lands in M1.\n'
        fi
    fi

    printf '\n'
    if [ "$DO_INSTALL" -eq 1 ]; then
        warn "There is no installable binary yet."
        printf '  Asli is at M0: the crypto library builds and is tested, and the tray client is not\n'
        printf '  written yet. When it exists, --install will place it in %s.\n' "$INSTALL_DIR"
    elif [ "$BUILD_ONLY" -eq 1 ]; then
        ok "Build only requested, stopping here."
    fi

    printf '\n%sDone.%s\n' "$GREEN" "$RESET"
    printf 'What exists today: the asli-crypto library, its test suite, and the frozen protocol vectors.\n'
    printf 'What does not exist yet: the tray client, the relay server, and installable packages.\n'
    printf 'See docs/BUILDING.md for the details.\n'
}

main "$@"
