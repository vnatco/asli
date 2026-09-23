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
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly REPO_ROOT

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
  --build-only    Check prerequisites and build. Do not run the tests and do not install.
  --install       Build, then install and start it: on Linux the binary into ~/.local/bin
                  (override with ASLI_INSTALL_DIR) with its menu entry and icon, on macOS
                  ~/Applications/Asli.app linked from ~/.local/bin. Turns on launch at login.
  --with-server   Also set up the relay server, which is the only part that needs Node.js.
  --uninstall     Remove what --install put in place. Does not touch your keychain.
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

# Freedesktop locations for the application entry and its icon, so the window and the task
# manager show the Asli mark rather than a generic one. Without these the icon works only on a
# machine where somebody copied them by hand.
readonly DATA_HOME="${XDG_DATA_HOME:-$HOME/.local/share}"
readonly DESKTOP_ENTRY="$DATA_HOME/applications/asli.desktop"
readonly ICON_FILE="$DATA_HOME/icons/hicolor/scalable/apps/asli.svg"
readonly AUTOSTART_DIR="${XDG_CONFIG_HOME:-$HOME/.config}/autostart"
# On macOS the binary lives inside an application bundle, so the system reads its Info.plist:
# that is what keeps a menu bar app out of the Dock and gives it a name in permission prompts.
readonly MAC_APP="${ASLI_MAC_APP:-$HOME/Applications/Asli.app}"
# macOS keeps a user's application logs in ~/Library/Logs, Linux in the XDG state directory. The
# same file either way, and the same one the login agent writes to, so there is one log to read.
if [ "$(uname -s)" = "Darwin" ]; then
    readonly LOG_DIR="$HOME/Library/Logs/Asli"
else
    readonly LOG_DIR="${XDG_STATE_HOME:-$HOME/.local/state}/asli"
fi

# Stops every running copy, so the new binary is what runs next. Matched on the exact process
# name, never on a command line, which would also match this script's own shell.
stop_running() {
    if pgrep -x asli >/dev/null 2>&1; then
        info "Stopping the running copy of Asli"
        run pkill -x asli || true
        [ "$DRY_RUN" -eq 1 ] || sleep 1
        ok "stopped"
    fi
}

# Starts the tray detached from this terminal, so closing the terminal does not end it.
start_tray() {
    local os="$1"
    info "Starting Asli"
    if [ "$DRY_RUN" -eq 1 ]; then
        printf '  would start the tray\n'
    elif [ "$os" = "macos" ]; then
        mkdir -p "$LOG_DIR"
        # Started the way login starts it, through the agent, so the install exercises the same
        # path and its output lands in the same log. `open` is the fallback for a machine with
        # launch at login turned off, and it leaves no log: LaunchServices discards both streams,
        # which is why a menu bar item that failed to appear once took a morning to explain.
        local agent="$HOME/Library/LaunchAgents/dev.vnat.asli.plist"
        if [ -f "$agent" ]; then
            launchctl bootstrap "gui/$(id -u)" "$agent" 2>/dev/null ||
                launchctl kickstart -k "gui/$(id -u)/dev.vnat.asli" 2>/dev/null ||
                open "$MAC_APP" --args tray
        else
            open "$MAC_APP" --args tray
        fi
    else
        # Logged to a file rather than discarded, so there is something to read when it misbehaves.
        mkdir -p "$LOG_DIR"
        nohup "$INSTALL_DIR/asli" tray >"$LOG_DIR/asli.log" 2>&1 &
    fi
    ok "Asli is running. Look for its icon in the tray or menu bar."
}

install_macos_bundle() {
    local built="$1"
    info "Building $MAC_APP"
    run mkdir -p "$MAC_APP/Contents/MacOS"
    run install -m 755 "$built" "$MAC_APP/Contents/MacOS/asli"
    run install -m 644 "$REPO_ROOT/packaging/macos/Info.plist" "$MAC_APP/Contents/Info.plist"
    # Apple Silicon refuses to run unsigned code, and a bundle whose contents changed needs its
    # signature redone. An ad hoc signature is local only and proves nothing to anyone else, which
    # is fine for a build made on this Mac.
    if command -v codesign >/dev/null 2>&1; then
        run codesign --force --sign - "$MAC_APP" || warn "could not sign the bundle; macOS may refuse to open it"
    fi
    run mkdir -p "$INSTALL_DIR"
    run ln -sf "$MAC_APP/Contents/MacOS/asli" "$INSTALL_DIR/asli"
    ok "Asli.app installed, and $INSTALL_DIR/asli links into it"
}

# Tells the desktop about new or removed entries. Every one of these is optional: a desktop that
# lacks the tool picks the change up at next login instead.
refresh_desktop_caches() {
    if command -v update-desktop-database >/dev/null 2>&1; then
        run update-desktop-database -q "$DATA_HOME/applications" || true
    fi
    if command -v gtk-update-icon-cache >/dev/null 2>&1 && [ -e "$DATA_HOME/icons/hicolor/index.theme" ]; then
        run gtk-update-icon-cache -q -t "$DATA_HOME/icons/hicolor" || true
    fi
    if command -v kbuildsycoca6 >/dev/null 2>&1; then
        run kbuildsycoca6 --noincremental >/dev/null 2>&1 || true
    fi
}

# Quotes a program path for a desktop entry Exec= line, the same way the app does. Percent signs
# are doubled everywhere; inside quotes the quote, backtick, dollar sign and backslash are escaped,
# and every backslash is then doubled again because the value itself is an escaped string.
desktop_exec_quote() {
    local path="${1//%/%%}"
    case "$1" in
        *[[:space:]\"\'\\\<\>~\|\&\;\$\*\?#\(\)\`]*) ;;
        *) printf '%s' "$path"; return ;;
    esac
    local bs=$'\\' out='' c i
    for (( i = 0; i < ${#path}; i++ )); do
        c="${path:i:1}"
        case "$c" in
            "$bs") out+="$bs$bs$bs$bs" ;;
            '"'|'`'|'$') out+="$bs$bs$c" ;;
            *) out+="$c" ;;
        esac
    done
    printf '"%s"' "$out"
}

do_install() {
    local os="$1"
    local built="$REPO_ROOT/target/release/asli"
    [ -x "$built" ] || [ "$DRY_RUN" -eq 1 ] || die "no binary at $built. The build step should have produced it."

    info "Installing"
    stop_running
    if [ "$os" = "macos" ]; then
        install_macos_bundle "$built"
    else
        run mkdir -p "$INSTALL_DIR"
        run install -m 755 "$built" "$INSTALL_DIR/asli"
        ok "binary installed at $INSTALL_DIR/asli"
    fi

    if [ "$os" = "linux" ]; then
        run mkdir -p "$(dirname "$ICON_FILE")" "$(dirname "$DESKTOP_ENTRY")"
        run install -m 644 "$REPO_ROOT/packaging/linux/asli.svg" "$ICON_FILE"
        # The packaged entry says Exec=asli, which relies on PATH. The installed one names the
        # binary exactly, because ~/.local/bin is not on PATH in every session. Written line by
        # line rather than with sed, so a path containing & or | cannot corrupt the replacement,
        # and quoted, so a path with a space is still one argument.
        if [ "$DRY_RUN" -eq 1 ]; then
            printf '  would write: %s\n' "$DESKTOP_ENTRY"
        else
            local program line
            program="$(desktop_exec_quote "$INSTALL_DIR/asli")"
            while IFS= read -r line || [ -n "$line" ]; do
                case "$line" in
                    "Exec=asli "*) printf 'Exec=%s %s\n' "$program" "${line#Exec=asli }" ;;
                    *) printf '%s\n' "$line" ;;
                esac
            done < "$REPO_ROOT/packaging/linux/asli.desktop" > "$DESKTOP_ENTRY"
            chmod 644 "$DESKTOP_ENTRY"
        fi
        refresh_desktop_caches
        ok "application entry and icon installed"
    fi

    # The binary writes the entry itself, so it points at the installed copy, and it is the same
    # code that runs every time the tray starts. On macOS that is the copy inside the bundle.
    local installed="$INSTALL_DIR/asli"
    [ "$os" = "macos" ] && installed="$MAC_APP/Contents/MacOS/asli"
    run "$installed" autostart on || warn "could not enable launch at login. Run 'asli autostart on' later."

    case ":$PATH:" in
        *":$INSTALL_DIR:"*) ;;
        *) warn "$INSTALL_DIR is not on your PATH. Add it to use the asli command from a shell." ;;
    esac

    printf '\n'
    start_tray "$os"
    printf '  It also starts by itself at login.\n'
    if [ "$os" = "windows" ]; then
        printf '  To watch its log, quit it from the menu and run: %s tray\n' "$installed"
    else
        printf '  Its log, now and at every login: %s\n' "$LOG_DIR/asli.log"
    fi
    if [ "$os" = "macos" ]; then
        printf '  If macOS ever asks whether Asli may paste from other apps, choose Allow, or it\n'
        printf '  cannot send what you copy on this Mac. It still receives either way.\n'
    fi
}

do_uninstall() {
    stop_running

    local target="$INSTALL_DIR/asli"
    if [ -e "$target" ] || [ -L "$target" ]; then
        info "Removing $target"
        run rm -f "$target"
        ok "binary removed"
    else
        ok "nothing installed at $target"
    fi

    # The second name is what builds before this one wrote, so an older install is cleaned too.
    local autostart
    for autostart in "$AUTOSTART_DIR/asli.desktop" "$AUTOSTART_DIR/dev.vnat.asli.desktop"; do
        if [ -e "$autostart" ]; then
            info "Removing autostart entry $autostart"
            run rm -f "$autostart"
            ok "autostart entry removed"
        fi
    done

    local removed_entry=0
    local file
    for file in "$DESKTOP_ENTRY" "$ICON_FILE"; do
        if [ -e "$file" ]; then
            info "Removing $file"
            run rm -f "$file"
            removed_entry=1
        fi
    done
    [ "$removed_entry" -eq 1 ] && refresh_desktop_caches && ok "application entry and icon removed"

    local agent="$HOME/Library/LaunchAgents/dev.vnat.asli.plist"
    if [ -e "$agent" ]; then
        info "Removing launch agent $agent"
        run rm -f "$agent"
        ok "launch agent removed"
    fi

    if [ -d "$MAC_APP" ]; then
        info "Removing $MAC_APP"
        run rm -rf "$MAC_APP"
        ok "Asli.app removed"
    fi

    printf '\n'
    info "Uninstall complete."
    printf '  Your account key is still in your OS keychain. Nothing here deleted it.\n'
    printf '  To remove it as well, run "asli reset" before uninstalling,\n'
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
    run cargo build --release -p asli-app || die "the build failed. The output above says why."
    ok "build finished"

    if [ "$BUILD_ONLY" -eq 0 ] && [ "$DO_INSTALL" -eq 0 ]; then
        printf '\n'
        info "Running tests"
        run cargo test --workspace || die "tests failed. Please open an issue with the output above."
        ok "tests passed"
    fi

    if [ "$WITH_SERVER" -eq 1 ]; then
        printf '\n'
        info "Setting up the relay server"
        run sh -c "cd '$REPO_ROOT/server' && npm ci"
        ok "server dependencies installed. Start it with: cd server && npm start"
    fi

    printf '\n'
    if [ "$DO_INSTALL" -eq 1 ]; then
        do_install "$os"
    elif [ "$BUILD_ONLY" -eq 1 ]; then
        ok "Build only requested, stopping here."
    else
        info "Built. Run ./setup.sh --install to install it, or run target/release/asli tray directly."
    fi

    printf '\n%sDone.%s\n' "$GREEN" "$RESET"
}

main "$@"
