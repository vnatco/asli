#!/usr/bin/env bash
#
# Installs a built Asli for the current user on Linux, or removes it. No root, nothing outside the
# home directory.
#
# The one copy of this logic: `setup.sh --install` runs it with the binary it just built, and the
# AppImage runs it with the binary inside itself, so a double clicked AppImage installs exactly
# what a source build installs.
#
#   install.sh --binary <path> [--no-start] [--dry-run]
#   install.sh --uninstall [--dry-run]
#
# It reads the desktop entry and the icon from its own directory. Install puts in place:
#
#   ~/.local/bin/asli                                      the program (ASLI_INSTALL_DIR overrides)
#   ~/.local/share/applications/asli.desktop               the menu entry
#   ~/.local/share/icons/hicolor/scalable/apps/asli.svg    its icon
#   ~/.config/autostart/asli.desktop                       start at login, written by the program
#   ~/.local/share/asli/install.sh                         this script, so uninstall needs nothing else
#
# Uninstall removes all of them. It never touches the account key in the keychain, the settings or
# the history, which live elsewhere and survive a reinstall.

set -euo pipefail

BINARY=''
UNINSTALL=0
START=1
DRY_RUN=0

readonly INSTALL_DIR="${ASLI_INSTALL_DIR:-$HOME/.local/bin}"
readonly DATA_HOME="${XDG_DATA_HOME:-$HOME/.local/share}"
readonly DESKTOP_ENTRY="$DATA_HOME/applications/asli.desktop"
readonly ICON_FILE="$DATA_HOME/icons/hicolor/scalable/apps/asli.svg"
readonly AUTOSTART_DIR="${XDG_CONFIG_HOME:-$HOME/.config}/autostart"
readonly SELF_COPY="$DATA_HOME/asli/install.sh"
readonly LOG_DIR="${XDG_STATE_HOME:-$HOME/.local/state}/asli"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly HERE

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

while [ $# -gt 0 ]; do
    case "$1" in
        --binary) [ $# -ge 2 ] || die "--binary needs a path"; BINARY="$2"; shift ;;
        --uninstall) UNINSTALL=1 ;;
        --no-start) START=0 ;;
        --dry-run) DRY_RUN=1 ;;
        --help|-h) sed -n '2,23p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *) die "unknown option: $1" ;;
    esac
    shift
done

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

# Starts the tray detached from this process, so it outlives both a closed terminal and an
# AppImage that unmounts itself as soon as this script returns.
start_tray() {
    info "Starting Asli"
    if [ "$DRY_RUN" -eq 1 ]; then
        printf '  would start: %s tray\n' "$INSTALL_DIR/asli"
        return
    fi
    # Logged to a file rather than discarded, so there is something to read when it misbehaves.
    mkdir -p "$LOG_DIR"
    if command -v setsid >/dev/null 2>&1; then
        setsid -f "$INSTALL_DIR/asli" tray >"$LOG_DIR/asli.log" 2>&1 </dev/null
    else
        nohup "$INSTALL_DIR/asli" tray >"$LOG_DIR/asli.log" 2>&1 </dev/null &
    fi
    ok "Asli is running. Look for its icon in the tray."
}

do_install() {
    [ -n "$BINARY" ] || die "nothing to install: pass --binary <path>"
    [ -f "$BINARY" ] || [ "$DRY_RUN" -eq 1 ] || die "no binary at $BINARY"
    [ -f "$HERE/asli.desktop" ] || die "asli.desktop is missing from $HERE"
    [ -f "$HERE/asli.svg" ] || die "asli.svg is missing from $HERE"

    info "Installing into $INSTALL_DIR"
    # A second double click on the same AppImage should raise the window, not restart Asli. The
    # copy is replaced only when it differs, and only then does the running one have to stop.
    if [ -f "$INSTALL_DIR/asli" ] && cmp -s "$BINARY" "$INSTALL_DIR/asli"; then
        ok "this version is already installed at $INSTALL_DIR/asli"
    else
        stop_running
        run mkdir -p "$INSTALL_DIR"
        run install -m 755 "$BINARY" "$INSTALL_DIR/asli"
        ok "binary installed at $INSTALL_DIR/asli"
    fi

    run mkdir -p "$(dirname "$ICON_FILE")" "$(dirname "$DESKTOP_ENTRY")" "$(dirname "$SELF_COPY")"
    run install -m 644 "$HERE/asli.svg" "$ICON_FILE"
    # The packaged entry says Exec=asli, which relies on PATH. The installed one names the binary
    # exactly, because ~/.local/bin is not on PATH in every session. Written line by line rather
    # than with sed, so a path containing & or | cannot corrupt the replacement, and quoted, so a
    # path with a space is still one argument.
    if [ "$DRY_RUN" -eq 1 ]; then
        printf '  would write: %s\n' "$DESKTOP_ENTRY"
    else
        local program line
        program="$(desktop_exec_quote "$INSTALL_DIR/asli")"
        while IFS= read -r line || [ -n "$line" ]; do
            case "$line" in
                "Exec=asli "*) printf 'Exec=%s %s\n' "$program" "${line#Exec=asli }" ;;
                "TryExec=asli") printf 'TryExec=%s\n' "${INSTALL_DIR//\\/\\\\}/asli" ;;
                *) printf '%s\n' "$line" ;;
            esac
        done < "$HERE/asli.desktop" > "$DESKTOP_ENTRY"
        chmod 644 "$DESKTOP_ENTRY"
    fi
    refresh_desktop_caches
    ok "application entry and icon installed"

    # Kept, so uninstalling works after the AppImage or the source tree it came from is gone.
    if [ "$HERE/install.sh" != "$SELF_COPY" ]; then
        run install -m 755 "$HERE/install.sh" "$SELF_COPY"
    fi

    # The binary writes the login entry itself, so it points at the installed copy, and it is the
    # same code that checks the entry every time the tray starts.
    run "$INSTALL_DIR/asli" autostart on ||
        warn "could not enable launch at login. Run 'asli autostart on' later."

    case ":$PATH:" in
        *":$INSTALL_DIR:"*) ;;
        *) warn "$INSTALL_DIR is not on your PATH. Add it to use the asli command from a shell." ;;
    esac

    if [ "$START" -eq 1 ]; then
        printf '\n'
        start_tray
        printf '  Its log, now and at every login: %s\n' "$LOG_DIR/asli.log"
    fi
    printf '  To uninstall: %s --uninstall\n' "$SELF_COPY"
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

    # Removed as files rather than through 'asli autostart off', which would also record the
    # choice in the settings, and uninstalling must leave the settings as they were. The second
    # name is what builds before this one wrote, so an older install is cleaned too.
    local autostart
    for autostart in "$AUTOSTART_DIR/asli.desktop" "$AUTOSTART_DIR/dev.vnat.asli.desktop"; do
        if [ -e "$autostart" ]; then
            info "Removing autostart entry $autostart"
            run rm -f "$autostart"
            ok "autostart entry removed"
        fi
    done

    local removed_entry=0 file
    for file in "$DESKTOP_ENTRY" "$ICON_FILE"; do
        if [ -e "$file" ]; then
            info "Removing $file"
            run rm -f "$file"
            removed_entry=1
        fi
    done
    if [ "$removed_entry" -eq 1 ]; then
        refresh_desktop_caches
        ok "application entry and icon removed"
    fi

    if [ -e "$SELF_COPY" ]; then
        run rm -f "$SELF_COPY"
        run rmdir "$(dirname "$SELF_COPY")" 2>/dev/null || true
    fi

    printf '\n'
    info "Uninstall complete."
    printf '  Your account key is still in your OS keychain, and your settings and history are\n'
    printf '  where they were. Nothing here deleted them. To remove the key as well, run\n'
    printf '  "asli reset" before uninstalling, or delete the "asli" entry from your keychain.\n'
}

[ "$DRY_RUN" -eq 1 ] && info "Dry run: nothing will be changed."
if [ "$UNINSTALL" -eq 1 ]; then
    do_uninstall
else
    do_install
fi
