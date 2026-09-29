#!/usr/bin/env bash
#
# Builds the Linux release artifacts into dist/ at the repository root:
#
#   asli-<version>-linux-<arch>.AppImage   the one to download: double click, and it installs and starts
#   asli-<version>-linux-<arch>.deb        for apt
#   asli-<version>-linux-<arch>.rpm        for dnf and zypper
#   asli-<version>-linux-<arch>.tar.gz     the plain files, which the asli-bin AUR package unpacks
#   SHA256SUMS                             over every artifact of this version in dist/
#
# One command, no arguments, from a fresh clone. It checks every tool first and stops with the
# exact command to install whatever is missing, so it never builds half the set.
#
# The binary is built against glibc 2.28 with cargo-zigbuild, not against this machine's own glibc.
# Built the ordinary way on a current distribution it would need that distribution's glibc and
# refuse to start on anything older, which for an AppImage defeats the point. ASLI_GLIBC overrides.
#
# Usage: packaging/linux/build-installer.sh [--dry-run] [--help]

set -euo pipefail

DRY_RUN=0
WORK=""
GLIBC_NEEDED=""
readonly GLIBC="${ASLI_GLIBC:-2.28}"

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$HERE/../.." && pwd)"
readonly HERE REPO_ROOT
readonly DIST="$REPO_ROOT/dist"

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
        --dry-run) DRY_RUN=1 ;;
        --help|-h) sed -n '2,19p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *) die "unknown option: $1. Run $0 --help for the list." ;;
    esac
    shift
done

[ "$(uname -s)" = "Linux" ] || die "this builds the Linux artifacts and has to run on Linux."

VERSION="$(sed -n 's/^version = "\(.*\)"/\1/p' "$REPO_ROOT/Cargo.toml" | head -n 1)"
[ -n "$VERSION" ] || die "could not read the version from Cargo.toml"
ARCH="$(uname -m)"
case "$ARCH" in
    x86_64|aarch64) ;;
    *) die "unsupported architecture: $ARCH. Asli is released for x86_64 and aarch64." ;;
esac
readonly VERSION ARCH
readonly TRIPLE="$ARCH-unknown-linux-gnu"
readonly BUILT="$REPO_ROOT/target/$TRIPLE/release/asli"
readonly BASE="asli-$VERSION-linux-$ARCH"

# cargo and zig are commonly installed without being on PATH in a fresh shell.
[ -d "$HOME/.cargo/bin" ] && PATH="$HOME/.cargo/bin:$PATH"
[ -d "$HOME/.local/bin" ] && PATH="$HOME/.local/bin:$PATH"

distro_family() {
    local id='' like=''
    if [ -r /etc/os-release ]; then
        # shellcheck disable=SC1091
        id="$(. /etc/os-release; echo "${ID:-}")"
        # shellcheck disable=SC1091
        like="$(. /etc/os-release; echo "${ID_LIKE:-}")"
    fi
    case " $id $like " in
        *" arch "*) echo arch ;;
        *" debian "*|*" ubuntu "*) echo debian ;;
        *" fedora "*|*" rhel "*) echo fedora ;;
        *) echo other ;;
    esac
}

# Every missing tool is collected before stopping, so one run lists everything to install rather
# than one thing per attempt.
MISSING=()
need() { MISSING+=("$1"$'\n'"    $2"); }

check_prerequisites() {
    local family
    family="$(distro_family)"

    if command -v cargo >/dev/null 2>&1; then
        ok "Rust is present ($(cargo --version))"
    else
        need "Rust" "curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh"
    fi

    if command -v cc >/dev/null 2>&1 && command -v pkg-config >/dev/null 2>&1 &&
        pkg-config --exists fontconfig 2>/dev/null; then
        ok "C toolchain, pkg-config and the fontconfig headers are present"
    else
        case "$family" in
            arch) need "a C toolchain and fontconfig" "sudo pacman -S --needed base-devel pkgconf fontconfig" ;;
            debian) need "a C toolchain and fontconfig" "sudo apt-get install -y build-essential pkg-config libfontconfig-dev" ;;
            fedora) need "a C toolchain and fontconfig" "sudo dnf install -y @c-development pkgconf-pkg-config fontconfig-devel" ;;
            *) need "a C toolchain and fontconfig" "install a C compiler, pkg-config and the fontconfig development files" ;;
        esac
    fi

    if command -v zig >/dev/null 2>&1; then
        ok "zig is present ($(zig version))"
    else
        case "$family" in
            arch) need "zig, which links against an older glibc" "sudo pacman -S zig" ;;
            *) need "zig, which links against an older glibc" \
                "mkdir -p ~/.local/opt ~/.local/bin && curl -L https://ziglang.org/download/0.16.0/zig-$ARCH-linux-0.16.0.tar.xz | tar -xJ -C ~/.local/opt && ln -sf ~/.local/opt/zig-$ARCH-linux-0.16.0/zig ~/.local/bin/zig" ;;
        esac
    fi

    local sub
    for sub in zigbuild deb generate-rpm; do
        if command -v "cargo-$sub" >/dev/null 2>&1; then
            ok "cargo-$sub is present"
        else
            need "cargo-$sub" "cargo install --locked cargo-$sub"
        fi
    done

    if command -v appimagetool >/dev/null 2>&1; then
        ok "appimagetool is present"
    else
        need "appimagetool" \
            "mkdir -p ~/.local/bin && curl -L -o ~/.local/bin/appimagetool https://github.com/AppImage/appimagetool/releases/download/continuous/appimagetool-$ARCH.AppImage && chmod +x ~/.local/bin/appimagetool"
    fi

    local tool
    for tool in readelf sha256sum tar; do
        command -v "$tool" >/dev/null 2>&1 || need "$tool" "install binutils and coreutils with your package manager"
    done

    if [ "${#MISSING[@]}" -gt 0 ]; then
        printf '\n'
        warn "Missing, with the command that installs each:"
        local item
        for item in "${MISSING[@]}"; do
            printf '  %s\n' "$item"
        done
        printf '\nInstall them, then run this again.\n'
        die "missing prerequisites"
    fi
}

# The newest glibc symbol version the binary asks for, and every shared library it names. Checked
# rather than trusted: a stray dependency on a library that is not on every desktop, or a symbol
# newer than the target, is exactly the failure that shows up only on someone else's machine.
check_binary() {
    local newest needed lib
    newest="$(readelf -W --dyn-syms "$BUILT" | grep -o 'GLIBC_[0-9][0-9.]*' | sed 's/GLIBC_//' | sort -uV | tail -n 1)"
    if [ "$(printf '%s\n%s\n' "$newest" "$GLIBC" | sort -V | tail -n 1)" != "$GLIBC" ]; then
        die "the binary needs glibc $newest, newer than the $GLIBC it was built for"
    fi
    needed="$(readelf -d "$BUILT" | sed -n 's/.*Shared library: \[\(.*\)\]/\1/p')"
    for lib in $needed; do
        case "$lib" in
            libc.so.6|libm.so.6|libpthread.so.0|libdl.so.2|librt.so.1|libgcc_s.so.1|ld-linux-*|libfontconfig.so.1) ;;
            *) die "the binary links $lib, which is not on every desktop. Find what pulled it in before shipping." ;;
        esac
    done
    ok "needs glibc $newest or newer, and only: $(echo "$needed" | tr '\n' ' ')"
    GLIBC_NEEDED="$newest"
}

build() {
    info "Building asli $VERSION for $TRIPLE against glibc $GLIBC"
    run cargo zigbuild --release --locked -p asli-app --target "$TRIPLE.$GLIBC" ||
        die "the build failed. The output above says why."
    if [ "$DRY_RUN" -eq 0 ]; then
        [ -x "$BUILT" ] || die "the build finished but $BUILT is not there"
        check_binary
    fi
}

build_appimage() {
    local out="$DIST/$BASE.AppImage"
    info "AppImage"
    if [ "$DRY_RUN" -eq 1 ]; then
        printf '  would stage an AppDir and run: appimagetool <AppDir> %s\n' "$out"
        return
    fi

    local appdir="$WORK/Asli.AppDir"
    mkdir -p "$appdir/usr/bin" "$appdir/usr/share/asli" "$appdir/usr/share/applications" \
        "$appdir/usr/share/icons/hicolor/scalable/apps" "$appdir/usr/share/icons/hicolor/256x256/apps"
    install -m 755 "$HERE/AppRun" "$appdir/AppRun"
    install -m 755 "$BUILT" "$appdir/usr/bin/asli"
    # What install.sh reads, beside it, exactly as in the source tree.
    install -m 755 "$HERE/install.sh" "$appdir/usr/share/asli/install.sh"
    install -m 644 "$HERE/asli.desktop" "$appdir/usr/share/asli/asli.desktop"
    install -m 644 "$HERE/asli.svg" "$appdir/usr/share/asli/asli.svg"
    # What the AppImage itself shows in a file manager and to integration tools. TryExec is left
    # out of this copy: asli is not on PATH inside the image, and a launcher would hide the entry.
    grep -v '^TryExec=' "$HERE/asli.desktop" > "$appdir/asli.desktop"
    cp "$appdir/asli.desktop" "$appdir/usr/share/applications/asli.desktop"
    install -m 644 "$HERE/asli.svg" "$appdir/asli.svg"
    install -m 644 "$HERE/asli.svg" "$appdir/usr/share/icons/hicolor/scalable/apps/asli.svg"
    install -m 644 "$REPO_ROOT/packaging/icons/asli-256.png" "$appdir/usr/share/icons/hicolor/256x256/apps/asli.png"
    install -m 644 "$REPO_ROOT/packaging/icons/asli-256.png" "$appdir/.DirIcon"

    # Extract and run, so building does not need FUSE on this machine.
    rm -f "$out"
    env APPIMAGE_EXTRACT_AND_RUN=1 ARCH="$ARCH" appimagetool --no-appstream "$appdir" "$out" ||
        die "appimagetool failed. The output above says why."
    ok "$out"
}

build_deb() {
    local out="$DIST/$BASE.deb"
    info "Debian package"
    run cargo deb -p asli-app --no-build --no-strip --target "$TRIPLE" --output "$out" ||
        die "cargo deb failed. The output above says why."
    [ "$DRY_RUN" -eq 1 ] || ok "$out"
}

build_rpm() {
    local out="$DIST/$BASE.rpm"
    info "RPM package"
    run cargo generate-rpm -p crates/asli-app --target "$TRIPLE" \
        --metadata-overwrite "$HERE/rpm-metadata.toml#package.metadata.generate-rpm" --output "$out" ||
        die "cargo generate-rpm failed. The output above says why."
    [ "$DRY_RUN" -eq 1 ] || ok "$out"
}

build_tarball() {
    local out="$DIST/$BASE.tar.gz"
    info "Tarball"
    if [ "$DRY_RUN" -eq 1 ]; then
        printf '  would write: %s\n' "$out"
        return
    fi
    local stage="$WORK/$BASE"
    mkdir -p "$stage"
    install -m 755 "$BUILT" "$stage/asli"
    install -m 644 "$REPO_ROOT/LICENSE" "$REPO_ROOT/README.md" "$HERE/asli.desktop" "$HERE/asli.svg" \
        "$HERE/systemd/asli.service" "$stage/"
    install -m 644 "$REPO_ROOT/packaging/icons/asli-256.png" "$stage/asli.png"
    tar -C "$WORK" --owner=0 --group=0 --numeric-owner --sort=name -czf "$out" "$BASE"
    ok "$out"
}

write_checksums() {
    info "Checksums"
    if [ "$DRY_RUN" -eq 1 ]; then
        printf '  would write: %s over asli-%s-*\n' "$DIST/SHA256SUMS" "$VERSION"
        return
    fi
    # Over every artifact of this version in dist/, including any copied in from the other two
    # machines, so the last machine to run writes the file that covers the whole release.
    (cd "$DIST" && sha256sum -- "asli-$VERSION-"* > SHA256SUMS)
    ok "$DIST/SHA256SUMS"
}

# A run that fails part way leaves none of this version's Linux artifacts behind, so nothing in
# dist/ looks finished when it is not.
FINISHED=0
cleanup() {
    rm -rf "$WORK"
    if [ "$FINISHED" -eq 0 ] && [ "$DRY_RUN" -eq 0 ]; then
        rm -f "$DIST/$BASE.AppImage" "$DIST/$BASE.deb" "$DIST/$BASE.rpm" "$DIST/$BASE.tar.gz"
    fi
}

main() {
    printf '%sAsli Linux installers%s, version %s, %s\n\n' "$BOLD" "$RESET" "$VERSION" "$ARCH"
    [ "$DRY_RUN" -eq 1 ] && info "Dry run: nothing will be changed."

    info "Checking prerequisites"
    check_prerequisites
    printf '\n'

    cd "$REPO_ROOT"
    build
    printf '\n'

    run mkdir -p "$DIST"
    WORK="$(mktemp -d)"
    trap cleanup EXIT

    build_appimage
    build_deb
    build_rpm
    build_tarball
    write_checksums
    FINISHED=1

    printf '\n%sDone.%s\n' "$GREEN" "$RESET"
    if [ "$DRY_RUN" -eq 0 ]; then
        printf '\nProduced:\n'
        local file
        for file in "$DIST/$BASE.AppImage" "$DIST/$BASE.deb" "$DIST/$BASE.rpm" "$DIST/$BASE.tar.gz" "$DIST/SHA256SUMS"; do
            printf '  %s\n' "$file"
        done
        printf '\nBuilt against glibc %s; the binary asks for glibc %s or newer.\n' "$GLIBC" "$GLIBC_NEEDED"
        if [ "$GLIBC" = "2.28" ]; then
            printf 'That is Debian 10, Ubuntu 18.10, RHEL 8 and Fedora 29, and everything after them.\n'
        fi
    fi
}

main
