#!/usr/bin/env bash
#
# Builds the macOS release artifact into dist/ at the repository root:
#
#   asli-<version>-macos-universal.dmg   Asli.app for Apple silicon and Intel, with a link to
#                                        Applications to drag it onto; signed, notarized, stapled
#   SHA256SUMS                           over every artifact of this version in dist/
#
# One command, no arguments, from a fresh clone. Signing and notarization take their identity and
# credentials from the environment and never from the repository. packaging/macos/README.md has
# the one time setup.
#
#   ASLI_SIGN_IDENTITY   "Developer ID Application: Your Name (TEAMID)"
#   ASLI_TEAM_ID         optional; if set, the identity must belong to this team
#   ASLI_NOTARY_PROFILE  a keychain profile saved with `xcrun notarytool store-credentials`
#     or all three of
#   ASLI_NOTARY_KEY, ASLI_NOTARY_KEY_ID, ASLI_NOTARY_ISSUER   an App Store Connect API key
#     or all three of
#   APPLE_ID, APPLE_APP_SPECIFIC_PASSWORD, APPLE_TEAM_ID     an Apple ID and app specific password
#
# The APPLE_ names are the ones electron-builder uses, so an env file already kept for another
# project works here as sourced. APPLE_SIGNING_IDENTITY and APPLE_TEAM_ID stand in for
# ASLI_SIGN_IDENTITY and ASLI_TEAM_ID when those are unset.
#
# With no ASLI_SIGN_IDENTITY it builds an unsigned image instead, named ...-unsigned.dmg so it
# cannot be mistaken for a release, and says what was skipped. ASLI_MAC_ARCHS picks the
# architectures ("arm64 x86_64" by default; "arm64" alone builds ...-macos-aarch64.dmg).
#
# Usage: packaging/macos/build-installer.sh [--dry-run] [--help]

set -euo pipefail

DRY_RUN=0
WORK=""
FINISHED=0
OUT=""

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$HERE/../.." && pwd)"
readonly HERE REPO_ROOT
readonly DIST="$REPO_ROOT/dist"
# The same floor as LSMinimumSystemVersion in Info.plist. Without it the binary is built for the
# SDK's own release and refuses to start on anything older, whatever the plist says.
export MACOSX_DEPLOYMENT_TARGET=11.0

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
        --help|-h) sed -n '2,24p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *) die "unknown option: $1. Run $0 --help for the list." ;;
    esac
    shift
done

[ "$(uname -s)" = "Darwin" ] || die "this builds the macOS artifact and has to run on a Mac."
[ -d "$HOME/.cargo/bin" ] && PATH="$HOME/.cargo/bin:$PATH"

VERSION="$(sed -n 's/^version = "\(.*\)"/\1/p' "$REPO_ROOT/Cargo.toml" | head -n 1)"
[ -n "$VERSION" ] || die "could not read the version from Cargo.toml"
readonly VERSION

read -r -a ARCHS <<< "${ASLI_MAC_ARCHS:-arm64 x86_64}"
TRIPLES=()
for arch in "${ARCHS[@]}"; do
    case "$arch" in
        arm64|aarch64) TRIPLES+=(aarch64-apple-darwin) ;;
        x86_64) TRIPLES+=(x86_64-apple-darwin) ;;
        *) die "unknown architecture in ASLI_MAC_ARCHS: $arch. Use arm64, x86_64 or both." ;;
    esac
done
if [ "${#TRIPLES[@]}" -eq 2 ]; then
    ARCH_NAME=universal
elif [ "${TRIPLES[0]}" = "aarch64-apple-darwin" ]; then
    ARCH_NAME=aarch64
else
    ARCH_NAME=x86_64
fi

ASLI_SIGN_IDENTITY="${ASLI_SIGN_IDENTITY:-${APPLE_SIGNING_IDENTITY:-}}"
ASLI_TEAM_ID="${ASLI_TEAM_ID:-${APPLE_TEAM_ID:-}}"

# Signed, or not signed at all. A signed image that is not notarized still meets a Gatekeeper
# warning on every other Mac, which is the one thing this is for, so that combination is refused
# rather than produced.
SIGN=0
NOTARY_AUTH=()
if [ -n "${ASLI_SIGN_IDENTITY:-}" ]; then
    SIGN=1
    if [ -n "${ASLI_NOTARY_PROFILE:-}" ]; then
        NOTARY_AUTH=(--keychain-profile "$ASLI_NOTARY_PROFILE")
    elif [ -n "${ASLI_NOTARY_KEY:-}" ] && [ -n "${ASLI_NOTARY_KEY_ID:-}" ] && [ -n "${ASLI_NOTARY_ISSUER:-}" ]; then
        NOTARY_AUTH=(--key "$ASLI_NOTARY_KEY" --key-id "$ASLI_NOTARY_KEY_ID" --issuer "$ASLI_NOTARY_ISSUER")
    elif [ -n "${APPLE_ID:-}" ] && [ -n "${APPLE_APP_SPECIFIC_PASSWORD:-}" ] && [ -n "$ASLI_TEAM_ID" ]; then
        NOTARY_AUTH=(--apple-id "$APPLE_ID" --password "$APPLE_APP_SPECIFIC_PASSWORD" --team-id "$ASLI_TEAM_ID")
    else
        die "a signing identity is set but no notarization credentials are. Set ASLI_NOTARY_PROFILE; or ASLI_NOTARY_KEY, ASLI_NOTARY_KEY_ID and ASLI_NOTARY_ISSUER; or APPLE_ID, APPLE_APP_SPECIFIC_PASSWORD and APPLE_TEAM_ID. See packaging/macos/README.md."
    fi
    OUT="$DIST/asli-$VERSION-macos-$ARCH_NAME.dmg"
else
    OUT="$DIST/asli-$VERSION-macos-$ARCH_NAME-unsigned.dmg"
fi
readonly SIGN OUT

MISSING=()
need() { MISSING+=("$1"$'\n'"    $2"); }

check_prerequisites() {
    if xcode-select -p >/dev/null 2>&1; then
        ok "Xcode command line tools are present"
    else
        need "Xcode command line tools" "xcode-select --install"
    fi

    if command -v cargo >/dev/null 2>&1; then
        ok "Rust is present ($(cargo --version))"
    else
        need "Rust" "curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh"
    fi

    if command -v rustup >/dev/null 2>&1; then
        local installed triple
        installed="$(rustup target list --installed 2>/dev/null)"
        for triple in "${TRIPLES[@]}"; do
            if grep -qx "$triple" <<< "$installed"; then
                ok "Rust target $triple is installed"
            else
                need "the Rust target $triple" "rustup target add $triple"
            fi
        done
    fi

    local tool
    for tool in lipo codesign hdiutil ditto plutil xcrun; do
        command -v "$tool" >/dev/null 2>&1 || need "$tool" "xcode-select --install"
    done
    [ -x /usr/libexec/PlistBuddy ] || need "PlistBuddy" "it ships with macOS; /usr/libexec/PlistBuddy is missing"

    if [ "$SIGN" -eq 1 ]; then
        if security find-identity -v -p codesigning | grep -qF "\"$ASLI_SIGN_IDENTITY\""; then
            ok "signing identity found: $ASLI_SIGN_IDENTITY"
        else
            need "the signing identity \"$ASLI_SIGN_IDENTITY\" in the keychain" \
                "see 'Once: the certificate' in packaging/macos/README.md; 'security find-identity -v -p codesigning' lists what is there"
        fi
        case "$ASLI_SIGN_IDENTITY" in
            "Developer ID Application:"*) ;;
            *) need "a Developer ID Application identity" \
                "ASLI_SIGN_IDENTITY must start with \"Developer ID Application:\"; only that kind passes Gatekeeper outside the App Store" ;;
        esac
        if [ -n "${ASLI_TEAM_ID:-}" ] && [[ "$ASLI_SIGN_IDENTITY" != *"($ASLI_TEAM_ID)" ]]; then
            need "an identity from team $ASLI_TEAM_ID" "ASLI_SIGN_IDENTITY ends with a different team id than ASLI_TEAM_ID"
        fi
        # Checked now rather than after a long build: a wrong profile would fail at the very end.
        if xcrun notarytool history "${NOTARY_AUTH[@]}" >/dev/null 2>&1; then
            ok "notarization credentials work"
        else
            need "working notarization credentials" \
                "xcrun notarytool history with the same credentials fails; run it by hand to see why (README has the setup)"
        fi
    fi

    if [ "${#MISSING[@]}" -gt 0 ]; then
        printf '\n'
        warn "Missing, with the command that installs or explains each:"
        local item
        for item in "${MISSING[@]}"; do
            printf '  %s\n' "$item"
        done
        printf '\nFix them, then run this again.\n'
        die "missing prerequisites"
    fi
}

build() {
    local triple slices=()
    for triple in "${TRIPLES[@]}"; do
        info "Building for $triple"
        run cargo build --release --locked -p asli-app --target "$triple" ||
            die "the build for $triple failed. The output above says why."
        slices+=("$REPO_ROOT/target/$triple/release/asli")
    done
    BINARY="$WORK/asli"
    info "Joining ${#slices[@]} architecture(s) into one binary"
    run lipo -create -output "$BINARY" "${slices[@]}"
    if [ "$DRY_RUN" -eq 0 ]; then
        ok "$(lipo -archs "$BINARY")"
    fi
}

# The bundle, laid out the way setup.sh --install lays out ~/Applications/Asli.app, with the
# version filled in from Cargo.toml.
make_bundle() {
    APP="$WORK/Asli.app"
    info "Assembling Asli.app"
    if [ "$DRY_RUN" -eq 1 ]; then
        printf '  would assemble: %s\n' "$APP"
        return
    fi
    mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources"
    install -m 755 "$BINARY" "$APP/Contents/MacOS/asli"
    install -m 644 "$HERE/Info.plist" "$APP/Contents/Info.plist"
    install -m 644 "$HERE/asli.icns" "$APP/Contents/Resources/asli.icns"
    printf 'APPL????' > "$APP/Contents/PkgInfo"
    /usr/libexec/PlistBuddy -c "Set :CFBundleShortVersionString $VERSION" "$APP/Contents/Info.plist"
    /usr/libexec/PlistBuddy -c "Set :CFBundleVersion $VERSION" "$APP/Contents/Info.plist"
    plutil -lint "$APP/Contents/Info.plist" >/dev/null || die "Info.plist does not parse"
    ok "$APP"
}

sign_app() {
    info "Signing Asli.app"
    if [ "$SIGN" -eq 1 ]; then
        # Hardened runtime and a secure timestamp are both required for notarization.
        run codesign --force --options runtime --timestamp \
            --entitlements "$HERE/entitlements.plist" --sign "$ASLI_SIGN_IDENTITY" "$APP"
    else
        # Apple silicon refuses to run code with no signature at all. An ad hoc one satisfies that
        # and proves nothing to anyone else, which is what "unsigned" means here.
        run codesign --force --sign - "$APP"
    fi
    run codesign --verify --strict --deep --verbose=2 "$APP" || die "the signature on Asli.app does not verify"
    [ "$DRY_RUN" -eq 1 ] || ok "signed"
}

# Submits a file, waits for Apple's verdict, and prints the log when it is not Accepted, which is
# the only place the reason is written.
notarize() {
    local file="$1" result status id
    info "Notarizing $(basename "$file") (usually a few minutes)"
    if [ "$DRY_RUN" -eq 1 ]; then
        printf '  would run: xcrun notarytool submit %s <credentials> --wait\n' "$file"
        return
    fi
    result="$(xcrun notarytool submit "$file" "${NOTARY_AUTH[@]}" --wait --output-format json)" ||
        die "notarytool could not submit $file: $result"
    status="$(plutil -extract status raw -o - - <<< "$result" 2>/dev/null || echo unknown)"
    id="$(plutil -extract id raw -o - - <<< "$result" 2>/dev/null || echo '')"
    if [ "$status" != "Accepted" ]; then
        warn "Apple answered $status for $(basename "$file")."
        [ -n "$id" ] && xcrun notarytool log "$id" "${NOTARY_AUTH[@]}" >&2 || true
        die "notarization failed. The log above says why."
    fi
    ok "accepted ($id)"
}

notarize_app() {
    [ "$SIGN" -eq 1 ] || return 0
    # notarytool takes a zip, a dmg or a pkg, not a bare bundle. This first round is so the ticket
    # can be stapled to the app itself, and the app then works offline even after it leaves the
    # disk image.
    local zip="$WORK/Asli.zip"
    run ditto -c -k --keepParent "$APP" "$zip"
    notarize "$zip"
    run xcrun stapler staple "$APP" || die "could not staple the ticket to Asli.app"
}

make_dmg() {
    info "Making the disk image"
    if [ "$DRY_RUN" -eq 1 ]; then
        printf '  would write: %s\n' "$OUT"
        return
    fi
    local stage="$WORK/dmg" rw="$WORK/rw.dmg" mount="$WORK/mnt"
    mkdir -p "$stage" "$mount"
    ditto "$APP" "$stage/Asli.app"
    # What the window shows: the app, and Applications to drag it onto.
    ln -s /Applications "$stage/Applications"
    # The volume's own icon, shown on the desktop and in the Finder sidebar while it is mounted.
    cp "$HERE/asli.icns" "$stage/.VolumeIcon.icns"

    hdiutil create -quiet -volname Asli -srcfolder "$stage" -fs HFS+ -format UDRW -ov "$rw"
    hdiutil attach -quiet -nobrowse -noautoopen -mountpoint "$mount" "$rw"
    # The flag that tells Finder the volume has a custom icon. SetFile comes with the command line
    # tools; without it the image still works and simply shows the generic disk icon.
    if command -v SetFile >/dev/null 2>&1; then
        SetFile -a C "$mount" || warn "could not mark the volume icon; the image will show a generic one"
    else
        warn "SetFile is missing, so the mounted image shows a generic disk icon"
    fi
    hdiutil detach -quiet "$mount"

    rm -f "$OUT"
    hdiutil convert -quiet "$rw" -format UDZO -imagekey zlib-level=9 -o "$OUT"
    ok "$OUT"
}

sign_dmg() {
    [ "$SIGN" -eq 1 ] || return 0
    info "Signing the disk image"
    run codesign --force --timestamp --sign "$ASLI_SIGN_IDENTITY" "$OUT"
    notarize "$OUT"
    run xcrun stapler staple "$OUT" || die "could not staple the ticket to the disk image"
}

# Proves the result with the same checks Gatekeeper makes on someone else's Mac. Loud on failure:
# an image that fails here would fail there, where nobody can see why.
verify() {
    info "Verifying"
    if [ "$DRY_RUN" -eq 1 ]; then
        printf '  would verify with codesign, spctl and stapler\n'
        return
    fi
    local mount="$WORK/verify"
    mkdir -p "$mount"
    hdiutil attach -quiet -readonly -nobrowse -noautoopen -mountpoint "$mount" "$OUT"
    local app="$mount/Asli.app" failed=0
    codesign --verify --strict --deep --verbose=2 "$app" || failed=1
    [ "$(lipo -archs "$app/Contents/MacOS/asli")" = "$(lipo -archs "$BINARY")" ] || failed=1
    [ -f "$app/Contents/Resources/asli.icns" ] || failed=1
    if [ "$SIGN" -eq 1 ]; then
        spctl --assess --type execute --verbose=2 "$app" || failed=1
        xcrun stapler validate "$app" || failed=1
        codesign --display --verbose=2 "$app" 2>&1 | grep -q 'flags=.*runtime' || {
            warn "the hardened runtime flag is missing"
            failed=1
        }
    fi
    hdiutil detach -quiet "$mount"
    if [ "$SIGN" -eq 1 ]; then
        spctl --assess --type open --context context:primary-signature --verbose=2 "$OUT" || failed=1
        xcrun stapler validate "$OUT" || failed=1
    fi
    [ "$failed" -eq 0 ] || die "verification failed. The output above says which check. Do not publish $OUT."
    ok "verified"
}

write_checksums() {
    info "Checksums"
    if [ "$DRY_RUN" -eq 1 ]; then
        printf '  would write: %s over asli-%s-*\n' "$DIST/SHA256SUMS" "$VERSION"
        return
    fi
    # Over every artifact of this version in dist/, including any copied in from the other two
    # machines, so the last machine to run writes the file that covers the whole release.
    (cd "$DIST" && shasum -a 256 -- "asli-$VERSION-"* > SHA256SUMS)
    ok "$DIST/SHA256SUMS"
}

cleanup() {
    [ -n "$WORK" ] && [ -d "$WORK/mnt" ] && hdiutil detach -quiet "$WORK/mnt" 2>/dev/null
    [ -n "$WORK" ] && [ -d "$WORK/verify" ] && hdiutil detach -quiet "$WORK/verify" 2>/dev/null
    [ -n "$WORK" ] && rm -rf "$WORK"
    # A run that fails part way leaves no image behind that looks finished.
    if [ "$FINISHED" -eq 0 ] && [ "$DRY_RUN" -eq 0 ] && [ -n "$OUT" ]; then
        rm -f "$OUT"
    fi
    return 0
}

main() {
    printf '%sAsli macOS installer%s, version %s, %s\n\n' "$BOLD" "$RESET" "$VERSION" "$ARCH_NAME"
    [ "$DRY_RUN" -eq 1 ] && info "Dry run: nothing will be changed."
    if [ "$SIGN" -eq 0 ]; then
        warn "ASLI_SIGN_IDENTITY is not set: building an UNSIGNED, un-notarized image."
        printf '  Gatekeeper will block it on any other Mac. To make a release, set ASLI_SIGN_IDENTITY\n'
        printf '  and ASLI_NOTARY_PROFILE as described in packaging/macos/README.md.\n\n'
    fi

    info "Checking prerequisites"
    check_prerequisites
    printf '\n'

    cd "$REPO_ROOT"
    WORK="$(mktemp -d)"
    trap cleanup EXIT
    run mkdir -p "$DIST"

    build
    make_bundle
    sign_app
    notarize_app
    make_dmg
    sign_dmg
    verify
    write_checksums
    FINISHED=1

    printf '\n%sDone.%s\n' "$GREEN" "$RESET"
    if [ "$DRY_RUN" -eq 0 ]; then
        printf '\nProduced:\n  %s\n  %s\n' "$OUT" "$DIST/SHA256SUMS"
        if [ "$SIGN" -eq 0 ]; then
            printf '\nSkipped: Developer ID signing, notarization and stapling. This image is for\n'
            printf 'testing on this Mac only and must not be published.\n'
        fi
    fi
}

main
