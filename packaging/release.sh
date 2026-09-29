#!/usr/bin/env bash
#
# Uploads the installers gathered in dist/ to a new GitHub release, as a draft.
#
# Run it on the machine where the files from all three build machines have been copied into
# dist/. It checks the set is complete and releasable, rewrites SHA256SUMS over all of it, and
# creates a draft release tagged v<version> on main with every artifact and the checksums
# attached. A draft is visible only to the repository's owners until Publish is pressed on
# GitHub, so there is a last look before anyone can download it.
#
# Needs the GitHub CLI, logged in: gh auth login
#
# Usage: packaging/release.sh [--dry-run] [--help]

set -euo pipefail

DRY_RUN=0
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
readonly REPO_ROOT
readonly DIST="$REPO_ROOT/dist"

die() { printf 'error %s\n' "$*" >&2; exit 1; }

while [ $# -gt 0 ]; do
    case "$1" in
        --dry-run) DRY_RUN=1 ;;
        --help|-h) sed -n '2,14p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *) die "unknown option: $1" ;;
    esac
    shift
done

VERSION="$(sed -n 's/^version = "\(.*\)"/\1/p' "$REPO_ROOT/Cargo.toml" | head -n 1)"
[ -n "$VERSION" ] || die "could not read the version from Cargo.toml"
readonly TAG="v$VERSION"

if [ "$DRY_RUN" -eq 0 ]; then
    command -v gh >/dev/null 2>&1 || die "the GitHub CLI is missing. Install it (https://cli.github.com), run 'gh auth login', then run this again."
    gh auth status >/dev/null 2>&1 || die "the GitHub CLI is not logged in. Run 'gh auth login', then run this again."
fi

# The set a release promises. A missing one is a machine whose build was not copied in.
EXPECTED=(
    "asli-$VERSION-windows-x86_64.exe"
    "asli-$VERSION-macos-universal.dmg"
    "asli-$VERSION-linux-x86_64.AppImage"
    "asli-$VERSION-linux-x86_64.deb"
    "asli-$VERSION-linux-x86_64.rpm"
    "asli-$VERSION-linux-x86_64.tar.gz"
)
missing=0
for file in "${EXPECTED[@]}"; do
    if [ ! -f "$DIST/$file" ]; then
        printf 'missing: dist/%s\n' "$file" >&2
        missing=1
    fi
done
[ "$missing" -eq 0 ] || die "copy the missing files into dist/ from the machine that built them."

# An unsigned Mac image is for testing on the Mac that built it and must never be downloadable.
if compgen -G "$DIST/asli-$VERSION-*-unsigned.*" >/dev/null; then
    die "dist/ holds an unsigned image ($(cd "$DIST" && ls asli-"$VERSION"-*-unsigned.*)). Delete it; releases carry the signed one only."
fi

FILES=()
while IFS= read -r file; do
    FILES+=("$file")
done < <(cd "$DIST" && ls -1 "asli-$VERSION-"*)

# Rewritten here over the combined set, since each build machine wrote one over its own files.
if command -v sha256sum >/dev/null 2>&1; then
    (cd "$DIST" && sha256sum -- "${FILES[@]}" > SHA256SUMS)
else
    (cd "$DIST" && shasum -a 256 -- "${FILES[@]}" > SHA256SUMS)
fi
printf 'SHA256SUMS:\n'
sed 's/^/  /' "$DIST/SHA256SUMS"

NOTES="$(mktemp)"
trap 'rm -f "$NOTES"' EXIT
cat > "$NOTES" <<EOF
| System | Download | |
|---|---|---|
| Windows 10 and 11 | \`asli-$VERSION-windows-x86_64.exe\` | Unsigned: SmartScreen asks once, choose **More info** then **Run anyway** |
| macOS 11 and later, Apple silicon and Intel | \`asli-$VERSION-macos-universal.dmg\` | Open it and drag Asli to Applications |
| Linux, any distribution | \`asli-$VERSION-linux-x86_64.AppImage\` | Make it executable and open it: it installs itself for your user |
| Debian and Ubuntu | \`asli-$VERSION-linux-x86_64.deb\` | \`sudo apt install ./asli-$VERSION-linux-x86_64.deb\` |
| Fedora and openSUSE | \`asli-$VERSION-linux-x86_64.rpm\` | \`sudo dnf install ./asli-$VERSION-linux-x86_64.rpm\` |

Check a download against \`SHA256SUMS\`: \`sha256sum -c SHA256SUMS --ignore-missing\`.

See CHANGELOG.md for what changed.
EOF

cmd=(gh release create "$TAG" --draft --target main --title "Asli $VERSION" --notes-file "$NOTES")
for file in "${FILES[@]}" SHA256SUMS; do
    cmd+=("$DIST/$file")
done

if [ "$DRY_RUN" -eq 1 ]; then
    printf '\nwould run: %s\n' "${cmd[*]}"
    exit 0
fi
(cd "$REPO_ROOT" && "${cmd[@]}")
printf '\nDraft release %s created. Review it on GitHub and press Publish.\n' "$TAG"
