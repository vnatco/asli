#!/usr/bin/env bash
#
# Renders the icon files that are derived from an SVG, so they can be made again when the mark
# changes. Run from anywhere; writes into the repository. Needs rsvg-convert, ffmpeg and python3.
#
#   packaging/macos/asli.icns              from packaging/linux/asli.svg
#   packaging/windows/installer-sidebar.bmp from packaging/windows/installer-sidebar.svg
#
# packaging/icons/asli-256.png and packaging/windows/asli.ico come from the same SVG but were made
# by hand; they are not rewritten here.

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PACKAGING="$(dirname "$HERE")"

for tool in rsvg-convert ffmpeg python3; do
    command -v "$tool" >/dev/null 2>&1 || { echo "error: $tool is required" >&2; exit 1; }
done

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

# An .icns is a header and a list of typed chunks, and every chunk type used here holds a PNG, so
# it can be written without Apple's iconutil. The types are the sizes macOS asks for: 16, 32, 128,
# 256 and 512 points, each at one and two times.
for size in 16 32 64 128 256 512 1024; do
    rsvg-convert -w "$size" -h "$size" "$PACKAGING/linux/asli.svg" -o "$work/$size.png"
done
python3 - "$work" "$PACKAGING/macos/asli.icns" <<'PY'
import struct, sys
work, out = sys.argv[1], sys.argv[2]
chunks = [("icp4", 16), ("icp5", 32), ("ic11", 32), ("ic12", 64), ("ic07", 128),
          ("ic13", 256), ("ic08", 256), ("ic14", 512), ("ic09", 512), ("ic10", 1024)]
body = b""
for kind, size in chunks:
    data = open(f"{work}/{size}.png", "rb").read()
    body += kind.encode() + struct.pack(">I", len(data) + 8) + data
open(out, "wb").write(b"icns" + struct.pack(">I", len(body) + 8) + body)
PY
echo "wrote $PACKAGING/macos/asli.icns"

# NSIS takes a 24 bit BMP and nothing else for this picture.
rsvg-convert -w 246 -h 471 "$PACKAGING/windows/installer-sidebar.svg" -o "$work/sidebar.png"
ffmpeg -loglevel error -y -i "$work/sidebar.png" -pix_fmt bgr24 "$PACKAGING/windows/installer-sidebar.bmp"
echo "wrote $PACKAGING/windows/installer-sidebar.bmp"
