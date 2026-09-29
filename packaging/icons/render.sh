#!/usr/bin/env bash
#
# Renders the icon files that are derived from an SVG, so they can be made again when the mark
# changes. Run from anywhere; writes into the repository. Needs rsvg-convert, ffmpeg and python3.
#
#   packaging/macos/asli.icns              from packaging/linux/asli.svg
#   packaging/windows/asli.ico             16 to 48 px drawn below, 64 to 256 px from asli.svg
#   packaging/windows/installer-sidebar.bmp from packaging/windows/installer-sidebar.svg
#
# packaging/icons/asli-256.png comes from the same SVG but was made by hand; it is not rewritten
# here.

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

# The Windows icon. Its small sizes are drawn separately rather than scaled down from asli.svg:
# scaled, the dark tile is all that survives at 16 and 32 pixels, and on the dark Start menu and
# taskbar that reads as a hole. So 16, 24, 32 and 48 are a bright tile with a light mark, each
# placed on its own pixel grid so the edges stay sharp. The mark is the same two sheets, the one
# behind drawn as an outline, with a gap in the tile's colour around the one in front.
python3 - "$work" <<'PY'
import sys
work = sys.argv[1]
# size: tile radius, margin, offset of the front sheet, stroke, sheet radius
GRID = {16: (3.5, 3, 3, 1, 1.5), 24: (5, 4, 5, 2, 2.5), 32: (7, 6, 6, 2, 3), 48: (10, 9, 9, 3, 4.5)}
for s, (r, m, d, t, rx) in GRID.items():
    k = s - 2 * m - d
    back, back_w, front = m + t / 2, k - t, m + d
    open(f"{work}/small-{s}.svg", "w").write(f"""<svg xmlns="http://www.w3.org/2000/svg" width="{s}" height="{s}" viewBox="0 0 {s} {s}">
<defs><linearGradient id="g" gradientUnits="userSpaceOnUse" x1="0" y1="0" x2="0" y2="{s}"><stop offset="0" stop-color="#5B9BFF"/><stop offset="1" stop-color="#2563EB"/></linearGradient></defs>
<rect width="{s}" height="{s}" rx="{r}" fill="url(#g)"/>
<rect x="{back}" y="{back}" width="{back_w}" height="{back_w}" rx="{max(rx - t / 2, 0.5)}" fill="none" stroke="#FFFFFF" stroke-opacity="0.9" stroke-width="{t}"/>
<rect x="{front - t}" y="{front - t}" width="{k + 2 * t}" height="{k + 2 * t}" rx="{rx + t}" fill="url(#g)"/>
<rect x="{front}" y="{front}" width="{k}" height="{k}" rx="{rx}" fill="#FFFFFF"/>
</svg>
""")
PY
for size in 16 24 32 48; do
    rsvg-convert "$work/small-$size.svg" -o "$work/ico-$size.png"
done
for size in 64 128 256; do
    cp "$work/$size.png" "$work/ico-$size.png"
done
# Every entry a PNG, which Windows has read since Vista, in one directory in ascending size.
python3 - "$work" "$PACKAGING/windows/asli.ico" <<'PY'
import struct, sys
work, out = sys.argv[1], sys.argv[2]
sizes = [16, 24, 32, 48, 64, 128, 256]
images = [open(f"{work}/ico-{s}.png", "rb").read() for s in sizes]
offset = 6 + 16 * len(sizes)
head = struct.pack("<HHH", 0, 1, len(sizes))
for s, data in zip(sizes, images):
    head += struct.pack("<BBBBHHII", s % 256, s % 256, 0, 0, 1, 32, len(data), offset)
    offset += len(data)
open(out, "wb").write(head + b"".join(images))
PY
echo "wrote $PACKAGING/windows/asli.ico"

# NSIS takes a 24 bit BMP and nothing else for this picture.
rsvg-convert -w 246 -h 471 "$PACKAGING/windows/installer-sidebar.svg" -o "$work/sidebar.png"
ffmpeg -loglevel error -y -i "$work/sidebar.png" -pix_fmt bgr24 "$PACKAGING/windows/installer-sidebar.bmp"
echo "wrote $PACKAGING/windows/installer-sidebar.bmp"
