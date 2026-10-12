#!/usr/bin/env python3
"""Writes packaging/THIRD_PARTY_LICENSES.txt: the licence of every crate built into Asli, with the
copyright notices those licences require a binary to carry, and the licences of the fonts and marks
bundled in the window.

Run it from anywhere after a dependency changes, and commit the result. Every installer ships the
file beside Asli's own LICENSE.

    python3 packaging/notices.py
"""

import json
import pathlib
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
OUT = ROOT / "packaging" / "THIRD_PARTY_LICENSES.txt"

# The platforms Asli ships for. A crate only some of them build is listed all the same.
TARGETS = [
    "x86_64-unknown-linux-gnu",
    "x86_64-pc-windows-msvc",
    "aarch64-apple-darwin",
    "x86_64-apple-darwin",
]

LICENCE_NAMES = ("LICENSE", "LICENCE", "COPYING", "NOTICE", "UNLICENSE", "COPYRIGHT")


def shipped_packages():
    """Every package in the normal dependency graph of the app, on any shipped platform."""
    ids = set()
    packages = {}
    for target in TARGETS:
        meta = json.loads(
            subprocess.check_output(
                [
                    "cargo", "metadata", "--format-version", "1", "--locked",
                    "--filter-platform", target, "--manifest-path", str(ROOT / "Cargo.toml"),
                ],
                cwd=ROOT,
            )
        )
        for package in meta["packages"]:
            packages[package["id"]] = package
        nodes = {node["id"]: node for node in meta["resolve"]["nodes"]}
        root = next(p["id"] for p in meta["packages"] if p["name"] == "asli-app")
        stack = [root]
        while stack:
            current = stack.pop()
            if current in ids:
                continue
            ids.add(current)
            for dep in nodes[current]["deps"]:
                # Build scripts and tests do not end up in the binary; normal dependencies do.
                if any(kind["kind"] is None for kind in dep["dep_kinds"]):
                    stack.append(dep["pkg"])
    workspace = {p["id"] for p in packages.values() if p["source"] is None}
    return sorted(
        (packages[i] for i in ids if i not in workspace),
        key=lambda p: (p["name"], p["version"]),
    )


def licence_texts(package):
    """The licence and notice files a crate publishes, by name."""
    folder = pathlib.Path(package["manifest_path"]).parent
    found = []
    if package.get("license_file"):
        found.append(folder / package["license_file"])
    for entry in sorted(folder.iterdir()):
        if entry.is_file() and entry.name.upper().startswith(LICENCE_NAMES) and entry not in found:
            found.append(entry)
    # Some crates, Slint's among them, keep their licences in a LICENSES folder, one per choice.
    shelf = folder / "LICENSES"
    if shelf.is_dir():
        found += sorted(entry for entry in shelf.iterdir() if entry.is_file())
    return [(path.name, plain(path.read_text(encoding="utf-8", errors="replace"))) for path in found]


def plain(text):
    """A licence text as this file keeps it: trimmed, with long dashes written as hyphens."""
    return text.strip().replace("\u2014", " - ").replace("\u2013", "-")


def main():
    lines = [
        "Third party licences",
        "====================",
        "",
        "Asli is MIT licensed (see LICENSE). It is built from the open source crates below, and its",
        "window bundles the fonts and marks at the end. Each is listed with its licence and the",
        "notices its authors publish. Where a crate offers a choice of licences, Asli uses it under",
        "the MIT licence when that is one of them.",
        "",
    ]
    missing = []
    # The same licence text, word for word, is printed once, under the first crate that has it.
    printed = {}
    for package in shipped_packages():
        lines += ["-" * 78, f"{package['name']} {package['version']}", f"Licence: {package.get('license') or 'see below'}"]
        if package.get("repository"):
            lines.append(f"Source: {package['repository']}")
        texts = licence_texts(package)
        if not texts:
            missing.append(f"{package['name']} {package['version']}")
            lines.append(
                "(The crate publishes no licence file of its own. Its licence is named above; the "
                "standard texts of MIT and Apache 2.0 are at the end of this file.)"
            )
        for name, text in texts:
            first = printed.setdefault(text, f"{package['name']} {package['version']}")
            if first == f"{package['name']} {package['version']}":
                lines += ["", f"[{name}]", text]
            else:
                lines += ["", f"[{name}] The same text as given for {first} above."]
        lines.append("")

    fonts = ROOT / "crates" / "asli-ui" / "ui" / "fonts"
    lines += ["=" * 78, "Bundled fonts", "=" * 78, ""]
    for family, licence in [("Figtree", "Figtree-OFL.txt"), ("Outfit", "Outfit-OFL.txt"),
                            ("JetBrains Mono", "JetBrainsMono-OFL.txt")]:
        lines += ["-" * 78, family, "Licence: SIL Open Font License 1.1", "",
                  plain((fonts / licence).read_text(encoding="utf-8")), ""]

    lines += [
        "=" * 78, "Operating system marks", "=" * 78, "",
        "The Windows, Apple and Linux (Tux) marks beside each device are from Simple Icons",
        "(https://simpleicons.org), released under CC0 1.0 Universal. The marks themselves are",
        "trademarks of their owners, Microsoft, Apple and the Linux Foundation, shown only to say",
        "which system a device runs.",
        "",
    ]
    # The standard texts, for the crates above that name a licence without shipping its text.
    mit = next((t for t in printed if t.startswith("MIT License") or "Permission is hereby granted" in t[:400]), None)
    apache = next((t for t in printed if "Apache License" in t[:200] and "Version 2.0" in t[:400]), None)
    lines += ["=" * 78, "Standard licence texts", "=" * 78, ""]
    for title, text in [("MIT", mit), ("Apache License 2.0", apache)]:
        lines += ["-" * 78, title, "", text or "(not found among the crates above)", ""]
    OUT.write_text("\n".join(lines) + "\n", encoding="utf-8")
    count = sum(1 for line in lines if line.startswith("Licence: ")) - 3
    print(f"wrote {OUT.relative_to(ROOT)}: {count} crates, {OUT.stat().st_size // 1024} KiB")
    if missing:
        print("no licence file shipped by: " + ", ".join(missing), file=sys.stderr)


if __name__ == "__main__":
    main()
