# Packaging

What a release contains, how it is built, and the honest state of code signing.

## Artifacts

| Platform | Artifact | Notes |
|---|---|---|
| Linux x86_64 | `asli-<version>-x86_64-linux.tar.gz` | Binary, README, LICENSE, desktop entry, user unit |
| Linux x86_64 | `.deb` | Package id is `asli-app`, the binary it installs is `asli` |
| Linux x86_64 | `.rpm` | Metadata from `linux/rpm-metadata.toml` |
| Linux aarch64 | the same three | Built natively on an arm64 runner, not cross compiled |
| Windows x86_64 | `asli-<version>-x86_64-windows.zip` | Portable, no installer. See `windows/README.md` |
| macOS aarch64 | `asli-<version>-aarch64-macos.tar.gz` | Unsigned. See `macos/README.md` |
| macOS x86_64 | `asli-<version>-x86_64-macos.tar.gz` | Unsigned |
| All | `SHA256SUMS` | `sha256sum -c SHA256SUMS --ignore-missing` |

Arch Linux is served through the AUR rather than a tarball: `asli` from source and `asli-bin` from
the release tarball. See `aur/README.md`.

## Two deliberate omissions

**No AppImage.** AppImage exists to bundle a runtime that the host may not have, and in this
category that runtime is almost always WebKitGTK. Asli has no webview, so there is nothing to
bundle: an AppImage would be a tarball with extra steps and a larger download. The tarball, deb,
rpm and AUR packages cover Linux better.

**No Windows installer.** The portable zip is the supported artifact. An installer that has never
been tested end to end on a clean machine is worse than no installer, because it fails in a way the
user cannot diagnose or undo.

## Signing, honestly

| Platform | Today | Plan |
|---|---|---|
| Linux | Not signed, and not expected to be | Package signing happens in the repositories, not here |
| Windows | **Unsigned.** SmartScreen shows "Windows protected your PC" on first run | Apply to the SignPath Foundation, which signs qualifying open source projects for free |
| macOS | **Unsigned and not notarized.** macOS refuses to open it until quarantine is cleared | Apple Developer membership at 99 USD a year, which also makes the clipboard permission grant survive updates |

Neither warning means the binary is unsafe. Both mean the publisher is unverified, which is exactly
true right now. Anyone downloading should check the file against `SHA256SUMS` regardless of what a
signature would have said.

## Building a release

There is no release workflow. Each artifact is built on its own platform from the tagged commit:

```sh
git tag -a v0.1.0 -m "0.1.0"
git push origin v0.1.0
cargo build --release -p asli-app        # on each platform, from the tag
```

On Windows the zip holds `asli.exe`, `asliw.exe`, `README.md` and `LICENSE`. Generate `SHA256SUMS`
over every artifact once they are gathered, and attach everything to the GitHub release.

## Known follow up

The deb package id is `asli-app` because `cargo-deb` takes it from the crate manifest, where the
package is named `asli-app` and the binary is named `asli`. Fixing that means adding a
`[package.metadata.deb]` block with `name = "asli"` to `crates/asli-app/Cargo.toml`. It is cosmetic,
it only shows in `dpkg -l` output, and it is worth doing before the first release that people
actually install.
