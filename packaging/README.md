# Packaging

How a release is built: one script per operating system, run on a machine of that system, each
writing into `dist/` at the repository root (gitignored). Then one more script puts everything on
GitHub.

## The flow

On each machine, from a fresh clone or an updated one:

| Machine | Command | Produces in `dist/` |
|---|---|---|
| Linux, x86_64 | `packaging/linux/build-installer.sh` | `asli-<version>-linux-x86_64.AppImage`, `.deb`, `.rpm`, `.tar.gz` |
| Windows, x86_64 | `.\packaging\windows\build-installer.ps1` | `asli-<version>-windows-x86_64.exe` |
| macOS | `packaging/macos/build-installer.sh` | `asli-<version>-macos-universal.dmg` |

Each script takes no arguments, checks every tool it needs before building anything, and stops with
the exact command to install whatever is missing. Each accepts `--dry-run` (`-DryRun` on Windows) to
print what it would do. Each writes `dist/SHA256SUMS` over every artifact of this version in
`dist/`, and prints the paths it produced at the end. A run that fails part way removes what it had
started, so nothing in `dist/` looks finished when it is not.

The version comes from `version` in the workspace `Cargo.toml`, the one place it is written. Bump it
there, commit, and pull on all three machines before building.

Then copy the files from the Windows and macOS machines into `dist/` on the Linux machine and run:

```sh
packaging/release.sh --dry-run    # checks the set is complete, prints the gh command
packaging/release.sh              # creates a DRAFT release v<version> with everything attached
```

It refuses to run while any of the six artifacts is missing, or while an unsigned Mac image is in
`dist/`. It rewrites `SHA256SUMS` over the combined set, and creates the release as a draft with a
table of which file is for whom, so there is a last look on GitHub before pressing Publish. It needs
the [GitHub CLI](https://cli.github.com), logged in with `gh auth login`. Without the script, the
same thing by hand:

```sh
cd dist && sha256sum asli-0.1.0-* > SHA256SUMS
gh release create v0.1.0 --draft --title "Asli 0.1.0" --notes "..." asli-0.1.0-* SHA256SUMS
```

## What each installer does

The installers do what `setup.sh --install` and `setup.ps1 -Install` do, with the same file names,
so either can update or remove what the other installed.

| | Windows `.exe` | macOS `.dmg` | Linux AppImage |
|---|---|---|---|
| Installs | `asli.exe` and `asliw.exe` into `%LOCALAPPDATA%\Programs\Asli`, per user, no administrator prompt | `Asli.app`, dragged to Applications | `~/.local/bin/asli`, per user |
| Application entry and icon | Start menu shortcut; Settings, Apps entry with the icon | The bundle itself, with `asli.icns` | `~/.local/share/applications/asli.desktop` and the icon in `hicolor` |
| Start at login | Startup folder shortcut, written by `asli.exe autostart on` | launchd agent, written by Asli at its first start | XDG autostart entry, written by `asli autostart on` |
| Starts Asli | At the end of the install | When opened from Applications | At the end of the install |
| Uninstall | Settings, Apps, Asli, Uninstall | Drag Asli to the Trash (see `macos/README.md` for the login entry) | `~/.local/share/asli/install.sh --uninstall`, or `Asli.AppImage --uninstall` |

No uninstaller touches the account key in the OS keychain, or the settings and history, so a
reinstall picks up where it left off. To remove the key too, run `asli reset` first.

The `.deb` and `.rpm` install system wide under `/usr` and are removed by the package manager. A
package runs as root and cannot start a program in someone's desktop session, so after installing
one, open Asli from the application menu once; it turns on start at login itself at that first
start. The login entry it writes lives in the user's home, where a package manager cannot reach, so
removing the package leaves it behind; it names the program in `TryExec`, which makes desktops
ignore it once the program is gone.

## Linux

**The AppImage is the one to download.** It is a single file that runs on any distribution; opened,
it installs itself for the current user through `linux/install.sh` (the same script `setup.sh
--install` runs) and starts Asli. Opened again, it reinstalls only if the version differs, and
otherwise brings the running window forward. Opened by double click, its output goes to
`~/.local/state/asli/install.log`, and a failure raises a notification saying so.

**Built against glibc 2.28**, with [cargo-zigbuild](https://github.com/rust-cross/cargo-zigbuild)
and zig, so it runs on Debian 10, Ubuntu 18.10, RHEL 8, Fedora 29 and everything newer. Built the
ordinary way on a current distribution, the binary would ask for that distribution's own glibc
(2.43 on the Arch machine the release is built on) and would refuse to start on Ubuntu or Debian.
The script checks the result: it fails if the binary asks for a newer glibc than 2.28, or links
any library beyond glibc and fontconfig. `ASLI_GLIBC` picks another floor.

**The `.deb` and `.rpm` are built on the same machine without containers**, by cargo-deb and
cargo-generate-rpm, which write the package formats themselves and need neither dpkg nor rpmbuild.
Their dependencies are written out (glibc 2.28, fontconfig, dbus) rather than detected, because the
detection tools exist only on their own distributions. The `.tar.gz` holds the plain files, and is
what the `asli-bin` AUR package unpacks (see `aur/`).

The binary's runtime needs are a D-Bus session for the tray, fontconfig, and the libraries the
window loads when it opens (libwayland-client and libxkbcommon on Wayland, libX11 and libxcb on
X11). Every desktop has them, which is why the AppImage bundles none of them. The AppImage runtime is
the current static one, so it needs no libfuse2, only the `fusermount` tool that desktops ship;
where that is missing, `--appimage-extract-and-run` runs it without FUSE.

## Signing, honestly

| Platform | State |
|---|---|
| Linux | Not signed, and not expected to be. Package signing happens in the repositories, not here |
| Windows | **Unsigned.** SmartScreen warns once. See `windows/README.md` for what the user sees |
| macOS | **Signed with a Developer ID, notarized and stapled** when the signing variables are set, and then opens with a plain double click. Without them the script builds an image named `...-unsigned.dmg`, which `release.sh` refuses to publish. See `macos/README.md` |

Anyone downloading can check a file against `SHA256SUMS`, whatever a signature says:
`sha256sum -c SHA256SUMS --ignore-missing`.

## Icons

Every installer carries the Asli mark, all of it rendered from `linux/asli.svg`:

| File | Used by |
|---|---|
| `windows/asli.ico` | Compiled into `asli.exe` and `asliw.exe`, the installer and uninstaller icon, the Apps entry |
| `windows/installer-sidebar.bmp` | The picture on the installer's first and last pages, from `windows/installer-sidebar.svg` |
| `macos/asli.icns` | The app bundle and the mounted disk image |
| `linux/asli.svg`, `icons/asli-256.png` | The menu entry in every Linux package, and the AppImage's own icon |

`icons/render.sh` renders the `.icns` and the sidebar picture again after the mark changes. The
`.ico` and the 256 pixel PNG were made by hand from the same SVG.

## Untested, stated plainly

What has been run, and where:

- **Linux, run here** (Arch, KDE Plasma, Wayland): the build, the four artifacts, the AppImage
  opened without a terminal in an isolated session (it installed, started, drew the first run
  window with its text, and wrote the login and menu entries), opened a second time (nothing
  reinstalled, the running copy kept), and `--uninstall` (everything removed, settings kept). The
  `asli-bin` PKGBUILD was built with `makepkg` from the produced tarball.
- **Windows, under Wine only**: the installer compiled with NSIS 3.11 under Wine, from binaries
  cross built with llvm-mingw rather than MSVC. Its welcome page was drawn and screenshotted. A
  silent install wrote the files, the Start menu shortcut and the Apps entry; the silent uninstall
  removed all of them, the Startup shortcut and an old `Run` value, and left the settings.

Not run anywhere yet:

- `windows/build-installer.ps1` itself, the MSVC build with the static C runtime, and its `dumpbin`
  check. The installer on real Windows: its pages clicked through, SmartScreen, the Startup
  shortcut (Wine has no PowerShell, which writes it), Asli starting at the end, and the Apps entry
  and its icon in Settings.
- `macos/build-installer.sh` at all: the universal build, signing, notarization, stapling, the disk
  image and its volume icon, and Gatekeeper on a second Mac. The Mac was not reachable when this
  was written.
- The `.deb` and `.rpm` installed on Debian, Ubuntu or Fedora. Their contents and control data
  were inspected, not installed.
- The AppImage on a distribution other than Arch, and on an old one in particular. glibc 2.28 is
  what the binary asks for, read from the binary, not observed on Debian 10.
- aarch64 Linux. The script supports it and has not been run on one.
