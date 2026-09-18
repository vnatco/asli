# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and this project uses
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

Nothing is tagged yet and there are no downloads. What exists today:

### Working, and verified against a live relay

- Text sync in both directions on Linux, over X11 and over Wayland.
- Wayland through `ext-data-control-v1` with a `wlr-data-control` fallback.
  Both are required: KDE removed the wlr protocol in Plasma 6.4, and older
  wlroots compositors predate the ext one.
- X11 through XFixes, which is also the GNOME path, because GNOME declines to
  implement either data control protocol.
- Images, sealed and sent in chunks, with the chunk index and count bound in
  each chunk's associated data so a relay cannot reorder or truncate them
  undetectably.
- A tray icon through StatusNotifierItem, needing no GTK and no
  libappindicator, only a D-Bus session.
- Autostart on Linux through an XDG desktop entry.
- Recovery from a relay restart, with full jitter backoff.
- Content marked sensitive by a password manager is never read, let alone sent.

- A window with six screens, opened from the tray: first run, join, the join token, history,
  status and settings.
- A local clipboard history, encrypted at rest.
- One running instance per configuration. Launching again brings the running one forward instead
  of starting a second connection.
- `setup.sh --install` installs the binary, the application entry and icon, and launch at login,
  and `--uninstall` removes all of it.

### Fixed

- On Wayland, every received clip after the first was advertised on the clipboard but pasted as
  nothing. The compositor's cancellation of our previous write arrived after the new write and
  cleared it.
- Launch at login could start Asli twice, because the app and the uninstaller used different names
  for the same entry.

### Written but unverified

- The Windows backend. Its decision logic is unit tested, but no Win32 call in it has been observed
  running yet.
- The macOS backend. Same position: no AppKit call in it has been observed running, and the
  behaviour of the macOS 15.4 pasteboard alert is inferred from documentation rather than observed.

### Known gaps

- No release has been tagged, so no artifact has been published.
- The macOS application layer: tray, autostart and the daemon wiring.
- No libsodium interop check yet; the frozen vectors pin our own output only.
