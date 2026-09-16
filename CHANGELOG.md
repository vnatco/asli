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

### Written but unverified

- The Windows backend. It cross compiles for the msvc and gnu targets and its
  decision logic is unit tested, but no Win32 call in it has ever executed.
- The macOS backend. Same position: it cross compiles for
  `aarch64-apple-darwin`, but no AppKit call in it has ever executed, and the
  behaviour of the macOS 15.4 pasteboard alert is inferred from documentation
  rather than observed.

### Known gaps

- No release has been tagged, so the packaging and release pipeline has never
  produced an artifact.
- "Paste last synced clip" in the tray is a stub.
- The relay's assembly timeout and concurrent assembly caps are exercised by
  code path, not by tests.
