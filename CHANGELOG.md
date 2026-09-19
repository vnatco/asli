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

- Windows: the daemon, tray, window and launch at login, with `asliw.exe`, a console free copy
  of the program for login and the Start menu. `setup.ps1 -Install` installs, starts and
  uninstalls it. Images are written to the clipboard as PNG and as a bitmap.

- macOS: the daemon, the menu bar icon, the window and the login item (a launchd agent), with all
  pasteboard access on the main thread. `setup.sh --install` builds `~/Applications/Asli.app`, so it
  stays out of the Dock. Type checked from Linux; not yet run on a Mac.
- `setup.sh --install` stops a running copy and starts the new one, so it also updates.

### Changed

- Sync no longer depends on clocks being right. The message ids and sequence numbers that refuse
  a replayed clip are now saved across restarts, so the freshness window, which used to be two
  minutes and carried that job alone, is now a 24 hour sanity bound. A device in the wrong time
  zone syncs normally, and one more than 12 hours off is told so.

### Fixed

- A connection left dead by sleep or a network change was never noticed: the tray said Synced
  and nothing arrived. The client now pings, and reconnects after 70 seconds of silence.
- A copy made just as the network dropped was lost with the connection. It is now sent again on
  the next one unless the relay confirmed it. Copies made while offline are no longer thrown away
  on reconnect, and a backlog goes out as its newest copy only.
- After a few disconnects every reconnect waited the full 30 seconds, and after one quota close
  an hour, for the rest of the run. A stable connection now resets the pacing.
- The history list did not update while open.
- The notifications switch, size cap and relay address took effect only after a restart.
- The relay: anyone could fill its room table for a day; a slow receiver was never disconnected;
  a clip parked behind a slow link could arrive after a newer one; images to slow receivers
  arrived broken; and per room quota state was never reclaimed.
- Paste It Here did nothing: a stored clip that was asked for was treated like one that was not,
  and a stored clip this device had sent itself was dropped without a word.
- The Windows executables and window had the generic program icon.
- Clicking the tray icon did not bring an open window to the front.
- The Status and Join screens could not scroll, so a short window cut them off.
- The join token clear could erase something copied after it, such as a password from a password
  manager or a file. The clear now happens only if the clipboard still holds the token.
- Restoring a history entry did not sync it to the other devices.
- On Wayland the writer stalled for two seconds after every write, and a hung application pasting
  a large image could freeze it for good. Offers for the middle click selection leaked.
- On X11 content over 1 MiB arrived cut, a copy made during a read was lost, large incremental
  transfers were abandoned, and one failed reply ended the writer.
- A clip queued at the wrong moment could wait unwritten until the next one arrived, and a clip
  queued just before the token clear was dropped.
- A connection that stayed up for more than 1000 copies, then crashed, restarted below sequence
  numbers it had already used, and its clips were dropped as replays.
- A locked keychain at login looked like no account, and first run offered to replace it.
- When the relay refused this device for good, the app vanished without saying why. It now stays
  in the tray with the reason.
- Opening the app from Finder, Launchpad or by double clicking `asliw.exe` did nothing.
- Windows: large screenshots offered only as bitmaps were refused, some bitmaps decoded as
  transparent or shifted, and Quit left a dead icon behind.
- macOS: every copy could raise the pasteboard alert when reads were not allowed, and each
  notification left a zombie process.
- Login and menu entries broke on install paths containing spaces or percent signs, and a login
  entry pointing at a binary that had moved was never repaired.
- Our own clipboard writes could come back through the watcher on Wayland, and be logged as queued
  and recorded in the history twice. The session never sent them, but the history was wrong.

- On a fresh install with no account, the first run window never opened. Work scheduled for the
  window before its event loop started was silently dropped.
- On Wayland, every received clip after the first was advertised on the clipboard but pasted as
  nothing. The compositor's cancellation of our previous write arrived after the new write and
  cleared it.
- Launch at login could start Asli twice, because the app and the uninstaller used different names
  for the same entry.

### Written but unverified

- Windows on real hardware. The Windows build has run under Wine against the live relay: text in
  both directions, no echo of received clips, the key in Credential Manager, the login entry, the
  tray, and a second launch handing over to the first. Wine is not Windows, and the window itself
  could not be drawn there, so none of it counts until it has run on Windows 11.
- The macOS backend. Same position: no AppKit call in it has been observed running, and the
  behaviour of the macOS 15.4 pasteboard alert is inferred from documentation rather than observed.

### Known gaps

- No release has been tagged, so no artifact has been published.
- macOS on real hardware, including the three pasteboard permission questions.
- No libsodium interop check yet; the frozen vectors pin our own output only.
