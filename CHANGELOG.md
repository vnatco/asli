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

- The window is redesigned throughout: its own title bar, a sidebar with icons and the sync state
  at its foot, a welcome screen with two ways in, a join screen with a way back, a status card
  whose colour, label and action follow the connection, and new icons for the application and the
  tray. The tray icon carries the state as a badge: green when synced, grey when paused, red when
  the relay cannot be reached, blinking while connecting.
- Devices now tell each other their name and operating system, sealed like a clip, and Status
  lists every device on the account with whether it is online or when it was last seen. The name
  defaults to the computer's own and can be changed in Settings. The relay forwards these
  announcements without storing them and cannot read them. See section 7.12 of the protocol.
- History says which device each clip came from, shows images as thumbnails with their size, and
  can copy an entry to this device alone without sending it anywhere.
- The join string's QR code uses the lowest error correction level, which is enough for a screen
  and makes its modules larger and easier for a camera to read.
- Sync no longer depends on clocks being right. The message ids and sequence numbers that refuse
  a replayed clip are now saved across restarts, so the freshness window, which used to be two
  minutes and carried that job alone, is now a 24 hour sanity bound. A device in the wrong time
  zone syncs normally, and one more than 12 hours off is told so.

### Fixed

- `asli join` no longer takes the token as a command line argument. `/proc/<pid>/cmdline` is
  world readable on Linux, so any other local user could read the account key out of the process
  list while a join was running, and the shell wrote it to its history file as well. The token is
  read from stdin now, and the old form is refused with an explanation rather than a parser error
  that printed the key back out.
- The join string is no longer drawn until it is asked for. Opening the Join String screen shows
  a Reveal button, and leaving the screen hides the string again, so a window left open on it is
  not a standing display of the account key.
- A device's sequence number can no longer jump an implausible distance in one step. The high
  water mark is persisted and never lowered, so a single clip claiming a peer's device id with
  `seq = u64::MAX` parked that peer's mark out of reach and stopped it syncing on every device,
  across restarts, until the replay store was edited by hand.
- The per device sequence map is bounded. It was keyed by a sender chosen device id with no cap,
  which made it the one collection in the tree that an account member could grow without limit.
- A decrypted clip is wiped when it is dropped rather than left legible in a freed allocation,
  where it reached swap and hibernation images. This covers clips the crypto layer still owns:
  ones the replay guard rejected, ones of a content type the client does not handle, and every
  error path.
- The relay caps a frame at four kilobytes until the connection has authenticated. A `hello` is
  under two hundred bytes, and anyone who had done nothing but open a socket could previously
  make the relay parse a megabyte of JSON per frame.
- `SECURITY.md` has a real security contact address in place of the TODO placeholder.
- On Linux, a notification service that never answered froze the tray: every menu click after the
  first notification did nothing. Notifications are now sent from a thread of their own.
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
