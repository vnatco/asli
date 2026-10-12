# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and this project uses
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2026-10-12

The first release. Asli runs on Linux, Windows 10 and 11, and macOS 11 or later, and is in daily
use on Linux, Windows 11 and macOS against the public relay.

### Added

#### Clipboard sync

- Text and images sync between your own machines, end to end encrypted with XChaCha20-Poly1305.
  Text travels in one message, up to the relay's limit (700 KiB on the public relay); images up to
  32 MiB travel in sealed pieces whose order and count are bound into each piece, so a relay
  cannot reorder or truncate them unnoticed. **Largest Clip to Sync** in Settings lowers the cap.
- Linux over X11 through XFixes, and over Wayland through `ext-data-control-v1` with a
  `wlr-data-control` fallback. GNOME Wayland works through XWayland, because GNOME implements
  neither data control protocol. Windows through the clipboard listener, writing images as PNG and
  as a bitmap. macOS through a pasteboard poll on the main thread.
- Content a password manager marks as sensitive is never read, sent or recorded. There is no
  setting that changes this.
- Three layers keep a received clip from being sent back: the sender's device id inside the
  ciphertext, a short lived hash of what was just written, and the platform's own change counter
  where there is one. Copying the same text twice on purpose still syncs.
- Replay protection that survives restarts: message ids and per device sequence numbers are saved,
  so a relay cannot resend old clips, and sync does not depend on clocks being exact. A device
  whose clock is far off is told so.
- A copy made while offline, or as the connection dropped, is sent on reconnecting, newest only.
- The relay keeps the most recent clip of each account, up to 64 KiB, for up to 24 hours. A device
  that was off fetches it only when asked, with **Paste Last Synced Clip** in the tray menu or
  **Paste It Here** on Home, so it never overwrites a newer local copy.

#### Devices and joining

- **Create a New Account** makes a 32 byte account key, kept in the OS keychain (Windows
  Credential Manager, macOS Keychain, Linux Secret Service), never shown. Where Linux has no
  Secret Service, it falls back to an owner only file and `asli status` says so.
- **Add a Device** makes a join code that works once, for ten minutes, and carries no key. The new
  device types it under **Join an Existing Account**, both show the same six digits, and the
  account key crosses only once the person approves, sealed to the new device's own key. **Copy
  Code** copies the code. `asli add` and `asli join` do the same from a terminal; `asli join` reads
  the code from stdin, never the command line.
- Every device has a key of its own beside the account key, and signs a card naming itself and its
  operating system. Each device's key is pinned the first time it is seen, so one device cannot
  take another's place.
- Home lists every device on the account, with its operating system mark, whether it is online or
  when it was last seen, and the version of Asli it runs. When another device runs a newer
  version, Home says so and offers **Download New Version**.
- **Remove** on Home, or `asli remove`, gives every other device a new account key sealed to its
  own key; the removed device can read nothing sent after. Devices offline at the time, or on a
  version too old to take part, have to join again, and the window names them first. `asli rekey`
  replaces the key and keeps every device.
- **Leave This Account** in Settings, or `asli leave`, signs this device out, deleting its account
  key, device list and history, and the other devices take it off their lists. **Join Another
  Account** does the same before joining a new one.
- **Same Network Only** in Settings: a device with it on approves a new device only when that
  device reaches it on the local network, and sends and receives files only there. Clips still
  sync from anywhere.

#### File transfer

- Files up to 4 GiB each, to one device at a time. Drop files on the window, where they wait under
  **Ready to Send** for a device or **All Devices**, or use **Send File** beside a device on Home,
  or `asli send <device> <file>`.
- The receiver sees who sent it, checked against that device's pinned key, and nothing is written
  until someone accepts. With **Ask About Files Right Away** on (the default) the question comes at
  once, in a notification with buttons on Linux and a small window in the corner of the screen on
  Windows and macOS; it is always on Home too, and `asli transfers`, `asli accept` and
  `asli decline` answer from a terminal. Several files from one device are one question.
- Accepting asks where to save. The file is written under a name the receiver makes safe, checked
  against the hash the sender signed, and marked as downloaded from the internet on Windows and
  macOS. **Show in Folder** opens its folder and never the file.
- On the same local network the file goes directly between the two devices over TCP, sealed under
  a key made for that transfer. Otherwise, or when nothing arrives directly within 15 seconds, it
  goes through the relay in sealed pieces that are never stored there.
- Offers are refused when more than a day old, more than a day in the future, or made on a
  connection the sender has since left. A waiting offer ends once the other device has been gone
  for 20 seconds, and a transfer that stops moving for a minute is abandoned.

#### History

- A local list of what was copied on any device, encrypted at rest under a key derived from the
  account key, 100 entries by default, grouped by day with thumbnails for images, the device each
  came from, and its size. Clicking an entry puts it back on every device's clipboard, or on this
  device only. It can be turned off and cleared, and it moves to the new key when the account is
  rekeyed.

#### Window and tray

- A tray icon (StatusNotifierItem on Linux, needing only a D-Bus session) whose badge shows the
  state: synced, paused, offline, connecting, and a red dot while something waits for an answer.
  Its menu has Pause Sync, Paste Last Synced Clip, Add a Device, Join Another Account, History,
  Home, Settings, Copy Diagnostics and Quit.
- A window with Home, History, Add a Device and Settings, drawn by Slint on the GPU, falling back
  to the software renderer where there is no working graphics driver. Text is set in Figtree,
  Outfit and JetBrains Mono, all bundled.
- **Copy Diagnostics** puts a short report on the clipboard, with no clipboard content in it.
- Dropping files on the window works on Windows, macOS, X11 and Wayland.
- One running instance per configuration; launching again brings the window forward.
- Start at login: an XDG autostart entry on Linux, a Startup folder shortcut on Windows, a launchd
  agent on macOS.

#### Command line

- `asli create`, `join`, `add`, `devices`, `remove`, `rekey`, `leave` and `reset` for the account;
  `send`, `transfers`, `accept` and `decline` for files; `status`, `autostart`, `run` and `tray`
  for the rest. `asli --help` describes each.

#### Relay

- A Node relay with one runtime dependency (`ws`), no database and nothing on disk. Devices prove
  themselves with an Ed25519 signature over a fresh challenge, and the room id is a hash of the
  public key, so the relay holds no credential.
- It forwards clips, image pieces, device announcements and sealed device to device messages
  (`msg`), which carry device cards, joining, key changes and files.
- Every limit is an environment variable, checked at startup: frame size (4 KiB until a connection
  has authenticated), per connection rates, a 50 MiB daily clip quota per room, separate bulk
  budgets for files and images of 4 GiB per room and 32 GiB per relay a day, connection caps, and
  backpressure that disconnects a receiver that cannot keep up.
- Logs are built from an allowlist of named fields, with room ids salted per process.
- `server/docker-compose.yml` runs it behind Caddy for self hosting.

#### Security

- Decrypted content is wiped from memory when dropped, including on every error path.
- Sequence numbers cannot be pushed out of reach by one hostile clip, and every per device table
  is bounded.

#### Installers

- Linux: an AppImage that installs itself for the current user, a `.deb`, an `.rpm` and a
  `.tar.gz`, all built against glibc 2.28. Arch packages `asli` and `asli-bin` in
  `packaging/aur`.
- Windows: a per user installer with no administrator prompt, which adds the Start menu entry,
  turns on start at login, registers an uninstaller and starts Asli.
- macOS: a universal disk image for Apple silicon and Intel, signed with a Developer ID, notarized
  and stapled.
- Every package carries `THIRD_PARTY_LICENSES.txt`. `setup.sh` and `setup.ps1` build and install
  from source.

### Known limitations

- No forward secrecy. Removing a device stops it reading what comes after; what it already
  received, it keeps.
- Clips and announcements are authenticated by the account key only, not signed by each device, so
  any device on the account could claim to be another in a clip.
- The Windows installer is unsigned, so SmartScreen warns once. The first time a file is sent,
  Windows may ask whether Asli may accept connections on private networks; saying no leaves files
  going through the relay.
- Dragging Asli to the Trash on macOS leaves its launchd agent behind, pointing at nothing. It
  starts nothing, but stays until removed by hand or **Start at Login** is turned off first.
- The behaviour of the macOS 15.4 pasteboard alert is inferred from documentation; it is not
  enabled by default and has not been seen.
- river cannot be supported: it implements no clipboard manager protocol. On GNOME Wayland sync
  depends on XWayland.
- Linux builds are x86_64 only.
- The frozen test vectors pin this implementation's own output; no check against libsodium has
  been done yet.
