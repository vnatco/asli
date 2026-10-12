# Asli

One clipboard, every machine. Copy on your laptop, paste on your desktop.

Asli is a small tray app that keeps the clipboard in sync across your own computers, over the
internet, end to end encrypted. There is no account, no email and no password. You create a key on
one machine, and add each other machine by typing a short code on it and approving it on the first.
That is the entire setup.

"Asli" is the Georgian word for copy (ასლი).

The protocol is specified in [docs/PROTOCOL.md](docs/PROTOCOL.md), and what it does and does not
protect against is in [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md).

## Why

Every existing option makes you pick one thing you did not want to give up: it is LAN only, or it
needs an account on someone's server, or the server can read your clipboard, or it works on two of
your three operating systems, or it syncs only when your mouse crosses a screen edge. Asli is the
boring one that just works across Windows, macOS and Linux, including Wayland.

## Install

Downloads are on the [releases page](https://github.com/vnatco/asli/releases/latest):

| System | Download |
|---|---|
| Windows 10 and 11 | `asli-<version>-windows-x86_64.exe`, an installer. It is unsigned, so SmartScreen asks once: choose **More info**, then **Run anyway** |
| macOS 11 or later, Apple silicon and Intel | `asli-<version>-macos-universal.dmg`. Open it and drag Asli to Applications |
| Linux, x86_64 | `.AppImage` (installs itself for your user when opened), `.deb`, `.rpm` or `.tar.gz` |

The Linux builds need glibc 2.28 or newer, fontconfig, and a D-Bus session. Check a download
against `SHA256SUMS` from the same page: `sha256sum -c SHA256SUMS --ignore-missing`.

To build from source instead:

```
git clone https://github.com/vnatco/asli && cd asli
./setup.sh --install    # macOS and Linux
.\setup.ps1 -Install     # Windows
```

With no options, `setup.sh` checks for a C toolchain (and installs Rust with rustup if it is
missing), builds the release binary and runs the test suite. With `--install` it builds, then
installs and starts the app and turns on launch at login: on Linux into `~/.local/bin` with its menu
entry and icon, on macOS as `~/Applications/Asli.app`. `./setup.sh --help` lists the rest, including
`--uninstall`; `setup.ps1` takes the same options as `-BuildOnly`, `-Install`, `-WithServer`,
`-Uninstall` and `-DryRun`. Building the client does **not** require Node.js. Node is needed only if you also
want to run the relay server locally, which `--with-server` sets up. On Linux the build also needs
the fontconfig development files (`libfontconfig-dev` on Debian and Ubuntu, `fontconfig-devel` on
Fedora); see [docs/BUILDING.md](docs/BUILDING.md).

## How it works

1. On the first machine you pick **Create a New Account**. Asli generates a 32 byte secret and keeps
   it in your OS keychain (Windows Credential Manager, macOS Keychain, Linux Secret Service). It is
   never shown.
2. To add another machine, open **Add a Device** on one that is set up. It makes a join code that
   works once, for ten minutes, and carries no key. Type it on the new machine under **Join an
   Existing Account**. Both machines show the same six digits; if they match, approve the new one,
   and the key crosses to it sealed so that only it can open it.
3. From then on, whenever you copy text or an image, the app encrypts it on your machine and sends
   it through a relay server to your other machines, which decrypt it and put it on their
   clipboard. Text goes in one message, up to the relay's limit of 700 KiB on the public relay;
   images go in pieces, up to 32 MiB. Anything your password manager marks as sensitive is never
   synced, and never recorded in History. There is no setting that changes this.
4. To take a machine off the account, remove it on Home (`asli remove`). Every other machine gets a
   new key, and the removed one can read nothing sent after. To take the machine you are on off
   its account, use **Leave This Account** in Settings (`asli leave`).
5. To send files, drop them on the window, where they wait under **Ready to Send** for you to pick
   the devices, or use **Send File** beside a device on Home (`asli send <device> <file>` in a
   terminal). A file can be up to 4 GiB. The other machine asks before taking it, right away in the
   corner of the screen when **Ask About Files Right Away** is on, which it is by default, and on
   Home either way. When both machines are on the same local network the file goes straight between
   them; otherwise it goes through the relay, encrypted like everything else and never stored
   there.

**Same Network Only**, in Settings, makes a machine approve a new device only when that device
reaches it on the local network, and send and receive files only there, never through the relay.
Clips still sync from anywhere.

**History** keeps a list of what was copied on any of your devices, on this machine only and
encrypted with a key derived from the account key. Click an entry to put it back on the clipboard
of every device. It keeps 100 entries by default and can be turned off in Settings.

The relay only ever sees ciphertext. It cannot read your clipboard, and it does not know who you
are. It keeps the most recent clip of each account, if it is no larger than 64 KiB, for up to 24
hours. A machine that was switched off does not receive it automatically: it fetches it only when
you ask, with **Paste Last Synced Clip** in the tray menu or **Paste It Here** on Home, so it never
overwrites something you copied in the meantime. You can point the app at your own relay in
Settings.

### The command line

The same binary is a command line tool. A few of its commands:

| Command | What it does |
|---|---|
| `asli status` | Show what this device is configured to do, and where its config file is |
| `asli create` | Create a New Account on this device |
| `asli add` | Show a join code for another device, and approve it when it asks |
| `asli join` | Join an existing account with a code, read from stdin |
| `asli devices` | List the devices on this account |
| `asli remove` | Remove a device: the others move to a new account key without it |
| `asli send`, `asli transfers`, `asli accept`, `asli decline` | Send files and answer offers |
| `asli leave` | Sign this device out of its account |
| `asli tray`, `asli run` | Run with the tray icon and window, or in the foreground with neither |

`asli --help` lists them all.

## Security model in five bullets

- Everything is encrypted on your device with XChaCha20-Poly1305 before it leaves. The relay stores
  and forwards ciphertext only.
- The key never reaches the server and is never displayed. It lives in your OS keychain, and goes to
  a new machine only after you approve it, sealed to that machine's own key.
- The server authenticates you with a signature over a fresh challenge, so it never holds a
  credential that would let it (or anyone who steals its database) join your room.
- Content that your password manager marks as sensitive is never synced and never recorded.
- Removing a machine gives every other machine a new key, so it reads nothing new. We do not claim
  forward secrecy: what it already had, it keeps. The full, honest version is in
  [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md).

## Self-hosting the relay

The relay is one Node process with a single runtime dependency, no database, and nothing written to
disk. It holds the most recent clip of each account in memory for up to 24 hours, then forgets it.
Full instructions are in [server/README.md](server/README.md); the short version:

```sh
cd server
docker compose up -d
```

That brings up the relay behind Caddy, which obtains and renews a certificate automatically. Point
your devices at it by setting **Relay Address** in Settings, or by editing `relay_url` in the config
file whose path `asli status` prints.

It is comfortable on the cheapest VPS you can rent. The public instance runs the same code as a
systemd service limited to 128 MB of memory (`MemoryMax=128M`), with its retention budget lowered
from the default 256 MiB to 16 MiB. The only thing a relay cannot do, yours or ours, is read your
clipboard.

## Platform notes

| Platform | Status |
|---|---|
| Windows 10 and 11 | Supported. In daily use on Windows 11 |
| macOS 11 or later (Apple silicon and Intel) | Supported. macOS does not currently prompt for clipboard access; if Apple enables its pasteboard alert, choose Allow once, or Asli cannot send what you copy on that Mac |
| Linux, X11 | Supported |
| Linux, Wayland (Hyprland, Sway, KDE Plasma 6.4+, COSMIC, niri) | Supported, through the compositor's clipboard manager protocol |
| Linux, GNOME Wayland | Works through an XWayland compatibility path, because GNOME declines to support clipboard managers |
| Linux, river | Not supportable: it implements no clipboard manager protocol |

Dropping files on the window works on Windows, macOS, X11 and Wayland.

Details and the reasoning are in [docs/PLATFORM_NOTES.md](docs/PLATFORM_NOTES.md).

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Bug reports about clipboard behaviour should say which OS,
which desktop and which compositor you are on, because that is nearly always the relevant detail.

## License

MIT. See [LICENSE](LICENSE).

The window bundles three typefaces, each under the SIL Open Font License 1.1:
[Figtree](https://github.com/erikdkennedy/figtree), [Outfit](https://github.com/Outfitio/Outfit-Fonts)
and [JetBrains Mono](https://www.jetbrains.com/lp/mono/). Their licences are in
`crates/asli-ui/ui/fonts/`. The Windows, Apple and Linux marks shown beside each device are from
[Simple Icons](https://simpleicons.org), under CC0, and are trademarks of their owners.

Every third party licence, for the crates the binary is built from as well as the fonts and marks,
is listed in [packaging/THIRD_PARTY_LICENSES.txt](packaging/THIRD_PARTY_LICENSES.txt), which ships
with every installer.

The window is drawn with [Slint](https://slint.dev), used under its royalty free licence, which
asks for this attribution where the application is distributed:

<a href="https://slint.dev">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/slint-ui/slint/master/logo/MadeWithSlint-logo-dark.svg">
    <img alt="Made with Slint" src="https://raw.githubusercontent.com/slint-ui/slint/master/logo/MadeWithSlint-logo-light.svg" height="48">
  </picture>
</a>
