# Asli

One clipboard, every machine. Copy on your laptop, paste on your desktop.

Asli is a small tray app that keeps the clipboard in sync across your own computers, over the
internet, end to end encrypted. There is no account, no email and no password. You create a key on
one machine and paste it (or scan its QR) on the others. That is the entire setup.

"Asli" is the Georgian word for copy (ასლი).

> **Status: pre-release, under active development.** Nothing has been tagged yet and there are no
> downloads. The protocol is specified in [docs/PROTOCOL.md](docs/PROTOCOL.md). This README describes the target, and the sections below
> marked "not yet" are not implemented.

## Why

Every existing option makes you pick one thing you did not want to give up: it is LAN only, or it
needs an account on someone's server, or the server can read your clipboard, or it works on two of
your three operating systems, or it syncs only when your mouse crosses a screen edge. Asli is the
boring one that just works across Windows, macOS and Linux, including Wayland.

## Install

Not yet. Prebuilt binaries and packages will be published on the releases page. Until then, build
from source:

```
git clone <repo-url> && cd asli
./setup.sh          # macOS and Linux
.\setup.ps1         # Windows
```

The setup script installs what is missing (Rust, and the small set of system packages your distro
needs), builds the release binary, and offers to install it and enable launch at login. Building the
client does **not** require Node.js. Node is needed only if you also want to run the relay server
locally, which `--with-server` sets up.

## How it works

1. On the first machine you pick **Create**. Asli generates a 32 byte secret, keeps it in your OS
   keychain (Windows Credential Manager, macOS Keychain, Linux Secret Service), and shows it to you
   once as a QR code and a short token.
2. On your other machines you pick **Connect** and scan or paste that token.
3. From then on, whenever you copy something, the app encrypts it on your machine and sends it
   through a relay server to your other machines, which decrypt it and put it on their clipboard.

The relay only ever sees ciphertext. It cannot read your clipboard, and it does not know who you
are. It keeps at most your most recent clip, briefly, so a machine that was switched off can catch
up when it comes back. You can point the app at your own relay in Settings, and the relay we run is
the same code and the same configuration you would deploy yourself.

## Security model in five bullets

- Everything is encrypted on your device with XChaCha20-Poly1305 before it leaves. The relay stores
  and forwards ciphertext only.
- The key never reaches the server. It exists only in the join token and in your OS keychain.
- The server authenticates you with a signature over a fresh challenge, so it never holds a
  credential that would let it (or anyone who steals its database) join your room.
- Content that your password manager marks as sensitive is not synced at all, by default.
- We do not claim forward secrecy, and v1 has no way to revoke one device: if a key leaks, you
  create a new one. The full, honest version is in [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md).

## Self-hosting the relay

Not yet documented; see [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for the design. The short version:
one Node process, no database, a Docker image and a compose file with Caddy for automatic HTTPS,
comfortable on the cheapest VPS you can rent.

## Platform notes

| Platform | Status |
|---|---|
| Windows 11 | Target for v1 |
| macOS (Apple Silicon and Intel) | Target for v1. macOS does not currently prompt for clipboard access; if Apple enables its pasteboard alert, Asli asks you to allow it once in System Settings and never again |
| Linux, X11 | Target for v1 |
| Linux, Wayland (Hyprland, Sway, KDE Plasma 6.4+, COSMIC, niri) | Target for v1 |
| Linux, GNOME Wayland | Works through an XWayland compatibility path, because GNOME declines to support clipboard managers |
| Linux, river | Not supportable: it implements no clipboard manager protocol |

Details and the reasoning are in [docs/PLATFORM_NOTES.md](docs/PLATFORM_NOTES.md).

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Bug reports about clipboard behaviour should say which OS,
which desktop and which compositor you are on, because that is nearly always the relevant detail.

## License

MIT. See [LICENSE](LICENSE).
