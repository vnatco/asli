# Contributing

Thanks for looking. This project is small on purpose, and the fastest way to get a change merged is
to keep it small too.

## Getting set up

```
./setup.sh --build-only        # macOS and Linux
.\setup.ps1 -BuildOnly         # Windows
```

You need Rust. You do **not** need Node.js unless you are working on the relay server, in which case
pass `--with-server`. The script installs what is missing and tells you exactly what it is doing.

Run the tests before you push:

```
cargo test --workspace
cargo fmt --check
cargo clippy --all-targets -- -D warnings
```

For the server:

```
cd server
npm ci
npm test
npm run lint
```

## Commit messages

Conventional commits, lowercase, imperative:

```
feat: add wayland ext-data-control watcher
fix: stop resending our own clip after reconnect
docs: correct the aad byte layout
chore: bump ws to 8.21.3
```

Keep commits focused. One logical change per commit is easier to review and much easier to revert.

## What we are strict about

- **Crypto changes.** Anything touching `crates/asli-crypto` needs a matching test vector and must
  keep `testdata/vectors.json` green. If a change alters the wire format, it is a protocol version
  bump, not a patch.
- **No plaintext in logs.** Ever, on either side. The relay logs an allowlist of named fields only.
- **Docs match the code.** If your change makes a document wrong, fix the document in the same pull
  request. We do not ship aspirational documentation.
- **Platform honesty.** If something cannot work on a platform, say so in
  `docs/PLATFORM_NOTES.md` with the reason, rather than shipping a silent degradation.
- **No em dashes or en dashes** in code, comments, documentation or commit messages. Hyphens, and
  only where necessary.

## Reporting bugs

For clipboard bugs, please include your OS and version, your desktop environment, and on Linux your
display server and compositor (for example: Arch, Hyprland, Wayland). Use the tray menu's
"Copy diagnostics" action if the app runs at all: it collects recent log lines, which never contain
clipboard content.

For security issues, do not open a public issue. See [SECURITY.md](SECURITY.md).

## Pull requests

- Describe what changes and why. Link the issue if there is one.
- Say which platforms you actually tested on. "Builds on Linux" is useful information; so is "not
  tested on Windows".
- There is no hosted CI, so run format, clippy with warnings denied and the tests yourself, on
  every platform you changed code for, and say which ones in the pull request.
