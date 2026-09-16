# macOS: Gatekeeper, and what unsigned means

The macOS build is **unsigned and not notarized**. macOS will refuse to open it, and the message it
shows is about a damaged file rather than an unsigned one, which is misleading but expected.

Verify the download first:

```sh
shasum -a 256 asli
```

Compare against the `SHA256SUMS` file attached to the release. Then remove the quarantine attribute
that the browser applied:

```sh
xattr -dr com.apple.quarantine ./asli
```

On macOS 15 and later there is no Control click shortcut any more: if you run it before clearing
quarantine, the only way through is **System Settings**, **Privacy and Security**, then
**Open Anyway** next to the blocked item.

## The clipboard permission is separate

Unrelated to signing: macOS 15.4 introduced an alert when an application reads the pasteboard
programmatically. It is not enabled by default in current releases, so there may be no prompt at
all. If it is enabled, Asli asks once and then directs you to **System Settings**, **Privacy and
Security**, **Paste from Other Apps**, where setting it to Allow is permanent. Writing to the
clipboard is never gated, so a Mac that is denied read access still receives clips from other
machines.

## The plan

Notarization needs an Apple Developer membership at 99 USD a year, which is also what makes the
permission grant survive application updates, since the grant is keyed to the signing identity. It
is budgeted and not yet purchased.

`Info.plist` beside this file is the template for the eventual `.app` bundle. `LSUIElement` is true
because this is a menu bar application and it must never appear in the Dock or the application
switcher.
