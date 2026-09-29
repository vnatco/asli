# macOS: the signed disk image

`build-installer.sh` beside this file builds `dist/asli-<version>-macos-universal.dmg`: Asli.app
for Apple silicon and Intel in one binary, and a link to Applications to drag it onto. Signed with
a Developer ID, notarized by Apple, with the ticket stapled to both the app and the image, it opens
on anyone's Mac with a plain double click: no Gatekeeper warning and no right click, Open.

```sh
packaging/macos/build-installer.sh
```

Nothing about signing lives in the repository. The identity and the notarization credentials come
from environment variables, and the certificate and its key stay in your keychain.

## Once: the certificate

A **Developer ID Application** certificate, which a paid Apple Developer membership includes. Not
"Apple Development" and not "Apple Distribution": those are for development and the App Store, and
Gatekeeper rejects them for a download.

1. In Xcode, **Settings**, **Accounts**, select the team, **Manage Certificates**, **+**,
   **Developer ID Application**. Or create it at developer.apple.com, Certificates, and double
   click the downloaded file.
2. Check it is in the keychain with its private key:

   ```sh
   security find-identity -v -p codesigning
   ```

   The line to use looks like `"Developer ID Application: Your Name (ABCDE12345)"`. The ten
   characters in brackets are your Team ID.

## Once: the notarization credentials

notarytool needs to log in to Apple. Save the credentials in the keychain under a profile name, so
they are never typed into a script or an environment variable:

1. Make an app specific password at account.apple.com, **Sign-In and Security**, **App-Specific
   Passwords**.
2. Store it:

   ```sh
   xcrun notarytool store-credentials asli-notary \
       --apple-id you@example.com --team-id ABCDE12345
   ```

   It prompts for the app specific password and checks it with Apple.

An App Store Connect API key works instead of a profile, for a machine without a login keychain:
the `.p8` file, its key id and its issuer id (App Store Connect, Users and Access, Integrations).

## Every build: the environment

```sh
export ASLI_SIGN_IDENTITY="Developer ID Application: Your Name (ABCDE12345)"
export ASLI_TEAM_ID=ABCDE12345          # optional: refuses an identity from another team
export ASLI_NOTARY_PROFILE=asli-notary
packaging/macos/build-installer.sh
```

Or, with an API key rather than a profile, `ASLI_NOTARY_KEY` (path to the `.p8`),
`ASLI_NOTARY_KEY_ID` and `ASLI_NOTARY_ISSUER` in place of `ASLI_NOTARY_PROFILE`.

The script checks before it builds anything that the identity is in the keychain and that the
notarization credentials log in. With `ASLI_SIGN_IDENTITY` set and no credentials it stops: a
signed image that is not notarized still meets a Gatekeeper warning everywhere else, which is the
one thing this is for.

**With no `ASLI_SIGN_IDENTITY`** it builds anyway, signs ad hoc (Apple silicon runs nothing with no
signature at all), skips notarization, and names the result
`asli-<version>-macos-universal-unsigned.dmg`, saying what it skipped. That image is for trying the
build on the Mac that made it. `packaging/release.sh` refuses to publish it.

## What the script does

1. Builds `aarch64-apple-darwin` and `x86_64-apple-darwin` release binaries against macOS 11, the
   floor `Info.plist` declares, and joins them with `lipo`. Missing targets are reported with
   `rustup target add`. `ASLI_MAC_ARCHS=arm64` builds one architecture, named `...-macos-aarch64.dmg`.
2. Assembles Asli.app from `Info.plist` (version filled in from `Cargo.toml`) and `asli.icns`.
3. Signs it with the hardened runtime, a secure timestamp and `entitlements.plist`, which is empty
   because Asli needs none of the runtime's exceptions; the file says why for each.
4. Notarizes the app (as a zip) and staples the ticket to it, so it also opens offline once it is
   out of the image.
5. Builds the image: the app, a link to Applications, the Asli volume icon. Signs, notarizes and
   staples the image too.
6. Verifies from the finished image, and fails loudly if any check fails: `codesign --verify
   --strict --deep`, the hardened runtime flag, `spctl --assess --type execute` on the app,
   `spctl --assess --type open --context context:primary-signature` on the image, and
   `xcrun stapler validate` on both.

A rejected notarization prints Apple's log, which is the only place the reason is written.

## Verifying by hand

On another Mac, after downloading it with a browser (so it carries the quarantine flag a real user's
copy has):

```sh
spctl --assess --type open --context context:primary-signature -vv asli-0.1.0-macos-universal.dmg
xcrun stapler validate asli-0.1.0-macos-universal.dmg
```

Both should say accepted and valid, with `source=Notarized Developer ID`. Then double click it, drag
Asli to Applications, and open it: no dialog should appear other than, the first time, macOS noting
it was downloaded from the internet with an **Open** button.

## Installing, starting at login, removing

Dragging Asli to Applications installs it. Opening it starts the menu bar icon (no Dock icon: the
bundle is `LSUIElement`), and at that first start Asli writes its launchd agent,
`~/Library/LaunchAgents/dev.vnat.asli.plist`, pointing at the copy in Applications. From then on it
starts at login. This is the same agent `setup.sh --install` sets up.

Dragging Asli to the Trash removes the app, but **not the launchd agent**: macOS runs nothing when an
app is trashed. The agent then points at a program that is not there, so at login launchd logs a
failure and starts nothing; there is nothing on screen. To remove it too, before trashing, turn off
**Start at login** in Asli's Settings, or afterwards:

```sh
launchctl bootout gui/$(id -u)/dev.vnat.asli 2>/dev/null
rm ~/Library/LaunchAgents/dev.vnat.asli.plist
```

A login item that vanishes with the app would need `SMAppService`, macOS 13 or later, in place of
the agent. That is a change to the app, not the packaging, and has not been made.

The account key stays in the keychain, and the settings and history in
`~/Library/Application Support/dev.vnat.asli`, either way.

A Developer ID signature also fixes the keychain prompts that came after each reinstall of an ad
hoc build: the keychain's **Always Allow** is tied to the signing identity, which now stays the same
from one version to the next. The first signed build still asks once, because the old entry was
granted to the ad hoc one.

## The clipboard permission is separate

Unrelated to signing: macOS 15.4 introduced an alert when an application reads the pasteboard
programmatically. It is not enabled by default in current releases, so there may be no prompt at
all. If it is enabled, Asli asks once and then directs you to **System Settings**, **Privacy and
Security**, **Paste from Other Apps**, where setting it to Allow is permanent. Writing to the
clipboard is never gated, so a Mac that is denied read access still receives clips from other
machines.

## Untested

The Mac was not reachable when this script was written, so **none of it has run**. It is linted with
shellcheck and built from what `setup.sh --install` already does on the owner's Mac, but the
universal build, the bundle, signing, both notarizations, stapling, the image, its volume icon and
every verification step are unproven until the first run. So is `asli.icns`, which was assembled
without Apple's `iconutil`, and whether Gatekeeper accepts the result on a second Mac.
