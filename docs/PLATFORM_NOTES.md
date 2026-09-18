# Platform notes

Everything awkward about clipboards, per operating system, written for someone whose clipboard is
not syncing. If you are reading this because something is broken, start at section 7.

> **Status.** Linux is implemented and verified on real hardware, for text and for images, over
> both X11 and Wayland. The Windows and macOS backends are written, but no Win32 or AppKit call in
> either has been observed running yet, so treat those sections as the mechanism they will use
> rather than as observed behaviour.

## 1. Support matrix

| Platform or desktop | Monitor mechanism | Background read | Write | Tray | Caveat |
|---|---|---|---|---|---|
| **Windows 11** | `AddClipboardFormatListener` on a message only window, real events, no polling | Yes, no focus needed | Yes | Yes, native | `OpenClipboard` can fail under contention; a delay rendered format can block for 30 seconds |
| **macOS 14 and earlier** | Poll `changeCount` at 500 ms | Yes | Yes | Yes | App Nap can throttle timers |
| **macOS 15.4 through 26.x** | Same polling | Yes, but gated by a permission alert | Yes | Yes | One time grant in System Settings. See section 3 |
| **Linux X11, any window manager** | XFixes selection notify on `CLIPBOARD` | Yes, no focus needed | Yes | Depends on the desktop | INCR for large payloads, content dies with the source client |
| **Hyprland** | `ext-data-control-v1`, falling back to `wlr-data-control` | Yes | Yes | waybar tray module only | The compositor has no tray of its own |
| **Sway and other wlroots** | `ext-data-control-v1` (Sway 1.12 and later), else `wlr` | Yes | Yes | waybar only | wlroots does not preserve clipboard content after the source exits |
| **KDE Plasma 6.4 and later** | `ext-data-control-v1` only | Yes | Yes | Yes, native | `wlr-data-control` was removed in Plasma 6.4 |
| **KDE Plasma 6.3 and earlier** | `wlr-data-control` only | Yes | Yes | Yes | `ext` is not present yet, which is why we implement both |
| **COSMIC, niri, Wayfire** | Both protocols | Yes | Yes | Varies by shell | Confirmed by reading their source |
| **GNOME Wayland** | Neither protocol. Hidden XWayland window plus XFixes | Yes, through the XWayland bridge | Yes | No, without the AppIndicator extension | GNOME declines to support clipboard managers as policy. See section 5 |
| **GNOME X11** | XFixes, the normal path | Yes | Yes | No, without the AppIndicator extension | Mutter caches clipboard content, so it survives the source exiting |
| **river** | None available | **No** | Partial | No | Implements neither protocol. Not supportable. See section 6 |

## 2. Windows

**Mechanism.** `AddClipboardFormatListener` on a message only window. Windows tells us when the
clipboard changes, so there is no polling and no idle wakeup cost.

**Contention is normal, not exceptional.** `WM_CLIPBOARDUPDATE` is posted to every registered
listener at the same moment, so every clipboard manager, cloud clipboard, antivirus scanner and
remote desktop bridge on the machine races to open the clipboard in the same few milliseconds, and
only one wins. Microsoft's own guidance describes the resulting access denied failure on Windows 11
as "mostly fails, sometimes works" when you call it directly from the notification handler.
`rdpclip.exe` is a known aggressive holder of the lock.

What we do: the notification handler does nothing except arm a 100 ms debounce timer. A worker
thread then opens the clipboard with exponential backoff (1 ms doubling, 8 attempts, roughly 150 ms
total) and gives up quietly until the next event if it never wins.

**The 30 second hazard.** A clipboard format can be advertised without being produced yet, and asking
for it makes the owning application render it while the system waits, for up to 30 seconds. During
that wait we would be holding the clipboard open, so every other application on the machine would
fail to open it. A careless clipboard monitor can freeze clipboard functionality system wide. What we
do: enumerate the available formats first, which never triggers a render, then ask for exactly one
format, on a worker thread, never on the message pump.

**Text handling.** Windows text is CRLF terminated and carries a trailing NUL. Both are normalized
away before hashing and before sending, and restored when writing, otherwise the same text hashes
differently on Windows than on Linux and the loop guard stops working.

**Exclusion formats we honour.** If a copy is marked with any of
`ExcludeClipboardContentFromMonitorProcessing`, `CanIncludeInClipboardHistory` set to zero, or
`CanUploadToCloudClipboard` set to zero, we skip it entirely: not read, not hashed, not encrypted,
not sent. The third one is the exact semantic of what this app does, so an application setting it is
explicitly saying "do not send this to my other devices". KeePassXC sets all three.

## 3. macOS

**Mechanism.** There is no clipboard change notification API on macOS, and there never has been. The
only option is to poll `NSPasteboard.general.changeCount`, which is cheap: it is an integer read, not
a content read.

**We poll at 500 ms**, matching Maccy, Clipy and CopyQ. Apple's own guidance says to investigate any
idle application that wakes more than once a second. A watcher holds a background activity token so
App Nap does not throttle the timer, and uses a timer tolerance so the system can coalesce wakeups
with other work.

**The permission alert, which is the real macOS story.** Starting with macOS 15.4, the system shows
an alert when an application programmatically reads the general pasteboard, unless the read followed
a user action the system considers paste related. The important facts:

- There is **no entitlement, no `Info.plist` key and no MDM profile** that grants this in advance.
  Apple deliberately declined to provide a programmatic grant, and said in a Feedback Assistant reply
  that applications should instead guide the user to the System Settings pane.
- The permission state is readable but not writable by us.
- The `detect` APIs that are exempt from the alert only match predefined patterns such as email
  addresses, links and phone numbers. They cannot return arbitrary text, so they are not a way to
  sync a clipboard without prompting.
- Reading the change counter and the type list carry no privacy language and are very likely exempt,
  which is what makes the design workable. **This is unverified against real macOS 26 hardware and is
  a blocking task before the macOS client ships.**

**What the app will do.** Read the permission state at launch. If clipboard access is blocked, say so
in the tray menu with a link to the settings pane rather than failing silently. Otherwise, show a
one time onboarding screen that walks you to System Settings, Privacy and Security, "Paste from Other
Apps", and asks you to choose Allow. After that the prompt does not return. Content is read only when
the change counter actually moves, which keeps the number of gate-able reads to at most one per real
copy.

**Receiving never needs permission.** Writing to the pasteboard is not gated. If you refuse the
permission, or macOS blocks it, this Mac still receives clips from your other machines and puts them
on your clipboard. Only sending from the Mac stops working. That is a degraded mode, not a dead app.

**Menu bar only.** The app is marked as an agent application, so it has no Dock icon and no menu bar
of its own, which is the behaviour a tray utility should have on macOS.

**Sensitive content.** Copies marked with the `org.nspasteboard.ConcealedType`, `TransientType` or
`AutoGeneratedType` conventions are skipped.

## 4. Linux, X11

**Mechanism.** XFixes selection notification on the `CLIPBOARD` selection. This is a real event, no
polling, and it requires no focus.

**Self echo detection is better here than anywhere else.** When we take ownership of the selection
after writing a received clip, the resulting notification names our own window as the new owner, so
we can drop it by identity rather than by content hash.

**Large payloads use INCR.** X11 transfers larger than the maximum request size arrive in chunks
through the INCR protocol. It has to be implemented properly on the receive path or large clips
silently truncate.

**Content dies with its owner.** X11 has no clipboard storage: the application that copied still owns
the data and serves it on request. Close that application and the clipboard is empty, unless a
clipboard manager took ownership. This is why we must keep serving the target list correctly for as
long as we hold the selection.

**We do not sync PRIMARY.** The middle click selection changes every time you select any text
anywhere, which would generate constant traffic and genuinely astonishing behaviour on your other
machines. Only `CLIPBOARD` is synced.

**Duplicate events are routine.** With Klipper, GPaste, clipmenu or cliphist running, one copy
produces two or more ownership changes. The 100 ms debounce coalesces them and we read once at the
end, which also avoids catching a half written set of formats.

## 5. Linux, Wayland

**Why two protocols.** An ordinary Wayland client cannot read the clipboard without keyboard focus.
Clipboard managers use a privileged protocol instead, and there are two of them:

- `wlr-data-control-unstable-v1`, the original wlroots protocol, now **deprecated in its own
  specification**.
- `ext-data-control-v1`, the standardised successor, shipped in wayland-protocols 1.39.

This is not an academic distinction. **KDE removed `wlr-data-control` in Plasma 6.4**, so a client
that speaks only `wlr` is broken on current KDE. Older wlroots compositors predate `ext`, so a client
that speaks only `ext` is broken there. We try `ext` first, fall back to `wlr`, and fall back to
XFixes through XWayland.

**Persistence differs by compositor.** wlroots compositors (Sway, Hyprland, Wayfire) drop clipboard
content when the source application exits, exactly like bare X11. KDE relies on Klipper to re-own the
selection. GNOME caches content in the compositor itself. This is one reason the debounce stays at
100 ms rather than something longer: on wlroots, waiting too long risks the source disappearing
first.

**Sensitive markers work here.** The password manager hint is an ordinary MIME type on the offer, so
it arrives before we read anything, and it survives the data-control path end to end.

### GNOME specifically

GNOME supports neither clipboard manager protocol, and this is a deliberate, maintainer stated
position that has been consistent for seven years, not a missing feature waiting on a patch. The
request was closed in 2019 ("There is no plan to support external clipboard managers"), again in
February 2025 ("consensus among mutter developers that we do not want to add those kinds of
protocols"), and again in April 2026 as out of scope ("The current plan is simply not to allow
external clipboard managers"). Do not expect this to change.

**What works anyway: the XWayland bridge.** GNOME's compositor mirrors Wayland native clipboard
ownership into the X11 selection so that X11 applications keep working. That means a hidden X11
client watching with XFixes **does see copies made by Wayland applications on GNOME**, and XFixes
needs no focus. This is the same code as the X11 backend, selected automatically at runtime. The tray
menu will say GNOME is running in compatibility mode so the behaviour is visible rather than
mysterious.

Two honest caveats: exotic clipboard formats may not survive the bridge (plain text and PNG do), and
whether the password manager hint survives it is **unverified** and must be tested before secret
filtering can be trusted on GNOME Wayland.

**Rejected alternatives, for the record.** A GNOME Shell extension would work, but no existing
extension exposes an interface a native application can use, so we would be shipping and maintaining
a second product in JavaScript, versioned against every GNOME Shell release. Shelling out to
`wl-paste --watch` does not work on GNOME at all: it is refused outright, not degraded. The desktop
portal clipboard interface requires an active remote desktop or input capture session, meaning a
visible screen sharing grant, which is not an acceptable foundation for a background utility.

### river

river implements neither data-control protocol, and data-control is the only sanctioned route for a
third party to watch or durably own the selection. There is no workaround, no fallback and nothing
clever to try. Clipboard sync cannot work on river. If you use river, this tool is not for you until
river adds the protocol.

## 6. The tray on Linux

The tray is a D-Bus protocol called StatusNotifierItem, and an icon only appears if something in your
session implements a host for it.

- **KDE Plasma**: works natively, no extra steps.
- **GNOME**: vanilla GNOME Shell has had no tray since 3.26. You need the "AppIndicator and
  KStatusNotifierItem Support" extension. Ubuntu ships it by default, Arch does not.
- **Hyprland, Sway and other bare compositors**: the compositor has no tray. Your status bar provides
  it, for example waybar's tray module. If your bar has no tray module configured, no icon appears.

**Left click opens the window** on hosts that deliver `Activate`, which KDE Plasma does. Some bars
only ever show the menu, so every action is also in the menu, and no feature depends on telling a
left click from a right click.

Because a missing tray host makes the application invisible rather than merely ugly, startup will
check whether a StatusNotifierItem host exists and, if not, show the onboarding window with the exact
command to fix it rather than vanishing into the background.

## 7. Troubleshooting

**Nothing syncs on GNOME Wayland.** Check that XWayland is running, since the GNOME path depends on
it. A Flatpak or Snap build would additionally need the X11 socket exposed, which is one reason those
are not the primary Linux packaging route.

**No tray icon on GNOME.** Install and enable the AppIndicator extension. On Arch that is
`gnome-shell-extension-appindicator`, then enable it in the Extensions application and log out and
back in.

**No tray icon on Hyprland or Sway.** Your bar needs a tray module. In waybar, add `tray` to the
modules list in your configuration.

**Clipboard does not sync on KDE.** If you are on Plasma 6.4 or later, this is the protocol removal
described in section 5. Make sure you are running a current build rather than an old one that speaks
only the removed protocol.

**The keychain fails on bare Hyprland or Sway.** A session with no `gnome-keyring-daemon` and no
`kwallet` running has no Secret Service provider, so there is nowhere standard to put the key. The
app falls back to an encrypted file in the configuration directory and will say so plainly in the
interface. That fallback protects against casual inspection, not against someone imaging the disk,
because the file and its key live on the same disk. If that matters to you, start a keyring daemon in
your session.

**macOS asks for clipboard permission repeatedly.** Open System Settings, Privacy and Security, and
find "Paste from Other Apps". Set Asli to Allow. The application appears in that list only after it
has triggered at least one prompt, which is a limitation of the operating system and the reason the
onboarding flow exists. If you would rather not grant it, the Mac still receives clips from your
other machines; only sending stops.

**Copying the same text twice does not sync the second time.** It should, and it is tested. The loop
prevention entries expire after a short window precisely so that deliberately re-copying works. If
you see this, please file a bug with your platform and desktop.

**Large clips do not arrive.** There is a size cap, and anything over it is skipped with a
notification rather than silently dropped. The limit is announced by the relay, so a self hosted
relay can raise it without a client update.
