# Windows: the installer

`build-installer.ps1` beside this file builds `dist\asli-<version>-windows-x86_64.exe`, a single
self contained installer. From the repository root, in PowerShell:

```powershell
Set-ExecutionPolicy -Scope Process Bypass
.\packaging\windows\build-installer.ps1
```

It needs what `setup.ps1` needs (the C++ build tools and Rust, which it installs if missing) and
NSIS, which it asks for with the exact command:

```powershell
winget install --id NSIS.NSIS -e
```

## What the installer does

It is `setup.ps1 -Install` for someone who has never opened a terminal:

- Installs `asli.exe` and `asliw.exe` into `%LOCALAPPDATA%\Programs\Asli`, for the current user
  only, so there is **no administrator prompt**. It stops a running copy first, so it also updates.
- Adds a Start menu shortcut to `asliw.exe tray`, with the Asli icon.
- Turns on start at login by running `asli.exe autostart on`, which writes
  `Asli.lnk` in the Startup folder. Not the `Run` registry key, which Explorer ignored at logon on
  the owner's machine; the uninstaller removes that one too, in case an earlier build wrote it.
- Registers itself under Settings, Apps (and Add or Remove Programs) with the Asli icon, its
  version and publisher.
- Starts Asli. Its finish page says to look for the icon by the clock.

The uninstaller, reached from Settings, Apps, Asli, Uninstall, stops Asli and removes all of that:
the files, the Start menu and Startup shortcuts, the old `Run` values, and the Apps entry. It
leaves the account key in Credential Manager and the settings and history in
`%APPDATA%\vnat\asli`, so reinstalling needs no rejoining. `uninstall.exe /S` does the same
silently, and so does the installer: `asli-<version>-windows-x86_64.exe /S`.

The icon is `asli.ico` beside this file, compiled into both executables by `build.rs` and used by
NSIS for the installer, the uninstaller and the Apps entry. `installer-sidebar.bmp` is the picture
on the first and last pages.

## Two choices, and why

**NSIS, not Inno Setup.** Both make a per user installer with an uninstaller. NSIS is zlib licensed
with no conditions, while Inno Setup now asks every commercial user to buy a licence. And the whole
install and uninstall is visible, step by step, in `asli.nsi`.

**The C runtime is linked in, not bundled.** Rust links the Visual C++ runtime
(`VCRUNTIME140.dll`) dynamically by default. That DLL is not part of Windows; it comes with Visual
Studio or its redistributable, and a clean machine without either refuses to start the program.
`.cargo\config.toml` links it statically for every MSVC build, which adds a few hundred kilobytes
and removes the question. The Universal C Runtime is part of Windows 10 and 11 and is not an issue.
`build-installer.ps1` checks both executables with `dumpbin /dependents` and refuses to build the
installer if either still imports `vcruntime*.dll` or `msvcp*.dll`, which is what would happen if a
`RUSTFLAGS` variable overrode the setting.

## The SmartScreen warning

The installer is **unsigned**. The first time someone runs it, Microsoft Defender SmartScreen shows
a blue window titled **Windows protected your PC**, saying it prevented an unrecognised app from
starting, with only a **Don't run** button. To continue:

1. Click **More info**, under the text. The publisher shows as **Unknown publisher**.
2. Click **Run anyway**, which appears at the bottom.

The installer then runs without any further prompt, since it needs no administrator rights.
Browsers may also say the file is not commonly downloaded; in Edge that is **...**, **Keep**, then
**Show more**, **Keep anyway**.

That warning is accurate. It means the publisher is unverified, not that the file has been found to
be malicious. Verify the download yourself before trusting it:

```powershell
Get-FileHash .\asli-0.1.0-windows-x86_64.exe -Algorithm SHA256
```

Compare the result against the `SHA256SUMS` file attached to the release.

### Why it is unsigned

A code signing certificate costs money and, since 2023, requires the private key to live on
hardware. Two things are worth knowing before paying for one:

- An EV certificate no longer buys an instant SmartScreen bypass. That changed in 2024.
- Reputation is what actually clears the warning, and it accrues to the certificate over downloads
  and time. A brand new certificate still shows the warning at first.

The plan is the **SignPath Foundation**, which provides free code signing for qualifying open
source projects. It requires an OSI approved licence with no commercial dual licensing and an
actively maintained project, both of which hold here.

## Untested

Compiled with NSIS 3.11 under Wine and run there silently, from binaries cross built with
llvm-mingw: the files, the Start menu shortcut, the Apps entry, and the uninstaller removing all of
them and leaving the settings, were all checked. The welcome page was seen. Nothing more:

- `build-installer.ps1` has not run on Windows. Neither has the MSVC build with the static runtime,
  nor the `dumpbin` check.
- Real Windows: clicking through the pages, SmartScreen, the Startup shortcut being written (Wine
  has no PowerShell to write it), Asli starting at the end and at the next sign in, and the Apps
  entry's icon.
