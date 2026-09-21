<#
.SYNOPSIS
    Asli setup script for Windows.

.DESCRIPTION
    Checks prerequisites, builds, and optionally installs Asli. It is idempotent: running it twice
    is safe. It never half succeeds. If something is missing that it cannot install for you, it
    stops and prints the exact command to fix it.

    Building the client does NOT require Node.js. Node is needed only for the relay server, which
    is what -WithServer sets up.

.PARAMETER BuildOnly
    Check prerequisites and build. Do not run the tests and do not install.

.PARAMETER Install
    Build, then install asli.exe and asliw.exe into the user programs directory, add a Start menu
    shortcut, turn on launch at login, and start Asli.

.PARAMETER WithServer
    Also install the relay server's dependencies, which is the only part that needs Node.js.

.PARAMETER Uninstall
    Stop Asli and remove what -Install put in place. Does not touch Credential Manager.

.PARAMETER DryRun
    Print what would happen and change nothing.

.EXAMPLE
    .\setup.ps1
    .\setup.ps1 -BuildOnly
    .\setup.ps1 -Install
    .\setup.ps1 -Uninstall
#>

[CmdletBinding()]
param(
    [switch]$BuildOnly,
    [switch]$Install,
    [switch]$WithServer,
    [switch]$Uninstall,
    [switch]$DryRun
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$RepoRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$InstallDir = if ($env:ASLI_INSTALL_DIR) { $env:ASLI_INSTALL_DIR } else { Join-Path $env:LOCALAPPDATA 'Programs\Asli' }
$Shortcut = Join-Path ([Environment]::GetFolderPath('Programs')) 'Asli.lnk'
$RunKey = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run'
# Explorer's record of which Run entries it will actually start at login. Written beside the Run
# value, so it has to be removed beside it too.
$ApprovedKey = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run'
$Binaries = @('asli.exe', 'asliw.exe')

function Write-Info { param([string]$Message) Write-Host "==> $Message" -ForegroundColor White }
function Write-Ok   { param([string]$Message) Write-Host "  ok $Message" -ForegroundColor Green }
function Write-Warn { param([string]$Message) Write-Host " warn $Message" -ForegroundColor Yellow }
function Write-Fail {
    param([string]$Message)
    Write-Host "error $Message" -ForegroundColor Red
    exit 1
}

function Invoke-Step {
    param([string]$Command, [string[]]$Arguments = @())
    if ($DryRun) {
        Write-Host "  would run: $Command $($Arguments -join ' ')"
        return
    }
    & $Command @Arguments
    if ($LASTEXITCODE -ne 0) {
        Write-Fail "command failed: $Command $($Arguments -join ' ')"
    }
}

function Test-CommandExists {
    param([string]$Name)
    $null -ne (Get-Command $Name -ErrorAction SilentlyContinue)
}

function Confirm-MsvcBuildTools {
    $vswhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe'
    if (-not (Test-Path $vswhere)) {
        Write-Warn 'The Microsoft C++ build tools are missing, and Rust needs them to link on Windows.'
        Write-Host '  Install them, then run this script again:'
        Write-Host '    winget install --id Microsoft.VisualStudio.2022.BuildTools --override "--quiet --wait --add Microsoft.VisualStudio.Workload.VCTools --includeRecommended"'
        Write-Host '  Or download from https://visualstudio.microsoft.com/visual-cpp-build-tools/ and select'
        Write-Host '  the "Desktop development with C++" workload.'
        Write-Fail 'missing prerequisite: MSVC build tools'
    }

    $installPath = & $vswhere -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
    if ([string]::IsNullOrWhiteSpace($installPath)) {
        Write-Warn 'Visual Studio is installed, but without the C++ toolset.'
        Write-Host '  Open the Visual Studio Installer, click Modify, and add the'
        Write-Host '  "Desktop development with C++" workload. Then run this script again.'
        Write-Fail 'missing prerequisite: MSVC C++ toolset'
    }
    Write-Ok "MSVC build tools found at $installPath"
}

function Confirm-Rust {
    if (-not (Test-CommandExists 'cargo')) {
        $cargoBin = Join-Path $env:USERPROFILE '.cargo\bin'
        if (Test-Path (Join-Path $cargoBin 'cargo.exe')) {
            $env:PATH = "$cargoBin;$env:PATH"
        }
    }

    if (-not (Test-CommandExists 'cargo')) {
        Write-Info 'Rust is not installed. Installing it with rustup (a user level install, no admin needed).'
        if ($DryRun) {
            Write-Host '  would run: rustup-init.exe -y --profile minimal --component rustfmt --component clippy'
            return
        }

        $installer = Join-Path $env:TEMP 'rustup-init.exe'
        try {
            Invoke-WebRequest -Uri 'https://win.rustup.rs/x86_64' -OutFile $installer -UseBasicParsing
        } catch {
            Write-Fail "could not download rustup. Install Rust manually from https://rustup.rs and run this script again. ($($_.Exception.Message))"
        }

        & $installer -y --profile minimal --component rustfmt --component clippy
        if ($LASTEXITCODE -ne 0) {
            Write-Fail 'rustup install failed. Install Rust manually from https://rustup.rs and run this script again.'
        }
        $env:PATH = "$(Join-Path $env:USERPROFILE '.cargo\bin');$env:PATH"
    }

    # The GNU toolchain would need MinGW, which this script does not set up. MSVC is the supported
    # one, and a rustup that defaulted to GNU builds nothing here.
    $host_triple = (& rustc -vV | Select-String '^host:').ToString()
    if ($host_triple -notmatch 'msvc') {
        Write-Warn "Rust is set to the GNU toolchain ($host_triple). Asli builds with MSVC on Windows."
        Write-Host '  Switch, then run this script again:'
        Write-Host '    rustup default stable-x86_64-pc-windows-msvc'
        Write-Fail 'wrong Rust toolchain'
    }
    Write-Ok "Rust is present ($(cargo --version))"
}

function Confirm-Node {
    if (Test-CommandExists 'node') {
        Write-Ok "Node.js is present ($(node --version)), which the relay server needs"
        return
    }
    Write-Warn 'Node.js is not installed, and the relay server needs it.'
    Write-Host '  Install it, then run: .\setup.ps1 -WithServer'
    Write-Host '    winget install --id OpenJS.NodeJS.LTS'
    Write-Fail 'missing prerequisite: Node.js (only needed for -WithServer)'
}

# A running copy holds its executable open, so it has to stop before the file can be replaced or
# removed. Every copy stops, not only installed ones: a build started from the source tree holds
# the single instance lock too, and the newly installed copy would then exit as already running
# while this script reported it as started. setup.sh does the same.
function Invoke-StopAsli {
    $running = @(Get-Process -Name 'asli', 'asliw' -ErrorAction SilentlyContinue)
    if ($running.Count -eq 0) { return }

    Write-Info 'Stopping the running copy of Asli'
    if (-not $DryRun) {
        $running | Stop-Process -Force
        $running | Wait-Process -Timeout 10 -ErrorAction SilentlyContinue
    }
    Write-Ok 'stopped'
}

function Invoke-Install {
    $built = Join-Path $RepoRoot 'target\release'
    foreach ($binary in $Binaries) {
        if (-not $DryRun -and -not (Test-Path (Join-Path $built $binary))) {
            Write-Fail "no $binary in $built. The build step should have produced it."
        }
    }

    Write-Info "Installing into $InstallDir"
    Invoke-StopAsli
    if (-not $DryRun) {
        New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
        foreach ($binary in $Binaries) {
            Copy-Item -Force (Join-Path $built $binary) (Join-Path $InstallDir $binary)
        }
    }
    Write-Ok 'asli.exe and asliw.exe installed'

    $windowed = Join-Path $InstallDir 'asliw.exe'
    if ($DryRun) {
        Write-Host "  would create: $Shortcut"
    } else {
        $shell = New-Object -ComObject WScript.Shell
        $link = $shell.CreateShortcut($Shortcut)
        $link.TargetPath = $windowed
        $link.Arguments = 'tray'
        $link.WorkingDirectory = $InstallDir
        $link.Description = 'Encrypted clipboard sync across your own machines'
        $link.Save()
    }
    Write-Ok 'Start menu shortcut created'

    # The binary writes the login entry itself, pointing at the installed asliw.exe, and it is the
    # same code that checks the entry every time Asli starts. A failure here is a warning, not the
    # end of the install: Asli works without starting at login.
    if ($DryRun) {
        Write-Host "  would run: $(Join-Path $InstallDir 'asli.exe') autostart on"
    } else {
        & (Join-Path $InstallDir 'asli.exe') autostart on
        if ($LASTEXITCODE -ne 0) {
            Write-Warn "could not turn on launch at login. Run 'asli autostart on' later."
        }
    }

    $userPath = [Environment]::GetEnvironmentVariable('PATH', 'User')
    if (-not ($userPath -split ';' | Where-Object { $_ -ieq $InstallDir })) {
        Write-Warn "$InstallDir is not on your PATH, so 'asli' will not work in a new terminal yet."
        Write-Host '  To add it for your user only:'
        Write-Host "    [Environment]::SetEnvironmentVariable('PATH', `"`$([Environment]::GetEnvironmentVariable('PATH','User'));$InstallDir`", 'User')"
    }

    Write-Host ''
    Write-Info 'Starting Asli'
    if ($DryRun) {
        Write-Host "  would run: $windowed tray"
    } else {
        Start-Process -FilePath $windowed -ArgumentList 'tray' -WorkingDirectory $InstallDir
    }
    Write-Ok 'Asli is running. Look for its icon in the notification area; it may be under the ^ arrow.'
    Write-Host '  It also starts by itself when you sign in.'
    Write-Host "  To watch its log, quit it from the tray and run: & '$(Join-Path $InstallDir 'asli.exe')' tray"
}

function Invoke-Uninstall {
    Invoke-StopAsli

    foreach ($binary in $Binaries) {
        $path = Join-Path $InstallDir $binary
        if (Test-Path $path) {
            Write-Info "Removing $path"
            if (-not $DryRun) { Remove-Item $path -Force }
        }
    }
    if ((Test-Path $InstallDir) -and -not (Get-ChildItem $InstallDir -Force | Select-Object -First 1)) {
        if (-not $DryRun) { Remove-Item $InstallDir -Force }
    }
    Write-Ok 'binaries removed'

    if (Test-Path $Shortcut) {
        Write-Info "Removing $Shortcut"
        if (-not $DryRun) { Remove-Item $Shortcut -Force }
        Write-Ok 'Start menu shortcut removed'
    }

    foreach ($key in @($RunKey, $ApprovedKey)) {
        $entry = Get-ItemProperty -Path $key -Name 'Asli' -ErrorAction SilentlyContinue
        if ($entry) {
            Write-Info "Removing the launch at login entry from $key"
            if (-not $DryRun) { Remove-ItemProperty -Path $key -Name 'Asli' }
            Write-Ok 'autostart entry removed'
        }
    }

    Write-Host ''
    Write-Info 'Uninstall complete.'
    Write-Host '  Your account key is still in Windows Credential Manager. Nothing here deleted it.'
    Write-Host '  To remove it as well, run "asli reset" before uninstalling, or delete the'
    Write-Host '  "asli" entry from Credential Manager by hand. Settings and history stay in'
    Write-Host "  $(Join-Path $env:APPDATA 'vnat\asli') until you delete that folder."
}

Write-Host 'Asli setup (Windows)' -ForegroundColor White
Write-Host ''
if ($DryRun) { Write-Info 'Dry run: nothing will be changed.' }

if ($Uninstall) {
    Invoke-Uninstall
    exit 0
}

Write-Info 'Checking prerequisites'
Confirm-MsvcBuildTools
Confirm-Rust
if ($WithServer) { Confirm-Node }

Write-Host ''
Write-Info 'Building'
# The windowed feature also builds asliw.exe, the console free copy that login and the Start menu
# launch.
Invoke-Step 'cargo' @('build', '--release', '-p', 'asli-app', '--features', 'windowed')
Write-Ok 'build finished'

if (-not $BuildOnly -and -not $Install) {
    Write-Host ''
    Write-Info 'Running tests'
    Invoke-Step 'cargo' @('test', '--workspace')
    Write-Ok 'tests passed'
}

if ($WithServer) {
    Write-Host ''
    Write-Info 'Setting up the relay server'
    Push-Location (Join-Path $RepoRoot 'server')
    try { Invoke-Step 'npm' @('ci') } finally { Pop-Location }
    Write-Ok 'server dependencies installed. Start it with: cd server; npm start'
}

Write-Host ''
if ($Install) {
    Invoke-Install
} elseif ($BuildOnly) {
    Write-Ok 'Build only requested, stopping here.'
} else {
    Write-Info 'Built. Run .\setup.ps1 -Install to install it, or run target\release\asli.exe tray directly.'
}

Write-Host ''
Write-Host 'Done.' -ForegroundColor Green
