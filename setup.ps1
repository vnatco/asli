<#
.SYNOPSIS
    Asli setup script for Windows.

.DESCRIPTION
    Installs what is missing, builds, and optionally installs the binary. It is idempotent:
    running it twice is safe and the second run does almost nothing. It never half succeeds.
    If something is missing that we cannot install for you, it stops and prints the exact
    command to fix it.

    Building the client does NOT require Node.js. Node is needed only for the relay server,
    which is what -WithServer sets up.

.PARAMETER BuildOnly
    Install prerequisites and build. Do not install the binary.

.PARAMETER Install
    Build, then install the binary into the user programs directory.

.PARAMETER WithServer
    Also set up the relay server, which is the only part that needs Node.js.

.PARAMETER Uninstall
    Remove an installed binary and its autostart entry. Does not touch Credential Manager.

.PARAMETER DryRun
    Print what would happen and change nothing.

.EXAMPLE
    .\setup.ps1
    .\setup.ps1 -BuildOnly
    .\setup.ps1 -WithServer
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
        Write-Host '    winget install --id Microsoft.VisualStudio.2022.BuildTools --override "--quiet --add Microsoft.VisualStudio.Workload.VCTools --includeRecommended"'
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
    if (Test-CommandExists 'cargo') {
        Write-Ok "Rust is present ($(cargo --version))"
        return
    }

    $cargoBin = Join-Path $env:USERPROFILE '.cargo\bin'
    if (Test-Path (Join-Path $cargoBin 'cargo.exe')) {
        $env:PATH = "$cargoBin;$env:PATH"
        Write-Ok 'Rust found in %USERPROFILE%\.cargo\bin'
        return
    }

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
    $env:PATH = "$cargoBin;$env:PATH"
    Write-Ok "Rust installed ($(cargo --version))"
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

function Invoke-Uninstall {
    $binary = Join-Path $InstallDir 'asli.exe'
    if (Test-Path $binary) {
        Write-Info "Removing $binary"
        if (-not $DryRun) { Remove-Item $binary -Force }
        Write-Ok 'binary removed'
    } else {
        Write-Ok "nothing installed at $binary"
    }

    $runKey = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run'
    $entry = Get-ItemProperty -Path $runKey -Name 'Asli' -ErrorAction SilentlyContinue
    if ($entry) {
        Write-Info 'Removing the launch at login entry'
        if (-not $DryRun) { Remove-ItemProperty -Path $runKey -Name 'Asli' }
        Write-Ok 'autostart entry removed'
    }

    Write-Host ''
    Write-Info 'Uninstall complete.'
    Write-Host '  Your account key is still in Windows Credential Manager. Nothing here deleted it.'
    Write-Host '  To remove it as well, use Reset account in the tray menu before uninstalling, or'
    Write-Host '  delete the "asli" entry from Credential Manager by hand.'
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
Invoke-Step 'cargo' @('build', '--release', '--workspace')
Write-Ok 'build finished'

Write-Host ''
Write-Info 'Running tests'
Invoke-Step 'cargo' @('test', '--workspace')
Write-Ok 'tests passed'

if ($WithServer) {
    Write-Host ''
    $serverDir = Join-Path $RepoRoot 'server'
    if (Test-Path $serverDir) {
        Write-Info 'Setting up the relay server'
        Push-Location $serverDir
        try { Invoke-Step 'npm' @('ci') } finally { Pop-Location }
        Write-Ok 'server dependencies installed. Start it with: cd server; npm start'
    } else {
        Write-Warn 'The relay server is not in this repository yet, so there is nothing to set up.'
        Write-Host '  The server lands in M1.'
    }
}

Write-Host ''
if ($Install) {
    Write-Warn 'There is no installable binary yet.'
    Write-Host "  Asli is at M0: the crypto library builds and is tested, and the tray client is not"
    Write-Host "  written yet. When it exists, -Install will place it in $InstallDir."
} elseif ($BuildOnly) {
    Write-Ok 'Build only requested, stopping here.'
}

Write-Host ''
Write-Host 'Done.' -ForegroundColor Green
Write-Host 'What exists today: the asli-crypto library, its test suite, and the frozen protocol vectors.'
Write-Host 'What does not exist yet: the tray client, the relay server, and installable packages.'
Write-Host 'See docs/BUILDING.md for the details.'
