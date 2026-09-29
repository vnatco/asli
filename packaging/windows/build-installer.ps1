<#
.SYNOPSIS
    Builds the Asli installer for Windows into dist\ at the repository root.

.DESCRIPTION
    One command, no arguments, from a fresh clone:

        .\packaging\windows\build-installer.ps1

    It checks for NSIS first, then builds asli.exe and asliw.exe through setup.ps1 -BuildOnly
    (which checks for the C++ build tools and Rust, and installs Rust if it is missing), confirms
    the executables do not need the Visual C++ runtime DLL, and compiles asli.nsi beside this file
    into a single self contained installer:

        dist\asli-<version>-windows-<arch>.exe
        dist\SHA256SUMS

    SHA256SUMS covers every artifact of this version in dist\, so with the Linux and macOS files
    copied in first it covers the whole release.

    Idempotent, and it never half succeeds: anything missing stops it with the exact command to
    install it, before the long build starts.

.PARAMETER DryRun
    Print what would happen and change nothing.

.EXAMPLE
    .\packaging\windows\build-installer.ps1
    .\packaging\windows\build-installer.ps1 -DryRun
#>

[CmdletBinding()]
param(
    [switch]$DryRun
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$Here = Split-Path -Parent $MyInvocation.MyCommand.Path
$RepoRoot = (Resolve-Path (Join-Path $Here '..\..')).Path
$Dist = Join-Path $RepoRoot 'dist'
$Built = Join-Path $RepoRoot 'target\release'

function Write-Info { param([string]$Message) Write-Host "==> $Message" -ForegroundColor White }
function Write-Ok   { param([string]$Message) Write-Host "  ok $Message" -ForegroundColor Green }
function Write-Warn { param([string]$Message) Write-Host " warn $Message" -ForegroundColor Yellow }
function Write-Fail {
    param([string]$Message)
    Write-Host "error $Message" -ForegroundColor Red
    exit 1
}

# The version, from the workspace manifest, which is the one place it is written.
function Get-AsliVersion {
    $match = Select-String -Path (Join-Path $RepoRoot 'Cargo.toml') -Pattern '^version\s*=\s*"([^"]+)"' |
        Select-Object -First 1
    if (-not $match) { Write-Fail 'could not read the version from Cargo.toml' }
    return $match.Matches[0].Groups[1].Value
}

function Get-AsliArch {
    switch ($env:PROCESSOR_ARCHITECTURE) {
        'AMD64' { return 'x86_64' }
        'ARM64' { return 'aarch64' }
        default { Write-Fail "unsupported architecture: $($env:PROCESSOR_ARCHITECTURE)" }
    }
}

# NSIS rather than Inno Setup: its licence is zlib with no conditions, where Inno Setup asks every
# commercial user to buy a licence, and the installer is a script whose every step is visible in
# asli.nsi, uninstaller included.
function Find-MakeNsis {
    $onPath = Get-Command 'makensis.exe' -ErrorAction SilentlyContinue
    if ($onPath) { return $onPath.Source }
    foreach ($base in @(${env:ProgramFiles(x86)}, $env:ProgramFiles, (Join-Path $env:LOCALAPPDATA 'Programs'))) {
        if (-not $base) { continue }
        $candidate = Join-Path $base 'NSIS\makensis.exe'
        if (Test-Path $candidate) { return $candidate }
    }
    return $null
}

# dumpbin ships with the C++ build tools that the build needs anyway.
function Find-Dumpbin {
    $vswhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe'
    if (-not (Test-Path $vswhere)) { return $null }
    $found = & $vswhere -latest -products * -find 'VC\Tools\MSVC\**\bin\Host*\*\dumpbin.exe' |
        Select-Object -First 1
    if ([string]::IsNullOrWhiteSpace($found)) { return $null }
    return $found
}

# The release profile links the C runtime statically (see .cargo\config.toml), because
# VCRUNTIME140.dll is not part of Windows and a fresh machine without it cannot start the program.
# Checked rather than assumed: a RUSTFLAGS variable in the environment silently replaces that
# setting, and the result would install fine and then fail to start on someone else's computer.
function Confirm-NoVcRuntime {
    param([string]$Dumpbin)
    foreach ($binary in @('asli.exe', 'asliw.exe')) {
        $path = Join-Path $Built $binary
        $imports = & $Dumpbin /nologo /dependents $path
        if ($LASTEXITCODE -ne 0) { Write-Fail "dumpbin could not read $path" }
        $runtime = @($imports | Where-Object { $_ -match '^\s*(vcruntime|msvcp)\d+.*\.dll\s*$' })
        if ($runtime.Count -gt 0) {
            Write-Warn "$binary imports $(($runtime | ForEach-Object { $_.Trim() }) -join ', ')."
            Write-Host '  It would not start on a machine without the Visual C++ redistributable.'
            Write-Host '  Is RUSTFLAGS set? It replaces the static runtime setting in .cargo\config.toml.'
            Write-Host '  Clear it, then run this again:'
            Write-Host '    Remove-Item Env:RUSTFLAGS'
            Write-Fail 'the executables depend on the Visual C++ runtime DLL'
        }
    }
    Write-Ok 'asli.exe and asliw.exe carry their own C runtime; no redistributable is needed'
}

# The same layout sha256sum writes and `sha256sum -c` reads: lowercase hash, two spaces, name,
# LF line endings, no byte order mark.
function Write-ChecksumFile {
    param([string]$Version)
    $lines = Get-ChildItem -Path $Dist -File -Filter "asli-$Version-*" | Sort-Object Name | ForEach-Object {
        "$((Get-FileHash -Algorithm SHA256 -Path $_.FullName).Hash.ToLowerInvariant())  $($_.Name)"
    }
    $text = ($lines -join "`n") + "`n"
    [System.IO.File]::WriteAllText((Join-Path $Dist 'SHA256SUMS'), $text, (New-Object System.Text.UTF8Encoding $false))
}

$Version = Get-AsliVersion
$Arch = Get-AsliArch
$Output = Join-Path $Dist "asli-$Version-windows-$Arch.exe"

Write-Host "Asli Windows installer, version $Version, $Arch" -ForegroundColor White
Write-Host ''
if ($DryRun) { Write-Info 'Dry run: nothing will be changed.' }

Write-Info 'Checking the packaging tools'
$MakeNsis = Find-MakeNsis
if (-not $MakeNsis) {
    Write-Warn 'NSIS is not installed, and it is what builds the installer.'
    Write-Host '  Install it, then run this again:'
    Write-Host '    winget install --id NSIS.NSIS -e'
    Write-Fail 'missing prerequisite: NSIS'
}
Write-Ok "NSIS found at $MakeNsis"

Write-Host ''
Write-Info 'Building, through setup.ps1 -BuildOnly'
$setupArgs = @{ BuildOnly = $true }
if ($DryRun) { $setupArgs.DryRun = $true }
& (Join-Path $RepoRoot 'setup.ps1') @setupArgs
if ($LASTEXITCODE -and $LASTEXITCODE -ne 0) { Write-Fail 'the build failed. The output above says why.' }
if (-not $DryRun) {
    foreach ($binary in @('asli.exe', 'asliw.exe')) {
        if (-not (Test-Path (Join-Path $Built $binary))) { Write-Fail "the build finished but $binary is not in $Built" }
    }
}

Write-Host ''
Write-Info 'Checking the executables'
$Dumpbin = Find-Dumpbin
if ($DryRun) {
    Write-Host '  would check the imports of asli.exe and asliw.exe with dumpbin'
} elseif (-not $Dumpbin) {
    Write-Warn 'dumpbin was not found beside the C++ build tools, so the C runtime cannot be checked.'
    Write-Host '  Open the Visual Studio Installer, click Modify, and make sure the'
    Write-Host '  "Desktop development with C++" workload is fully installed. Then run this again.'
    Write-Fail 'missing prerequisite: dumpbin'
} else {
    Confirm-NoVcRuntime -Dumpbin $Dumpbin
}

Write-Host ''
Write-Info 'Building the installer'
# The installer's own version resource needs four numbers; a pre-release suffix is dropped there
# and kept everywhere a person reads it.
$numeric = ($Version -split '[-+]')[0]
$viVersion = (@($numeric.Split('.')) + @('0', '0', '0', '0'))[0..3] -join '.'
$sizeKb = 0
if (-not $DryRun) {
    $sizeKb = [int][Math]::Ceiling(((Get-Item (Join-Path $Built 'asli.exe')).Length + (Get-Item (Join-Path $Built 'asliw.exe')).Length) / 1024)
}
$nsisArgs = @(
    '/V2', '/INPUTCHARSET', 'UTF8',
    "/DVERSION=$Version",
    "/DVIVERSION=$viVersion",
    "/DSIZE_KB=$sizeKb",
    "/DSRCDIR=$Built",
    "/DREPO=$RepoRoot",
    "/DOUTFILE=$Output",
    (Join-Path $Here 'asli.nsi')
)
if ($DryRun) {
    Write-Host "  would run: $MakeNsis $($nsisArgs -join ' ')"
} else {
    New-Item -ItemType Directory -Force -Path $Dist | Out-Null
    if (Test-Path $Output) { Remove-Item -Force $Output }
    & $MakeNsis @nsisArgs
    if ($LASTEXITCODE -ne 0 -or -not (Test-Path $Output)) {
        if (Test-Path $Output) { Remove-Item -Force $Output }
        Write-Fail 'makensis failed. The output above says why.'
    }
    Write-Ok $Output
}

Write-Host ''
Write-Info 'Checksums'
if ($DryRun) {
    Write-Host "  would write: $(Join-Path $Dist 'SHA256SUMS') over asli-$Version-*"
} else {
    Write-ChecksumFile -Version $Version
    Write-Ok (Join-Path $Dist 'SHA256SUMS')
}

Write-Host ''
Write-Host 'Done.' -ForegroundColor Green
if (-not $DryRun) {
    Write-Host ''
    Write-Host 'Produced:'
    Write-Host "  $Output"
    Write-Host "  $(Join-Path $Dist 'SHA256SUMS')"
    Write-Host ''
    Write-Host 'It is unsigned, so SmartScreen warns on first run. See packaging\windows\README.md.'
}
