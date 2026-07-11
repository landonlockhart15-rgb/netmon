# build_installer.ps1 - reproducible NetMon release build.
#
#   powershell -ExecutionPolicy Bypass -File .\tools\build_installer.ps1
#
# The release version comes only from app/version.py. This script passes that
# value to Inno Setup, builds the React assets before freezing, validates the
# repository by default, and writes a SHA-256 sidecar for the installer.

[CmdletBinding()]
param(
    [switch]$SkipValidation,
    [switch]$SkipFrontend,
    [switch]$SkipInstaller,
    [switch]$SmokeTest,
    [switch]$ConfirmDisposableVm,
    [string]$PreviousInstallerPath
)

$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent (Split-Path -Parent $PSCommandPath)
Set-Location $Root

function Invoke-Checked {
    param([string]$Label, [scriptblock]$Command)
    Write-Host ""
    Write-Host "==> $Label" -ForegroundColor Cyan
    & $Command
    if ($LASTEXITCODE -ne 0) { throw "$Label failed (exit code $LASTEXITCODE)." }
}

$Python = Join-Path $Root ".venv\Scripts\python.exe"
if (-not (Test-Path $Python)) {
    throw "venv python not found at $Python - run tools\setup.ps1 first."
}

$Version = (& $Python -c "from app.version import __version__; print(__version__)" | Select-Object -Last 1).Trim()
if ($LASTEXITCODE -ne 0 -or $Version -notmatch '^\d+\.\d+\.\d+$') {
    throw "app.version.__version__ did not produce a valid x.y.z release version."
}
Write-Host "Building NetMon v$Version" -ForegroundColor Green

if ($env:GITHUB_REF_TYPE -eq "tag") {
    $ExpectedTag = "v$Version"
    if ($env:GITHUB_REF_NAME -ne $ExpectedTag) {
        throw "Git tag '$($env:GITHUB_REF_NAME)' does not match application version '$ExpectedTag'."
    }
}

if (-not $SkipFrontend -or -not $SkipValidation) {
    Push-Location (Join-Path $Root "frontend")
    try {
        Invoke-Checked "Installing locked frontend dependencies" { & npm.cmd ci --no-audit --no-fund }
    }
    finally {
        Pop-Location
    }
}

if (-not $SkipValidation) {
    Invoke-Checked "Backend validation" {
        & powershell.exe -NoProfile -ExecutionPolicy Bypass -File (Join-Path $Root "validate.ps1")
    }
    Invoke-Checked "Frontend lint baseline" {
        & powershell.exe -NoProfile -ExecutionPolicy Bypass -File (Join-Path $Root "tools\check_frontend_lint.ps1")
    }
}

if (-not $SkipFrontend) {
    Push-Location (Join-Path $Root "frontend")
    try {
        Invoke-Checked "Building production frontend" { & npm.cmd run build }
    }
    finally {
        Pop-Location
    }
}

Invoke-Checked "Freezing app with PyInstaller" {
    & $Python -m PyInstaller NetMon.spec --noconfirm --clean
}
$FrozenExe = Join-Path $Root "dist\NetMon\NetMon.exe"
if (-not (Test-Path $FrozenExe)) { throw "Expected $FrozenExe was not produced." }

if ($SkipInstaller) {
    Write-Host "Frozen application ready: $FrozenExe" -ForegroundColor Green
    exit 0
}

$isccCandidates = @(
    "C:\Program Files (x86)\Inno Setup 6\ISCC.exe",
    "C:\Program Files\Inno Setup 6\ISCC.exe",
    "$env:LOCALAPPDATA\Programs\Inno Setup 6\ISCC.exe"
)
$ISCC = $isccCandidates | Where-Object { Test-Path $_ } | Select-Object -First 1
if (-not $ISCC) {
    throw "ISCC.exe not found. Install Inno Setup 6: winget install JRSoftware.InnoSetup"
}

Invoke-Checked "Building v$Version installer with Inno Setup" {
    & $ISCC "/DAppVersion=$Version" (Join-Path $Root "installer\netmon.iss")
}

$Installer = Join-Path $Root "installer\Output\NetMon-Setup-$Version.exe"
if (-not (Test-Path $Installer)) { throw "Expected installer was not produced at $Installer." }
$Hash = (Get-FileHash -Algorithm SHA256 -LiteralPath $Installer).Hash.ToLowerInvariant()
$HashFile = "$Installer.sha256"
Set-Content -LiteralPath $HashFile -Value "$Hash  $([IO.Path]::GetFileName($Installer))" -Encoding ascii

if ($SmokeTest) {
    $SmokeArgs = @(
        "-NoProfile", "-ExecutionPolicy", "Bypass",
        "-File", (Join-Path $Root "tools\test_installer.ps1"),
        "-InstallerPath", $Installer,
        "-ExpectedVersion", $Version
    )
    if ($ConfirmDisposableVm) { $SmokeArgs += "-ConfirmDisposableVm" }
    if ($PreviousInstallerPath) { $SmokeArgs += @("-PreviousInstallerPath", $PreviousInstallerPath) }
    Invoke-Checked "Disposable-VM installer smoke test" { & powershell.exe @SmokeArgs }
}

Write-Host ""
Write-Host "Installer: $Installer" -ForegroundColor Green
Write-Host "SHA-256:  $Hash" -ForegroundColor Green
Write-Host "Sidecar:  $HashFile" -ForegroundColor Green
