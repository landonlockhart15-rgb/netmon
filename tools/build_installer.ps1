# build_installer.ps1 — build NetMon's frozen exe and double-click installer.
#
#   powershell -ExecutionPolicy Bypass -File .\tools\build_installer.ps1
#
# Steps:
#   1. PyInstaller freezes the app          -> dist\NetMon\NetMon.exe
#   2. Inno Setup packages it into a setup  -> installer\Output\NetMon-Setup-*.exe
#
# Requirements: the project's .venv with pyinstaller installed, and Inno Setup 6
# (install via: winget install JRSoftware.InnoSetup).

$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent (Split-Path -Parent $PSCommandPath)
Set-Location $Root

$Python = Join-Path $Root ".venv\Scripts\python.exe"
if (-not (Test-Path $Python)) { throw "venv python not found at $Python — run tools\setup.ps1 first." }

Write-Host "==> [1/2] Freezing app with PyInstaller (production: admin manifest, windowed)..."
& $Python -m PyInstaller NetMon.spec --noconfirm --clean
if ($LASTEXITCODE -ne 0) { throw "PyInstaller build failed ($LASTEXITCODE)." }
if (-not (Test-Path (Join-Path $Root "dist\NetMon\NetMon.exe"))) { throw "Expected dist\NetMon\NetMon.exe was not produced." }

# Locate ISCC.exe (winget may install it per-user or per-machine).
$isccCandidates = @(
    "C:\Program Files (x86)\Inno Setup 6\ISCC.exe",
    "C:\Program Files\Inno Setup 6\ISCC.exe",
    "$env:LOCALAPPDATA\Programs\Inno Setup 6\ISCC.exe"
)
$ISCC = $isccCandidates | Where-Object { Test-Path $_ } | Select-Object -First 1
if (-not $ISCC) { throw "ISCC.exe not found. Install Inno Setup 6: winget install JRSoftware.InnoSetup" }

Write-Host "==> [2/2] Building installer with Inno Setup ($ISCC)..."
& $ISCC (Join-Path $Root "installer\netmon.iss")
if ($LASTEXITCODE -ne 0) { throw "Inno Setup build failed ($LASTEXITCODE)." }

$out = Get-ChildItem (Join-Path $Root "installer\Output") -Filter "NetMon-Setup-*.exe" | Sort-Object LastWriteTime -Descending | Select-Object -First 1
Write-Host ""
Write-Host "Done. Installer: $($out.FullName)" -ForegroundColor Green
