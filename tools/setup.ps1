# NetMon first-run setup for Windows.
# Run from PowerShell:
#   powershell -ExecutionPolicy Bypass -File .\tools\setup.ps1

$ErrorActionPreference = "Stop"

$Root = Split-Path -Parent (Split-Path -Parent $PSCommandPath)
Set-Location $Root

function Invoke-Checked {
    param(
        [string]$Label,
        [scriptblock]$Command
    )
    Write-Host ""
    Write-Host "==> $Label"
    & $Command
    if ($LASTEXITCODE -ne 0) {
        throw "$Label failed with exit code $LASTEXITCODE"
    }
}

function Invoke-BasePython {
    param([string[]]$Args)
    if ($script:UsePyLauncher) {
        & py -3 @Args
    } else {
        & $script:PythonExe @Args
    }
}

$script:UsePyLauncher = $false
$script:PythonExe = $null

if (Get-Command py.exe -ErrorAction SilentlyContinue) {
    $script:UsePyLauncher = $true
} elseif (Get-Command python.exe -ErrorAction SilentlyContinue) {
    $script:PythonExe = "python.exe"
} else {
    throw "Python 3.10+ was not found. Install Python, then run this script again."
}

Invoke-Checked "Create virtual environment" {
    Invoke-BasePython @("-m", "venv", ".venv")
}

$VenvPython = Join-Path $Root ".venv\Scripts\python.exe"
if (-not (Test-Path $VenvPython)) {
    throw "Virtual environment Python was not created at $VenvPython"
}

Invoke-Checked "Upgrade pip" {
    & $VenvPython -m pip install --upgrade pip
}

Invoke-Checked "Install Python dependencies" {
    & $VenvPython -m pip install -r requirements.txt
}

$EnvFile = Join-Path $Root ".env"
$Example = Join-Path $Root ".env.example"
if (-not (Test-Path $EnvFile)) {
    Copy-Item $Example $EnvFile
    Write-Host "Created .env from .env.example"
} else {
    Write-Host ".env already exists; leaving your settings in place"
}

Invoke-Checked "Set dashboard password" {
    & $VenvPython (Join-Path $Root "tools\set_password.py") --write --env-file $EnvFile
}

Invoke-Checked "Create desktop shortcut" {
    powershell -NoProfile -ExecutionPolicy Bypass -File (Join-Path $Root "tools\create_shortcut.ps1")
}

Write-Host ""
Write-Host "Setup complete."
Write-Host "Start NetMon with .\start.bat or the NetMon desktop shortcut."
Write-Host ""

if (-not (Get-Command nmap.exe -ErrorAction SilentlyContinue)) {
    Write-Host "Next: install nmap and add it to PATH: https://nmap.org/download.html"
}
if (-not (Get-Command ollama.exe -ErrorAction SilentlyContinue)) {
    Write-Host "Optional local AI: install Ollama, then run: ollama pull qwen2.5:3b"
}
