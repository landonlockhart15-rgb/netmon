# validate.ps1 — Standardized validation and test entrypoint for NetMon.
#
# Run from PowerShell:
#   powershell -ExecutionPolicy Bypass -File .\validate.ps1
#
# Options:
#   -IncludeSecurity    Run WSL/Kali security lab integration tests (requires WSL and Kali installed)

param(
    [switch]$IncludeSecurity
)

$ErrorActionPreference = "Stop"

$Root = Split-Path -Parent $MyInvocation.MyCommand.Path
if (-not $Root) { $Root = Get-Location }
Set-Location $Root

# 1. Detect Python
$script:UsePyLauncher = $false
$script:PythonExe = $null

$VenvPython = Join-Path $Root ".venv\Scripts\python.exe"
if (Test-Path $VenvPython) {
    $script:PythonExe = $VenvPython
    Write-Host "Using virtual environment Python: $script:PythonExe" -ForegroundColor Yellow
} elseif (Get-Command py.exe -ErrorAction SilentlyContinue) {
    $script:UsePyLauncher = $true
    Write-Host "Using Python launcher: py -3" -ForegroundColor Yellow
} elseif (Get-Command python.exe -ErrorAction SilentlyContinue) {
    $script:PythonExe = "python.exe"
    Write-Host "Using system Python: $script:PythonExe" -ForegroundColor Yellow
} else {
    Write-Error "Python was not found. Please install Python or run tools\setup.ps1 first."
    Exit 1
}

# Helper function to execute Python with appropriate executable/parameters
function Invoke-Python {
    param(
        [string]$Arguments
    )
    if ($script:UsePyLauncher) {
        Invoke-Expression "py -3 -u $Arguments"
    } else {
        Invoke-Expression "& `"$script:PythonExe`" -u $Arguments"
    }
}

# Helper function to run commands and check exit codes
function Invoke-Checked {
    param(
        [string]$Label,
        [string]$Arguments
    )
    Write-Host ""
    Write-Host "============================================================" -ForegroundColor Cyan
    Write-Host " RUNNING: $Label" -ForegroundColor Cyan
    Write-Host "============================================================" -ForegroundColor Cyan
    
    Invoke-Python $Arguments | Out-Host
    
    if ($LASTEXITCODE -ne 0) {
        Write-Host ""
        Write-Host "[-] $Label FAILED with exit code $LASTEXITCODE" -ForegroundColor Red
        return $false
    }
    Write-Host "[+] $Label PASSED" -ForegroundColor Green
    return $true
}

# 2. Ensure data directory and database schema are initialized
Write-Host "Initializing testing environment..." -ForegroundColor Yellow
Invoke-Python "-c `"import os; os.makedirs('data', exist_ok=True)`""
Invoke-Python "-c `"import sys, os; sys.path.insert(0, os.getcwd()); import models.tables; from app.database import Base, engine, run_migrations, seed_default_settings; Base.metadata.create_all(bind=engine); run_migrations(); seed_default_settings()`""
if ($LASTEXITCODE -ne 0) {
    Write-Error "Failed to initialize test database."
    Exit 1
}

$FailedTests = 0

# 3. Run unit tests
$UnitPassed = Invoke-Checked "Unit Tests (unittest)" "-m unittest discover -s tests -v"
if (-not $UnitPassed) { $FailedTests++ }

# 4. Run autoheal/uptime guardian tests
$AutohealPassed = Invoke-Checked "Autoheal Uptime Guardian Tests" "tools/test_autoheal.py"
if (-not $AutohealPassed) { $FailedTests++ }

# 5. Run security lab integration tests (optional)
if ($IncludeSecurity) {
    $SecurityPassed = Invoke-Checked "WSL Security Lab Integration Tests" "security_test.py"
    if (-not $SecurityPassed) { $FailedTests++ }
} else {
    Write-Host ""
    Write-Host "Skipping WSL Security Lab Integration Tests (use -IncludeSecurity switch to run them)." -ForegroundColor Yellow
}

Write-Host ""
Write-Host "============================================================" -ForegroundColor Cyan
if ($FailedTests -eq 0) {
    Write-Host " SUCCESS: All validation suites passed!" -ForegroundColor Green
    Write-Host "============================================================" -ForegroundColor Cyan
    Exit 0
} else {
    Write-Host " FAILURE: $FailedTests validation suite(s) failed." -ForegroundColor Red
    Write-Host "============================================================" -ForegroundColor Cyan
    Exit 1
}
