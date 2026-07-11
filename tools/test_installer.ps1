# Destructive clean-install and upgrade smoke test for a disposable Windows VM.
[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string]$InstallerPath,
    [string]$ExpectedVersion,
    [string]$PreviousInstallerPath,
    [switch]$ConfirmDisposableVm,
    [switch]$PreserveInstalledState,
    [int]$StartupTimeoutSeconds = 90
)

$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent (Split-Path -Parent $PSCommandPath)
if (-not $ExpectedVersion) {
    $Python = Join-Path $Root ".venv\Scripts\python.exe"
    if (-not (Test-Path $Python)) { $Python = "python.exe" }
    $ExpectedVersion = (& $Python -c "from app.version import __version__; print(__version__)" | Select-Object -Last 1).Trim()
}
$InstallerPath = (Resolve-Path -LiteralPath $InstallerPath).Path
if ($PreviousInstallerPath) { $PreviousInstallerPath = (Resolve-Path -LiteralPath $PreviousInstallerPath).Path }

if (-not $ConfirmDisposableVm -and $env:NETMON_VM_LAB -ne "1") {
    throw "Refusing to install/uninstall software on an unconfirmed host. Run only inside a disposable VM with -ConfirmDisposableVm."
}
$IsAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator
)
if (-not $IsAdmin) { throw "Installer smoke testing requires an elevated PowerShell inside the VM." }

$DataHome = Join-Path $env:LOCALAPPDATA "NetMon"
$Marker = Join-Path $DataHome "upgrade-smoke-marker.txt"
$LogDir = Join-Path $env:TEMP "NetMonInstallerSmoke"
New-Item -ItemType Directory -Force -Path $LogDir | Out-Null

function Get-NetMonInstall {
    $Roots = @(
        "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*",
        "HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
    )
    Get-ItemProperty $Roots -ErrorAction SilentlyContinue |
        Where-Object { $_.DisplayName -eq "NetMon" } |
        Select-Object -First 1
}

function Install-NetMon([string]$Path, [string]$Label) {
    $Log = Join-Path $LogDir "$Label-install.log"
    $Process = Start-Process -FilePath $Path -ArgumentList @(
        "/VERYSILENT", "/SUPPRESSMSGBOXES", "/NORESTART", "/SP-", "/LOG=$Log"
    ) -Wait -PassThru
    if ($Process.ExitCode -ne 0) { throw "$Label installer exited $($Process.ExitCode). See $Log" }
}

function Assert-InstalledVersion([string]$Version) {
    $Install = Get-NetMonInstall
    if (-not $Install) { throw "NetMon uninstall registration was not found." }
    if ($Install.DisplayVersion -ne $Version) {
        throw "Installed version '$($Install.DisplayVersion)' does not match '$Version'."
    }
    $Exe = Join-Path $Install.InstallLocation "NetMon.exe"
    if (-not (Test-Path $Exe)) { throw "Installed executable not found at $Exe" }
    return @{ Registration = $Install; Exe = $Exe }
}

function Test-FrozenStartup([string]$Exe, [string]$Label) {
    $Port = Get-Random -Minimum 18000 -Maximum 24000
    $OldSelfTest = $env:NETMON_SELFTEST
    $OldPort = $env:APP_PORT
    $env:NETMON_SELFTEST = "1"
    $env:APP_PORT = "$Port"
    $Process = $null
    try {
        $Process = Start-Process -FilePath $Exe -PassThru
        $Deadline = (Get-Date).AddSeconds($StartupTimeoutSeconds)
        $Ready = $false
        while ((Get-Date) -lt $Deadline -and -not $Process.HasExited) {
            try {
                $Request = [Net.HttpWebRequest]::Create("http://127.0.0.1:$Port/login")
                $Request.AllowAutoRedirect = $false
                $Request.Timeout = 2000
                $Response = $Request.GetResponse()
                $Ready = [int]$Response.StatusCode -eq 200
                $Response.Dispose()
                if ($Ready) { break }
            }
            catch { Start-Sleep -Milliseconds 500 }
        }
        if (-not $Ready) {
            $Log = Join-Path $DataHome "logs\netmon.log"
            throw "$Label did not serve /login within $StartupTimeoutSeconds seconds. Runtime log: $Log"
        }
        $CredentialNote = Join-Path $DataHome "FIRST-RUN-LOGIN.txt"
        if (-not (Test-Path $CredentialNote)) { throw "$Label did not create its first-run login note." }
        Write-Host "[PASS] $Label starts and serves the login page." -ForegroundColor Green
    }
    finally {
        if ($Process -and -not $Process.HasExited) { Stop-Process -Id $Process.Id -Force -ErrorAction SilentlyContinue }
        $env:NETMON_SELFTEST = $OldSelfTest
        $env:APP_PORT = $OldPort
    }
}

function Uninstall-NetMon {
    $Install = Get-NetMonInstall
    if (-not $Install) { return }
    $Uninstall = $Install.QuietUninstallString
    if (-not $Uninstall) { $Uninstall = $Install.UninstallString }
    if ($Uninstall -notmatch '^"?([^"\s]+(?:\s[^"\s]+)*)"?') { throw "Could not parse uninstall command." }
    $Uninstaller = $Matches[1].Trim('"')
    $Process = Start-Process -FilePath $Uninstaller -ArgumentList @(
        "/VERYSILENT", "/SUPPRESSMSGBOXES", "/NORESTART"
    ) -Wait -PassThru
    if ($Process.ExitCode -ne 0) { throw "Uninstaller exited $($Process.ExitCode)." }
}

function Reset-NetMonData {
    if (-not (Test-Path $DataHome)) { return }
    $ResolvedData = (Resolve-Path -LiteralPath $DataHome).Path
    $ResolvedLocal = (Resolve-Path -LiteralPath $env:LOCALAPPDATA).Path
    if (-not $ResolvedData.StartsWith($ResolvedLocal, [StringComparison]::OrdinalIgnoreCase)) {
        throw "Refusing to remove unexpected data path: $ResolvedData"
    }
    Remove-Item -LiteralPath $ResolvedData -Recurse -Force
}

try {
    if (Get-NetMonInstall) { throw "NetMon is already installed. Start from a clean disposable VM snapshot." }
    if (Test-Path $DataHome) { throw "$DataHome already exists. Start from a clean disposable VM snapshot." }

    Write-Host "Testing clean installation of NetMon $ExpectedVersion..." -ForegroundColor Cyan
    Install-NetMon $InstallerPath "clean-$ExpectedVersion"
    $Current = Assert-InstalledVersion $ExpectedVersion
    Test-FrozenStartup $Current.Exe "NetMon $ExpectedVersion clean install"
    Uninstall-NetMon
    Reset-NetMonData
    Write-Host "[PASS] Clean install/uninstall." -ForegroundColor Green

    if ($PreviousInstallerPath) {
        $PreviousVersion = [IO.Path]::GetFileName($PreviousInstallerPath) -replace '^NetMon-Setup-', '' -replace '\.exe$', ''
        Write-Host "Testing upgrade $PreviousVersion -> $ExpectedVersion..." -ForegroundColor Cyan
        Install-NetMon $PreviousInstallerPath "upgrade-$PreviousVersion"
        $Previous = Assert-InstalledVersion $PreviousVersion
        Test-FrozenStartup $Previous.Exe "NetMon $PreviousVersion before upgrade"
        New-Item -ItemType Directory -Force -Path $DataHome | Out-Null
        Set-Content -LiteralPath $Marker -Value "preserve-me" -Encoding ascii

        Install-NetMon $InstallerPath "upgrade-$ExpectedVersion"
        $Current = Assert-InstalledVersion $ExpectedVersion
        if ((Get-Content -LiteralPath $Marker -Raw).Trim() -ne "preserve-me") {
            throw "Upgrade did not preserve the user-data marker."
        }
        Test-FrozenStartup $Current.Exe "NetMon $ExpectedVersion after upgrade"
        Write-Host "[PASS] Upgrade preserved user data and starts successfully." -ForegroundColor Green
    }
}
finally {
    if (-not $PreserveInstalledState) {
        Uninstall-NetMon
        Reset-NetMonData
    }
}

Write-Host "Installer smoke test complete. Logs: $LogDir" -ForegroundColor Green
