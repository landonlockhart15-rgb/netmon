# Copy release artifacts into the clean VM and run clean-install + upgrade tests.
[CmdletBinding()]
param(
    [string]$VmName = "NetMon-Win11-Clean",
    [Parameter(Mandatory)] [string]$CurrentInstaller,
    [Parameter(Mandatory)] [string]$PreviousInstaller,
    [Parameter(Mandatory)] [PSCredential]$GuestCredential,
    [switch]$RestoreCleanSnapshot
)

$ErrorActionPreference = "Stop"
$VBox = "C:\Program Files\Oracle\VirtualBox\VBoxManage.exe"
$Root = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
$SmokeScript = Join-Path $Root "tools\test_installer.ps1"
$CurrentInstaller = (Resolve-Path -LiteralPath $CurrentInstaller).Path
$PreviousInstaller = (Resolve-Path -LiteralPath $PreviousInstaller).Path
$VersionPython = Join-Path $Root ".venv\Scripts\python.exe"
$ExpectedVersion = (& $VersionPython -c "from app.version import __version__; print(__version__)" | Select-Object -Last 1).Trim()
$PasswordFile = Join-Path $env:TEMP "netmon-vm-$([guid]::NewGuid().ToString('N')).password"
$Bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($GuestCredential.Password)

try {
    $PlainPassword = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($Bstr)
    [IO.File]::WriteAllText($PasswordFile, $PlainPassword, [Text.Encoding]::UTF8)
    $PlainPassword = $null

    if ($RestoreCleanSnapshot) {
        $CurrentState = (& $VBox showvminfo $VmName --machinereadable | Select-String '^VMState=').ToString()
        if ($CurrentState -match 'running') {
            $PreviousErrorActionPreference = $ErrorActionPreference
            $ErrorActionPreference = "Continue"
            & $VBox controlvm $VmName poweroff 2>$null
            $PowerOffExitCode = $LASTEXITCODE
            $ErrorActionPreference = $PreviousErrorActionPreference
            if ($PowerOffExitCode -ne 0) {
                throw "Could not power off '$VmName' before restoring its clean snapshot."
            }
        }
        & $VBox snapshot $VmName restore clean-windows
        if ($LASTEXITCODE -ne 0) { throw "Could not restore '$VmName' to clean-windows." }
    }
    $State = (& $VBox showvminfo $VmName --machinereadable | Select-String '^VMState=').ToString()
    if ($State -notmatch 'running') {
        $StartDeadline = (Get-Date).AddSeconds(60)
        do {
            $PreviousErrorActionPreference = $ErrorActionPreference
            $ErrorActionPreference = "Continue"
            & $VBox startvm $VmName --type headless 2>$null
            $StartExitCode = $LASTEXITCODE
            $ErrorActionPreference = $PreviousErrorActionPreference
            if ($StartExitCode -eq 0) { break }
            Start-Sleep -Seconds 3
        } until ((Get-Date) -gt $StartDeadline)
        if ($StartExitCode -ne 0) { throw "Could not start '$VmName' after waiting for the snapshot session to unlock." }
    }

    $Auth = @("--username=$($GuestCredential.UserName)", "--passwordfile=$PasswordFile")
    $Deadline = (Get-Date).AddMinutes(5)
    do {
        Start-Sleep -Seconds 5
        $PreviousErrorActionPreference = $ErrorActionPreference
        $ErrorActionPreference = "Continue"
        & $VBox guestcontrol $VmName mkdir @Auth --parents "C:\NetMonTest" 2>$null
        $GuestControlExitCode = $LASTEXITCODE
        $ErrorActionPreference = $PreviousErrorActionPreference
    } until ($GuestControlExitCode -eq 0 -or (Get-Date) -gt $Deadline)
    if ($GuestControlExitCode -ne 0) { throw "Guest control did not become ready within five minutes." }

    & $VBox guestcontrol $VmName copyto @Auth --target-directory="C:\NetMonTest" $SmokeScript $CurrentInstaller $PreviousInstaller
    if ($LASTEXITCODE -ne 0) { throw "Could not copy smoke-test artifacts into the VM." }

    $CurrentName = [IO.Path]::GetFileName($CurrentInstaller)
    $PreviousName = [IO.Path]::GetFileName($PreviousInstaller)
    & $VBox guestcontrol $VmName run @Auth --exe="C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" --wait-stdout --wait-stderr --timeout=900000 -- -NoProfile -ExecutionPolicy Bypass -File "C:\NetMonTest\test_installer.ps1" -InstallerPath "C:\NetMonTest\$CurrentName" -PreviousInstallerPath "C:\NetMonTest\$PreviousName" -ExpectedVersion $ExpectedVersion -ConfirmDisposableVm
    if ($LASTEXITCODE -ne 0) { throw "VM installer smoke test failed (exit $LASTEXITCODE)." }
}
finally {
    if ($Bstr -ne [IntPtr]::Zero) { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($Bstr) }
    if (Test-Path $PasswordFile) { Remove-Item -LiteralPath $PasswordFile -Force }
}

Write-Host "Clean install and upgrade smoke tests passed in '$VmName'." -ForegroundColor Green
