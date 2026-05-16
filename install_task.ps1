# Self-elevate if not already admin
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Start-Process powershell -ArgumentList "-ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs
    exit
}

$root      = Split-Path -Parent $PSCommandPath
$start     = Join-Path $root "start_service.bat"
$action    = New-ScheduledTaskAction -Execute $start -WorkingDirectory $root
$trigger   = New-ScheduledTaskTrigger -AtStartup
$principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -RunLevel Highest
$settings  = New-ScheduledTaskSettingsSet -ExecutionTimeLimit 0 -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1)
Register-ScheduledTask -TaskName "NetMon Server" -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Force
Write-Host "Done. NetMon will auto-start on next boot."
Read-Host "Press Enter to close"
