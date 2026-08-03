# Self-elevate if not already admin
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Start-Process powershell -ArgumentList "-ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs
    exit
}

$root      = Split-Path -Parent $PSCommandPath
$start     = Join-Path $root "start_service.bat"
$watchdog  = Join-Path $root "service_watchdog.ps1"
$action    = New-ScheduledTaskAction -Execute $start -WorkingDirectory $root
$trigger   = New-ScheduledTaskTrigger -AtStartup
$principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -RunLevel Highest
$settings  = New-ScheduledTaskSettingsSet -ExecutionTimeLimit 0 -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1)
Register-ScheduledTask -TaskName "NetMon Server" -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Force

$watchdogAction = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-NoProfile -NonInteractive -ExecutionPolicy Bypass -File `"$watchdog`"" -WorkingDirectory $root
$watchdogTrigger = New-ScheduledTaskTrigger -Once -At (Get-Date) -RepetitionInterval (New-TimeSpan -Minutes 5) -RepetitionDuration (New-TimeSpan -Days 3650)
$watchdogSettings = New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Minutes 1) -MultipleInstances IgnoreNew
Register-ScheduledTask -TaskName "NetMon Service Watchdog" -Action $watchdogAction -Trigger $watchdogTrigger -Principal $principal -Settings $watchdogSettings -Force
Write-Host "Done. NetMon will auto-start on next boot and its health will be checked every five minutes."
Read-Host "Press Enter to close"
