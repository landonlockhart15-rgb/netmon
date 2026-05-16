# Creates a desktop shortcut for NetMon that always launches as Administrator.
# Run once: right-click → Run with PowerShell

$desktop  = [Environment]::GetFolderPath("Desktop")
$shortcut = "$desktop\NetMon.lnk"
$root     = Split-Path -Parent (Split-Path -Parent $PSCommandPath)
$target   = Join-Path $root "start.bat"

$shell = New-Object -ComObject WScript.Shell
$lnk   = $shell.CreateShortcut($shortcut)
$lnk.TargetPath       = $target
$lnk.WorkingDirectory = $root
$lnk.Description      = "NetMon Network Monitor (Admin)"
$lnk.IconLocation     = "shell32.dll,48"   # network icon
$lnk.Save()

# Set "Run as administrator" flag on the shortcut
$bytes = [System.IO.File]::ReadAllBytes($shortcut)
$bytes[0x15] = $bytes[0x15] -bor 0x20   # byte 21, bit 5 = RunAsAdmin
[System.IO.File]::WriteAllBytes($shortcut, $bytes)

Write-Host "Shortcut created: $shortcut"
Write-Host "Double-click NetMon on your desktop to start (UAC prompt appears once)."
