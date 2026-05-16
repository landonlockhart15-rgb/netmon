$shell    = New-Object -ComObject WScript.Shell
$shortcut = $shell.CreateShortcut("$env:USERPROFILE\Desktop\NetMon.lnk")
$root = Split-Path -Parent $PSCommandPath
$shortcut.TargetPath       = Join-Path $root "start.bat"
$shortcut.WorkingDirectory = $root
$shortcut.Description      = "NetMon - Network Monitor (LIVE)"
$shortcut.WindowStyle      = 1
$shortcut.Save()
Write-Host "Shortcut created on Desktop."
