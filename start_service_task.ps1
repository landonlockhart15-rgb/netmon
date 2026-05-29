$ErrorActionPreference = "Stop"

$port = if ($env:APP_PORT) { [int]$env:APP_PORT } else { 8000 }
$root = Split-Path -Parent $MyInvocation.MyCommand.Path

$listener = Get-NetTCPConnection -LocalPort $port -State Listen -ErrorAction SilentlyContinue
if ($listener) {
    exit 0
}

Set-Location -LiteralPath $root
& (Join-Path $root "start_service.bat")
exit $LASTEXITCODE
