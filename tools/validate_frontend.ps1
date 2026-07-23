param(
    [switch]$SkipInstall
)

$ErrorActionPreference = "Stop"
$repoRoot = Split-Path -Parent $PSScriptRoot
$frontendRoot = Join-Path $repoRoot "frontend"

Push-Location $repoRoot
try {
    if (-not $SkipInstall) {
        & npm --prefix $frontendRoot ci --no-audit --no-fund
        if ($LASTEXITCODE -ne 0) {
            throw "Frontend dependency installation failed with exit code $LASTEXITCODE."
        }
    }

    & (Join-Path $PSScriptRoot "check_frontend_lint.ps1")
    if ($LASTEXITCODE -ne 0) {
        throw "Frontend lint failed with exit code $LASTEXITCODE."
    }

    & npm --prefix $frontendRoot run build
    if ($LASTEXITCODE -ne 0) {
        throw "Frontend build failed with exit code $LASTEXITCODE."
    }

    & git diff --exit-code -- static
    if ($LASTEXITCODE -ne 0) {
        throw "Committed production assets are stale. Rebuild and commit static/."
    }

    Write-Host "Frontend lint, build, and committed-asset checks passed."
}
finally {
    Pop-Location
}
