# Enforce a visible, non-regressing ESLint baseline while legacy debt is paid down.
[CmdletBinding()]
param(
    [string]$ReportPath,
    [switch]$UpdateBaseline
)

$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent (Split-Path -Parent $PSCommandPath)
$Frontend = Join-Path $Root "frontend"
$BaselinePath = Join-Path $Frontend "lint-baseline.json"
if (-not $ReportPath) { $ReportPath = Join-Path $env:TEMP "netmon-eslint.json" }

Push-Location $Frontend
try {
    & npm.cmd exec eslint . -- --format json --output-file $ReportPath
    $EslintExit = $LASTEXITCODE
}
finally {
    Pop-Location
}

if (-not (Test-Path $ReportPath)) { throw "ESLint did not produce $ReportPath (exit $EslintExit)." }
$Results = Get-Content -LiteralPath $ReportPath -Raw | ConvertFrom-Json
$Errors = [int](($Results | Measure-Object -Property errorCount -Sum).Sum)
$Warnings = [int](($Results | Measure-Object -Property warningCount -Sum).Sum)

if ($UpdateBaseline) {
    $NewBaseline = [ordered]@{
        errors = $Errors
        warnings = $Warnings
        note = "Known legacy lint debt. CI fails if either count increases and publishes the complete ESLint JSON report."
    }
    $NewBaseline | ConvertTo-Json | Set-Content -LiteralPath $BaselinePath -Encoding utf8
    Write-Host "Updated lint baseline: $Errors errors, $Warnings warnings." -ForegroundColor Yellow
    exit 0
}

$Baseline = Get-Content -LiteralPath $BaselinePath -Raw | ConvertFrom-Json
Write-Host "ESLint found $Errors errors and $Warnings warnings (baseline: $($Baseline.errors) errors, $($Baseline.warnings) warnings)."
Write-Host "Full machine-readable report: $ReportPath"

if ($Errors -gt [int]$Baseline.errors -or $Warnings -gt [int]$Baseline.warnings) {
    Write-Error "Frontend lint debt regressed. Fix new findings or intentionally update the reviewed baseline."
    exit 1
}
if ($Errors -gt 0 -or $Warnings -gt 0) {
    Write-Warning "Known frontend lint debt remains visible: $Errors errors, $Warnings warnings."
}
if ($Errors -lt [int]$Baseline.errors -or $Warnings -lt [int]$Baseline.warnings) {
    Write-Warning "Lint improved. Lower frontend/lint-baseline.json in the same change so debt cannot return."
}
exit 0
