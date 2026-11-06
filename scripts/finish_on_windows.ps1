# One-command authorized Windows engineering acceptance and executable build.
# This is a release GATE, not a workaround for Chrome enterprise policy.
$ErrorActionPreference='Stop'
$Root=Split-Path -Parent $PSScriptRoot
Set-Location $Root
& "$PSScriptRoot\setup_windows.ps1"
if ($LASTEXITCODE -ne 0) { throw 'Dependency installation failed' }
# Source-only Chrome smoke uses installed Chrome; the standalone path
# instead validates its own bundled Chromium after the EXE is built.
& "$PSScriptRoot\build_single_exe_windows.ps1"
if ($LASTEXITCODE -ne 0) { throw 'Windows executable build failed' }
& "$PSScriptRoot\validate_onefile_clean_windows.ps1" -Exe (Join-Path $Root 'dist\DiagnosticBrowser.exe')
if ($LASTEXITCODE -ne 0) { throw 'Packaged EXE acceptance failed' }
# Prove the packaged EXE performs real offline AI inference with its bundled
# model (not merely that the model file is present).
$Exe=Join-Path $Root 'dist\DiagnosticBrowser.exe'
$AiJson=(& $Exe --ai-selftest) | Select-Object -Last 1
if ($LASTEXITCODE -ne 0) { throw ('Offline AI inference self-test failed: '+$AiJson) }
$Ai=$AiJson | ConvertFrom-Json
if (-not $Ai.verified -or $Ai.status -ne 'LOCAL_UNVERIFIED' -or [int]$Ai.analysis_chars -le 0 -or -not $Ai.sanitized_ok -or -not $Ai.leak_free) {
    throw ('Offline AI inference self-test did not meet the contract: '+$AiJson)
}
Write-Host ('Offline AI inference verified on packaged EXE: '+$AiJson)
Write-Host 'Automated Windows checks passed. Do NOT declare final production approval until IT verifies Okta/target system, endpoint security, installer, and signing.'
