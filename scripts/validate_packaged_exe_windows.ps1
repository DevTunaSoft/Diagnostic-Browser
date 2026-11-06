# Compatibility entrypoint for the strict onefile Windows acceptance check.
$ErrorActionPreference='Stop'
$Root=Split-Path -Parent $PSScriptRoot
& (Join-Path $PSScriptRoot 'validate_onefile_clean_windows.ps1') -Exe (Join-Path $Root 'dist\DiagnosticBrowser.exe')
if ($LASTEXITCODE -ne 0) { throw 'Onefile acceptance failed' }
