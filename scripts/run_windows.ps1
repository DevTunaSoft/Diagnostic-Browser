# Run from an activated Python 3.11+ virtual environment on an authorized Windows IT workstation.
# Browser uses the locally installed Google Chrome channel; no GitHub or external telemetry is used.
$ErrorActionPreference = 'Stop'
$Root = Split-Path -Parent $PSScriptRoot
Set-Location $Root
& ".\.venv\Scripts\python.exe" -m diagnostic_browser.main --url 'about:blank'
