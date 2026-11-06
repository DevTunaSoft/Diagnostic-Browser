# Requires Windows PowerShell and Python 3.11+ already installed.
# Dependency installation uses PyPI if packages are not cached; NO runtime data is uploaded.
$ErrorActionPreference = 'Stop'
$Root = Split-Path -Parent $PSScriptRoot
Set-Location $Root
python -m venv .venv
& '.\.venv\Scripts\python.exe' -m pip install --upgrade pip
& '.\.venv\Scripts\python.exe' -m pip install -e '.[test]'
Write-Host 'Installed local development preview. Use .venv\Scripts\python.exe -m diagnostic_browser.main'
