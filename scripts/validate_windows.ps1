# Windows on-device validation. No Github, no remote data upload, no policy bypass.
$ErrorActionPreference = 'Stop'
$Root = Split-Path -Parent $PSScriptRoot
Set-Location $Root
$Python = '.\.venv\Scripts\python.exe'
if (-not (Test-Path $Python)) { throw 'Run setup_windows.ps1 to install test dependencies first' }
& $Python scripts\verify_sqlcipher_runtime.py
if ($LASTEXITCODE -ne 0) { throw 'SQLCipher whole-database encryption or reopen validation failed' }
& $Python -m compileall -q diagnostic_browser tests
if ($LASTEXITCODE -ne 0) { throw 'Source compilation failed' }
& $Python -m pytest -q tests
if ($LASTEXITCODE -ne 0) { throw 'Local automated tests failed' }
& $Python scripts\chrome_smoke.py
if ($LASTEXITCODE -ne 0) { throw 'Actual sandboxed Chrome/CDP smoke test failed' }
& $Python scripts\windows_real_browser_lab.py --output validation\windows_real_browser_lab_result.json
if ($LASTEXITCODE -ne 0) { throw 'Real Chrome + encrypted recorder + synthetic defect + export acceptance failed' }
Write-Host 'Local checks passed. Okta, target system and enterprise security acceptance still require approved manual validation.'
