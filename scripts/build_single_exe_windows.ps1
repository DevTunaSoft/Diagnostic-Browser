# Build on Windows x64 with Python 3.11 (build tools are NOT required by users).
# The output directory contains exactly one distributable EXE plus integrity text.
# An unsigned or untested build MUST NOT be named a certified production release.
$ErrorActionPreference = 'Stop'
$Root = Split-Path -Parent $PSScriptRoot
Set-Location $Root
$Python = Join-Path $Root '.venv\Scripts\python.exe'
if (-not (Test-Path $Python)) { throw 'Windows build environment missing; run setup_windows.ps1' }
if (-not [Environment]::Is64BitOperatingSystem) { throw 'Windows x64 required' }

# Build-time-only network access. The final EXE never installs or downloads.
& $Python -m pip install --only-binary=:all: 'llama-cpp-python' --extra-index-url 'https://abetlen.github.io/llama-cpp-python/whl/cpu'
if ($LASTEXITCODE -ne 0) { throw 'CPU native AI wheel unavailable; no incomplete EXE will be built' }
& $Python -m pip install 'pyinstaller>=6.22.1,<7'
if ($LASTEXITCODE -ne 0) { throw 'PyInstaller not installed' }
$env:PLAYWRIGHT_BROWSERS_PATH = '0'
& $Python -m playwright install chromium
if ($LASTEXITCODE -ne 0) { throw 'Bundled Chromium download failed' }
$PackagePath = (& $Python -c 'from playwright._impl._driver import compute_driver_executable;from pathlib import Path;print(Path(compute_driver_executable()[0]).parent / "package" / ".local-browsers")').Trim()
if (-not (Test-Path $PackagePath)) { throw 'Bundled Chromium directory missing' }
if (-not (Get-ChildItem $PackagePath -Directory | Where-Object { $_.Name -like 'chromium-*' })) {
    throw 'Visible Chromium required. Headless shell only is not acceptable'
}

$ModelDir = Join-Path $Root 'models'
$ModelPath = Join-Path $ModelDir 'SmolLM2-135M-Instruct-Q4_K_M.gguf'
$ModelSha = '8030f04528538d47bda434f6f0bdf3952c40a58123e4d5e755332f23731a8684'
New-Item -ItemType Directory $ModelDir -Force | Out-Null
if (-not (Test-Path $ModelPath)) {
    $Source = 'https://huggingface.co/QuantFactory/SmolLM2-135M-Instruct-GGUF/resolve/main/SmolLM2-135M-Instruct.Q4_K_M.gguf'
    $TempModel = Join-Path $ModelDir 'download.incomplete'
    try {
        Invoke-WebRequest -Uri $Source -OutFile $TempModel -MaximumRedirection 5
        if ((Get-FileHash -Algorithm SHA256 $TempModel).Hash.ToLowerInvariant() -ne $ModelSha) {
            throw 'Downloaded model checksum differs from the publisher SHA256'
        }
        Move-Item -Force $TempModel $ModelPath
    } finally { Remove-Item $TempModel -ErrorAction SilentlyContinue }
}
if ((Get-FileHash -Algorithm SHA256 $ModelPath).Hash.ToLowerInvariant() -ne $ModelSha) {
    throw 'Offline AI model checksum mismatch; refusing build'
}

& $Python scripts\verify_sqlcipher_runtime.py
if ($LASTEXITCODE -ne 0) { throw 'SQLCipher / DPAPI check failed' }
& $Python -m pytest -q tests
if ($LASTEXITCODE -ne 0) { throw 'Source regression tests failed' }

# Copy the browsers as data under the exact path expected by Playwright.
# All children invoke this SAME onefile executable with internal command flags.
& $Python -m PyInstaller --clean --noconfirm --onefile --console `
    --name 'DiagnosticBrowser' `
    --collect-all playwright --collect-all fastapi --collect-all uvicorn `
    --collect-all reportlab --collect-all cryptography --collect-all sqlcipher3 `
    --collect-all llama_cpp `
    --add-data "${PackagePath};playwright/driver/package/.local-browsers" `
    --add-data 'diagnostic_browser\static;diagnostic_browser\static' `
    --add-data "${ModelDir};models" `
    --hidden-import diagnostic_browser.offline_ai --hidden-import diagnostic_browser.watchdog `
    --hidden-import diagnostic_browser.browser_host --hidden-import diagnostic_browser.repair `
    launcher.py
if ($LASTEXITCODE -ne 0) { throw 'Onefile PyInstaller build failed' }
$Exe = Join-Path $Root 'dist\DiagnosticBrowser.exe'
if (-not (Test-Path $Exe) -or (Test-Path 'dist\DiagnosticBrowser\DiagnosticBrowser.exe')) {
    throw 'Required single-file EXE not produced'
}
& $Exe --verify-bundle
if ($LASTEXITCODE -ne 0) { throw 'EXE self-test found missing mandatory embedded assets' }
Get-FileHash -Algorithm SHA256 $Exe | Format-List | Out-File 'dist\DiagnosticBrowser.exe.sha256.txt'
Write-Host 'Standalone onefile EXE built with Chromium and offline AI. Production approval still requires native Windows acceptance.'
