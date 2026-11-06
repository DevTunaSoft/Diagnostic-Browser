# Acceptance on a clean, authorized Windows 10/11 x64 desktop.
# Environment must not have Python, Chrome, Playwright, sqlcipher, or AI tools installed.
param([string]$Exe)
$ErrorActionPreference = 'Stop'
if (-not $Exe) { throw 'Provide absolute path to DiagnosticBrowser.exe' }
$Exe=(Resolve-Path $Exe).Path
if (-not (Test-Path $Exe) -or [IO.Path]::GetFileName($Exe) -ne 'DiagnosticBrowser.exe') { throw 'Invalid EXE path' }
$Work=Join-Path $env:LOCALAPPDATA ('DiagnosticBrowser-Acceptance-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $Work -Force | Out-Null
& $Exe --verify-bundle
if ($LASTEXITCODE -ne 0) { throw 'Mandatory bundled assets missing' }
$P=$null
try {
    $Args=@('--data-dir','"'+$Work+'"','--url','about:blank','--headless','--synthetic-lab','--port','18739')
    $P=Start-Process -FilePath $Exe -ArgumentList $Args -PassThru -NoNewWindow
    $Deadline=(Get-Date).AddSeconds(360)
    $OK=$false
    while ((Get-Date) -lt $Deadline) {
        Start-Sleep -Seconds 1
        if ($P.HasExited) { throw ('Executable exited unexpectedly: '+$P.ExitCode) }
        $H=Join-Path $Work 'browser-host.health.json'
        $W=Join-Path $Work 'watchdog.health.json'
        $E=Join-Path $Work 'flight_recorder.sqlite'
        if ((Test-Path $H) -and (Test-Path $W) -and (Test-Path $E)) {
            try {
                $Health=Get-Content -Raw $H | ConvertFrom-Json
                if ($Health.browser_connected -and $Health.bridge_connected) { $OK=$true;break }
            } catch { }
        }
    }
    if (-not $OK) { throw 'Chromium, encrypted recorder, and watchdog integration failed' }
    $Database=Join-Path $Work 'flight_recorder.sqlite'
    $Magic=[Text.Encoding]::ASCII.GetString([IO.File]::ReadAllBytes($Database),0,16)
    if ($Magic -eq "SQLite format 3`0") { throw 'Plaintext SQLite found in production application' }
    New-Item -ItemType File -Path (Join-Path $Work 'engine.stop') -Force | Out-Null
    if (-not $P.WaitForExit(45000)) { throw 'Graceful process shutdown failed' }
    if ($P.ExitCode -ne 0) { throw ('Shutdown exited with code '+$P.ExitCode) }
    Write-Host 'PASS: standalone EXE + bundled Chromium + encrypted evidence + subprocesses'
} finally {
    if ($P -and -not $P.HasExited) {
        New-Item -ItemType File -Path (Join-Path $Work 'engine.stop') -Force | Out-Null
        Write-Warning ('Manual inspection required for synthetic acceptance process '+$P.Id)
    }
}
