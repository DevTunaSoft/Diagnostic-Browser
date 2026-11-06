# Compatibility entrypoint: no old onedir/incomplete releases are permitted.
$ErrorActionPreference='Stop'
& (Join-Path $PSScriptRoot 'build_single_exe_windows.ps1')
if ($LASTEXITCODE -ne 0) { throw 'Onefile build failed' }
