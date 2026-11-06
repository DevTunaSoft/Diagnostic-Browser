# Compatibility entrypoint: there is only ONE supported build path now.
$ErrorActionPreference='Stop'
& (Join-Path $PSScriptRoot 'build_single_exe_windows.ps1')
if ($LASTEXITCODE -ne 0) { throw 'Onefile build failed' }
