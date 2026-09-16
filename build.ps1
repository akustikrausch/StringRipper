# build.ps1 - build the portable URLRipper.exe with MSVC (static CRT, no DLLs).
# Usage: pwsh -File build.ps1
$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
$vswhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
$inst = & $vswhere -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
$vcvars = Join-Path $inst "VC\Auxiliary\Build\vcvars64.bat"
if (-not (Test-Path $vcvars)) { throw "vcvars64.bat not found. Install the MSVC C++ build tools." }

New-Item -ItemType Directory -Force -Path (Join-Path $root "bin") | Out-Null
$src = Join-Path $root "src\main.cpp"
$out = Join-Path $root "bin\URLRipper.exe"

$cl = "cl /nologo /std:c++20 /EHsc /O2 /MT /W3 /DUNICODE /D_UNICODE `"$src`" /Fe:`"$out`" /Fo:`"$env:TEMP\urlripper_`" /link /SUBSYSTEM:WINDOWS"
cmd /c "`"$vcvars`" >nul && $cl"
if ($LASTEXITCODE -ne 0) { throw "compile failed ($LASTEXITCODE)" }
Write-Host "built $out"
Get-Item $out | Select-Object Name, Length, LastWriteTime | Format-Table -AutoSize
