# build.ps1 - build the portable StringRipper.exe with MSVC (static CRT, no DLLs).
#
# StringRipper reuses FXChainPlayer's ripper reader (src/audio/rip_backend_win32.cpp
# + headers). Point FXCHAINPLAYER_DIR at your FXChainPlayer checkout; it defaults
# to the sibling folder ..\VST-Player.
#
# Usage: pwsh -File build.ps1
$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $MyInvocation.MyCommand.Path

$fx = if ($env:FXCHAINPLAYER_DIR) { $env:FXCHAINPLAYER_DIR } else { Join-Path $root "..\VST-Player" }
$fxsrc = Join-Path $fx "src"
$rb = Join-Path $fxsrc "audio\rip_backend_win32.cpp"
if (-not (Test-Path $rb)) {
    throw "FXChainPlayer source not found at '$fxsrc'. Set FXCHAINPLAYER_DIR to your FXChainPlayer checkout."
}

$vswhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
$inst = & $vswhere -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
$vcvars = Join-Path $inst "VC\Auxiliary\Build\vcvars64.bat"
if (-not (Test-Path $vcvars)) { throw "vcvars64.bat not found. Install the MSVC C++ build tools." }

New-Item -ItemType Directory -Force -Path (Join-Path $root "bin") | Out-Null
$srcdir = Join-Path $root "src"
$src = Join-Path $srcdir "main.cpp"
$rc  = Join-Path $srcdir "StringRipper.rc"
$out = Join-Path $root "bin\StringRipper.exe"
$tmp = $env:TEMP
$res = Join-Path $tmp "StringRipper.res"
$build = Get-Date -Format "yyyyMMddHHmm"   # build number = build timestamp

$rcc = "rc /nologo /I `"$srcdir`" /fo `"$res`" `"$rc`""
$cl = "cl /nologo /std:c++20 /EHsc /O2 /Gy /GL /MT /W3 /DUNICODE /D_UNICODE /DSTRINGRIPPER_BUILD=$build /I `"$fxsrc`" `"$src`" `"$rb`" `"$res`" /Fe:`"$out`" /link /LTCG /SUBSYSTEM:WINDOWS /OPT:REF /OPT:ICF /MANIFEST:EMBED"
# cd into a local temp dir so object files do not need a UNC-unfriendly /Fo.
cmd /c "call `"$vcvars`" >nul 2>&1 && cd /d `"$tmp`" && $rcc && $cl"
if ($LASTEXITCODE -ne 0) { throw "compile failed ($LASTEXITCODE)" }

# Sign when a cert is configured. A signed exe from a known publisher stops
# Defender's ML heuristics flagging a memory-reading tool as a false positive.
# Set SR_SIGN_THUMBPRINT (cert in the store) or SR_SIGN_PFX + SR_SIGN_PFX_PASS.
if ($env:SR_SIGN_THUMBPRINT -or $env:SR_SIGN_PFX) {
    $ts = "http://timestamp.digicert.com"
    if ($env:SR_SIGN_THUMBPRINT) {
        $sign = "signtool sign /sha1 $env:SR_SIGN_THUMBPRINT /fd SHA256 /tr $ts /td SHA256 `"$out`""
    } else {
        $sign = "signtool sign /f `"$env:SR_SIGN_PFX`" /p `"$env:SR_SIGN_PFX_PASS`" /fd SHA256 /tr $ts /td SHA256 `"$out`""
    }
    cmd /c "call `"$vcvars`" >nul 2>&1 && $sign"
    if ($LASTEXITCODE -ne 0) { throw "signing failed ($LASTEXITCODE)" }
    Write-Host "signed $out"
}
Write-Host "built $out  (reused FXChainPlayer ripper from $fxsrc)"
Get-Item $out | Select-Object Name, Length, LastWriteTime | Format-Table -AutoSize | Out-String
