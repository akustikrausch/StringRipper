# release.ps1 - cut a GitHub release and the latest.json the auto-updater reads.
# Adapted from FXChainPlayer's release.ps1. StringRipper ships a portable exe,
# so the "installer" asset is StringRipper.exe itself; the updater self-replaces.
#
# Usage: pwsh -File release.ps1 -Version 1.2.2 [-Notes "..."] [-Exe bin\StringRipper.exe]
param(
    [Parameter(Mandatory)] [string]$Version,
    [string]$Exe = "bin\StringRipper.exe",
    [string]$Preset = "bin\regex-user-presets.ini",
    [string]$Notes = "",
    [string]$Repo = "akustikrausch/StringRipper"
)
$ErrorActionPreference = "Stop"
if (-not (Test-Path $Exe)) { throw "exe not found: $Exe" }

$hash = (Get-FileHash -Path $Exe -Algorithm SHA256).Hash.ToLower()
$size = (Get-Item $Exe).Length
if ([string]::IsNullOrWhiteSpace($hash)) { throw "empty sha256" }

$exeName     = Split-Path $Exe -Leaf
$downloadUrl = "https://github.com/$Repo/releases/download/v$Version/$exeName"
$releasesUrl = "https://github.com/$Repo/releases/tag/v$Version"
if (-not $Notes) { $Notes = "StringRipper v$Version" }

# latest.json — same shape as FXChainPlayer's manifest (version, installer{url,
# size,sha256}, changelog, minVersion, notes). update.hpp reads these keys.
$manifest = [ordered]@{
    version   = $Version
    date      = (Get-Date -Format "yyyy-MM-dd")
    installer = [ordered]@{ url = $downloadUrl; size = $size; sha256 = $hash }
    changelog = $Notes
    minVersion = "1.2.0"
    notes     = $releasesUrl
}
$dir = Split-Path $Exe -Parent
$manifestPath = Join-Path $dir "latest.json"
$manifest | ConvertTo-Json -Depth 5 | Set-Content -Path $manifestPath -Encoding UTF8

$sumsPath = Join-Path $dir "SHA256SUMS.txt"
"$hash  $exeName" | Set-Content -Path $sumsPath -Encoding ASCII
if (Test-Path $Preset) {
    $ph = (Get-FileHash -Path $Preset -Algorithm SHA256).Hash.ToLower()
    Add-Content -Path $sumsPath -Value "$ph  $(Split-Path $Preset -Leaf)" -Encoding ASCII
}

Write-Host "v$Version  sha256=$hash  size=$size"
Write-Host "manifest: $manifestPath"
$assets = @($Exe, $manifestPath, $sumsPath)
if (Test-Path $Preset) { $assets += $Preset }
gh release create "v$Version" --target (git rev-parse HEAD) --title "StringRipper $Version" --notes $Notes @assets
Write-Host "latest.json uploaded — the updater reads /releases/latest/download/latest.json"
