# CipherAI installer for Windows (PowerShell 5.1 or 7+).
#
# Same integrity rule as install.sh: the release binary is checked against the
# SHA256SUMS.txt published with the release before anything is installed.
#
# Usage:
#   powershell -ExecutionPolicy Bypass -File install.ps1 [-Version vX.Y.Z] [-Prefix DIR]
#
# Options:
#   -Version   Release tag to install (default: latest published release)
#   -Prefix    Install directory (default: $env:LOCALAPPDATA\cipher-ai\bin, or $env:CIPHER_AI_PREFIX)
#   -BaseUrl   Download base URL, for testing only (default: the GitHub release for -Version)
[CmdletBinding()]
param(
    [string]$Version = "",
    [string]$Prefix = "",
    [string]$BaseUrl = ""
)

$ErrorActionPreference = "Stop"
$Repo = "sandeepannandi/Cipher"

function Fail([string]$Message) {
    [Console]::Error.WriteLine("install: $Message")
    exit 1
}

# Only 64-bit Windows has a release artifact.
$arch = $env:PROCESSOR_ARCHITECTURE
if ($env:PROCESSOR_ARCHITEW6432) { $arch = $env:PROCESSOR_ARCHITEW6432 }
if ($arch -ne "AMD64") {
    Fail "unsupported architecture: $arch - build from source (see README)"
}
$Target = "x86_64-pc-windows-msvc"
$Artifact = "cipher-ai-$Target.exe"

if (-not $Prefix) {
    if ($env:CIPHER_AI_PREFIX) { $Prefix = $env:CIPHER_AI_PREFIX }
    else { $Prefix = Join-Path $env:LOCALAPPDATA "cipher-ai\bin" }
}

[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12

if (-not $BaseUrl) {
    if (-not $Version) {
        try {
            $release = Invoke-RestMethod -UseBasicParsing -Uri "https://api.github.com/repos/$Repo/releases/latest"
            $Version = $release.tag_name
        } catch {
            Fail "could not resolve the latest release tag - pass -Version vX.Y.Z"
        }
        if (-not $Version) { Fail "could not resolve the latest release tag - pass -Version vX.Y.Z" }
    }
    $BaseUrl = "https://github.com/$Repo/releases/download/$Version"
} elseif (-not $Version) {
    $Version = "(custom base url)"
}

$Tmp = Join-Path ([IO.Path]::GetTempPath()) ("cipher-ai-install-" + [Guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Path $Tmp | Out-Null
try {
    Write-Host "install: cipher-ai $Version for $Target"
    Write-Host "install: downloading $Artifact + SHA256SUMS.txt"
    $binPath = Join-Path $Tmp $Artifact
    $sumsPath = Join-Path $Tmp "SHA256SUMS.txt"
    try { Invoke-WebRequest -UseBasicParsing -Uri "$BaseUrl/$Artifact" -OutFile $binPath }
    catch { Fail "download failed: $BaseUrl/$Artifact" }
    try { Invoke-WebRequest -UseBasicParsing -Uri "$BaseUrl/SHA256SUMS.txt" -OutFile $sumsPath }
    catch { Fail "download failed: $BaseUrl/SHA256SUMS.txt" }

    # The release must carry a checksum line for this exact artifact, and the
    # downloaded bytes must match it. Anything else is a hard failure.
    $expected = $null
    foreach ($line in Get-Content -LiteralPath $sumsPath) {
        $parts = $line.Trim() -split "\s+", 2
        if ($parts.Count -eq 2 -and $parts[1].TrimStart("*") -eq $Artifact) {
            $expected = $parts[0].ToLowerInvariant()
        }
    }
    if (-not $expected) {
        Fail "no checksum for $Artifact in $Version SHA256SUMS.txt - refusing to install"
    }
    $actual = (Get-FileHash -LiteralPath $binPath -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($actual -ne $expected) {
        Fail "checksum mismatch for $Artifact - refusing to install"
    }
    Write-Host "install: checksum verified"

    New-Item -ItemType Directory -Path $Prefix -Force | Out-Null
    $dest = Join-Path $Prefix "cipher-ai.exe"
    Copy-Item -LiteralPath $binPath -Destination $dest -Force
    Write-Host "install: installed $dest"

    $onPath = ($env:PATH -split ";") | Where-Object { $_.TrimEnd("\") -ieq $Prefix.TrimEnd("\") }
    if (-not $onPath) { Write-Host "install: add $Prefix to your PATH" }
    Write-Host "install: done - run 'cipher-ai setup' to configure an AI provider"
} finally {
    Remove-Item -LiteralPath $Tmp -Recurse -Force -ErrorAction SilentlyContinue
}
