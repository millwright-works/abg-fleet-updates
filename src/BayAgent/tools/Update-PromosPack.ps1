<#
Update-PromosPack.ps1
- Downloads a promos pack zip (promos.json + promos/ assets)
- Validates SHA256 (optional)
- Validates promos.json parses
- Validates every referenced bg.src under /promos/ exists in the pack
- Mirrors promos/ assets into C:\AceOfClubs\SessionDisplay\data\promos\ (deletes old files not in pack)
- Atomically replaces C:\AceOfClubs\SessionDisplay\data\promos.json
- Logs to C:\AceOfClubs\BayAgent\logs\Update-PromosPack.log

Run via BayCommand StartProcess.
#>

[CmdletBinding()]
param(
  [Parameter(Mandatory=$true)][string]$PackageUrl,
  [string]$Sha256 = "",

  [string]$SessionDisplayDir = "",   # empty = SessionDisplay beside the BayAgent folder this script is installed in
  [string]$LogPath = ""   # empty = logs\Update-PromosPack.log in the BayAgent folder
)


# The install root is where this script is installed, not a constant (the rename, A0.634/A0.636). Get-BayInstallRoot
# is copied byte for byte into every script that needs it (tests\BayAgent.InstallRoot.Tests.ps1 pins the copies).
function Get-BayInstallRoot([string]$ScriptDir) {
    if ([string]::IsNullOrWhiteSpace($ScriptDir)) { throw "Cannot tell where this script is installed (no script folder)." }
    $d = $ScriptDir.TrimEnd('\')
    for ($i = 0; $i -lt 4; $i++) {
        $leaf = Split-Path -Leaf $d
        $parent = Split-Path -Parent $d
        if ([string]::IsNullOrEmpty($parent)) { break }
        if ($leaf -in @("tools", "bootstrap", "kiosk")) { $d = $parent; continue }
        if ($leaf -in @("current", "rollback")) { $d = $parent; break }
        if ((Split-Path -Leaf $parent) -eq "releases") { $d = Split-Path -Parent $parent; break }
        break
    }
    return $d
}
$InstallRoot = Get-BayInstallRoot $PSScriptRoot
if ([string]::IsNullOrWhiteSpace($SessionDisplayDir)) { $SessionDisplayDir = Join-Path (Split-Path -Parent $InstallRoot) "SessionDisplay" }
if ([string]::IsNullOrWhiteSpace($LogPath)) { $LogPath = Join-Path $InstallRoot "logs\Update-PromosPack.log" }

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Ensure-Dir([string]$p) {
  if (-not (Test-Path -LiteralPath $p)) {
    New-Item -ItemType Directory -Path $p -Force | Out-Null
  }
}

function Write-Log([string]$msg) {
  Ensure-Dir (Split-Path $LogPath -Parent)
  $line = "{0} {1}" -f (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ"), $msg
  Add-Content -Path $LogPath -Value $line -Encoding UTF8
}

function Get-Sha256Lower([string]$path) {
  return (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()
}

function Invoke-RoboCopyMirror([string]$src, [string]$dst) {
  Ensure-Dir $dst
  # /MIR mirrors and deletes dest files not present in src
  $args = @($src, $dst, "/MIR", "/R:2", "/W:1", "/NFL", "/NDL", "/NJH", "/NJS", "/NP")
  $p = Start-Process -FilePath "robocopy.exe" -ArgumentList $args -Wait -PassThru -NoNewWindow
  # Robocopy exit codes: 0-7 are OK, 8+ is failure
  if ($p.ExitCode -ge 8) { throw "Robocopy /MIR failed with exit code $($p.ExitCode)" }
}

function Normalize-PromoAssetRelPath([string]$src) {
  if ([string]::IsNullOrWhiteSpace($src)) { return $null }

  # We expect bg.src like "../data/promos/noonflight.jpg" or "promos/noonflight.jpg"
  # Extract everything after "/promos/" or "promos/" and normalize to Windows relative path
  $s = $src.Trim()

  # Disallow obvious traversal
  if ($s -match "\.\.[\\/]" -and $s -notmatch "^\.\.[\\/]data[\\/]promos[\\/]") {
    throw "bg.src contains unsupported path traversal: $src"
  }

  $rel = $null

  $m = [regex]::Match($s, "(?i)(?:^|[\\/])promos[\\/](.+)$")
  if ($m.Success) {
    $rel = $m.Groups[1].Value
  } else {
    return $null
  }

  # Convert URL slashes to Windows slashes
  $rel = $rel -replace "/", "\"

  # Final hardening: no drive letters, no rooted paths
  if ([System.IO.Path]::IsPathRooted($rel)) {
    throw "bg.src resolves to a rooted path (not allowed): $src"
  }
  if ($rel -match "^[A-Za-z]:") {
    throw "bg.src contains a drive path (not allowed): $src"
  }

  return $rel
}

Write-Log "----"
Write-Log "Starting promos pack update. Url=$PackageUrl ShaProvided=$([bool](-not [string]::IsNullOrWhiteSpace($Sha256)))"

# Target paths
$dataDir    = Join-Path $SessionDisplayDir "data"
$promosDir  = Join-Path $dataDir "promos"
$destJson   = Join-Path $dataDir "promos.json"

Ensure-Dir $dataDir
Ensure-Dir $promosDir
Ensure-Dir (Split-Path $LogPath -Parent)

# Staging
$staging   = Join-Path $env:TEMP ("abg-promos-staging-{0}" -f ([Guid]::NewGuid().ToString("N")))
$zipPath   = Join-Path $staging "PromosPack.zip"
$expandDir = Join-Path $staging "expand"
Ensure-Dir $staging
Ensure-Dir $expandDir

try {
  [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

  Write-Log "Downloading zip..."
  Invoke-WebRequest -Uri $PackageUrl -OutFile $zipPath -UseBasicParsing

  if (-not [string]::IsNullOrWhiteSpace($Sha256)) {
    $actual   = Get-Sha256Lower $zipPath
    $expected = $Sha256.ToLowerInvariant().Replace(" ", "")
    Write-Log "SHA expected=$expected actual=$actual"
    if ($actual -ne $expected) { throw "SHA256 mismatch. Expected $expected, got $actual" }
  } else {
    Write-Log "SHA256 not provided (skipping hash validation)."
  }

  Write-Log "Expanding zip..."
  Expand-Archive -LiteralPath $zipPath -DestinationPath $expandDir -Force

  # Detect content root (support single top-level folder)
  $contentRoot = $expandDir
  $children = @(Get-ChildItem -LiteralPath $expandDir)
  if ($children.Count -eq 1 -and $children[0].PSIsContainer) { $contentRoot = $children[0].FullName }

  $packJson = Join-Path $contentRoot "promos.json"
  if (-not (Test-Path -LiteralPath $packJson)) { throw "promos.json not found in pack root." }

  $packPromosDir = Join-Path $contentRoot "promos"
  if (-not (Test-Path -LiteralPath $packPromosDir)) {
    throw "promos/ folder not found in pack. For pruning behavior, promos/ must be present."
  }

  Write-Log "Validating promos.json parses..."
  $raw = Get-Content -LiteralPath $packJson -Raw -Encoding UTF8
  $obj = $raw | ConvertFrom-Json

  # Extract promos array (support either {promos:[...]} or [...] directly)
  $promos = $null
  if ($obj -is [System.Array]) { $promos = $obj }
  elseif ($null -ne $obj.promos) { $promos = $obj.promos }
  else { throw "promos.json must be an array or an object with a 'promos' array." }

  # Build list of referenced bg assets (relative paths under promos/)
  $referenced = New-Object System.Collections.Generic.HashSet[string]([StringComparer]::OrdinalIgnoreCase)

  foreach ($p in $promos) {
    if ($null -eq $p) { continue }
    if ($null -eq $p.bg) { continue }
    $src = $p.bg.src
    $rel = Normalize-PromoAssetRelPath $src
    if ($null -ne $rel -and $rel.Trim() -ne "") {
      [void]$referenced.Add($rel)
    }
  }

  # Safety check: every referenced asset must exist in the pack promos/ folder
  foreach ($rel in $referenced) {
    $candidate = Join-Path $packPromosDir $rel
    if (-not (Test-Path -LiteralPath $candidate)) {
      throw "Referenced promo image missing from pack: '$rel' (expected at $candidate). Aborting to prevent deletions."
    }
  }

  Write-Log ("Referenced promo images in new pack: {0}" -f $referenced.Count)

  # Mirror pack assets -> destination (this deletes old/unlisted files)
  Write-Log "Mirroring promo assets to data\promos (deleting removed files)..."
  Invoke-RoboCopyMirror $packPromosDir $promosDir

  # Atomic replace promos.json AFTER assets are in place
  Write-Log "Updating promos.json..."
  $tmpJson = Join-Path $dataDir ("promos.json.tmp.{0}" -f ([Guid]::NewGuid().ToString("N")))
  Set-Content -LiteralPath $tmpJson -Value $raw -Encoding UTF8
  Move-Item -LiteralPath $tmpJson -Destination $destJson -Force

  Write-Log "OK: Promos pack installed."
  Write-Output "OK: Promos pack installed."
}
finally {
  try { Remove-Item -LiteralPath $staging -Recurse -Force } catch {}
}
