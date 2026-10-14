<#
Update-SessionDisplay.ps1

Purpose
- Pull a versioned SessionDisplay package (zip) from HTTPS (e.g., GitHub Releases)
- Verify SHA256
- Expand into:   C:\AceOfClubs\SessionDisplay\releases\<version>\
- Promote into:  C:\AceOfClubs\SessionDisplay\current\   (active UI bundle)
- Preserve runtime/persistent folders:
    C:\AceOfClubs\SessionDisplay\data\
    C:\AceOfClubs\SessionDisplay\edge-profile\
- Stop the Edge instance that is using the SessionDisplay profile directory so files are not locked.

Notes
- This script does NOT attempt to launch Edge. Your BayAgent already knows how to open/re-open SessionDisplay
  (e.g., via UpdateSessionDisplay command). This script focuses on safe file deployment.
- ZIP structure supported:
  A) Files at root of zip (index.html, css/, js/, assets/)
  B) A single top-level folder containing those files
  Anything deeper than one folder level is not recommended.

Usage example (via StartProcess BayCommand):
  powershell.exe -NoProfile -File "C:\AceOfClubs\BayAgent\tools\Update-SessionDisplay.ps1" `
    -Version "1.0.0" `
    -PackageUrl "https://github.com/<owner>/<repo>/releases/download/<tag>/SessionDisplay-1.0.0.zip" `
    -Sha256 "<sha256>" `
    -Restart

#>

[CmdletBinding()]
param(
  [Parameter(Mandatory = $true)][string]$Version,
  [Parameter(Mandatory = $true)][string]$PackageUrl,
  [Parameter(Mandatory = $true)][string]$Sha256,

  # SessionDisplay base
  [string]$BaseDir = "",   # empty = SessionDisplay beside the BayAgent folder this script is installed in

  # Where the active UI bundle lives (BaseDir\current)
  [string]$CurrentDirName = "current",

  # Edge profile dir used for the Session Display instance
  [string]$ProfileDir = "",   # empty = edge-profile inside the SessionDisplay folder

  # If provided, we stop the Edge process and leave it stopped.
  # (Your BayAgent can re-open it via UpdateSessionDisplay command.)
  [switch]$Restart,

  # Optional: mirror into legacy BaseDir layout (index.html/css/js in BaseDir root)
  # Only use this if you haven't switched agent-config.json to .../current/index.html yet.
  [switch]$LegacyBaseMirror,

  # Optional log file (helpful when running from StartProcess)
  [string]$LogPath = ""   # empty = logs\Update-SessionDisplay.log in the BayAgent folder
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
$SessionDisplayRoot = Join-Path (Split-Path -Parent $InstallRoot) "SessionDisplay"
if ([string]::IsNullOrWhiteSpace($BaseDir)) { $BaseDir = $SessionDisplayRoot }
if ([string]::IsNullOrWhiteSpace($ProfileDir)) { $ProfileDir = Join-Path $SessionDisplayRoot "edge-profile" }
if ([string]::IsNullOrWhiteSpace($LogPath)) { $LogPath = Join-Path $InstallRoot "logs\Update-SessionDisplay.log" }

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Ensure-Dir([string]$p) {
  if (-not (Test-Path -LiteralPath $p)) {
    New-Item -ItemType Directory -Path $p -Force | Out-Null
  }
}

function Write-Log([string]$msg) {
  try {
    Ensure-Dir (Split-Path -Parent $LogPath)
    $line = ("{0} {1}" -f (Get-Date).ToString("s"), $msg)
    Add-Content -LiteralPath $LogPath -Value $line -Encoding UTF8
  } catch {
    # Logging should never block the update
  }
}

function Get-Sha([string]$path) {
  return (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()
}

function Invoke-Robo([string]$src, [string]$dst, [string[]]$extraArgs) {
  Ensure-Dir $dst
  $args = @($src, $dst) + $extraArgs
  $p = Start-Process -FilePath "robocopy.exe" -ArgumentList $args -Wait -PassThru -NoNewWindow
  # Robocopy exit codes: 0-7 are success-ish; >=8 indicates failure
  if ($p.ExitCode -ge 8) { throw "Robocopy failed with exit code $($p.ExitCode)" }
}

function Get-EdgePidsForProfile([string]$pdir) {
  $ids = @()
  try {
    $procs = Get-CimInstance Win32_Process -Filter "Name='msedge.exe'" -ErrorAction SilentlyContinue
    foreach ($p in $procs) {
      # CommandLine typically contains --user-data-dir="<ProfileDir>"
      if ($p.CommandLine -and $p.CommandLine -like "*$pdir*") { $ids += [int]$p.ProcessId }
    }
  } catch {}
  return @($ids | Select-Object -Unique)
}

function Stop-SessionDisplayEdge([string]$pdir) {
  $pids = @(Get-EdgePidsForProfile $pdir)
  foreach ($id in $pids) { try { Stop-Process -Id $id -Force -ErrorAction SilentlyContinue } catch {} }
  return $pids
}

# ---- Begin main ----

Write-Log "Starting update. Version=$Version Url=$PackageUrl BaseDir=$BaseDir CurrentDirName=$CurrentDirName"

# Paths
$StagingDir  = Join-Path $BaseDir "staging"
$ReleasesDir = Join-Path $BaseDir "releases"
$CurrentDir  = Join-Path $BaseDir $CurrentDirName

Ensure-Dir $StagingDir
Ensure-Dir $ReleasesDir
Ensure-Dir $CurrentDir

$zipPath   = Join-Path $StagingDir ("SessionDisplay-{0}.zip" -f $Version)
$expandDir = Join-Path $StagingDir ("expand-{0}" -f $Version)
$relDir    = Join-Path $ReleasesDir $Version

# Download
Write-Log "Downloading zip to $zipPath"
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
Invoke-WebRequest -Uri $PackageUrl -OutFile $zipPath -UseBasicParsing

# Verify SHA
$actual   = Get-Sha $zipPath
$expected = $Sha256.ToLowerInvariant().Replace(" ", "")

Write-Log "SHA expected=$expected actual=$actual"
if ($actual -ne $expected) { throw "SHA256 mismatch. Expected $expected, got $actual" }

# Expand
Write-Log "Expanding zip to $expandDir"
if (Test-Path -LiteralPath $expandDir) { Remove-Item $expandDir -Recurse -Force }
Ensure-Dir $expandDir
Expand-Archive -LiteralPath $zipPath -DestinationPath $expandDir -Force

# Determine content root
$contentRoot = $expandDir
$children = @(Get-ChildItem -LiteralPath $expandDir)
if ($children.Count -eq 1 -and $children[0].PSIsContainer) {
  $contentRoot = $children[0].FullName
}
Write-Log "Content root is $contentRoot"

# Stage into releases\<version>\
Write-Log "Staging into release folder $relDir"
if (Test-Path -LiteralPath $relDir) { Remove-Item $relDir -Recurse -Force }
Ensure-Dir $relDir
Invoke-Robo $contentRoot $relDir @("/MIR")

# Basic sanity check: release must contain index.html
if (-not (Test-Path -LiteralPath (Join-Path $relDir "index.html"))) {
  throw "Release folder does not contain index.html at expected location: $relDir\index.html. Check zip structure."
}

# Stop display (so files aren't locked)
$killed = Stop-SessionDisplayEdge $ProfileDir
Write-Log ("Stopped Edge PIDs: {0}" -f ($killed -join ","))

# Promote release -> current
# We exclude data/edge-profile just in case a package mistakenly contains them.
Write-Log "Promoting release -> current ($CurrentDir)"
Invoke-Robo $relDir $CurrentDir @(
  "/MIR",
  "/XD", "data", "edge-profile", "releases", "staging"
)

# Optional: mirror to legacy BaseDir layout if you haven't switched to current yet
if ($LegacyBaseMirror) {
  Write-Log "LegacyBaseMirror enabled: mirroring release -> BaseDir root ($BaseDir)"
  Invoke-Robo $relDir $BaseDir @(
    "/MIR",
    "/XD", "data", "edge-profile", "releases", "staging", $CurrentDirName
  )
}

if ($Restart) {
  # We intentionally leave Edge stopped here.
  # Your BayAgent can re-open Session Display via an UpdateSessionDisplay command.
  Write-Log "Restart switch set: leaving Edge stopped for BayAgent to re-open."
}

Write-Log "Update complete OK. Version=$Version"
Write-Output ("OK: Updated SessionDisplay to {0}. ReleaseDir={1}. CurrentDir={2}. KilledEdgePids={3}. LegacyBaseMirror={4}" -f $Version, $relDir, $CurrentDir, ($killed -join ","), [bool]$LegacyBaseMirror)
