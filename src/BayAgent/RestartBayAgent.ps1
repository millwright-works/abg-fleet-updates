[CmdletBinding()]
param([switch]$FromAgent)

$ErrorActionPreference = "Stop"

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
$BaseDir    = Get-BayInstallRoot $PSScriptRoot
$ControlDir = Join-Path $BaseDir "control"
$LogDir     = Join-Path $BaseDir "logs"

$StopFile1  = Join-Path $BaseDir "stop.host"
$StopFile2  = Join-Path $ControlDir "stop.host"
$Rq         = Join-Path $ControlDir "restart.host"
$LogPath    = Join-Path $LogDir ("RestartBayAgent-{0}.log" -f (Get-Date -Format yyyyMMdd))

function Log([string]$msg) {
  $ts = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
  try { Add-Content -Path $LogPath -Value ("$ts $msg") -Encoding UTF8 } catch {}
  Write-Output $msg
}

# Avoid "-or" entirely (PowerShell can misread it as a parameter in some contexts)
$hasStop = $false
if (Test-Path $StopFile1) { $hasStop = $true }
if (Test-Path $StopFile2) { $hasStop = $true }

if ($hasStop) {
  Log "stop.host present; not requesting restart."
  exit 0
}

if (-not (Test-Path $ControlDir)) {
  New-Item -ItemType Directory -Path $ControlDir -Force | Out-Null
}

try {
  $stamp  = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
  $procId = $PID
  $who    = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name

  $content = @(
    "requestedUtc=$stamp"
    "requestedBy=$who"
    "requesterPid=$procId"
    "fromAgent=$FromAgent"
  ) -join "`r`n"

  Set-Content -Path $Rq -Value $content -Encoding ASCII -Force
  Log ("Restart requested (marker written): {0}" -f $Rq)
  exit 0
}
catch {
  Log ("Failed to write restart marker: {0}" -f $_.Exception.Message)
  exit 1
}
