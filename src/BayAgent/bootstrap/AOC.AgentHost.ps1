<#
AOC.AgentHost.ps1 (Step 7.2.1)
- Single, stable entrypoint launched by Scheduled Task: \AOC Bay Agent (Run as BayKiosk)
- Starts and supervises BayAgent.ps1 from C:\AceOfClubs\BayAgent\current
- IMPORTANT for AllSigned: does NOT use -ExecutionPolicy Bypass.

Hardening in this version:
- Single-instance lock (mutex) for AgentHost itself
- Pre-start cleanup: kills orphan BayAgent instances before launching a new one
- Writes structured logs to C:\AceOfClubs\BayAgent\logs\AgentHost-YYYYMMDD.log
#>

[CmdletBinding()]
param(
  [switch]$Once
)

Set-StrictMode -Version Latest
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
$BaseDir = Get-BayInstallRoot $PSScriptRoot
$LogDir  = Join-Path $BaseDir "logs"
$StopFile = Join-Path $BaseDir "stop.host"

if (!(Test-Path $LogDir)) { New-Item -ItemType Directory -Force -Path $LogDir | Out-Null }
$LogFile = Join-Path $LogDir ("AgentHost-{0}.log" -f (Get-Date).ToString("yyyyMMdd"))

function Write-HostLog([string]$msg, [ValidateSet("DEBUG","INFO","WARN","ERROR")] [string]$level="INFO") {
  $ts = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
  $line = "$ts [$level] $msg"
  Write-Host $line
  try { Add-Content -Path $LogFile -Value $line } catch {}
}

# -------------------------
# Single-instance mutex
# -------------------------
$mutex = $null
$createdNew = $false
try {
  $mutex = New-Object System.Threading.Mutex($true, "Global\AOC.AgentHost", [ref]$createdNew)
  if (-not $createdNew) {
    Write-HostLog "Another AgentHost instance is already running. Exiting." "WARN"
    exit 0
  }
} catch {
  Write-HostLog "Failed to create AgentHost mutex (continuing). $($_.Exception.Message)" "WARN"
}

# -------------------------
# Helpers
# -------------------------
function Get-PSProcessesByCmdLike([string]$pattern) {
  Get-CimInstance Win32_Process -Filter "Name='powershell.exe'" |
    Where-Object { $_.CommandLine -and $_.CommandLine -like $pattern }
}

function Stop-OrphanBayAgents {
  # Match any BayAgent.ps1 running from current or releases
  $procs = @(Get-PSProcessesByCmdLike ("*" + $BaseDir.TrimEnd('\') + "\*\BayAgent.ps1*"))
  if ($procs.Count -gt 0) {
    Write-HostLog ("Found {0} BayAgent process(es) already running. Killing before launch to prevent duplicates." -f $procs.Count) "WARN"
    foreach ($p in $procs) {
      try { Stop-Process -Id $p.ProcessId -Force } catch {}
    }
    Start-Sleep -Milliseconds 300
  }
}

# -------------------------
# Main loop
# -------------------------
try {
  Write-HostLog "AgentHost starting. Once=$Once BaseDir=$BaseDir PID=$PID" "INFO"

  if (Test-Path $StopFile) {
    Write-HostLog "stop.host present; refusing to start BayAgent. Remove $StopFile to resume." "WARN"
    exit 0
  }

  $AgentPath = Join-Path $BaseDir "current\BayAgent.ps1"
  if (!(Test-Path $AgentPath)) { throw "AgentPath not found: $AgentPath" }

  $psExe = "$env:WINDIR\System32\WindowsPowerShell\v1.0\powershell.exe"
  $delay = 5
  $MaxRestartDelaySeconds = 60

  while ($true) {
    if (Test-Path $StopFile) {
      Write-HostLog "stop.host present; exiting AgentHost." "WARN"
      break
    }

    # Prevent duplicates if AgentHost was restarted while BayAgent survived
    Stop-OrphanBayAgents

    $arg = "-NoProfile -WindowStyle Minimized -File `"$AgentPath`""
    Write-HostLog "Starting agent: $psExe $arg" "INFO"

    $p = Start-Process -FilePath $psExe -ArgumentList $arg -PassThru -WindowStyle Minimized
    Write-HostLog "Agent started. pid=$($p.Id)" "INFO"

    Wait-Process -Id $p.Id
    $exitCode = $p.ExitCode
    Write-HostLog "Agent exited. pid=$($p.Id) exitCode=$exitCode" "WARN"

    if ($Once) { break }

    Write-HostLog "Restarting agent after $delay seconds..." "INFO"
    Start-Sleep -Seconds $delay
    $delay = [Math]::Min($delay * 2, $MaxRestartDelaySeconds)
  }

  Write-HostLog "AgentHost exiting." "INFO"
  exit 0
}
catch {
  Write-HostLog ("AgentHost fatal: {0}" -f $_.Exception.Message) "ERROR"
  exit 1
}
finally {
  try {
    if ($mutex) {
      if ($createdNew) { $mutex.ReleaseMutex() | Out-Null }
      $mutex.Dispose()
    }
  } catch {}
}
