<#
ABG.HostWatchdog.ps1 (Step 7.2.5)

Runs as SYSTEM via Task Scheduler.
Purpose:
- Ensure ABG.AgentHost is running (via scheduled task \ABG Bay Agent).
- Consume restart requests written by RestartBayAgent.ps1:
    C:\AllBirdies\BayAgent\control\restart.host

IMPORTANT HARDENING NOTE:
- This script intentionally avoids using "-or" in places that could be mis-parsed as a cmdlet parameter
  (e.g., `Test-Path $a -or Test-Path $b`). We use explicit boolean checks instead.
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# ---------------------------
# Config
# ---------------------------
$BaseDir       = "C:\AllBirdies\BayAgent"
$ControlDir    = Join-Path $BaseDir "control"
$LogDir        = Join-Path $BaseDir "logs"

$HostTaskName    = "\ABG Bay Agent"
$HostScriptPath  = Join-Path $BaseDir "bootstrap\ABG.AgentHost.ps1"

$StopFile1     = Join-Path $BaseDir "stop.host"
$StopFile2     = Join-Path $ControlDir "stop.host"
$RestartFile   = Join-Path $ControlDir "restart.host"

$LogPath       = Join-Path $LogDir ("HostWatchdog-{0}.log" -f (Get-Date -Format yyyyMMdd))

# ---------------------------
# Helpers
# ---------------------------
function Log([string]$level, [string]$msg) {
  $ts = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
  Add-Content -Path $LogPath -Value ("$ts [$level] $msg") -Encoding UTF8
}

function Ensure-Dir([string]$path) {
  if (-not (Test-Path $path)) {
    New-Item -ItemType Directory -Path $path -Force | Out-Null
  }
}

function Get-PowerShellProcs() {
  return @(Get-CimInstance Win32_Process -Filter "Name='powershell.exe'" -ErrorAction SilentlyContinue)
}

function Get-AgentHostProcs() {
  $hits = @()
  foreach ($p in (Get-PowerShellProcs)) {
    $cl = $p.CommandLine
    if ([string]::IsNullOrWhiteSpace($cl)) { continue }
    if ($cl -match "ABG\.AgentHost\.ps1") { $hits += $p }
  }
  return @($hits)
}

function Get-BayAgentProcs() {
  $hits = @()
  foreach ($p in (Get-PowerShellProcs)) {
    $cl = $p.CommandLine
    if ([string]::IsNullOrWhiteSpace($cl)) { continue }
    if ($cl -match "\\AllBirdies\\BayAgent\\.*\\BayAgent\.ps1") { $hits += $p }
  }
  return @($hits)
}

function Kill-Procs([object[]]$procs, [string]$label) {
  foreach ($p in @($procs)) {
    try {
      Stop-Process -Id $p.ProcessId -Force -ErrorAction SilentlyContinue
      Log "WARN" ("Killed PID {0} ({1})" -f $p.ProcessId, $label)
    } catch {
      Log "WARN" ("Failed to kill PID {0} ({1}): {2}" -f $p.ProcessId, $label, $_.Exception.Message)
    }
  }
}

# The name of the user signed in at the console (DOMAIN\name), or "" when nobody is. The agent task is registered
# Interactive for BayKiosk, so it can only start inside that user's own session.
function Get-ConsoleUser() {
  try {
    $cs = Get-CimInstance Win32_ComputerSystem -ErrorAction Stop
    if ($null -ne $cs -and -not [string]::IsNullOrWhiteSpace([string]$cs.UserName)) { return [string]$cs.UserName }
  } catch {}
  return ""
}

# Starts the agent task and reports what Task Scheduler really said. A native program's failure does not throw, so
# the exit code is read on the very next line. Stderr is merged in, with the error preference lowered for the call
# (Windows PowerShell 5.1 turns merged native stderr into a terminating error under Stop), so the text of the
# refusal, for example "ERROR: Element not found.", reaches the log. Returns $true only when schtasks exited 0.
function Start-HostTask() {
  $text = ""
  $rc = -1
  $savedPref = $ErrorActionPreference
  try {
    $ErrorActionPreference = "Continue"
    $global:LASTEXITCODE = 0
    $out = schtasks.exe /Run /TN $HostTaskName 2>&1
    $rc = $LASTEXITCODE
    $text = ((@($out) | ForEach-Object { if ($_ -is [System.Management.Automation.ErrorRecord]) { [string]$_.Exception.Message } else { [string]$_ } } | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }) -join " ").Trim()
  } catch {
    $text = [string]$_.Exception.Message
    $rc = -1
  } finally {
    $ErrorActionPreference = $savedPref
  }
  if ($rc -eq 0) {
    Log "INFO" ("Started scheduled task {0}" -f $HostTaskName)
    return $true
  }
  Log "WARN" ("Failed to start scheduled task {0}: schtasks exit {1}: {2}" -f $HostTaskName, $rc, $text)
  return $false
}

function End-HostTask() {
  try {
    schtasks.exe /End /TN $HostTaskName | Out-Null
    Log "WARN" ("Ended scheduled task {0}" -f $HostTaskName)
  } catch {
    Log "WARN" ("Failed to end scheduled task {0}: {1}" -f $HostTaskName, $_.Exception.Message)
  }
}

# ---------------------------
# Main (single instance)
# ---------------------------
$mutex = New-Object System.Threading.Mutex($false, "Global\ABG.HostWatchdog")
if (-not $mutex.WaitOne(0)) { exit 0 }

try {
  Ensure-Dir $LogDir
  Ensure-Dir $ControlDir

  # stop.host check (avoid "-or" patterns entirely)
  $hasStop = $false
  if (Test-Path $StopFile1) { $hasStop = $true }
  if (Test-Path $StopFile2) { $hasStop = $true }

  if ($hasStop) {
    Log "WARN" "stop.host present; watchdog will not start or restart host."
    exit 0
  }

  # Restart requested?
  if (Test-Path $RestartFile) {
    $ackName = ("restart.ack.{0}.host" -f (Get-Date -Format yyyyMMdd-HHmmss))
    $ackPath = Join-Path $ControlDir $ackName

    try {
      Rename-Item -Path $RestartFile -NewName $ackName -Force
      Log "WARN" ("Restart requested. Acknowledged => {0}" -f $ackPath)
    } catch {
      Log "WARN" ("Restart marker found but could not rename/ack: {0}" -f $_.Exception.Message)
    }

    End-HostTask

    # Hard stop any remaining processes
    Kill-Procs (Get-AgentHostProcs) "AgentHost"
    Kill-Procs (Get-BayAgentProcs)  "BayAgent"

    Start-Sleep -Seconds 2
    [void](Start-HostTask)
    exit 0
  }

  # Host already running?
  $hostProcs = @(Get-AgentHostProcs)
  if ($hostProcs.Count -gt 0) {
    Log "INFO" "Host is running."
    exit 0
  }

  Log "WARN" "AgentHost process not detected. Ensuring scheduled task is running..."
  $consoleUser = Get-ConsoleUser
  if ([string]::IsNullOrWhiteSpace($consoleUser)) {
    # The agent task is Interactive: it starts only inside the kiosk user's own session, and its logon trigger does
    # that at the next sign-in. Nothing here can start it sooner, so say so and try again next minute.
    Log "WARN" ("No interactive session is signed in; not starting {0}. Waiting for the kiosk user to sign in (the task's logon trigger starts the agent)." -f $HostTaskName)
    exit 0
  }

  $started = Start-HostTask
  if (-not $started) {
    # There is deliberately NO direct Start-Process fallback. This script runs as SYSTEM, so a process it starts
    # lives in session 0 under the SYSTEM account: invisible, and not the kiosk user. A failed task start is logged
    # above with the real schtasks error and retried on the next run.
    Log "WARN" ("Task start failed with an interactive session open ({0}). AgentHost is not started directly: from this SYSTEM task it would run in session 0 as SYSTEM. Retrying next run." -f $consoleUser)
  }
}
catch {
  try { Log "WARN" ("Watchdog fatal: {0}" -f $_.Exception.Message) } catch {}
  exit 1
}
finally {
  $mutex.ReleaseMutex() | Out-Null
  $mutex.Dispose()
}

# SIG # Begin signature block
# MIIFiwYJKoZIhvcNAQcCoIIFfDCCBXgCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUlx444bC+C+eyW3y9xCPkNY9D
# JY6gggMcMIIDGDCCAgCgAwIBAgIQcB7+YhwgR7ZJib3KL4WIcjANBgkqhkiG9w0B
# AQsFADAkMSIwIAYDVQQDDBlBQkcgQmF5QWdlbnQgQ29kZSBTaWduaW5nMB4XDTI2
# MDEwMzExMjAyNloXDTI3MDEwMzExNDAyNlowJDEiMCAGA1UEAwwZQUJHIEJheUFn
# ZW50IENvZGUgU2lnbmluZzCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEB
# AMHHQzWuIzBHO6BwscGzuoCN3bquhA+YTha7xYBsvX/eatjwlCpT4buJXeVZvoHQ
# OOcMsKg+kt+taj9s/gv2Arm0rh730JVHtJcSm0X96L+GI29bjydtSFqLl8iAtCvh
# 1EQoakIaxXTVGXKxMNEnhNwIocdDETF1wT1kkZ/bCDZyPY5Y0/iEcRc5CAKAhF/H
# IrIJXd/QL4esRkg1HkmDCOoHD3vZkQAWLgTLchRFE6Uk10RAHwJmpHBWo/pjho0L
# tGNFDRJvgXGpO6hbSSjxu5gyznnDWd2chg/xW6WLJ3dhqFpYIixOR+gBJumVS46F
# 8jFj+hT8MfWxzhpX3NtQf2ECAwEAAaNGMEQwDgYDVR0PAQH/BAQDAgeAMBMGA1Ud
# JQQMMAoGCCsGAQUFBwMDMB0GA1UdDgQWBBTlEn8ZOjY/C0/ILYEj+knQETbTMzAN
# BgkqhkiG9w0BAQsFAAOCAQEATPNqtG54FSKaVvJ/XtuHqccWzTJ3koMG6gq+jlLE
# OiOhQ7auwTNPRy42er59N79LInazh5pEENqFfyorsbzHETk06VEgvagczzUkwnsR
# 0CtRhbeLzaxDu2UGMyoUbeSDC6wpeftBIae0N4Vb+u88Ml3psmyX5vIBduJQ00hL
# kTrgcBL63YcCrfgOmUMxOsTumkDPUPSaA5M9tlEnXo3lSQ/jfzrzJx+CPVg8h3E/
# rssfpBbvvZ7mf0R9Kl7eAMSHw58jrvOuJA2V/7Ws3y9BjiW9YJeuZMCNJFDlI6bG
# 0SPAugVCPD0VTyDtOavtPO1ZmA1nwRA36FKC8ZqWUF2mrzGCAdkwggHVAgEBMDgw
# JDEiMCAGA1UEAwwZQUJHIEJheUFnZW50IENvZGUgU2lnbmluZwIQcB7+YhwgR7ZJ
# ib3KL4WIcjAJBgUrDgMCGgUAoHgwGAYKKwYBBAGCNwIBDDEKMAigAoAAoQKAADAZ
# BgkqhkiG9w0BCQMxDAYKKwYBBAGCNwIBBDAcBgorBgEEAYI3AgELMQ4wDAYKKwYB
# BAGCNwIBFTAjBgkqhkiG9w0BCQQxFgQUp36tHlnLCvsEU0x9MJSkSwFmSCYwDQYJ
# KoZIhvcNAQEBBQAEggEAT7wkEadDWqZTn45xEhOptlW426jZnoznMiox8dzQ6dN8
# QpydU7wWBpnXQXtSipZ8d5QxNEZAvwP+gFfIgoye0Y0NQSl8UyySSLbf9as5unrm
# XAgZvTftIBVMZ1xPQ70qw8+boXSVRshzrNm58Sq2f+nMRZs62XBpTQ3lqOEgHh0l
# T2bPm6jYSA3Y42rf6Mi90ETpLcVe2dtaZ2hx2Bi70BOancXlwRJs/hhEBlL3Yjro
# KXzr15KENGdoZJgDUBiHcAvPDL158y41u78M0erzAxySVXlF/MMk1XTnAWKZUgaW
# szus7lKoQbnhNxKCDIa6+XHDqNIzXdGEaNYW5xW5ig==
# SIG # End signature block
