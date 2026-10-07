<#
Watch-BayAgentUpdate.ps1 -- the BayAgent update rollback guard (1.3.1, A0.437)

WHY THIS EXISTS
  Kevin, 2026-10-07: "I don't like that you need me to be at the Bay PC in order to update the BayAgent. Shouldn't
  you be able to do that remotely?" Through 1.3.0 a remote update had one unrecoverable failure: if the new agent did
  not come back, nothing on the bay could put the old one back. The only remote path into a bay is the agent itself
  (outbound HTTPS, no inbound port), so a dead agent meant a site visit.

WHAT IT DOES
  Update-BayAgent.ps1 starts this script, outside the agent's scheduled task, BEFORE it promotes anything, and waits
  for it to say it is armed. Then:
    1. It waits for the new agent to prove itself back: state\agent-alive.json written by a process whose script
       hashes to the bytes that were promoted (expectedAgentSha256), first written after promotion began, and still
       being refreshed -soak- seconds later. A version label proves nothing (1.3.0 reported 1.2.1, F1).
    2. If that proof does not arrive within confirmTimeoutSeconds of time in which the cloud was REACHABLE (the
       Dataverse host answering 401 to an anonymous request and the token authority answering), it restores the
       snapshot the updater took of what was running (rollback\current, rollback\tools; local, already signed,
       verified by hash first), records the rollback where the old agent already reports it (state\last-update-
       result.json, carried in the heartbeat as lastUpdateResult), and asks for a restart.
    3. Time the cloud is unreachable does not count. A network outage cannot roll back a healthy bay; past
       maxWaitSeconds of wall time it gives up WITHOUT rolling back and says so.
    4. After a rollback it watches for the restored agent the same way and records whether it came back.
  -drill- (Update-BayAgent.ps1 -RollbackDrill) rolls back on purpose after the new agent confirms, so the path can be
  proven remotely by reinstalling the SAME version.

WHAT IT NEVER DOES
  Reads or writes agent-config.json beyond the three non-secret values it needs to probe reachability; touches a
  credential; rolls back when the snapshot does not hash to its own record; runs twice for one install (lock file).

RUN
  Launched by Update-BayAgent.ps1 only (a per-user scheduled task, or WMI as the fallback), from the SNAPSHOT copy
  rollback\tools\Watch-BayAgentUpdate.ps1, so the package being installed cannot change the code that judges it.
  The command line never contains "\BayAgent.ps1", so ABG.HostWatchdog.ps1 and ABG.AgentHost.ps1, which stop
  processes whose command line names the agent script, leave it alone.

Exit code 0 always (a scheduled task has nobody to read it); the outcome is state\update-guard.json.
Hyphens only in comments (em-dashes break AllSigned parsing).
#>
[CmdletBinding()]
param(
  [Parameter(Mandatory = $true)][string]$InstallId,
  [string]$BaseDir = "C:\AllBirdies\BayAgent",
  [string]$TaskName = "",
  [int]$PollSeconds = 5,
  [int]$ProbeEverySeconds = 30,
  # How long to wait for the updater to begin promotion before standing down (it may have failed early).
  [int]$NeverPromotedSeconds = 1800
)

function Get-GuardUtcNow { return (Get-Date).ToUniversalTime() }
function Format-GuardUtc([DateTime]$d) { return $d.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ") }

function ConvertTo-GuardUtc($value) {
  # ConvertFrom-Json gives a string on Windows PowerShell 5.1 and a DateTime on PowerShell 7; accept both.
  if ($null -eq $value) { return $null }
  if ($value -is [DateTime]) { return $value.ToUniversalTime() }
  $s = [string]$value
  if ([string]::IsNullOrWhiteSpace($s)) { return $null }
  $styles = [Globalization.DateTimeStyles]::AdjustToUniversal -bor [Globalization.DateTimeStyles]::AssumeUniversal
  $d = [DateTime]::MinValue
  if ([DateTime]::TryParse($s, [Globalization.CultureInfo]::InvariantCulture, $styles, [ref]$d)) { return $d }
  return $null
}

function Write-GuardLog([string]$msg) {
  try {
    $dir = Join-Path $BaseDir "logs"
    if (-not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Force -Path $dir | Out-Null }
    $line = ("{0} [{1}] {2}" -f (Format-GuardUtc (Get-GuardUtcNow)), $PID, $msg)
    Add-Content -LiteralPath (Join-Path $dir "Watch-BayAgentUpdate.log") -Value $line -Encoding UTF8
  } catch { }
}

function Write-GuardJson([string]$path, $obj) {
  $dir = Split-Path -Parent $path
  if (-not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Force -Path $dir | Out-Null }
  $tmp = "$path.tmp"
  [IO.File]::WriteAllText($tmp, ($obj | ConvertTo-Json -Depth 8), (New-Object Text.UTF8Encoding($false)))
  if (Test-Path -LiteralPath $path) { [IO.File]::Replace($tmp, $path, $null, $true) }
  else { [IO.File]::Move($tmp, $path) }
}

function Read-GuardJson([string]$path) {
  if (-not (Test-Path -LiteralPath $path)) { return $null }
  try { return ([IO.File]::ReadAllText($path) | ConvertFrom-Json) } catch { return $null }
}

function Get-GuardSha([string]$path) { return (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant() }

function Get-GuardTreeHashes([string]$root) {
  $map = @{}
  if (-not (Test-Path -LiteralPath $root)) { return $map }
  $full = (Get-Item -LiteralPath $root -Force).FullName.TrimEnd('\')
  foreach ($f in @(Get-ChildItem -LiteralPath $root -Recurse -File -Force)) {
    $map[$f.FullName.Substring($full.Length).TrimStart('\').ToLowerInvariant()] = Get-GuardSha $f.FullName
  }
  return $map
}

function Compare-GuardTrees($expected, [hashtable]$actual, [switch]$AllowExtra) {
  # $expected is a hashtable or the PSCustomObject ConvertFrom-Json makes of one.
  $exp = @{}
  if ($expected -is [hashtable]) { $exp = $expected }
  elseif ($null -ne $expected) { foreach ($p in $expected.PSObject.Properties) { $exp[[string]$p.Name] = [string]$p.Value } }
  $diffs = @()
  foreach ($k in @($exp.Keys | Sort-Object)) {
    if (-not $actual.ContainsKey($k)) { $diffs += "missing $k" }
    elseif ($actual[$k] -ne $exp[$k]) { $diffs += "different $k" }
  }
  if (-not $AllowExtra) { foreach ($k in @($actual.Keys | Sort-Object)) { if (-not $exp.ContainsKey($k)) { $diffs += "extra $k" } } }
  return $diffs
}

function Test-AgentAliveConfirmed([string]$expectedSha, [DateTime]$sinceUtc, [int]$soakSeconds) {
  # The proof that the code we put in place came back: an alive record for exactly those bytes, first written after
  # $sinceUtc, refreshed at least $soakSeconds later by the same process. Anything unreadable is "not yet".
  $rec = Read-GuardJson (Join-Path $BaseDir "state\agent-alive.json")
  if ($null -eq $rec) { return $false }
  try {
    $sha = [string]$rec.codeSha256
    if ($sha -notmatch '^[0-9a-fA-F]{64}$') { return $false }
    if (-not [string]::Equals($sha, $expectedSha, [StringComparison]::OrdinalIgnoreCase)) { return $false }
    $first = ConvertTo-GuardUtc $rec.firstOkUtc
    $last = ConvertTo-GuardUtc $rec.lastOkUtc
    if ($null -eq $first -or $null -eq $last) { return $false }
    if ($first -lt $sinceUtc) { return $false }
    return (($last - $first).TotalSeconds -ge $soakSeconds)
  } catch { return $false }
}

function Get-GuardHttpStatus([string]$url) {
  # An anonymous GET: the HTTP status, or 0 when nothing answered.
  try {
    $req = [Net.WebRequest]::Create($url)
    $req.Method = "GET"
    $req.Timeout = 15000
    $resp = $req.GetResponse()
    $code = [int]$resp.StatusCode
    $resp.Close()
    return $code
  } catch [Net.WebException] {
    $r = $_.Exception.Response
    if ($null -ne $r) { $code = [int]$r.StatusCode; try { $r.Close() } catch { }; return $code }
    return 0
  } catch { return 0 }
}

function Test-CloudReachable {
  # Could a healthy agent reach what it needs right now? Dataverse answers an anonymous request with 401, and the
  # token authority serves its discovery document. A 5xx or no answer is "unreachable": an agent could not work
  # either, so the time does not count against it. An unreadable config is "unreachable" (cannot tell holds).
  try {
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    $c = [IO.File]::ReadAllText((Join-Path $BaseDir "agent-config.json")) | ConvertFrom-Json
    $envUrl = [string]$c.environmentUrl
    if ([string]::IsNullOrWhiteSpace($envUrl)) { $envUrl = [string]$c.dataverseUrl }
    $tenant = [string]$c.tenantId
    $auth = [string]$c.tokenAuthorityHost
    if ([string]::IsNullOrWhiteSpace($auth)) { $auth = "https://login.microsoftonline.com" }
    if ([string]::IsNullOrWhiteSpace($envUrl) -or [string]::IsNullOrWhiteSpace($tenant)) { return @{ reachable = $false; detail = "config lacks environmentUrl or tenantId" } }
    $dv = Get-GuardHttpStatus ($envUrl.TrimEnd('/') + "/api/data/v9.2/")
    $tk = Get-GuardHttpStatus ($auth.TrimEnd('/') + "/" + $tenant + "/v2.0/.well-known/openid-configuration")
    return @{ reachable = ($dv -eq 401 -and $tk -eq 200); detail = ("dataverse={0} authority={1}" -f $dv, $tk) }
  } catch { return @{ reachable = $false; detail = ("probe failed: " + $_.Exception.Message) } }
}

function Write-GuardState([string]$state, [string]$detail) {
  $script:GuardState["state"] = $state
  $script:GuardState["utc"] = Format-GuardUtc (Get-GuardUtcNow)
  $script:GuardState["detail"] = $detail
  $script:GuardState["reachableSeconds"] = [int]$script:ReachableSeconds
  try { Write-GuardJson $script:GuardStatePath $script:GuardState } catch { Write-GuardLog ("could not write the guard state: " + $_.Exception.Message) }
  Write-GuardLog ("state={0} {1}" -f $state, $detail)
}

function Request-AgentRestart([string]$why) {
  $ctl = Join-Path $BaseDir "control"
  if (-not (Test-Path -LiteralPath $ctl)) { New-Item -ItemType Directory -Force -Path $ctl | Out-Null }
  Set-Content -LiteralPath (Join-Path $ctl "restart.host") -Value ("restart requested {0} by the update guard: {1}" -f (Format-GuardUtc (Get-GuardUtcNow)), $why) -Encoding UTF8
}

function Invoke-GuardRollback([string]$why) {
  # Restore the snapshot of what was running before the install. Refuses when the snapshot does not hash to its own
  # record: rolling back to damaged code is not better than leaving the new code in place.
  $rb = Join-Path $BaseDir "rollback"
  $snapCur = Join-Path $rb "current"
  $snapTools = Join-Path $rb "tools"
  $snap = Read-GuardJson (Join-Path $rb "snapshot.json")
  if ($null -eq $snap) { return @{ ok = $false; detail = "rollback\snapshot.json is missing or unreadable" } }
  $d0 = @(Compare-GuardTrees $snap.current (Get-GuardTreeHashes $snapCur))
  $d0 += @(Compare-GuardTrees $snap.tools (Get-GuardTreeHashes $snapTools))
  if ($d0.Count -gt 0) { return @{ ok = $false; detail = ("the snapshot does not match its record: " + ($d0 -join "; ")) } }

  $cur = Join-Path $BaseDir "current"
  if (Test-Path -LiteralPath $cur) {
    $it = Get-Item -LiteralPath $cur -Force
    if (($it.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { [IO.Directory]::Delete($cur, $false) }
  }
  $robo = @("/MIR", "/IS", "/IT", "/R:5", "/W:2", "/NP", "/NJH", "/NJS")
  $p = Start-Process -FilePath "robocopy.exe" -ArgumentList (@($snapCur, $cur) + $robo) -Wait -PassThru -NoNewWindow
  if ($p.ExitCode -ge 8) { return @{ ok = $false; detail = ("robocopy of current\ failed with exit code {0}" -f $p.ExitCode) } }
  $tools = Join-Path $BaseDir "tools"
  if (Test-Path -LiteralPath $snapTools) {
    $robo2 = @("/E", "/IS", "/IT", "/R:5", "/W:2", "/NP", "/NJH", "/NJS")
    $p2 = Start-Process -FilePath "robocopy.exe" -ArgumentList (@($snapTools, $tools) + $robo2) -Wait -PassThru -NoNewWindow
    if ($p2.ExitCode -ge 8) { return @{ ok = $false; detail = ("robocopy of tools\ failed with exit code {0}" -f $p2.ExitCode) } }
  }
  $d1 = @(Compare-GuardTrees $snap.current (Get-GuardTreeHashes $cur))
  $d1 += @(Compare-GuardTrees $snap.tools (Get-GuardTreeHashes $tools) -AllowExtra)
  if ($d1.Count -gt 0) { return @{ ok = $false; detail = ("current\ does not match the snapshot after the restore: " + ($d1 -join "; ")) } }

  $pend = $script:Pending
  $res = [ordered]@{
    ok                  = $false
    version             = [string]$pend.version
    stage               = "rolled-back"
    reason              = $why
    packageUrl          = [string]$pend.packageUrl
    utc                 = (Format-GuardUtc (Get-GuardUtcNow))
    machine             = $env:COMPUTERNAME
    installId           = $InstallId
    drill               = [bool]$pend.drill
    restoredAgentSha256 = [string]$snap.agentSha256
    restoredManifest    = [string]$snap.manifestVersion
  }
  try { Write-GuardJson (Join-Path $BaseDir "state\last-update-result.json") $res } catch { Write-GuardLog ("could not write last-update-result.json: " + $_.Exception.Message) }
  Request-AgentRestart ("rollback of {0}" -f $pend.version)
  return @{ ok = $true; detail = ("restored the snapshot (agent {0}), verified by hash; restart requested" -f $snap.agentSha256) }
}

function Wait-ForConfirmation([string]$expectedSha, [DateTime]$sinceUtc, [int]$timeoutReachable, [int]$soak, [int]$maxWait, [string]$label) {
  # Returns "confirmed", "timeout" (reachable time used up) or "gave-up" (wall cap reached).
  $start = Get-GuardUtcNow
  $lastTick = $start
  $lastProbeUtc = [DateTime]::MinValue
  $lastReachable = $false
  while ($true) {
    $now = Get-GuardUtcNow
    if (Test-AgentAliveConfirmed -expectedSha $expectedSha -sinceUtc $sinceUtc -soakSeconds $soak) { return "confirmed" }
    if (($now - $lastProbeUtc).TotalSeconds -ge $ProbeEverySeconds) {
      $pr = Test-CloudReachable
      $lastReachable = [bool]$pr.reachable
      $lastProbeUtc = $now
      $script:LastProbeDetail = $pr.detail
    }
    if ($lastReachable) { $script:ReachableSeconds += ($now - $lastTick).TotalSeconds }
    $lastTick = $now
    Write-GuardState "watching" ("{0}: waiting for agent {1}; reachable {2:N0}/{3} s; last probe {4}" -f $label, $expectedSha.Substring(0, [Math]::Min(12, $expectedSha.Length)), $script:ReachableSeconds, $timeoutReachable, $script:LastProbeDetail)
    if ($script:ReachableSeconds -ge $timeoutReachable) { return "timeout" }
    if (($now - $sinceUtc).TotalSeconds -ge $maxWait) { return "gave-up" }
    Start-Sleep -Seconds $PollSeconds
  }
}

function Complete-Guard([string]$state, [string]$detail) {
  Write-GuardState $state $detail
  try {
    $pp = Join-Path $BaseDir "state\update-pending.json"
    $po = Read-GuardJson $pp
    if ($null -ne $po -and [string]$po.installId -eq $InstallId) {
      Move-Item -LiteralPath $pp -Destination (Join-Path $BaseDir "state\update-pending.done.json") -Force
    }
  } catch { Write-GuardLog ("could not retire the pending record: " + $_.Exception.Message) }
  if (-not [string]::IsNullOrWhiteSpace($TaskName)) {
    try { Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction Stop } catch { Write-GuardLog ("could not unregister task '{0}': {1}" -f $TaskName, $_.Exception.Message) }
  }
}

# ------------------------------------------------------------------ main
$ErrorActionPreference = "Stop"
$script:GuardStatePath = Join-Path $BaseDir "state\update-guard.json"
$script:ReachableSeconds = 0.0
$script:LastProbeDetail = ""
$script:GuardState = [ordered]@{ installId = $InstallId; version = $null; state = "starting"; utc = $null; pid = $PID; armedUtc = $null; reachableSeconds = 0; detail = "" }
$lockStream = $null
try {
  $stateDir = Join-Path $BaseDir "state"
  if (-not (Test-Path -LiteralPath $stateDir)) { New-Item -ItemType Directory -Force -Path $stateDir | Out-Null }
  try {
    $lockStream = [IO.File]::Open((Join-Path $stateDir "update-guard.lock"), [IO.FileMode]::OpenOrCreate, [IO.FileAccess]::ReadWrite, [IO.FileShare]::None)
  } catch {
    Write-GuardLog "another guard instance holds the lock; exiting"
    exit 0
  }

  $script:Pending = Read-GuardJson (Join-Path $stateDir "update-pending.json")
  if ($null -eq $script:Pending -or [string]$script:Pending.installId -ne $InstallId) {
    Write-GuardLog ("no pending record for install {0}; nothing to watch" -f $InstallId)
    if (-not [string]::IsNullOrWhiteSpace($TaskName)) { try { Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction Stop } catch { } }
    exit 0
  }
  $script:GuardState["version"] = [string]$script:Pending.version

  # A restart of this guard (the at-logon trigger after a reboot) resumes the reachable-time count.
  $prev = Read-GuardJson $script:GuardStatePath
  if ($null -ne $prev -and [string]$prev.installId -eq $InstallId) {
    if ([string]$prev.state -in @("confirmed", "rolled-back", "rollback-confirmed", "rollback-unconfirmed", "rollback-failed", "gave-up-unreachable", "aborted", "never-promoted")) {
      Write-GuardLog ("install {0} already finished ({1}); nothing to do" -f $InstallId, $prev.state)
      exit 0
    }
    try { $script:ReachableSeconds = [double]$prev.reachableSeconds } catch { }
  }
  $script:GuardState["armedUtc"] = Format-GuardUtc (Get-GuardUtcNow)
  Write-GuardState "armed" ("watching install of {0}" -f $script:Pending.version)

  # Wait for promotion to begin (the updater writes phase=promoting just before it copies into current\).
  $armedAt = Get-GuardUtcNow
  while ($true) {
    $script:Pending = Read-GuardJson (Join-Path $stateDir "update-pending.json")
    if ($null -eq $script:Pending -or [string]$script:Pending.installId -ne $InstallId) { Complete-Guard "aborted" "the pending record disappeared before promotion"; exit 0 }
    $ph = [string]$script:Pending.phase
    if ($ph -eq "aborted") { Complete-Guard "aborted" "the updater stood the guard down before promotion (nothing changed in current\)"; exit 0 }
    if ($ph -in @("promoting", "promoted")) { break }
    if (((Get-GuardUtcNow) - $armedAt).TotalSeconds -ge $NeverPromotedSeconds) { Complete-Guard "never-promoted" "promotion never began; no action"; exit 0 }
    Start-Sleep -Seconds 1
  }

  $since = ConvertTo-GuardUtc $script:Pending.promotingUtc
  if ($null -eq $since) { $since = Get-GuardUtcNow }
  $expected = [string]$script:Pending.expectedAgentSha256
  $timeout = [int]$script:Pending.confirmTimeoutSeconds
  $soak = [int]$script:Pending.soakSeconds
  $maxWait = [int]$script:Pending.maxWaitSeconds
  if ($timeout -le 0) { $timeout = 900 }
  if ($soak -lt 0) { $soak = 60 }
  if ($maxWait -le 0) { $maxWait = 21600 }
  if ($expected -notmatch '^[0-9a-fA-F]{64}$') { Complete-Guard "aborted" "the pending record carries no valid expected agent hash; no action"; exit 0 }

  $outcome = Wait-ForConfirmation -expectedSha $expected -sinceUtc $since -timeoutReachable $timeout -soak $soak -maxWait $maxWait -label "new agent"
  if ($outcome -eq "gave-up") {
    Complete-Guard "gave-up-unreachable" ("the cloud was not reachable for {0} s within {1} s; the new agent was neither confirmed nor rolled back" -f $timeout, $maxWait)
    exit 0
  }
  $drill = [bool]$script:Pending.drill
  if ($outcome -eq "confirmed" -and -not $drill) {
    Complete-Guard "confirmed" ("the new agent ({0}) came back and stayed up {1} s" -f $expected, $soak)
    exit 0
  }

  $why = $(if ($outcome -eq "confirmed") { "rollback drill: the new agent confirmed, rolled back on purpose" } else { "the new agent did not prove itself back within {0} s of reachable time" -f $timeout })
  Write-GuardState "rolling-back" $why
  $rb = Invoke-GuardRollback $why
  if (-not $rb.ok) { Complete-Guard "rollback-failed" ("{0}; {1}" -f $why, $rb.detail); exit 0 }
  Write-GuardState "rolled-back" ("{0}; {1}" -f $why, $rb.detail)

  # Watch the restored agent the same way. Code from before 1.3.1 writes no alive record, so "unconfirmed" there
  # means "cannot tell", not "failed"; nothing more is attempted either way.
  $snapSha = [string]$script:Pending.snapshotAgentSha256
  $script:ReachableSeconds = 0.0
  $rbSince = Get-GuardUtcNow
  if ($snapSha -match '^[0-9a-fA-F]{64}$') {
    $o2 = Wait-ForConfirmation -expectedSha $snapSha -sinceUtc $rbSince -timeoutReachable $timeout -soak $soak -maxWait $maxWait -label "restored agent"
    if ($o2 -eq "confirmed") { Complete-Guard "rollback-confirmed" ("{0}; the restored agent ({1}) came back" -f $why, $snapSha) }
    else { Complete-Guard "rollback-unconfirmed" ("{0}; the restored agent ({1}) did not confirm ({2}); code older than 1.3.1 writes no alive record" -f $why, $snapSha, $o2) }
  } else {
    Complete-Guard "rollback-unconfirmed" ("{0}; the snapshot carries no agent hash to watch for" -f $why)
  }
  exit 0
}
catch {
  try { Write-GuardState "guard-error" ("the guard failed: " + $_.Exception.Message) } catch { }
  exit 0
}
finally {
  if ($null -ne $lockStream) { try { $lockStream.Dispose() } catch { } }
}
