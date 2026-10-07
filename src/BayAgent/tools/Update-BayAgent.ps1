<#
Update-BayAgent.ps1

Purpose
- Download a versioned BayAgent zip from HTTPS (e.g., GitHub Releases)
- Verify SHA256
- Expand into:   C:\AllBirdies\BayAgent\releases\<version>\
- Promote into:  C:\AllBirdies\BayAgent\current\
- Sign installed scripts (BayAgent.ps1 and any .ps1/.psm1/.psd1 in current) to satisfy AllSigned,
  RFC 3161 timestamped so the signature outlives the signing certificate's own expiry
- Optionally request restart by writing: C:\AllBirdies\BayAgent\control\restart.host

ZIP structure supported:
A) Files at root (BayAgent.ps1, manifest.json, etc.)
B) A single top-level folder containing those files
(Anything deeper than one folder is not recommended.)

Typical usage (via StartProcess BayCommand):

  powershell.exe -NoProfile -File "C:\AllBirdies\BayAgent\tools\Update-BayAgent.ps1" `
    -Version "1.1.8" `
    -PackageUrl "https://github.com/<owner>/<repo>/releases/download/<tag>/BayAgent-1.1.8.zip" `
    -Sha256 "<sha256>" `
    -RequestRestart

PACKAGE HOSTING -- GitHub Releases, no authentication
  PackageUrl must be an HTTPS URL that needs no credentials. All three fleet packages
  (BayAgent, SessionDisplay, PromosPack) are hosted as GitHub Release assets and are
  fetched with a plain Invoke-WebRequest, exactly as Update-SessionDisplay.ps1 and
  Update-PromosPack.ps1 have always done.

  Dataverse file-column hosting is RETIRED. It required a Bearer token handed over in
  control\dvtoken.tmp plus MSCRMCallerID / CallerObjectId impersonation headers, because
  an S2S (client_credentials) token cannot read a file column directly. That in turn
  forced prvActOnBehalfOfAnotherUser at GLOBAL scope onto the ABG Bay AGent role -- a
  standing privilege to act as any user in the org, held by an unattended kiosk PC, for
  the sole purpose of fetching a zip. Moving the package to GitHub removes the need for
  the token, the impersonation headers and the privilege.

INTEGRITY IS UNCHANGED BY THIS MOVE
  What protects the fleet is the SHA256 check below plus the Authenticode signing pass
  that follows it -- not the transport. The package bytes are identical whichever host
  serves them, so the expected hash does not change when hosting moves. A tampered or
  truncated download fails the hash and the script throws before anything is staged.

REMOTE INSTALL WITH NOBODY ON SITE (1.3.1, A0.437)
  Kevin, 2026-10-07: "I don't like that you need me to be at the Bay PC in order to update the BayAgent."
  Four changes make an update installable AND provable remotely:

  1. EVERY FILE IS COPIED, AND current\ IS VERIFIED BY HASH. Through 1.3.0 promotion used robocopy /MIR, which
     skips a file whose size and time match. The reproducible build gives every zip entry one fixed time and
     two releases' manifest.json were both 68 bytes, so 1.3.0 installed on Bay 1 and kept REPORTING 1.2.1.
     Promotion now copies every file whose bytes differ (robocopy, then an explicit copy of anything it left: /IS
     alone was MEASURED not to copy a same-size, same-time file) and the run is ok only if every file in current\
     (and every shipped tools\ file) hashes equal to releases\<version>.
  2. A SNAPSHOT OF WHAT IS RUNNING IS TAKEN FIRST (rollback\current, rollback\tools, rollback\snapshot.json,
     hash-verified). It is local and already signed, so a rollback needs no download and no live agent.
  3. current\ IS NEVER A LINK WHEN IT IS WRITTEN. ABG.ReleaseFinalize.ps1 can make current\ a junction to
     releases\<v>; a /MIR into it would overwrite that release, the very copy a rollback needs. The link is
     removed NON-recursively (the target is never touched) and replaced by a real folder first.
  4. A ROLLBACK GUARD WATCHES THE NEW AGENT (tools\Watch-BayAgentUpdate.ps1, launched from the snapshot so the
     package being installed cannot change it). It runs OUTSIDE the agent's process tree and scheduled task (its
     own per-user task, falling back to WMI): the restart that brings the new agent up ends \ABG Bay Agent and
     stops processes by command line, and the guard's at-logon trigger re-arms it if the bay reboots. It must
     confirm it is armed before anything is promoted; if it cannot arm, nothing is promoted and the run fails
     with stage "guard". If the new code does not prove itself back (an alive record carrying the hash of the
     script that ran, see BayAgent.ps1 Update-AgentAliveRecord) within -ConfirmTimeoutSeconds of time in which
     the cloud was reachable, the guard restores the snapshot and restarts the agent. Unreachable time does not
     count, so a network outage cannot roll back a healthy bay.
     -NoRollbackGuard installs the 1.3.0 way (no guard); -RollbackDrill rolls back on purpose after the new
     agent confirms, to prove the path (use it by reinstalling the SAME version).
  The fix runs on the install AFTER the one that ships it: installing 1.3.1 runs the 1.3.0 updater already on
  the bay. 1.3.1's manifest.json therefore differs in length from every earlier one, and the agent now reports
  the version constant in its own code.

#>

[CmdletBinding()]
param(
  [Parameter(Mandatory = $true)][string]$Version,
  [Parameter(Mandatory = $true)][string]$PackageUrl,
  [Parameter(Mandatory = $true)][string]$Sha256,

  [string]$BaseDir = "C:\AllBirdies\BayAgent",

  # If you provide -CertThumbprint we'll use that exact cert.
  [string]$CertThumbprint = "",

  # If you don't provide thumbprint, we find a Code Signing cert.
  # Optional hint to pick the right one if you have multiple.
  [string]$CertSubjectContains = "ABG",

  # Sign the promoted scripts in current\ (recommended for AllSigned)
  [switch]$SignAfterInstall = $true,

  # Create restart marker for watchdog/host
  [switch]$RequestRestart,

  # Logging
  # Empty means "derive from -BaseDir" (resolved just below). It used to be hardcoded to the default
  # install path, so an updater run against any other -BaseDir wrote its log into a DIFFERENT install's
  # log directory -- or into one that did not exist. On a real bay the two coincide, which is why it was
  # never noticed; it showed up the moment a test ran the updater against its own BaseDir and the failure
  # it was looking for had been written somewhere else entirely.
  [string]$LogPath = "",

  # Download retry count
  [int]$DownloadRetries = 3,

  # RFC 3161 timestamp server used when signing installed scripts. A timestamped
  # Authenticode signature stays valid after the signing certificate itself expires;
  # an untimestamped one does not. Must be HTTP, not HTTPS -- Set-AuthenticodeSignature
  # does not support HTTPS timestamp URLs. Override only if DigiCert's responder
  # endpoint moves or a different CA is used.
  [string]$TimeStampServer = "http://timestamp.digicert.com",

  # Rollback guard (1.3.1). Seconds of REACHABLE time the new agent has to prove itself back before the guard
  # restores the snapshot; the soak is how long one agent process must stay healthy to count as back.
  [int]$ConfirmTimeoutSeconds = 900,
  [int]$ConfirmSoakSeconds = 60,
  # Wall-clock cap: past this the guard gives up WITHOUT rolling back (the cloud was never reachable long enough
  # to judge, and rolling back cannot be shown to be better).
  [int]$GuardMaxWaitSeconds = 21600,
  [int]$GuardArmTimeoutSeconds = 60,
  [string]$GuardTaskName = "ABG BayAgent Update Guard",
  [switch]$NoRollbackGuard,
  [switch]$RollbackDrill
)

# NOTHING EXECUTABLE RUNS BEFORE THE TRAP BELOW IS ARMED WITH FUNCTIONS THAT EXIST.
# A trap is hoisted to the top of its script block, so it catches errors raised above the line it is
# written on -- at which point the functions it calls may not have been defined yet (MEASURED on Windows
# PowerShell 5.1, 2026-09-21). Set-StrictMode, $ErrorActionPreference and the $LogPath default used to sit
# here, above these definitions; any failure in them reached a trap that called three functions that did
# not exist, and the update died with nothing in the log and no last-update-result.json. Function
# definitions cannot throw, so they go first and the executable prologue goes after the trap.

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
    # Never block update due to logging
  }
}

function Get-Sha([string]$path) {
  return (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()
}

function Write-UpdateResult([bool]$ok, [string]$reason, [string]$stage, [hashtable]$extra = $null) {
  # THE DURABLE OUTCOME OF THIS RUN, and the only thing that can contradict a Succeeded BayCommand.
  #
  # A fleet update is triggered by StartProcess, whose result is written the instant powershell.exe launches.
  # Nothing downstream ever learns what this script then did. MEASURED 2026-09-14: on a bay PC with no
  # code-signing certificate, Get-CodeSigningCert throws, the script dies, and the command reports Succeeded
  # having installed nothing -- with not one line in the log, because the throw happened before any Write-Log
  # on that path. That is the bench-day failure: BENCH-01 is a fresh machine, and a fresh machine only has a
  # code-signing certificate if Day-0 setup ran.
  #
  # So every exit writes here, success or failure, and the agent carries it in the heartbeat as
  # lastUpdateResult. A version that did not install can then be SEEN rather than inferred from a bay that
  # keeps reporting its old version for no stated reason.
  try {
    $dir = Join-Path $BaseDir "state"
    Ensure-Dir $dir
    $obj = [ordered]@{
      ok        = $ok
      version   = $Version
      stage     = $stage
      reason    = $reason
      packageUrl = $PackageUrl
      utc       = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
      machine   = $env:COMPUTERNAME
    }
    if ($null -ne $extra) { foreach ($k in @($extra.Keys)) { $obj[[string]$k] = $extra[$k] } }
    $json = $obj | ConvertTo-Json -Depth 4
    [IO.File]::WriteAllText((Join-Path $dir "last-update-result.json"), $json, (New-Object Text.UTF8Encoding($false)))
  } catch {
    # A marker we cannot write must not itself break the update.
    Write-Log ("WARNING: could not write last-update-result.json: " + $_.Exception.Message)
  }
}

function Get-UpdateRunValue([string]$name, [string]$default) {
  # Run state the trap reports ($script:Stage, $script:InstallId). The trap is hoisted above the lines that set
  # them, so it reads them by name and falls back to a default rather than assume they exist yet.
  $v = Get-Variable -Name $name -Scope Script -ValueOnly -ErrorAction SilentlyContinue
  if ($null -eq $v -or [string]::IsNullOrWhiteSpace([string]$v)) { return $default }
  return [string]$v
}

function Set-PendingAbortedIfNotPromoting() {
  # A failure before promotion began must stand the rollback guard down (nothing changed in current\). After
  # promotion began the guard keeps watching: current\ may hold new code, and it is the guard's call.
  try {
    $id = Get-UpdateRunValue "InstallId" ""
    if ([string]::IsNullOrWhiteSpace($id)) { return }
    $pp = Join-Path $BaseDir "state\update-pending.json"
    if (-not (Test-Path -LiteralPath $pp)) { return }
    $po = [IO.File]::ReadAllText($pp) | ConvertFrom-Json
    if ([string]$po.installId -ne $id) { return }
    if ([string]$po.phase -ne "armed") { return }
    $po.phase = "aborted"
    [IO.File]::WriteAllText($pp, ($po | ConvertTo-Json -Depth 6), (New-Object Text.UTF8Encoding($false)))
  } catch { }
}

# Catches EVERY terminating error in the linear body below -- including the ones thrown before their own
# stage had logged anything. `break` re-throws after running, so the caller still sees a failure.
trap {
  $msg = $_.Exception.Message
  Write-Log ("UPDATE FAILED at stage " + (Get-UpdateRunValue "Stage" "unknown") + ": " + $msg)
  Set-PendingAbortedIfNotPromoting
  Write-UpdateResult -ok $false -reason $msg -stage (Get-UpdateRunValue "Stage" "unknown")
  break
}

$script:Stage = "start"
$script:InstallId = ""

# The executable prologue, moved below the trap so the trap is armed before anything can fail.
Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

if ([string]::IsNullOrWhiteSpace($LogPath)) { $LogPath = Join-Path $BaseDir "logs\Update-BayAgent.log" }

function Invoke-Robo([string]$src, [string]$dst, [string[]]$extraArgs) {
  Ensure-Dir $dst
  $args = @($src, $dst) + $extraArgs
  $p = Start-Process -FilePath "robocopy.exe" -ArgumentList $args -Wait -PassThru -NoNewWindow
  # Robocopy exit codes: 0-7 are success-ish; >=8 indicates failure
  if ($p.ExitCode -ge 8) { throw "Robocopy failed with exit code $($p.ExitCode)" }
  return $p.ExitCode
}

function Clear-StaleDataverseToken() {
  # BayAgent writes its live OAuth bearer token to control\dvtoken.tmp before launching
  # ANY powershell.exe StartProcess child, not just this one. Nothing else on the machine
  # deletes it. Downloads no longer need that token, so shred it on every run rather than
  # leaving a usable Dataverse credential sitting in plaintext on an unattended kiosk.
  # This is a strict improvement on the previous behaviour, which only deleted the file
  # when the package URL happened to be a Dataverse URL -- a GitHub-hosted update already
  # left it behind indefinitely.
  $tokenFile = Join-Path $BaseDir "control\dvtoken.tmp"
  try {
    if (Test-Path -LiteralPath $tokenFile) {
      Remove-Item -LiteralPath $tokenFile -Force -ErrorAction Stop
      Write-Log "Removed stale control\dvtoken.tmp (downloads no longer use a Dataverse token)."
    }
  } catch {
    Write-Log "WARNING: could not remove control\dvtoken.tmp: $($_.Exception.Message)"
  }
}

function Test-IsDataverseUrl([string]$url) {
  return ($url -match '\.crm\d*\.dynamics\.com/')
}

function Download-FileWithRetry([string]$url, [string]$outFile, [int]$retries) {
  [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

  # Dataverse file-column hosting is retired -- refuse it loudly rather than attempting a
  # fetch that can only ever 401. An S2S token cannot read a file column without
  # impersonation headers, and this script no longer sends them by design. Failing here
  # with an explanation beats three silent retries and a generic timeout.
  if (Test-IsDataverseUrl $url) {
    # NOTE the parentheses around the concatenation: "a" + "b" -f $x parses as "a" + ("b" -f $x),
    # which silently drops the placeholder and prints a URL-less message on an unmanned machine.
    $msg = ("PackageUrl points at Dataverse ({0}). Dataverse file-column hosting is retired: " +
            "this script no longer impersonates a user to read file columns. Publish the package " +
            "as a GitHub Release asset and set the Fleet.BayAgent.PackageUrl ConfigItem to that " +
            "URL -- the SHA256 does not change, because the package bytes do not change.")
    throw ($msg -f $url)
  }

  $lastErr = $null
  for ($i = 1; $i -le $retries; $i++) {
    try {
      Write-Log "Downloading (attempt $i/$retries): $url"
      Invoke-WebRequest -Uri $url -OutFile $outFile -UseBasicParsing -MaximumRedirection 10
      if (-not (Test-Path -LiteralPath $outFile)) { throw "Download completed but file missing: $outFile" }
      if ((Get-Item -LiteralPath $outFile).Length -lt 100) { Write-Log "Warning: downloaded file is very small (<100 bytes). Verify URL." }
      return
    } catch {
      $lastErr = $_
      Write-Log "Download attempt $i failed: $($_.Exception.Message)"
      Start-Sleep -Seconds ([Math]::Min(10, 2 * $i))
    }
  }
  throw "Failed to download after $retries attempts. Last error: $($lastErr.Exception.Message)"
}

function Get-CodeSigningCert() {
  if (-not [string]::IsNullOrWhiteSpace($CertThumbprint)) {
    $tp = $CertThumbprint.Replace(" ", "")
    $c = Get-ChildItem Cert:\LocalMachine\My\$tp -ErrorAction SilentlyContinue
    if (-not $c) { throw "Code signing cert not found by thumbprint in LocalMachine\My: $CertThumbprint" }
    return $c
  }

  $cands = @(Get-ChildItem Cert:\LocalMachine\My | Where-Object {
      $_.EnhancedKeyUsageList.FriendlyName -contains "Code Signing"
    })

  if ($cands.Count -eq 0) {
    throw "No Code Signing certificate found in Cert:\LocalMachine\My"
  }

  if (-not [string]::IsNullOrWhiteSpace($CertSubjectContains)) {
    $filtered = @($cands | Where-Object { $_.Subject -like "*$CertSubjectContains*" })
    if ($filtered.Count -gt 0) { $cands = $filtered }
  }

  # pick the one with the latest expiry
  return ($cands | Sort-Object NotAfter -Descending | Select-Object -First 1)
}

function Sign-File([string]$path, $cert, [string]$timeStampServer) {
  if (-not (Test-Path -LiteralPath $path)) { return $false }
  $ext = [IO.Path]::GetExtension($path).ToLowerInvariant()
  if ($ext -notin @(".ps1", ".psm1", ".psd1")) { return $false }

  # Signing modifies file content: do it only after all copying is complete.
  Set-AuthenticodeSignature -FilePath $path -Certificate $cert -TimeStampServer $timeStampServer | Out-Null
  $sig = Get-AuthenticodeSignature -FilePath $path

  if ($sig.Status -ne "Valid") {
    throw "Signature invalid for $path. Status=$($sig.Status) Message=$($sig.StatusMessage)"
  }
  if ($null -eq $sig.TimeStamperCertificate) {
    # Set-AuthenticodeSignature can silently sign WITHOUT a timestamp and still report
    # Status=Valid if the timestamp server was unreachable or rejected the request --
    # that untimestamped signature stops validating the moment the signing cert expires.
    # Hard-fail rather than ship that silently.
    throw "Signature for $path is Valid but UNTIMESTAMPED (server: $timeStampServer). Refusing to ship an untimestamped release -- it would stop validating when the signing certificate expires."
  }

  return $true
}

# ------------------ 1.3.1 helpers: hashes, links, snapshot, rollback guard ------------------

function Write-JsonFileAtomic([string]$path, $obj) {
  # Readers (the guard, the agent) must never see half a file: write beside it, then replace.
  Ensure-Dir (Split-Path -Parent $path)
  $tmp = "$path.tmp"
  [IO.File]::WriteAllText($tmp, ($obj | ConvertTo-Json -Depth 8), (New-Object Text.UTF8Encoding($false)))
  # [NullString]::Value, not $null: PowerShell passes $null to a .NET string parameter as "", and File.Replace then
  # throws "The path is not of a legal form" on every call (MEASURED 2026-10-07; the agent's own copies of this line had
  # silently fallen back to a non-atomic overwrite since they were written).
  if (Test-Path -LiteralPath $path) { [IO.File]::Replace($tmp, $path, [NullString]::Value, $true) }
  else { [IO.File]::Move($tmp, $path) }
}

function Get-TreeHashes([string]$root) {
  # Relative path (lower case, backslashes) -> SHA256 of every file under $root. An absent root is an empty tree.
  $map = @{}
  if (-not (Test-Path -LiteralPath $root)) { return $map }
  $full = (Get-Item -LiteralPath $root -Force).FullName.TrimEnd('\')
  foreach ($f in @(Get-ChildItem -LiteralPath $root -Recurse -File -Force)) {
    $rel = $f.FullName.Substring($full.Length).TrimStart('\').ToLowerInvariant()
    $map[$rel] = Get-Sha $f.FullName
  }
  return $map
}

function Compare-TreeHashes([hashtable]$expected, [hashtable]$actual, [switch]$AllowExtra) {
  # Returns the differences as text; empty means equal. With -AllowExtra, files only in $actual are ignored
  # (tools\ holds scripts the package does not ship).
  $diffs = @()
  foreach ($k in @($expected.Keys | Sort-Object)) {
    if (-not $actual.ContainsKey($k)) { $diffs += "missing $k" }
    elseif ($actual[$k] -ne $expected[$k]) { $diffs += "different $k" }
  }
  if (-not $AllowExtra) {
    foreach ($k in @($actual.Keys | Sort-Object)) { if (-not $expected.ContainsKey($k)) { $diffs += "extra $k" } }
  }
  return $diffs
}

function Sync-TreeExact([string]$src, [string]$dst, [switch]$Mirror) {
  # Make every file of $src present in $dst with the SAME BYTES. robocopy does the bulk (and, with -Mirror, removes
  # files $src does not have); then any file whose hash still differs is copied explicitly.
  # WHY THE SECOND STEP: robocopy decides "same" from size and time, and /IS ("include same files") does NOT make it
  # copy such a file. MEASURED 2026-10-07 on Windows 11 (26300): a same-size, same-time file with different bytes
  # stayed as it was under /MIR /IS /IT and /E /IS /IT (it copied only with /IM, which keys on the NTFS change time).
  # That is F1 exactly, so the fix cannot rest on a robocopy flag; the callers verify by hash afterwards as well.
  $mode = $(if ($Mirror) { "/MIR" } else { "/E" })
  Invoke-Robo $src $dst @($mode, "/IS", "/IT", "/IM", "/R:5", "/W:2", "/NP") | Out-Null
  $srcFull = (Get-Item -LiteralPath $src -Force).FullName.TrimEnd('\')
  $dstFull = (Get-Item -LiteralPath $dst -Force).FullName.TrimEnd('\')
  $fixed = 0
  foreach ($f in @(Get-ChildItem -LiteralPath $src -Recurse -File -Force)) {
    $rel = $f.FullName.Substring($srcFull.Length).TrimStart('\')
    $target = Join-Path $dstFull $rel
    if ((Test-Path -LiteralPath $target) -and ((Get-Sha $target) -eq (Get-Sha $f.FullName))) { continue }
    Ensure-Dir (Split-Path -Parent $target)
    [IO.File]::Copy($f.FullName, $target, $true)
    $fixed++
  }
  if ($fixed -gt 0) { Write-Log ("Copied {0} file(s) robocopy left unchanged into {1}" -f $fixed, $dst) }
  return $fixed
}

function Test-IsLink([string]$path) {
  if (-not (Test-Path -LiteralPath $path)) { return $false }
  $it = Get-Item -LiteralPath $path -Force
  return (($it.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0)
}

function Convert-LinkToFolder([string]$linkPath, [string]$fillFrom) {
  # R-D (1.3.0 attack): current\ may be a junction into releases\<v>. Remove ONLY the link -- Directory.Delete with
  # recursive=$false removes the reparse point and never follows it -- then make a real folder holding exactly the
  # snapshot of what was running. A recursive delete here would wipe the release the link pointed at.
  if (-not (Test-IsLink $linkPath)) { return $false }
  $target = ""
  try { $target = (@((Get-Item -LiteralPath $linkPath -Force).Target) -join ";") } catch { }
  Write-Log "current\ is a link (target: $target). Removing the link only, then making a real folder."
  [IO.Directory]::Delete($linkPath, $false)
  if (Test-Path -LiteralPath $linkPath) { throw "could not remove the link at $linkPath" }
  Ensure-Dir $linkPath
  [void](Sync-TreeExact -src $fillFrom -dst $linkPath -Mirror)
  $d = @(Compare-TreeHashes (Get-TreeHashes $fillFrom) (Get-TreeHashes $linkPath))
  if ($d.Count -gt 0) { throw ("current\ rebuilt from the snapshot does not match it: " + ($d -join "; ")) }
  return $true
}

function Read-JsonFileOrNull([string]$path) {
  if (-not (Test-Path -LiteralPath $path)) { return $null }
  try { return ([IO.File]::ReadAllText($path) | ConvertFrom-Json) } catch { return $null }
}

function Test-GuardProcessAlive($guardState) {
  # Is the guard named in update-guard.json still running? Matched by pid AND command line, so a reused pid
  # does not count. Anything unreadable is "not alive": a stale pending file must not block updates forever.
  try {
    $gp = [int]$guardState.pid
    if ($gp -le 0) { return $false }
    $p = Get-CimInstance Win32_Process -Filter ("ProcessId={0}" -f $gp) -ErrorAction Stop
    if ($null -eq $p) { return $false }
    return ([string]$p.CommandLine -match 'Watch-BayAgentUpdate\.ps1')
  } catch { return $false }
}

function Get-UpdateGuardArguments([string]$guardScript, [string]$installId, [string]$taskName) {
  # The guard runs under the bay's AllSigned policy like everything else: no -ExecutionPolicy, -File only.
  return ('-NoProfile -NonInteractive -WindowStyle Hidden -File "{0}" -InstallId {1} -BaseDir "{2}" -TaskName "{3}"' -f $guardScript, $installId, $BaseDir.TrimEnd('\'), $taskName)
}

function Start-UpdateGuard([string]$guardScript, [string]$installId) {
  # Launch the guard OUTSIDE this process tree. The agent is restarted by HostWatchdog ending the \ABG Bay Agent
  # scheduled task and stopping processes by command line, so the guard must belong to neither. MEASURED 2026-10-07
  # (Windows 11 26300, tests\BayAgent.UpdateGuard.Tests.ps1 K): ending a task did NOT stop a plain child it had
  # started, but nothing here relies on that either way. First choice: a per-user scheduled task (its own task; an
  # at-logon trigger re-arms it after a reboot). Fallback: WMI Win32_Process.Create (a child of the WMI host).
  $psExe = Join-Path $env:WINDIR "System32\WindowsPowerShell\v1.0\powershell.exe"
  $argLine = Get-UpdateGuardArguments $guardScript $installId $GuardTaskName
  $errors = @()
  try {
    $userId = "{0}\{1}" -f $env:USERDOMAIN, $env:USERNAME
    $action = New-ScheduledTaskAction -Execute $psExe -Argument $argLine -WorkingDirectory $BaseDir
    $trigger = New-ScheduledTaskTrigger -AtLogOn -User $userId
    $principal = New-ScheduledTaskPrincipal -UserId $userId -LogonType Interactive -RunLevel Limited
    $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable `
      -MultipleInstances IgnoreNew -ExecutionTimeLimit (New-TimeSpan -Hours 8)
    Register-ScheduledTask -TaskName $GuardTaskName -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Force -ErrorAction Stop | Out-Null
    Start-ScheduledTask -TaskName $GuardTaskName -ErrorAction Stop
    return "scheduledTask"
  } catch { $errors += ("scheduledTask: " + $_.Exception.Message) }
  try {
    $cl = ('"{0}" {1}' -f $psExe, $argLine)
    $r = Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{ CommandLine = $cl; CurrentDirectory = $BaseDir } -ErrorAction Stop
    if ([int]$r.ReturnValue -ne 0) { throw ("Win32_Process.Create returned {0}" -f $r.ReturnValue) }
    return "wmi"
  } catch { $errors += ("wmi: " + $_.Exception.Message) }
  throw ("the rollback guard could not be launched: " + ($errors -join " | "))
}

function Wait-GuardArmed([string]$installId, [int]$timeoutSec) {
  $gpath = Join-Path $BaseDir "state\update-guard.json"
  $deadline = (Get-Date).AddSeconds($timeoutSec)
  do {
    $g = Read-JsonFileOrNull $gpath
    if ($null -ne $g -and [string]$g.installId -eq $installId -and [string]$g.state -in @("armed", "watching")) { return $g }
    Start-Sleep -Milliseconds 500
  } while ((Get-Date) -lt $deadline)
  return $null
}

function Restore-FromSnapshot([string]$snapCurrent, [string]$snapTools) {
  # Put back exactly what was running before this run touched current\. Returns the differences left (empty = ok).
  if (Test-IsLink $CurrentDir) { [IO.Directory]::Delete($CurrentDir, $false) }
  [void](Sync-TreeExact -src $snapCurrent -dst $CurrentDir -Mirror)
  $d = @(Compare-TreeHashes (Get-TreeHashes $snapCurrent) (Get-TreeHashes $CurrentDir))
  if (Test-Path -LiteralPath $snapTools) {
    [void](Sync-TreeExact -src $snapTools -dst $ToolsDir)
    $d += @(Compare-TreeHashes (Get-TreeHashes $snapTools) (Get-TreeHashes $ToolsDir) -AllowExtra)
  }
  return $d
}

# ------------------ MAIN ------------------

Write-Log "----"
Write-Log "Starting update. Version=$Version Url=$PackageUrl BaseDir=$BaseDir SignAfterInstall=$([bool]$SignAfterInstall) TimeStampServer=$TimeStampServer RequestRestart=$([bool]$RequestRestart)"

# Standard folders
$StagingDir  = Join-Path $BaseDir "staging"
$ReleasesDir = Join-Path $BaseDir "releases"
$CurrentDir  = Join-Path $BaseDir "current"
$ControlDir  = Join-Path $BaseDir "control"

Ensure-Dir $BaseDir
Ensure-Dir $StagingDir
Ensure-Dir $ReleasesDir
Ensure-Dir $CurrentDir
Ensure-Dir $ControlDir

# Downloads are unauthenticated now; shred any bearer token BayAgent left for us.
Clear-StaleDataverseToken

# Paths for this version
$zipPath   = Join-Path $StagingDir ("BayAgent-{0}.zip" -f $Version)
$expandDir = Join-Path $StagingDir ("expand-{0}" -f $Version)
$relDir    = Join-Path $ReleasesDir $Version

# Download
Download-FileWithRetry -url $PackageUrl -outFile $zipPath -retries $DownloadRetries

# Verify SHA
$actual   = Get-Sha $zipPath
$expected = $Sha256.ToLowerInvariant().Replace(" ", "")
Write-Log "SHA expected=$expected actual=$actual"
if ($actual -ne $expected) { throw "SHA256 mismatch. Expected $expected, got $actual" }

# Expand
Write-Log "Expanding zip to $expandDir"
if (Test-Path -LiteralPath $expandDir) { Remove-Item -LiteralPath $expandDir -Recurse -Force }
Ensure-Dir $expandDir
Expand-Archive -LiteralPath $zipPath -DestinationPath $expandDir -Force

# Determine content root (zip root vs single top folder)
$contentRoot = $expandDir
$children = @(Get-ChildItem -LiteralPath $expandDir)
if ($children.Count -eq 1 -and $children[0].PSIsContainer) {
  $contentRoot = $children[0].FullName
}
Write-Log "Content root is $contentRoot"

# Sanity check
if (-not (Test-Path -LiteralPath (Join-Path $contentRoot "BayAgent.ps1"))) {
  Write-Log "WARNING: BayAgent.ps1 not found at content root. Files: $(@(Get-ChildItem -LiteralPath $contentRoot | Select-Object -ExpandProperty Name) -join ', ')"
  throw "Package missing BayAgent.ps1 at expected location. Check zip structure."
}
if (-not (Test-Path -LiteralPath (Join-Path $contentRoot "manifest.json"))) {
  Write-Log "WARNING: manifest.json not found at content root. The agent may report an old version."
  # We don't hard-fail because you might not be using manifest for versioning yet.
}

# ---- Snapshot what is running (1.3.1) ----
# Taken BEFORE releases\<version> is touched: if current\ is a link into releases\<version> (a reinstall of the same
# version), the staging step below would otherwise delete the very files the agent is running.
$script:Stage = "snapshot"
$RollbackDir  = Join-Path $BaseDir "rollback"
$SnapCurrent  = Join-Path $RollbackDir "current"
$SnapTools    = Join-Path $RollbackDir "tools"
$SnapManifest = Join-Path $RollbackDir "snapshot.json"
$PendingPath  = Join-Path $BaseDir "state\update-pending.json"
$GuardPath    = Join-Path $BaseDir "state\update-guard.json"
$ToolsDir     = Join-Path $BaseDir "tools"

# One update at a time: a guard still watching the previous install owns rollback\ (its snapshot is the only copy
# of the code that last proved itself), so overwriting it now would make "the last good version" whatever was
# installed a minute ago.
$prevPending = Read-JsonFileOrNull $PendingPath
if ($null -ne $prevPending -and [string]$prevPending.phase -in @("armed", "promoting", "promoted")) {
  $prevGuard = Read-JsonFileOrNull $GuardPath
  if ($null -ne $prevGuard -and [string]$prevGuard.installId -eq [string]$prevPending.installId -and (Test-GuardProcessAlive $prevGuard)) {
    $script:Stage = "guard-busy"
    throw ("the rollback guard for the previous install (version {0}, installId {1}) is still watching; wait for it to finish (state\update-guard.json) and retry" -f $prevPending.version, $prevPending.installId)
  }
  Write-Log ("A pending record from install {0} has no live guard; treating it as stale." -f $prevPending.installId)
}

$haveSnapshot = $false
$snapAgentSha = $null
if (Test-Path -LiteralPath (Join-Path $CurrentDir "BayAgent.ps1")) {
  Write-Log "Snapshotting current\ and tools\ into $RollbackDir"
  if (Test-IsLink $RollbackDir) { [IO.Directory]::Delete($RollbackDir, $false) }
  Ensure-Dir $RollbackDir
  [void](Sync-TreeExact -src $CurrentDir -dst $SnapCurrent -Mirror)
  $curMapBefore = Get-TreeHashes $CurrentDir
  $snapCurMap = Get-TreeHashes $SnapCurrent
  $d1 = @(Compare-TreeHashes $curMapBefore $snapCurMap)
  if ($d1.Count -gt 0) { throw ("the snapshot of current\ does not match it: " + ($d1 -join "; ")) }
  $snapToolsMap = @{}
  if (Test-Path -LiteralPath $ToolsDir) {
    [void](Sync-TreeExact -src $ToolsDir -dst $SnapTools -Mirror)
    $snapToolsMap = Get-TreeHashes $SnapTools
    $d2 = @(Compare-TreeHashes (Get-TreeHashes $ToolsDir) $snapToolsMap)
    if ($d2.Count -gt 0) { throw ("the snapshot of tools\ does not match it: " + ($d2 -join "; ")) }
  }
  $snapAgentSha = $snapCurMap["bayagent.ps1"]
  $snapManifestVersion = $null
  $sm = Read-JsonFileOrNull (Join-Path $SnapCurrent "manifest.json")
  if ($null -ne $sm) { $snapManifestVersion = [string]$sm.version }
  Write-JsonFileAtomic $SnapManifest ([ordered]@{
    takenUtc        = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
    forVersion      = $Version
    agentSha256     = $snapAgentSha
    manifestVersion = $snapManifestVersion
    current         = $snapCurMap
    tools           = $snapToolsMap
  })
  $haveSnapshot = $true
} else {
  Write-Log "No current\BayAgent.ps1: a first install, nothing to snapshot (and nothing to roll back to)."
}

# ---- current\ must be a real folder before anything is written through it (R-D) ----
$script:Stage = "unlink"
if ($haveSnapshot -and (Test-IsLink $CurrentDir)) {
  [void](Convert-LinkToFolder -linkPath $CurrentDir -fillFrom $SnapCurrent)
}

# Stage into releases\<version>
$script:Stage = "stage"
Write-Log "Staging into release folder $relDir"
if (Test-Path -LiteralPath $relDir) { Remove-Item -LiteralPath $relDir -Recurse -Force }
Ensure-Dir $relDir
Invoke-Robo $contentRoot $relDir @("/MIR") | Out-Null

# ---- Sign in release folder first (safe) ----
$script:Stage = "sign"
$signCount = 0
if ($SignAfterInstall) {
  Write-Log "Signing enabled. Locating code-signing certificate..."
  $cert = Get-CodeSigningCert
  Write-Log "Using cert Subject=$($cert.Subject) Thumbprint=$($cert.Thumbprint) NotAfter=$($cert.NotAfter)"

  # Sign BayAgent.ps1 inside the release folder first
  $relAgentPath = Join-Path $relDir "BayAgent.ps1"
  if (-not (Test-Path $relAgentPath)) { throw "Release missing BayAgent.ps1: $relAgentPath" }

  if (Sign-File -path $relAgentPath -cert $cert -timeStampServer $TimeStampServer) { $signCount++ }

  # Sign any shipped modules/scripts in the release folder too
  $toSign = @(Get-ChildItem -LiteralPath $relDir -Recurse -File |
    Where-Object { $_.Extension -in ".ps1", ".psm1", ".psd1" })

  foreach ($f in $toSign) {
    if ($f.FullName -ieq $relAgentPath) { continue }
    if (Sign-File -path $f.FullName -cert $cert -timeStampServer $TimeStampServer) { $signCount++ }
  }

  # Verify the release agent signature is Valid AND timestamped before touching current
  $sig = Get-AuthenticodeSignature -FilePath $relAgentPath
  if ($sig.Status -ne "Valid") {
    throw "Release BayAgent.ps1 signature invalid ($($sig.Status)): $($sig.StatusMessage)"
  }
  if ($null -eq $sig.TimeStamperCertificate) {
    throw "Release BayAgent.ps1 signature is Valid but UNTIMESTAMPED. Refusing to promote to current."
  }

  Write-Log "Signing complete in release folder. SignedFiles=$signCount"
}

# The bytes current\ must hold after promotion (taken after signing: signing rewrites the files).
$relMap = Get-TreeHashes $relDir
$newAgentSha = $relMap["bayagent.ps1"]

# ---- Arm the rollback guard BEFORE promotion (1.3.1) ----
$script:Stage = "guard"
$guardMode = "off"
$guardNote = ""
$script:InstallId = [guid]::NewGuid().ToString()
if ($NoRollbackGuard) {
  $guardNote = "-NoRollbackGuard"
} elseif (-not $haveSnapshot) {
  $guardNote = "first install: nothing to roll back to"
} elseif (-not $RequestRestart) {
  $guardNote = "no -RequestRestart: the new code would not run until a later restart, so there is nothing to watch"
} else {
  $guardScript = Join-Path $SnapTools "Watch-BayAgentUpdate.ps1"
  if (-not (Test-Path -LiteralPath $guardScript)) {
    throw ("the rollback guard is not installed ({0}); install with -NoRollbackGuard to proceed without automatic rollback" -f $guardScript)
  }
  Write-JsonFileAtomic $PendingPath ([ordered]@{
    installId             = $script:InstallId
    version               = $Version
    packageUrl            = $PackageUrl
    phase                 = "armed"
    createdUtc            = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
    promotingUtc          = $null
    expectedAgentSha256   = $newAgentSha
    snapshotAgentSha256   = $snapAgentSha
    confirmTimeoutSeconds = $ConfirmTimeoutSeconds
    soakSeconds           = $ConfirmSoakSeconds
    maxWaitSeconds        = $GuardMaxWaitSeconds
    drill                 = [bool]$RollbackDrill
    updaterPid            = $PID
  })
  $launcher = Start-UpdateGuard -guardScript $guardScript -installId $script:InstallId
  Write-Log "Rollback guard launched via $launcher; waiting up to $GuardArmTimeoutSeconds s for it to arm."
  $armed = Wait-GuardArmed -installId $script:InstallId -timeoutSec $GuardArmTimeoutSeconds
  if ($null -eq $armed) {
    # Leave no task behind that could start a guard later for an install that never happened.
    if ($launcher -eq "scheduledTask") { try { Unregister-ScheduledTask -TaskName $GuardTaskName -Confirm:$false -ErrorAction Stop } catch { } }
    throw ("the rollback guard did not arm within {0} s (launched via {1}); nothing was promoted. Install with -NoRollbackGuard to proceed without automatic rollback." -f $GuardArmTimeoutSeconds, $launcher)
  }
  $guardMode = "armed"
  $guardNote = ("pid {0} via {1}" -f $armed.pid, $launcher)
}
Write-Log "Rollback guard: $guardMode ($guardNote)"

function Set-PendingPhase([string]$phase) {
  if ($guardMode -ne "armed") { return }
  $po = Read-JsonFileOrNull $PendingPath
  if ($null -eq $po -or [string]$po.installId -ne $script:InstallId) { throw "the pending record changed under this run" }
  $po.phase = $phase
  if ($phase -eq "promoting") { $po.promotingUtc = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ") }
  Write-JsonFileAtomic $PendingPath $po
}

# ---- Promote release -> current only after signing succeeded ----
# Every file is made byte-equal (Sync-TreeExact): /MIR alone skips a file whose size and time match, which is how 1.3.0
# kept a 1.2.1 manifest.json (F1). Then current\ must hash equal to the release, file for file, or the run is not ok.
$script:Stage = "promote"
Set-PendingPhase "promoting"
Write-Log "Promoting SIGNED release -> current ($CurrentDir)"
$promoteError = $null
try {
  [void](Sync-TreeExact -src $relDir -dst $CurrentDir -Mirror)
  $curDiff = @(Compare-TreeHashes $relMap (Get-TreeHashes $CurrentDir))
  if ($curDiff.Count -gt 0) { $promoteError = ("current\ does not match releases\{0} after promotion: {1}" -f $Version, ($curDiff -join "; ")) }
} catch { $promoteError = ("promotion failed: " + $_.Exception.Message) }

if ($null -ne $promoteError) {
  # Put back what was running, here and now, rather than leave a half-promoted current\ for the next restart.
  $restored = $false
  $restoreDetail = "no snapshot"
  if ($haveSnapshot) {
    try {
      $left = @(Restore-FromSnapshot -snapCurrent $SnapCurrent -snapTools $SnapTools)
      $restored = ($left.Count -eq 0)
      $restoreDetail = $(if ($restored) { "restored from the snapshot, verified by hash" } else { "restore incomplete: " + ($left -join "; ") })
    } catch { $restoreDetail = "restore failed: " + $_.Exception.Message }
  }
  if ($guardMode -eq "armed") {
    # Restored: the guard has nothing left to watch. Not restored: leave it watching (it may still put things back).
    if ($restored) { try { Set-PendingPhase "aborted" } catch { } }
  }
  $script:Stage = "verify"
  Write-Log ("UPDATE FAILED at promotion: {0} ({1})" -f $promoteError, $restoreDetail)
  Write-UpdateResult -ok $false -reason ("{0}; {1}" -f $promoteError, $restoreDetail) -stage "verify" -extra @{ installId = $script:InstallId; restored = $restored; guard = $guardMode }
  exit 1
}
Write-Log "current\ verified: every file hashes equal to releases\$Version (agent $newAgentSha)."

# ---- If the package ships a tools/ folder, merge into $BaseDir\tools ----
$script:Stage = "tools"
$pkgTools = Join-Path $relDir "tools"
if (Test-Path -LiteralPath $pkgTools) {
  $destTools = Join-Path $BaseDir "tools"
  Ensure-Dir $destTools
  Write-Log "Package includes tools/ -- merging into $destTools"
  # /E (no -Mirror) so scripts not in the package are not deleted; every shipped file made byte-equal (Sync-TreeExact).
  [void](Sync-TreeExact -src $pkgTools -dst $destTools)
  $toolDiff = @(Compare-TreeHashes (Get-TreeHashes $pkgTools) (Get-TreeHashes $destTools) -AllowExtra)
  if ($toolDiff.Count -gt 0) { throw ("tools\ does not match the package after the merge: " + ($toolDiff -join "; ")) }
  Write-Log "Tools merge complete and verified."
}

# Request restart (watchdog/host should honor)
$script:Stage = "restart"
if ($RequestRestart) {
  Set-PendingPhase "promoted"
  $marker = Join-Path $ControlDir "restart.host"
  $msg = "restart requested $(Get-Date).ToUniversalTime().ToString('s')Z version=$Version"
  Set-Content -LiteralPath $marker -Value $msg -Encoding UTF8
  Write-Log "Wrote restart marker: $marker"
}

$script:Stage = "complete"
Write-UpdateResult -ok $true -reason "" -stage "complete" -extra @{
  installId     = $script:InstallId
  verified      = $true
  agentSha256   = $newAgentSha
  guard         = $guardMode
  guardNote     = $guardNote
  snapshotSha256 = $snapAgentSha
}
Write-Log "Update complete OK. Version=$Version Guard=$guardMode"
Write-Output ("OK: Updated BayAgent to {0}. ReleaseDir={1}. CurrentDir={2}. SignedFiles={3}. RestartRequested={4}. Verified=True. Guard={5}" -f $Version, $relDir, $CurrentDir, $signCount, [bool]$RequestRestart, $guardMode)
