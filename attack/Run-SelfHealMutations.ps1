# Mutation runner for the A0.327 Phase 2 self-heal section. Mutates a COPY of BayAgent.ps1 (the worktree is never
# touched), runs the named suite against the copy with -AgentScript, and scores only finished runs:
#   KILLED   = the suite printed RESULT with failed > 0
#   SURVIVED = the suite printed RESULT with failed = 0
#   ERROR    = no RESULT line (a crash or a hang is not a kill)
# Every anchor must match exactly once or the mutant is NOT-APPLIED and the run exits non-zero. Hyphens only.
# Results and mutant copies go to -WorkDir (default %TEMP%\bayagent-selfheal-mut), never into the repo.
# Expect column: KILLED, SURVIVED (the baseline), or EITHER (a single layer of a check that is enforced twice;
# its all-layers twin must be KILLED). Measured 2026-10-02 at cf6839b: 49 killed of 52; survivors M15a, M16a and
# M23 are single layers of checks enforced two or three times, and their all-layer twins M15d, M16c, M23c are killed.
# Fix round (2026-10-02, verifier F1/R1/R2/R7): F1a-F1i, R2a, R2b, R7a, and V01/V05/V07 on the live suite.
[CmdletBinding()]
param([string]$Only = "", [string]$Repo = "", [string]$WorkDir = "", [string]$ResultsName = "mutation-results.txt", [string]$LockName = "mutation.lock")

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

if ([string]::IsNullOrWhiteSpace($Repo)) { $Repo = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path }
if ([string]::IsNullOrWhiteSpace($WorkDir)) { $WorkDir = Join-Path $env:TEMP "bayagent-selfheal-mut" }
New-Item -ItemType Directory -Force -Path $WorkDir | Out-Null
$Lane = $WorkDir
$Results = Join-Path $Lane $ResultsName
$Src = Join-Path $Repo "src\BayAgent"
$SuiteSelfHeal = Join-Path $Repo "tests\BayAgent.SelfHeal.Tests.ps1"
$SuiteLaunch = Join-Path $Repo "tests\BayAgent.Launch.Tests.ps1"
$SuiteLive = Join-Path $Repo "tests\BayAgent.SelfHeal.Live.Tests.ps1"

function M([string]$Id, [string]$Why, [string[]]$From, [string[]]$To, [string]$Suite = "selfheal", [string]$Expect = "KILLED") {
    return [pscustomobject]@{ Id = $Id; Why = $Why; From = $From; To = $To; Suite = $Suite; Expect = $Expect }
}

$Muts = @(
    (M "M00" "baseline (no change)" @() @() "selfheal" "SURVIVED")
    (M "M01" "freeze threshold 10 s" @('$unrespFor -ge $Settings.UnresponsiveSeconds -and $quietFor -ge $Settings.UnresponsiveSeconds') @('$unrespFor -ge 10 -and $quietFor -ge 10'))
    (M "M02" "work signs ignored" @('$busy = $cpuBusy -or $ioBusy') @('$busy = $false'))
    (M "M03" "disk reads ignored" @('$busy = $cpuBusy -or $ioBusy') @('$busy = $cpuBusy'))
    (M "M04a" "unreadable CPU counts as idle" @('    $cpuBusy = $true') @('    $cpuBusy = $false'))
    (M "M04b" "unreadable disk counts as idle" @('    $ioBusy = $true') @('    $ioBusy = $false'))
    (M "M05" "no launch grace" @('-lt $Settings.LaunchGraceSeconds') @('-lt 0'))
    (M "M06" "cannot-tell counts as not responding" @('if ($null -eq $Sample.Responding) {') @('if ($false) {'))
    (M "M07" "reading gap ignored" @('$gapOk = ($null -ne $prevAt) -and (($Now - $prevAt).TotalSeconds -le $Settings.MaxSampleGapSeconds)') @('$gapOk = ($null -ne $prevAt)'))
    (M "M08" "no 180 s bound for a busy hang" @('if ($unrespFor -ge $Settings.LoadingMaxSeconds) {') @('if ($false) {'))
    (M "M09" "no rate limit" @('$allowed = ($inWindow.Count -lt $MaxRestarts)') @('$allowed = $true'))
    (M "M10" "empty window" @('$_ -gt $cut }') @('$_ -gt $Now }'))
    (M "M11" "restart count not reloaded" @('$script:SelfHealRuntime.History = Read-SelfHealState -Now $Now -MaxRestarts $script:SelfHealSettings.MaxRestarts') @('$script:SelfHealRuntime.History = [DateTime[]]@()'))
    (M "M12" "corrupt count reads as zero" @('$hist = @(); for ($i = 0; $i -lt [Math]::Max(1, $MaxRestarts); $i++) { $hist += $Now }') @('$hist = @()'))
    (M "M13" "unresponsiveSeconds floor removed" @('"unresponsiveSeconds" 30 30 600') @('"unresponsiveSeconds" 30 1 600'))
    (M "M14" "maxRestarts cap removed" @('"maxRestarts" 2 0 2') @('"maxRestarts" 2 0 20'))
    (M "M15a" "tick session filter removed (closer still checks)" @('if ($null -eq $layer.OwnSessionId -or $pi.SessionId -ne $layer.OwnSessionId) { continue }') @('if ($false) { continue }') "selfheal" "EITHER")
    (M "M15b" "closer session check removed" @('if ($null -eq $Layer.OwnSessionId -or $ProcInfo.SessionId -ne $Layer.OwnSessionId) {') @('if ($false) {'))
    (M "M15c" "both session checks removed" @('if ($null -eq $layer.OwnSessionId -or $pi.SessionId -ne $layer.OwnSessionId) { continue }', 'if ($null -eq $Layer.OwnSessionId -or $ProcInfo.SessionId -ne $Layer.OwnSessionId) {') @('if ($false) { continue }', 'if ($false) {'))
    (M "M16a" "tick self filter removed (closer still checks)" @('if ([int]$pi.Id -eq $PID) { continue }') @('if ($false) { continue }') "selfheal" "EITHER")
    (M "M16b" "closer self check removed" @('if ([int]$ProcInfo.Id -eq $PID) {') @('if ($false) {'))
    (M "M16c" "both self checks removed" @('if ([int]$pi.Id -eq $PID) { continue }', 'if ([int]$ProcInfo.Id -eq $PID) {') @('if ($false) { continue }', 'if ($false) {'))
    (M "M17" "start-time re-check removed" @('if ($null -eq $fresh.StartTimeUtc -or $fresh.StartTimeUtc -ne $ProcInfo.StartTimeUtc) {') @('if ($false) {'))
    (M "M18" "name re-check removed" @('if ([string]$fresh.Name -ine [string]$ProcInfo.Name) {') @('if ($false) {'))
    (M "M19a" "config deny list removed" @('foreach ($d in $SelfHealDenyNames) { if ($n -ieq $d) { return $null } }') @('# MUTANT deny removed'))
    (M "M19b" "closer deny list removed" @('foreach ($d in $SelfHealDenyNames) { if ($name -ieq $d) { return $false } }') @('# MUTANT deny removed'))
    (M "M20" "name shape check removed" @("if (`$n -notmatch '^[A-Za-z0-9][A-Za-z0-9 ._-]{0,63}`$') { return `$null }") @('if ($false) { return $null }'))
    (M "M21" "target from the overlaid cfg" @('$lname = ConvertTo-SelfHealTargetName ([string](Get-PropValue (Get-PropValue $root "launcher" $null) "processName" ""))') @('$lname = ConvertTo-SelfHealTargetName ([string]$cfg.launcher.processName)'))
    (M "M22" "flag accepts truthy text" @('return (($v -is [bool]) -and ($v -eq $true))') @('return [bool]$v'))
    (M "M23" "master flag ignored at one layer (two more hold)" @('if (-not $s.Enabled) { $s.WatchdogEnabled = $false; $s.HealthEnabled = $false }') @('# MUTANT master flag ignored') "selfheal" "EITHER")
    (M "M24" "maintenance does not hold" @('if ($op.Blocked) { return') @('if ($false) { return'))
    (M "M25" "emergency stop does not hold" @('if ($Global:EmergencyStopEngaged) { return "emergency_stop" }') @('# MUTANT estop ignored'))
    (M "M26" "restart row Warning" @('return New-SelfHealDiagRow -CheckId $SelfHealCheckRestarting -Category $SelfHealCatSoftware -Severity $SelfHealSevInfo') @('return New-SelfHealDiagRow -CheckId $SelfHealCheckRestarting -Category $SelfHealCatSoftware -Severity $SelfHealSevWarning'))
    (M "M27" "gave-up row Warning by default" @('        GiveUpSeverity = $SelfHealSevInfo') @('        GiveUpSeverity = $SelfHealSevWarning'))
    (M "M28" "lost minutes rounded down" @('[Math]::Ceiling([Math]::Max(0, $frozenFor) / 60.0)') @('[Math]::Floor([Math]::Max(0, $frozenFor) / 60.0)'))
    (M "M29" "fault measured from detection" @('FrozenSinceUtc = $frozen[0].UnrespSince') @('FrozenSinceUtc = $Now'))
    (M "M30" "duplicate key not recognized" @("`$dup = (`$body -match '0x80040237') -or ((`$status -eq 412) -and (`$body -match 'already exists'))") @('$dup = $false'))
    (M "M31" "error body read only from the stream" @('try { if ($postErr.ErrorDetails -and $postErr.ErrorDetails.Message) { $body = [string]$postErr.ErrorDetails.Message } } catch {}') @('# MUTANT ErrorDetails not read'))
    (M "M32" "no backoff" @('$script:SelfHealNextSendUtc = $Now.AddSeconds($script:SelfHealSendBackoffSeconds)') @('$script:SelfHealNextSendUtc = $null'))
    (M "M33" "keeps posting after a failure" @('        $failed = $true') @('        $failed = $false'))
    (M "M34" "outbox unbounded" @('if ($script:SelfHealOutbox.Count -gt $SelfHealOutboxMax) {') @('if ($false) {'))
    (M "M35" "non-boolean reading accepted" @('if ($null -ne $resp -and -not ($resp -is [bool])) { $resp = $null }') @('# MUTANT coercion removed'))
    (M "M36" "tick not called from the loop" @('    if (-not $TokenOnly) {') @('    if ($false) {') "launch")
    (M "M37" "reports never delivered from the loop" @('try { Send-SelfHealOutboxIfDue -token $token -Now ((Get-Date).ToUniversalTime()) }') @('try { $null }') "launch")
    (M "M38" "health change ignores the minimum gap" @('if (-not ($scheduled -or ($changed -and $gapOk))) { return }') @('if (-not ($scheduled -or $changed)) { return }'))
    (M "M39" "muted reads as fine" @('elseif ($au.Muted -eq $true) {') @('elseif ($false) {'))
    (M "M40" "expected screens ignored" @('elseif ($null -ne $s.ExpectedScreens -and $snap.Screens -lt $s.ExpectedScreens) {') @('elseif ($false) {'))
    (M "M41" "recovered without a running copy" @('else { $recovered = ($stuck -eq 0 -and $healthy -gt 0) }') @('else { $recovered = ($stuck -eq 0) }'))
    (M "M42" "never gives up waiting" @('-ge $s.RecoveryWaitSeconds) {') @('-ge 100000) {'))
    (M "M43" "agent relaunch never starts" @('if ($instances.Count -eq 0) {') @('if ($false) {'))
    (M "M15d" "all three session checks removed" @('if ($null -eq $layer.OwnSessionId -or $pi.SessionId -ne $layer.OwnSessionId) { continue }', 'if ($null -eq $Layer.OwnSessionId -or $ProcInfo.SessionId -ne $Layer.OwnSessionId) {', 'if ($fresh.SessionId -ne $Layer.OwnSessionId) {') @('if ($false) { continue }', 'if ($false) {', 'if ($false) {'))
    (M "M23c" "master flag removed at all three layers" @('if (-not $s.Enabled) { $s.WatchdogEnabled = $false; $s.HealthEnabled = $false }', 'if (-not $script:SelfHealSettings.Enabled) {', ("param([Parameter(Mandatory=`$true)][DateTime]`$Now)`r`n    if (`$null -eq `$script:SelfHealSettings -or -not `$script:SelfHealSettings.Enabled) { return }")) @('# MUTANT master flag ignored', 'if ($false) {', ("param([Parameter(Mandatory=`$true)][DateTime]`$Now)`r`n    if (`$null -eq `$script:SelfHealSettings) { return }")))
    (M "F1a" "count: object check removed" @('if ($null -eq $o -or -not ($o -is [System.Management.Automation.PSCustomObject])) {') @('if ($false) {') "selfheal" "EITHER")
    (M "F1b" "count: array check removed" @('if ($null -eq $arr -or -not ($arr -is [System.Array])) {') @('if ($false) {'))
    (M "F1c" "count: bad entries skipped instead of refused" @('if ($null -eq $d) { $fail.Reason = "an entry is not a timestamp"; return $fail }') @('if ($null -eq $d) { continue }'))
    (M "F1d" "count: empty file check removed" @('if ([string]::IsNullOrWhiteSpace($Text)) { $fail.Reason = "empty"; return $fail }') @('if ($false) { return $fail }') "selfheal" "EITHER")
    (M "F1e" "count: NUL check removed" @('if ($Text.IndexOf([char]0) -ge 0) { $fail.Reason = "NUL bytes"; return $fail }') @('# MUTANT NUL check removed') "selfheal" "EITHER")
    (M "F1f" "count: renamed key accepted as empty" @('if ($prop.Count -ne 1) { $fail.Reason = "no restartHistoryUtc"; return $fail }') @('if ($prop.Count -ne 1) { return @{ Ok = $true; Dates = @(); Reason = "" } }'))
    (M "F1g" "closes even when the count was not saved" @('if (-not (Save-SelfHealState)) {') @('if ($false) {'))
    (M "F1h" "save does not read back" @('if (-not $back.Ok -or @($back.Dates).Count -ne $hist.Count) {') @('if ($false) {'))
    (M "F1i" "count saved to whole seconds" @('ToString("yyyy-MM-ddTHH:mm:ss.fffffffZ", [Globalization.CultureInfo]::InvariantCulture)') @('ToString("yyyy-MM-ddTHH:mm:ssZ", [Globalization.CultureInfo]::InvariantCulture)'))
    (M "R2a" "grace floor back to 60" @('"launchGraceSeconds" 120 120 1800') @('"launchGraceSeconds" 120 60 1800'))
    (M "R2b" "loading floor back to unresponsiveSeconds" @('"loadingMaxSeconds" 180 ([Math]::Max(180, $s.UnresponsiveSeconds)) 3600') @('"loadingMaxSeconds" 180 $s.UnresponsiveSeconds 3600'))
    (M "R7a" "flag read through Get-PropValue (unrolls [true])" @('$v = $hit[0].Value') @('$v = Get-PropValue $obj $name $null'))
    (M "V01" "real layer start time left in local time" @('try { $start = $proc.StartTime.ToUniversalTime() } catch {}') @('try { $start = $proc.StartTime } catch {}') "live")
    (M "V05" "real layer closes by NAME" @('Stop-Process -Id $procId -Force -ErrorAction Stop') @('Stop-Process -Name (Get-Process -Id $procId).ProcessName -Force -ErrorAction Stop') "live")
    (M "V07" "real layer own session hardcoded" @('try { $own = [int](Get-Process -Id $SessionOfProcessId).SessionId } catch {}') @('$own = 1') "live")
    (M "M44" "health row Warning" @('-Category $SelfHealCatDisplay -Severity $SelfHealSevInfo') @('-Category $SelfHealCatDisplay -Severity $SelfHealSevWarning'))
)
if ($Only) { $Muts = @($Muts | Where-Object { $_.Id -in ($Only -split ",") }) }

$lockPath = Join-Path $Lane $LockName
if (Test-Path $lockPath) { throw "a mutation run is already in progress ($lockPath)" }
Set-Content -Path $lockPath -Value $PID
try {
    "# run started $((Get-Date).ToUniversalTime().ToString('o')) repo HEAD $((git -C $Repo rev-parse --short HEAD))" | Out-File -FilePath $Results -Encoding utf8
    $orig = [IO.File]::ReadAllText((Join-Path $Src "BayAgent.ps1"))
    $notApplied = 0
    foreach ($m in $Muts) {
        $work = Join-Path $Lane ("mut-" + $m.Id)
        if (Test-Path $work) { Remove-Item -LiteralPath $work -Recurse -Force }
        New-Item -ItemType Directory -Force -Path $work | Out-Null
        $text = $orig
        $applied = $true
        for ($i = 0; $i -lt @($m.From).Count; $i++) {
            $f = @($m.From)[$i]; $to = @($m.To)[$i]
            $count = ([regex]::Matches($text, [regex]::Escape($f))).Count
            if ($count -ne 1) { $applied = $false; Write-Host ("{0} NOT-APPLIED: anchor {1} matched {2} times" -f $m.Id, $i, $count) -ForegroundColor Yellow; break }
            $text = $text.Replace($f, $to)
        }
        if (-not $applied) { $notApplied++; ("{0}`tNOT-APPLIED`t{1}" -f $m.Id, $m.Why) | Out-File -FilePath $Results -Append -Encoding utf8; continue }
        $agent = Join-Path $work "BayAgent.ps1"
        [IO.File]::WriteAllText($agent, $text, (New-Object Text.UTF8Encoding($true)))
        Copy-Item -LiteralPath (Join-Path $Src "agent-config.json") -Destination $work
        Copy-Item -LiteralPath (Join-Path $Src "manifest.json") -Destination $work
        $suite = $(if ($m.Suite -eq "launch") { $SuiteLaunch } elseif ($m.Suite -eq "live") { $SuiteLive } else { $SuiteSelfHeal })
        $log = Join-Path $work "suite.log"
        $started = Get-Date
        # A suite's stderr must not become a terminating NativeCommandError in this runner (measured: it aborted run 1).
        $ErrorActionPreference = "Continue"
        if ($m.Suite -eq "launch") {
            & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $suite -AgentScript $agent -LaunchTimeoutSeconds 180 *>&1 | Out-File -FilePath $log -Encoding utf8
        } else {
            & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $suite -AgentScript $agent *>&1 | Out-File -FilePath $log -Encoding utf8
        }
        $exitCode = $LASTEXITCODE
        $ErrorActionPreference = "Stop"
        $secs = [int]((Get-Date) - $started).TotalSeconds
        $body = [IO.File]::ReadAllText($log)
        $rm = [regex]::Match($body, "RESULT: (\d+) passed, (\d+) failed")
        $verdict = "ERROR"; $detail = "no RESULT line (exit $exitCode)"
        if ($rm.Success) {
            $failedN = [int]$rm.Groups[2].Value
            $verdict = $(if ($failedN -gt 0) { "KILLED" } else { "SURVIVED" })
            $firstFail = ([regex]::Match($body, "(?m)^\s+FAIL\s+(.+)$")).Groups[1].Value
            $detail = ("{0} passed, {1} failed; first: {2}" -f $rm.Groups[1].Value, $failedN, $firstFail)
        }
        $line = ("{0}`t{1}`t{2}`t{3}s`t{4}`t{5}" -f $m.Id, $verdict, $m.Expect, $secs, $m.Why, $detail)
        Write-Host $line
        $line | Out-File -FilePath $Results -Append -Encoding utf8
    }
    "# run finished $((Get-Date).ToUniversalTime().ToString('o')) notApplied=$notApplied" | Out-File -FilePath $Results -Append -Encoding utf8
    if ($notApplied -gt 0) { exit 2 }
} finally {
    Remove-Item -LiteralPath $lockPath -Force -ErrorAction SilentlyContinue
}
