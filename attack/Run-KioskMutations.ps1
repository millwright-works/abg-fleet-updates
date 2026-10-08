# Mutation runner for the A0.363 kiosk build (BayAgent 1.4.0). Mutates COPIES (the worktree is never touched), runs the
# named suite against the copy, and scores only finished runs:
#   KILLED   = the suite printed RESULT with failed > 0
#   SURVIVED = the suite printed RESULT with failed = 0
#   ERROR    = no RESULT line (a crash or a hang is not a kill)
# Every anchor must match exactly once or the mutant is NOT-APPLIED (counted; the run exits 2). Anchors are single
# lines, so they match CRLF and LF sources alike. Hyphens only.
# Target: agent | shell | both (the same edit in BayAgent.ps1 AND the shell: the shared functions, so the parity test
# cannot be what kills it) | builder | ordertest.
# Suite: unit (BayAgent.Kiosk.Tests) | live (BayAgent.KioskShell.Live.Tests) | launch (BayAgent.Launch.Tests) |
# package (BayAgent.KioskPackage.Tests, on a repo copy) | order (BayAgent.StartupOrder.Tests, on a repo copy).
# Expect: KILLED, SURVIVED (baselines) or EITHER (one layer of a check enforced twice; named in the results).
# Results and copies go to -WorkDir (default %TEMP%\bayagent-kiosk-mut). Resume with -Only M1,M2 or -From <id>.
[CmdletBinding()]
param([string]$Only = "", [string]$From = "", [string]$Repo = "", [string]$WorkDir = "", [string]$ResultsName = "kiosk-mutation-results.txt", [switch]$DryRun, [string]$OnlySuites = "")

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
if ([string]::IsNullOrWhiteSpace($Repo)) { $Repo = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path }
if ([string]::IsNullOrWhiteSpace($WorkDir)) { $WorkDir = Join-Path $env:TEMP "bayagent-kiosk-mut" }
New-Item -ItemType Directory -Force -Path $WorkDir | Out-Null
$Results = Join-Path $WorkDir $ResultsName
$Paths = @{
    agent     = Join-Path $Repo "src\BayAgent\BayAgent.ps1"
    shell     = Join-Path $Repo "src\BayAgent\kiosk\ABG.KioskShell.ps1"
    builder   = Join-Path $Repo "tools\Build-ReleasePackage.ps1"
    ordertest = Join-Path $Repo "tests\BayAgent.StartupOrder.Tests.ps1"
}
$Suites = @{
    unit    = Join-Path $Repo "tests\BayAgent.Kiosk.Tests.ps1"
    live    = Join-Path $Repo "tests\BayAgent.KioskShell.Live.Tests.ps1"
    launch  = Join-Path $Repo "tests\BayAgent.Launch.Tests.ps1"
    package = "tests\BayAgent.KioskPackage.Tests.ps1"
    order   = "tests\BayAgent.StartupOrder.Tests.ps1"
}

function M([string]$Id, [string]$Target, [string]$Suite, [string]$Why, [string[]]$From, [string[]]$To, [string]$Expect = "KILLED") {
    return [pscustomobject]@{ Id = $Id; Target = $Target; Suite = $Suite; Why = $Why; From = $From; To = $To; Expect = $Expect }
}

$Muts = @(
    (M "M00u" "agent" "unit" "baseline" @() @() "SURVIVED")
    (M "M00l" "shell" "live" "baseline" @() @() "SURVIVED")
    (M "M00p" "builder" "package" "baseline" @() @() "SURVIVED")
    (M "M00o" "ordertest" "order" "baseline" @() @() "SURVIVED")

    # ---- shared decision functions (both files)
    (M "K01" "both" "unit" "kill switch ignored" @('    if ($KillSwitchPresent) { $d.Reason = "kill switch present (control\kiosk.off)"; return $d }') @('    if ($false) { $d.Reason = "kill switch present (control\kiosk.off)"; return $d }'))
    (M "K02" "both" "unit" "mode compared without case (both checks)" @('if ($mode -cnotin @("explorer", "companion", "shell"))', 'if ($mode -cnotin $SupportedModes)') @('if ($mode -notin @("explorer", "companion", "shell"))', 'if ($mode -notin $SupportedModes)'))
    (M "K03" "both" "unit" "policy schema check removed" @('if (-not ($schema -is [int] -or $schema -is [long]) -or [int64]$schema -lt 1) { $d.Reason = "policy schema missing or not a positive integer"; return $d }') @('if ($false) { $d.Reason = "x"; return $d }'))
    (M "K04" "both" "unit" "shell mode treated as implemented" @('[string[]]$SupportedModes = @("explorer", "companion")') @('[string[]]$SupportedModes = @("explorer", "companion", "shell")'))
    (M "K05" "both" "unit" "minShellBytes floor removed" @('[int64]$min -lt 1024 -or [int64]$min -gt 1048576') @('[int64]$min -gt 1048576'))
    (M "K06" "both" "unit" "array values unrolled by Get-KioskProp" @('if ($v -is [Array]) { return ,$v }') @('if ($v -is [Array]) { return $v }'))
    (M "K07" "both" "unit" "launcher value compared without case" @('if ($l -isnot [string] -or $l -cne "wanted")') @('if ($l -isnot [string] -or $l -ne "wanted")'))
    (M "K08" "both" "unit" "intent expiry ignored" @('if ($NowUtc -ge $until) { $w.Reason = "intent expired"; return $w }') @('if ($false) { $w.Reason = "intent expired"; return $w }'))
    (M "K08l" "both" "live" "intent expiry ignored (live)" @('if ($NowUtc -ge $until) { $w.Reason = "intent expired"; return $w }') @('if ($false) { $w.Reason = "intent expired"; return $w }'))
    (M "K09" "both" "unit" "zone-less time text accepted" @('(Z|[+-]\d{2}:\d{2})$''') @('(Z|[+-]\d{2}:\d{2})?$'''))
    (M "K10" "both" "unit" "Unspecified DateTime accepted" @('if ($value.Kind -eq [DateTimeKind]::Utc) { return $value }') @('if ($true) { return [DateTime]::SpecifyKind($value, [DateTimeKind]::Utc) }'))
    (M "K11" "both" "unit" "reader object checks removed (decision layer still needs fields)" @('if (-not $t.StartsWith("{")) { $r.Why = "not a JSON object"; return $r }', 'if ($null -eq $o -or $o -is [Array] -or $o -is [string] -or $o -is [ValueType]) { $r.Why = "not a JSON object"; return $r }') @('if ($false) { $r.Why = "x"; return $r }', 'if ($null -eq $o) { $r.Why = "x"; return $r }') "EITHER")

    # ---- agent: intent
    (M "A01" "agent" "unit" "no grace after play end" @('$KioskIntentGraceSeconds    = 120') @('$KioskIntentGraceSeconds    = 0'))
    (M "A02" "agent" "unit" "Start without an end becomes wanted" @('if ($null -eq $end) { return @{ Launcher = "unmanaged"; UntilUtc = $null; SessionId = $sid; Reason = "Start without a readable end time" } }') @('if ($null -eq $end) { $end = $NowUtc.AddHours(1) }'))
    (M "A03" "agent" "unit" "late EndSession of an older session clears the intent" @('if (-not $SameSession) { return $null }') @('if ($false) { return $null }'))
    (M "A04" "agent" "unit" "emergency stop ignored at Start" @('if ($EmergencyStopEngaged) { return @{ Launcher = "unmanaged"; UntilUtc = $null; SessionId = $sid; Reason = "emergency stop engaged" } }') @('if ($false) { return @{ Launcher = "x" } }'))
    (M "A05" "agent" "unit" "extension accepted for another session" @(' -or [string]$cur.SessionId -cne $sid) { return $null }') @(') { return $null }'))
    (M "A06" "agent" "unit" "extension can shorten" @('if ($newUntil -le $cur.UntilUtc) { return $null }') @('if ($false) { return $null }'))
    (M "A07" "agent" "unit" "extension creates a wanted intent" @('if (-not $cur.Wanted -or [string]::IsNullOrWhiteSpace($sid)') @('if ([string]::IsNullOrWhiteSpace($sid)'))
    (M "A08" "agent" "unit" "emergency-stop clear writes the intent" @('if ($a.ToLowerInvariant() -eq "clear") { return $null }') @('if ($false) { return $null }'))
    (M "A09" "agent" "unit" "session.json ENDED read as running at start" @('if ($status -in @("ACTIVE", "ENDING") -and $null -ne $end') @('if ($status -in @("ACTIVE", "ENDING", "ENDED") -and $null -ne $end'))
    (M "A10" "agent" "unit" "engaged stop ignored at agent start" @('if ($cur.Wanted) { [void](Write-KioskIntent -Launcher "unmanaged" -UntilUtc $null -SessionId ([string]$cur.SessionId) -Reason "agent start: emergency stop engaged") }') @('if ($false) { }'))
    (M "A19" "agent" "unit" "Maintenance leaves closed in force" @('if ($cur.Wanted -or $cur.Closed) {') @('if ($cur.Wanted) {'))
    (M "A12" "agent" "unit" "agent start re-derives over a readable intent" @('if ($l -is [string] -and $l -cin @("wanted", "closed", "unmanaged")) { return }') @('if ($false) { return }'))
    (M "A13" "agent" "unit" "agent start derives closed from session.json" @('[void](Write-KioskIntent -Launcher "unmanaged" -UntilUtc $null -SessionId $sid -Reason ("agent start: no running session (status ''{0}'')" -f $status))') @('[void](Write-KioskIntent -Launcher "closed" -UntilUtc $null -SessionId $sid -Reason "x")'))
    (M "A14" "agent" "unit" "EndSession writes unmanaged instead of closed" @('return @{ Launcher = "closed"; UntilUtc = $null; SessionId = $sid; Reason = "EndSession" }') @('return @{ Launcher = "unmanaged"; UntilUtc = $null; SessionId = $sid; Reason = "EndSession" }'))
    (M "A15" "agent" "unit" "Reset closes over a wanted session" @('        if ($cur.Wanted) { return $null }') @('        if ($false) { return $null }'))
    (M "A16" "agent" "unit" "emergency stop closes" @('        return @{ Launcher = "unmanaged"; UntilUtc = $null; SessionId = $sid; Reason = "emergency stop engaged" }') @('        return @{ Launcher = "closed"; UntilUtc = $null; SessionId = $sid; Reason = "emergency stop engaged" }'))
    (M "A17" "agent" "unit" "Prep closes" @('        # Prep (start minus 15 minutes) may run while the PREVIOUS booking is still playing: it changes nothing.') @('        if ($m -eq "prep") { return @{ Launcher = "closed"; UntilUtc = $null; SessionId = $sid; Reason = "Prep" } }'))
    (M "A18" "agent" "unit" "a Start without an end writes closed" @('if ($null -eq $end) { return @{ Launcher = "unmanaged"; UntilUtc = $null; SessionId = $sid; Reason = "Start without a readable end time" } }') @('if ($null -eq $end) { return @{ Launcher = "closed"; UntilUtc = $null; SessionId = $sid; Reason = "x" } }'))
    (M "A11" "agent" "unit" "Maintenance does not clear the intent" @('                if ($op.Blocked) {') @('                if ($false) {'))

    # ---- agent: verifier
    (M "A20" "agent" "unit" "release-folder check removed" @('if (-not $full.StartsWith($folder, [StringComparison]::OrdinalIgnoreCase)) { $v.Why = "not inside $folder"; return $v }') @('if ($false) { $v.Why = "x"; return $v }'))
    (M "A21" "agent" "unit" "size check removed" @('if ($fi.Length -lt $MinBytes) {') @('if ($false) {'))
    (M "A22" "agent" "unit" "parse check removed" @('if (@($perr).Count -gt 0) { $v.Why = ("{0} parse error(s)" -f @($perr).Count); return $v }') @('if ($false) { return $v }'))
    (M "A23" "agent" "unit" "signature status ignored" @('if ($sig.Status -ne "Valid") { $v.Why = ("signature {0}" -f $sig.Status); return $v }') @('if ($false) { return $v }'))
    (M "A24" "agent" "unit" "timestamp ignored" @('if (-not $sig.Timestamped) { $v.Why = "signature is not timestamped"; return $v }') @('if ($false) { return $v }'))
    (M "A25" "agent" "unit" "signer ignored" @('if (-not $v.SignerMatches) { $v.Why = "signed by a certificate other than the one that signed this agent"; return $v }') @('if ($false) { return $v }'))
    (M "A26" "agent" "unit" "empty signer matches empty" @('$v.SignerMatches = (-not [string]::IsNullOrWhiteSpace($ExpectedSignerThumbprint) -and [string]$sig.Thumbprint -ieq $ExpectedSignerThumbprint)') @('$v.SignerMatches = ([string]$sig.Thumbprint -ieq $ExpectedSignerThumbprint)'))
    (M "A27" "agent" "unit" "shell path not version-pinned" @('return (Join-Path $BaseDir ("releases\{0}\{1}" -f $AgentCodeVersion, $KioskShellRelPath))') @('return (Join-Path $BaseDir ("current\{0}" -f $KioskShellRelPath))'))
    (M "A28" "agent" "unit" "-Companion dropped from the command line" @('-File "{0}" -Companion'' -f $ShellPath)') @('-File "{0}"'' -f $ShellPath)'))
    (M "A29" "agent" "unit" "execution-policy override added" @('return (''-NoProfile -NonInteractive -WindowStyle Hidden -File') @('return (''-NoProfile -NonInteractive -ExecutionPolicy Bypass -WindowStyle Hidden -File'))

    # ---- agent: liveness and reconciler
    (M "A40" "agent" "unit" "foreign process treated as the shell" @('if (-not (Test-KioskShellCommandLine $cl)) { $l.State = "foreign";') @('if ($false) { $l.State = "foreign";'))
    (M "A41" "agent" "unit" "foreign process treated as HUNG (would be stopped)" @('if (-not (Test-KioskShellCommandLine $cl)) { $l.State = "foreign";') @('if (-not (Test-KioskShellCommandLine $cl)) { $l.State = "hung";'))
    (M "A42" "agent" "unit" "command-line match loosened to the file name" @('return ($CommandLine -match (''(?i)'' + $root + ''[^\\"]+\\kiosk\\ABG\.KioskShell\.ps1''))') @('return ($CommandLine -match ''(?i)ABG\.KioskShell\.ps1'')'))
    (M "A43" "agent" "unit" "hung after 60 s" @('if ($age -gt $KioskShellHungSeconds) {') @('if ($age -gt $KioskShellAliveSeconds) {'))
    (M "A44" "agent" "unit" "alive up to 180 s" @('if ($age -le $KioskShellAliveSeconds) {') @('if ($age -le $KioskShellHungSeconds) {'))
    (M "A45" "agent" "unit" "unreadable lastLoopUtc read as alive" @('if ($null -eq $last) { $l.State = "hung";') @('if ($null -eq $last) { $l.State = "alive";'))
    (M "A46" "agent" "unit" "reconciler starts a shell under any policy" @('if ($policy.Mode -eq "companion" -and $live.State -in @("absent", "foreign")) {') @('if ($live.State -in @("absent", "foreign")) {'))
    (M "A47" "agent" "unit" "verification ignored" @('if (-not $verify.Ok) { $action = "not started: shell file " + $verify.Why }') @('if ($false) { $action = "x" }'))
    (M "A47l" "agent" "launch" "verification ignored (real agent)" @('if (-not $verify.Ok) { $action = "not started: shell file " + $verify.Why }') @('if ($false) { $action = "x" }'))
    (M "A48" "agent" "unit" "Explorer requirement removed" @('elseif (-not $explorer) {') @('elseif ($false) {'))
    (M "A49" "agent" "unit" "hourly start cap removed" @('elseif (@($Global:KioskStarts).Count -ge $KioskShellMaxStartsPerHour) {') @('elseif ($false) {'))
    (M "A50" "agent" "unit" "start times not persisted" @('shellStarts = @(@($Global:KioskStarts) | ForEach-Object { $_.ToString("yyyy-MM-ddTHH:mm:ssZ") })') @('shellStarts = @()'))
    (M "A51" "agent" "unit" "unreadable reconcile file reads as no starts" @('for ($i = 0; $i -lt $KioskShellMaxStartsPerHour; $i++) { $seed += $NowUtc }') @('# MUTANT no seed'))
    (M "A52" "agent" "unit" "a stale shell is stopped too" @('if ($live.State -eq "hung") {') @('if ($live.State -in @("hung", "stale")) {'))

    # ---- agent: deferral and command wiring
    (M "A60" "agent" "unit" "deferral under an explorer policy" @('if ($policy.Mode -ne "companion") { return @{ Defer = $false; Why = "policy " + $policy.Mode } }') @('if ($false) { return @{ Defer = $false } }'))
    (M "A61" "agent" "unit" "deferral without a wanted intent" @('if (-not $want.Wanted) { return @{ Defer = $false; Why = $want.Reason } }') @('if ($false) { return @{ Defer = $false } }'))
    (M "A62" "agent" "unit" "deferral to a shell that is not alive" @('if ($live.State -ne "alive") { return @{ Defer = $false; Why = "shell " + $live.State } }') @('if ($false) { return @{ Defer = $false } }'))
    (M "A63" "agent" "unit" "deferral to a degraded shell" @('if (-not $live.Supervising -or $live.Degraded) { return @{ Defer = $false; Why = "shell not supervising" } }') @('if (-not $live.Supervising) { return @{ Defer = $false; Why = "x" } }'))
    (M "A64" "agent" "unit" "deferral to a non-supervising shell" @('if (-not $live.Supervising -or $live.Degraded) { return @{ Defer = $false; Why = "shell not supervising" } }') @('if ($live.Degraded) { return @{ Defer = $false; Why = "x" } }'))
    (M "W01" "agent" "unit" "wall deferral under an explorer policy" @('if ($policy.Mode -ne "companion") { return @{ Defer = $false; Why = "wall: policy " + $policy.Mode } }') @('if ($false) { return @{ Defer = $false } }'))
    (M "W02" "agent" "unit" "wall deferral to a shell that is not alive" @('if ($live.State -ne "alive") { return @{ Defer = $false; Why = "wall: shell " + $live.State } }') @('if ($false) { return @{ Defer = $false } }'))
    (M "W03" "agent" "unit" "wall deferral to a degraded shell" @('if (-not $live.Supervising -or $live.Degraded) { return @{ Defer = $false; Why = "wall: shell not supervising" } }') @('if (-not $live.Supervising) { return @{ Defer = $false; Why = "x" } }'))
    (M "W04" "agent" "unit" "wall deferral to a non-supervising shell" @('if (-not $live.Supervising -or $live.Degraded) { return @{ Defer = $false; Why = "wall: shell not supervising" } }') @('if ($live.Degraded) { return @{ Defer = $false; Why = "x" } }'))
    (M "W05" "agent" "unit" "Start-SessionDisplay ignores the shell" @('if ($kioskWall.Defer) { return @{ started = $false; reason = "kiosk_shell_owns_wall" } }') @('if ($false) { return @{ started = $false } }'))
    (M "W06" "shell" "live" "aside not re-checked" @('} elseif ($S.WallRunning -and $S.WallPids.Count -gt 0 -and $S.WallPlan -eq "aside" -and $S.WallCheckedUtc -eq $NowUtc) {') @('} elseif ($false) {'))
    (M "A65" "agent" "unit" "StartSession never defers" @('if ($kioskDefer.Defer) {') @('if ($false) {'))
    (M "A66" "agent" "unit" "startOnStart=false still wanted" @('$kioskMode = $(if ($modeLower -eq "start" -and -not [bool]$startOnStartCfg) { "start-disabled" } else { $mode })') @('$kioskMode = $mode'))
    (M "A67" "agent" "unit" "EndSession does not write the intent" @('            $kioskIntent = Set-KioskIntentForCommand -CommandType $CMD_ENDSESSION -Mode "End" -Payload $payloadObj -SameSession $sameSession') @('            $kioskIntent = $null'))
    (M "A68" "agent" "unit" "Reset does not write the intent" @('$null = Set-KioskIntentForCommand -CommandType $CMD_RESET -Mode "" -Payload $payloadObj') @('$null = $null'))
    (M "A69" "agent" "unit" "emergency stop does not write the intent" @('$null = Set-KioskIntentForCommand -CommandType $CMD_EMERGENCY_STOP -Mode "" -Payload $payloadObj') @('$null = $null'))
    (M "A70" "agent" "unit" "UpdateSessionDisplay does not extend" @('$null = Set-KioskIntentForCommand -CommandType $CMD_UPDATESESSIONDISPLAY -Mode ([string](Get-PropValue $payloadObj "mode" "")) -Payload $payloadObj') @('$null = $null'))

    # ---- shell: decisions (unit) and behavior (live)
    (M "S01" "shell" "unit" "launcher started when not wanted" @('    if (-not $Wanted) { return "none" }') @('    if ($false) { return "none" }'))
    (M "S01l" "shell" "live" "launcher started when not wanted (live)" @('    if (-not $Wanted) { return "none" }') @('    if ($false) { return "none" }'))
    (M "S02" "shell" "unit" "no two-tick wait" @('if ($AbsentTicks -lt 2) { return "wait" }') @('if ($AbsentTicks -lt 0) { return "wait" }'))
    (M "S03" "shell" "unit" "start cap ignored" @('if (-not $StartAllowed) { return "held" }') @('if ($false) { return "held" }'))
    (M "S04" "shell" "unit" "missing launcher path ignored" @('if (-not $PathExists) { return "missing" }') @('if ($false) { return "missing" }'))
    (M "S05" "shell" "unit" "single-screen rule removed" @('if ($ScreenCount -eq 1 -and $LauncherWanted) { return "aside" }') @('if ($false) { return "aside" }'))
    (M "S05l" "shell" "live" "single-screen rule removed (live)" @('if ($ScreenCount -eq 1 -and $LauncherWanted) { return "aside" }') @('if ($false) { return "aside" }'))
    (M "S06" "shell" "unit" "no-screen rule removed" @('if ($ScreenCount -le 0) { return "none" }') @('if ($false) { return "none" }'))
    (M "S07" "shell" "unit" "a degraded companion exits" @('if ($CompanionRole -and -not $PolicyWantsCompanion) { return "exit" }') @('if ($CompanionRole) { return "exit" }'))
    (M "S07l" "shell" "live" "a degraded companion exits (live)" @('if ($CompanionRole -and -not $PolicyWantsCompanion) { return "exit" }') @('if ($CompanionRole) { return "exit" }'))
    (M "S08" "shell" "unit" "no Explorer floor" @('if (-not $ExplorerPresent) { return "start-explorer" }') @('if ($false) { return "start-explorer" }'))
    (M "S09" "shell" "unit" "supervises without the companion role" @('if (-not $CompanionRole) { return @{ Supervise = $false;') @('if ($false) { return @{ Supervise = $false;'))
    (M "S09l" "shell" "live" "supervises without the companion role (live)" @('if (-not $CompanionRole) { return @{ Supervise = $false;') @('if ($false) { return @{ Supervise = $false;'))
    (M "S10" "shell" "unit" "supervises while degraded" @('if ($Degraded) { return @{ Supervise = $false; Reason = "degraded" } }') @('if ($false) { return @{ Supervise = $false } }'))
    (M "S10l" "shell" "live" "supervises while degraded (live)" @('if ($Degraded) { return @{ Supervise = $false; Reason = "degraded" } }') @('if ($false) { return @{ Supervise = $false } }'))
    (M "S11" "shell" "live" "degrade threshold 50" @('$KioskDegradeAfterFailures   = 5') @('$KioskDegradeAfterFailures   = 50'))
    (M "S12" "shell" "live" "single instance removed" @('if (-not $KioskOwnsMutex) {') @('if ($false) {'))
    (M "S13" "shell" "unit" "control ignores the primary flag" @('if ($null -eq $c) { foreach ($s in $list) { if ([bool](Get-KioskProp $s "Primary" $false)) { $c = $s; break } } }') @('# MUTANT no primary'))
    (M "S14" "shell" "unit" "session may be the control screen" @('if ($null -ne $s2 -and [string]$s2.DeviceName -ieq [string]$c.DeviceName) { $s2 = $null }') @('if ($false) { $s2 = $null }'))
    (M "S15" "shell" "live" "never exits on a policy change" @('    if ($floor -eq "exit") {') @('    if ($false) {'))
    (M "S16" "shell" "live" "intent judged on a clock a year behind" @('$S.Wanted = Get-KioskLauncherWanted -IntentRead (Read-KioskJsonFile -Path $KioskIntentPath -MaxBytes 8192) -NowUtc $NowUtc') @('$S.Wanted = Get-KioskLauncherWanted -IntentRead (Read-KioskJsonFile -Path $KioskIntentPath -MaxBytes 8192) -NowUtc $NowUtc.AddYears(-1)'))
    (M "S17" "shell" "live" "launcher not maximized" @('$r = Set-KioskWindowPlacement -Pids @([int]$S.LauncherPid) -Screen $roles.Control -Maximize') @('$r = Set-KioskWindowPlacement -Pids @([int]$S.LauncherPid) -Screen $roles.Control'))
    (M "S18" "shell" "live" "topology never stable" @('$KioskTopologyStableSeconds  = 10') @('$KioskTopologyStableSeconds  = 100000'))
    (M "S19" "shell" "live" "aside does not minimize" @('        [void][ABGKioskNative]::ShowWindow($hw, 6)') @('        # MUTANT no minimize'))
    (M "S20" "shell" "live" "shell closes a launcher that is merely unmanaged" @('    if (-not $Wanted) { return "none" }') @('    if (-not $Wanted) { if ($Running) { return "close" }; return "none" }'))
    (M "C01" "shell" "unit" "close without the 15 s grace" @('if ($Running -and $ClosedForSeconds -ge $CloseGraceSeconds) { return "close" }') @('if ($Running) { return "close" }'))
    (M "C01l" "shell" "live" "close without the 15 s grace (live)" @('if ($Running -and $ClosedForSeconds -ge $CloseGraceSeconds) { return "close" }') @('if ($Running) { return "close" }'))
    (M "C02" "both" "unit" "closed intent not honored" @('if ($l -is [string] -and $l -ceq "closed") {') @('if ($false) {'))
    (M "C02l" "both" "live" "closed intent not honored (live acceptance)" @('if ($l -is [string] -and $l -ceq "closed") {') @('if ($false) {'))
    (M "C03" "both" "unit" "closed without a writtenUtc still closes" @('if ($null -eq $since) { $w.Reason = "intent closed without a readable writtenUtc (left alone)"; return $w }') @('if ($null -eq $since) { $since = $NowUtc.AddHours(-1) }'))
    (M "C04" "both" "unit" "closed compared without case" @('if ($l -is [string] -and $l -ceq "closed") {') @('if ($l -is [string] -and $l -eq "closed") {'))
    (M "C05" "shell" "unit" "reused id not re-checked before ending" @('if ($fresh.ProcessName -ine [string]$S.Cfg.LauncherName -or $fresh.SessionId -ne $S.SessionId -or $null -eq $fst -or $fst -ne $rec.Start) {') @('if ($false) {'))
    (M "C06" "shell" "unit" "start time not re-checked" @(' -or $null -eq $fst -or $fst -ne $rec.Start) {') @(') {'))
    (M "C07" "shell" "unit" "ended without the polite-close wait" @('if (($NowUtc - $rec.First).TotalSeconds -lt $KioskCloseKillAfterSeconds) { continue }') @('# MUTANT no wait'))
    (M "C08" "shell" "live" "the close action does nothing" @('"close" { Close-KioskLauncher -S $S -Procs $procs -NowUtc $NowUtc }') @('"close" { }'))
    (M "C09" "shell" "live" "the kill step removed (a launcher whose X only minimizes survives)" @('try { $fresh.Kill();') @('try { $null = $fresh;'))
    (M "S21" "shell" "unit" "degrade only above the threshold" @('-WindowSeconds $WindowSeconds) -ge $Threshold)') @('-WindowSeconds $WindowSeconds) -gt $Threshold)'))
    (M "S22" "shell" "unit" "one start too many allowed" @('-WindowSeconds $WindowSeconds) -lt $MaxStarts)') @('-WindowSeconds $WindowSeconds) -le $MaxStarts)'))
    (M "S23" "shell" "unit" "routing selectors kept when routing is disabled" @('if ($en -isnot [bool] -or $en) {') @('if ($true) {'))

    # ---- builder
    (M "P01" "builder" "package" "shell mode buildable" @('$BuildableKioskModes = @("explorer", "companion")') @('$BuildableKioskModes = @("explorer", "companion", "shell")'))
    (M "P02" "builder" "package" "required kiosk entries not checked" @('if (@($Entries | Where-Object { $_.Zip -ceq $k }).Count -ne 1) {') @('if ($false) {'))
    (M "P03" "builder" "package" "json skipped by the CRLF/ASCII gate" @('if (-not $isPs1 -and -not $e.Zip.EndsWith(".json")) { continue }') @('if (-not $isPs1) { continue }'))
    (M "P04" "builder" "package" "shell version not checked" @('if ($sv[0].Groups[1].Value -ne $Version) {') @('if ($false) {'))
    (M "P05" "builder" "package" "minShellBytes above the shell size accepted" @('if ([int64]$pMin.Value -gt $shellLen) {') @('if ($false) {'))
    (M "P06" "builder" "package" "schema value not checked" @(' -or [int64]$pSchema.Value -ne 1) { Fail "kiosk-policy.json schema must be the integer 1" }') @(') { Fail "kiosk-policy.json schema must be the integer 1" }'))

    # ---- the order test's drift guard
    (M "O01" "ordertest" "order" "kiosk shell left out of the analyzed list" @('    "src\BayAgent\kiosk\ABG.KioskShell.ps1"') @('    # MUTANT dropped'))
)
if ($Only) { $Muts = @($Muts | Where-Object { $_.Id -in ($Only -split ",") }) }
# (Not named $Suites: that is the suite-path table above, and PowerShell names are case-insensitive.)
if ($OnlySuites) { $Muts = @($Muts | Where-Object { $_.Suite -in ($OnlySuites -split ",") }) }
if ($From) { $idx = -1; for ($i = 0; $i -lt $Muts.Count; $i++) { if ($Muts[$i].Id -eq $From) { $idx = $i; break } }; if ($idx -lt 0) { throw "no mutant $From" }; $Muts = @($Muts | Select-Object -Skip $idx) }

function Read-Src([string]$p) { $b = [IO.File]::ReadAllBytes($p); $bom = ($b.Length -ge 3 -and $b[0] -eq 0xEF -and $b[1] -eq 0xBB -and $b[2] -eq 0xBF); return @{ Text = [IO.File]::ReadAllText($p); Bom = $bom } }
function Write-Src([string]$p, $src, [string]$text) { New-Item -ItemType Directory -Force -Path (Split-Path -Parent $p) | Out-Null; [IO.File]::WriteAllText($p, $text, (New-Object Text.UTF8Encoding([bool]$src.Bom))) }
function Apply([string]$text, [string[]]$from, [string[]]$to) {
    for ($i = 0; $i -lt @($from).Count; $i++) {
        $f = @($from)[$i]; $t = @($to)[$i]
        $c = ([regex]::Matches($text, [regex]::Escape($f))).Count
        if ($c -ne 1) { return @{ Ok = $false; Why = ("anchor {0} matched {1} times" -f $i, $c) } }
        $text = $text.Replace($f, $t)
    }
    return @{ Ok = $true; Text = $text }
}

$lock = Join-Path $WorkDir "kiosk-mutation.lock"
if (Test-Path $lock) { throw "a mutation run is already in progress ($lock)" }
Set-Content -Path $lock -Value $PID
$notApplied = 0
try {
    ("# run started {0} repo {1} HEAD {2}" -f (Get-Date).ToUniversalTime().ToString("o"), $Repo, (git -C $Repo rev-parse --short HEAD)) | Out-File -FilePath $Results -Append -Encoding utf8
    $orig = @{}
    foreach ($k in $Paths.Keys) { $orig[$k] = Read-Src $Paths[$k] }
    foreach ($m in $Muts) {
        $work = Join-Path $WorkDir ("mut-" + $m.Id)
        if (Test-Path $work) { Remove-Item -LiteralPath $work -Recurse -Force }
        New-Item -ItemType Directory -Force -Path $work | Out-Null
        $targets = $(if ($m.Target -eq "both") { @("agent", "shell") } else { @($m.Target) })
        $texts = @{}
        foreach ($k in $Paths.Keys) { $texts[$k] = $orig[$k].Text }
        $ok = $true; $why = ""
        foreach ($tg in $targets) {
            if (@($m.From).Count -eq 0) { continue }
            $r = Apply $texts[$tg] $m.From $m.To
            if (-not $r.Ok) { $ok = $false; $why = "$tg $($r.Why)"; break }
            if ($r.Text -ceq $texts[$tg]) { $ok = $false; $why = "$tg unchanged"; break }
            $texts[$tg] = $r.Text
        }
        if (-not $ok) { $notApplied++; $l = ("{0}`tNOT-APPLIED`t{1}`t{2}" -f $m.Id, $m.Why, $why); Write-Host $l -ForegroundColor Yellow; $l | Out-File -FilePath $Results -Append -Encoding utf8; continue }
        if ($DryRun) { Write-Host ("{0}`tAPPLIES`t{1}" -f $m.Id, $m.Why); Remove-Item -LiteralPath $work -Recurse -Force; continue }

        # A repo copy for the suites that build or analyze a tree; plain file copies for the others.
        $repoCopy = Join-Path $work "repo"
        Copy-Item -LiteralPath (Join-Path $Repo "src") -Destination (Join-Path $repoCopy "src") -Recurse -Force
        New-Item -ItemType Directory -Force -Path (Join-Path $repoCopy "tools"), (Join-Path $repoCopy "tests") | Out-Null
        Copy-Item -LiteralPath $Paths.builder -Destination (Join-Path $repoCopy "tools\Build-ReleasePackage.ps1") -Force
        Copy-Item -LiteralPath (Join-Path $Repo "tests\BayAgent.KioskPackage.Tests.ps1") -Destination (Join-Path $repoCopy "tests") -Force
        Copy-Item -LiteralPath $Paths.ordertest -Destination (Join-Path $repoCopy "tests\BayAgent.StartupOrder.Tests.ps1") -Force
        $map = @{ agent = "src\BayAgent\BayAgent.ps1"; shell = "src\BayAgent\kiosk\ABG.KioskShell.ps1"; builder = "tools\Build-ReleasePackage.ps1"; ordertest = "tests\BayAgent.StartupOrder.Tests.ps1" }
        foreach ($k in $Paths.Keys) { Write-Src (Join-Path $repoCopy $map[$k]) $orig[$k] $texts[$k] }
        $agentCopy = Join-Path $repoCopy $map.agent
        $shellCopy = Join-Path $repoCopy $map.shell

        $log = Join-Path $work "suite.log"
        $started = Get-Date
        $ErrorActionPreference = "Continue"
        switch ($m.Suite) {
            "unit"    { & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $Suites.unit -AgentScript $agentCopy -ShellScript $shellCopy *>&1 | Out-File -FilePath $log -Encoding utf8 }
            "live"    { & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $Suites.live -ShellScript $shellCopy -AgentScript $agentCopy *>&1 | Out-File -FilePath $log -Encoding utf8 }
            "launch"  { & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $Suites.launch -AgentScript $agentCopy -LaunchTimeoutSeconds 180 *>&1 | Out-File -FilePath $log -Encoding utf8 }
            "package" { & powershell.exe -NoProfile -ExecutionPolicy Bypass -File (Join-Path $repoCopy $Suites.package) -RepoRoot $repoCopy *>&1 | Out-File -FilePath $log -Encoding utf8 }
            "order"   { & powershell.exe -NoProfile -ExecutionPolicy Bypass -File (Join-Path $repoCopy $Suites.order) *>&1 | Out-File -FilePath $log -Encoding utf8 }
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
        $line = ("{0}`t{1}`t{2}`t{3}`t{4}s`t{5}`t{6}" -f $m.Id, $verdict, $m.Expect, $m.Suite, $secs, $m.Why, $detail)
        Write-Host $line
        $line | Out-File -FilePath $Results -Append -Encoding utf8
        if ($verdict -ne "ERROR") { try { Remove-Item -LiteralPath $repoCopy -Recurse -Force -ErrorAction SilentlyContinue } catch { } }
    }
    ("# run finished {0} notApplied={1}" -f (Get-Date).ToUniversalTime().ToString("o"), $notApplied) | Out-File -FilePath $Results -Append -Encoding utf8
} finally {
    Remove-Item -LiteralPath $lock -Force -ErrorAction SilentlyContinue
}
if ($notApplied -gt 0) { exit 2 }
exit 0
