<#
BayAgent.SelfHeal.Tests.ps1

WHY THIS EXISTS
  A0.327(2), Kevin, 2026-10-01: a frozen golf program is restarted by the BAY ITSELF, using a local watchdog that
  nothing outside the bay can trigger. No new bay command. This suite pins what that watchdog may and may not do,
  through a FAKE process layer, so no real process on this machine is ever read or closed by the watchdog logic:

    W0  OFF by default: no selfHeal block, enabled=false, enabled="true" (text) -> nothing is read, nothing closed
    W1  frozen -> restart: closed by Id only after 30+ s of unbroken, quiet unresponsiveness; then recovered
    W2  loading is not frozen: launch grace, CPU or disk work, a reading gap, and "cannot tell" readings
    W3  rate limit: at most 2 restarts per rolling 15 minutes, surviving an agent restart and a corrupt state file
    W4  the wrong process is never touched: other names, deny list, other session, PID reuse, the agent itself,
        and a platform-side overlay of $cfg.launcher cannot steer the target
    W5  holds: Maintenance/Offline mode and the emergency-stop latch only ever HOLD a restart
    W6  health self-reports: golf program, screens, audio; cadence and change detection
    W7  delivery into the diagnostic pipe (a mock Dataverse): POST shape, duplicate key, failure and backoff
    W8  detectors are pluggable; an unknown detector restarts nothing; the shipped detectors fail to "cannot tell"
    W9  wiring: the tick runs before the token and outside its try, delivery after the heartbeat

  The functions under test are lifted from BayAgent.ps1 with the AST and dot-sourced, and so are the section's
  script-level constants (the deny list among them), so the suite tests the SHIPPED values, not copies.

RUN (from the repo root)
  powershell -NoProfile -ExecutionPolicy Bypass -File tests\BayAgent.SelfHeal.Tests.ps1

Exit code 0 = all assertions passed. Hyphens only in comments.
#>
[CmdletBinding()]
param([string]$AgentScript = "")

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

if ([string]::IsNullOrWhiteSpace($AgentScript)) { $AgentScript = Join-Path $PSScriptRoot "..\src\BayAgent\BayAgent.ps1" }
$AgentScript = (Resolve-Path $AgentScript).Path

# ---------------------------------------------------------------- harness
$script:Pass = 0; $script:Fail = 0; $script:Failures = @()
function Assert-True([bool]$cond, [string]$msg) {
    if ($cond) { $script:Pass++; Write-Host "  PASS  $msg" }
    else { $script:Fail++; $script:Failures += $msg; Write-Host "  FAIL  $msg" -ForegroundColor Red }
}
function Section([string]$name) { Write-Host ""; Write-Host "== $name" -ForegroundColor Cyan }

# ---------------------------------------------------------------- lift from BayAgent.ps1
$tokens = $null; $errors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile($AgentScript, [ref]$tokens, [ref]$errors)
if ($errors.Count -gt 0) { throw "BayAgent.ps1 has parse errors: $($errors | ForEach-Object { $_.Message } | Out-String)" }

$defs = @($ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $true))
$wanted = @("Get-PropValue", "Write-TextAtomic", "Get-BayLabel", "Get-EffectiveConfigValue", "Get-AgentOperationalState",
            "Read-WebExceptionBody", "New-DvHeaders")
$wanted += @($defs | Where-Object { $_.Name -match 'SelfHeal' } | ForEach-Object { $_.Name })
$lifted = 0
foreach ($name in $wanted) {
    $d = $defs | Where-Object { $_.Name -eq $name } | Select-Object -First 1
    if (-not $d) { throw "Function '$name' not found in $AgentScript" }
    . ([scriptblock]::Create($d.Extent.Text))
    $lifted++
}

# Test-side environment the lifted code reads (mirrors the top of BayAgent.ps1).
$script:LogLines = New-Object System.Collections.ArrayList
function Write-Log { param([string]$Message, [string]$Level = "INFO") [void]$script:LogLines.Add("[$Level] $Message") }
$BaseDir = Join-Path $env:TEMP ("bayagent-selfheal-" + [guid]::NewGuid().ToString("N").Substring(0, 8))
New-Item -ItemType Directory -Force -Path (Join-Path $BaseDir "state") | Out-Null
$BayId = "33333333-3333-3333-3333-333333333333"
$BayEntitySet = "build_baies"
$OrgUrl = "http://127.0.0.1:1"
$AgentVersion = "test"
$cfg = [pscustomobject]@{ bayLabel = "BAY1"; launcher = [pscustomobject]@{ processName = "UneekorLauncher" } }
$AGENTSTATUS_ONLINE = 100000000; $AGENTSTATUS_DEGRADED = 100000001; $AGENTSTATUS_OFFLINE = 100000002; $AGENTSTATUS_MAINTENANCE = 100000003
$Global:EffectiveConfig = $null
$Global:EmergencyStopEngaged = $false

# The section's script-level constants and the detector registry, executed from the shipped source.
$constCount = 0
foreach ($st in @($ast.EndBlock.Statements)) {
    if ($st -isnot [System.Management.Automation.Language.AssignmentStatementAst]) { continue }
    $lhs = $st.Left.Extent.Text
    if ($lhs -match '^\$SelfHeal' -or $lhs -eq '$script:SelfHealDetectors' -or $lhs -eq '$script:SelfHealNativeState') {
        . ([scriptblock]::Create($st.Extent.Text)); $constCount++
    }
}
Write-Host "Lifted $lifted functions and $constCount section constants from $AgentScript"
Assert-True ($constCount -ge 20) "the section's constants were found in the shipped file ($constCount)"
Assert-True ($SelfHealStatePath.StartsWith($BaseDir)) "state paths resolve under the sandbox, not the live install"

# ---------------------------------------------------------------- the fake process layer
$T0 = [DateTime]::new(2026, 10, 2, 12, 0, 0, [DateTimeKind]::Utc)
$script:FakeProcs = @{}
$script:FakeResponding = @{}
$script:Stopped = New-Object System.Collections.ArrayList
$script:Started = New-Object System.Collections.ArrayList
$script:ListCalls = 0
$script:FakeScreens = 3
$script:FakeAudio = [pscustomobject]@{ Present = $true; HResult = 0; DeviceId = "dev"; Muted = $false; VolumeScalar = 0.5 }
$script:GetByIdOverride = $null

function Add-FakeProc {
    param([int]$Id, [string]$Name = "UneekorLauncher", [DateTime]$Start = $T0.AddMinutes(-10), [int]$Session = 1, $Responding = $true)
    $script:FakeProcs[$Id] = @{ Id = $Id; Name = $Name; SessionId = $Session; StartTimeUtc = $Start; MainWindowHandle = [Int64](1000 + $Id); CpuSeconds = 10.0; IoReadBytes = 1000000.0 }
    $script:FakeResponding[$Id] = $Responding
}
function Set-FakeCounter([int]$Id, [string]$Prop, $Value) {
    if ($script:FakeProcs.ContainsKey($Id)) { $script:FakeProcs[$Id][$Prop] = $Value }
}
function New-FakeLayer {
    return @{
        OwnSessionId = 1
        List = { param([string]$name) $script:ListCalls++; foreach ($p in @($script:FakeProcs.Values)) { if ($p.Name -ieq $name) { [pscustomobject]$p } } }
        GetById = {
            param([int]$procId)
            if ($null -ne $script:GetByIdOverride) { return (& $script:GetByIdOverride $procId) }
            if ($script:FakeProcs.ContainsKey($procId)) { return [pscustomobject]$script:FakeProcs[$procId] }
            return $null
        }
        Stop = { param([int]$procId) [void]$script:Stopped.Add($procId); $script:FakeProcs.Remove($procId); $script:FakeResponding.Remove($procId) }
        Start = { param([string]$path, [string]$argLine) [void]$script:Started.Add($path) }
        ScreenCount = { $script:FakeScreens }
        Audio = { $script:FakeAudio }
    }
}
$script:SelfHealDetectors["fake"] = {
    param($procInfo, $layer)
    $r = $null
    if ($script:FakeResponding.ContainsKey([int]$procInfo.Id)) { $r = $script:FakeResponding[[int]$procInfo.Id] }
    return @{ Responding = $r; Detail = "fake" }
}

$script:CfgCounter = 0
function New-SelfHealConfig {
    param($SelfHeal, [string]$LauncherName = "UneekorLauncher")
    $script:CfgCounter++
    $p = Join-Path $BaseDir ("agent-config-{0}.json" -f $script:CfgCounter)
    $o = [ordered]@{ bayId = $BayId; launcher = [ordered]@{ processName = $LauncherName } }
    if ($null -ne $SelfHeal) { $o["selfHeal"] = $SelfHeal }
    [IO.File]::WriteAllText($p, ($o | ConvertTo-Json -Depth 8), (New-Object Text.UTF8Encoding($false)))
    return $p
}
function Reset-World {
    param([switch]$KeepState)
    $script:FakeProcs = @{}; $script:FakeResponding = @{}
    $script:Stopped.Clear(); $script:Started.Clear(); $script:ListCalls = 0
    $script:GetByIdOverride = $null
    $script:LogLines.Clear()
    $Global:EffectiveConfig = $null; $Global:EmergencyStopEngaged = $false
    $script:FakeScreens = 3
    $script:FakeAudio = [pscustomobject]@{ Present = $true; HResult = 0; DeviceId = "dev"; Muted = $false; VolumeScalar = 0.5 }
    if (-not $KeepState) {
        Remove-Item -LiteralPath $SelfHealStatePath -Force -ErrorAction SilentlyContinue
        Remove-Item -LiteralPath $SelfHealOutboxPath -Force -ErrorAction SilentlyContinue
    }
}
function Start-SelfHeal {
    param($WatchdogExtra = @{}, [switch]$Health, $HealthExtra = @{}, [switch]$NoWatchdog, [switch]$KeepState, $Detector = "fake")
    $wd = [ordered]@{ enabled = (-not $NoWatchdog); detector = $Detector }
    foreach ($k in $WatchdogExtra.Keys) { $wd[$k] = $WatchdogExtra[$k] }
    $hr = [ordered]@{ enabled = [bool]$Health }
    foreach ($k in $HealthExtra.Keys) { $hr[$k] = $HealthExtra[$k] }
    $path = New-SelfHealConfig -SelfHeal ([ordered]@{ enabled = $true; watchdog = $wd; healthReports = $hr })
    Initialize-SelfHeal -ConfigPath $path -Now $T0 -Layer (New-FakeLayer)
}
function Invoke-Ticks {
    # Ticks the watchdog every $Step seconds from $From to $To (inclusive), running $Each before each tick.
    param([int]$From, [int]$To, [int]$Step = 5, [scriptblock]$Each = $null)
    for ($t = $From; $t -le $To; $t += $Step) {
        if ($null -ne $Each) { & $Each $t }
        Invoke-SelfHealTick -Now $T0.AddSeconds($t)
    }
}
function Get-OutboxRows([string]$CheckId) {
    return @(@($script:SelfHealOutbox) | ForEach-Object { $_.row } | Where-Object { $_.build_diagnosticname -like "* | $CheckId" })
}
function Get-Metric($row) { return ($row.build_metricjson | ConvertFrom-Json) }

try {
    # ============================================================ W0 off by default
    Section "W0 the feature is OFF unless agent-config.json says selfHeal.enabled = true (JSON true)"
    foreach ($case in @(
        @{ Label = "no selfHeal block"; Block = $null },
        @{ Label = "selfHeal.enabled = false"; Block = [ordered]@{ enabled = $false; watchdog = [ordered]@{ enabled = $true; detector = "fake" }; healthReports = [ordered]@{ enabled = $true } } },
        @{ Label = "selfHeal.enabled = ""true"" (text, not a JSON true)"; Block = [ordered]@{ enabled = "true"; watchdog = [ordered]@{ enabled = $true; detector = "fake" }; healthReports = [ordered]@{ enabled = $true } } },
        @{ Label = "selfHeal.enabled = 1"; Block = [ordered]@{ enabled = 1; watchdog = [ordered]@{ enabled = $true; detector = "fake" } } },
        @{ Label = "selfHeal.enabled = [true] (an array, verifier R7)"; Block = [ordered]@{ enabled = @($true); watchdog = [ordered]@{ enabled = $true; detector = "fake" }; healthReports = [ordered]@{ enabled = $true } } },
        @{ Label = "watchdog.enabled = [true] under a true master flag"; Block = [ordered]@{ enabled = $true; watchdog = [ordered]@{ enabled = @($true); detector = "fake" } } }
    )) {
        Reset-World
        Add-FakeProc -Id 1001 -Responding $false
        Initialize-SelfHeal -ConfigPath (New-SelfHealConfig -SelfHeal $case.Block) -Now $T0 -Layer (New-FakeLayer)
        Invoke-Ticks -From 0 -To 400
        Assert-True ($script:Stopped.Count -eq 0) "$($case.Label): a program frozen for 400 s is NOT closed"
        Assert-True ($script:ListCalls -eq 0) "$($case.Label): no process is even listed"
        Assert-True (@($script:SelfHealOutbox).Count -eq 0) "$($case.Label): nothing is queued for the platform"
        Assert-True (-not (Test-Path -LiteralPath $SelfHealStatePath)) "$($case.Label): no state file is written"
    }
    # The repo's agent-config.json is a scrubbed template (its ids read `redacted`, so it is not parseable JSON); read as text.
    $shippedCfgText = [IO.File]::ReadAllText((Join-Path (Split-Path $AgentScript) "agent-config.json"))
    Assert-True ($shippedCfgText -notmatch '"selfHeal"') "the shipped agent-config.json does not turn it on (it has no selfHeal block)"

    # ============================================================ W1 frozen -> restart -> recovered
    Section "W1 a program frozen for 30+ s is closed by Id, the shell reopens it, and the lost minutes are recorded"
    Reset-World
    Add-FakeProc -Id 1001
    Start-SelfHeal
    Invoke-Ticks -From 0 -To 20                                     # responding: nothing
    $script:FakeResponding[1001] = $false                           # freezes at t=25 (first reading at t=25)
    $firstUnresp = 25
    $stopAt = $null
    for ($t = 25; $t -le 120; $t += 5) {
        Invoke-SelfHealTick -Now $T0.AddSeconds($t)
        if ($script:Stopped.Count -gt 0) { $stopAt = $t; break }
    }
    Assert-True ($script:Stopped.Count -eq 1 -and $script:Stopped[0] -eq 1001) "the frozen copy (pid 1001) was closed exactly once, by its Id (stopped: $($script:Stopped -join ','))"
    Assert-True ($null -ne $stopAt -and ($stopAt - $firstUnresp) -ge 30) "...no sooner than 30 s after the first unresponsive reading (closed at t=$stopAt, first unresponsive t=$firstUnresp)"
    Assert-True ($null -ne $stopAt -and ($stopAt - $firstUnresp) -le 45) "...and promptly after that (within 45 s)"
    $rr = @(Get-OutboxRows "software.golf.restarting")
    Assert-True ($rr.Count -eq 1) "one 'restarting' report is queued for the platform"
    if ($rr.Count -eq 1) {
        $m = Get-Metric $rr[0]
        Assert-True ($rr[0].build_severity -eq 100000000) "...at Info severity, so the ingest opens no issue and emails nobody (A0.327(3))"
        Assert-True ($rr[0].statuscode -eq 271980001) "...status Failed (the program was frozen)"
        Assert-True ($rr[0].build_checkcategory -eq 100000004) "...category Software"
        Assert-True ($rr[0]."build_Bay@odata.bind" -eq "/build_baies($BayId)") "...bound to this bay"
        Assert-True ($rr[0].build_diagnosticname -eq "BAY1 | software.golf.restarting") "...named so the ingest's check id is the last token"
        Assert-True ($m.event -eq "restarting" -and $m.target -eq "UneekorLauncher") "...metric says what happened and to which program"
        Assert-True ((ConvertTo-SelfHealUtc $m.frozenSinceUtc) -eq $T0.AddSeconds($firstUnresp)) "...and when it first stopped responding"
        Assert-True ([guid]::TryParse([string]$rr[0].build_diagnosticlogid, [ref][guid]::Empty)) "...with its own row id (a retry is a duplicate key, not a second event)"
    }
    Assert-True (Test-Path -LiteralPath $SelfHealStatePath) "the restart is counted in the state file"
    # The next reading comes before the shell has reopened it: nothing is running. That is not "recovered".
    Invoke-SelfHealTick -Now $T0.AddSeconds($stopAt + 5)
    Assert-True (@(Get-OutboxRows "software.golf.recovered").Count -eq 0) "with no copy running yet, the program is NOT reported recovered"
    # The shell reopens it (a NEW pid, start time = now), responding.
    $relaunchAt = $stopAt + 8
    Add-FakeProc -Id 1002 -Start $T0.AddSeconds($relaunchAt) -Responding $true
    Invoke-Ticks -From ($stopAt + 10) -To ($stopAt + 30)
    $rec = @(Get-OutboxRows "software.golf.recovered")
    Assert-True ($rec.Count -eq 1) "one 'recovered' report once the reopened copy responds"
    if ($rec.Count -eq 1) {
        $m2 = Get-Metric $rec[0]
        $expectedSec = [int](($stopAt + 10) - $firstUnresp)
        Assert-True ($m2.faultSeconds -eq $expectedSec) "...lost time measured from the first unresponsive reading to the first healthy one ($($m2.faultSeconds) s, expected $expectedSec)"
        Assert-True ($m2.faultMinutes -eq [int][Math]::Ceiling($expectedSec / 60.0) -and $rec[0].build_metricvalue -eq $m2.faultMinutes) "...in whole minutes, rounded up ($($m2.faultMinutes)), as the metric value"
        Assert-True ($rec[0].build_severity -eq 100000000 -and $rec[0].statuscode -eq 1) "...Info and Passed: nothing is alerted and nothing is paid out (A0.327(4): the club decides by hand)"
        Assert-True ($m2.episodeId -eq (Get-Metric $rr[0]).episodeId -and $rec[0].build_diagnosticrunid -eq $rr[0].build_diagnosticrunid) "...same episode id and run id as the restart, so the platform can pair them"
    }
    Assert-True ($script:Stopped.Count -eq 1) "the reopened copy is left alone"
    Assert-True ($script:SelfHealRuntime.Episodes.Count -eq 0) "the episode is closed"
    Assert-True (@($script:LogLines | Where-Object { $_ -match "tick failed" }).Count -eq 0) "no tick failed along the way ($(@($script:LogLines | Where-Object { $_ -match 'tick failed' }) | Select-Object -First 1))"

    # W1b: closed, and the shell never brings it back: one 'gave up' report after the recovery wait (120 s).
    Reset-World
    Add-FakeProc -Id 1101 -Responding $false
    Start-SelfHeal
    Invoke-Ticks -From 0 -To 40
    Assert-True ($script:Stopped.Count -eq 1) "W1b precondition: closed"
    Invoke-Ticks -From 45 -To 150
    Assert-True (@(Get-OutboxRows "software.golf.frozen").Count -eq 0) "W1b: not given up before the 120 s recovery wait"
    Invoke-Ticks -From 155 -To 400
    $nr = @(Get-OutboxRows "software.golf.frozen")
    Assert-True ($nr.Count -eq 1 -and (Get-Metric $nr[0]).reason -eq "not_recovered") "W1b: one 'gave up' report (not_recovered) when it has not come back 120 s after the restart"
    Assert-True ($script:Started.Count -eq 0) "W1b: relaunch 'shell' never makes the agent start anything"

    # W1c: relaunch 'agent' (a bay without the kiosk shell): the agent starts ONLY the configured local path.
    Reset-World
    Add-FakeProc -Id 1201 -Responding $false
    Start-SelfHeal -WatchdogExtra @{ targets = @(@{ processName = "UneekorLauncher"; relaunch = "agent"; path = "C:\Uneekor\Launcher\UneekorLauncher.exe" }) }
    Invoke-Ticks -From 0 -To 40
    Assert-True ($script:Stopped.Count -eq 1) "W1c precondition: closed"
    Invoke-Ticks -From 45 -To 45
    Assert-True ($script:Started.Count -eq 0) "W1c: the agent waits relaunchWaitSeconds (15 s) before starting it"
    Invoke-Ticks -From 55 -To 120
    Assert-True ($script:Started.Count -eq 1 -and $script:Started[0] -eq "C:\Uneekor\Launcher\UneekorLauncher.exe") "W1c: then starts exactly the configured path, once"
    Reset-World
    Add-FakeProc -Id 1301 -Responding $false
    Start-SelfHeal -WatchdogExtra @{ targets = @(@{ processName = "UneekorLauncher"; relaunch = "agent"; path = "C:\Uneekor\Launcher\UneekorLauncher.exe" }) }
    Invoke-Ticks -From 0 -To 40
    Add-FakeProc -Id 1302 -Start $T0.AddSeconds(42) -Responding $true
    Invoke-Ticks -From 45 -To 120
    Assert-True ($script:Started.Count -eq 0) "W1c: if something already brought it back, the agent starts nothing"

    # ============================================================ W2 loading is not frozen
    Section "W2 a loading game is not frozen"
    # (a) launch grace: a copy started 10 s ago and not responding is never judged inside its first 120 s.
    Reset-World
    Add-FakeProc -Id 2001 -Start $T0.AddSeconds(-10) -Responding $false
    Start-SelfHeal
    Invoke-Ticks -From 0 -To 105
    Assert-True ($script:Stopped.Count -eq 0) "(a) not responding for its first 115 s after launch: not closed (launch grace 120 s)"
    Invoke-Ticks -From 110 -To 175
    Assert-True ($script:Stopped.Count -eq 1) "(a) ...and once the grace is over, 30 s more of not responding does close it"

    # (b) busy on the CPU: not responding for 170 s while using 40% of a core is loading, not frozen.
    Reset-World
    Add-FakeProc -Id 2002 -Responding $false
    Start-SelfHeal
    Invoke-Ticks -From 0 -To 170 -Each { param($t) Set-FakeCounter 2002 "CpuSeconds" (10.0 + 0.4 * $t) }
    Assert-True ($script:Stopped.Count -eq 0) "(b) not responding for 170 s but working the CPU: not closed"
    if ($script:FakeProcs.ContainsKey(2002)) { $script:FakeResponding[2002] = $true }
    Invoke-Ticks -From 175 -To 400 -Each { param($t) Set-FakeCounter 2002 "CpuSeconds" (10.0 + 0.4 * $t) }
    Assert-True ($script:Stopped.Count -eq 0) "(b) ...it finishes loading and responds: never closed"
    Assert-True (@($script:SelfHealOutbox).Count -eq 0) "(b) ...and nothing is reported"

    # (c) busy on the disk only.
    Reset-World
    Add-FakeProc -Id 2003 -Responding $false
    Start-SelfHeal
    Invoke-Ticks -From 0 -To 170 -Each { param($t) Set-FakeCounter 2003 "IoReadBytes" (1000000.0 + 5000000.0 * $t) }
    Assert-True ($script:Stopped.Count -eq 0) "(c) not responding for 170 s but reading from disk: not closed"

    # (d) a load that never ends is bounded: 180 s of not responding is frozen whatever the work signs say.
    Invoke-Ticks -From 175 -To 200 -Each { param($t) Set-FakeCounter 2003 "IoReadBytes" (1000000.0 + 5000000.0 * $t) }
    Assert-True ($script:Stopped.Count -eq 1) "(d) ...but not responding for 180 s even while busy is frozen (a busy hang is still a hang)"

    # (e) "cannot tell" breaks the run: alternating not-responding and unknown readings never add up.
    Reset-World
    Add-FakeProc -Id 2004 -Responding $false
    Start-SelfHeal
    Invoke-Ticks -From 0 -To 600 -Each { param($t) if ($script:FakeProcs.ContainsKey(2004)) { $script:FakeResponding[2004] = $(if (($t / 5) % 2 -eq 0) { $false } else { $null }) } }
    Assert-True ($script:Stopped.Count -eq 0) "(e) not responding every other reading, 'cannot tell' between: never closed"

    # (f) a reading gap restarts the count: quiet and unresponsive at t=0, 5 and 10, then the next reading at t=40.
    # (Mutation M07 survived the first version of this test, which had a single reading before the gap: the quiet
    # clock restarted at the gap anyway. Three readings first put the quiet clock at t=5, so only the gap rule stops
    # a close at t=40.)
    Reset-World
    Add-FakeProc -Id 2005 -Responding $false
    Start-SelfHeal
    Invoke-Ticks -From 0 -To 10
    Invoke-SelfHealTick -Now $T0.AddSeconds(40)
    Assert-True ($script:Stopped.Count -eq 0) "(f) unresponsive at 0, 5, 10 and then 40 (nobody watched for 30 s) does not make a freeze at 40"
    Invoke-Ticks -From 45 -To 65
    Assert-True ($script:Stopped.Count -eq 0) "(f) ...the 30 s count starts again at t=40 (not closed by t=65)"
    Invoke-Ticks -From 70 -To 85
    Assert-True ($script:Stopped.Count -eq 1) "(f) ...and closes after 30 s of unbroken readings"

    # (g) config cannot make it quicker: unresponsiveSeconds 5 and launchGraceSeconds 1 are clamped.
    Reset-World
    Add-FakeProc -Id 2006 -Responding $false
    Start-SelfHeal -WatchdogExtra @{ unresponsiveSeconds = 5; launchGraceSeconds = 1; loadingMaxSeconds = 1; maxRestarts = 9; windowMinutes = 1 }
    Assert-True ($script:SelfHealSettings.UnresponsiveSeconds -eq 30 -and $script:SelfHealSettings.MaxRestarts -eq 2 -and $script:SelfHealSettings.WindowMinutes -eq 15) "(g) floors hold: 30 s, 2 restarts, 15 minutes"
    Assert-True ($script:SelfHealSettings.LaunchGraceSeconds -eq 120 -and $script:SelfHealSettings.LoadingMaxSeconds -eq 180) "(g) ...and the 120 s launch grace and 180 s loading bound (verifier R2: they could be lowered to 60 and 30)"
    Invoke-Ticks -From 0 -To 25
    Assert-True ($script:Stopped.Count -eq 0) "(g) ...behaviorally: a config asking for 5 s still waits 30 s"
    # Behaviorally for R2: a config asking for a 30 s loading bound still lets a busy program load for 170 s,
    # and one asking for a 60 s grace still leaves a just-launched program alone for 115 s.
    Reset-World
    Add-FakeProc -Id 2010 -Responding $false
    Start-SelfHeal -WatchdogExtra @{ loadingMaxSeconds = 30 }
    Invoke-Ticks -From 0 -To 170 -Each { param($t) Set-FakeCounter 2010 "CpuSeconds" (10.0 + 0.4 * $t) }
    Assert-True ($script:Stopped.Count -eq 0) "(g) loadingMaxSeconds 30 in config: a busy program is still not closed at 170 s"
    Reset-World
    Add-FakeProc -Id 2011 -Start $T0.AddSeconds(-10) -Responding $false
    Start-SelfHeal -WatchdogExtra @{ launchGraceSeconds = 60 }
    Invoke-Ticks -From 0 -To 105
    Assert-True ($script:Stopped.Count -eq 0) "(g) launchGraceSeconds 60 in config: a program 115 s old is still inside the 120 s grace"

    # (h) counters that cannot be read count as BUSY: not frozen until the 180 s bound.
    Reset-World
    Add-FakeProc -Id 2007 -Responding $false
    $script:FakeProcs[2007].CpuSeconds = $null; $script:FakeProcs[2007].IoReadBytes = $null
    Start-SelfHeal
    Invoke-Ticks -From 0 -To 170
    Assert-True ($script:Stopped.Count -eq 0) "(h) CPU and disk counters unreadable: not closed at 170 s (no evidence it is idle)"
    Invoke-Ticks -From 175 -To 190
    Assert-True ($script:Stopped.Count -eq 1) "(h) ...closed at the 180 s bound"
    # (h2)/(h3) each counter on its own: one unreadable, the other readable and flat. Unknown still counts as busy.
    Reset-World
    Add-FakeProc -Id 2008 -Responding $false
    $script:FakeProcs[2008].CpuSeconds = $null
    Start-SelfHeal
    Invoke-Ticks -From 0 -To 170
    Assert-True ($script:Stopped.Count -eq 0) "(h2) CPU unreadable, disk reads flat: not closed at 170 s"
    Reset-World
    Add-FakeProc -Id 2009 -Responding $false
    $script:FakeProcs[2009].IoReadBytes = $null
    Start-SelfHeal
    Invoke-Ticks -From 0 -To 170
    Assert-True ($script:Stopped.Count -eq 0) "(h3) disk counter unreadable, CPU flat: not closed at 170 s"

    # ============================================================ W3 rate limit
    Section "W3 at most 2 restarts per rolling 15 minutes"
    Reset-World
    Start-SelfHeal
    # A program that freezes again every time it comes back: each new copy is past grace (start time in the past).
    $script:NextId = 3001
    $each = {
        param($t)
        if ($script:FakeProcs.Count -eq 0) { Add-FakeProc -Id $script:NextId -Start $T0.AddSeconds($t - 600) -Responding $false; $script:NextId++ }
    }
    Invoke-Ticks -From 0 -To 840 -Each $each
    Assert-True ($script:Stopped.Count -eq 2) "a program that keeps freezing is closed exactly 2 times inside 15 minutes (closed $($script:Stopped.Count))"
    $gu = @(Get-OutboxRows "software.golf.frozen")
    Assert-True ($gu.Count -eq 1) "one 'gave up' report when the limit is reached"
    if ($gu.Count -eq 1) {
        $gm = Get-Metric $gu[0]
        Assert-True ($gm.reason -eq "rate_limit" -and $gm.restarts -ge 1) "...saying why (rate_limit) and how many restarts were tried"
        Assert-True ($gu[0].build_severity -eq 100000000) "...at Info by default: the gave-up row does not page the club on its own (A0.327(3)); see giveUpSeverity"
    }
    Invoke-Ticks -From 845 -To 960 -Each $each
    Assert-True ($script:Stopped.Count -eq 3) "15 minutes after the first restart, a third one is allowed (rolling window; closed $($script:Stopped.Count))"
    Invoke-Ticks -From 965 -To 3600 -Each $each
    $hist = @($script:SelfHealRuntime.History | Sort-Object)
    $worst = 0
    for ($i = 0; $i -lt $hist.Count; $i++) {
        $inWin = @($hist | Where-Object { $_ -ge $hist[$i] -and $_ -lt $hist[$i].AddMinutes(15) }).Count
        if ($inWin -gt $worst) { $worst = $inWin }
    }
    Assert-True ($hist.Count -ge 6 -and $worst -eq 2) "over an hour of a program that keeps freezing: $($hist.Count) restarts, never more than 2 in any 15-minute window (worst $worst)"

    # giveUpSeverity = warning opens an issue by design (a deliberate local choice, not a platform one).
    Reset-World
    Start-SelfHeal -WatchdogExtra @{ giveUpSeverity = "warning" }
    $script:NextId = 3101
    Invoke-Ticks -From 0 -To 840 -Each $each
    $gw = @(Get-OutboxRows "software.golf.frozen")
    Assert-True ($gw.Count -eq 1 -and $gw[0].build_severity -eq 100000001) "giveUpSeverity=warning makes ONLY the gave-up row Warning"
    Assert-True (@(Get-OutboxRows "software.golf.restarting" | Where-Object { $_.build_severity -ne 100000000 }).Count -eq 0) "...restart rows stay Info"

    # The count survives an agent restart (HostWatchdog restarts a dead agent; a crash loop must not reset it).
    Reset-World
    Start-SelfHeal
    $script:NextId = 3201
    Invoke-Ticks -From 0 -To 400 -Each $each
    $before = $script:Stopped.Count
    Assert-True ($before -eq 2) "precondition: 2 restarts used"
    $script:FakeProcs = @{}; $script:FakeResponding = @{}
    Start-SelfHeal -KeepState                                       # the agent restarts, same state file
    Invoke-Ticks -From 405 -To 800 -Each $each
    Assert-True ($script:Stopped.Count -eq $before) "after an agent restart, the 2 restarts already used still count (no third)"

    # A corrupt state file is not a zero count.
    Reset-World
    [IO.File]::WriteAllText($SelfHealStatePath, "{ this is not json")
    Start-SelfHeal -KeepState
    Add-FakeProc -Id 3301 -Responding $false
    Invoke-Ticks -From 0 -To 300
    Assert-True ($script:Stopped.Count -eq 0) "an unreadable state file holds restarts for a window rather than reading as zero"
    Invoke-Ticks -From 905 -To 960
    Assert-True ($script:Stopped.Count -eq 1) "...and releases them once that window has passed"

    # F1 (verifier, 2026-10-02, DO-NOT-MERGE): EVERY damaged shape of the count file holds, not only a parse error.
    # Two restarts used; the agent restarts and finds the file damaged; the program keeps freezing. No third restart
    # may happen inside 15 minutes of the first. (Lifted from the verifier's VFY-A, widened to its probe table.)
    $recentIso = $T0.AddSeconds(60).ToString("yyyy-MM-ddTHH:mm:ssZ")
    $shapes = [ordered]@{
        "empty (0 bytes)"            = [byte[]]@()
        "whitespace"                 = [Text.Encoding]::ASCII.GetBytes("  `r`n")
        "UTF-8 BOM only"             = [byte[]]@(0xEF, 0xBB, 0xBF)
        "NUL bytes"                  = (New-Object byte[] 80)
        "json null"                  = [Text.Encoding]::ASCII.GetBytes("null")
        "json {}"                    = [Text.Encoding]::ASCII.GetBytes("{}")
        "json []"                    = [Text.Encoding]::ASCII.GetBytes("[]")
        "history null"               = [Text.Encoding]::ASCII.GetBytes('{"restartHistoryUtc":null}')
        "history text"               = [Text.Encoding]::ASCII.GetBytes('{"restartHistoryUtc":"garbage"}')
        "history [garbage]"          = [Text.Encoding]::ASCII.GetBytes('{"restartHistoryUtc":["garbage"]}')
        "history [number]"           = [Text.Encoding]::ASCII.GetBytes('{"restartHistoryUtc":[12345]}')
        "history [one good, one bad]" = [Text.Encoding]::ASCII.GetBytes(('{"restartHistoryUtc":["' + $recentIso + '","x"]}'))
        "renamed key"                = [Text.Encoding]::ASCII.GetBytes(('{"restarts":["' + $recentIso + '"]}'))
        "truncated json"             = [Text.Encoding]::ASCII.GetBytes(('{"restartHistoryUtc":["' + $recentIso + '"'))
    }
    foreach ($shapeName in $shapes.Keys) {
        Reset-World
        Start-SelfHeal
        $script:NextId = 3401
        Invoke-Ticks -From 0 -To 400 -Each $each
        $usedBefore = $script:Stopped.Count
        [IO.File]::WriteAllBytes($SelfHealStatePath, $shapes[$shapeName])
        $script:FakeProcs = @{}; $script:FakeResponding = @{}
        Start-SelfHeal -KeepState
        Invoke-Ticks -From 405 -To 800 -Each $each
        $more = $script:Stopped.Count - $usedBefore
        Assert-True ($usedBefore -eq 2 -and $more -eq 0) "count file '$shapeName' after an agent restart: no third restart inside 15 minutes (got $usedBefore, then $more more)"
        Assert-True (@($script:LogLines | Where-Object { $_ -match "watchdog state unreadable" }).Count -ge 1) "...and the log says the count was unreadable"
    }
    # The control: a valid file holding two recent restarts also holds (it is read, not reset).
    Reset-World
    [IO.File]::WriteAllText($SelfHealStatePath, ('{"restartHistoryUtc":["' + $recentIso + '","' + $recentIso + '"]}'))
    Start-SelfHeal -KeepState
    Assert-True (@($script:SelfHealRuntime.History).Count -eq 2 -and @($script:LogLines | Where-Object { $_ -match "unreadable" }).Count -eq 0) "control: a valid count file is read as its two restarts, with no 'unreadable' line"
    Reset-World
    [IO.File]::WriteAllText($SelfHealStatePath, '{"restartHistoryUtc":[]}')
    Start-SelfHeal -KeepState
    Assert-True (@($script:SelfHealRuntime.History).Count -eq 0 -and @($script:LogLines | Where-Object { $_ -match "unreadable" }).Count -eq 0) "control: a valid EMPTY history reads as zero (not held)"

    # The count cannot be SAVED (a directory where the temp file goes stands in for a locked file or a full disk):
    # nothing is ever closed, and the bay says why. (Lifted from the verifier's VFY-B.)
    Reset-World
    Start-SelfHeal
    $script:NextId = 3501
    New-Item -ItemType Directory -Force -Path ($SelfHealStatePath + ".tmp") | Out-Null
    try {
        Invoke-Ticks -From 0 -To 400 -Each $each
        $usedB = $script:Stopped.Count
        $script:FakeProcs = @{}; $script:FakeResponding = @{}
        Start-SelfHeal -KeepState
        Invoke-Ticks -From 405 -To 800 -Each $each
        $moreB = $script:Stopped.Count - $usedB
        Assert-True ($usedB -eq 0 -and $moreB -eq 0) "count cannot be saved: nothing is closed, before or after an agent restart (got $usedB, then $moreB)"
        $cns = @(Get-OutboxRows "software.golf.frozen" | Where-Object { (Get-Metric $_).reason -eq "count_not_saved" })
        Assert-True ($cns.Count -ge 1) "...and a 'gave up' report says the count could not be saved"
    } finally {
        Remove-Item -LiteralPath ($SelfHealStatePath + ".tmp") -Recurse -Force -ErrorAction SilentlyContinue
    }

    # A save that "succeeds" but does not read back (the write landed something else) also never closes.
    Reset-World
    Add-FakeProc -Id 3601 -Responding $false
    Start-SelfHeal
    $realWriteTextAtomic = ${function:Write-TextAtomic}
    function Write-TextAtomic([string]$path, [string]$text) { [IO.File]::WriteAllText($path, "{}") }
    try {
        Invoke-Ticks -From 0 -To 120
        Assert-True ($script:Stopped.Count -eq 0) "a count file that does not read back after the save: nothing is closed"
    } finally {
        Set-Item -Path function:Write-TextAtomic -Value $realWriteTextAtomic
    }
    # The round trip keeps full precision (verifier R5: whole seconds let a slot free up to 1 s early).
    Reset-World
    Start-SelfHeal
    $script:SelfHealRuntime.History = [DateTime[]]@($T0.AddMilliseconds(900))
    $savedOk = Save-SelfHealState
    Assert-True ($savedOk -eq $true) "a normal save reports success"
    $back = Read-SelfHealState -Now $T0 -MaxRestarts 2
    Assert-True (@($back).Count -eq 1 -and $back[0] -eq $T0.AddMilliseconds(900)) "the saved restart time reads back to the tick ($(if (@($back).Count) { $back[0].ToString('o') }))"

    # The pure gate itself.
    $g = Get-SelfHealRestartAllowed -History @($T0, $T0.AddMinutes(5)) -Now $T0.AddMinutes(10) -MaxRestarts 2 -WindowMinutes 15
    Assert-True (-not $g.Allowed -and $g.NextAllowedUtc -eq $T0.AddMinutes(15)) "gate: 2 in the window refuses, next allowed when the oldest leaves"
    $g0 = Get-SelfHealRestartAllowed -History @($T0) -Now $T0.AddMinutes(1) -MaxRestarts 0 -WindowMinutes 15
    Assert-True (-not $g0.Allowed) "gate: maxRestarts 0 never allows (and does not throw)"

    # ============================================================ W4 the wrong process is never touched
    Section "W4 it never touches any other process"
    Reset-World
    Add-FakeProc -Id 4001 -Name "msedge" -Responding $false
    Add-FakeProc -Id 4002 -Name "powershell" -Responding $false
    Add-FakeProc -Id 4003 -Name "UneekorLauncherHelper" -Responding $false
    Add-FakeProc -Id 4004 -Name "UneekorLauncher" -Session 2 -Responding $false
    Add-FakeProc -Id $PID -Name "UneekorLauncher" -Responding $false
    Add-FakeProc -Id 4006 -Name "Refine" -Responding $false
    Start-SelfHeal
    Invoke-Ticks -From 0 -To 600
    Assert-True ($script:Stopped.Count -eq 0) "frozen msedge, powershell, a name that only STARTS with the target, the target in another Windows session, the agent's own pid, and an unlisted game: none closed (closed: $($script:Stopped -join ','))"

    # Deny list and name shape are enforced on the CONFIG, so a bad target never becomes a target.
    Reset-World
    Start-SelfHeal -WatchdogExtra @{ targets = @(@{ processName = "msedge" }, @{ processName = "Uneekor*" }, @{ processName = "C:\Uneekor\Launcher.exe" }, @{ processName = "explorer.exe" }, @{ processName = "BayAgent" }) }
    Assert-True (-not $script:SelfHealSettings.WatchdogEnabled) "a config whose only targets are msedge, a wildcard, a path, explorer and the agent leaves the watchdog OFF"
    Assert-True (@($script:SelfHealSettings.Errors | Where-Object { $_ -match "refused" }).Count -eq 5) "...each refused target is named in the log"
    Assert-True ($null -eq (ConvertTo-SelfHealTargetName "Uneekor?")) "a ? wildcard is refused"
    Assert-True ((ConvertTo-SelfHealTargetName "UneekorLauncher.exe") -eq "UneekorLauncher") "a trailing .exe is accepted and stripped"

    # PID reuse: the process judged frozen exits and its pid is reused by another program before the close.
    Reset-World
    Add-FakeProc -Id 4101 -Responding $false
    Start-SelfHeal
    $script:GetByIdOverride = { param($procId) [pscustomobject]@{ Id = $procId; Name = "notepad"; SessionId = 1; StartTimeUtc = $T0.AddMinutes(-10); MainWindowHandle = [Int64]0; CpuSeconds = 0.0; IoReadBytes = 0.0 } }
    Invoke-Ticks -From 0 -To 60
    Assert-True ($script:Stopped.Count -eq 0) "pid reused by another program between the judgment and the close: not closed"
    Assert-True (@($script:LogLines | Where-Object { $_ -match "NOT closed: pid_reused" }).Count -ge 1) "...and the log says why"
    Reset-World
    Add-FakeProc -Id 4102 -Responding $false
    Start-SelfHeal
    $script:GetByIdOverride = { param($procId) [pscustomobject]@{ Id = $procId; Name = "UneekorLauncher"; SessionId = 1; StartTimeUtc = $T0.AddSeconds(3); MainWindowHandle = [Int64]0; CpuSeconds = 0.0; IoReadBytes = 0.0 } }
    Invoke-Ticks -From 0 -To 60
    Assert-True ($script:Stopped.Count -eq 0) "pid reused by a NEW copy of the same program (different start time): not closed"
    Assert-True (@($script:LogLines | Where-Object { $_ -match "NOT closed: pid_reused" }).Count -ge 1) "...refused for the same reason"

    # Direct refusals of the closer itself.
    $layer = New-FakeLayer
    $tg = @([pscustomobject]@{ Name = "UneekorLauncher"; Relaunch = "shell"; Path = ""; ArgLine = "" })
    $mk = { param($id, $name, $sess, $start) [pscustomobject]@{ Id = $id; Name = $name; SessionId = $sess; StartTimeUtc = $start; MainWindowHandle = [Int64]0; CpuSeconds = 0.0; IoReadBytes = 0.0 } }
    $script:Stopped.Clear()
    Assert-True ((Invoke-SelfHealRestart -Layer $layer -ProcInfo (& $mk 5 "msedge" 1 $T0) -Targets $tg).Reason -eq "not_a_target") "closer refuses a non-target name"
    Assert-True ((Invoke-SelfHealRestart -Layer $layer -ProcInfo (& $mk $PID "UneekorLauncher" 1 $T0) -Targets $tg).Reason -eq "self") "closer refuses the agent's own pid"
    Assert-True ((Invoke-SelfHealRestart -Layer $layer -ProcInfo (& $mk 6 "UneekorLauncher" 2 $T0) -Targets $tg).Reason -eq "other_session") "closer refuses another session's copy"
    Assert-True ((Invoke-SelfHealRestart -Layer $layer -ProcInfo (& $mk 7 "UneekorLauncher" 1 $null) -Targets $tg).Reason -eq "no_start_time") "closer refuses a process whose identity (start time) cannot be read"
    $tgBad = @([pscustomobject]@{ Name = "msedge"; Relaunch = "shell"; Path = ""; ArgLine = "" })
    Assert-True ((Invoke-SelfHealRestart -Layer $layer -ProcInfo (& $mk 8 "msedge" 1 $T0) -Targets $tgBad).Reason -eq "not_a_target") "closer refuses a deny-listed name even if a target list names it"
    Assert-True ($script:Stopped.Count -eq 0) "...and none of those reached Stop"

    # The platform cannot steer the target: Apply-EffectiveConfigToRuntime rewrites $cfg.launcher.processName from
    # Dataverse. The watchdog reads the LOCAL file, so pointing $cfg at msedge changes nothing.
    Reset-World
    $path = New-SelfHealConfig -SelfHeal ([ordered]@{ enabled = $true; watchdog = [ordered]@{ enabled = $true; detector = "fake" } }) -LauncherName "UneekorLauncher"
    $cfg.launcher.processName = "msedge"
    Initialize-SelfHeal -ConfigPath $path -Now $T0 -Layer (New-FakeLayer)
    $cfg.launcher.processName = "msedge"
    Add-FakeProc -Id 4201 -Name "msedge" -Responding $false
    Add-FakeProc -Id 4202 -Name "UneekorLauncher" -Responding $false
    Invoke-Ticks -From 0 -To 60
    Assert-True (@($script:SelfHealSettings.Targets).Count -eq 1 -and $script:SelfHealSettings.Targets[0].Name -eq "UneekorLauncher") "the target comes from the local file's launcher, not the overlaid `$cfg"
    Assert-True ($script:Stopped.Count -eq 1 -and $script:Stopped[0] -eq 4202) "with `$cfg.launcher pointed at msedge, only the local file's target was closed"
    $cfg.launcher.processName = "UneekorLauncher"
    function Get-FuncVarNames([string]$fname) {
        $fd = $defs | Where-Object { $_.Name -eq $fname } | Select-Object -First 1
        return @($fd.FindAll({ param($n) $n -is [System.Management.Automation.Language.VariableExpressionAst] }, $true) | ForEach-Object { $_.VariablePath.UserPath })
    }
    $readVars = Get-FuncVarNames "Read-SelfHealSettings"
    Assert-True ($readVars.Count -gt 10 -and ($readVars -notcontains "cfg")) "Read-SelfHealSettings never reads the variable `$cfg (AST, comments excluded)"
    $tickVars = Get-FuncVarNames "Invoke-SelfHealWatchdogTick"
    Assert-True ($tickVars.Count -gt 10 -and ($tickVars -notcontains "cfg") -and (@($tickVars | Where-Object { $_ -match "EffectiveConfig" }).Count -eq 0)) "the watchdog tick never reads `$cfg or the platform overlay (AST)"

    # ============================================================ W5 holds
    Section "W5 Maintenance/Offline and the emergency stop only HOLD a restart"
    Reset-World
    Add-FakeProc -Id 5001 -Responding $false
    Start-SelfHeal
    $Global:EffectiveConfig = @{ "Bay.AgentStatus" = $AGENTSTATUS_MAINTENANCE; "Bay.AgentStatusReason" = "technician on site" }
    Invoke-Ticks -From 0 -To 300
    Assert-True ($script:Stopped.Count -eq 0) "bay in Maintenance (a technician may be at it): a frozen program is NOT closed"
    $Global:EffectiveConfig = @{ "Bay.AgentStatus" = $AGENTSTATUS_ONLINE }
    Invoke-Ticks -From 305 -To 320
    Assert-True ($script:Stopped.Count -eq 1) "...back Online, the still-frozen program is closed"
    Reset-World
    Add-FakeProc -Id 5002 -Responding $false
    Start-SelfHeal
    $Global:EmergencyStopEngaged = $true
    Invoke-Ticks -From 0 -To 300
    Assert-True ($script:Stopped.Count -eq 0) "emergency stop engaged: not closed"

    # ============================================================ W6 health self-reports
    Section "W6 health self-reports: golf program, screens, audio"
    Reset-World
    Add-FakeProc -Id 6001 -Responding $true
    Start-SelfHeal -NoWatchdog -Health -HealthExtra @{ expectedScreens = 3 }
    Invoke-SelfHealTick -Now $T0
    $h1 = @(@($script:SelfHealOutbox) | ForEach-Object { $_.row })
    Assert-True ($h1.Count -eq 3) "the first sample sends three rows (got $($h1.Count))"
    $hp = @(Get-OutboxRows "software.golf.responding"); $hs = @(Get-OutboxRows "display.screens"); $ha = @(Get-OutboxRows "pc.audio")
    Assert-True ($hp.Count -eq 1 -and $hp[0].statuscode -eq 1 -and $hp[0].build_metricvalue -eq 1 -and $hp[0].build_checkcategory -eq 100000004) "golf program running and responding: Passed, Software"
    Assert-True ($hs.Count -eq 1 -and $hs[0].statuscode -eq 1 -and $hs[0].build_metricvalue -eq 3 -and $hs[0].build_checkcategory -eq 100000005) "3 of 3 screens: Passed, Display, metric 3"
    Assert-True ($ha.Count -eq 1 -and $ha[0].statuscode -eq 1 -and $ha[0].build_metricvalue -eq 1 -and $ha[0].build_checkcategory -eq 100000000) "audio output present and unmuted: Passed, PC"
    Assert-True (@($h1 | Where-Object { $_.build_severity -ne 100000000 }).Count -eq 0) "all three are Info: a self-report never pages anyone"
    Assert-True (@($h1 | ForEach-Object { $_.build_diagnosticrunid } | Sort-Object -Unique).Count -eq 1) "the three share one run id (the ingest rolls up the worst of a run)"
    Assert-True (@($h1 | Where-Object { $_.build_diagnosticrunid.Length -gt 100 }).Count -eq 0) "run id fits the 100-character column"
    Invoke-SelfHealTick -Now $T0.AddSeconds(60)
    Assert-True (@($script:SelfHealOutbox).Count -eq 3) "nothing changed a minute later: nothing more is sent"

    # A change is sent, but not more often than the minimum gap.
    $script:FakeAudio = [pscustomobject]@{ Present = $false; HResult = -2147023728; DeviceId = $null; Muted = $null; VolumeScalar = $null }
    Invoke-SelfHealTick -Now $T0.AddSeconds(120)
    Assert-True (@($script:SelfHealOutbox).Count -eq 3) "audio lost 2 minutes after the last report: held by the 5-minute minimum gap"
    Invoke-SelfHealTick -Now $T0.AddSeconds(300)
    $ha2 = @(Get-OutboxRows "pc.audio")
    Assert-True ($ha2.Count -eq 2 -and $ha2[1].statuscode -eq 271980001 -and $ha2[1].build_metricvalue -eq 0) "...then sent: no audio output is Failed, metric 0"
    Assert-True ((Get-Metric $ha2[1]).hresult -eq "0x80070490") "...carrying Windows' own answer (E_NOTFOUND)"

    $script:FakeAudio = [pscustomobject]@{ Present = $true; HResult = 0; DeviceId = "dev"; Muted = $true; VolumeScalar = 0.5 }
    $script:FakeScreens = 2
    if ($script:FakeProcs.ContainsKey(6001)) { $script:FakeResponding[6001] = $false }
    Invoke-SelfHealTick -Now $T0.AddSeconds(660)
    $ha3 = @(Get-OutboxRows "pc.audio"); $hs3 = @(Get-OutboxRows "display.screens"); $hp3 = @(Get-OutboxRows "software.golf.responding")
    Assert-True ($ha3[$ha3.Count - 1].statuscode -eq 271980001) "muted output is Failed"
    Assert-True ($hs3[$hs3.Count - 1].statuscode -eq 271980001 -and $hs3[$hs3.Count - 1].build_metricvalue -eq 2) "2 of 3 expected screens is Failed"
    Assert-True ($hp3[$hp3.Count - 1].statuscode -eq 271980001) "golf program running but NOT responding is Failed"
    $script:FakeProcs.Remove(6001)
    $script:FakeAudio = $null
    Invoke-SelfHealTick -Now $T0.AddSeconds(1000)
    $hp4 = @(Get-OutboxRows "software.golf.responding"); $ha4 = @(Get-OutboxRows "pc.audio")
    Assert-True ($hp4[$hp4.Count - 1].statuscode -eq 271980001 -and $hp4[$hp4.Count - 1].build_details -match "not running") "golf program not running is Failed and says so"
    Assert-True ($ha4[$ha4.Count - 1].statuscode -eq 271980002) "an audio probe that cannot read is Inconclusive, not Passed"
    # Scheduled: an unchanged bay still reports every intervalMinutes.
    $n = @($script:SelfHealOutbox).Count
    Invoke-SelfHealTick -Now $T0.AddSeconds(1000 + 59 * 60)
    Assert-True (@($script:SelfHealOutbox).Count -eq $n) "unchanged, 59 minutes later: nothing"
    Invoke-SelfHealTick -Now $T0.AddSeconds(1000 + 60 * 60)
    Assert-True (@($script:SelfHealOutbox).Count -eq $n + 3) "unchanged, 60 minutes later: the scheduled report"

    # ============================================================ W7 delivery into the pipe (mock Dataverse)
    Section "W7 delivery into build_diagnosticlogs (a MOCK Dataverse on 127.0.0.1)"
    $sync = [hashtable]::Synchronized(@{
        Stop = $false; Port = 0
        Requests = [System.Collections.ArrayList]::Synchronized((New-Object System.Collections.ArrayList))
        Responses = [System.Collections.Queue]::Synchronized((New-Object System.Collections.Queue))
        Errors = [System.Collections.ArrayList]::Synchronized((New-Object System.Collections.ArrayList))
    })
    $rs = [runspacefactory]::CreateRunspace(); $rs.Open(); $rs.SessionStateProxy.SetVariable("sync", $sync)
    $mockPs = [powershell]::Create(); $mockPs.Runspace = $rs
    [void]$mockPs.AddScript({
        $listener = New-Object System.Net.Sockets.TcpListener([System.Net.IPAddress]::Loopback, 0)
        $listener.Start()
        $sync["Port"] = ([System.Net.IPEndPoint]$listener.LocalEndpoint).Port
        try {
            while (-not $sync["Stop"]) {
                if (-not $listener.Server.Poll(200000, [System.Net.Sockets.SelectMode]::SelectRead)) { continue }
                $client = $listener.AcceptTcpClient()
                try {
                    $client.ReceiveTimeout = 5000
                    $stream = $client.GetStream()
                    $buf = New-Object byte[] 65536
                    $ms = New-Object System.IO.MemoryStream
                    $headerEnd = -1
                    while ($headerEnd -lt 0) {
                        $n = $stream.Read($buf, 0, $buf.Length); if ($n -le 0) { break }
                        $ms.Write($buf, 0, $n)
                        $headerEnd = ([Text.Encoding]::ASCII.GetString($ms.ToArray())).IndexOf("`r`n`r`n")
                    }
                    $all = $ms.ToArray()
                    $headText = [Text.Encoding]::ASCII.GetString($all, 0, $headerEnd)
                    $contentLength = 0
                    if ($headText -match "(?im)^Content-Length:\s*(\d+)") { $contentLength = [int]$Matches[1] }
                    $bodyStart = $headerEnd + 4
                    while (($all.Length - $bodyStart) -lt $contentLength) {
                        $n = $stream.Read($buf, 0, $buf.Length); if ($n -le 0) { break }
                        $ms.Write($buf, 0, $n); $all = $ms.ToArray()
                    }
                    $body = [Text.Encoding]::UTF8.GetString($all, $bodyStart, [Math]::Min($contentLength, $all.Length - $bodyStart))
                    [void]$sync["Requests"].Add(@{ requestLine = (($headText -split "`r`n")[0]); headers = $headText; body = $body })
                    $resp = @{ status = 204; body = "" }
                    if ($sync["Responses"].Count -gt 0) { $resp = $sync["Responses"].Dequeue() }
                    $status = [int]$resp.status
                    $reason = "No Content"; if ($status -eq 412) { $reason = "Precondition Failed" } elseif ($status -eq 403) { $reason = "Forbidden" } elseif ($status -eq 500) { $reason = "Internal Server Error" }
                    $bytes = [Text.Encoding]::UTF8.GetBytes([string]$resp.body)
                    $head = "HTTP/1.1 $status $reason`r`nContent-Type: application/json; charset=utf-8`r`nContent-Length: $($bytes.Length)`r`nConnection: close`r`n`r`n"
                    $hb = [Text.Encoding]::ASCII.GetBytes($head)
                    $stream.Write($hb, 0, $hb.Length); if ($bytes.Length -gt 0) { $stream.Write($bytes, 0, $bytes.Length) }; $stream.Flush()
                } catch { [void]$sync["Errors"].Add($_.Exception.Message) }
                finally { $client.Close() }
            }
        } finally { $listener.Stop() }
    })
    $mockHandle = $mockPs.BeginInvoke()
    $deadline = (Get-Date).AddSeconds(10)
    while ($sync["Port"] -eq 0 -and (Get-Date) -lt $deadline) { Start-Sleep -Milliseconds 50 }
    try {
        Assert-True ($sync["Port"] -ne 0) "mock Dataverse is listening"
        $OrgUrl = "http://127.0.0.1:$($sync['Port'])"

        Reset-World
        Add-FakeProc -Id 7001 -Responding $true
        Start-SelfHeal -NoWatchdog -Health
        Invoke-SelfHealTick -Now $T0
        $queued = @(@($script:SelfHealOutbox) | ForEach-Object { $_.row.build_diagnosticlogid })
        Assert-True ($queued.Count -eq 3) "precondition: three reports queued"
        $onDiskRaw = Get-Content -LiteralPath $SelfHealOutboxPath -Raw | ConvertFrom-Json
        Assert-True (@($onDiskRaw).Count -eq 3) "the outbox is on disk (it survives an agent restart before delivery)"
        Start-SelfHeal -NoWatchdog -Health -KeepState
        Assert-True (@($script:SelfHealOutbox).Count -eq 3) "...and an agent restart reloads it"

        # 1: a failure keeps everything and backs off.
        $sync["Responses"].Enqueue(@{ status = 403; body = '{"error":{"code":"0x80040220","message":"Principal user is missing prvCreatebuild_DiagnosticLog privilege"}}' })
        Send-SelfHealOutboxIfDue -token "mock-token" -Now $T0
        Assert-True ($sync["Requests"].Count -eq 1) "one POST, then it stops trying for this pass after a failure"
        Assert-True (@($script:SelfHealOutbox).Count -eq 3) "a 403 (role cannot create the row) loses nothing"
        Assert-True (@($script:LogLines | Where-Object { $_ -match "not delivered \(status=403\)" -and $_ -match "prvCreate" }).Count -eq 1) "...and the log names the status and Dataverse's reason"
        Send-SelfHealOutboxIfDue -token "mock-token" -Now $T0.AddSeconds(30)
        Assert-True ($sync["Requests"].Count -eq 1) "...and it backs off (no retry 30 s later)"

        # 2: success after the backoff; the first is a duplicate (an earlier POST that landed, response lost).
        $sync["Responses"].Enqueue(@{ status = 412; body = '{"error":{"code":"0x80040237","message":"A record with matching key values already exists."}}' })
        Send-SelfHealOutboxIfDue -token "mock-token" -Now $T0.AddSeconds(200)
        Assert-True ($sync["Requests"].Count -eq 4) "after the backoff, all three are POSTed (got $($sync['Requests'].Count - 1) more)"
        Assert-True (@($script:SelfHealOutbox).Count -eq 0) "a duplicate-key answer counts as delivered; the outbox is empty"
        $req = $sync["Requests"][1]
        Assert-True ($req.requestLine -match '^POST /api/data/v9\.2/build_diagnosticlogs HTTP/1\.1$') "POST goes to /api/data/v9.2/build_diagnosticlogs ($($req.requestLine))"
        Assert-True ($req.headers -match "(?im)^Authorization: Bearer mock-token") "...with the bearer token"
        $b = $req.body | ConvertFrom-Json
        Assert-True ($queued -contains $b.build_diagnosticlogid) "...carrying the row's own id (idempotent retry)"
        Assert-True ($b."build_Bay@odata.bind" -eq "/build_baies($BayId)" -and $null -ne $b.build_checkcategory -and $null -ne $b.build_severity -and $null -ne $b.statuscode -and $null -ne $b.build_timestamp) "...and the contract's fields: bay, category, severity, status, timestamp"
        Assert-True ($req.body -notmatch "mock-token") "the token is never in a row body"
        $onDiskRaw2 = Get-Content -LiteralPath $SelfHealOutboxPath -Raw | ConvertFrom-Json
        Assert-True (@(@($onDiskRaw2) | Where-Object { $null -ne $_ }).Count -eq 0) "the outbox on disk is emptied too"

        # 3: a full outbox drops the OLDEST and says so.
        Reset-World
        Start-SelfHeal -NoWatchdog -Health
        for ($i = 0; $i -lt ($SelfHealOutboxMax + 5); $i++) {
            Add-SelfHealOutbox (New-SelfHealDiagRow -CheckId "pc.audio" -Category 100000000 -Severity 100000000 -Status 1 -RunId "r$i" -AtUtc $T0)
        }
        Assert-True (@($script:SelfHealOutbox).Count -eq $SelfHealOutboxMax) "the outbox is bounded at $SelfHealOutboxMax"
        Assert-True (@($script:SelfHealOutbox)[0].row.build_diagnosticrunid -eq "r5") "...dropping the oldest first"
        Assert-True (@($script:LogLines | Where-Object { $_ -match "outbox full" }).Count -ge 1) "...and logging the drop"
    } finally {
        $sync["Stop"] = $true
        try { $mockPs.Stop() } catch {}
        try { $rs.Close() } catch {}
    }

    # ============================================================ W8 detectors
    Section "W8 detection is pluggable; 'cannot tell' never restarts"
    Reset-World
    Add-FakeProc -Id 8001 -Responding $false
    Start-SelfHeal -Detector "uneekorShotFeed"
    Invoke-Ticks -From 0 -To 600
    Assert-True ($script:Stopped.Count -eq 0) "an unknown detector name: every reading is 'cannot tell', nothing is closed"
    Assert-True (@($script:LogLines | Where-Object { $_ -match "\[ERROR\].*detector 'uneekorShotFeed' is not known" }).Count -eq 1) "...and the log says so at ERROR"
    # Plugging one in: register it, name it in config, and it is the one asked.
    $script:CustomAsked = 0
    $script:SelfHealDetectors["benchAnswer"] = { param($procInfo, $layer) $script:CustomAsked++; return @{ Responding = $false; Detail = "bench" } }
    Reset-World
    Add-FakeProc -Id 8002 -Responding $true
    Start-SelfHeal -Detector "benchAnswer"
    Invoke-Ticks -From 0 -To 60
    Assert-True ($script:CustomAsked -gt 0 -and $script:Stopped.Count -eq 1) "a detector plugged in by name is the one the watchdog asks (asked $($script:CustomAsked) times)"
    $script:SelfHealDetectors.Remove("benchAnswer")
    # A detector that throws or answers something that is not a boolean reads as 'cannot tell'.
    $script:SelfHealDetectors["broken"] = { param($procInfo, $layer) throw "boom" }
    $script:SelfHealDetectors["texty"] = { param($procInfo, $layer) return @{ Responding = "false" } }
    $pinfo = [pscustomobject]@{ Id = 1; Name = "x"; SessionId = 1; StartTimeUtc = $T0; MainWindowHandle = [Int64]0; CpuSeconds = 0.0; IoReadBytes = 0.0 }
    Assert-True ($null -eq (Get-SelfHealReading $pinfo $null "broken").Responding) "a detector that throws reads as 'cannot tell'"
    Assert-True ($null -eq (Get-SelfHealReading $pinfo $null "texty").Responding) "a detector answering the TEXT 'false' reads as 'cannot tell', not as frozen"
    # The shipped detectors: no window is 'cannot tell'; a handle that is not a window is 'cannot tell'.
    Assert-True ($script:SelfHealDetectors.ContainsKey("hungAppWindow") -and $script:SelfHealDetectors.ContainsKey("processResponding")) "the two shipped detectors are registered"
    Assert-True ($null -eq (Get-SelfHealReading $pinfo $null "hungAppWindow").Responding) "hungAppWindow: a process with no main window is 'cannot tell'"
    $pinfo2 = [pscustomobject]@{ Id = 1; Name = "x"; SessionId = 1; StartTimeUtc = $T0; MainWindowHandle = [Int64]0x7FFF0001; CpuSeconds = 0.0; IoReadBytes = 0.0 }
    Assert-True ($null -eq (Get-SelfHealReading $pinfo2 $null "hungAppWindow").Responding) "hungAppWindow: a handle that is not a window is 'cannot tell' (real user32 call)"
    Assert-True ($script:SelfHealSettings.Detector -ne "" -and (Read-SelfHealSettings -Path (New-SelfHealConfig -SelfHeal ([ordered]@{ enabled = $true; watchdog = [ordered]@{ enabled = $true } }))).Detector -eq "hungAppWindow") "the default detector is hungAppWindow"
    # The real audio probe (READ ONLY) answers without throwing on this machine.
    $realLayer = New-SelfHealProcessLayer
    $au = & $realLayer.Audio
    Assert-True ($null -ne $au -and ($au.Present -is [bool])) "the real Core Audio probe answers on this machine (present=$($au.Present), hr=0x$('{0:X8}' -f [int]$au.HResult))"
    Assert-True ([int](& $realLayer.ScreenCount) -ge 1) "the real screen count answers on this machine"
    $selfInfo = & $realLayer.GetById $PID
    Assert-True ($null -ne $selfInfo -and $null -ne $selfInfo.StartTimeUtc -and $selfInfo.SessionId -eq $realLayer.OwnSessionId) "the real process layer reads id, session and start time (read only, this test's own process)"

    # ============================================================ W9 wiring
    Section "W9 wiring in the main loop"
    $src = [IO.File]::ReadAllText($AgentScript)
    $loopAt = $src.LastIndexOf("while (`$true) {")
    $tickAt = $src.IndexOf("Invoke-SelfHealTick -Now", $loopAt)
    $tokenAt = $src.IndexOf("`$token = Get-AccessToken", $loopAt)
    $tryAt = $src.LastIndexOf("try {", $tokenAt)
    $hbAt = $src.IndexOf("Send-HeartbeatIfDue `$token", $loopAt)
    $sendAt = $src.IndexOf("Send-SelfHealOutboxIfDue -token `$token", $loopAt)
    Assert-True ($loopAt -gt 0 -and $tickAt -gt $loopAt -and $tickAt -lt $tryAt -and $tickAt -lt $tokenAt) "the watchdog tick runs at the top of the loop, before and outside the token's try (it works with the internet down)"
    Assert-True ($sendAt -gt $hbAt) "report delivery runs after the heartbeat, inside the token's try"
    $cmdSrc = (($defs | Where-Object { $_.Name -eq "Execute-Command" }) | Select-Object -First 1).Extent.Text
    Assert-True ($cmdSrc -notmatch "SelfHeal") "no bay command reaches the watchdog: Execute-Command never calls it (A0.316(4), no new bay command)"
    $callers = @($defs | Where-Object { $_.Name -notmatch "SelfHeal" -and $_.Extent.Text -match "Invoke-SelfHealRestart|Invoke-SelfHealWatchdogTick|Invoke-SelfHealTick" } | ForEach-Object { $_.Name })
    Assert-True ($callers.Count -eq 0) "nothing outside the self-heal section calls the watchdog or the closer (callers: $($callers -join ','))"
}
finally {
    try { Remove-Item -LiteralPath $BaseDir -Recurse -Force -ErrorAction SilentlyContinue } catch {}
}

Write-Host ""
Write-Host ("RESULT: {0} passed, {1} failed" -f $script:Pass, $script:Fail) -ForegroundColor $(if ($script:Fail -eq 0) { "Green" } else { "Red" })
if ($script:Fail -gt 0) { $script:Failures | ForEach-Object { Write-Host "  - $_" -ForegroundColor Red }; exit 1 }
exit 0
