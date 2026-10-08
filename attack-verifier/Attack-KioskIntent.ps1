<#
Verifier attack (2026-10-08): drive the REAL agent kiosk-intent functions (lifted by AST from BayAgent.ps1 at the
branch head) through command sequences a bay can receive, and read what the shell would do (its real
Get-KioskLauncherWanted + Get-KioskLauncherAction, lifted from ABG.KioskShell.ps1). Sandbox only; hyphens only.
#>
param([string]$Repo = "C:\aoc-wt\kiosk-attack")
Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
$AgentScript = Join-Path $Repo "src\BayAgent\BayAgent.ps1"
$ShellScript = Join-Path $Repo "src\BayAgent\kiosk\ABG.KioskShell.ps1"

$tk = $null; $er = $null
$agentAst = [System.Management.Automation.Language.Parser]::ParseFile($AgentScript, [ref]$tk, [ref]$er)
$shellAst = [System.Management.Automation.Language.Parser]::ParseFile($ShellScript, [ref]$tk, [ref]$er)

# constants the functions read
$CMD_UPDATESESSIONDISPLAY = 100000005; $CMD_STARTSESSION = 100000010; $CMD_ENDSESSION = 100000011; $CMD_RESET = 100000012; $CMD_EMERGENCY_STOP = 100000027
$AgentCodeVersion = "1.4.0"
$BaseDir = Join-Path $env:TEMP ("kiosk-verif-" + [guid]::NewGuid().ToString("N").Substring(0, 8))
New-Item -ItemType Directory -Force -Path (Join-Path $BaseDir "state") | Out-Null
$Global:EmergencyStopEngaged = $false
function Write-Log([string]$m, [string]$l = "INFO") { Write-Host ("    [agent log {0}] {1}" -f $l, $m) -ForegroundColor DarkGray }

# lift every top-level $Kiosk* assignment and every Kiosk function from the agent
foreach ($st in $agentAst.EndBlock.Statements) {
    if ($st -is [System.Management.Automation.Language.AssignmentStatementAst] -and $st.Left.Extent.Text -match '^\$(Global:)?Kiosk') {
        . ([scriptblock]::Create($st.Extent.Text))
    }
}
$agentFns = @($agentAst.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -match 'Kiosk' }, $true))
foreach ($f in $agentFns) { . ([scriptblock]::Create($f.Extent.Text)) }
# the shell's own launcher-action decision
$shellAction = @($shellAst.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq "Get-KioskLauncherAction" }, $true))[0]
. ([scriptblock]::Create($shellAction.Extent.Text))
Write-Host ("lifted {0} agent functions; intent path {1}" -f $agentFns.Count, $KioskIntentPath)

function Show-Shell([string]$label, [int]$secondsLater = 20) {
    $now = (Get-Date).ToUniversalTime().AddSeconds($secondsLater)
    $w = Get-KioskLauncherWanted -IntentRead (Read-KioskJsonFile -Path $KioskIntentPath -MaxBytes 8192) -NowUtc $now
    $closedFor = $(if ($w.Closed) { ($now - $w.ClosedSinceUtc).TotalSeconds } else { 0 })
    $act = Get-KioskLauncherAction -Wanted $w.Wanted -Running $true -AbsentTicks 0 -StartAllowed $true -PathExists $true -Closed $w.Closed -ClosedForSeconds $closedFor -CloseGraceSeconds 15
    Write-Host ("  {0}: intent wanted={1} closed={2} ({3}); shell action on a RUNNING launcher {4} s later = {5}" -f $label, $w.Wanted, $w.Closed, $w.Reason, $secondsLater, $act.ToUpper())
    return $act
}
function Reset-Sandbox { Remove-Item -LiteralPath $KioskIntentPath -Force -ErrorAction SilentlyContinue; $Global:KioskIntentExpectedText = $null; $Global:EmergencyStopEngaged = $false }

$now = (Get-Date).ToUniversalTime()
$start = @{ mode = "Start"; baySessionId = "S-A"; playEndUtc = $now.AddMinutes(45).ToString("yyyy-MM-ddTHH:mm:ssZ") }
$resetCanceled = (ConvertFrom-Json '{"mode":"Full","reason":"BookingCanceled"}')   # the platform's exact Reset payload (BayCancelEndSessionPolicy.ResetPayload)
$results = [ordered]@{}

Write-Host "`n== E1 baseline: a member plays (wanted), another booking on the bay is canceled (Reset)"
Reset-Sandbox
$null = Set-KioskIntentForCommand -CommandType $CMD_STARTSESSION -Mode "Start" -Payload $start
$null = Set-KioskIntentForCommand -CommandType $CMD_RESET -Mode "" -Payload $resetCanceled
$results["E1 baseline"] = Show-Shell "E1"

Write-Host "`n== E2 emergency stop engaged and CLEARED mid-session, member resumes play, then another booking is canceled"
Reset-Sandbox
$null = Set-KioskIntentForCommand -CommandType $CMD_STARTSESSION -Mode "Start" -Payload $start
$Global:EmergencyStopEngaged = $false
$null = Set-KioskIntentForCommand -CommandType $CMD_EMERGENCY_STOP -Mode "" -Payload (ConvertFrom-Json '{"action":"engage","reason":"test"}')
$Global:EmergencyStopEngaged = $true
$null = Set-KioskIntentForCommand -CommandType $CMD_EMERGENCY_STOP -Mode "" -Payload (ConvertFrom-Json '{"action":"clear"}')
$Global:EmergencyStopEngaged = $false
Show-Shell "E2 after clear" | Out-Null
$null = Set-KioskIntentForCommand -CommandType $CMD_RESET -Mode "" -Payload $resetCanceled
$results["E2 estop-clear then Reset"] = Show-Shell "E2 after Reset"

Write-Host "`n== E3 Maintenance mode mid-session (reconcile writes unmanaged), lifted, member keeps playing, then a Reset"
Reset-Sandbox
$null = Set-KioskIntentForCommand -CommandType $CMD_STARTSESSION -Mode "Start" -Payload $start
# exactly what Invoke-KioskReconcileTick writes when Get-AgentOperationalState says Blocked
$cur = Get-KioskLauncherWanted -IntentRead (Read-KioskJsonFile -Path $KioskIntentPath -MaxBytes 8192) -NowUtc ((Get-Date).ToUniversalTime())
if ($cur.Wanted -or $cur.Closed) { [void](Write-KioskIntent -Launcher "unmanaged" -UntilUtc $null -SessionId ([string]$cur.SessionId) -Reason "bay in Maintenance mode") }
$null = Set-KioskIntentForCommand -CommandType $CMD_RESET -Mode "" -Payload $resetCanceled
$results["E3 maintenance-lifted then Reset"] = Show-Shell "E3"

Write-Host "`n== E4 add-time extension: the Extend display command was not queued (best effort), old end + 2 min passed, member still in paid time, then a Reset"
Reset-Sandbox
$startOld = @{ mode = "Start"; baySessionId = "S-A"; playEndUtc = (Get-Date).ToUniversalTime().AddMinutes(-3).ToString("yyyy-MM-ddTHH:mm:ssZ") }
$null = Set-KioskIntentForCommand -CommandType $CMD_STARTSESSION -Mode "Start" -Payload $startOld
# the Warn5 at the NEW end - 5 min arrives later; before it, a Reset
$null = Set-KioskIntentForCommand -CommandType $CMD_RESET -Mode "" -Payload $resetCanceled
$results["E4 extension display lost then Reset"] = Show-Shell "E4"
$warn5 = @{ mode = "Warn5"; baySessionId = "S-A"; playEndUtc = (Get-Date).ToUniversalTime().AddMinutes(25).ToString("yyyy-MM-ddTHH:mm:ssZ") }
$null = Set-KioskIntentForCommand -CommandType $CMD_UPDATESESSIONDISPLAY -Mode "Warn5" -Payload $warn5
Show-Shell "E4 after the new-end Warn5 (same session)" | Out-Null

Write-Host "`n== E5 back-to-back: A's End writes closed; B's Start intent write FAILS (file held open by a reader without FILE_SHARE_DELETE)"
Reset-Sandbox
$null = Set-KioskIntentForCommand -CommandType $CMD_STARTSESSION -Mode "Start" -Payload $start
$null = Set-KioskIntentForCommand -CommandType $CMD_ENDSESSION -Mode "End" -Payload @{ baySessionId = "S-A" } -SameSession $true
Show-Shell "E5 after A End" | Out-Null
$hold = [IO.File]::Open($KioskIntentPath, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
try {
    $startB = @{ mode = "Start"; baySessionId = "S-B"; playEndUtc = (Get-Date).ToUniversalTime().AddMinutes(60).ToString("yyyy-MM-ddTHH:mm:ssZ") }
    $r = Set-KioskIntentForCommand -CommandType $CMD_STARTSESSION -Mode "Start" -Payload $startB
    Write-Host ("  B Start returned: launcher={0} written={1}" -f $r.launcher, $r.written)
} finally { $hold.Dispose() }
# next main-loop passes: the integrity check (does it repair?)
$restored = Test-KioskIntentIntegrity
Write-Host ("  integrity check after the lock released: restored={0}" -f $restored)
$results["E5 Start write failed (B paying)"] = Show-Shell "E5 B is playing" 60
$results["E5 ... 30 min later"] = Show-Shell "E5 B still playing" 1800

Write-Host "`n== E6 a late End for an OLDER session with NO baySessionId while B plays (sameSession reads true)"
Reset-Sandbox
$null = Set-KioskIntentForCommand -CommandType $CMD_STARTSESSION -Mode "Start" -Payload @{ mode = "Start"; baySessionId = "S-B"; playEndUtc = (Get-Date).ToUniversalTime().AddMinutes(60).ToString("yyyy-MM-ddTHH:mm:ssZ") }
$null = Set-KioskIntentForCommand -CommandType $CMD_ENDSESSION -Mode "End" -Payload @{ } -SameSession $true
$results["E6 sid-less End"] = Show-Shell "E6"

Write-Host "`n== SUMMARY"
foreach ($k in $results.Keys) { Write-Host ("  {0,-40} {1}" -f $k, $results[$k]) }
Remove-Item -LiteralPath $BaseDir -Recurse -Force -ErrorAction SilentlyContinue
