<#
BayAgent.Kiosk.Tests.ps1 (A0.363, BayAgent 1.4.0)

WHAT THIS COVERS
  The kiosk shell's decisions, on both sides, lifted out of the shipped files by AST (no registry, no real shell):
    K-PARITY  the five functions the agent and the shell share are byte-identical in both files
    K1        the policy reader: every malformed shape reads as "explorer" (today's desktop); only an exact schema-1
              policy naming an implemented mode turns anything on; the kill switch beats everything
    K2        the intent reader: only an exact "wanted" with a future, zoned untilUtc is wanted
    K3        ConvertTo-KioskUtc: zone required, PowerShell 7 DateTime and 5.1 string both read
    K4        what each command does to the intent (Start, Prep, End same/other session, Reset, emergency stop,
              an extension by UpdateSessionDisplay, startOnStart=false)
    K5        the intent writer reads back through the shell's own reader
    K6        the intent at agent start, re-derived from session.json
    K7        the activation verifier, every refusal and its order
    K8        shell liveness: absent, gone, foreign process, alive, stale, hung; the command-line match
    K9        the reconciler with injected start/stop: starts only a verified file in companion mode, never in
              explorer mode, stops only a hung shell by its verified pid, caps starts per hour (persisted)
    K10       the launcher deferral at StartSession Start (one starter at a time)
    K11       the shell's pure decisions: launcher action (never "stop"), wall plan, floor, supervision, roles over
              topologies (missing screen included), start caps, degrade threshold
    K18c      RF-K1/RF-K2 (attack 2026-10-09): the running-session record, the Reset gate keyed on it, the shell's
              ENDED-for-that-session close rule, the Skipped close-out in Process-Command, through the real handlers
    K12       censuses: no registry WRITE in either file, no process stop in the shell at all, the agent stops a
              process only in the hung branch, the shell reads nothing from the platform, the intent is written
              before the launcher is started (Start) and before it is closed (End)

RUN (from the repo root; Windows PowerShell 5.1 or PowerShell 7)
  powershell -NoProfile -ExecutionPolicy Bypass -File tests\BayAgent.Kiosk.Tests.ps1
Exit code 0 = all assertions passed. Hyphens only in comments.
#>
[CmdletBinding()]
param([string]$AgentScript = "", [string]$ShellScript = "")

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
if ([string]::IsNullOrWhiteSpace($AgentScript)) { $AgentScript = Join-Path $PSScriptRoot "..\src\BayAgent\BayAgent.ps1" }
if ([string]::IsNullOrWhiteSpace($ShellScript)) { $ShellScript = Join-Path $PSScriptRoot "..\src\BayAgent\kiosk\ABG.KioskShell.ps1" }
$AgentScript = (Resolve-Path $AgentScript).Path
$ShellScript = (Resolve-Path $ShellScript).Path

$script:Pass = 0; $script:Fail = 0; $script:Failures = @()
function Assert-True([bool]$cond, [string]$msg) {
    if ($cond) { $script:Pass++; Write-Host "  PASS  $msg" }
    else { $script:Fail++; $script:Failures += $msg; Write-Host "  FAIL  $msg" -ForegroundColor Red }
}
function Section([string]$name) { Write-Host ""; Write-Host "== $name" -ForegroundColor Cyan }

function Get-TestAst([string]$path) {
    $tk = $null; $er = $null
    $a = [System.Management.Automation.Language.Parser]::ParseFile($path, [ref]$tk, [ref]$er)
    if (@($er).Count -gt 0) { throw "$path has parse errors" }
    return $a
}
$AgentAst = Get-TestAst $AgentScript
$ShellAst = Get-TestAst $ShellScript
$AgentDefs = @($AgentAst.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $true))
$ShellDefs = @($ShellAst.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $true))
function Get-DefText($defs, [string]$name) {
    $d = @($defs | Where-Object { $_.Name -eq $name })
    if ($d.Count -ne 1) { throw "function $name found $($d.Count) times" }
    return $d[0].Extent.Text
}

$Sandbox = Join-Path $env:TEMP ("bayagent-kiosk-unit-" + [guid]::NewGuid().ToString("N").Substring(0, 8))
New-Item -ItemType Directory -Force -Path (Join-Path $Sandbox "state") | Out-Null
New-Item -ItemType Directory -Force -Path (Join-Path $Sandbox "control") | Out-Null
New-Item -ItemType Directory -Force -Path (Join-Path $Sandbox "current\kiosk") | Out-Null
$BaseDir = $Sandbox
$AgentCodeVersion = "1.4.0"
$AgentScriptPath = $AgentScript
$Global:LogLevel = "DEBUG"
$script:LogLines = New-Object System.Collections.ArrayList
function Write-Log { param([string]$Message, [string]$Level = "INFO") [void]$script:LogLines.Add("[$Level] $Message") }
$Global:EmergencyStopEngaged = $false
$Global:EffectiveConfig = $null
$Global:NextCapabilitiesUtc = [DateTime]::MinValue

# ---------------------------------------------------------------- lift: script constants, then functions
foreach ($st in @($AgentAst.EndBlock.Statements)) {
    if ($st -isnot [System.Management.Automation.Language.AssignmentStatementAst]) { continue }
    $lhs = $st.Left.Extent.Text
    if ($lhs -match '^\$(CMD_|AGENTSTATUS_|STATUS_|Lookup_|Col_|Kiosk|RunningSession)' -or $lhs -match '^\$Global:(Kiosk|RunningSession)') { . ([scriptblock]::Create($st.Extent.Text)) }
}
$agentWanted = @("Get-PropValue", "Write-TextAtomic", "Write-JsonAtomic", "Get-SessionJsonPath", "Read-SessionModelFromDisk", "Get-EffectiveConfigValue", "Get-AgentOperationalState") +
    @($AgentDefs | Where-Object { $_.Name -match 'Kiosk' -and $_.Parent -isnot [System.Management.Automation.Language.FunctionDefinitionAst] } | ForEach-Object { $_.Name })
foreach ($n in $agentWanted) { . ([scriptblock]::Create((Get-DefText $AgentDefs $n))) }
$shellOnly = @($ShellDefs | Where-Object { $_.Name -notin $agentWanted } | ForEach-Object { $_.Name })
foreach ($n in $shellOnly) { . ([scriptblock]::Create((Get-DefText $ShellDefs $n))) }
$cfg = [pscustomobject]@{ sessionJsonPath = (Join-Path $Sandbox "session.json") }

$UtcNow = [DateTime]::SpecifyKind([DateTime]::Parse("2026-10-08T12:00:00"), [DateTimeKind]::Utc)
function Set-TestFile([string]$path, [string]$text) {
    $d = Split-Path -Parent $path
    if (-not (Test-Path -LiteralPath $d)) { New-Item -ItemType Directory -Force -Path $d | Out-Null }
    [IO.File]::WriteAllText($path, $text, (New-Object Text.UTF8Encoding($false)))
}
function Set-TestBytes([string]$path, [byte[]]$bytes) { [IO.File]::WriteAllBytes($path, $bytes) }
function Read-Policy([string]$text) {
    $p = Join-Path $Sandbox "probe-policy.json"
    if ($null -eq $text) { if (Test-Path -LiteralPath $p) { Remove-Item -LiteralPath $p -Force }; return (Read-KioskJsonFile -Path $p -MaxBytes 4096) }
    Set-TestFile $p $text
    return (Read-KioskJsonFile -Path $p -MaxBytes 4096)
}

try {
    # ============================================================ K-PARITY
    Section "K-PARITY the agent and the shell decide the same way (shared functions byte-identical)"
    foreach ($n in @("Get-KioskProp", "Read-KioskJsonFile", "ConvertTo-KioskUtc", "Get-KioskPolicyDecision", "Get-KioskLauncherWanted")) {
        $a = (Get-DefText $AgentDefs $n) -replace "`r", ""
        $s = (Get-DefText $ShellDefs $n) -replace "`r", ""
        Assert-True ($a -ceq $s) "$n is identical in BayAgent.ps1 and ABG.KioskShell.ps1"
    }

    # ============================================================ K1
    Section "K1 policy: everything but an exact, implemented policy is explorer"
    $cases = @(
        @{ T = $null; Want = "explorer"; Why = "absent" },
        @{ T = ""; Want = "explorer"; Why = "empty file" },
        @{ T = "   `r`n "; Want = "explorer"; Why = "whitespace" },
        @{ T = "null"; Want = "explorer"; Why = "null" },
        @{ T = "[]"; Want = "explorer"; Why = "an array" },
        @{ T = "[{`"schema`":1,`"mode`":`"companion`",`"minShellBytes`":4096}]"; Want = "explorer"; Why = "a policy wrapped in an array" },
        @{ T = "{}"; Want = "explorer"; Why = "an empty object" },
        @{ T = "123"; Want = "explorer"; Why = "a number" },
        @{ T = "`"companion`""; Want = "explorer"; Why = "a bare string" },
        @{ T = "{`"mode`":`"companion`",`"minShellBytes`":4096}"; Want = "explorer"; Why = "no schema" },
        @{ T = "{`"schema`":`"1`",`"mode`":`"companion`",`"minShellBytes`":4096}"; Want = "explorer"; Why = "schema as text" },
        @{ T = "{`"schema`":0,`"mode`":`"companion`",`"minShellBytes`":4096}"; Want = "explorer"; Why = "schema 0" },
        @{ T = "{`"schema`":1.5,`"mode`":`"companion`",`"minShellBytes`":4096}"; Want = "explorer"; Why = "schema not an integer" },
        @{ T = "{`"schema`":true,`"mode`":`"companion`",`"minShellBytes`":4096}"; Want = "explorer"; Why = "schema true" },
        @{ T = "{`"schema`":1,`"minShellBytes`":4096}"; Want = "explorer"; Why = "no mode" },
        @{ T = "{`"schema`":1,`"mode`":null,`"minShellBytes`":4096}"; Want = "explorer"; Why = "mode null" },
        @{ T = "{`"schema`":1,`"mode`":`"Companion`",`"minShellBytes`":4096}"; Want = "explorer"; Why = "mode in another case" },
        @{ T = "{`"schema`":1,`"mode`":`" companion`",`"minShellBytes`":4096}"; Want = "explorer"; Why = "mode with a space" },
        @{ T = "{`"schema`":1,`"mode`":[`"companion`"],`"minShellBytes`":4096}"; Want = "explorer"; Why = "mode as an array" },
        @{ T = "{`"schema`":1,`"mode`":`"kiosk`",`"minShellBytes`":4096}"; Want = "explorer"; Why = "an unknown mode" },
        @{ T = "{`"schema`":1,`"mode`":`"shell`",`"minShellBytes`":4096}"; Want = "explorer"; Why = "shell mode (designed, not implemented)" },
        @{ T = "{`"schema`":1,`"mode`":`"companion`"}"; Want = "companion"; Why = "minShellBytes omitted takes the 4096 default" },
        @{ T = "{`"schema`":1,`"mode`":`"companion`",`"minShellBytes`":10}"; Want = "explorer"; Why = "minShellBytes under 1024" },
        @{ T = "{`"schema`":1,`"mode`":`"companion`",`"minShellBytes`":2000000}"; Want = "explorer"; Why = "minShellBytes over 1 MB" },
        @{ T = "{`"schema`":1,`"mode`":`"companion`",`"minShellBytes`":`"4096`"}"; Want = "explorer"; Why = "minShellBytes as text" },
        @{ T = "{`"schema`":1,`"mode`":`"companion`",`"minShellBytes`":4096"; Want = "explorer"; Why = "truncated JSON" },
        @{ T = "{`"schema`":1,`"mode`":`"explorer`",`"minShellBytes`":4096}"; Want = "explorer"; Why = "explorer (the dormant release)" },
        @{ T = "{`"schema`":1,`"mode`":`"companion`",`"minShellBytes`":4096}"; Want = "companion"; Why = "companion" },
        @{ T = "{`"schema`":2,`"mode`":`"companion`",`"minShellBytes`":4096,`"newField`":{`"x`":1}}"; Want = "companion"; Why = "a newer schema with the same fields (forward compatible)" }
    )
    foreach ($c in $cases) {
        $d = Get-KioskPolicyDecision -PolicyRead (Read-Policy $c.T) -KillSwitchPresent $false
        Assert-True ($d.Mode -ceq $c.Want) ("{0}: {1} (reason: {2})" -f $c.Why, $d.Mode, $d.Reason)
    }
    $p0 = Join-Path $Sandbox "probe-policy.json"
    Set-TestBytes $p0 ([byte[]](0xEF, 0xBB, 0xBF))
    Assert-True ((Get-KioskPolicyDecision -PolicyRead (Read-KioskJsonFile -Path $p0) -KillSwitchPresent $false).Mode -eq "explorer") "BOM only: explorer"
    Set-TestBytes $p0 ([byte[]](0x7B, 0x00, 0x7D))
    Assert-True ((Get-KioskPolicyDecision -PolicyRead (Read-KioskJsonFile -Path $p0) -KillSwitchPresent $false).Mode -eq "explorer") "NUL bytes: explorer"
    $bomCompanion = [byte[]](@(0xEF, 0xBB, 0xBF) + [Text.Encoding]::ASCII.GetBytes("{`"schema`":1,`"mode`":`"companion`",`"minShellBytes`":4096}"))
    Set-TestBytes $p0 $bomCompanion
    Assert-True ((Get-KioskPolicyDecision -PolicyRead (Read-KioskJsonFile -Path $p0) -KillSwitchPresent $false).Mode -eq "companion") "a BOM before a valid policy is read (Notepad saves one)"
    Set-TestFile $p0 ("{`"schema`":1,`"mode`":`"companion`",`"minShellBytes`":4096,`"pad`":`"" + ("x" * 5000) + "`"}")
    Assert-True ((Get-KioskPolicyDecision -PolicyRead (Read-KioskJsonFile -Path $p0 -MaxBytes 4096) -KillSwitchPresent $false).Mode -eq "explorer") "a policy larger than 4096 bytes: explorer"
    $dk = Get-KioskPolicyDecision -PolicyRead (Read-Policy "{`"schema`":1,`"mode`":`"companion`",`"minShellBytes`":4096}") -KillSwitchPresent $true
    Assert-True ($dk.Mode -eq "explorer" -and $dk.Reason -match "kill switch") "kill switch beats a valid companion policy"
    $ds = Get-KioskPolicyDecision -PolicyRead (Read-Policy "{`"schema`":1,`"mode`":`"shell`",`"minShellBytes`":4096}") -KillSwitchPresent $false -SupportedModes @("explorer", "companion", "shell")
    Assert-True ($ds.Mode -eq "shell") "the mode list is the gate: a release that implements shell can name it (proves the refusal above is the list, not the parser)"
    $dm = Get-KioskPolicyDecision -PolicyRead (Read-Policy "{`"schema`":1,`"mode`":`"companion`",`"minShellBytes`":8192}") -KillSwitchPresent $false
    Assert-True ($dm.MinShellBytes -eq 8192) "minShellBytes is carried to the verifier"

    # ============================================================ K2 / K3
    Section "K2 intent: only an exact, zoned, future 'wanted' is wanted"
    $ip = Join-Path $Sandbox "probe-intent.json"
    function Read-Intent([string]$text) { Set-TestFile $ip $text; return (Read-KioskJsonFile -Path $ip -MaxBytes 8192) }
    $icases = @(
        @{ T = "{}"; W = $false; Why = "empty object" },
        @{ T = "null"; W = $false; Why = "null" },
        @{ T = "[]"; W = $false; Why = "array" },
        @{ T = "{`"launcher`":`"wanted`",`"untilUtc`":`"2026-10-08T13:00:00Z`"}"; W = $false; Why = "no schema" },
        @{ T = "{`"schema`":1,`"launcher`":`"Wanted`",`"untilUtc`":`"2026-10-08T13:00:00Z`"}"; W = $false; Why = "Wanted in another case" },
        @{ T = "{`"schema`":1,`"launcher`":true,`"untilUtc`":`"2026-10-08T13:00:00Z`"}"; W = $false; Why = "launcher true (a boolean)" },
        @{ T = "{`"schema`":1,`"launcher`":`"wanted`"}"; W = $false; Why = "no untilUtc" },
        @{ T = "{`"schema`":1,`"launcher`":`"wanted`",`"untilUtc`":null}"; W = $false; Why = "untilUtc null" },
        @{ T = "{`"schema`":1,`"launcher`":`"wanted`",`"untilUtc`":`"2026-10-08T13:00:00`"}"; W = $false; Why = "untilUtc without a zone" },
        @{ T = "{`"schema`":1,`"launcher`":`"wanted`",`"untilUtc`":`"tomorrow`"}"; W = $false; Why = "untilUtc garbage" },
        @{ T = "{`"schema`":1,`"launcher`":`"wanted`",`"untilUtc`":1791900000}"; W = $false; Why = "untilUtc a number" },
        @{ T = "{`"schema`":1,`"launcher`":`"wanted`",`"untilUtc`":`"2026-10-08T11:59:59Z`"}"; W = $false; Why = "expired a second ago" },
        @{ T = "{`"schema`":1,`"launcher`":`"wanted`",`"untilUtc`":`"2026-10-08T12:00:00Z`"}"; W = $false; Why = "expires exactly now" },
        @{ T = "{`"schema`":1,`"launcher`":`"not_wanted`",`"untilUtc`":`"2026-10-08T13:00:00Z`"}"; W = $false; Why = "not_wanted with a future time" },
        @{ T = "{`"schema`":1,`"launcher`":`"wanted`",`"untilUtc`":`"2026-10-08T12:00:01Z`"}"; W = $true; Why = "wanted, one second left" },
        @{ T = "{`"schema`":1,`"launcher`":`"wanted`",`"untilUtc`":`"2026-10-08T09:00:30-04:00`"}"; W = $true; Why = "wanted with an offset (13:00:30Z)" },
        @{ T = "{`"schema`":3,`"launcher`":`"wanted`",`"untilUtc`":`"2026-10-08T13:00:00Z`",`"extra`":[1,2]}"; W = $true; Why = "a newer schema with the same fields" }
    )
    foreach ($c in $icases) {
        $w = Get-KioskLauncherWanted -IntentRead (Read-Intent $c.T) -NowUtc $UtcNow
        Assert-True ([bool]$w.Wanted -eq $c.W) ("{0}: wanted={1} ({2})" -f $c.Why, $w.Wanted, $w.Reason)
    }
    Remove-Item -LiteralPath $ip -Force
    Assert-True (-not (Get-KioskLauncherWanted -IntentRead (Read-KioskJsonFile -Path $ip) -NowUtc $UtcNow).Wanted) "absent intent: not wanted"
    $dtObj = [pscustomobject]@{ schema = 1; launcher = "wanted"; untilUtc = [DateTime]::SpecifyKind([DateTime]::Parse("2026-10-08T13:00:00"), [DateTimeKind]::Utc) }
    Assert-True ((Get-KioskLauncherWanted -IntentRead @{ Ok = $true; Obj = $dtObj; Why = "" } -NowUtc $UtcNow).Wanted) "a DateTime value (what PowerShell 7's ConvertFrom-Json produces) is read"
    # "closed" (no session may play): only an exact "closed" with a readable writtenUtc; anything else is hands off.
    $ccases = @(
        @{ T = "{`"schema`":1,`"launcher`":`"closed`",`"writtenUtc`":`"2026-10-08T11:59:00Z`"}"; C = $true; Why = "closed with a writtenUtc" },
        @{ T = "{`"schema`":1,`"launcher`":`"closed`"}"; C = $false; Why = "closed without a writtenUtc: hands off" },
        @{ T = "{`"schema`":1,`"launcher`":`"closed`",`"writtenUtc`":`"2026-10-08T11:59:00`"}"; C = $false; Why = "closed whose writtenUtc has no zone: hands off" },
        @{ T = "{`"schema`":1,`"launcher`":`"Closed`",`"writtenUtc`":`"2026-10-08T11:59:00Z`"}"; C = $false; Why = "Closed in another case: hands off" },
        @{ T = "{`"launcher`":`"closed`",`"writtenUtc`":`"2026-10-08T11:59:00Z`"}"; C = $false; Why = "closed without a schema: hands off" },
        @{ T = "{`"schema`":1,`"launcher`":`"unmanaged`",`"writtenUtc`":`"2026-10-08T11:59:00Z`"}"; C = $false; Why = "unmanaged" },
        @{ T = "{`"schema`":1,`"launcher`":`"not_wanted`",`"writtenUtc`":`"2026-10-08T11:59:00Z`"}"; C = $false; Why = "not_wanted (an older value): hands off" },
        @{ T = "{`"schema`":1,`"launcher`":[`"closed`"],`"writtenUtc`":`"2026-10-08T11:59:00Z`"}"; C = $false; Why = "closed inside an array: hands off" }
    )
    foreach ($c in $ccases) {
        $w = Get-KioskLauncherWanted -IntentRead (Read-Intent $c.T) -NowUtc $UtcNow
        Assert-True ([bool]$w.Closed -eq $c.C -and -not $w.Wanted) ("{0}: closed={1} ({2})" -f $c.Why, $w.Closed, $w.Reason)
    }
    $wc = Get-KioskLauncherWanted -IntentRead (Read-Intent "{`"schema`":1,`"launcher`":`"closed`",`"writtenUtc`":`"2026-10-08T11:59:00Z`"}") -NowUtc $UtcNow
    Assert-True ($wc.ClosedSinceUtc -eq (ConvertTo-KioskUtc "2026-10-08T11:59:00Z")) "closed carries when it was written (the shell's grace runs from it)"
    Remove-Item -LiteralPath $ip -Force

    Section "K3 ConvertTo-KioskUtc"
    Assert-True ((ConvertTo-KioskUtc "2026-10-08T13:00:00Z") -eq [DateTime]::SpecifyKind([DateTime]::Parse("2026-10-08T13:00:00"), [DateTimeKind]::Utc)) "Z text"
    Assert-True ((ConvertTo-KioskUtc "2026-10-08T09:00:00-04:00").Hour -eq 13) "offset text converts to UTC"
    Assert-True ($null -eq (ConvertTo-KioskUtc "2026-10-08T13:00:00")) "text without a zone is refused"
    Assert-True ($null -eq (ConvertTo-KioskUtc "10/08/2026 13:00:00Z")) "a culture-shaped date is refused"
    Assert-True ($null -eq (ConvertTo-KioskUtc 5)) "a number is refused"
    $loc = [DateTime]::SpecifyKind([DateTime]::Parse("2026-10-08T09:00:00"), [DateTimeKind]::Local)
    Assert-True ((ConvertTo-KioskUtc $loc) -eq $loc.ToUniversalTime()) "a Local DateTime is converted, not relabeled"
    $uns = [DateTime]::SpecifyKind([DateTime]::Parse("2026-10-08T13:00:00"), [DateTimeKind]::Unspecified)
    Assert-True ($null -eq (ConvertTo-KioskUtc $uns)) "an Unspecified DateTime (PowerShell 7's reading of zone-less text) is refused"

    # ============================================================ K4
    Section "K4 what each command does to the intent"
    $none = @{ Ok = $false; Obj = $null; Why = "absent" }
    $payStart = [pscustomobject]@{ mode = "Start"; baySessionId = "s-1"; startUtc = "2026-10-08T12:00:00Z"; endUtc = "2026-10-08T13:00:00Z"; playEndUtc = "2026-10-08T12:55:00Z" }
    $r = Get-KioskIntentForCommand -CommandType $CMD_STARTSESSION -Mode "Start" -Payload $payStart -CurrentIntentRead $none -SameSession $true -EmergencyStopEngaged $false -NowUtc $UtcNow
    Assert-True ($r.Launcher -eq "wanted" -and $r.UntilUtc -eq (ConvertTo-KioskUtc "2026-10-08T12:57:00Z") -and $r.SessionId -eq "s-1") "Start: wanted until playEndUtc + 2 min (got $($r.Launcher) until $($r.UntilUtc.ToString('o')))"
    $payNoPlay = [pscustomobject]@{ mode = "Start"; baySessionId = "s-1"; endUtc = "2026-10-08T13:00:00Z" }
    $r = Get-KioskIntentForCommand -CommandType $CMD_STARTSESSION -Mode "Start" -Payload $payNoPlay -CurrentIntentRead $none -SameSession $true -EmergencyStopEngaged $false -NowUtc $UtcNow
    Assert-True ($r.UntilUtc -eq (ConvertTo-KioskUtc "2026-10-08T13:02:00Z")) "Start without playEndUtc falls back to endUtc"
    $payNoEnd = [pscustomobject]@{ mode = "Start"; baySessionId = "s-1" }
    $r = Get-KioskIntentForCommand -CommandType $CMD_STARTSESSION -Mode "Start" -Payload $payNoEnd -CurrentIntentRead $none -SameSession $true -EmergencyStopEngaged $false -NowUtc $UtcNow
    Assert-True ($r.Launcher -eq "unmanaged") "Start without a readable end: unmanaged (the agent starts the launcher itself; the shell neither restarts nor closes it)"
    $payNoZone = [pscustomobject]@{ mode = "Start"; baySessionId = "s-1"; playEndUtc = "2026-10-08T12:55:00" }
    Assert-True ((Get-KioskIntentForCommand -CommandType $CMD_STARTSESSION -Mode "Start" -Payload $payNoZone -CurrentIntentRead $none -SameSession $true -EmergencyStopEngaged $false -NowUtc $UtcNow).Launcher -eq "unmanaged") "Start whose end has no zone: unmanaged"
    Assert-True ((Get-KioskIntentForCommand -CommandType $CMD_STARTSESSION -Mode "Start" -Payload $payStart -CurrentIntentRead $none -SameSession $true -EmergencyStopEngaged $true -NowUtc $UtcNow).Launcher -eq "unmanaged") "Start with the emergency stop engaged: unmanaged"
    $curWanted = @{ Ok = $true; Why = ""; Obj = [pscustomobject]@{ schema = 1; launcher = "wanted"; untilUtc = "2026-10-08T12:57:00Z"; baySessionId = "s-1" } }
    $curClosed = @{ Ok = $true; Why = ""; Obj = [pscustomobject]@{ schema = 1; launcher = "closed"; writtenUtc = "2026-10-08T11:00:00Z"; baySessionId = "s-0" } }
    Assert-True ($null -eq (Get-KioskIntentForCommand -CommandType $CMD_STARTSESSION -Mode "Prep" -Payload ([pscustomobject]@{ mode = "Prep"; baySessionId = "s-2" }) -CurrentIntentRead $curWanted -SameSession $true -EmergencyStopEngaged $false -NowUtc $UtcNow)) "Prep of the NEXT booking while this one plays: no change (it must not close or stop restarting the current game)"
    Assert-True ($null -eq (Get-KioskIntentForCommand -CommandType $CMD_STARTSESSION -Mode "Prep" -Payload $payStart -CurrentIntentRead $curClosed -SameSession $true -EmergencyStopEngaged $false -NowUtc $UtcNow)) "Prep after an End: no change (stays closed)"
    Assert-True ((Get-KioskIntentForCommand -CommandType $CMD_STARTSESSION -Mode "start-disabled" -Payload $payStart -CurrentIntentRead $none -SameSession $true -EmergencyStopEngaged $false -NowUtc $UtcNow).Launcher -eq "unmanaged") "Start with launcher.startOnStart=false: unmanaged"
    $rEnd = Get-KioskIntentForCommand -CommandType $CMD_ENDSESSION -Mode "End" -Payload $payStart -CurrentIntentRead $curWanted -SameSession $true -EmergencyStopEngaged $false -NowUtc $UtcNow
    Assert-True ($rEnd.Launcher -eq "closed") "EndSession of the current session: closed (no free play after the end)"
    Assert-True ($null -eq (Get-KioskIntentForCommand -CommandType $CMD_ENDSESSION -Mode "End" -Payload $payStart -CurrentIntentRead $curWanted -SameSession $false -EmergencyStopEngaged $false -NowUtc $UtcNow)) "a late EndSession for an older session leaves the intent alone"
    # Attack RF1: the platform's Reset for a canceled booking (immediate, no session id) never changes the intent.
    $resetPayload = [pscustomobject]@{ mode = "Full"; reason = "BookingCanceled" }
    $curUnmanagedPlaying = @{ Ok = $true; Why = ""; Obj = [pscustomobject]@{ schema = 1; launcher = "unmanaged"; baySessionId = "s-1"; reason = "emergency stop engaged" } }
    $curExpired = @{ Ok = $true; Why = ""; Obj = [pscustomobject]@{ schema = 1; launcher = "wanted"; untilUtc = "2026-10-08T11:00:00Z"; baySessionId = "s-1" } }
    foreach ($rc in @(@{ R = $none; W = "nothing on disk" }, @{ R = $curWanted; W = "a wanted session" }, @{ R = $curUnmanagedPlaying; W = "a paid session left unmanaged by an emergency stop or Maintenance" }, @{ R = $curExpired; W = "a paid extension whose display command was lost (intent expired)" }, @{ R = $curClosed; W = "closed" })) {
        Assert-True ($null -eq (Get-KioskIntentForCommand -CommandType $CMD_RESET -Mode "" -Payload $resetPayload -CurrentIntentRead $rc.R -SameSession $true -EmergencyStopEngaged $false -NowUtc $UtcNow)) ("Reset over {0}: no change, never closed (RF1)" -f $rc.W)
    }
    Assert-True ($null -eq (Get-KioskIntentForCommand -CommandType $CMD_ENDSESSION -Mode "End" -Payload ([pscustomobject]@{ mode = "End" }) -CurrentIntentRead $curWanted -SameSession $true -EmergencyStopEngaged $false -NowUtc $UtcNow)) "an EndSession that names no session: no closed (it cannot prove it ends the running one)"
    Assert-True ($null -eq (Get-KioskIntentForCommand -CommandType $CMD_ENDSESSION -Mode "End" -Payload ([pscustomobject]@{ mode = "End" }) -CurrentIntentRead $none -SameSession $true -EmergencyStopEngaged $false -NowUtc $UtcNow)) "...also when no intent names a session at all (attack E6)"
    $curWantedB = @{ Ok = $true; Why = ""; Obj = [pscustomobject]@{ schema = 1; launcher = "wanted"; untilUtc = "2026-10-08T13:57:00Z"; baySessionId = "s-B" } }
    Assert-True ($null -eq (Get-KioskIntentForCommand -CommandType $CMD_ENDSESSION -Mode "End" -Payload $payStart -CurrentIntentRead $curWantedB -SameSession $true -EmergencyStopEngaged $false -NowUtc $UtcNow)) "an EndSession of s-1 while the intent names s-B: no closed"
    $rEnd2 = Get-KioskIntentForCommand -CommandType $CMD_ENDSESSION -Mode "End" -Payload $payStart -CurrentIntentRead $curUnmanagedPlaying -SameSession $true -EmergencyStopEngaged $false -NowUtc $UtcNow
    Assert-True ($null -ne $rEnd2 -and $rEnd2.Launcher -eq "closed") "the EndSession of s-1 after an emergency stop (intent unmanaged, s-1): closed"
    Assert-True ((Get-KioskIntentForCommand -CommandType $CMD_EMERGENCY_STOP -Mode "" -Payload ([pscustomobject]@{ action = "engage" }) -CurrentIntentRead $curWanted -SameSession $true -EmergencyStopEngaged $false -NowUtc $UtcNow).Launcher -eq "unmanaged") "emergency stop during a session: unmanaged (no restarts; closes nothing)"
    Assert-True ($null -eq (Get-KioskIntentForCommand -CommandType $CMD_EMERGENCY_STOP -Mode "" -Payload ([pscustomobject]@{ action = "engage" }) -CurrentIntentRead $curClosed -SameSession $true -EmergencyStopEngaged $false -NowUtc $UtcNow)) "emergency stop with no session: no change (stays closed)"
    Assert-True ($null -eq (Get-KioskIntentForCommand -CommandType $CMD_EMERGENCY_STOP -Mode "" -Payload ([pscustomobject]@{ action = "clear" }) -CurrentIntentRead $curWanted -SameSession $true -EmergencyStopEngaged $false -NowUtc $UtcNow)) "emergency stop clear: no change (clearing never makes the launcher wanted)"
    Assert-True ($null -eq (Get-KioskIntentForCommand -CommandType $CMD_HEALTHCHECK -Mode "" -Payload ([pscustomobject]@{}) -CurrentIntentRead $none -SameSession $true -EmergencyStopEngaged $false -NowUtc $UtcNow)) "HealthCheck: no change"
    $payExt = [pscustomobject]@{ mode = "Warn5"; baySessionId = "s-1"; playEndUtc = "2026-10-08T13:25:00Z" }
    $r = Get-KioskIntentForCommand -CommandType $CMD_UPDATESESSIONDISPLAY -Mode "Warn5" -Payload $payExt -CurrentIntentRead $curWanted -SameSession $true -EmergencyStopEngaged $false -NowUtc $UtcNow
    Assert-True ($null -ne $r -and $r.Launcher -eq "wanted" -and $r.UntilUtc -eq (ConvertTo-KioskUtc "2026-10-08T13:27:00Z")) "UpdateSessionDisplay with a later end for the SAME session extends the intent"
    $payOther = [pscustomobject]@{ mode = "Warn5"; baySessionId = "s-2"; playEndUtc = "2026-10-08T13:25:00Z" }
    Assert-True ($null -eq (Get-KioskIntentForCommand -CommandType $CMD_UPDATESESSIONDISPLAY -Mode "Warn5" -Payload $payOther -CurrentIntentRead $curWanted -SameSession $true -EmergencyStopEngaged $false -NowUtc $UtcNow)) "...not for another session"
    $paySame = [pscustomobject]@{ mode = "Warn5"; baySessionId = "s-1"; playEndUtc = "2026-10-08T12:50:00Z" }
    Assert-True ($null -eq (Get-KioskIntentForCommand -CommandType $CMD_UPDATESESSIONDISPLAY -Mode "Warn5" -Payload $paySame -CurrentIntentRead $curWanted -SameSession $true -EmergencyStopEngaged $false -NowUtc $UtcNow)) "...not to an earlier end"
    $curNot = @{ Ok = $true; Why = ""; Obj = [pscustomobject]@{ schema = 1; launcher = "not_wanted"; untilUtc = $null; baySessionId = "s-1" } }
    Assert-True ($null -eq (Get-KioskIntentForCommand -CommandType $CMD_UPDATESESSIONDISPLAY -Mode "Warn5" -Payload $payExt -CurrentIntentRead $curNot -SameSession $true -EmergencyStopEngaged $false -NowUtc $UtcNow)) "...and never creates a wanted intent"

    # ============================================================ K5
    Section "K5 the intent writer reads back through the shell's own reader"
    $ok = Write-KioskIntent -Launcher "wanted" -UntilUtc (ConvertTo-KioskUtc "2026-10-08T12:57:00Z") -SessionId "s-1" -Reason "test"
    Assert-True $ok "Write-KioskIntent returned true"
    $w = Get-KioskLauncherWanted -IntentRead (Read-KioskJsonFile -Path $KioskIntentPath) -NowUtc $UtcNow
    Assert-True ($w.Wanted -and $w.UntilUtc -eq (ConvertTo-KioskUtc "2026-10-08T12:57:00Z") -and $w.SessionId -eq "s-1") "the shell's reader sees wanted until 12:57:00Z for s-1"
    Assert-True (-not (Test-Path -LiteralPath "$KioskIntentPath.tmp")) "no temporary file left behind"
    $raw = [IO.File]::ReadAllText($KioskIntentPath)
    Assert-True ($raw -match '"untilUtc":\s*"2026-10-08T12:57:00Z"') "untilUtc is stored as zoned text"
    $ok = Write-KioskIntent -Launcher "unmanaged" -UntilUtc $null -SessionId "s-1" -Reason "test"
    $wu = Get-KioskLauncherWanted -IntentRead (Read-KioskJsonFile -Path $KioskIntentPath) -NowUtc $UtcNow
    Assert-True ($ok -and -not $wu.Wanted -and -not $wu.Closed) "unmanaged round-trips (neither wanted nor closed)"
    $ok = Write-KioskIntent -Launcher "closed" -UntilUtc $null -SessionId "s-1" -Reason "test"
    $wcl = Get-KioskLauncherWanted -IntentRead (Read-KioskJsonFile -Path $KioskIntentPath) -NowUtc ((Get-Date).ToUniversalTime())
    Assert-True ($ok -and $wcl.Closed -and $null -ne $wcl.ClosedSinceUtc -and [Math]::Abs(((Get-Date).ToUniversalTime() - $wcl.ClosedSinceUtc).TotalSeconds) -lt 60) "closed round-trips with its writtenUtc"

    # ============================================================ K6
    Section "K6 the intent at agent start: a readable one is kept; an absent one is derived, never as closed"
    $now6 = (Get-Date).ToUniversalTime()
    $sj = Join-Path $Sandbox "session.json"
    function Read-IntentNow6 { return (Get-KioskLauncherWanted -IntentRead (Read-KioskJsonFile -Path $KioskIntentPath) -NowUtc $now6) }
    function Remove-Intent { if (Test-Path -LiteralPath $KioskIntentPath) { Remove-Item -LiteralPath $KioskIntentPath -Force } }
    Remove-Intent
    Set-TestFile $sj (ConvertTo-Json -InputObject ([ordered]@{ status = "ACTIVE"; baySessionId = "s-9"; sessionEndUtc = $now6.AddMinutes(30).ToString("yyyy-MM-ddTHH:mm:ssZ") }))
    Initialize-KioskIntent -NowUtc $now6
    $w = Read-IntentNow6
    Assert-True ($w.Wanted -and $w.SessionId -eq "s-9") "no intent, ACTIVE with a future end: wanted (an agent restart mid-session keeps the member playing)"
    Remove-Intent
    Set-TestFile $sj (ConvertTo-Json -InputObject ([ordered]@{ status = "ENDED"; baySessionId = "s-9"; sessionEndUtc = $now6.AddMinutes(-30).ToString("yyyy-MM-ddTHH:mm:ssZ") }))
    Initialize-KioskIntent -NowUtc $now6
    $w = Read-IntentNow6
    Assert-True (-not $w.Wanted -and -not $w.Closed) "no intent, ENDED: unmanaged, never closed (session.json can be rewritten by a late EndSession of an older session)"
    Remove-Intent
    Set-TestFile $sj (ConvertTo-Json -InputObject ([ordered]@{ status = "ENDED"; baySessionId = "s-9"; sessionEndUtc = $now6.AddMinutes(30).ToString("yyyy-MM-ddTHH:mm:ssZ") }))
    Initialize-KioskIntent -NowUtc $now6
    $w = Read-IntentNow6
    Assert-True (-not $w.Wanted -and -not $w.Closed) "no intent, ENDED with an end still ahead: not wanted (only ACTIVE or ENDING is a running session)"
    Remove-Intent
    Set-TestFile $sj (ConvertTo-Json -InputObject ([ordered]@{ status = "ACTIVE"; baySessionId = "s-9"; sessionEndUtc = $now6.AddMinutes(-3).ToString("yyyy-MM-ddTHH:mm:ssZ") }))
    Initialize-KioskIntent -NowUtc $now6
    Assert-True (-not (Read-IntentNow6).Wanted) "no intent, ACTIVE whose end passed more than the grace ago: not wanted"
    Remove-Intent
    Remove-Item -LiteralPath $sj -Force
    Initialize-KioskIntent -NowUtc $now6
    $w = Read-IntentNow6
    Assert-True ((Test-Path -LiteralPath $KioskIntentPath) -and -not $w.Wanted -and -not $w.Closed) "no intent and no session.json: unmanaged, written"
    # A readable wanted intent is adopted at start only when session.json backs it (attack residual R1).
    Set-TestFile $sj (ConvertTo-Json -InputObject ([ordered]@{ status = "ACTIVE"; baySessionId = "s-9"; sessionEndUtc = $now6.AddMinutes(38).ToString("yyyy-MM-ddTHH:mm:ssZ") }))
    [void](Write-KioskIntent -Launcher "wanted" -UntilUtc ($now6.AddMinutes(40)) -SessionId "s-9" -Reason "test")
    Initialize-KioskIntent -NowUtc $now6
    $w = Read-IntentNow6
    Assert-True ($w.Wanted -and $w.SessionId -eq "s-9") "a wanted intent backed by session.json (same session, until within its end + grace) is kept"
    Set-TestFile $KioskIntentPath ("{`"schema`":1,`"launcher`":`"wanted`",`"untilUtc`":`"2099-01-01T00:00:00Z`",`"baySessionId`":`"s-9`"}")
    Initialize-KioskIntent -NowUtc $now6
    $w = Read-IntentNow6
    Assert-True (-not $w.Wanted -and -not $w.Closed) "a 'wanted until 2099' found at start (written while the agent was down): unmanaged (R1)"
    Set-TestFile $sj (ConvertTo-Json -InputObject ([ordered]@{ status = "ENDED"; baySessionId = "s-old"; sessionEndUtc = $now6.AddMinutes(-90).ToString("yyyy-MM-ddTHH:mm:ssZ") }))
    [void](Write-KioskIntent -Launcher "wanted" -UntilUtc ($now6.AddMinutes(40)) -SessionId "s-9" -Reason "test")
    Initialize-KioskIntent -NowUtc $now6
    $w = Read-IntentNow6
    Assert-True (-not $w.Wanted -and -not $w.Closed) "a wanted intent session.json does not show running: unmanaged, never closed"
    [void](Write-KioskIntent -Launcher "closed" -UntilUtc $null -SessionId "s-9" -Reason "test")
    Set-TestFile $sj (ConvertTo-Json -InputObject ([ordered]@{ status = "ACTIVE"; baySessionId = "s-9"; sessionEndUtc = $now6.AddMinutes(30).ToString("yyyy-MM-ddTHH:mm:ssZ") }))
    Initialize-KioskIntent -NowUtc $now6
    Assert-True ((Read-IntentNow6).Closed) "a readable closed intent is kept"
    Set-TestFile $KioskIntentPath "{ garbage"
    Initialize-KioskIntent -NowUtc $now6
    Assert-True ((Read-IntentNow6).Wanted) "an unreadable intent is derived again (ACTIVE: wanted)"
    [void](Write-KioskIntent -Launcher "wanted" -UntilUtc ($now6.AddMinutes(40)) -SessionId "s-9" -Reason "test")
    $Global:EmergencyStopEngaged = $true
    Initialize-KioskIntent -NowUtc $now6
    $Global:EmergencyStopEngaged = $false
    $w = Read-IntentNow6
    Assert-True (-not $w.Wanted -and -not $w.Closed) "an engaged emergency stop at start turns wanted into unmanaged"
    [void](Write-KioskIntent -Launcher "closed" -UntilUtc $null -SessionId "s-9" -Reason "test")
    $Global:EmergencyStopEngaged = $true
    Initialize-KioskIntent -NowUtc $now6
    $Global:EmergencyStopEngaged = $false
    Assert-True ((Read-IntentNow6).Closed) "...and leaves closed closed"
    Remove-Item -LiteralPath $sj -Force

    # ============================================================ K7
    Section "K7 the activation verifier refuses every shape but a verified file, in order"
    $relKiosk = Join-Path $Sandbox "releases\1.4.0\kiosk"
    New-Item -ItemType Directory -Force -Path $relKiosk | Out-Null
    $goodShell = Join-Path $relKiosk "ABG.KioskShell.ps1"
    [IO.File]::Copy($ShellScript, $goodShell, $true)
    $script:SigFake = @{ Status = "Valid"; Timestamped = $true; Thumbprint = "AAAA" }
    function Get-KioskAuthenticode([string]$Path) { return $script:SigFake }
    function Test-V([string]$p, [int]$min = 4096, [string]$tp = "AAAA") { return (Test-KioskShellFile -Path $p -MinBytes $min -ExpectedSignerThumbprint $tp -ExpectedFolder $relKiosk) }
    $v = Test-V $goodShell
    Assert-True ($v.Ok -and $v.Why -eq "verified" -and $v.SignerMatches) "a parsed, big enough, Valid, timestamped file signed by the agent's certificate: verified"
    Assert-True ($v.Sha256 -match '^[0-9a-f]{64}$') "...and its sha256 is reported"
    Assert-True (-not (Test-V (Join-Path $relKiosk "missing.ps1")).Ok) "missing file: refused"
    $outside = Join-Path $Sandbox "current\kiosk\ABG.KioskShell.ps1"
    [IO.File]::Copy($ShellScript, $outside, $true)
    $vo = Test-V $outside
    Assert-True (-not $vo.Ok -and $vo.Why -match "not inside") "a good file OUTSIDE this version's release folder (current\kiosk): refused (version-pinned path)"
    $vt = Test-V ($relKiosk + "\..\..\1.4.0\kiosk\ABG.KioskShell.ps1")
    Assert-True ($vt.Ok) "a path with .. that resolves inside the folder is judged on its full path"
    $vt2 = Test-V ($relKiosk + "\..\..\..\current\kiosk\ABG.KioskShell.ps1")
    Assert-True (-not $vt2.Ok) "a path with .. that resolves outside the folder: refused"
    $small = Join-Path $relKiosk "small.ps1"; Set-TestFile $small "Write-Host 1"
    $vs = Test-V $small
    Assert-True (-not $vs.Ok -and $vs.Why -match "under the policy minimum") "a tiny file (a truncated download): refused by size"
    $zero = Join-Path $relKiosk "zero.ps1"; Set-TestFile $zero ""
    Assert-True (-not (Test-V $zero).Ok) "0 bytes: refused"
    $broken = Join-Path $relKiosk "broken.ps1"; Set-TestFile $broken ("function x {`r`n" + ("# pad`r`n" * 1200))
    $vb = Test-V $broken
    Assert-True (-not $vb.Ok -and $vb.Why -match "parse error") "a big file that does not parse: refused"
    $vbs = Test-V $broken 999999
    Assert-True ($vbs.Why -match "under the policy minimum") "order: the size check runs before the parse check"
    foreach ($st in @("NotSigned", "HashMismatch", "UnknownError", "NotTrusted")) {
        $script:SigFake = @{ Status = $st; Timestamped = $true; Thumbprint = "AAAA" }
        $vx = Test-V $goodShell
        Assert-True (-not $vx.Ok -and $vx.Why -match $st) "signature $st`: refused"
    }
    $script:SigFake = @{ Status = "Valid"; Timestamped = $false; Thumbprint = "AAAA" }
    Assert-True (-not (Test-V $goodShell).Ok) "Valid but untimestamped: refused"
    $script:SigFake = @{ Status = "Valid"; Timestamped = $true; Thumbprint = "BBBB" }
    $vd = Test-V $goodShell
    Assert-True (-not $vd.Ok -and $vd.SignerMatches -eq $false) "Valid, timestamped, signed by ANOTHER certificate: refused"
    $script:SigFake = @{ Status = "Valid"; Timestamped = $true; Thumbprint = "" }
    Assert-True (-not (Test-V $goodShell 4096 "").Ok) "no known agent signer (an unsigned agent) and an unsigned-thumbprint file: refused, never matched on empty"
    $script:SigFake = @{ Status = "Valid"; Timestamped = $true; Thumbprint = "aaaa" }
    Assert-True ((Test-V $goodShell).Ok) "thumbprints compare without case"
    $script:SigFake = @{ Status = "Valid"; Timestamped = $true; Thumbprint = "AAAA" }

    # ============================================================ K8
    Section "K8 shell liveness and the command-line match"
    $myShellCl = ('"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -NonInteractive -WindowStyle Hidden -File "{0}" -Companion' -f $goodShell)
    Assert-True (Test-KioskShellCommandLine $myShellCl) "the command line the agent builds is recognized"
    $older = $myShellCl.Replace("\1.4.0\", "\1.3.9\")
    Assert-True (Test-KioskShellCommandLine $older) "an older version's shell of this install is recognized (it keeps running after an update)"
    Assert-True (-not (Test-KioskShellCommandLine '"powershell.exe" -File "D:\Other\releases\1.4.0\kiosk\ABG.KioskShell.ps1"')) "a shell file under another root is not this install's"
    Assert-True (-not (Test-KioskShellCommandLine ('"powershell.exe" -File "{0}"' -f (Join-Path $Sandbox "current\kiosk\ABG.KioskShell.ps1")))) "the current\ copy is not a release-folder shell"
    Assert-True (-not (Test-KioskShellCommandLine '"notepad.exe" C:\x.txt')) "an unrelated program is not"
    Assert-True (-not (Test-KioskShellCommandLine $null)) "an unreadable command line is not"
    $hbPath = Join-Path $Sandbox "probe-hb.json"
    function Read-Hb([hashtable]$h) { Set-TestFile $hbPath (ConvertTo-Json -InputObject $h -Depth 5); return (Read-KioskJsonFile -Path $hbPath -MaxBytes 65536) }
    $now8 = $UtcNow
    $clShell = { param($procId) $myShellCl }
    $clGone = { param($procId) $null }
    $clOther = { param($procId) '"C:\Windows\notepad.exe"' }
    $hbFresh = @{ schema = 1; pid = 4242; lastLoopUtc = $now8.AddSeconds(-10).ToString("yyyy-MM-ddTHH:mm:ssZ"); supervising = $true; degraded = $false; launcher = @{ running = $true; pid = 77 } }
    Assert-True ((Get-KioskShellLiveness -HeartbeatRead @{ Ok = $false; Why = "absent"; Obj = $null } -NowUtc $now8 -CommandLineOf $clShell).State -eq "absent") "no heartbeat: absent"
    $l = Get-KioskShellLiveness -HeartbeatRead (Read-Hb $hbFresh) -NowUtc $now8 -CommandLineOf $clShell
    Assert-True ($l.State -eq "alive" -and $l.Supervising -and $l.LauncherRunning) "fresh heartbeat of a shell process: alive"
    Assert-True ((Get-KioskShellLiveness -HeartbeatRead (Read-Hb $hbFresh) -NowUtc $now8 -CommandLineOf $clGone).State -eq "absent") "fresh heartbeat but the process is gone: absent"
    Assert-True ((Get-KioskShellLiveness -HeartbeatRead (Read-Hb $hbFresh) -NowUtc $now8 -CommandLineOf $clOther).State -eq "foreign") "the pid now belongs to another program: foreign (never stopped)"
    $hbStale = $hbFresh.Clone(); $hbStale.lastLoopUtc = $now8.AddSeconds(-90).ToString("yyyy-MM-ddTHH:mm:ssZ")
    Assert-True ((Get-KioskShellLiveness -HeartbeatRead (Read-Hb $hbStale) -NowUtc $now8 -CommandLineOf $clShell).State -eq "stale") "90 s old: stale (wait)"
    $hbHung = $hbFresh.Clone(); $hbHung.lastLoopUtc = $now8.AddSeconds(-200).ToString("yyyy-MM-ddTHH:mm:ssZ")
    Assert-True ((Get-KioskShellLiveness -HeartbeatRead (Read-Hb $hbHung) -NowUtc $now8 -CommandLineOf $clShell).State -eq "hung") "200 s old with the shell process still there: hung"
    Assert-True ((Get-KioskShellLiveness -HeartbeatRead (Read-Hb $hbHung) -NowUtc $now8 -CommandLineOf $clOther).State -eq "foreign") "200 s old but the pid is another program: foreign, not hung"
    $hbNoLoop = $hbFresh.Clone(); $hbNoLoop.lastLoopUtc = "soon"
    Assert-True ((Get-KioskShellLiveness -HeartbeatRead (Read-Hb $hbNoLoop) -NowUtc $now8 -CommandLineOf $clShell).State -eq "hung") "an unreadable lastLoopUtc on a live shell process: hung"
    $hbNoPid = $hbFresh.Clone(); $hbNoPid.pid = "4242"
    Assert-True ((Get-KioskShellLiveness -HeartbeatRead (Read-Hb $hbNoPid) -NowUtc $now8 -CommandLineOf $clShell).State -eq "absent") "a pid as text: absent"
    $hbDeg = $hbFresh.Clone(); $hbDeg.degraded = $true
    Assert-True ((Get-KioskShellLiveness -HeartbeatRead (Read-Hb $hbDeg) -NowUtc $now8 -CommandLineOf $clShell).Degraded) "degraded is read"

    # ============================================================ K9
    Section "K9 the reconciler (injected start and stop)"
    $script:Started = New-Object System.Collections.ArrayList
    $script:Stopped = New-Object System.Collections.ArrayList
    $startSb = { param($exe, $argLine) [void]$script:Started.Add(@{ Exe = $exe; Args = $argLine }); return 9001 }
    $stopSb = { param($procId) [void]$script:Stopped.Add($procId) }
    $Global:KioskSignerThumbprint = "AAAA"
    $script:SigFake = @{ Status = "Valid"; Timestamped = $true; Thumbprint = "AAAA" }
    function Reset-K9 { $script:Started.Clear(); $script:Stopped.Clear(); $Global:KioskStarts = [DateTime[]]@(); $Global:KioskVerifyCache = $null; $Global:KioskReport = $null; foreach ($f in @($KioskHeartbeatPath, $KioskReconcilePath, $KioskKillSwitchPath)) { if (Test-Path -LiteralPath $f) { Remove-Item -LiteralPath $f -Force } } }
    $ownSession = [System.Diagnostics.Process]::GetCurrentProcess().SessionId
    $explorerHere = @(Get-Process -Name explorer -ErrorAction SilentlyContinue | Where-Object { $_.SessionId -eq $ownSession }).Count -gt 0
    Assert-True $explorerHere "precondition: Explorer runs in this test's session (the companion needs the desktop)"
    $now9 = (Get-Date).ToUniversalTime()

    # ---- K15 (security review 2026-10-08): the policy FILE can never grant the mode; the signed release constant must
    Section "K15 authority: a companion policy file in a release built dormant grants nothing, and is reported"
    Assert-True ($KioskReleaseMode -ceq "explorer") "precondition: the shipped BayAgent.ps1 is built dormant (`$KioskReleaseMode = explorer)"
    Reset-K9
    Set-TestFile $KioskPolicyPath "{`"schema`":1,`"mode`":`"companion`",`"minShellBytes`":4096}"
    $rp = Get-KioskReleasePolicy
    Assert-True ($rp.Mode -eq "explorer" -and -not $rp.MatchesRelease -and $rp.Reason -match "built 'explorer'") "an edited policy file saying companion: explorer, and the disagreement is named ($($rp.Reason))"
    Invoke-KioskReconcileTick -NowUtc $now9 -CommandLineOf $clGone -StartShell $startSb -StopProcess $stopSb
    Assert-True ($script:Started.Count -eq 0 -and $Global:KioskReport.target -eq "explorer" -and $Global:KioskReport.policyMatchesRelease -eq $false) "...the reconciler starts no shell and reports policyMatchesRelease=false"
    [void](Write-KioskIntent -Launcher "wanted" -UntilUtc ($now9.AddMinutes(30)) -SessionId "s-1" -Reason "test")
    Set-TestFile $KioskHeartbeatPath (ConvertTo-Json -InputObject @{ schema = 1; pid = 4242; lastLoopUtc = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ"); supervising = $true; degraded = $false })
    Assert-True (-not (Get-KioskLauncherDeferral -NowUtc ((Get-Date).ToUniversalTime()) -CommandLineOf $clShell).Defer -and -not (Get-KioskWallDeferral -NowUtc ((Get-Date).ToUniversalTime()) -CommandLineOf $clShell).Defer) "...and the agent hands neither the launcher nor the wall to a shell"
    $KioskReleaseMode = "companion"
    $rp = Get-KioskReleasePolicy
    Assert-True ($rp.Mode -eq "companion" -and $rp.MatchesRelease) "a release built companion with a companion policy: companion"
    Set-TestFile $KioskPolicyPath "{`"schema`":1,`"mode`":`"explorer`",`"minShellBytes`":4096}"
    $rp = Get-KioskReleasePolicy
    Assert-True ($rp.Mode -eq "explorer" -and -not $rp.MatchesRelease) "a release built companion whose policy file says explorer: explorer (the file may only turn it off), reported"
    $KioskReleaseMode = "shell"
    Set-TestFile $KioskPolicyPath "{`"schema`":1,`"mode`":`"shell`",`"minShellBytes`":4096}"
    Assert-True ((Get-KioskReleasePolicy).Mode -eq "explorer") "a release constant naming a mode this code does not implement: explorer"
    # The rest of this suite exercises the companion release.
    $KioskReleaseMode = "companion"
    Section "K9 (continued) the reconciler under a companion release"

    Reset-K9
    Set-TestFile $KioskPolicyPath "{`"schema`":1,`"mode`":`"explorer`",`"minShellBytes`":4096}"
    Invoke-KioskReconcileTick -NowUtc $now9 -CommandLineOf $clGone -StartShell $startSb -StopProcess $stopSb
    Assert-True ($script:Started.Count -eq 0 -and $script:Stopped.Count -eq 0) "explorer policy (the dormant release): nothing started, nothing stopped"
    Assert-True ($Global:KioskReport.target -eq "explorer" -and $Global:KioskReport.shellFile.ok) "...and the report still says the shell file arrived verified (remote proof of the package)"
    Assert-True ($Global:KioskReport.Contains("winlogon") -and $Global:KioskReport.winlogon.Contains("hkcuShell") -and $Global:KioskReport.winlogon.Contains("hklmShell")) "...and carries the Winlogon Shell values, read only"

    Reset-K9
    Set-TestFile $KioskPolicyPath "{`"schema`":1,`"mode`":`"companion`",`"minShellBytes`":4096}"
    Invoke-KioskReconcileTick -NowUtc $now9 -CommandLineOf $clGone -StartShell $startSb -StopProcess $stopSb
    Assert-True ($script:Started.Count -eq 1) "companion, verified file, no live shell: one start"
    if ($script:Started.Count -ge 1) {
        Assert-True ($script:Started[0].Exe -ieq (Join-Path $env:WINDIR "System32\WindowsPowerShell\v1.0\powershell.exe")) "...with System32 Windows PowerShell"
        Assert-True ($script:Started[0].Args -ceq (Get-KioskShellArgumentList (Get-KioskShellPath))) "...and exactly the argument list Get-KioskShellArgumentList builds for the version-pinned path"
        Assert-True ($script:Started[0].Args -notmatch '(?i)executionpolicy|bypass|-command|-enc') "...which carries no execution-policy override and no inline command"
    }
    $rec = Read-KioskJsonFile -Path $KioskReconcilePath
    $recStarts = $(if ($rec.Ok) { Get-KioskProp $rec.Obj "shellStarts" $null } else { $null })
    Assert-True ($rec.Ok -and @($recStarts).Count -eq 1 -and $null -ne (ConvertTo-KioskUtc @($recStarts)[0])) "the start time is persisted in state\kiosk-reconcile.json"

    Reset-K9
    Set-TestFile $KioskHeartbeatPath (ConvertTo-Json -InputObject @{ schema = 1; pid = 4242; lastLoopUtc = $now9.AddSeconds(-5).ToString("yyyy-MM-ddTHH:mm:ssZ"); supervising = $true })
    Invoke-KioskReconcileTick -NowUtc $now9 -CommandLineOf $clShell -StartShell $startSb -StopProcess $stopSb
    Assert-True ($script:Started.Count -eq 0 -and $script:Stopped.Count -eq 0) "a live shell: nothing started, nothing stopped"

    Reset-K9
    Set-TestFile $KioskHeartbeatPath (ConvertTo-Json -InputObject @{ schema = 1; pid = 4242; lastLoopUtc = $now9.AddSeconds(-90).ToString("yyyy-MM-ddTHH:mm:ssZ") })
    Invoke-KioskReconcileTick -NowUtc $now9 -CommandLineOf $clShell -StartShell $startSb -StopProcess $stopSb
    Assert-True ($script:Started.Count -eq 0 -and $script:Stopped.Count -eq 0) "a stale (90 s) shell: wait, no second copy"

    Reset-K9
    Set-TestFile $KioskHeartbeatPath (ConvertTo-Json -InputObject @{ schema = 1; pid = 4242; lastLoopUtc = $now9.AddSeconds(-400).ToString("yyyy-MM-ddTHH:mm:ssZ") })
    Invoke-KioskReconcileTick -NowUtc $now9 -CommandLineOf $clShell -StartShell $startSb -StopProcess $stopSb
    Assert-True ($script:Stopped.Count -eq 1 -and $script:Stopped[0] -eq 4242) "a hung shell is stopped by the pid in its heartbeat"
    Assert-True ($script:Started.Count -eq 1) "...and a fresh one started"

    Reset-K9
    Set-TestFile $KioskHeartbeatPath (ConvertTo-Json -InputObject @{ schema = 1; pid = 4242; lastLoopUtc = $now9.AddSeconds(-400).ToString("yyyy-MM-ddTHH:mm:ssZ") })
    Invoke-KioskReconcileTick -NowUtc $now9 -CommandLineOf $clOther -StartShell $startSb -StopProcess $stopSb
    Assert-True ($script:Stopped.Count -eq 0) "an old heartbeat whose pid is now ANOTHER program: nothing is stopped"
    Assert-True ($script:Started.Count -eq 1) "...and a shell is started"

    Reset-K9
    Set-TestFile $KioskPolicyPath "{`"schema`":1,`"mode`":`"explorer`",`"minShellBytes`":4096}"
    Set-TestFile $KioskHeartbeatPath (ConvertTo-Json -InputObject @{ schema = 1; pid = 4242; lastLoopUtc = $now9.AddSeconds(-400).ToString("yyyy-MM-ddTHH:mm:ssZ") })
    Invoke-KioskReconcileTick -NowUtc $now9 -CommandLineOf $clShell -StartShell $startSb -StopProcess $stopSb
    Assert-True ($script:Stopped.Count -eq 1 -and $script:Started.Count -eq 0) "explorer policy with a hung shell left over: it is stopped, none is started"

    Reset-K9
    Set-TestFile $KioskPolicyPath "{`"schema`":1,`"mode`":`"companion`",`"minShellBytes`":4096}"
    Set-TestFile $KioskKillSwitchPath ""
    Invoke-KioskReconcileTick -NowUtc $now9 -CommandLineOf $clGone -StartShell $startSb -StopProcess $stopSb
    Assert-True ($script:Started.Count -eq 0 -and $Global:KioskReport.target -eq "explorer" -and $Global:KioskReport.killSwitch) "kill switch present: nothing started, the report says why"

    Reset-K9
    $script:SigFake = @{ Status = "NotSigned"; Timestamped = $false; Thumbprint = $null }
    Invoke-KioskReconcileTick -NowUtc $now9 -CommandLineOf $clGone -StartShell $startSb -StopProcess $stopSb
    Assert-True ($script:Started.Count -eq 0 -and $Global:KioskReport.action -match "NotSigned") "companion with an unsigned shell file: not started, and the action says the signature"
    $script:SigFake = @{ Status = "Valid"; Timestamped = $true; Thumbprint = "AAAA" }

    Reset-K9
    Invoke-KioskReconcileTick -NowUtc $now9 -CommandLineOf $clGone -StartShell $startSb -StopProcess $stopSb -ExplorerProbe { $false }
    Assert-True ($script:Started.Count -eq 0 -and $Global:KioskReport.action -match "no Explorer") "companion with no Explorer in the session: not started (a companion needs the Windows desktop)"

    Reset-K9
    $Global:KioskSignerThumbprint = $null
    Invoke-KioskReconcileTick -NowUtc $now9 -CommandLineOf $clGone -StartShell $startSb -StopProcess $stopSb
    Assert-True ($script:Started.Count -eq 0) "companion while the agent's own signer is unknown: not started"
    $Global:KioskSignerThumbprint = "AAAA"

    Reset-K9
    for ($i = 0; $i -lt 8; $i++) { Invoke-KioskReconcileTick -NowUtc $now9.AddMinutes($i) -CommandLineOf $clGone -StartShell $startSb -StopProcess $stopSb }
    Assert-True ($script:Started.Count -eq 6) "a shell that keeps dying is started at most 6 times an hour (got $($script:Started.Count) of 8 ticks)"
    $Global:KioskStarts = Read-KioskReconcileStarts -NowUtc $now9.AddMinutes(9)
    Assert-True (@($Global:KioskStarts).Count -eq 6) "the 6 starts survive an agent restart (read back from the reconcile file)"
    $script:Started.Clear()
    Invoke-KioskReconcileTick -NowUtc $now9.AddMinutes(10) -CommandLineOf $clGone -StartShell $startSb -StopProcess $stopSb
    Assert-True ($script:Started.Count -eq 0) "...so the restarted agent still holds"
    Invoke-KioskReconcileTick -NowUtc $now9.AddMinutes(61) -CommandLineOf $clGone -StartShell $startSb -StopProcess $stopSb
    Assert-True ($script:Started.Count -eq 1) "an hour after the first start, one more is allowed"
    Set-TestFile $KioskReconcilePath "{ not json"
    $held = Read-KioskReconcileStarts -NowUtc $now9
    Assert-True (@($held).Count -eq 6) "an unreadable reconcile file reads as the cap spent (fail toward not starting)"
    Remove-Item -LiteralPath $KioskReconcilePath -Force
    Assert-True (@(Read-KioskReconcileStarts -NowUtc $now9).Count -eq 0) "an absent reconcile file reads as no starts"

    Reset-K9
    [void](Write-KioskIntent -Launcher "wanted" -UntilUtc ($now9.AddMinutes(30)) -SessionId "s-1" -Reason "test")
    $Global:EffectiveConfig = @{ "Bay.AgentStatus" = $AGENTSTATUS_MAINTENANCE; "Bay.AgentStatusReason" = "test" }
    Invoke-KioskReconcileTick -NowUtc $now9 -CommandLineOf $clGone -StartShell $startSb -StopProcess $stopSb
    $Global:EffectiveConfig = $null
    $wm = Get-KioskLauncherWanted -IntentRead (Read-KioskJsonFile -Path $KioskIntentPath) -NowUtc $now9
    Assert-True (-not $wm.Wanted -and -not $wm.Closed) "Maintenance mode turns a wanted intent into unmanaged (no restarts; never closed)"
    [void](Write-KioskIntent -Launcher "closed" -UntilUtc $null -SessionId "s-1" -Reason "test")
    $Global:EffectiveConfig = @{ "Bay.AgentStatus" = $AGENTSTATUS_MAINTENANCE; "Bay.AgentStatusReason" = "test" }
    Invoke-KioskReconcileTick -NowUtc $now9 -CommandLineOf $clGone -StartShell $startSb -StopProcess $stopSb
    $Global:EffectiveConfig = $null
    $wm = Get-KioskLauncherWanted -IntentRead (Read-KioskJsonFile -Path $KioskIntentPath) -NowUtc $now9
    Assert-True (-not $wm.Wanted -and -not $wm.Closed) "Maintenance mode lifts closed too (staff on the bay can run the launcher)"
    [void](Write-KioskIntent -Launcher "closed" -UntilUtc $null -SessionId "s-1" -Reason "test")
    Invoke-KioskReconcileTick -NowUtc $now9 -CommandLineOf $clGone -StartShell $startSb -StopProcess $stopSb
    Assert-True ((Get-KioskLauncherWanted -IntentRead (Read-KioskJsonFile -Path $KioskIntentPath) -NowUtc $now9).Closed) "...and only in Maintenance/Offline (Online leaves closed as it is)"

    $cap = Get-KioskCapability
    $capJson = ConvertTo-Json -InputObject $cap -Depth 8 -Compress
    Assert-True ($capJson.Length -lt 4000) "the kiosk capability block is small ($($capJson.Length) chars)"
    Assert-True ($capJson -match '"hkcuShell"' -and $capJson -match '"shellFile"' -and $capJson -match '"intent"') "...and carries the shell file, the intent and the Winlogon reads"

    # ============================================================ K10
    Section "K10 the launcher deferral at StartSession Start"
    Reset-K9
    $nowA = (Get-Date).ToUniversalTime()
    Set-TestFile $KioskPolicyPath "{`"schema`":1,`"mode`":`"explorer`",`"minShellBytes`":4096}"
    [void](Write-KioskIntent -Launcher "wanted" -UntilUtc ($nowA.AddMinutes(30)) -SessionId "s-1" -Reason "test")
    $hbLive = @{ schema = 1; pid = 4242; lastLoopUtc = $nowA.ToString("yyyy-MM-ddTHH:mm:ssZ"); supervising = $true; degraded = $false }
    Set-TestFile $KioskHeartbeatPath (ConvertTo-Json -InputObject $hbLive)
    Assert-True (-not (Get-KioskLauncherDeferral -NowUtc $nowA -CommandLineOf $clShell).Defer) "explorer policy: the agent starts the launcher itself"
    Set-TestFile $KioskPolicyPath "{`"schema`":1,`"mode`":`"companion`",`"minShellBytes`":4096}"
    Assert-True ((Get-KioskLauncherDeferral -NowUtc $nowA -CommandLineOf $clShell).Defer) "companion + wanted + a live supervising shell: the shell starts it"
    Assert-True (-not (Get-KioskLauncherDeferral -NowUtc $nowA -CommandLineOf $clGone).Defer) "...not when the shell process is gone"
    # A stale heartbeat that still SAYS supervising (the shell froze after writing it): only the alive check stops this.
    $hbStaleSup = @{ schema = 1; pid = 4242; lastLoopUtc = $nowA.AddSeconds(-90).ToString("yyyy-MM-ddTHH:mm:ssZ"); supervising = $true; degraded = $false }
    Set-TestFile $KioskHeartbeatPath (ConvertTo-Json -InputObject $hbStaleSup)
    Assert-True (-not (Get-KioskLauncherDeferral -NowUtc $nowA -CommandLineOf $clShell).Defer) "...not to a shell whose heartbeat is 90 s old, even though it says supervising"
    Assert-True (-not (Get-KioskWallDeferral -NowUtc $nowA -CommandLineOf $clShell).Defer) "wall: not to a shell whose heartbeat is 90 s old, even though it says supervising"
    Set-TestFile $KioskHeartbeatPath (ConvertTo-Json -InputObject $hbLive)
    $hbLive.supervising = $false; Set-TestFile $KioskHeartbeatPath (ConvertTo-Json -InputObject $hbLive)
    Assert-True (-not (Get-KioskLauncherDeferral -NowUtc $nowA -CommandLineOf $clShell).Defer) "...not when the shell says it is not supervising"
    $hbLive.supervising = $true; $hbLive.degraded = $true; Set-TestFile $KioskHeartbeatPath (ConvertTo-Json -InputObject $hbLive)
    Assert-True (-not (Get-KioskLauncherDeferral -NowUtc $nowA -CommandLineOf $clShell).Defer) "...not when the shell is degraded"
    $hbLive.degraded = $false; Set-TestFile $KioskHeartbeatPath (ConvertTo-Json -InputObject $hbLive)
    [void](Write-KioskIntent -Launcher "unmanaged" -UntilUtc $null -SessionId "s-1" -Reason "test")
    Assert-True (-not (Get-KioskLauncherDeferral -NowUtc $nowA -CommandLineOf $clShell).Defer) "...not when the intent is unmanaged (a Start with no end time)"
    Set-TestFile $KioskKillSwitchPath ""
    [void](Write-KioskIntent -Launcher "wanted" -UntilUtc ($nowA.AddMinutes(30)) -SessionId "s-1" -Reason "test")
    Assert-True (-not (Get-KioskLauncherDeferral -NowUtc $nowA -CommandLineOf $clShell).Defer) "...not with the kill switch present"
    Assert-True (-not (Get-KioskWallDeferral -NowUtc $nowA -CommandLineOf $clShell).Defer) "wall: not with the kill switch present"
    Remove-Item -LiteralPath $KioskKillSwitchPath -Force
    [void](Write-KioskIntent -Launcher "closed" -UntilUtc $null -SessionId "s-1" -Reason "test")
    Assert-True ((Get-KioskWallDeferral -NowUtc $nowA -CommandLineOf $clShell).Defer) "wall: a live supervising companion shell owns the wall whatever the intent"
    Assert-True (-not (Get-KioskWallDeferral -NowUtc $nowA -CommandLineOf $clGone).Defer) "wall: not when the shell process is gone"
    $hbLive.degraded = $true; Set-TestFile $KioskHeartbeatPath (ConvertTo-Json -InputObject $hbLive)
    Assert-True (-not (Get-KioskWallDeferral -NowUtc $nowA -CommandLineOf $clShell).Defer) "wall: not when the shell is degraded"
    $hbLive.degraded = $false; $hbLive.supervising = $false; Set-TestFile $KioskHeartbeatPath (ConvertTo-Json -InputObject $hbLive)
    Assert-True (-not (Get-KioskWallDeferral -NowUtc $nowA -CommandLineOf $clShell).Defer) "wall: not when the shell is not supervising"
    $hbLive.supervising = $true; Set-TestFile $KioskHeartbeatPath (ConvertTo-Json -InputObject $hbLive)
    Set-TestFile $KioskPolicyPath "{`"schema`":1,`"mode`":`"explorer`",`"minShellBytes`":4096}"
    Assert-True (-not (Get-KioskWallDeferral -NowUtc $nowA -CommandLineOf $clShell).Defer) "wall: not under an explorer policy"

    # ============================================================ K11
    Section "K11 the shell's own decisions"
    $comboBad = 0; $combos = 0
    foreach ($w in @($true, $false)) { foreach ($rn in @($true, $false)) { foreach ($ab in @(0, 1, 2, 5)) { foreach ($al in @($true, $false)) { foreach ($pe in @($true, $false)) { foreach ($cl in @($true, $false)) { foreach ($cf in @(0, 14, 15, 60)) {
        if ($w -and $cl) { continue }   # the reader never returns both
        $combos++
        $a = Get-KioskLauncherAction -Wanted $w -Running $rn -AbsentTicks $ab -StartAllowed $al -PathExists $pe -Closed $cl -ClosedForSeconds $cf -CloseGraceSeconds 15
        if ($a -notin @("none", "wait", "held", "missing", "start", "close")) { $comboBad++; Write-Host "        unexpected launcher action '$a'" }
        if ($a -eq "start" -and -not ($w -and -not $rn -and $ab -ge 2 -and $al -and $pe)) { $comboBad++; Write-Host "        start without every condition (w=$w r=$rn a=$ab allowed=$al path=$pe closed=$cl)" }
        if ($a -eq "close" -and -not ($cl -and $rn -and $cf -ge 15)) { $comboBad++; Write-Host "        close without every condition (closed=$cl running=$rn for=$cf)" }
    } } } } } } }
    Assert-True ($comboBad -eq 0 -and $combos -eq 384) "over all $combos combinations: start needs wanted+absent 2 ticks+allowed+path; close needs closed+running+15 s; nothing else acts"
    Assert-True ((Get-KioskLauncherAction -Wanted $false -Running $true -AbsentTicks 0 -StartAllowed $true -PathExists $true -Closed $true -ClosedForSeconds 15) -eq "close") "closed for 15 s and a launcher running (a member relaunched it after End): close"
    Assert-True ((Get-KioskLauncherAction -Wanted $false -Running $true -AbsentTicks 0 -StartAllowed $true -PathExists $true -Closed $true -ClosedForSeconds 14) -eq "none") "closed for 14 s: not yet (EndSession closes it first)"
    Assert-True ((Get-KioskLauncherAction -Wanted $false -Running $true -AbsentTicks 0 -StartAllowed $true -PathExists $true -Closed $false -ClosedForSeconds 600) -eq "none") "unmanaged with a launcher running: hands off"
    Assert-True ((Get-KioskLauncherAction -Wanted $false -Running $false -AbsentTicks 9 -StartAllowed $true -PathExists $true) -eq "none") "not wanted, absent: nothing (no free play after End)"
    Assert-True ((Get-KioskLauncherAction -Wanted $true -Running $false -AbsentTicks 1 -StartAllowed $true -PathExists $true) -eq "wait") "wanted, absent one tick: wait"
    Assert-True ((Get-KioskLauncherAction -Wanted $true -Running $false -AbsentTicks 2 -StartAllowed $true -PathExists $true) -eq "start") "wanted, absent two ticks: start"
    Assert-True ((Get-KioskLauncherAction -Wanted $true -Running $false -AbsentTicks 2 -StartAllowed $false -PathExists $true) -eq "held") "wanted but the start cap is spent: held"
    Assert-True ((Get-KioskLauncherAction -Wanted $true -Running $true -AbsentTicks 0 -StartAllowed $true -PathExists $true) -eq "none") "wanted and running: nothing"

    Assert-True ((Get-KioskWallPlan -ScreenCount 2 -LauncherWanted $true -WallEnabled $true) -eq "show") "two screens: the wall shows"
    Assert-True ((Get-KioskWallPlan -ScreenCount 1 -LauncherWanted $true -WallEnabled $true) -eq "aside") "one screen and the member needs the launcher: the wall stands aside"
    Assert-True ((Get-KioskWallPlan -ScreenCount 1 -LauncherWanted $false -WallEnabled $true) -eq "show") "one screen, no session: the wall shows on it"
    Assert-True ((Get-KioskWallPlan -ScreenCount 0 -LauncherWanted $false -WallEnabled $true) -eq "none") "no screen at all (TV off and touchscreen gone): start nothing"
    Assert-True ((Get-KioskWallPlan -ScreenCount 2 -LauncherWanted $false -WallEnabled $false) -eq "none") "wall switched off locally: nothing"

    Assert-True ((Get-KioskFloorAction -CompanionRole $true -Supervise $true -ExplorerPresent $true -PolicyWantsCompanion $true) -eq "supervise") "floor: supervising companion supervises"
    Assert-True ((Get-KioskFloorAction -CompanionRole $true -Supervise $false -ExplorerPresent $true -PolicyWantsCompanion $false) -eq "exit") "floor: a companion the policy no longer wants exits (Explorer is the desktop)"
    Assert-True ((Get-KioskFloorAction -CompanionRole $true -Supervise $false -ExplorerPresent $false -PolicyWantsCompanion $false) -eq "start-explorer") "floor: never exit with no Explorer; start one"
    Assert-True ((Get-KioskFloorAction -CompanionRole $true -Supervise $false -ExplorerPresent $true -PolicyWantsCompanion $true) -eq "idle") "floor: a degraded companion the policy still wants idles (not restarted by the agent)"
    Assert-True ((Get-KioskFloorAction -CompanionRole $false -Supervise $false -ExplorerPresent $true -PolicyWantsCompanion $true) -eq "idle") "floor: not started as the companion: never exits"
    Assert-True ((Get-KioskFloorAction -CompanionRole $false -Supervise $false -ExplorerPresent $false -PolicyWantsCompanion $false) -eq "start-explorer") "floor: not the companion and no Explorer: start Explorer"

    $polC = @{ Mode = "companion"; Reason = "policy" }
    Assert-True ((Get-KioskSupervision -CompanionRole $true -PolicyDecision $polC -Degraded $false).Supervise) "supervision: companion + companion policy"
    Assert-True (-not (Get-KioskSupervision -CompanionRole $false -PolicyDecision $polC -Degraded $false).Supervise) "supervision: never without the companion role (this release has no shell mode)"
    Assert-True (-not (Get-KioskSupervision -CompanionRole $true -PolicyDecision $polC -Degraded $true).Supervise) "supervision: never once degraded"
    Assert-True (-not (Get-KioskSupervision -CompanionRole $true -PolicyDecision @{ Mode = "explorer"; Reason = "x" } -Degraded $false).Supervise) "supervision: never under an explorer policy"
    Assert-True (-not (Get-KioskSupervision -CompanionRole $true -PolicyDecision $null -Degraded $false).Supervise) "supervision: never without a policy decision"

    function New-Scr([string]$n, [bool]$pri, [int]$x, [string]$mon = "") { return [pscustomobject]@{ DeviceName = $n; Primary = $pri; Left = $x; Top = 0; Width = 1920; Height = 1080; MonitorName = $mon } }
    $bay1 = @((New-Scr "\\.\DISPLAY1" $true 0 "Touch Panel"), (New-Scr "\\.\DISPLAY2" $false 1920 "Samsung TV"))
    $r = Resolve-KioskRoleScreens -Screens $bay1 -ControlSelector $null -SessionSelector $null
    Assert-True ($r.Control.DeviceName -eq "\\.\DISPLAY1" -and $r.Session.DeviceName -eq "\\.\DISPLAY2") "Bay 1 shape, no selectors: control = the primary touchscreen, session = the TV"
    $r = Resolve-KioskRoleScreens -Screens $bay1 -ControlSelector "DISPLAY1" -SessionSelector "DISPLAY3"
    Assert-True ($r.Control.DeviceName -eq "\\.\DISPLAY1" -and $r.Session.DeviceName -eq "\\.\DISPLAY2") "the template's DISPLAY3 (absent on Bay 1): session falls to the other screen"
    $renum = @((New-Scr "\\.\DISPLAY5" $false 1920 "Samsung TV"), (New-Scr "\\.\DISPLAY4" $true 0 "Touch Panel"))
    $r = Resolve-KioskRoleScreens -Screens $renum -ControlSelector "DISPLAY1" -SessionSelector $null
    Assert-True ($r.Control.DeviceName -eq "\\.\DISPLAY4" -and $r.Session.DeviceName -eq "\\.\DISPLAY5") "renumbered DISPLAYn (two GPUs): roles follow the primary flag, not the number"
    $r = Resolve-KioskRoleScreens -Screens $renum -ControlSelector "Touch" -SessionSelector "samsung"
    Assert-True ($r.Control.DeviceName -eq "\\.\DISPLAY4" -and $r.Session.DeviceName -eq "\\.\DISPLAY5") "monitor-name selectors match without case"
    $r = Resolve-KioskRoleScreens -Screens $bay1 -ControlSelector "DISPLAY2" -SessionSelector "DISPLAY2"
    Assert-True ($r.Control.DeviceName -eq "\\.\DISPLAY2" -and $r.Session.DeviceName -eq "\\.\DISPLAY1") "a session selector naming the control screen is not used: the wall never covers the launcher"
    $one = @((New-Scr "\\.\DISPLAY2" $true 0 "Samsung TV"))
    $r = Resolve-KioskRoleScreens -Screens $one -ControlSelector "DISPLAY1" -SessionSelector $null
    Assert-True ($r.Count -eq 1 -and $r.Control.DeviceName -eq "\\.\DISPLAY2" -and $r.Session.DeviceName -eq "\\.\DISPLAY2") "touchscreen unplugged (only the TV): both roles are the TV, and the wall plan decides who uses it"
    $r = Resolve-KioskRoleScreens -Screens @() -ControlSelector "DISPLAY1" -SessionSelector $null
    Assert-True ($r.Count -eq 0 -and $null -eq $r.Control -and $null -eq $r.Session) "no screen: no roles, nothing to place"
    $three = @((New-Scr "\\.\DISPLAY1" $true 0), (New-Scr "\\.\DISPLAY2" $false 1920), (New-Scr "\\.\DISPLAY3" $false 3840))
    $r = Resolve-KioskRoleScreens -Screens $three -ControlSelector $null -SessionSelector $null
    Assert-True ($r.Control.DeviceName -eq "\\.\DISPLAY1" -and $r.Session.DeviceName -eq "\\.\DISPLAY3") "three screens: session is the last non-control"
    $r = Resolve-KioskRoleScreens -Screens $three -ControlSelector 1 -SessionSelector 2
    Assert-True ($r.Control.DeviceName -eq "\\.\DISPLAY2" -and $r.Session.DeviceName -eq "\\.\DISPLAY3") "numeric selectors are indexes"
    $noPri = @((New-Scr "\\.\DISPLAY1" $false 0), (New-Scr "\\.\DISPLAY2" $false 1920))
    $r = Resolve-KioskRoleScreens -Screens $noPri -ControlSelector $null -SessionSelector $null
    Assert-True ($r.Control.DeviceName -eq "\\.\DISPLAY1") "no primary flag anywhere: control is the first"
    Assert-True ((Get-KioskTopologySignature $bay1) -eq (Get-KioskTopologySignature @($bay1[1], $bay1[0]))) "the topology signature does not depend on enumeration order"
    Assert-True ((Get-KioskTopologySignature $bay1) -ne (Get-KioskTopologySignature $one)) "...and changes when a screen goes"

    $tn = $UtcNow
    $t4 = [DateTime[]]@($tn.AddSeconds(-10), $tn.AddSeconds(-20), $tn.AddSeconds(-30), $tn.AddSeconds(-40))
    Assert-True (-not (Test-KioskStartAllowed -Times $t4 -NowUtc $tn -WindowSeconds 120 -MaxStarts 4)) "4 launcher starts in 2 minutes: the 5th is held"
    Assert-True (Test-KioskStartAllowed -Times $t4 -NowUtc $tn.AddSeconds(100) -WindowSeconds 120 -MaxStarts 4) "...and allowed once the oldest leaves the window"
    $f5 = [DateTime[]]@($tn.AddSeconds(-1), $tn.AddSeconds(-2), $tn.AddSeconds(-3), $tn.AddSeconds(-4), $tn.AddSeconds(-5))
    Assert-True (Get-KioskDegradeVerdict -Failures $f5 -NowUtc $tn -WindowSeconds 600 -Threshold 5) "5 failures in 10 minutes: degraded"
    Assert-True (-not (Get-KioskDegradeVerdict -Failures ([DateTime[]]@($f5 | Select-Object -First 4)) -NowUtc $tn -WindowSeconds 600 -Threshold 5)) "4 failures: not degraded"
    $f5old = [DateTime[]]@($tn.AddSeconds(-700), $tn.AddSeconds(-2), $tn.AddSeconds(-3), $tn.AddSeconds(-4), $tn.AddSeconds(-5))
    Assert-True (-not (Get-KioskDegradeVerdict -Failures $f5old -NowUtc $tn -WindowSeconds 600 -Threshold 5)) "a failure older than the window does not count"

    $lc = Read-KioskLocalConfig -Path (Join-Path $Sandbox "no-such-config.json")
    Assert-True ($lc.Source -match "defaults" -and $lc.LauncherName -eq "UneekorLauncher") "no agent-config.json: defaults, and it says so"
    $cfgP = Join-Path $Sandbox "probe-cfg.json"
    Set-TestFile $cfgP '{"launcher":{"path":"C:\\X\\Golf.exe","processName":"Golf.exe"},"sessionDisplay":{"enabled":false,"profileDir":"D:\\p"},"displayRouting":{"enabled":true,"roles":{"control":{"selector":"Touch"},"session":{"index":1}}}}'
    $lc = Read-KioskLocalConfig -Path $cfgP
    Assert-True ($lc.LauncherPath -eq "C:\X\Golf.exe" -and $lc.LauncherName -eq "Golf" -and -not $lc.WallEnabled -and $lc.ProfileDir -eq "D:\p" -and $lc.ControlSelector -eq "Touch" -and $lc.SessionSelector -eq 1) "the local config is read field by field (name without .exe, selectors, wall switch)"
    Set-TestFile $cfgP '{"launcher":{"path":5},"displayRouting":{"enabled":false,"roles":{"control":{"selector":"Touch"}}}}'
    $lc = Read-KioskLocalConfig -Path $cfgP
    Assert-True ($lc.LauncherPath -eq "C:\Uneekor\Launcher\UneekorLauncher.exe" -and $null -eq $lc.ControlSelector) "a wrong-typed path keeps the default; routing disabled drops the selectors"

    # ============================================================ K12
    Section "K12 censuses"
    $shellText = [IO.File]::ReadAllText($ShellScript)
    $agentText = [IO.File]::ReadAllText($AgentScript)
    $shellCode = (@($ShellAst.FindAll({ param($n) $n -is [System.Management.Automation.Language.CommandAst] }, $true)) | ForEach-Object { $_.GetCommandName() }) | Where-Object { $_ }
    $agentCmds = @($AgentAst.FindAll({ param($n) $n -is [System.Management.Automation.Language.CommandAst] }, $true))
    $regWrite = '(?i)^(Set-ItemProperty|New-ItemProperty|Remove-ItemProperty|Rename-ItemProperty|Clear-ItemProperty|sp|reg|reg\.exe|regedit|regedit\.exe)$'
    Assert-True (@($shellCode | Where-Object { $_ -match $regWrite }).Count -eq 0) "the shell calls no registry-writing command"
    Assert-True (@($agentCmds | Where-Object { $_.GetCommandName() -match $regWrite }).Count -eq 0) "BayAgent calls no registry-writing command anywhere"
    $members = @($AgentAst.FindAll({ param($n) $n -is [System.Management.Automation.Language.InvokeMemberExpressionAst] }, $true)) + @($ShellAst.FindAll({ param($n) $n -is [System.Management.Automation.Language.InvokeMemberExpressionAst] }, $true))
    Assert-True (@($members | Where-Object { $_.Member.Extent.Text -match '(?i)^(SetValue|CreateSubKey|DeleteValue|DeleteSubKey|DeleteSubKeyTree|OpenSubKey)$' }).Count -eq 0) "no .NET registry write (SetValue, CreateSubKey, DeleteValue, OpenSubKey for write) in either file"
    # Every string in the code (not comments) that names a hive: a constant, an expandable string, or a here-string.
    function Get-HiveStrings($ast) {
        return @($ast.FindAll({ param($n) ($n -is [System.Management.Automation.Language.StringConstantExpressionAst] -or $n -is [System.Management.Automation.Language.ExpandableStringExpressionAst]) -and [string]$n.Value -match '(?i)((^|[^A-Za-z0-9_])(HK(CU|LM|U|CR|CC)|HKEY_[A-Z_]+)(:|\\))|Registry::' }, $true))
    }
    $agentHives = @(Get-HiveStrings $AgentAst)
    $wlDef = @($AgentDefs | Where-Object { $_.Name -eq "Get-KioskWinlogonFacts" })[0]
    $inWl = @($agentHives | Where-Object { $_.Extent.StartOffset -ge $wlDef.Extent.StartOffset -and $_.Extent.EndOffset -le $wlDef.Extent.EndOffset })
    Assert-True ($agentHives.Count -eq 2 -and $inWl.Count -eq 2) "BayAgent's code names a registry hive in exactly two strings, both inside Get-KioskWinlogonFacts (found $($agentHives.Count), $($inWl.Count) there)"
    Assert-True (@($inWl | Where-Object { $_.Parent -is [System.Management.Automation.Language.CommandParameterAst] -or ($_.Parent -is [System.Management.Automation.Language.CommandAst] -and $_.Parent.GetCommandName() -ne "Get-ItemProperty") }).Count -eq 0) "...and both are arguments of Get-ItemProperty (a read)"
    Assert-True (@(Get-HiveStrings $ShellAst).Count -eq 0) "the shell's code names no registry hive at all"
    Assert-True (@($shellCode | Where-Object { $_ -match '(?i)^(Stop-Process|kill|spps|taskkill|taskkill\.exe|Stop-Computer|Restart-Computer|logoff|shutdown|shutdown\.exe)$' }).Count -eq 0) "the shell stops no process (and never signs out or restarts)"
    $shellEnds = @($ShellAst.FindAll({ param($n) $n -is [System.Management.Automation.Language.InvokeMemberExpressionAst] -and $n.Member.Extent.Text -match '(?i)^(Kill|CloseMainWindow|WaitForExit|CloseMainWindowAsync)$' }, $true))
    $closeDef = @($ShellDefs | Where-Object { $_.Name -eq "Close-KioskLauncher" })[0]
    $inClose = @($shellEnds | Where-Object { $_.Extent.StartOffset -ge $closeDef.Extent.StartOffset -and $_.Extent.EndOffset -le $closeDef.Extent.EndOffset })
    Assert-True ($shellEnds.Count -eq 2 -and $inClose.Count -eq 2 -and @($inClose | Where-Object { $_.Member.Extent.Text -eq "Kill" }).Count -eq 1) "the shell ends a process in exactly one place: one CloseMainWindow and one Kill, both inside Close-KioskLauncher"
    $closeCalls = @($ShellAst.FindAll({ param($n) $n -is [System.Management.Automation.Language.CommandAst] -and $n.GetCommandName() -eq "Close-KioskLauncher" }, $true))
    $ccIf = $null; $ccSwitch = $null
    if ($closeCalls.Count -eq 1) {
        $anc = $closeCalls[0].Parent
        while ($null -ne $anc) {
            if ($null -eq $ccIf -and $anc -is [System.Management.Automation.Language.IfStatementAst]) { $ccIf = $anc }
            if ($null -eq $ccSwitch -and $anc -is [System.Management.Automation.Language.SwitchStatementAst]) { $ccSwitch = $anc }
            $anc = $anc.Parent
        }
    }
    Assert-True ($closeCalls.Count -eq 1 -and $null -ne $ccIf -and $ccIf.Clauses[0].Item1.Extent.Text -eq '$guard.AllowClose' -and $null -ne $ccSwitch -and $ccSwitch.Condition.Extent.Text -eq '$action') "...reached only from the launcher action switch, and only when the session.json guard allows it"
    $closeText = Get-DefText $ShellDefs "Close-KioskLauncher"
    Assert-True ($closeText -match 'Test-KioskIsConfiguredLauncher -Proc \$fresh -Cfg \$S\.Cfg -SessionId \$S\.SessionId\) -or \$null -eq \$fst -or \$fst -ne \$rec\.Start' -and $closeText -match 'Test-KioskIsConfiguredLauncher -Proc \$p ') "...and it re-checks name, path, session and start time before asking and before ending"
    Assert-True (@($shellCode | Where-Object { $_ -match '(?i)^Remove-Item$' }).Count -eq 1 -and (Get-DefText $ShellDefs "Remove-KioskOldLogs") -match 'Remove-Item') "the shell's only Remove-Item is the 14-day log retention"
    Assert-True ($shellText -notmatch '(?i)Invoke-RestMethod|Invoke-WebRequest|EffectiveConfig|ConfigItem|BayProfile|dataverse|crm\.dynamics') "the shell reads nothing from the platform (I6)"
    Assert-True (@([regex]::Matches($shellText, '(?m)^\$BaseDir = "C:\\AllBirdies\\BayAgent"\r?$')).Count -eq 1) "the shell has exactly one install-path literal (the launch test repoints only it)"
    Assert-True (($agentText + $shellText) -notmatch '@\(\s*Get-KioskProp') "no call wraps Get-KioskProp in @() (it returns an array as one object; @() would nest it)"
    $kioskFns = @($AgentDefs | Where-Object { $_.Name -match 'Kiosk' })
    $stopsInKiosk = @($kioskFns | ForEach-Object { @($_.FindAll({ param($n) $n -is [System.Management.Automation.Language.CommandAst] -and $n.GetCommandName() -match '(?i)^(Stop-Process|kill|spps|taskkill)$' }, $true)) })
    Assert-True ($stopsInKiosk.Count -eq 1 -and ((Get-DefText $AgentDefs "Invoke-KioskReconcileTick") -match 'Stop-Process -Id \$procId')) "the agent's kiosk code stops a process in exactly one place, by id, in the reconciler"
    $tick = Get-DefText $AgentDefs "Invoke-KioskReconcileTick"
    Assert-True ($tick -match '(?s)if \(\$live\.State -eq "hung"\) \{.*?& \$StopProcess') "...and only on the hung branch"
    $argOut = Get-KioskShellArgumentList "C:\x\releases\1.4.0\kiosk\ABG.KioskShell.ps1"
    Assert-True ($argOut -notmatch '(?i)ExecutionPolicy|Bypass|-Command|-ep |-enc') "the shell's command line carries no execution-policy override (AllSigned applies)"
    Assert-True ($argOut -ceq '-NoProfile -NonInteractive -WindowStyle Hidden -File "C:\x\releases\1.4.0\kiosk\ABG.KioskShell.ps1" -Companion') "...and is exactly the documented one"
    $exec = Get-DefText $AgentDefs "Execute-Command"
    $iStart = $exec.IndexOf('$kioskIntent = Set-KioskIntentForCommand -CommandType $CMD_STARTSESSION')
    $iLaunch = $exec.IndexOf('Start-LauncherIfNeeded "StartSession:Start"')
    Assert-True ($iStart -gt 0 -and $iLaunch -gt $iStart) "StartSession writes the intent BEFORE anything starts the launcher"
    $iEnd = $exec.IndexOf('Set-KioskIntentForCommand -CommandType $CMD_ENDSESSION')
    $iClose = $exec.IndexOf('$launcherStopped = Stop-ProcessesGracefully $procs 8')
    Assert-True ($iEnd -gt 0 -and $iClose -gt $iEnd) "EndSession writes 'not wanted' BEFORE it closes the launcher"
    Assert-True ($exec.IndexOf('Set-KioskIntentForCommand -CommandType $CMD_RESET') -gt 0 -and $exec.IndexOf('Set-KioskIntentForCommand -CommandType $CMD_EMERGENCY_STOP') -gt 0 -and $exec.IndexOf('Set-KioskIntentForCommand -CommandType $CMD_UPDATESESSIONDISPLAY') -gt 0) "Reset, emergency stop and UpdateSessionDisplay each reach the intent"
    $iDefer = $exec.IndexOf('Get-KioskLauncherDeferral')
    Assert-True ($iDefer -gt 0 -and $iDefer -lt $iLaunch) "the deferral is decided before the agent's own launcher start"

    # ============================================================ K13
    Section "K13 the command handlers reach the intent and the deferral (Execute-Command run with stubs)"
    foreach ($n in @("Execute-Command", "Try-ParseJson", "Get-BayLabel", "Set-PropValue", "To-Hashtable", "Merge-Hashtables", "Build-SessionDisplayPatchFromPayload",
                     "Normalize-SessionModel", "UtcNow-Z", "Get-HelpText", "Get-LauncherConfigFromPayloadOrConfig", "Write-SessionFiles", "Set-EmergencyStopBanner", "Get-SessionJsPath", "Get-ResetGate", "Read-SessionModelFromDisk",
                     "Test-BaySessionIdMatch", "Get-RunningSessionForCommand", "Write-RunningSessionFile", "Set-RunningSession", "Sync-RunningSessionFile",
                     "Set-RunningSessionForCommand", "Initialize-RunningSession")) {
        . ([scriptblock]::Create((Get-DefText $AgentDefs $n)))
    }
    # Kiosk round 2 (A0.467, F1-R1, F1-R2, RV1-RV4). Lifted when present, so this file also runs against the base
    # release (4c8851ac), where the K21 scenarios then FAIL for the reason they exist instead of the lift throwing.
    foreach ($n in @("Set-AgentRunningStamp", "ConvertTo-RunningSnapshot", "Test-SessionFinished", "Add-FinishedSessionToList", "Add-FinishedSession",
                     "Get-EndSessionScope", "Get-CancelEndUtc", "Get-CancelWarningText", "Send-ControlScreenWarning", "Start-CancelWarning", "Invoke-CancelEndIfDue",
                     "Test-EndPendingFor", "Get-CommandRefusal", "Add-EndPending", "Clear-EndPending", "Invoke-PendingEndRetry", "Start-ControlScreenSender")) {
        if (@($AgentDefs | Where-Object { $_.Name -eq $n }).Count -eq 1) { . ([scriptblock]::Create((Get-DefText $AgentDefs $n))) }
        else { . ([scriptblock]::Create("function $n { return `$null }")) }
    }
    # The real msg.exe would put a message box on this PC's desktop: the suite records the call instead (K21 tests the
    # real function with an injected starter).
    $script:ControlWarnings = New-Object System.Collections.ArrayList
    if (@($AgentDefs | Where-Object { $_.Name -eq "Send-ControlScreenWarning" }).Count -eq 1) {
        . ([scriptblock]::Create((Get-DefText $AgentDefs "Send-ControlScreenWarning").Replace("function Send-ControlScreenWarning", "function Test-RealSendControlScreenWarning")))
    }
    function Send-ControlScreenWarning { param([string]$Text, [int]$Seconds, [scriptblock]$Starter = $null) [void]$script:ControlWarnings.Add(@{ Text = $Text; Seconds = $Seconds }); return [ordered]@{ shown = $true; via = "test"; why = "recorded"; pid = $null } }
    $BayId = "33333333-3333-3333-3333-333333333333"
    $Global:EmergencyStopReason = $null
    $script:LauncherStarts = 0
    function Invoke-FacilitySetMode { param([string]$Mode, $payloadObj) return @{ ok = $true; scene = $Mode } }
    function Start-SessionDisplay($payloadObj) { return @{ started = $false; reason = "stub" } }
    function Stop-SessionDisplay { return @{ stopped = $false; reason = "stub" } }
    function Stop-AppsIfRequested($payloadObj) { return @{ stopped = $false; reason = "stub" } }
    function Start-LauncherIfNeeded([string]$context, $launcherCfg) { $script:LauncherStarts++; return @{ started = $true; pid = 1; context = $context } }
    function Invoke-EmergencyStopInternal { param($payloadObj) $Global:EmergencyStopEngaged = $true; return @{ ok = $true; engaged = $true } }
    function Get-KioskProcessCommandLine([int]$ProcessId) { if ($ProcessId -eq 4242) { return $myShellCl } return $null }
    function Get-IntentNow { return (Get-KioskLauncherWanted -IntentRead (Read-KioskJsonFile -Path $KioskIntentPath) -NowUtc ((Get-Date).ToUniversalTime())) }
    $endIso = (Get-Date).ToUniversalTime().AddMinutes(50).ToString("yyyy-MM-ddTHH:mm:ssZ")
    function New-Payload([string]$mode, [string]$sid, [string]$extra = "") { return ('{"mode":"' + $mode + '","baySessionId":"' + $sid + '","startUtc":"2026-10-08T12:00:00Z","playEndUtc":"' + $endIso + '","endUtc":"' + $endIso + '","closeLauncher":false' + $extra + '}') }
    foreach ($f in @($KioskHeartbeatPath, $KioskKillSwitchPath, (Join-Path $Sandbox "session.json"))) { if (Test-Path -LiteralPath $f) { Remove-Item -LiteralPath $f -Force } }
    $Global:EmergencyStopEngaged = $false

    Set-TestFile $KioskPolicyPath "{`"schema`":1,`"mode`":`"explorer`",`"minShellBytes`":4096}"
    $res = Execute-Command -CommandType $CMD_STARTSESSION -PayloadJson (New-Payload "Start" "s-1") -BayLabel "Bay"
    Assert-True ((Get-IntentNow).Wanted -and $script:LauncherStarts -eq 1) "explorer policy, Start: intent wanted, and the agent started the launcher itself (as before)"
    Assert-True ($null -ne $res.kiosk -and $res.kiosk.launcher -eq "wanted" -and $res.kiosk.written) "...and the command result says the intent was written"

    Set-TestFile $KioskPolicyPath "{`"schema`":1,`"mode`":`"companion`",`"minShellBytes`":4096}"
    Set-TestFile $KioskHeartbeatPath (ConvertTo-Json -InputObject @{ schema = 1; pid = 4242; lastLoopUtc = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ"); supervising = $true; degraded = $false; launcher = @{ running = $true; pid = 77 } })
    $script:LauncherStarts = 0
    $res = Execute-Command -CommandType $CMD_STARTSESSION -PayloadJson (New-Payload "Start" "s-1") -BayLabel "Bay"
    Assert-True ($script:LauncherStarts -eq 0 -and $res.launcher.reason -eq "kiosk_shell_owns_launcher") "companion with a live supervising shell, Start: the agent does NOT start the launcher; the shell does"
    Assert-True ((Get-PropValue (Get-PropValue $res.launcher "shell" $null) "running" $false) -eq $true) "...and the result reports the shell's launcher running"
    # The REAL Start-SessionDisplay (renamed so the stub above stays for the other handlers). Its Edge path does not
    # exist, so if the deferral were missing it would throw instead of starting a browser on this PC.
    . ([scriptblock]::Create((Get-DefText $AgentDefs "Start-SessionDisplay").Replace("function Start-SessionDisplay(", "function Test-RealStartSessionDisplay(")))
    $Global:SessionDisplayProfileDir = Join-Path $Sandbox "edge-profile"
    $cfg | Add-Member -NotePropertyName sessionDisplay -NotePropertyValue ([pscustomobject]@{ edgePath = "C:\AbgNoSuch\msedge.exe"; url = "about:blank"; profileDir = $Global:SessionDisplayProfileDir; mode = "kiosk" }) -Force
    $wallRes = $null; try { $wallRes = Test-RealStartSessionDisplay ([pscustomobject]@{}) } catch { $wallRes = @{ reason = "threw: " + $_.Exception.Message } }
    Assert-True ($null -ne $wallRes -and $wallRes.reason -eq "kiosk_shell_owns_wall") "Start-SessionDisplay leaves the wall to the live supervising shell (got: $(if ($wallRes) { $wallRes.reason }))"

    function Get-IntentField([string]$f) { try { return [string](([IO.File]::ReadAllText($KioskIntentPath) | ConvertFrom-Json).$f) } catch { return "" } }
    $res = Execute-Command -CommandType $CMD_STARTSESSION -PayloadJson (New-Payload "Start" "s-1" ',"launcher":{"startOnStart":false}') -BayLabel "Bay"
    Assert-True ((Get-IntentField "launcher") -eq "unmanaged" -and $script:LauncherStarts -eq 0 -and $res.launcher.reason -eq "startOnStart_false") "Start with launcher.startOnStart=false: unmanaged, so the shell neither starts nor closes what the agent left alone"

    $reasonBefore = Get-IntentField "writtenUtc"
    Start-Sleep -Milliseconds 1100
    [void](Execute-Command -CommandType $CMD_STARTSESSION -PayloadJson (New-Payload "Prep" "s-1") -BayLabel "Bay")
    Assert-True ((Get-IntentField "writtenUtc") -eq $reasonBefore -and (Get-IntentField "launcher") -eq "unmanaged") "Prep: the intent is not touched"

    [void](Execute-Command -CommandType $CMD_STARTSESSION -PayloadJson (New-Payload "Start" "s-1") -BayLabel "Bay")
    Assert-True ((Get-IntentNow).Wanted) "Start again: wanted"
    $res = Execute-Command -CommandType $CMD_ENDSESSION -PayloadJson (New-Payload "End" "s-0-older") -BayLabel "Bay"
    Assert-True ((Get-IntentNow).Wanted -and $null -eq $res.kiosk) "a late EndSession for an OLDER session leaves the current session wanted"
    # (Pre-existing, measured here: that late EndSession also rewrote session.json with the OLDER session's id and ENDED.
    # Start s-1 again so the next EndSession is judged against s-1.)
    [void](Execute-Command -CommandType $CMD_STARTSESSION -PayloadJson (New-Payload "Start" "s-1") -BayLabel "Bay")
    $res = Execute-Command -CommandType $CMD_ENDSESSION -PayloadJson (New-Payload "End" "s-1") -BayLabel "Bay"
    Assert-True ((Get-IntentNow).Closed -and $res.kiosk.launcher -eq "closed") "EndSession of the current session: closed"

    [void](Execute-Command -CommandType $CMD_STARTSESSION -PayloadJson (New-Payload "Start" "s-2") -BayLabel "Bay")
    [void](Execute-Command -CommandType $CMD_RESET -PayloadJson '{}' -BayLabel "Bay")
    Assert-True ((Get-IntentNow).Wanted) "Reset while s-2 plays (a canceled other booking): s-2 stays wanted"
    [void](Execute-Command -CommandType $CMD_ENDSESSION -PayloadJson (New-Payload "End" "s-2") -BayLabel "Bay")
    Assert-True ((Get-IntentNow).Closed) "EndSession s-2: closed"
    [void](Execute-Command -CommandType $CMD_RESET -PayloadJson '{}' -BayLabel "Bay")
    Assert-True ((Get-IntentNow).Closed) "Reset after an End: no change (stays closed)"

    # ---- K18: the attack's scenarios (RF1 E2-E4, RF2 E5) through the real handlers, judged by the shell's own decisions
    Section "K18 attack RF1/RF2: no Reset and no failed write ever turns a paying session into a close"
    function Clear-EmergencyStopInternal { $Global:EmergencyStopEngaged = $false; return @{ ok = $true; engaged = $false } }
    $resetJson = '{"mode":"Full","reason":"BookingCanceled"}'
    function Get-ShellVerdictNow {
        # What the shell would do to a running launcher right now, 60 s into the intent (past any grace).
        $wn = Get-KioskLauncherWanted -IntentRead (Read-KioskJsonFile -Path $KioskIntentPath) -NowUtc ((Get-Date).ToUniversalTime())
        $act = Get-KioskLauncherAction -Wanted ([bool]$wn.Wanted) -Running $true -AbsentTicks 0 -StartAllowed $true -PathExists $true -Closed ([bool]$wn.Closed) -ClosedForSeconds 600 -CloseGraceSeconds 15
        # As Invoke-KioskTick calls it (round 2 passes the closed intent's time; the base release's guard has no such parameter).
        $gArgs = @{ SessionRead = (Read-KioskJsonFile -Path (Join-Path $Sandbox "session.json") -MaxBytes 262144); ClosedSessionId = ([string]$wn.SessionId); NowUtc = ((Get-Date).ToUniversalTime()) }
        if ((Get-Command Get-KioskSessionGuard).Parameters.ContainsKey("ClosedSinceUtc")) { $gArgs["ClosedSinceUtc"] = $wn.ClosedSinceUtc }
        $g = Get-KioskSessionGuard @gArgs
        if ($act -eq "close" -and -not $g.AllowClose) { return "held" }
        return $act
    }
    # E2: emergency stop engaged then cleared mid-session, then another booking's Reset.
    [void](Execute-Command -CommandType $CMD_STARTSESSION -PayloadJson (New-Payload "Start" "s-e2") -BayLabel "Bay")
    [void](Execute-Command -CommandType $CMD_EMERGENCY_STOP -PayloadJson '{"action":"engage","reason":"t"}' -BayLabel "Bay")
    [void](Execute-Command -CommandType $CMD_EMERGENCY_STOP -PayloadJson '{"action":"clear"}' -BayLabel "Bay")
    [void](Execute-Command -CommandType $CMD_RESET -PayloadJson $resetJson -BayLabel "Bay")
    Assert-True (-not (Get-IntentNow).Closed -and (Get-ShellVerdictNow) -ne "close") "E2 e-stop engage, clear, then a canceled booking's Reset: not closed (shell: $(Get-ShellVerdictNow))"
    # E3: Maintenance mid-session (the reconciler writes unmanaged), lifted, then a Reset.
    [void](Execute-Command -CommandType $CMD_STARTSESSION -PayloadJson (New-Payload "Start" "s-e3") -BayLabel "Bay")
    $Global:EffectiveConfig = @{ "Bay.AgentStatus" = $AGENTSTATUS_MAINTENANCE; "Bay.AgentStatusReason" = "t" }
    Invoke-KioskReconcileTick -NowUtc ((Get-Date).ToUniversalTime()) -CommandLineOf $clGone -StartShell $startSb -StopProcess $stopSb
    $Global:EffectiveConfig = $null
    Invoke-KioskReconcileTick -NowUtc ((Get-Date).ToUniversalTime()) -CommandLineOf $clGone -StartShell $startSb -StopProcess $stopSb
    [void](Execute-Command -CommandType $CMD_RESET -PayloadJson $resetJson -BayLabel "Bay")
    Assert-True (-not (Get-IntentNow).Closed -and (Get-ShellVerdictNow) -ne "close") "E3 Maintenance on and off mid-session, then a Reset: not closed"
    # E4: paid extended time whose display command was lost: the intent expired at the old end, then a Reset.
    [void](Execute-Command -CommandType $CMD_STARTSESSION -PayloadJson (New-Payload "Start" "s-e4") -BayLabel "Bay")
    [void](Write-KioskIntent -Launcher "wanted" -UntilUtc ((Get-Date).ToUniversalTime().AddMinutes(-1)) -SessionId "s-e4" -Reason "expired at the old end")
    [void](Execute-Command -CommandType $CMD_RESET -PayloadJson $resetJson -BayLabel "Bay")
    Assert-True (-not (Get-IntentNow).Closed -and (Get-ShellVerdictNow) -ne "close") "E4 extension with a lost display command, then a Reset: not closed"
    # E5 (RF2): back-to-back. A ends (closed); B's Start write fails because the file is held open; B plays.
    [void](Execute-Command -CommandType $CMD_STARTSESSION -PayloadJson (New-Payload "Start" "s-A") -BayLabel "Bay")
    [void](Execute-Command -CommandType $CMD_ENDSESSION -PayloadJson (New-Payload "End" "s-A") -BayLabel "Bay")
    Assert-True ((Get-IntentNow).Closed) "E5 precondition: A's End wrote closed"
    $lock = New-Object IO.FileStream($KioskIntentPath, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
    try {
        $resB = Execute-Command -CommandType $CMD_STARTSESSION -PayloadJson (New-Payload "Start" "s-B") -BayLabel "Bay"
        Assert-True ($null -ne $resB.kiosk -and $resB.kiosk.written -eq $false) "E5 B's Start: the intent write failed (file held open), and the result says so"
        $onDiskB = Get-KioskLauncherWanted -IntentRead (Read-KioskJsonFile -Path $KioskIntentPath) -NowUtc ((Get-Date).ToUniversalTime())
        Assert-True ($onDiskB.Closed) "E5 precondition: A's closed is still on disk"
        Assert-True ((Get-ShellVerdictNow) -eq "held") "E5 the shell holds: session.json shows B running, so A's closed is not acted on"
        Assert-True ((Get-KioskCapability)["intentPending"] -eq $true) "E5 the report says an intent is pending"
        $laterB = (Get-Date).ToUniversalTime().AddMinutes(90).ToString("yyyy-MM-ddTHH:mm:ssZ")
        $rx = Set-KioskIntentForCommand -CommandType $CMD_UPDATESESSIONDISPLAY -Mode "Warn5" -Payload ([pscustomobject]@{ mode = "Warn5"; baySessionId = "s-B"; playEndUtc = $laterB })
        Assert-True ($null -ne $rx -and $rx.launcher -eq "wanted") "E5 a later command decides from B's pending wanted, not A's closed left on disk (an extension of B is still applied)"
        [void](Test-KioskIntentIntegrity)
        Assert-True ((Get-KioskLauncherWanted -IntentRead (Read-KioskJsonFile -Path $KioskIntentPath) -NowUtc ((Get-Date).ToUniversalTime())).Closed) "E5 while still held, the retry cannot land (and nothing worse happens)"
    } finally { $lock.Dispose() }
    $Global:KioskNextReconcileUtc = [DateTime]::MaxValue
    Invoke-KioskReconcileTickIfDue -NowUtc ((Get-Date).ToUniversalTime())
    $Global:KioskNextReconcileUtc = [DateTime]::MinValue
    $wB = Get-IntentNow
    Assert-True ($wB.Wanted -and $wB.SessionId -eq "s-B" -and -not (Get-KioskCapability)["intentPending"]) "E5 once released, the next main-loop pass lands B's wanted, and pending clears"
    Assert-True ($null -eq $Global:KioskIntentTamper -or $Global:KioskIntentTamper.count -eq 0) "E5 a landed pending write is not counted as tampering"
    $resEndB = Execute-Command -CommandType $CMD_ENDSESSION -PayloadJson (New-Payload "End" "s-B") -BayLabel "Bay"
    Assert-True ((Get-IntentNow).Closed) "B's own End: closed"

    # ---- K18b: R7 and RR1 (attack 2026-10-08). A Reset for a canceled booking is tied to its own session: it never
    # rewrites the wall (session.json), restarts the display, moves the facility or touches the intent while a DIFFERENT
    # session runs on the bay.
    Section "K18b R7/RR1: a Reset for another booking leaves a running session's wall, display and facility alone"
    $script:DisplayStops = 0; $script:FacilityCalls = 0
    function Invoke-FacilitySetMode { param([string]$Mode, $payloadObj) $script:FacilityCalls++; return @{ ok = $true; scene = $Mode } }
    function Start-SessionDisplay($payloadObj) { $script:DisplayStops++; return @{ started = $false; reason = "stub" } }
    function Stop-SessionDisplay { $script:DisplayStops++; return @{ stopped = $false; reason = "stub" } }
    $sessPath = Join-Path $Sandbox "session.json"
    function Get-SessNow { return ([IO.File]::ReadAllText($sessPath) | ConvertFrom-Json) }
    [void](Execute-Command -CommandType $CMD_STARTSESSION -PayloadJson (New-Payload "Start" "s-r7") -BayLabel "Bay")
    $before = [IO.File]::ReadAllText($sessPath)
    $script:DisplayStops = 0; $script:FacilityCalls = 0
    $r7 = Execute-Command -CommandType $CMD_RESET -PayloadJson $resetJson -BayLabel "Bay"
    Assert-True ($r7.reset -eq $false -and $r7.skipped -eq $true -and $r7.runningSessionId -eq "s-r7") "R7 Reset (BookingCanceled, no session id) while s-r7 plays: skipped, and the result says who is running"
    Assert-True ((Get-SessNow).status -eq "ACTIVE" -and (Get-SessNow).baySessionId -eq "s-r7" -and [IO.File]::ReadAllText($sessPath) -ceq $before) "R7 the wall's session.json is byte for byte unchanged (still ACTIVE s-r7, not READY)"
    Assert-True ($script:DisplayStops -eq 0 -and $script:FacilityCalls -eq 0) "R7 no display stop/start and no facility change"
    Assert-True ((Get-IntentNow).Wanted -and (Get-IntentNow).SessionId -eq "s-r7") "R7 the launcher signal (intent) still wanted for s-r7"
    $rN = Execute-Command -CommandType $CMD_RESET -PayloadJson '{"mode":"Full","baySessionId":"s-other"}' -BayLabel "Bay"
    Assert-True ($rN.reset -eq $false -and (Get-SessNow).status -eq "ACTIVE") "R7 a Reset naming a DIFFERENT session: skipped"
    $rS = Execute-Command -CommandType $CMD_RESET -PayloadJson '{"mode":"Full","baySessionId":"s-r7"}' -BayLabel "Bay"
    # Kiosk round 2 (A0.467): the running booking canceled mid-play is warned for 5 minutes (the wall goes ENDING), not reset.
    Assert-True ((Get-PropValue $rS "reset" $null) -eq $false -and $null -ne (Get-PropValue $rS "cancelWarning" $null) -and (Get-SessNow).status -eq "ENDING") "R7 a Reset naming the running session itself (canceled mid-play): its 5-minute warning starts, the wall goes ENDING (A0.467)"
    [void](Execute-Command -CommandType $CMD_STARTSESSION -PayloadJson (New-Payload "Start" "s-r7b") -BayLabel "Bay")
    $rF = Execute-Command -CommandType $CMD_RESET -PayloadJson '{"mode":"Full","force":true}' -BayLabel "Bay"
    Assert-True ($rF.reset -eq $true -and (Get-SessNow).status -eq "READY") "R7 an operator's force=true Reset proceeds"
    [void](Execute-Command -CommandType $CMD_STARTSESSION -PayloadJson (New-Payload "Start" "s-r7c") -BayLabel "Bay")
    [void](Execute-Command -CommandType $CMD_ENDSESSION -PayloadJson (New-Payload "End" "s-r7c") -BayLabel "Bay")
    $rE = Execute-Command -CommandType $CMD_RESET -PayloadJson $resetJson -BayLabel "Bay"
    Assert-True ($rE.reset -eq $true -and (Get-SessNow).status -eq "READY") "R7 a canceled booking's Reset when nobody plays (after an End): still resets the wall to READY"
    # RR1 (L3): A ends (closed A); B's Start write keeps failing (file held open); a canceled booking's Reset arrives.
    [void](Execute-Command -CommandType $CMD_STARTSESSION -PayloadJson (New-Payload "Start" "s-LA") -BayLabel "Bay")
    [void](Execute-Command -CommandType $CMD_ENDSESSION -PayloadJson (New-Payload "End" "s-LA") -BayLabel "Bay")
    $lock3 = New-Object IO.FileStream($KioskIntentPath, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
    try {
        [void](Execute-Command -CommandType $CMD_STARTSESSION -PayloadJson (New-Payload "Start" "s-LB") -BayLabel "Bay")
        [void](Execute-Command -CommandType $CMD_RESET -PayloadJson $resetJson -BayLabel "Bay")
        Assert-True ((Get-SessNow).status -eq "ACTIVE" -and (Get-SessNow).baySessionId -eq "s-LB") "RR1 L3 the Reset during a failing intent write leaves session.json ACTIVE s-LB (not READY)"
        Assert-True ((Get-ShellVerdictNow) -eq "held") "RR1 L3 the shell holds A's stale closed (B plays): B's game is not ended"
    } finally { $lock3.Dispose() }
    [void](Execute-Command -CommandType $CMD_ENDSESSION -PayloadJson (New-Payload "End" "s-LB") -BayLabel "Bay")
    # The gate itself, pure (RF-K1: keyed on the running-session record, never on session.json).
    $nR = (Get-Date).ToUniversalTime(); $fut = $nR.AddMinutes(30).ToString("yyyy-MM-ddTHH:mm:ssZ"); $recent = $nR.AddMinutes(-16).ToString("yyyy-MM-ddTHH:mm:ssZ")
    $lapsed = $nR.AddHours(-7).ToString("yyyy-MM-ddTHH:mm:ssZ"); $nearLapse = $nR.AddHours(-5).ToString("yyyy-MM-ddTHH:mm:ssZ")
    $gid = "8a4f2c10-1d2e-4f50-9a6b-7c8d9e0f1a2b"
    function New-Rec([string]$sid, $end) { return [ordered]@{ baySessionId = $sid; endUtc = $end; since = "2026-10-09T12:00:00Z" } }
    function Get-RG($rec, [string]$bound, [string]$payloadJson = '{"mode":"Full","reason":"BookingCanceled"}') { return (Get-ResetGate -Running $rec -BoundSessionId $bound -Payload ($payloadJson | ConvertFrom-Json) -NowUtc $nR) }
    Assert-True ((Get-RG $null "").Proceed) "gate: no running-session record (nobody plays): proceed"
    Assert-True (-not (Get-RG (New-Rec "s-x" $fut) "").Proceed) "gate: s-x playing, a Reset bound to no session: hold"
    Assert-True (-not (Get-RG (New-Rec "s-x" $fut) "s-y").Proceed) "gate: s-x playing, a Reset bound to another session: hold"
    $gS = Get-RG (New-Rec "s-x" $fut) "s-x"
    Assert-True ($gS.Proceed -and $gS.NamesRunning) "gate: a Reset bound to the running session (canceled mid-play): proceed, and it is told to clear the record"
    Assert-True ((Get-RG (New-Rec "s-x" $fut) "" '{"mode":"Full","baySessionId":"s-x"}').NamesRunning) "gate: no row binding, the payload names the running session: proceed"
    Assert-True (-not (Get-RG (New-Rec "s-x" $fut) "s-y" '{"mode":"Full","baySessionId":"s-x"}').Proceed) "gate: the row binding wins over a payload id (bound to s-y, payload says s-x): hold"
    Assert-True (-not (Get-RG (New-Rec "s-x" $recent) "").Proceed) "gate: 16 minutes past the recorded end (a lost extension display, a late End): hold (attack N2a)"
    Assert-True (-not (Get-RG (New-Rec "s-x" $nearLapse) "").Proceed) "gate: 5 hours past the recorded end: still hold"
    Assert-True ((Get-RG (New-Rec "s-x" $lapsed) "").Proceed) "gate: 7 hours past the recorded end and no End ever: proceed (the record lapses; the bay is recoverable)"
    Assert-True (-not (Get-RG (New-Rec "s-x" $null) "").Proceed) "gate: a record with no readable end: hold (it lapses only by its End, a Reset for it, the next Start or force)"
    Assert-True (-not (Get-RG (New-Rec "" $fut) "").Proceed) "gate: a running record with no id and a Reset naming none: hold (empty never matches empty)"
    # Clock fast by hours (attack N2b): 4 real minutes left, bay clock +80 min and +5 h.
    $realEnd = $nR.AddMinutes(4).ToString("yyyy-MM-ddTHH:mm:ssZ")
    Assert-True (-not (Get-ResetGate -Running (New-Rec "s-x" $realEnd) -BoundSessionId "" -Payload ([pscustomobject]@{}) -NowUtc $nR.AddMinutes(80)).Proceed) "gate: bay clock 80 minutes fast: hold (attack N2b)"
    Assert-True (-not (Get-ResetGate -Running (New-Rec "s-x" $realEnd) -BoundSessionId "" -Payload ([pscustomobject]@{}) -NowUtc $nR.AddHours(5)).Proceed) "gate: bay clock 5 hours fast: hold"
    # force is the JSON literal true only (attack N1).
    foreach ($pj in @('{"force":"false"}', '{"force":"true"}', '{"force":"0"}', '{"force":"no"}', '{"force":0}', '{"force":1}', '{"force":false}', '{"FORCE":"x"}', '{"force":null}', '{"force":[]}', '{"force":[true]}', '{"force":{}}', '{"force":{"a":true}}')) {
        $gF = Get-RG (New-Rec "s-x" $fut) "" $pj
        Assert-True (-not $gF.Proceed -and -not $gF.Force) "gate: payload $pj is not force: hold"
    }
    $gT = Get-RG (New-Rec "s-x" $fut) "" '{"mode":"Full","force":true}'
    Assert-True ($gT.Proceed -and $gT.Force -and -not $gT.NamesRunning) "gate: force = JSON true: proceed (an operator), and the record is NOT cleared"
    # Session ids compare as GUID text (attack N6).
    foreach ($v in @($gid.ToUpperInvariant(), "{$gid}", " $gid ", "{$($gid.ToUpperInvariant())}")) {
        Assert-True ((Get-RG (New-Rec $gid $fut) $v).NamesRunning) "gate: the running GUID bound as [$v]: the same session"
    }
    foreach ($v in @(($gid -replace '-', ''), "8a4f2c10-1d2e-4f50-9a6b-7c8d9e0f1a2c", "{}", " ")) {
        Assert-True (-not (Get-RG (New-Rec $gid $fut) $v).Proceed) "gate: bound as [$v]: not the running session: hold"
    }

    # ---- K18c: RF-K1 / RF-K2 (attack 2026-10-09). The four writers that move session.json off ACTIVE while a member still
    # plays, each run through the REAL handler (the REAL emergency stop, not the stub), then another booking's cancel Reset;
    # and the RR1 shapes (X1b, X2b) judged by the shell's own decision functions.
    Section "K18c RF-K1/RF-K2: a Reset holds in every state where a member still plays; a stale closed is never acted on"
    function Save-EmergencyStopState { param([bool]$Engaged, [string]$Reason) return @{ Ok = $true; Detail = "test" } }
    . ([scriptblock]::Create((Get-DefText $AgentDefs "Invoke-EmergencyStopInternal")))
    . ([scriptblock]::Create((Get-DefText $AgentDefs "Clear-EmergencyStopInternal")))
    $Global:EmergencyStopEngaged = $false
    function Get-SessStatus { try { $o = [IO.File]::ReadAllText($sessPath) | ConvertFrom-Json; return ("{0}/{1}" -f (Get-PropValue $o "status" ""), (Get-PropValue $o "baySessionId" "")) } catch { return "unreadable" } }
    function Get-RecSid { if ($null -eq $Global:RunningSession) { return "<none>" }; return [string](Get-KioskProp $Global:RunningSession "baySessionId" "") }
    function Invoke-CancelReset([string]$bound) {
        $script:DisplayStops = 0; $script:FacilityCalls = 0
        $wallBefore = [IO.File]::ReadAllText($sessPath)
        $r = Execute-Command -CommandType $CMD_RESET -PayloadJson $resetJson -BayLabel "Bay" -BoundSessionId $bound
        # Read through Get-PropValue: under StrictMode a missing key read as a property throws (a mutant must score, not crash).
        return @{ R = $r; Skipped = ((Get-PropValue $r "skipped" $null) -eq $true); Reset = ((Get-PropValue $r "reset" $null) -eq $true)
                  WallSame = ([IO.File]::ReadAllText($sessPath) -ceq $wallBefore); Touched = ($script:DisplayStops + $script:FacilityCalls) }
    }
    function Release-IntentLock { $Global:KioskNextReconcileUtc = [DateTime]::MaxValue; Invoke-KioskReconcileTickIfDue -NowUtc ((Get-Date).ToUniversalTime()); $Global:KioskNextReconcileUtc = [DateTime]::MinValue }

    # X1: the REAL e-stop engaged and cleared mid-session (A0.457: the game keeps running; STOP stays in session.json).
    [void](Execute-Command -CommandType $CMD_STARTSESSION -PayloadJson (New-Payload "Start" "s-x1") -BayLabel "Bay")
    [void](Execute-Command -CommandType $CMD_EMERGENCY_STOP -PayloadJson '{"action":"engage","reason":"t"}' -BayLabel "Bay")
    [void](Execute-Command -CommandType $CMD_EMERGENCY_STOP -PayloadJson '{"action":"clear"}' -BayLabel "Bay")
    Assert-True ((Get-SessStatus) -eq "STOP/s-x1" -and -not $Global:EmergencyStopEngaged) "X1 precondition: the real e-stop left session.json STOP after the clear"
    foreach ($b in @("", "s-other")) {
        $x = Invoke-CancelReset $b
        Assert-True ($x.Skipped -and -not $x.Reset -and $x.WallSame -and $x.Touched -eq 0) "X1 cleared e-stop, then a cancel Reset bound to [$b]: skipped, wall byte-identical, no display or facility call"
    }
    Assert-True ((Get-RecSid) -eq "s-x1") "X1 the running-session record still names s-x1"
    [void](Execute-Command -CommandType $CMD_ENDSESSION -PayloadJson (New-Payload "End" "s-x1") -BayLabel "Bay")
    Assert-True ((Get-RecSid) -eq "<none>") "X1 s-x1's own End clears the record"

    # X1b: RR1 through STOP. P ends (closed P); Q's Start intent write keeps failing; e-stop engage and clear; cancel Reset.
    [void](Execute-Command -CommandType $CMD_STARTSESSION -PayloadJson (New-Payload "Start" "s-P") -BayLabel "Bay")
    [void](Execute-Command -CommandType $CMD_ENDSESSION -PayloadJson (New-Payload "End" "s-P") -BayLabel "Bay")
    $lockX = New-Object IO.FileStream($KioskIntentPath, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
    try {
        [void](Execute-Command -CommandType $CMD_STARTSESSION -PayloadJson (New-Payload "Start" "s-Q") -BayLabel "Bay")
        Assert-True ((Get-KioskLauncherWanted -IntentRead (Read-KioskJsonFile -Path $KioskIntentPath) -NowUtc ((Get-Date).ToUniversalTime())).Closed) "X1b precondition: P's closed is still on disk (Q's write failed)"
        [void](Execute-Command -CommandType $CMD_EMERGENCY_STOP -PayloadJson '{"action":"engage","reason":"t"}' -BayLabel "Bay")
        [void](Execute-Command -CommandType $CMD_EMERGENCY_STOP -PayloadJson '{"action":"clear"}' -BayLabel "Bay")
        Assert-True ((Get-ShellVerdictNow) -eq "held") "X1b after the e-stop engage and clear (wall STOP): the shell holds"
        $x = Invoke-CancelReset ""
        Assert-True ($x.Skipped -and (Get-SessStatus) -eq "STOP/s-Q") "X1b the cancel Reset is skipped: the wall stays STOP/s-Q, never READY"
        Assert-True ((Get-ShellVerdictNow) -eq "held") "X1b the shell's verdict on Q's running launcher: held (the attack measured close)"
    } finally { $lockX.Dispose() }
    Release-IntentLock
    [void](Execute-Command -CommandType $CMD_ENDSESSION -PayloadJson (New-Payload "End" "s-Q") -BayLabel "Bay")

    # X2: A plays; B's Prep at A's end minus 15 (session.json PREP/B); B is canceled (its Reset bound to B).
    [void](Execute-Command -CommandType $CMD_STARTSESSION -PayloadJson (New-Payload "Start" "s-A2") -BayLabel "Bay")
    [void](Execute-Command -CommandType $CMD_STARTSESSION -PayloadJson (New-Payload "Prep" "s-B2") -BayLabel "Bay")
    Assert-True ((Get-SessStatus) -eq "PREP/s-B2" -and (Get-RecSid) -eq "s-A2") "X2 precondition: B's Prep moved session.json to PREP/s-B2; the record still names A"
    $x = Invoke-CancelReset "s-B2"
    Assert-True ($x.Skipped -and $x.WallSame -and $x.Touched -eq 0 -and (Get-IntentNow).Wanted) "X2 B's cancel Reset (bound to s-B2) while A plays: skipped, nothing touched, A still wanted"
    [void](Execute-Command -CommandType $CMD_ENDSESSION -PayloadJson (New-Payload "End" "s-A2") -BayLabel "Bay")

    # X2b: RR1 through Prep with NO Reset. P2 closed; A2b's Start write keeps failing; the next booking's Prep.
    [void](Execute-Command -CommandType $CMD_STARTSESSION -PayloadJson (New-Payload "Start" "s-P2") -BayLabel "Bay")
    [void](Execute-Command -CommandType $CMD_ENDSESSION -PayloadJson (New-Payload "End" "s-P2") -BayLabel "Bay")
    $lockX = New-Object IO.FileStream($KioskIntentPath, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
    try {
        [void](Execute-Command -CommandType $CMD_STARTSESSION -PayloadJson (New-Payload "Start" "s-A2b") -BayLabel "Bay")
        [void](Execute-Command -CommandType $CMD_STARTSESSION -PayloadJson (New-Payload "Prep" "s-B2b") -BayLabel "Bay")
        Assert-True ((Get-SessStatus) -eq "PREP/s-B2b") "X2b precondition: the next Prep wrote PREP/s-B2b over A2b's wall"
        Assert-True ((Get-ShellVerdictNow) -eq "held") "X2b the shell's verdict on A2b's running launcher after the next Prep: held (the attack measured close)"
        $gx = Get-KioskSessionGuard -SessionRead (Read-KioskJsonFile -Path $sessPath -MaxBytes 262144) -ClosedSessionId "s-P2" -NowUtc ((Get-Date).ToUniversalTime())
        Assert-True (-not $gx.AllowClose -and $gx.Why -match "s-P2") "X2b the guard says why: not ENDED for the closed intent's session"
    } finally { $lockX.Dispose() }
    Release-IntentLock
    [void](Execute-Command -CommandType $CMD_ENDSESSION -PayloadJson (New-Payload "End" "s-A2b") -BayLabel "Bay")

    # X3: B3's Start before A3's End (both due at A3's end; the agent claims createdon asc): A3's late End, then a Reset.
    [void](Execute-Command -CommandType $CMD_STARTSESSION -PayloadJson (New-Payload "Start" "s-A3") -BayLabel "Bay")
    [void](Execute-Command -CommandType $CMD_STARTSESSION -PayloadJson (New-Payload "Start" "s-B3") -BayLabel "Bay")
    [void](Execute-Command -CommandType $CMD_ENDSESSION -PayloadJson (New-Payload "End" "s-A3") -BayLabel "Bay")
    Assert-True ((Get-SessStatus) -eq "ACTIVE/s-B3" -and (Get-RecSid) -eq "s-B3") "X3 A3's late End leaves B3's wall ACTIVE/s-B3 (round 2, F1-R2; it wrote ENDED/s-A3 before); the record still names B3"
    foreach ($b in @("", "s-C3", "s-A3")) {
        $x = Invoke-CancelReset $b
        Assert-True ($x.Skipped -and $x.WallSame -and $x.Touched -eq 0) "X3 then a cancel Reset bound to [$b]: skipped, nothing touched"
    }
    [void](Execute-Command -CommandType $CMD_ENDSESSION -PayloadJson (New-Payload "End" "s-B3") -BayLabel "Bay")

    # X4: the stale shape (a lost extension display keeps the old end): the recorded end 16 minutes ago.
    $e16 = (Get-Date).ToUniversalTime().AddMinutes(-16).ToString("yyyy-MM-ddTHH:mm:ssZ")
    [void](Execute-Command -CommandType $CMD_STARTSESSION -PayloadJson ('{"mode":"Start","baySessionId":"s-x4","startUtc":"2026-10-08T12:00:00Z","playEndUtc":"' + $e16 + '","endUtc":"' + $e16 + '"}') -BayLabel "Bay")
    $x = Invoke-CancelReset ""
    Assert-True ($x.Skipped -and $x.WallSame -and $x.Touched -eq 0) "X4 recorded end 16 minutes ago (no End yet): a cancel Reset is skipped (the old 15-minute stale rule released it)"
    [void](Execute-Command -CommandType $CMD_ENDSESSION -PayloadJson (New-Payload "End" "s-x4") -BayLabel "Bay")

    # X10 / N3: the RUNNING booking itself is canceled mid-play; the platform cancels its End and sends a Reset bound to it.
    [void](Execute-Command -CommandType $CMD_STARTSESSION -PayloadJson (New-Payload "Start" "s-x10") -BayLabel "Bay")
    $x = Invoke-CancelReset ""
    Assert-True ($x.Skipped) "X10 a Reset bound to no session while s-x10 plays: skipped"
    $x = Invoke-CancelReset "S-X10"
    Assert-True (-not $x.Reset -and $null -ne (Get-PropValue $x.R "cancelWarning" $null) -and (Get-SessStatus) -eq "ENDING/s-x10" -and (Get-RecSid) -eq "s-x10") "X10 the Reset bound to s-x10 itself (canceled mid-play): its warning starts (wall ENDING/s-x10, still recorded; A0.467)"
    [void](Invoke-CancelEndIfDue -NowUtc ((Get-Date).ToUniversalTime().AddMinutes(6)))
    Assert-True ((Get-SessStatus) -eq "ENDED/s-x10" -and (Get-RecSid) -eq "<none>") "X10 when the warning is over, s-x10 ends like a normal End (ENDED, record cleared)"
    $x = Invoke-CancelReset "s-later"
    Assert-True ($x.Reset) "X10 after that, nobody plays: a later cancel Reset proceeds"
    $rForce = Execute-Command -CommandType $CMD_RESET -PayloadJson '{"mode":"Full","force":"true"}' -BayLabel "Bay"
    Assert-True ((Get-PropValue $rForce "reset" $null) -eq $true -and (Get-PropValue $rForce "force" $null) -eq $false) "the result records force (text 'true' is not force)"

    # The record's lifecycle (pure).
    $nP = [DateTime]::SpecifyKind([DateTime]::Parse("2026-10-09T12:00:00"), [DateTimeKind]::Utc)
    function Get-RC([int]$t, [string]$m, [string]$pj, $cur) { return (Get-RunningSessionForCommand -CommandType $t -Mode $m -Payload ($pj | ConvertFrom-Json) -Current $cur -NowUtc $nP) }
    $recA = New-Rec "s-a" "2026-10-09T13:00:00Z"
    Assert-True (-not (Get-RC $CMD_STARTSESSION "Prep" '{"baySessionId":"s-b","playEndUtc":"2026-10-09T14:00:00Z"}' $recA).Change) "record: Prep changes nothing"
    $cS = Get-RC $CMD_STARTSESSION "Start" '{"baySessionId":"s-b","playEndUtc":"2026-10-09T14:00:00Z"}' $recA
    Assert-True ($cS.Change -and (Get-KioskProp $cS.Record "baySessionId" "") -eq "s-b" -and (Get-KioskProp $cS.Record "endUtc" "") -eq "2026-10-09T14:00:00Z") "record: Start replaces it with the starting session and its end"
    Assert-True ((Get-KioskProp (Get-RC $CMD_STARTSESSION "start" '{"baySessionId":"s-b","endUtc":"2026-10-09T14:00:00Z"}' $null).Record "endUtc" "") -eq "2026-10-09T14:00:00Z") "record: Start reads endUtc when playEndUtc is absent"
    Assert-True (-not (Get-RC $CMD_ENDSESSION "End" '{"baySessionId":"s-old"}' $recA).Change) "record: a late End of another session does not clear it"
    Assert-True (-not (Get-RC $CMD_ENDSESSION "End" '{}' $recA).Change) "record: an End naming no session does not clear it"
    $cE = Get-RC $CMD_ENDSESSION "End" '{"baySessionId":"S-A"}' $recA
    Assert-True ($cE.Change -and $null -eq $cE.Record) "record: the recorded session's own End clears it"
    $cU = Get-RC $CMD_UPDATESESSIONDISPLAY "Warn5" '{"baySessionId":"s-a","playEndUtc":"2026-10-09T13:30:00Z"}' $recA
    Assert-True ($cU.Change -and (Get-KioskProp $cU.Record "endUtc" "") -eq "2026-10-09T13:30:00Z" -and (Get-KioskProp $cU.Record "baySessionId" "") -eq "s-a") "record: an extension of the recorded session moves its end later"
    Assert-True (-not (Get-RC $CMD_UPDATESESSIONDISPLAY "Warn5" '{"baySessionId":"s-a","playEndUtc":"2026-10-09T12:30:00Z"}' $recA).Change) "record: an earlier end never shortens it"
    Assert-True (-not (Get-RC $CMD_UPDATESESSIONDISPLAY "Warn5" '{"baySessionId":"s-z","playEndUtc":"2026-10-09T15:30:00Z"}' $recA).Change) "record: another session's display update never moves it"
    Assert-True (-not (Get-RC $CMD_RESET "" '{"baySessionId":"s-a"}' $recA).Change -and -not (Get-RC $CMD_EMERGENCY_STOP "" '{"action":"engage"}' $recA).Change) "record: Reset (cleared only through the gate) and the emergency stop never change it here"
    # Through the handlers: an extension display moves the record; an e-stop Start refusal does not create one.
    [void](Execute-Command -CommandType $CMD_STARTSESSION -PayloadJson (New-Payload "Start" "s-ext") -BayLabel "Bay")
    $lat = (Get-Date).ToUniversalTime().AddMinutes(95).ToString("yyyy-MM-ddTHH:mm:ssZ")
    [void](Execute-Command -CommandType $CMD_UPDATESESSIONDISPLAY -PayloadJson ('{"mode":"Warn5","baySessionId":"s-ext","playEndUtc":"' + $lat + '"}') -BayLabel "Bay")
    Assert-True ([string](Get-KioskProp $Global:RunningSession "endUtc" "") -eq $lat) "record: UpdateSessionDisplay through the handler extends the recorded end"
    [void](Execute-Command -CommandType $CMD_ENDSESSION -PayloadJson (New-Payload "End" "s-ext") -BayLabel "Bay")
    [void](Execute-Command -CommandType $CMD_EMERGENCY_STOP -PayloadJson '{"action":"engage","reason":"t"}' -BayLabel "Bay")
    [void](Execute-Command -CommandType $CMD_STARTSESSION -PayloadJson (New-Payload "Start" "s-blocked") -BayLabel "Bay")
    Assert-True ((Get-RecSid) -eq "s-blocked") "record: a Start refused by an engaged emergency stop is still recorded (round 2, RV3: it is the bay's running booking)"
    [void](Execute-Command -CommandType $CMD_EMERGENCY_STOP -PayloadJson '{"action":"clear"}' -BayLabel "Bay")

    # Persistence: the file carries the record across a restart; a failed write keeps memory authoritative and lands later.
    [void](Execute-Command -CommandType $CMD_STARTSESSION -PayloadJson (New-Payload "Start" "s-file") -BayLabel "Bay")
    $rf = Read-KioskJsonFile -Path $RunningSessionPath
    Assert-True ($rf.Ok -and (Get-KioskProp $rf.Obj "running" $null) -eq $true -and (Get-KioskProp $rf.Obj "baySessionId" "") -eq "s-file") "persist: Start wrote state\running-session.json (running, s-file)"
    $Global:RunningSession = $null
    Initialize-RunningSession -NowUtc ((Get-Date).ToUniversalTime())
    Assert-True ((Get-RecSid) -eq "s-file") "restart: the record is read back from the file"
    $lockR = New-Object IO.FileStream($RunningSessionPath, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
    try {
        [void](Execute-Command -CommandType $CMD_STARTSESSION -PayloadJson (New-Payload "Start" "s-file2") -BayLabel "Bay")
        Assert-True ((Get-RecSid) -eq "s-file2" -and $Global:RunningSessionPending) "persist: the file held open, the write fails: memory still names s-file2 (the gate's authority) and the write is pending"
        Assert-True ((Invoke-CancelReset "").Skipped) "persist: while pending, another booking's Reset still holds"
        Assert-True (-not (Sync-RunningSessionFile)) "persist: still held, the retry cannot land"
    } finally { $lockR.Dispose() }
    Release-IntentLock
    Assert-True (-not $Global:RunningSessionPending -and (Get-KioskProp (Read-KioskJsonFile -Path $RunningSessionPath).Obj "baySessionId" "") -eq "s-file2") "persist: released, the next main-loop pass lands it"
    [void](Execute-Command -CommandType $CMD_ENDSESSION -PayloadJson (New-Payload "End" "s-file2") -BayLabel "Bay")
    $rf = Read-KioskJsonFile -Path $RunningSessionPath
    Assert-True ($rf.Ok -and (Get-KioskProp $rf.Obj "running" $null) -eq $false) "persist: the End wrote running=false"
    $Global:RunningSession = New-Rec "s-stale" $fut
    Initialize-RunningSession -NowUtc ((Get-Date).ToUniversalTime())
    Assert-True ((Get-RecSid) -eq "<none>") "restart: a file saying running=false wins over memory"
    # The file wins over session.json both ways (session.json is what Prep, a late End and the e-stop rewrite).
    $endK = (Get-Date).ToUniversalTime().AddMinutes(40).ToString("yyyy-MM-ddTHH:mm:ssZ")
    Set-TestFile $RunningSessionPath ('{"schema":1,"running":true,"baySessionId":"s-keep","endUtc":"' + $endK + '","since":"2026-10-09T12:00:00Z"}')
    Set-TestFile $sessPath ('{"status":"PREP","baySessionId":"s-next","sessionEndUtc":"' + $endK + '"}')
    $Global:RunningSession = $null; Initialize-RunningSession -NowUtc ((Get-Date).ToUniversalTime())
    Assert-True ((Get-RecSid) -eq "s-keep") "restart during the next booking's Prep: the file's running s-keep is kept (session.json says PREP/s-next)"
    Set-TestFile $RunningSessionPath '{"schema":1,"running":false,"baySessionId":null,"endUtc":null}'
    Set-TestFile $sessPath ('{"status":"ACTIVE","baySessionId":"s-wall","sessionEndUtc":"' + $endK + '"}')
    $Global:RunningSession = $null; Initialize-RunningSession -NowUtc ((Get-Date).ToUniversalTime())
    Assert-True ((Get-RecSid) -eq "<none>") "restart: the file's running=false is kept even when session.json still says ACTIVE"
    # Absent or unreadable file: derived once from session.json.
    $endSoon = (Get-Date).ToUniversalTime().AddMinutes(20).ToString("yyyy-MM-ddTHH:mm:ssZ"); $endGone = (Get-Date).ToUniversalTime().AddMinutes(-20).ToString("yyyy-MM-ddTHH:mm:ssZ")
    $deriv = @(
        @{ F = $null; S = '{"status":"ACTIVE","baySessionId":"s-d1","sessionEndUtc":"' + $endSoon + '"}'; W = "s-d1"; Why = "no file, session.json ACTIVE" },
        @{ F = "{ garbage"; S = '{"status":"ENDING","baySessionId":"s-d2","sessionEndUtc":"' + $endSoon + '"}'; W = "s-d2"; Why = "an unreadable file, session.json ENDING" },
        @{ F = '{"schema":1,"running":"yes","baySessionId":"s-x"}'; S = '{"status":"STOP","baySessionId":"s-d3","sessionEndUtc":"' + $endSoon + '"}'; W = "s-d3"; Why = "a malformed file, session.json STOP with its end ahead" },
        @{ F = $null; S = '{"status":"STOP","baySessionId":"s-d4","sessionEndUtc":"' + $endGone + '"}'; W = "<none>"; Why = "no file, session.json STOP with its end behind" },
        @{ F = $null; S = '{"status":"PREP","baySessionId":"s-d5","sessionEndUtc":"' + $endSoon + '"}'; W = "<none>"; Why = "no file, session.json PREP" },
        @{ F = $null; S = '{"status":"ACTIVE","sessionEndUtc":"' + $endSoon + '"}'; W = "<none>"; Why = "no file, session.json ACTIVE with no id" }
    )
    foreach ($d in $deriv) {
        if ($null -eq $d.F) { Remove-Item -LiteralPath $RunningSessionPath -Force -ErrorAction SilentlyContinue } else { Set-TestFile $RunningSessionPath $d.F }
        Set-TestFile $sessPath $d.S
        $Global:RunningSession = $null
        Initialize-RunningSession -NowUtc ((Get-Date).ToUniversalTime())
        Assert-True ((Get-RecSid) -eq $d.W -and (Read-KioskJsonFile -Path $RunningSessionPath).Ok) ("restart: {0}: record {1}, and the file is written" -f $d.Why, $d.W)
    }
    $Global:RunningSession = $null; Remove-Item -LiteralPath $RunningSessionPath -Force -ErrorAction SilentlyContinue

    # Process-Command: a refused Reset is closed out as Skipped while Pending (no execution fields: the guard plugin's only
    # allowed shape); if that write fails it runs, the gate skips it, and the row says Succeeded with skipped in the result.
    . ([scriptblock]::Create((Get-DefText $AgentDefs "Process-Command")))
    . ([scriptblock]::Create((Get-DefText $AgentDefs "Is-CommandAllowedInMode")))
    $BayCommandEntitySet = "build_baycommands"
    function Get-BayLabelFromCommandRow { param($cmdRow) return "Bay" }
    function Limit-ResultJson { param($ResultObj) return (ConvertTo-Json -InputObject $ResultObj -Depth 6 -Compress) }
    $script:Patches = New-Object System.Collections.ArrayList
    $script:FailSkip = $false
    function Patch-Row { param($token, $entitySet, $id, $bodyObj, $ifMatch)
        [void]$script:Patches.Add(@{ Body = $bodyObj; IfMatch = $ifMatch })
        if ($script:FailSkip -and $bodyObj[$Col_Status] -eq $STATUS_SKIPPED) { throw "simulated guard refusal" }
    }
    function New-ResetRow([string]$bound) {
        $row = [ordered]@{ "@odata.etag" = 'W/"1"' }
        $row[$Col_CommandId] = "c0ffee00-0000-0000-0000-000000000001"; $row[$Col_CommandType] = $CMD_RESET; $row[$Col_AttemptCount] = 0
        $row[$Col_Payload] = '{"mode":"Full","reason":"BookingCanceled"}'
        if ($bound) { $row[$Lookup_BaySessionValue] = $bound }
        return [pscustomobject]$row
    }
    [void](Execute-Command -CommandType $CMD_STARTSESSION -PayloadJson (New-Payload "Start" "s-pc") -BayLabel "Bay")
    $wallPc = [IO.File]::ReadAllText($sessPath)
    $script:Patches.Clear(); Process-Command -token "t" -cmd (New-ResetRow "s-other")
    $p0 = $(if ($script:Patches.Count -gt 0) { $script:Patches[0] } else { @{ Body = @{}; IfMatch = "" } })
    Assert-True ($script:Patches.Count -eq 1 -and @($p0.Body.Keys).Count -eq 1 -and $p0.Body[$Col_Status] -eq 100000005 -and $p0.IfMatch -eq 'W/"1"') "Process-Command: another booking's Reset while s-pc plays: ONE write, status Skipped only, under the row's etag (no lock, no execution fields)"
    Assert-True ([IO.File]::ReadAllText($sessPath) -ceq $wallPc) "...and the wall is untouched"
    $script:FailSkip = $true; $script:Patches.Clear(); Process-Command -token "t" -cmd (New-ResetRow "s-other"); $script:FailSkip = $false
    $last = $(if ($script:Patches.Count -gt 0) { $script:Patches[$script:Patches.Count - 1] } else { @{ Body = @{}; IfMatch = "" } })
    Assert-True ($script:Patches.Count -eq 3 -and $script:Patches[1].Body[$Col_Status] -eq $STATUS_INPROGRESS -and $last.Body[$Col_Status] -eq $STATUS_SUCCEEDED -and [string]$last.Body[$Col_Result] -match '"skipped":true') "Process-Command: the Skipped write refused: it runs, the gate skips it, Succeeded with skipped in the result (never left Pending)"
    Assert-True ([IO.File]::ReadAllText($sessPath) -ceq $wallPc) "...and the wall is still untouched"
    $script:Patches.Clear(); Process-Command -token "t" -cmd (New-ResetRow "s-pc")
    $last = $(if ($script:Patches.Count -gt 0) { $script:Patches[$script:Patches.Count - 1] } else { @{ Body = @{}; IfMatch = "" } })
    Assert-True ($last.Body[$Col_Status] -eq $STATUS_SUCCEEDED -and [string]$last.Body[$Col_Result] -match '"cancelWarning"' -and (Get-SessStatus) -eq "ENDING/s-pc" -and (Get-RecSid) -eq "s-pc") "Process-Command: the Reset bound (row lookup) to the running s-pc: runs, starts its warning (ENDING; A0.467)"
    [void](Invoke-CancelEndIfDue -NowUtc ((Get-Date).ToUniversalTime().AddMinutes(6)))
    Assert-True ((Get-RecSid) -eq "<none>") "...and its End after the warning clears the record"
    $script:Patches.Clear(); Process-Command -token "t" -cmd (New-ResetRow "")
    Assert-True ($script:Patches.Count -eq 2 -and $script:Patches[1].Body[$Col_Status] -eq $STATUS_SUCCEEDED) "Process-Command: nobody plays: a Reset runs as before (lock, then Succeeded)"

    # The poll reads the row's bound session (without it every platform Reset names no session).
    . ([scriptblock]::Create((Get-DefText $AgentDefs "Get-NextPendingCommand")))
    $OrgUrl = "https://example.invalid"
    $script:PollUri = ""
    function New-DvHeaders { param($t, $m) return @{} }
    function Invoke-DvSafe { param($Method, $Uri, $Headers, $BodyJson) $script:PollUri = $Uri; return [pscustomobject]@{ value = @() } }
    [void](Get-NextPendingCommand -token "t")
    $selPart = $(if ($script:PollUri -match '\$select=([^&]+)') { $Matches[1] } else { "" })
    Assert-True (@($selPart -split ',') -contains "_build_baysession_value") "the command poll selects _build_baysession_value (got: $selPart)"

    # ============================================================ K21 (kiosk round 2, 2026-10-09)
    # A0.467 (a booking canceled mid-play: a 5-minute warning, then a normal End), F1-R2/X3b (a second End of an ended
    # session), F1-R3 (an on-time End after the next Prep), F1-R1 (A0.360 after a Prep or a cancel Reset), RV1 to RV4.
    # Through the real Execute-Command (Process-Command where the row matters) with the real emergency stop, judged by the
    # shell's own decision functions. Each scenario FAILS on 4c8851ac (this file with -AgentScript/-ShellScript of it).
    Section "K21 round 2: a canceled booking is warned then ended; a stale End never ends a paying game; no free play after an End"
    $script:Fac = @()
    function Invoke-FacilitySetMode { param([string]$Mode, $payloadObj) $script:Fac += $Mode; return @{ ok = $true; scene = $Mode } }
    function Start-SessionDisplay($payloadObj) { return @{ started = $false; reason = "stub" } }
    function Stop-SessionDisplay { return @{ stopped = $false; reason = "stub" } }
    function Get-Sess { try { return ([IO.File]::ReadAllText($sessPath) | ConvertFrom-Json) } catch { return $null } }
    function Get-RecCancel { if ($null -eq $Global:RunningSession) { return $null }; return (Get-KioskProp $Global:RunningSession "cancelEndUtc" $null) }
    function Clear-Bay { $Global:RunningSession = $null; $Global:RunningSessionPending = $false; $Global:RunningSessionFinished = @(); $Global:RunningSessionEndPending = @(); $Global:RunningSessionOwnEnd = $false; Remove-Item -LiteralPath $RunningSessionPath -Force -ErrorAction SilentlyContinue; $Global:EmergencyStopEngaged = $false }
    function Invoke-Start([string]$sid, [string]$mode = "Start") { return (Execute-Command -CommandType $CMD_STARTSESSION -PayloadJson (New-Payload $mode $sid) -BayLabel "Bay") }
    function Invoke-End([string]$sid) { return (Execute-Command -CommandType $CMD_ENDSESSION -PayloadJson (New-Payload "End" $sid) -BayLabel "Bay") }
    function Invoke-BoundReset([string]$bound) { try { return (Execute-Command -CommandType $CMD_RESET -PayloadJson $resetJson -BayLabel "Bay" -BoundSessionId $bound) } catch { return $null } }
    function Lock-Intent { return (New-Object IO.FileStream($KioskIntentPath, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)) }
    function Get-Stamp { return (Get-PropValue (Get-Sess) "agentRunning" $null) }
    function Get-EndsOf($r) { return (ConvertTo-KioskUtc (Get-PropValue (Get-PropValue $r "cancelWarning" $null) "endsUtc" $null)) }
    $fmtZ = "yyyy-MM-ddTHH:mm:ssZ"
    Clear-Bay

    # ---- A0.467: the RUNNING booking is canceled mid-play (the platform cancels its Warn5 and End and sends a Reset bound to it).
    $t0 = (Get-Date).ToUniversalTime()
    [void](Invoke-Start "s-c1")
    $script:Fac = @(); $script:ControlWarnings.Clear()
    $rc = Invoke-BoundReset "s-c1"
    $ends = Get-EndsOf $rc
    Assert-True ((Get-PropValue $rc "reset" $null) -eq $false -and $null -ne $ends -and [Math]::Abs(($ends - $t0.AddMinutes(5)).TotalSeconds) -le 15) "A0.467 the cancel Reset of the running s-c1 is not a reset: a warning that ends 5 minutes from now"
    $s = Get-Sess
    Assert-True ((Get-PropValue $s "status" "") -eq "ENDING" -and (Get-PropValue $s "baySessionId" "") -eq "s-c1" -and $null -ne $ends -and (ConvertTo-KioskUtc (Get-PropValue $s "playEndUtc" $null)) -eq $ends -and (Get-PropValue $s "bannerText" "") -eq "Booking canceled") "A0.467 the wall shows the warning: ENDING for s-c1, its countdown to the new end, a 'Booking canceled' banner"
    $cwText = $(if ($script:ControlWarnings.Count -gt 0) { [string]$script:ControlWarnings[0].Text } else { "" })
    $cwSecs = $(if ($script:ControlWarnings.Count -gt 0) { [int]$script:ControlWarnings[0].Seconds } else { 0 })
    Assert-True ($script:ControlWarnings.Count -eq 1 -and $cwText -match "canceled" -and $cwText -match "5 minutes" -and $cwSecs -ge 285 -and $cwSecs -le 300) "A0.467 the control screen (the launcher's screen) shows the warning once, for its 5 minutes (got: $cwText / $cwSecs s)"
    Assert-True ($script:Fac -contains "Warning") "A0.467 the facility moves to its Warning scene"
    $wi = Get-IntentNow
    Assert-True ($wi.Wanted -and $wi.SessionId -eq "s-c1" -and $null -ne $ends -and $wi.UntilUtc -eq $ends.AddSeconds(120)) "A0.467 the game keeps running: the launcher stays wanted for s-c1, but only until the warning ends (plus the 2-minute grace)"
    $bk = Get-KioskSessionBacksWanted -SessionRead (Read-KioskJsonFile -Path $sessPath -MaxBytes 262144) -WantedSessionId "s-c1"
    Assert-True ($bk.Backed -and (Get-ShellVerdictNow) -ne "close") "A0.467 during the warning the shell keeps the game (session.json backs a restart; nothing is closed)"
    Assert-True ((Get-RecSid) -eq "s-c1" -and $null -ne $ends -and (ConvertTo-KioskUtc (Get-RecCancel)) -eq $ends) "A0.467 the running-session record keeps s-c1 and carries the warning's end"
    $rfC = Read-KioskJsonFile -Path $RunningSessionPath
    Assert-True ($rfC.Ok -and $null -ne $ends -and (ConvertTo-KioskUtc (Get-KioskProp $rfC.Obj "cancelEndUtc" $null)) -eq $ends) "A0.467 ...and so does the record file (a restart keeps the warning)"
    $stC = Get-Stamp
    Assert-True ((Get-PropValue $stC "running" $null) -eq $true -and (Get-PropValue $stC "baySessionId" "") -eq "s-c1") "A0.467 the wall's stamp says s-c1 still plays"
    $script:ControlWarnings.Clear()
    $rc2 = Invoke-BoundReset "s-c1"
    Assert-True ($null -ne $ends -and (ConvertTo-KioskUtc (Get-RecCancel)) -eq $ends -and $script:ControlWarnings.Count -eq 0 -and (Get-PropValue (Get-PropValue $rc2 "cancelWarning" $null) "duplicate" $null) -eq $true) "A0.467 a redelivered cancel Reset keeps the first end and warns only once"
    $x = Invoke-CancelReset "s-other"
    Assert-True ($x.Skipped -and $x.WallSame) "A0.467 another booking's Reset during the warning: held, the warning wall untouched"
    $early = Invoke-CancelEndIfDue -NowUtc $t0.AddMinutes(4)
    Assert-True ($null -eq $early -and (Get-RecSid) -eq "s-c1" -and (Get-PropValue (Get-Sess) "status" "") -eq "ENDING") "A0.467 4 minutes in: nothing ends yet"
    $agentText = [IO.File]::ReadAllText($AgentScript)
    $iLoop = $agentText.IndexOf("# ---------------- Main Loop")
    $iDue = $(if ($iLoop -ge 0) { $agentText.IndexOf("Invoke-CancelEndIfDue -NowUtc", $iLoop) } else { -1 })
    $iTok = $(if ($iLoop -ge 0) { $agentText.IndexOf("Get-AccessToken", $iLoop) } else { -1 })
    Assert-True ($iLoop -gt 0 -and $iDue -gt $iLoop -and $iDue -lt $iTok) "A0.467 the main loop runs the due check every pass, before the token (no network needed)"
    $script:Fac = @()
    $endRes = $(if ($null -ne $ends) { Invoke-CancelEndIfDue -NowUtc $ends.AddSeconds(1) } else { $null })
    $s = Get-Sess; $wE = Get-IntentNow
    Assert-True ((Get-PropValue $s "status" "") -eq "ENDED" -and (Get-PropValue $s "baySessionId" "") -eq "s-c1" -and $wE.Closed -and $wE.SessionId -eq "s-c1" -and (Get-RecSid) -eq "<none>" -and $script:Fac -contains "Cleanup") "A0.467 when the warning is over: a normal End (wall ENDED, intent closed, record cleared, facility Cleanup)"
    Assert-True ((Get-PropValue $endRes "scope" "") -eq "running") "A0.467 ...through the same End handler, as the running session"
    Assert-True ((Get-ShellVerdictNow) -eq "close") "A0.467 a launcher relaunched after that end is closed by the shell: a canceled booking never becomes free play"
    $wallC = [IO.File]::ReadAllText($sessPath)
    $rr = Invoke-Start "s-c1"
    Assert-True ((Get-PropValue $rr "skipped" $null) -eq $true -and (Get-RecSid) -eq "<none>" -and [IO.File]::ReadAllText($sessPath) -ceq $wallC -and (Get-IntentNow).Closed) "A0.467/RV1 a replayed Start of the canceled booking after its end: refused, nothing touched"
    # Only 2 minutes left in the booking: it ends at its own end, not 3 minutes later.
    Clear-Bay
    $e2 = (Get-Date).ToUniversalTime().AddMinutes(2).ToString($fmtZ)
    [void](Execute-Command -CommandType $CMD_STARTSESSION -PayloadJson ('{"mode":"Start","baySessionId":"s-c2","startUtc":"2026-10-08T12:00:00Z","playEndUtc":"' + $e2 + '","endUtc":"' + $e2 + '","closeLauncher":false}') -BayLabel "Bay")
    $rc = Invoke-BoundReset "s-c2"
    Assert-True ((Get-EndsOf $rc) -eq (ConvertTo-KioskUtc $e2)) "A0.467 with 2 minutes left, the canceled booking ends at its own end (never plays longer than it would have)"
    [void](Invoke-CancelEndIfDue -NowUtc ((Get-Date).ToUniversalTime().AddMinutes(3)))
    # The booking's own end already passed (its End was canceled before it ran): it ends now.
    Clear-Bay
    $ePast = (Get-Date).ToUniversalTime().AddMinutes(-1).ToString($fmtZ)
    [void](Execute-Command -CommandType $CMD_STARTSESSION -PayloadJson ('{"mode":"Start","baySessionId":"s-c3","startUtc":"2026-10-08T12:00:00Z","playEndUtc":"' + $ePast + '","endUtc":"' + $ePast + '","closeLauncher":false}') -BayLabel "Bay")
    $rc = Invoke-BoundReset "s-c3"
    Assert-True ((Get-PropValue (Get-PropValue $rc "cancelWarning" $null) "endedNow" $null) -eq $true -and (Get-SessStatus) -eq "ENDED/s-c3" -and (Get-RecSid) -eq "<none>" -and (Get-IntentNow).Closed) "A0.467 with the booking's own end already past, the cancel ends it now"
    # An agent restart during the warning keeps it.
    Clear-Bay
    [void](Invoke-Start "s-c4")
    $ends4 = Get-EndsOf (Invoke-BoundReset "s-c4")
    $Global:RunningSession = $null
    Initialize-RunningSession -NowUtc ((Get-Date).ToUniversalTime())
    Assert-True ((Get-RecSid) -eq "s-c4" -and $null -ne $ends4 -and (ConvertTo-KioskUtc (Get-RecCancel)) -eq $ends4) "A0.467 an agent restart during the warning keeps it (record and end read back)"
    if ($null -ne $ends4) { [void](Invoke-CancelEndIfDue -NowUtc $ends4.AddSeconds(1)) }
    Assert-True ((Get-SessStatus) -eq "ENDED/s-c4" -and (Get-RecSid) -eq "<none>") "A0.467 ...and still ends it on time"
    # The next booking's Start during the warning takes the bay: the canceled booking's end does nothing to it.
    Clear-Bay
    [void](Invoke-Start "s-c5")
    $ends5 = Get-EndsOf (Invoke-BoundReset "s-c5")
    [void](Invoke-Start "s-n5")
    $r5 = $(if ($null -ne $ends5) { Invoke-CancelEndIfDue -NowUtc $ends5.AddSeconds(1) } else { "no warning" })
    Assert-True ($null -eq $r5 -and (Get-RecSid) -eq "s-n5" -and (Get-SessStatus) -eq "ACTIVE/s-n5" -and (Get-IntentNow).Wanted) "A0.467 the next booking's Start during the warning takes over; the canceled booking's end does not touch it"
    [void](Invoke-End "s-n5")
    # Canceled after the next booking's Prep already rewrote the wall: the warning is the canceled booking's own.
    Clear-Bay
    [void](Invoke-Start "s-c9"); [void](Invoke-Start "s-n9" "Prep")
    $ends9 = Get-EndsOf (Invoke-BoundReset "s-c9")
    Assert-True ($null -ne $ends9 -and (Get-SessStatus) -eq "ENDING/s-c9" -and (ConvertTo-KioskUtc (Get-PropValue (Get-Sess) "playEndUtc" $null)) -eq $ends9) "A0.467 canceled after the next booking's Prep rewrote the wall: the warning shows s-c9's own countdown (ENDING/s-c9), not s-n9's Prep"
    if ($null -ne $ends9) { [void](Invoke-CancelEndIfDue -NowUtc $ends9.AddSeconds(1)) }
    # Pure: the warning's end, the record across a replayed Start or an extension, the intent cut.
    $nC = [DateTime]::SpecifyKind([DateTime]::Parse("2026-10-09T12:00:00"), [DateTimeKind]::Utc)
    Assert-True ((Get-CancelEndUtc -NowUtc $nC -RecordEndUtc $nC.AddHours(1) -WarningSeconds 300) -eq $nC.AddMinutes(5)) "A0.467 end: 5 minutes from now when the booking runs longer"
    Assert-True ((Get-CancelEndUtc -NowUtc $nC -RecordEndUtc $nC.AddMinutes(2) -WarningSeconds 300) -eq $nC.AddMinutes(2)) "A0.467 end: the booking's own end when that is sooner"
    Assert-True ((Get-CancelEndUtc -NowUtc $nC -RecordEndUtc $nC.AddMinutes(-3) -WarningSeconds 300) -eq $nC) "A0.467 end: now when the booking's end has passed"
    Assert-True ((Get-CancelEndUtc -NowUtc $nC -RecordEndUtc $null -WarningSeconds 300) -eq $nC.AddMinutes(5)) "A0.467 end: 5 minutes when the booking's end is unreadable"
    $recC = [ordered]@{ baySessionId = "s-a"; endUtc = "2026-10-09T13:00:00Z"; since = "2026-10-09T11:00:00Z"; cancelEndUtc = "2026-10-09T12:05:00Z" }
    $cS2 = Get-RunningSessionForCommand -CommandType $CMD_STARTSESSION -Mode "Start" -Payload ('{"baySessionId":"s-a","playEndUtc":"2026-10-09T13:00:00Z"}' | ConvertFrom-Json) -Current $recC -NowUtc $nC
    Assert-True ((Get-KioskProp $cS2.Record "cancelEndUtc" $null) -eq "2026-10-09T12:05:00Z") "A0.467 a replayed Start of the SAME canceled booking during its warning keeps the warning's end"
    $cS3 = Get-RunningSessionForCommand -CommandType $CMD_STARTSESSION -Mode "Start" -Payload ('{"baySessionId":"s-b","playEndUtc":"2026-10-09T14:00:00Z"}' | ConvertFrom-Json) -Current $recC -NowUtc $nC
    Assert-True ($null -eq (Get-KioskProp $cS3.Record "cancelEndUtc" $null)) "A0.467 ...the next booking's Start does not inherit it"
    $cU2 = Get-RunningSessionForCommand -CommandType $CMD_UPDATESESSIONDISPLAY -Mode "Warn5" -Payload ('{"baySessionId":"s-a","playEndUtc":"2026-10-09T13:30:00Z"}' | ConvertFrom-Json) -Current $recC -NowUtc $nC
    Assert-True ((Get-KioskProp $cU2.Record "cancelEndUtc" $null) -eq "2026-10-09T12:05:00Z") "A0.467 ...and an extension display keeps it too"
    function New-IntentRead($l, $until, $sid) { return @{ Ok = $true; Why = ""; Obj = ([pscustomobject]@{ schema = 1; launcher = $l; untilUtc = $until; baySessionId = $sid; writtenUtc = $nC.ToString($fmtZ) }) } }
    $cw5 = [pscustomobject]@{ baySessionId = "s-a"; playEndUtc = $nC.AddMinutes(5).ToString($fmtZ) }
    $ki = Get-KioskIntentForCommand -CommandType $CMD_RESET -Mode "cancel-warning" -Payload $cw5 -CurrentIntentRead (New-IntentRead "wanted" $nC.AddHours(1).ToString($fmtZ) "s-a") -SameSession $true -EmergencyStopEngaged $false -NowUtc $nC
    Assert-True ($null -ne $ki -and $ki.Launcher -eq "wanted" -and $ki.UntilUtc -eq $nC.AddMinutes(7) -and $ki.SessionId -eq "s-a") "A0.467 intent: a wanted s-a is cut to the warning's end plus the grace"
    Assert-True ($null -eq (Get-KioskIntentForCommand -CommandType $CMD_RESET -Mode "cancel-warning" -Payload $cw5 -CurrentIntentRead (New-IntentRead "wanted" $nC.AddHours(1).ToString($fmtZ) "s-b") -SameSession $true -EmergencyStopEngaged $false -NowUtc $nC)) "A0.467 intent: never another session's"
    Assert-True ($null -eq (Get-KioskIntentForCommand -CommandType $CMD_RESET -Mode "cancel-warning" -Payload $cw5 -CurrentIntentRead (New-IntentRead "wanted" $nC.AddMinutes(4).ToString($fmtZ) "s-a") -SameSession $true -EmergencyStopEngaged $false -NowUtc $nC)) "A0.467 intent: never extended (a sooner until is kept)"
    Assert-True ($null -eq (Get-KioskIntentForCommand -CommandType $CMD_RESET -Mode "cancel-warning" -Payload $cw5 -CurrentIntentRead (New-IntentRead "closed" $null "s-a") -SameSession $true -EmergencyStopEngaged $false -NowUtc $nC)) "A0.467 intent: a closed intent is never made wanted"
    Assert-True ($null -eq (Get-KioskIntentForCommand -CommandType $CMD_RESET -Mode "" -Payload $cw5 -CurrentIntentRead (New-IntentRead "wanted" $nC.AddHours(1).ToString($fmtZ) "s-a") -SameSession $true -EmergencyStopEngaged $false -NowUtc $nC)) "A0.467 intent: a plain Reset still never touches it"
    $wt5 = Get-CancelWarningText -EndsUtc $nC.AddMinutes(5) -NowUtc $nC
    $wt1 = Get-CancelWarningText -EndsUtc $nC.AddSeconds(30) -NowUtc $nC
    Assert-True ([string]$wt5 -match "^This booking was canceled\. Play ends in 5 minutes, at " -and [string]$wt1 -match "in 1 minute, at " -and [string]$wt5 -notmatch '["&|<>]') "A0.467 the control-screen text (got: $wt5)"
    if (Get-Command Test-RealSendControlScreenWarning -ErrorAction SilentlyContinue) {
        $script:MsgStarts = New-Object System.Collections.ArrayList
        $sw = Test-RealSendControlScreenWarning -Text 'This booking was canceled. Play ends in 5 minutes, at 7:42 PM. "x" & y' -Seconds 300 -Starter { param($f, $a) [void]$script:MsgStarts.Add(@($f, $a)); return @{ pid = 4321; exitCode = 0 } }
        $ownSess = [System.Diagnostics.Process]::GetCurrentProcess().SessionId
        $wantArgs = ('{0} /TIME:300 "This booking was canceled. Play ends in 5 minutes, at 7:42 PM. x  y"' -f $ownSess)
        $gotArgs = $(if ($script:MsgStarts.Count -gt 0) { [string]$script:MsgStarts[0][1] } else { "" })
        Assert-True ($sw["shown"] -eq $true -and $sw["pid"] -eq 4321 -and $script:MsgStarts.Count -eq 1 -and [string]$script:MsgStarts[0][0] -like "*\System32\msg.exe" -and $gotArgs -ceq $wantArgs) "A0.467 the real control-screen sender: msg.exe to this desktop session, for the warning's seconds, only safe characters on its command line (got: $gotArgs)"
        # Item 5 (2026-10-10): "shown" is the sender's exit code, not the fact that a process started.
        $swX = Test-RealSendControlScreenWarning -Text "t" -Seconds 30 -Starter { param($f, $a) return @{ pid = 11; exitCode = 1 } }
        Assert-True ($swX["shown"] -eq $false -and $swX["exitCode"] -eq 1 -and [string]$swX["why"] -match "exited with code 1") "item 5 msg.exe exiting 1: shown is false and the result says the code (it read true once the process started)"
        $swN = Test-RealSendControlScreenWarning -Text "t" -Seconds 30 -Starter { param($f, $a) return @{ pid = 12; exitCode = $null } }
        Assert-True ($swN["shown"] -eq $false -and $null -eq $swN["exitCode"] -and [string]$swN["why"] -match "no exit code") "item 5 a starter that got no exit code (msg.exe still running, or unreadable): not confirmed, shown is false"
        $swL = Test-RealSendControlScreenWarning -Text "t" -Seconds 30 -Starter { param($f, $a) return 4321 }
        Assert-True ($swL["shown"] -eq $false) "item 5 a starter that returns only a process id (no exit code): shown is false"
        $swOk = Test-RealSendControlScreenWarning -Text "t" -Seconds 30 -Starter { param($f, $a) return @{ pid = 13; exitCode = 0 } }
        Assert-True ($swOk["shown"] -eq $true -and $swOk["exitCode"] -eq 0) "item 5 msg.exe exiting 0: shown is true"
        $swF = $null; try { $swF = Test-RealSendControlScreenWarning -Text "t" -Seconds 0 -Starter { param($f, $a) throw "no desktop" } } catch { $swF = $null }
        Assert-True ($null -ne $swF -and $swF["shown"] -eq $false -and [string]$swF["why"] -match "no desktop") "A0.467 a sender that fails is reported, never thrown"
    } else { Assert-True $false "A0.467 the real control-screen sender exists" }

    # ---- F1-R2 / X3b: a SECOND End of an ended session S arrives while T plays and T's intent write keeps failing.
    Clear-Bay
    [void](Invoke-Start "s-S"); [void](Invoke-End "s-S")
    $lockY = Lock-Intent
    try {
        [void](Invoke-Start "s-T")
        $wallT = [IO.File]::ReadAllText($sessPath); $script:Fac = @()
        $r2 = $null; try { $r2 = Invoke-End "s-S" } catch { $r2 = $null }
        Assert-True ((Get-SessStatus) -eq "ACTIVE/s-T" -and [IO.File]::ReadAllText($sessPath) -ceq $wallT -and $script:Fac.Count -eq 0) "X3b a second End of the ended s-S while s-T plays: the wall and the facility are left alone (it wrote ENDED/s-S before)"
        Assert-True ((Get-ShellVerdictNow) -eq "held") "X3b the shell's verdict on s-T's running launcher: held (the attack measured close)"
        Assert-True ((Get-PropValue $r2 "skipped" $null) -eq $true -and (Get-RecSid) -eq "s-T") "X3b ...that End was refused as a duplicate (s-S already ended here) and s-T still plays"
    } finally { $lockY.Dispose() }
    Release-IntentLock
    [void](Invoke-End "s-T")
    # The same with the ended-session list lost (a restart with an older record file): the record alone protects T2.
    [void](Invoke-Start "s-S2"); [void](Invoke-End "s-S2")
    $lockY = Lock-Intent
    try {
        [void](Invoke-Start "s-T2")
        $Global:RunningSessionFinished = @()
        $wallT2 = [IO.File]::ReadAllText($sessPath)
        $r2b = $null; try { $r2b = Invoke-End "s-S2" } catch { $r2b = $null }
        Assert-True ((Get-PropValue $r2b "scope" "") -eq "other" -and [IO.File]::ReadAllText($sessPath) -ceq $wallT2 -and (Get-ShellVerdictNow) -eq "held") "X3b with no ended-session list, the record decides: the End of s-S2 while s-T2 plays leaves the wall alone, and the shell holds"
    } finally { $lockY.Dispose() }
    Release-IntentLock
    [void](Invoke-End "s-T2")
    # A late End of a booking that never played here, and an End naming no session, while s-T3 plays: nothing touched.
    [void](Invoke-Start "s-T3")
    $wallT3 = [IO.File]::ReadAllText($sessPath); $script:Fac = @()
    $rU = Invoke-End "s-U3"
    $rN = Execute-Command -CommandType $CMD_ENDSESSION -PayloadJson '{"mode":"End","closeLauncher":false}' -BayLabel "Bay"
    Assert-True ([IO.File]::ReadAllText($sessPath) -ceq $wallT3 -and $script:Fac.Count -eq 0 -and (Get-RecSid) -eq "s-T3" -and (Get-IntentNow).Wanted -and (Get-PropValue $rU "scope" "") -eq "other" -and (Get-PropValue $rN "scope" "") -eq "other") "an End of another booking, or naming no session, while s-T3 plays: wall, facility, record and intent untouched"
    $rU3 = Invoke-Start "s-U3"
    Assert-True ((Get-PropValue $rU3 "skipped" $null) -eq $true -and (Get-RecSid) -eq "s-T3") "RV1 a booking whose late End came while another played is listed as ended: a replayed Start of it is refused"
    [void](Invoke-End "s-T3")

    # ---- F1-R3: an ON-TIME End after the next booking's Prep (session.json moved to the next booking).
    Clear-Bay
    [void](Invoke-Start "s-A4"); [void](Invoke-Start "s-B4" "Prep")
    $r4 = Invoke-End "s-A4"
    $w4 = Get-IntentNow
    Assert-True ($w4.Closed -and $w4.SessionId -eq "s-A4" -and (Get-PropValue (Get-PropValue $r4 "launcherStopped" $null) "reason" "") -ne "late_old_session_skip" -and (Get-RecSid) -eq "<none>") "F1-R3 the on-time End of s-A4 after s-B4's Prep is A4's own End: intent closed, the launcher not skipped as 'late', record cleared"

    # ---- F1-R1: after an End, the next Prep or a cancel Reset on the idle bay must not open free play until the next Start.
    Assert-True ((Get-ShellVerdictNow) -eq "close") "F1-R1 (setup) after A4's End the shell closes a relaunched launcher (ENDED/s-A4)"
    [void](Invoke-Start "s-B5" "Prep")
    Assert-True ((Get-SessStatus) -eq "PREP/s-B5" -and (Get-ShellVerdictNow) -eq "close") "F1-R1 after the next booking's Prep (PREP/s-B5, nobody plays): a relaunched launcher is still closed (held before)"
    [void](Invoke-Start "s-B5"); [void](Invoke-End "s-B5")
    $x = Invoke-CancelReset ""
    Assert-True ($x.Reset -and (Get-SessStatus) -match "^READY" -and (Get-ShellVerdictNow) -eq "close") "F1-R1 after an End and a canceled booking's Reset on the idle bay (READY): a relaunched launcher is closed (held before: free play until the next Start)"
    [void](Execute-Command -CommandType $CMD_EMERGENCY_STOP -PayloadJson '{"action":"engage","reason":"t"}' -BayLabel "Bay")
    Assert-True ((Get-ShellVerdictNow) -eq "held") "F1-R1 an emergency stop on the idle bay (STOP): still held (A0.457: a stop never leads to a close; named residual)"
    [void](Execute-Command -CommandType $CMD_EMERGENCY_STOP -PayloadJson '{"action":"clear"}' -BayLabel "Bay")
    # Never on a paying game: a stale closed, s-T6 playing with its intent write failing, then the next Prep, a Reset of
    # another booking, an operator's force Reset and an emergency stop.
    Clear-Bay
    [void](Invoke-Start "s-P6"); [void](Invoke-End "s-P6")
    $lockY = Lock-Intent
    try {
        [void](Invoke-Start "s-T6")
        [void](Invoke-Start "s-N6" "Prep")
        Assert-True ((Get-SessStatus) -eq "PREP/s-N6" -and (Get-ShellVerdictNow) -eq "held") "F1-R1 never on a paying game: stale closed s-P6, s-T6 playing, the next Prep: held (the stamp says s-T6 plays)"
        [void](Invoke-CancelReset "s-other")
        Assert-True ((Get-ShellVerdictNow) -eq "held") "F1-R1 ...then another booking's Reset: held"
        [void](Execute-Command -CommandType $CMD_RESET -PayloadJson '{"mode":"Full","force":true}' -BayLabel "Bay")
        Assert-True ((Get-SessStatus) -match "^READY" -and (Get-ShellVerdictNow) -eq "held") "F1-R1 ...then an operator's force Reset (READY, but the stamp says s-T6 plays): held"
        [void](Execute-Command -CommandType $CMD_EMERGENCY_STOP -PayloadJson '{"action":"engage","reason":"t"}' -BayLabel "Bay")
        [void](Execute-Command -CommandType $CMD_EMERGENCY_STOP -PayloadJson '{"action":"clear"}' -BayLabel "Bay")
        Assert-True ((Get-ShellVerdictNow) -eq "held") "F1-R1 ...then an emergency stop and its clear: held"
    } finally { $lockY.Dispose() }
    Release-IntentLock
    [void](Invoke-End "s-T6")
    # The stamp itself, on every wall write.
    Clear-Bay
    [void](Invoke-Start "s-st")
    $st1 = Get-Stamp
    Assert-True ((Get-PropValue $st1 "running" $null) -eq $true -and (Get-PropValue $st1 "baySessionId" "") -eq "s-st" -and (Get-PropValue $st1 "status" "") -eq "ACTIVE" -and (Get-PropValue $st1 "forSessionId" "") -eq "s-st" -and $null -ne (ConvertTo-KioskUtc (Get-PropValue $st1 "writtenUtc" $null))) "stamp: Start's wall write says s-st plays, for ACTIVE/s-st"
    [void](Invoke-End "s-st")
    $st2 = Get-Stamp
    Assert-True ((Get-PropValue $st2 "running" $null) -eq $false -and (Get-PropValue $st2 "status" "") -eq "ENDED") "stamp: the End's wall write says nobody plays, for ENDED"
    # The shell's rule, pure (every refusal shape).
    $nS = (Get-Date).ToUniversalTime(); $sinceS = $nS.AddMinutes(-1)
    function New-Wall([string]$status, $wallSid, $stamp) { $h = [ordered]@{ status = $status }; if ($null -ne $wallSid) { $h["baySessionId"] = $wallSid }; if ($null -ne $stamp) { $h["agentRunning"] = [pscustomobject]$stamp }; return [pscustomobject]$h }
    function New-St($running, [string]$status, $for, $at) { $h = [ordered]@{ schema = 1; running = $running; baySessionId = ""; status = $status; writtenUtc = $at }; if ($null -ne $for) { $h["forSessionId"] = $for }; return $h }
    function Get-GG($wall, [string]$closedSid, $since) {
        $a = @{ SessionRead = @{ Ok = $true; Why = ""; Obj = $wall }; ClosedSessionId = $closedSid; NowUtc = $nS }
        if ((Get-Command Get-KioskSessionGuard).Parameters.ContainsKey("ClosedSinceUtc")) { $a["ClosedSinceUtc"] = $since }
        return (Get-KioskSessionGuard @a).AllowClose
    }
    $tickText = Get-DefText $ShellDefs "Invoke-KioskTick"
    Assert-True ($tickText -match 'Get-KioskSessionGuard [^\r\n]*-ClosedSinceUtc \$S\.Wanted\.ClosedSinceUtc') "the shell's tick passes the closed intent's time to its guard (the rule below needs it)"
    $atOk = $nS.ToString($fmtZ); $atOld = $nS.AddMinutes(-5).ToString($fmtZ)
    Assert-True (Get-GG (New-Wall "PREP" "s-n" (New-St $false "PREP" "s-n" $atOk)) "s-a" $sinceS) "guard: PREP stamped nobody-plays, after the closed intent: close"
    Assert-True (Get-GG (New-Wall "READY" $null (New-St $false "READY" "" $atOk)) "s-a" $sinceS) "guard: READY (no session) stamped nobody-plays: close"
    Assert-True (-not (Get-GG (New-Wall "PREP" "s-n" (New-St $true "PREP" "s-n" $atOk)) "s-a" $sinceS)) "guard: PREP stamped someone-plays: hold"
    Assert-True (-not (Get-GG (New-Wall "PREP" "s-n" (New-St "false" "PREP" "s-n" $atOk)) "s-a" $sinceS)) "guard: running as the text 'false': hold"
    Assert-True (-not (Get-GG (New-Wall "PREP" "s-n" (New-St $false "READY" "s-n" $atOk)) "s-a" $sinceS)) "guard: a stamp for another status (merged forward): hold"
    Assert-True (-not (Get-GG (New-Wall "PREP" "s-n" (New-St $false "PREP" "s-m" $atOk)) "s-a" $sinceS)) "guard: a stamp for another session: hold"
    Assert-True (-not (Get-GG (New-Wall "PREP" "s-n" (New-St $false "PREP" $null $atOk)) "s-a" $sinceS)) "guard: a stamp with no forSessionId: hold"
    Assert-True (-not (Get-GG (New-Wall "PREP" "s-n" (New-St $false "PREP" "s-n" $atOld)) "s-a" $sinceS)) "guard: a stamp older than the closed intent: hold"
    Assert-True (-not (Get-GG (New-Wall "PREP" "s-n" (New-St $false "PREP" "s-n" "not a time")) "s-a" $sinceS)) "guard: a stamp with no readable time: hold"
    Assert-True (-not (Get-GG (New-Wall "PREP" "s-n" $null) "s-a" $sinceS)) "guard: no stamp (an older agent's wall): hold"
    Assert-True (-not (Get-GG (New-Wall "PREP" "s-n" (New-St $false "PREP" "s-n" $atOk)) "s-a" $null)) "guard: no closed-intent time: hold"
    Assert-True (-not (Get-GG (New-Wall "PREP" "s-n" (New-St $false "PREP" "s-n" $atOk)) "" $sinceS)) "guard: a closed intent naming no session: hold"
    Assert-True (-not (Get-GG (New-Wall "STOP" "s-n" (New-St $false "STOP" "s-n" $atOk)) "s-a" $sinceS)) "guard: STOP even stamped nobody-plays: hold (A0.457)"
    Assert-True (-not (Get-GG (New-Wall "ACTIVE" "s-n" (New-St $false "ACTIVE" "s-n" $atOk)) "s-a" $sinceS)) "guard: ACTIVE even stamped nobody-plays: hold"
    Assert-True (-not (Get-GG (New-Wall "ENDING" "s-n" (New-St $false "ENDING" "s-n" $atOk)) "s-a" $sinceS)) "guard: ENDING even stamped nobody-plays: hold"
    Assert-True (-not (Get-GG (New-Wall "prep" "s-n" (New-St $false "prep" "s-n" $atOk)) "s-a" $sinceS)) "guard: a lower-case prep: hold"
    Assert-True (-not (Get-GG (New-Wall "PREP" 7 (New-St $false "PREP" "7" $atOk)) "s-a" $sinceS)) "guard: a wall session id that is not text: hold"
    # ---- RV2: a restart while the record file's write was failing.
    Clear-Bay
    Set-TestFile $RunningSessionPath ('{"schema":1,"running":false,"baySessionId":null,"endUtc":null,"since":null,"writtenUtc":"' + (Get-Date).ToUniversalTime().AddMinutes(-10).ToString($fmtZ) + '"}')
    $lockR2 = New-Object IO.FileStream($RunningSessionPath, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
    try {
        [void](Invoke-Start "s-r2")
        Assert-True ($Global:RunningSessionPending) "RV2 precondition: s-r2's record write failed (file held open)"
    } finally { $lockR2.Dispose() }
    $Global:RunningSession = $null; $Global:RunningSessionPending = $false
    Initialize-RunningSession -NowUtc ((Get-Date).ToUniversalTime())
    Assert-True ((Get-RecSid) -eq "s-r2") "RV2 the restart keeps s-r2 playing: the wall's newer stamp wins over the stale file (it read 'nobody' before)"
    $x = Invoke-CancelReset "s-other"
    Assert-True ($x.Skipped -and $x.WallSame) "RV2 ...so another booking's Reset is still held after the restart"
    $rfR2 = Read-KioskJsonFile -Path $RunningSessionPath
    Assert-True ($rfR2.Ok -and (Get-KioskProp $rfR2.Obj "baySessionId" "") -eq "s-r2") "RV2 ...and the record file is rewritten to agree"
    [void](Invoke-End "s-r2")
    $endK2 = (Get-Date).ToUniversalTime().AddMinutes(30).ToString($fmtZ)
    $stOld = '{"schema":1,"running":true,"baySessionId":"s-old","endUtc":"' + $endK2 + '","status":"ACTIVE","forSessionId":"s-old","writtenUtc":"' + (Get-Date).ToUniversalTime().AddMinutes(-20).ToString($fmtZ) + '"}'
    Set-TestFile $sessPath ('{"status":"ACTIVE","baySessionId":"s-old","sessionEndUtc":"' + $endK2 + '","agentRunning":' + $stOld + '}')
    Set-TestFile $RunningSessionPath ('{"schema":1,"running":false,"baySessionId":null,"endUtc":null,"writtenUtc":"' + (Get-Date).ToUniversalTime().AddMinutes(-1).ToString($fmtZ) + '"}')
    $Global:RunningSession = $null; Initialize-RunningSession -NowUtc ((Get-Date).ToUniversalTime())
    Assert-True ((Get-RecSid) -eq "<none>") "RV2 a stamp OLDER than the record file loses (the file's later 'nobody' wins)"
    $tEq = (Get-Date).ToUniversalTime().AddMinutes(-2).ToString($fmtZ)
    Set-TestFile $sessPath ('{"status":"ACTIVE","baySessionId":"s-eq","sessionEndUtc":"' + $endK2 + '","agentRunning":{"schema":1,"running":true,"baySessionId":"s-eq","endUtc":"' + $endK2 + '","status":"ACTIVE","forSessionId":"s-eq","writtenUtc":"' + $tEq + '"}}')
    Set-TestFile $RunningSessionPath ('{"schema":1,"running":false,"baySessionId":null,"endUtc":null,"writtenUtc":"' + $tEq + '"}')
    $Global:RunningSession = $null; Initialize-RunningSession -NowUtc ((Get-Date).ToUniversalTime())
    Assert-True ((Get-RecSid) -eq "s-eq") "RV2 equal times: the snapshot saying someone plays wins"
    Set-TestFile $RunningSessionPath ('{"schema":1,"running":false,"baySessionId":null,"endUtc":null,"writtenUtc":"' + (Get-Date).ToUniversalTime().AddMinutes(-30).ToString($fmtZ) + '","finished":[{"id":"s-eq","utc":"' + $tEq + '"}]}')
    $Global:RunningSession = $null; Initialize-RunningSession -NowUtc ((Get-Date).ToUniversalTime())
    Assert-True ((Get-RecSid) -eq "<none>") "RV2 a newer stamp naming a session this bay already ended: nobody"
    Set-TestFile $sessPath ('{"status":"ACTIVE","baySessionId":"s-bad","sessionEndUtc":"' + $endK2 + '","agentRunning":{"schema":1,"running":"yes","baySessionId":"s-bad","writtenUtc":"' + (Get-Date).ToUniversalTime().ToString($fmtZ) + '"}}')
    Set-TestFile $RunningSessionPath ('{"schema":1,"running":false,"baySessionId":null,"endUtc":null,"writtenUtc":"' + (Get-Date).ToUniversalTime().AddMinutes(-30).ToString($fmtZ) + '"}')
    $Global:RunningSession = $null; Initialize-RunningSession -NowUtc ((Get-Date).ToUniversalTime())
    Assert-True ((Get-RecSid) -eq "<none>") "RV2 a malformed stamp is not a snapshot (the file decides)"
    Clear-Bay

    # ---- RV3: a Start refused by an emergency stop is recorded (when it names its session).
    [void](Execute-Command -CommandType $CMD_EMERGENCY_STOP -PayloadJson '{"action":"engage","reason":"t"}' -BayLabel "Bay")
    $rb3 = Invoke-Start "s-b3"
    Assert-True ((Get-PropValue $rb3 "note" "") -eq "emergency_stop_engaged" -and (Get-RecSid) -eq "s-b3") "RV3 the refused Start of s-b3 is recorded (the stop refuses the launcher, not the booking)"
    [void](Execute-Command -CommandType $CMD_EMERGENCY_STOP -PayloadJson '{"action":"clear"}' -BayLabel "Bay")
    $x = Invoke-CancelReset "s-other"
    Assert-True ($x.Skipped -and $x.WallSame) "RV3 after the clear, another booking's Reset is held (it reset s-b3's wall before)"
    [void](Invoke-End "s-b3")
    Assert-True ((Get-RecSid) -eq "<none>") "RV3 s-b3's own End clears it"
    [void](Execute-Command -CommandType $CMD_EMERGENCY_STOP -PayloadJson '{"action":"engage","reason":"t"}' -BayLabel "Bay")
    [void](Execute-Command -CommandType $CMD_STARTSESSION -PayloadJson '{"mode":"Start","closeLauncher":false}' -BayLabel "Bay")
    Assert-True ((Get-RecSid) -eq "<none>") "RV3 an unnamed refused Start is not recorded (nothing to protect; it would hold every unbound Reset)"
    [void](Execute-Command -CommandType $CMD_EMERGENCY_STOP -PayloadJson '{"action":"clear"}' -BayLabel "Bay")

    # ---- RV4: a Start with no session id leaves an empty-id record; an End with no id now clears it.
    Clear-Bay
    $eN = (Get-Date).ToUniversalTime().AddMinutes(40).ToString($fmtZ)
    [void](Execute-Command -CommandType $CMD_STARTSESSION -PayloadJson ('{"mode":"Start","playEndUtc":"' + $eN + '","closeLauncher":false}') -BayLabel "Bay")
    Assert-True ($null -ne $Global:RunningSession -and (Get-RecSid) -eq "") "RV4 precondition: an unnamed Start records an unnamed session"
    [void](Execute-Command -CommandType $CMD_ENDSESSION -PayloadJson '{"mode":"End","closeLauncher":false}' -BayLabel "Bay")
    Assert-True ((Get-RecSid) -eq "<none>") "RV4 an End naming no session clears the unnamed record (it stayed until the next Start before)"
    $x = Invoke-CancelReset ""
    Assert-True ($x.Reset) "RV4 ...so the next unbound Reset is no longer held"

    # ---- RV1: replays of a session this bay already ended, while the next one plays.
    Clear-Bay
    [void](Invoke-Start "s-R"); [void](Invoke-End "s-R")
    [void](Invoke-Start "s-T7")
    $wallT7 = [IO.File]::ReadAllText($sessPath); $script:Fac = @()
    $rp = Invoke-Start "s-R" "Prep"
    $rs = Invoke-Start "s-R"
    $rw = Execute-Command -CommandType $CMD_UPDATESESSIONDISPLAY -PayloadJson ('{"mode":"Warn5","baySessionId":"s-R","playEndUtc":"' + $endIso + '"}') -BayLabel "Bay"
    $re = Invoke-End "s-R"
    $allSkipped = ((Get-PropValue $rp "skipped" $null) -eq $true -and (Get-PropValue $rs "skipped" $null) -eq $true -and (Get-PropValue $rw "skipped" $null) -eq $true -and (Get-PropValue $re "skipped" $null) -eq $true)
    Assert-True ($allSkipped -and [IO.File]::ReadAllText($sessPath) -ceq $wallT7 -and $script:Fac.Count -eq 0 -and (Get-RecSid) -eq "s-T7" -and (Get-IntentNow).Wanted -and (Get-IntentNow).SessionId -eq "s-T7") "RV1 a replayed Prep, Start, Warn5 and End of the ended s-R while s-T7 plays: each refused, s-T7's wall, record and intent untouched"
    $Global:RunningSession = $null; Initialize-RunningSession -NowUtc ((Get-Date).ToUniversalTime())
    Assert-True ((Test-SessionFinished "s-R" $Global:RunningSessionFinished) -and (Get-RecSid) -eq "s-T7") "RV1 the ended-session list survives a restart (record file)"
    $l60 = @(); for ($i = 1; $i -le 60; $i++) { $l60 = @(Add-FinishedSessionToList -Finished $l60 -SessionId ("s-" + $i) -NowUtc $nC -Max 50) }
    $l60b = @(Add-FinishedSessionToList -Finished $l60 -SessionId "S-20" -NowUtc $nC -Max 50)
    Assert-True ($l60.Count -eq 50 -and -not (Test-SessionFinished "s-10" $l60) -and (Test-SessionFinished "s-11" $l60) -and (Test-SessionFinished "s-60" $l60) -and $l60b.Count -eq 50 -and [string](Get-KioskProp $l60b[49] "id" "") -eq "S-20") "RV1 the list keeps the newest 50; a re-added session moves to newest"
    Assert-True (@($l60b | Where-Object { Test-BaySessionIdMatch ([string](Get-KioskProp $_ "id" "")) "s-20" }).Count -eq 1 -and (Test-SessionFinished "s-11" $l60b)) "RV1 ...with no duplicate entry (the oldest, s-11, is still kept)"
    Assert-True (-not (Test-SessionFinished "" $l60) -and -not (Test-SessionFinished $null @())) "RV1 an empty id is never 'ended'"
    # Process-Command: a refused replay writes NO booking status (it would move a completed booking back to in-process);
    # a late End of another booking still writes its booking complete.
    $script:Patches2 = New-Object System.Collections.ArrayList
    function Patch-Row { param($token, $entitySet, $id, $bodyObj, $ifMatch) [void]$script:Patches2.Add(@{ Set = $entitySet; Id = $id; Body = $bodyObj }) }
    function New-CmdRow([int]$type, [string]$payloadText) {
        $row = [ordered]@{ "@odata.etag" = 'W/"7"' }
        $row[$Col_CommandId] = "c0ffee00-0000-0000-0000-000000000021"; $row[$Col_CommandType] = $type; $row[$Col_AttemptCount] = 0; $row[$Col_Payload] = $payloadText
        return [pscustomobject]$row
    }
    $bkPay = '{"mode":"Start","baySessionId":"s-R","bookingId":"b0000000-0000-0000-0000-0000000000r1","playEndUtc":"' + $endIso + '","closeLauncher":false}'
    Process-Command -token "t" -cmd (New-CmdRow $CMD_STARTSESSION $bkPay)
    Assert-True (@($script:Patches2 | Where-Object { $_.Set -eq "build_bookings" }).Count -eq 0 -and (Get-RecSid) -eq "s-T7") "RV1 Process-Command: the replayed Start of s-R writes no booking status"
    $script:Patches2.Clear()
    Process-Command -token "t" -cmd (New-CmdRow $CMD_ENDSESSION ('{"mode":"End","baySessionId":"s-U8","bookingId":"b0000000-0000-0000-0000-0000000000u8","closeLauncher":false}'))
    Assert-True (@($script:Patches2 | Where-Object { $_.Set -eq "build_bookings" }).Count -eq 1 -and (Get-RecSid) -eq "s-T7") "Process-Command: a late End of another booking (left alone) still writes that booking complete"
    [void](Invoke-End "s-T7")

    # ---- An End whose wall write fails still closes (A0.360; a canceled booking never becomes free play).
    Clear-Bay
    [void](Invoke-Start "s-w")
    $realWsf = Get-DefText $AgentDefs "Write-SessionFiles"
    function Write-SessionFiles($modelObj) { throw "simulated disk failure" }
    $rwf = $null; try { $rwf = Invoke-End "s-w" } catch { $rwf = $null }
    . ([scriptblock]::Create($realWsf))
    Assert-True ($null -ne $rwf -and -not [string]::IsNullOrWhiteSpace([string](Get-PropValue $rwf "wallError" $null)) -and (Get-IntentNow).Closed -and (Get-RecSid) -eq "<none>") "an End whose wall write fails still closes the launcher and the intent, and the result says the wall failed (it threw before)"
    Clear-Bay

    # ============================================================ K22 (kiosk round 2 FIX, 2026-10-10)
    # A0.489 (a cancel is final on that bay), the refusal shown on the command row, R2 (an End that fails after the session
    # was listed as ended is retried into closing the launcher), R1 (the attack's four surviving mutants: the main-loop call,
    # the cancel End closing a real launcher, the cancel End naming the recorded session). Each assertion names what it pins.
    Section "K22 round 2 fix: a cancel is final (A0.489); a refusal shows on the row; a failed End is retried (R2); the headline claims are pinned (R1)"
    $script:Patches3 = New-Object System.Collections.ArrayList
    $script:FailSkip3 = $false
    function Patch-Row { param($token, $entitySet, $id, $bodyObj, $ifMatch)
        [void]$script:Patches3.Add(@{ Set = $entitySet; Id = $id; Body = $bodyObj })
        if ($script:FailSkip3 -and $bodyObj[$Col_Status] -eq $STATUS_SKIPPED) { throw "simulated guard refusal" }
    }
    function New-StandInLauncher {
        # A real process the agent's End can find by path and close: a renamed copy of ping.exe in the sandbox.
        $d = Join-Path $Sandbox ("standin-" + [guid]::NewGuid().ToString("N").Substring(0, 8)); New-Item -ItemType Directory -Force -Path $d | Out-Null
        $nm = "AbgStandIn" + [guid]::NewGuid().ToString("N").Substring(0, 8)
        $exe = Join-Path $d ($nm + ".exe")
        Copy-Item -LiteralPath (Join-Path $env:WINDIR "System32\ping.exe") -Destination $exe
        $p = Start-Process -FilePath $exe -ArgumentList "-t 127.0.0.1" -WindowStyle Hidden -PassThru
        Start-Sleep -Milliseconds 600
        $cfg | Add-Member -NotePropertyName launcher -NotePropertyValue ([pscustomobject]@{ path = $exe; processName = $nm }) -Force
        return [pscustomobject]@{ Proc = $p; Exe = $exe; Name = $nm }
    }
    function Test-StandInAlive($s) { try { $s.Proc.Refresh(); return (-not $s.Proc.HasExited) } catch { return $false } }
    function Remove-StandInLauncher($s) {
        try { if ($null -ne $s -and (Test-StandInAlive $s)) { Stop-Process -Id $s.Proc.Id -Force -ErrorAction SilentlyContinue } } catch { }
        try { if ($null -ne $cfg.PSObject.Properties["launcher"]) { $cfg.PSObject.Properties.Remove("launcher") } } catch { }
    }
    function Get-BookingWrites { return @($script:Patches3 | Where-Object { $_.Set -eq "build_bookings" }).Count }
    $realGetLauncherCfg = Get-DefText $AgentDefs "Get-LauncherConfigFromPayloadOrConfig"
    $script:GlThrows = 0
    # A step between the ended list and the launcher close that fails, and its repair (both define the function in script scope).
    $brokenGetLauncherCfg = 'function script:Get-LauncherConfigFromPayloadOrConfig($payloadObj) { $script:GlThrows++; throw "simulated failure after the session was listed as ended" }'
    $repairGetLauncherCfg = $realGetLauncherCfg.Replace("function Get-LauncherConfigFromPayloadOrConfig", "function script:Get-LauncherConfigFromPayloadOrConfig")
    function Break-LauncherStep { . ([scriptblock]::Create($brokenGetLauncherCfg)) }
    function Repair-LauncherStep { . ([scriptblock]::Create($repairGetLauncherCfg)) }

    # ---- A0.489: a Start, Prep, display update or End for the canceled booking during its warning is refused.
    Clear-Bay
    [void](Invoke-Start "s-h1")
    $script:Fac = @(); $script:ControlWarnings.Clear()
    $rh = Invoke-BoundReset "s-h1"; $endsH = Get-EndsOf $rh
    $wallH = [IO.File]::ReadAllText($sessPath); $recH = [IO.File]::ReadAllText($RunningSessionPath); $intH = [IO.File]::ReadAllText($KioskIntentPath); $facH = @($script:Fac).Count
    $hPrep = Invoke-Start "s-h1" "Prep"
    $hStart = Invoke-Start "s-h1"
    $hUpd = Execute-Command -CommandType $CMD_UPDATESESSIONDISPLAY -PayloadJson ('{"mode":"Warn5","baySessionId":"s-h1","playEndUtc":"' + $endIso + '"}') -BayLabel "Bay"
    $hEnd = Invoke-End "s-h1"
    $allHeld = $true
    foreach ($hr in @($hPrep, $hStart, $hUpd, $hEnd)) { if (-not ((Get-PropValue $hr "skipped" $null) -eq $true -and (Get-PropValue $hr "refusal" "") -eq "cancel-warning")) { $allHeld = $false } }
    Assert-True $allHeld "A0.489 a Prep, a Start, a display update and an End for the canceled s-h1 during its warning: each refused (skipped, refusal cancel-warning)"
    Assert-True ([IO.File]::ReadAllText($sessPath) -ceq $wallH -and [IO.File]::ReadAllText($RunningSessionPath) -ceq $recH -and [IO.File]::ReadAllText($KioskIntentPath) -ceq $intH -and @($script:Fac).Count -eq $facH) "A0.489 ...and nothing is touched: the warning wall, the record file, the intent file and the facility are as the cancel left them"
    Assert-True ((Get-SessStatus) -eq "ENDING/s-h1" -and (Get-PropValue (Get-Sess) "bannerText" "") -eq "Booking canceled" -and $null -ne $endsH -and (ConvertTo-KioskUtc (Get-RecCancel)) -eq $endsH -and (Get-IntentNow).Wanted) "A0.489 ...the warning stays on the wall with the end set at the cancel (never back to 'In progress' with the full countdown: the middle state)"
    $endH = Invoke-CancelEndIfDue -NowUtc $endsH.AddSeconds(1)
    Assert-True ((Get-SessStatus) -eq "ENDED/s-h1" -and (Get-IntentNow).Closed -and (Get-RecSid) -eq "<none>" -and (Get-PropValue $endH "scope" "") -eq "running" -and (Test-SessionFinished "s-h1" $Global:RunningSessionFinished)) "A0.489 ...and the game still ends at the warning's mark: the agent's own End is not refused by the hold"
    Assert-True (-not $Global:RunningSessionOwnEnd) "A0.489 ...and the 'agent's own End' flag is off again afterwards (it would switch the hold off for every later command)"
    $hAfter = Invoke-Start "s-h1"
    Assert-True ((Get-PropValue $hAfter "skipped" $null) -eq $true -and (Get-PropValue $hAfter "refusal" "") -eq "ended-replay" -and (Get-SessStatus) -eq "ENDED/s-h1") "A0.489 a booking reinstated after the bay ended it stays refused"
    # Only that booking: the next booking's Prep and Start still run during the warning (the hold is per session).
    Clear-Bay
    [void](Invoke-Start "s-h5")
    $endsH5 = Get-EndsOf (Invoke-BoundReset "s-h5")
    $nPrep = Invoke-Start "s-n5" "Prep"
    Assert-True ($null -eq (Get-PropValue $nPrep "skipped" $null) -and (Get-SessStatus) -eq "PREP/s-n5" -and (Get-RecSid) -eq "s-h5") "A0.489 the hold is for the canceled booking only: the next booking's Prep during the warning still runs"
    $nStart = Invoke-Start "s-n5"
    Assert-True ($null -eq (Get-PropValue $nStart "skipped" $null) -and (Get-RecSid) -eq "s-n5" -and $null -eq (Get-RecCancel)) "A0.489 ...and the next booking's Start takes the bay (the canceled booking's warning is over for it)"
    [void](Invoke-End "s-n5")
    # The pure rule, every branch.
    $recW = [ordered]@{ baySessionId = "s-a"; endUtc = "2026-10-09T13:00:00Z"; since = "2026-10-09T11:00:00Z"; cancelEndUtc = "2026-10-09T12:05:00Z" }
    $recP = [ordered]@{ baySessionId = "s-a"; endUtc = "2026-10-09T13:00:00Z"; since = "2026-10-09T11:00:00Z" }
    foreach ($ct in @($CMD_STARTSESSION, $CMD_UPDATESESSIONDISPLAY, $CMD_ENDSESSION)) {
        $gW = Get-CommandRefusal -CommandType $ct -Payload ([pscustomobject]@{ baySessionId = " S-A " }) -Running $recW -Finished @() -Pending @()
        Assert-True ($null -ne $gW -and $gW.Kind -eq "cancel-warning") "A0.489 rule: command type $ct for the canceled running session (id compared the way the bay compares ids): refused"
    }
    Assert-True ($null -eq (Get-CommandRefusal -CommandType $CMD_ENDSESSION -Payload ([pscustomobject]@{ baySessionId = "s-a" }) -Running $recW -Finished @() -Pending @() -OwnEnd $true)) "A0.489 rule: the agent's own End of the canceled session is not refused"
    Assert-True ($null -eq (Get-CommandRefusal -CommandType $CMD_STARTSESSION -Payload ([pscustomobject]@{ baySessionId = "s-b" }) -Running $recW -Finished @() -Pending @())) "A0.489 rule: another session's Start is not refused"
    Assert-True ($null -eq (Get-CommandRefusal -CommandType $CMD_STARTSESSION -Payload ([pscustomobject]@{ baySessionId = "s-a" }) -Running $recP -Finished @() -Pending @())) "A0.489 rule: the running session that was NOT canceled is not refused"
    Assert-True ($null -eq (Get-CommandRefusal -CommandType $CMD_STARTSESSION -Payload ([pscustomobject]@{ mode = "Start" }) -Running $recW -Finished @() -Pending @())) "A0.489 rule: a command naming no session is not refused"
    Assert-True ($null -eq (Get-CommandRefusal -CommandType $CMD_RESET -Payload ([pscustomobject]@{ baySessionId = "s-a" }) -Running $recW -Finished @() -Pending @())) "A0.489 rule: a Reset is not this rule's (the Reset gate decides)"
    $finA = @([ordered]@{ id = "s-a"; utc = "2026-10-09T12:00:00Z" })
    $gF = Get-CommandRefusal -CommandType $CMD_STARTSESSION -Payload ([pscustomobject]@{ baySessionId = "s-a" }) -Running $null -Finished $finA -Pending @()
    Assert-True ($null -ne $gF -and $gF.Kind -eq "ended-replay") "RV1 rule: a session the bay ended: refused"
    Assert-True ($null -eq (Get-CommandRefusal -CommandType $CMD_ENDSESSION -Payload ([pscustomobject]@{ baySessionId = "s-a" }) -Running $null -Finished $finA -Pending @([ordered]@{ id = "s-a"; payload = "{}"; tries = 0 }))) "R2 rule: an End of an ended session whose protective act is pending, nobody playing: not refused (the retry)"
    Assert-True ($null -ne (Get-CommandRefusal -CommandType $CMD_ENDSESSION -Payload ([pscustomobject]@{ baySessionId = "s-a" }) -Running $recP -Finished $finA -Pending @([ordered]@{ id = "s-a"; payload = "{}"; tries = 0 }))) "R2 rule: ...but refused while another session is recorded as playing"
    Assert-True ($null -ne (Get-CommandRefusal -CommandType $CMD_STARTSESSION -Payload ([pscustomobject]@{ baySessionId = "s-a" }) -Running $null -Finished $finA -Pending @([ordered]@{ id = "s-a"; payload = "{}"; tries = 0 }))) "R2 rule: a pending End never lets a Start of the ended session through"

    # ---- Item 2: the refusal is visible on the command row (Skipped), not only inside a Succeeded row's result text.
    function Get-FirstPatch { if ($script:Patches3.Count -gt 0) { return $script:Patches3[0] }; return @{ Body = @{}; Set = ""; Id = "" } }
    Clear-Bay
    [void](Invoke-Start "s-h2"); [void](Invoke-BoundReset "s-h2")
    $bkH2 = 'b0000000-0000-0000-0000-0000000000h2'
    foreach ($rowSpec in @(
        @{ T = $CMD_STARTSESSION; N = "Start"; P = ('{"mode":"Start","baySessionId":"s-h2","bookingId":"' + $bkH2 + '","playEndUtc":"' + $endIso + '","closeLauncher":false}') },
        @{ T = $CMD_STARTSESSION; N = "Prep"; P = ('{"mode":"Prep","baySessionId":"s-h2","bookingId":"' + $bkH2 + '","playEndUtc":"' + $endIso + '"}') },
        @{ T = $CMD_UPDATESESSIONDISPLAY; N = "display update"; P = ('{"mode":"Warn5","baySessionId":"s-h2","playEndUtc":"' + $endIso + '"}') },
        @{ T = $CMD_ENDSESSION; N = "End"; P = ('{"mode":"End","baySessionId":"s-h2","bookingId":"' + $bkH2 + '","closeLauncher":false}') })) {
        $script:Patches3.Clear()
        Process-Command -token "t" -cmd (New-CmdRow $rowSpec.T $rowSpec.P)
        $p1 = Get-FirstPatch
        Assert-True ($script:Patches3.Count -eq 1 -and @($p1.Body.Keys).Count -eq 1 -and $p1.Body[$Col_Status] -eq 100000005 -and (Get-BookingWrites) -eq 0) "item 2 the canceled s-h2's $($rowSpec.N) row during its warning: ONE write, status Skipped only (no lock, no execution fields, no booking write)"
    }
    Assert-True ((Get-RecSid) -eq "s-h2" -and (Get-SessStatus) -eq "ENDING/s-h2") "item 2 ...and none of them moved the warning"
    $script:FailSkip3 = $true; $script:Patches3.Clear()
    Process-Command -token "t" -cmd (New-CmdRow $CMD_STARTSESSION ('{"mode":"Start","baySessionId":"s-h2","bookingId":"' + $bkH2 + '","playEndUtc":"' + $endIso + '","closeLauncher":false}'))
    $script:FailSkip3 = $false
    $lastP = $(if ($script:Patches3.Count -gt 0) { $script:Patches3[$script:Patches3.Count - 1] } else { @{ Body = @{}; Set = "" } })
    Assert-True ($script:Patches3.Count -eq 3 -and $script:Patches3[1].Body[$Col_Status] -eq $STATUS_INPROGRESS -and $lastP.Body[$Col_Status] -eq $STATUS_SUCCEEDED -and [string]$lastP.Body[$Col_Result] -match '"skipped":true' -and (Get-BookingWrites) -eq 0 -and (Get-SessStatus) -eq "ENDING/s-h2") "item 2 if the Skipped write is refused: the command runs, the handler refuses it, Succeeded with skipped in the result, no booking write, the warning stands"
    [void](Invoke-CancelEndIfDue -NowUtc ((Get-Date).ToUniversalTime().AddMinutes(6)))
    # An ended session's replay is visible the same way; a fresh Start is NOT turned away.
    Clear-Bay
    [void](Invoke-Start "s-h3"); [void](Invoke-End "s-h3")
    $script:Patches3.Clear()
    Process-Command -token "t" -cmd (New-CmdRow $CMD_ENDSESSION '{"mode":"End","baySessionId":"s-h3","closeLauncher":false}')
    $p3 = Get-FirstPatch
    Assert-True ($script:Patches3.Count -eq 1 -and $p3.Body[$Col_Status] -eq 100000005 -and @($p3.Body.Keys).Count -eq 1) "item 2 a repeated End of the ended s-h3: one write, Skipped"
    $script:Patches3.Clear()
    Process-Command -token "t" -cmd (New-CmdRow $CMD_STARTSESSION ('{"mode":"Start","baySessionId":"s-h4","bookingId":"b0000000-0000-0000-0000-0000000000h4","playEndUtc":"' + $endIso + '","closeLauncher":false}'))
    Assert-True ($script:Patches3.Count -ge 2 -and $script:Patches3[0].Body[$Col_Status] -eq $STATUS_INPROGRESS -and (Get-BookingWrites) -eq 1 -and (Get-RecSid) -eq "s-h4") "item 2 a fresh booking's Start is not turned away: locked, run, booking written In-process"
    [void](Invoke-End "s-h4")

    # ---- R1 (VM04, VM05): the cancel End, run against a REAL launcher process, naming the recorded session.
    Clear-Bay
    $sl1 = New-StandInLauncher
    try {
        [void](Invoke-Start "s-c10")
        $endsC10 = Get-EndsOf (Invoke-BoundReset "s-c10")
        [void](Invoke-Start "s-n10" "Prep")
        Assert-True ((Get-SessStatus) -eq "PREP/s-n10" -and (Get-RecSid) -eq "s-c10") "R1 setup: the next booking's Prep rewrote the wall (PREP/s-n10) while s-c10, canceled, plays out its warning"
        $dueEarly = Invoke-CancelEndIfDue -NowUtc ((Get-Date).ToUniversalTime().AddMinutes(4))
        Assert-True ($null -eq $dueEarly -and (Test-StandInAlive $sl1)) "R1 4 minutes into the warning: nothing ended, the real launcher process is still running"
        $dueRes = Invoke-CancelEndIfDue -NowUtc $endsC10.AddSeconds(1)
        Start-Sleep -Milliseconds 500
        Assert-True (-not (Test-StandInAlive $sl1)) "R1 (VM04) the cancel End closes the real launcher process when the warning is over"
        $iC = Get-IntentNow
        Assert-True ((Get-PropValue $dueRes "scope" "") -eq "running" -and $iC.Closed -and $iC.SessionId -eq "s-c10" -and (Test-SessionFinished "s-c10" $Global:RunningSessionFinished) -and -not (Test-SessionFinished "s-n10" $Global:RunningSessionFinished) -and (Get-RecSid) -eq "<none>") "R1 (VM05) the cancel End names the RECORDED session (s-c10), not the session the wall shows (s-n10): intent closed for s-c10, s-c10 listed as ended, s-n10 not"
    } finally { Remove-StandInLauncher $sl1 }

    # ---- R2: an End that fails after the session was listed as ended is retried into closing the launcher.
    # (a) the cancel End.
    Clear-Bay
    $sl2 = New-StandInLauncher
    try {
        [void](Invoke-Start "s-r2a")
        $endsR2a = Get-EndsOf (Invoke-BoundReset "s-r2a")
        Break-LauncherStep; $script:GlThrows = 0
        $failRes = Invoke-CancelEndIfDue -NowUtc $endsR2a.AddSeconds(1)
        Assert-True ($null -eq $failRes -and $script:GlThrows -eq 1 -and (Test-StandInAlive $sl2) -and (Test-SessionFinished "s-r2a" $Global:RunningSessionFinished) -and (Test-EndPendingFor "s-r2a" $Global:RunningSessionEndPending) -and (Get-RecSid) -eq "<none>") "R2 setup: the cancel End failed between the ended list and the launcher close: launcher still open, session listed as ended, End pending"
        Assert-True (-not $Global:RunningSessionOwnEnd) "A0.489 ...and the 'agent's own End' flag is off after an End that threw too"
        Repair-LauncherStep
        $retry = Invoke-CancelEndIfDue -NowUtc $endsR2a.AddSeconds(4)
        Start-Sleep -Milliseconds 500
        Assert-True ($null -ne $retry -and (Get-PropValue $retry "scope" "") -eq "retry" -and -not (Test-StandInAlive $sl2) -and (Get-IntentNow).Closed -and -not (Test-EndPendingFor "s-r2a" $Global:RunningSessionEndPending)) "R2 the next pass retries the cancel End: the real launcher is closed, the intent closed, the mark dropped (the ended list no longer makes the protective act a no-op)"
        Assert-True ($null -eq (Invoke-CancelEndIfDue -NowUtc $endsR2a.AddSeconds(8))) "R2 ...and a pass after that does nothing"
    } finally { Remove-StandInLauncher $sl2 }
    # (b) a platform End, through Process-Command rows, with the next booking's Prep arriving in between: the retry does
    # not rewrite the next booking's wall.
    Clear-Bay
    $sl3 = New-StandInLauncher
    try {
        [void](Invoke-Start "s-r2b")
        $endRowPayload = '{"mode":"End","baySessionId":"s-r2b","bookingId":"b0000000-0000-0000-0000-0000000000b2"}'
        Break-LauncherStep; $script:GlThrows = 0; $script:Patches3.Clear()
        Process-Command -token "t" -cmd (New-CmdRow $CMD_ENDSESSION $endRowPayload)
        $lastF = $(if ($script:Patches3.Count -gt 0) { $script:Patches3[$script:Patches3.Count - 1] } else { @{ Body = @{} } })
        Assert-True ($lastF.Body[$Col_Status] -eq $STATUS_FAILED -and (Test-StandInAlive $sl3) -and (Test-EndPendingFor "s-r2b" $Global:RunningSessionEndPending)) "R2 setup: a platform End failed mid-way: its row is Failed, the launcher still open, End pending"
        Repair-LauncherStep
        [void](Invoke-Start "s-n11" "Prep")
        $wallBeforeRetry = [IO.File]::ReadAllText($sessPath)
        $script:Patches3.Clear()
        Process-Command -token "t" -cmd (New-CmdRow $CMD_ENDSESSION $endRowPayload)
        Start-Sleep -Milliseconds 500
        $p0b = Get-FirstPatch; $lastR = @($script:Patches3 | Where-Object { $_.Set -ne "build_bookings" })[-1]
        Assert-True ($p0b.Body[$Col_Status] -eq $STATUS_INPROGRESS -and $lastR.Body[$Col_Status] -eq $STATUS_SUCCEEDED -and [string]$lastR.Body[$Col_Result] -match '"scope":"retry"') "R2 the platform sends the same End again: not turned away as 'already ended' (a lock, a run, Succeeded as a retry)"
        Assert-True (-not (Test-StandInAlive $sl3) -and (Get-IntentNow).Closed -and (Get-IntentNow).SessionId -eq "s-r2b" -and -not (Test-EndPendingFor "s-r2b" $Global:RunningSessionEndPending)) "R2 ...the real launcher is closed, the intent closed, the mark dropped"
        Assert-True ((Get-SessStatus) -eq "PREP/s-n11" -and [IO.File]::ReadAllText($sessPath) -ceq $wallBeforeRetry -and (Get-BookingWrites) -eq 1) "R2 ...the retry left the next booking's wall alone (PREP/s-n11) and, as the first run never got that far, wrote the booking Complete once"
        $script:Patches3.Clear()
        Process-Command -token "t" -cmd (New-CmdRow $CMD_ENDSESSION $endRowPayload)
        Assert-True ($script:Patches3.Count -eq 1 -and $script:Patches3[0].Body[$Col_Status] -eq 100000005) "R2 a third send of that End, now finished for good: refused as Skipped"
    } finally { Remove-StandInLauncher $sl3 }
    # (c) the retry stops after its cap; (d) a session that plays now ends the retry without touching its launcher.
    Clear-Bay
    $sl4 = New-StandInLauncher
    try {
        [void](Invoke-Start "s-r2c")
        Break-LauncherStep; $script:GlThrows = 0; $script:LogLines.Clear()
        try { [void](Execute-Command -CommandType $CMD_ENDSESSION -PayloadJson '{"mode":"End","baySessionId":"s-r2c"}' -BayLabel "Bay") } catch { }
        for ($i = 0; $i -lt 8; $i++) { [void](Invoke-CancelEndIfDue -NowUtc ((Get-Date).ToUniversalTime())) }
        $dropLogged = @($script:LogLines | Where-Object { $_ -match "could not finish its protective act after 5 tries" }).Count
        Assert-True ($script:GlThrows -eq 6 -and @($Global:RunningSessionEndPending).Count -eq 0 -and $dropLogged -eq 1 -and (Test-StandInAlive $sl4)) "R2 a step that keeps failing: the first run plus exactly 5 retries (6 attempts), then dropped with one WARN; no endless loop (got $($script:GlThrows) attempts, drop logged $dropLogged)"
        Repair-LauncherStep
    } finally { Remove-StandInLauncher $sl4 }
    Clear-Bay
    $sl5 = New-StandInLauncher
    try {
        [void](Invoke-Start "s-r2d")
        Break-LauncherStep; $script:GlThrows = 0
        try { [void](Execute-Command -CommandType $CMD_ENDSESSION -PayloadJson '{"mode":"End","baySessionId":"s-r2d"}' -BayLabel "Bay") } catch { }
        Repair-LauncherStep
        [void](Invoke-Start "s-r2e")
        [void](Invoke-CancelEndIfDue -NowUtc ((Get-Date).ToUniversalTime()))
        Assert-True (@($Global:RunningSessionEndPending).Count -eq 0 -and (Test-StandInAlive $sl5) -and (Get-RecSid) -eq "s-r2e" -and (Get-IntentNow).Wanted -and (Get-IntentNow).SessionId -eq "s-r2e") "R2 another session started meanwhile: the old End's retry is dropped and s-r2e's launcher is not touched"
        [void](Invoke-End "s-r2e")
    } finally { Remove-StandInLauncher $sl5 }
    Clear-Bay

    # ---- R1 (VM01, VM02): the REAL BayAgent.ps1, one main-loop pass (-Once), no network, a canceled booking whose warning is over.
    $realLoopOk = $true
    function Invoke-RealLoopCase([string]$Name, [int]$CancelEndOffsetSeconds) {
        $root = Join-Path $Sandbox ("realloop-" + $Name)
        foreach ($d in @("", "logs", "secrets", "state")) { New-Item -ItemType Directory -Force -Path (Join-Path $root $d) | Out-Null }
        $text = [IO.File]::ReadAllText($AgentScript)
        $needle = '$BaseDir = "C:\AllBirdies\BayAgent"'
        if (-not $text.Contains($needle)) { throw "the BaseDir literal was not found in the agent" }
        $agent = Join-Path $root "BayAgent.ps1"
        [IO.File]::WriteAllText($agent, $text.Replace($needle, ('$BaseDir = "{0}"' -f $root)), (New-Object Text.UTF8Encoding($true)))
        Copy-Item -LiteralPath (Join-Path $PSScriptRoot "..\src\BayAgent\manifest.json") -Destination (Join-Path $root "manifest.json") -Force
        try { Add-Type -AssemblyName System.Security -ErrorAction SilentlyContinue } catch { }
        $plain = [Text.Encoding]::UTF8.GetBytes("not-a-real-secret-" + [guid]::NewGuid().ToString("N"))
        $prot = [System.Security.Cryptography.ProtectedData]::Protect($plain, $null, [System.Security.Cryptography.DataProtectionScope]::LocalMachine)
        [IO.File]::WriteAllBytes((Join-Path $root "secrets\clientsecret.dpapi"), $prot)
        $sl = New-StandInLauncher
        $sessP = Join-Path $root "session.json"
        $c = [ordered]@{
            environmentUrl = "http://127.0.0.1:9"; tenantId = "11111111-1111-1111-1111-111111111111"; clientId = "22222222-2222-2222-2222-222222222222"
            clientSecretDpapiPath = (Join-Path $root "secrets\clientsecret.dpapi"); clientCertThumbprint = ""; bayId = "33333333-3333-3333-3333-333333333333"
            pollSeconds = 3; heartbeatSeconds = 60; tokenAuthorityHost = "http://127.0.0.1:9"; logLevel = "DEBUG"; sessionJsonPath = $sessP
            launcher = [ordered]@{ path = $sl.Exe; args = ""; processName = $sl.Name; displayRole = "control"; startOnPrep = $false; startOnStart = $true }
            sessionDisplay = [ordered]@{ enabled = $false }
        }
        $u8 = New-Object Text.UTF8Encoding($false)
        [IO.File]::WriteAllText((Join-Path $root "agent-config.json"), ($c | ConvertTo-Json -Depth 5), $u8)
        $now = (Get-Date).ToUniversalTime()
        $cEnd = $now.AddSeconds($CancelEndOffsetSeconds).ToString($fmtZ); $bEnd = $now.AddMinutes(40).ToString($fmtZ); $wr = $now.AddMinutes(-4).ToString($fmtZ); $since = $now.AddMinutes(-30).ToString($fmtZ)
        $stamp = [ordered]@{ schema = 1; running = $true; baySessionId = "s-live"; endUtc = $bEnd; since = $since; cancelEndUtc = $cEnd; status = "ENDING"; forSessionId = "s-live"; writtenUtc = $wr }
        $wall = [ordered]@{ schema = 1; status = "ENDING"; baySessionId = "s-live"; displayName = "Guest"; playEndUtc = $cEnd; sessionEndUtc = $cEnd; endUtc = $cEnd; bannerText = "Booking canceled"; statusDetail = "This booking was canceled."; agentRunning = $stamp }
        [IO.File]::WriteAllText($sessP, ($wall | ConvertTo-Json -Depth 6), $u8)
        $rec = [ordered]@{ schema = 1; running = $true; baySessionId = "s-live"; endUtc = $bEnd; since = $since; cancelEndUtc = $cEnd; finished = @(); writtenUtc = $wr }
        [IO.File]::WriteAllText((Join-Path $root "state\running-session.json"), ($rec | ConvertTo-Json -Depth 4), $u8)
        $intent = [ordered]@{ schema = 1; launcher = "wanted"; untilUtc = $now.AddSeconds($CancelEndOffsetSeconds + 120).ToString($fmtZ); baySessionId = "s-live"; reason = "booking canceled mid-play: wanted until its warning ends (A0.467)"; writtenUtc = $wr; agentPid = 1 }
        [IO.File]::WriteAllText((Join-Path $root "state\kiosk-intent.json"), ($intent | ConvertTo-Json -Depth 3), $u8)
        $psi = New-Object System.Diagnostics.ProcessStartInfo
        $psi.FileName = Join-Path $env:WINDIR "System32\WindowsPowerShell\v1.0\powershell.exe"
        $psi.Arguments = "-NoProfile -ExecutionPolicy Bypass -WindowStyle Minimized -File `"$agent`" -Once"
        $psi.UseShellExecute = $false; $psi.RedirectStandardOutput = $true; $psi.RedirectStandardError = $true; $psi.CreateNoWindow = $true; $psi.WorkingDirectory = $root
        if ($psi.EnvironmentVariables.ContainsKey("PSModulePath")) { $psi.EnvironmentVariables.Remove("PSModulePath") }
        $proc = [System.Diagnostics.Process]::Start($psi)
        $so = $proc.StandardOutput.ReadToEndAsync(); $se = $proc.StandardError.ReadToEndAsync()
        $exited = $proc.WaitForExit(180000)
        if (-not $exited) { try { $proc.Kill() } catch { } }
        Start-Sleep -Milliseconds 300
        $log = ""
        foreach ($lf in @(Get-ChildItem -LiteralPath (Join-Path $root "logs") -Filter "*.log" -ErrorAction SilentlyContinue)) { $log += [IO.File]::ReadAllText($lf.FullName) }
        $w = $null; try { $w = [IO.File]::ReadAllText($sessP) | ConvertFrom-Json } catch { }
        $ik = $null; try { $ik = [IO.File]::ReadAllText((Join-Path $root "state\kiosk-intent.json")) | ConvertFrom-Json } catch { }
        $rc = $null; try { $rc = [IO.File]::ReadAllText((Join-Path $root "state\running-session.json")) | ConvertFrom-Json } catch { }
        $fin = ""; try { $fin = (@($rc.finished) | ForEach-Object { $_.id }) -join "," } catch { }
        $alive = Test-StandInAlive $sl
        Remove-StandInLauncher $sl
        return [pscustomobject]@{ Exited = $exited; Wall = $(if ($w) { "{0}/{1}" -f $w.status, $w.baySessionId } else { "?" }); Intent = $(if ($ik) { "{0}/{1}" -f $ik.launcher, $ik.baySessionId } else { "?" }); Running = $(if ($rc) { $rc.running } else { "?" }); Finished = $fin; LauncherAlive = $alive; EndLogged = ($log -match "ended after its warning") }
    }
    $rlDue = $null; $rlNot = $null
    try { $rlDue = Invoke-RealLoopCase "due" -60; $rlNot = Invoke-RealLoopCase "notdue" 600 } catch { $realLoopOk = $false; Write-Host ("  real-loop setup failed: " + $_.Exception.Message) }
    Assert-True ($realLoopOk -and $null -ne $rlDue -and $rlDue.Exited -and $rlDue.Wall -eq "ENDED/s-live" -and $rlDue.Intent -eq "closed/s-live" -and $rlDue.Running -eq $false -and $rlDue.Finished -match "s-live" -and -not $rlDue.LauncherAlive -and $rlDue.EndLogged) "R1 (VM01, VM02) the REAL agent script, one main-loop pass with no network, a canceled booking whose warning is over: wall ENDED, intent closed, record cleared and listed, the real launcher process closed (got: $(if ($rlDue) { '{0} | {1} | running={2} | finished={3} | launcher alive={4} | logged={5}' -f $rlDue.Wall, $rlDue.Intent, $rlDue.Running, $rlDue.Finished, $rlDue.LauncherAlive, $rlDue.EndLogged } else { 'no result' }))"
    Assert-True ($realLoopOk -and $null -ne $rlNot -and $rlNot.Exited -and $rlNot.Wall -eq "ENDING/s-live" -and $rlNot.Intent -eq "wanted/s-live" -and $rlNot.Running -eq $true -and $rlNot.LauncherAlive -and -not $rlNot.EndLogged) "R1 ...and with 10 minutes of the warning left, the same pass ends nothing (the control: the check is on the clock)"

    # ---- Item 5: the default sender's process handling, against real processes (a renamed copy of ping.exe stands in for msg.exe).
    $slS = New-StandInLauncher
    try {
        $sOk = Start-ControlScreenSender -Exe $slS.Exe -ArgLine "127.0.0.1 -n 1"
        Assert-True ($null -ne $sOk -and $sOk["exitCode"] -eq 0 -and $sOk["pid"] -gt 0) "item 5 the default sender reads exit code 0 from a process that exits 0 (got: $($sOk['exitCode']))"
        $sBad = Start-ControlScreenSender -Exe $slS.Exe -ArgLine "/bogus-option"
        Assert-True ($null -ne $sBad -and $sBad["exitCode"] -is [int] -and $sBad["exitCode"] -ne 0) "item 5 ...and the non-zero code of one that fails (got: $($sBad['exitCode']))"
        $sSlow = Start-ControlScreenSender -Exe $slS.Exe -ArgLine "-t 127.0.0.1" -WaitMs 400
        Assert-True ($null -ne $sSlow -and $null -eq $sSlow["exitCode"] -and $sSlow["pid"] -gt 0) "item 5 ...and no exit code at all for one still running when the wait ends"
        try { Stop-Process -Id $sSlow["pid"] -Force -ErrorAction SilentlyContinue } catch { }
    } finally { Remove-StandInLauncher $slS }

    # restore the suite's e-stop stubs for the sections below
    function Invoke-EmergencyStopInternal { param($payloadObj) $Global:EmergencyStopEngaged = $true; return @{ ok = $true; engaged = $true } }
    function Clear-EmergencyStopInternal { $Global:EmergencyStopEngaged = $false; return @{ ok = $true; engaged = $false } }
    $Global:EmergencyStopEngaged = $false
    Section "K19 the shell's second check: session.json must show the closed intent's own session ENDED (RF-K2)"
    $nG = (Get-Date).ToUniversalTime()
    function Get-G($obj, [string]$closedSid) { return (Get-KioskSessionGuard -SessionRead $obj -ClosedSessionId $closedSid -NowUtc $nG) }
    function New-SR($h) { return @{ Ok = $true; Why = ""; Obj = [pscustomobject]$h } }
    $futureEnd = $nG.AddMinutes(30).ToString("yyyy-MM-ddTHH:mm:ssZ"); $pastEnd = $nG.AddMinutes(-10).ToString("yyyy-MM-ddTHH:mm:ssZ")
    Assert-True (-not (Get-G @{ Ok = $false; Why = "absent"; Obj = $null } "s-A").AllowClose) "session.json absent or unreadable: hold (cannot tell)"
    Assert-True (-not (Get-G (New-SR @{ baySessionId = "s-A" }) "s-A").AllowClose) "no status: hold"
    Assert-True ((Get-G (New-SR @{ status = "ENDED"; baySessionId = "s-A"; sessionEndUtc = $pastEnd }) "s-A").AllowClose) "ENDED for the closed intent's own session: allow"
    Assert-True (-not (Get-G (New-SR @{ status = "ENDED"; baySessionId = "s-B"; sessionEndUtc = $pastEnd }) "s-A").AllowClose) "ENDED for ANOTHER session (a late End rewrote it): hold"
    Assert-True (-not (Get-G (New-SR @{ status = "ENDED"; sessionEndUtc = $pastEnd }) "s-A").AllowClose) "ENDED naming no session: hold"
    Assert-True (-not (Get-G (New-SR @{ status = "ENDED"; baySessionId = "" }) "").AllowClose) "ENDED with an empty id and a closed intent naming none: hold (empty never matches)"
    Assert-True (-not (Get-G (New-SR @{ status = "ENDED"; baySessionId = "S-A" }) "s-A").AllowClose) "ENDED for the same id in another case: hold (both come from the same End payload, so exact)"
    Assert-True (-not (Get-G (New-SR @{ status = "ended"; baySessionId = "s-A" }) "s-A").AllowClose) "a lower-case ended: hold"
    Assert-True (-not (Get-G (New-SR @{ status = "ENDED"; baySessionId = 7 }) "7").AllowClose) "a session id that is not text: hold"
    Assert-True (-not (Get-G (New-SR @{ status = "READY" }) "s-A").AllowClose) "READY (a Reset wrote it; a member may still be playing): hold"
    Assert-True (-not (Get-G (New-SR @{ status = "READY"; baySessionId = "s-A" }) "s-A").AllowClose) "READY even naming the closed session: hold (only ENDED is evidence)"
    Assert-True (-not (Get-G (New-SR @{ status = "PREP"; baySessionId = "s-A" }) "s-A").AllowClose) "PREP even naming the closed session: hold"
    Assert-True (-not (Get-G (New-SR @{ status = "ACTIVE"; baySessionId = "s-A"; sessionEndUtc = $futureEnd }) "s-A").AllowClose) "ACTIVE even for the session the intent says ended: hold (the two sources disagree; fail-open review)"
    Assert-True (-not (Get-G (New-SR @{ status = "ACTIVE"; baySessionId = "s-B"; sessionEndUtc = $futureEnd }) "s-A").AllowClose) "ACTIVE for ANOTHER session still within its time: hold"
    Assert-True (-not (Get-G (New-SR @{ status = "ENDING"; baySessionId = "s-B"; sessionEndUtc = $futureEnd }) "s-A").AllowClose) "ENDING (last five minutes) for another session: hold"
    Assert-True (-not (Get-G (New-SR @{ status = "ACTIVE"; baySessionId = "s-B"; sessionEndUtc = $futureEnd }) "").AllowClose) "a closed intent naming no session, another running: hold"
    Assert-True (-not (Get-G (New-SR @{ status = "ACTIVE"; baySessionId = "s-B" }) "s-A").AllowClose) "ACTIVE for another session with no readable end: hold"
    Assert-True (-not (Get-G (New-SR @{ status = "ACTIVE"; baySessionId = "s-B"; sessionEndUtc = $pastEnd }) "s-A").AllowClose) "ACTIVE for another session past its end (no End arrived, or an extension the agent never heard of): hold"
    Assert-True (-not (Get-G (New-SR @{ status = "active"; baySessionId = "s-B"; sessionEndUtc = $futureEnd }) "s-A").AllowClose) "an unknown status (here lower case) for another session within its time: hold"
    Assert-True (-not (Get-G (New-SR @{ status = "STOP"; baySessionId = "s-B"; sessionEndUtc = $futureEnd }) "s-A").AllowClose) "STOP (the emergency-stop banner) over another session within its time: hold"
    Assert-True (-not (Get-G (New-SR @{ status = "PREP"; baySessionId = "s-C"; sessionEndUtc = $futureEnd }) "s-A").AllowClose) "PREP of the next booking (written at end minus 15 while a member plays, X2b): hold"
    Assert-True (-not (Get-G (New-SR @{ status = "STOP"; baySessionId = "s-A"; sessionEndUtc = $pastEnd }) "s-A").AllowClose) "STOP even naming the closed session: hold"
    Assert-True (-not (Get-G (New-SR @{ status = 5; baySessionId = "s-B" }) "s-A").AllowClose) "a status that is not text: hold"

    Section "K20 a restart needs session.json to run the wanted session (security review: source divergence)"
    function Get-B($obj, [string]$wantedSid) { return (Get-KioskSessionBacksWanted -SessionRead $obj -WantedSessionId $wantedSid) }
    Assert-True ((Get-B (New-SR @{ status = "ACTIVE"; baySessionId = "s-A" }) "s-A").Backed) "ACTIVE, same session: restart allowed"
    Assert-True ((Get-B (New-SR @{ status = "ENDING"; baySessionId = "s-A" }) "s-A").Backed) "ENDING (last five minutes), same session: restart allowed"
    Assert-True (-not (Get-B (New-SR @{ status = "ENDED"; baySessionId = "s-A" }) "s-A").Backed) "ENDED for the wanted session (its End's intent write failed): no restart"
    Assert-True (-not (Get-B (New-SR @{ status = "ACTIVE"; baySessionId = "s-B" }) "s-A").Backed) "ACTIVE for ANOTHER session: no restart for this one"
    Assert-True (-not (Get-B @{ Ok = $false; Why = "absent"; Obj = $null } "s-A").Backed) "session.json unreadable: no restart"
    Assert-True (-not (Get-B (New-SR @{ status = "ACTIVE"; baySessionId = "s-A" }) "").Backed) "an intent naming no session: no restart"
    Assert-True (-not (Get-B (New-SR @{ status = "ACTIVE" }) "s-A").Backed) "session.json naming no session: no restart"
    Assert-True (-not (Get-B (New-SR @{ status = "active"; baySessionId = "s-A" }) "s-A").Backed) "an unknown status: no restart"
    Assert-True (-not (Get-B (New-SR @{ status = "STOP"; baySessionId = "s-A" }) "s-A").Backed) "STOP: no restart"

    [void](Execute-Command -CommandType $CMD_STARTSESSION -PayloadJson (New-Payload "Start" "s-3") -BayLabel "Bay")
    $later = (Get-Date).ToUniversalTime().AddMinutes(80).ToString("yyyy-MM-ddTHH:mm:ssZ")
    [void](Execute-Command -CommandType $CMD_UPDATESESSIONDISPLAY -PayloadJson ('{"mode":"Warn5","baySessionId":"s-3","playEndUtc":"' + $later + '"}') -BayLabel "Bay")
    $wNow = Get-IntentNow
    Assert-True ($wNow.Wanted -and $wNow.UntilUtc -eq (ConvertTo-KioskUtc $later).AddSeconds(120)) "UpdateSessionDisplay with a later end for the same session extends the intent"
    [void](Execute-Command -CommandType $CMD_EMERGENCY_STOP -PayloadJson '{"action":"engage","reason":"test"}' -BayLabel "Bay")
    $we = Get-IntentNow
    Assert-True (-not $we.Wanted -and -not $we.Closed -and (Get-IntentField "launcher") -eq "unmanaged") "emergency stop during a session: unmanaged (no restarts, closes nothing)"
    $script:LauncherStarts = 0
    $res = Execute-Command -CommandType $CMD_STARTSESSION -PayloadJson (New-Payload "Start" "s-4") -BayLabel "Bay"
    Assert-True ((Get-IntentField "launcher") -eq "unmanaged" -and $script:LauncherStarts -eq 0 -and $res.note -eq "emergency_stop_engaged") "Start while the stop is engaged: refused, unmanaged"
    $Global:EmergencyStopEngaged = $false

    # ============================================================ K14
    # ============================================================ K16 (security review 2026-10-08)
    Section "K16 a verified shell file replaced with the same size and write time is verified again (content-keyed cache)"
    function Get-TestSha([string]$p) { $a = [Security.Cryptography.SHA256]::Create(); try { return ([BitConverter]::ToString($a.ComputeHash([IO.File]::ReadAllBytes($p))) -replace "-", "") } finally { $a.Dispose() } }
    $script:SignedSha = Get-TestSha $goodShell
    function Get-KioskAuthenticode([string]$Path) {
        # Valid only for the exact bytes that were "signed"; any other content reads as NotSigned.
        if ((Get-TestSha $Path) -eq $script:SignedSha) { return @{ Status = "Valid"; Timestamped = $true; Thumbprint = "AAAA"; Error = $null } }
        return @{ Status = "NotSigned"; Timestamped = $false; Thumbprint = $null; Error = $null }
    }
    $KioskReleaseMode = "companion"; $Global:KioskSignerThumbprint = "AAAA"
    Set-TestFile $KioskPolicyPath "{`"schema`":1,`"mode`":`"companion`",`"minShellBytes`":4096}"
    Reset-K9
    $now16 = (Get-Date).ToUniversalTime()
    Invoke-KioskReconcileTick -NowUtc $now16 -CommandLineOf $clGone -StartShell $startSb -StopProcess $stopSb
    Assert-True ($script:Started.Count -eq 1) "precondition: the signed file verified and a shell was started"
    $origBytes = [IO.File]::ReadAllBytes($goodShell)
    $origTime = (Get-Item -LiteralPath $goodShell).LastWriteTimeUtc
    $tampered = [byte[]]$origBytes.Clone()
    $idx = [Array]::IndexOf($tampered, [byte][char]'W')
    $tampered[$idx] = [byte][char]'X'
    [IO.File]::WriteAllBytes($goodShell, $tampered)
    (Get-Item -LiteralPath $goodShell).LastWriteTimeUtc = $origTime
    $fiT = Get-Item -LiteralPath $goodShell
    Assert-True ($fiT.Length -eq $origBytes.Length -and $fiT.LastWriteTimeUtc -eq $origTime -and (Get-TestSha $goodShell) -ne $script:SignedSha) "precondition: same size, same write time, different bytes"
    $script:Started.Clear()
    Invoke-KioskReconcileTick -NowUtc $now16.AddMinutes(1) -CommandLineOf $clGone -StartShell $startSb -StopProcess $stopSb
    Assert-True ($script:Started.Count -eq 0 -and $Global:KioskReport.action -match "NotSigned" -and $Global:KioskReport.shellFile.ok -eq $false) "the replaced file is verified again and refused (no stale 'verified')"
    [IO.File]::WriteAllBytes($goodShell, $origBytes)
    function Get-KioskAuthenticode([string]$Path) { return $script:SigFake }

    # ============================================================ K17 (security review 2026-10-08)
    Section "K17 an intent edited behind the agent's back is put back before anything acts on it"
    Reset-K9
    $Global:KioskIntentTamper = $null
    [void](Write-KioskIntent -Launcher "closed" -UntilUtc $null -SessionId "s-1" -Reason "EndSession")
    Set-TestFile $KioskIntentPath "{`"schema`":1,`"launcher`":`"wanted`",`"untilUtc`":`"2099-01-01T00:00:00Z`",`"baySessionId`":`"x`"}"
    Assert-True (Test-KioskIntentIntegrity) "an edited intent (free play until 2099) is detected"
    $w17 = Get-KioskLauncherWanted -IntentRead (Read-KioskJsonFile -Path $KioskIntentPath) -NowUtc ((Get-Date).ToUniversalTime())
    Assert-True ($w17.Closed -and -not $w17.Wanted -and $Global:KioskIntentTamper.count -eq 1) "...restored to what the agent wrote (closed), and counted"
    Assert-True (-not (Test-KioskIntentIntegrity)) "an untouched intent: nothing to restore"
    Remove-Item -LiteralPath $KioskIntentPath -Force
    Assert-True ((Test-KioskIntentIntegrity) -and (Get-KioskLauncherWanted -IntentRead (Read-KioskJsonFile -Path $KioskIntentPath) -NowUtc ((Get-Date).ToUniversalTime())).Closed) "a deleted intent is restored too"
    Set-TestFile $KioskIntentPath "{`"schema`":1,`"launcher`":`"wanted`",`"untilUtc`":`"2099-01-01T00:00:00Z`"}"
    $Global:KioskNextReconcileUtc = [DateTime]::MaxValue
    Invoke-KioskReconcileTickIfDue -NowUtc ((Get-Date).ToUniversalTime())
    $Global:KioskNextReconcileUtc = [DateTime]::MinValue
    Assert-True ((Get-KioskLauncherWanted -IntentRead (Read-KioskJsonFile -Path $KioskIntentPath) -NowUtc ((Get-Date).ToUniversalTime())).Closed) "the main-loop check restores it every pass, even when the reconcile is not due"
    Set-TestFile $KioskIntentPath "{`"schema`":1,`"launcher`":`"wanted`",`"untilUtc`":`"2099-01-01T00:00:00Z`",`"baySessionId`":`"s-1`"}"
    [void](Set-KioskIntentForCommand -CommandType $CMD_RESET -Mode "" -Payload ([pscustomobject]@{}))
    Assert-True ((Get-KioskLauncherWanted -IntentRead (Read-KioskJsonFile -Path $KioskIntentPath) -NowUtc ((Get-Date).ToUniversalTime())).Closed) "a command decides from the restored intent, not the edited one (Reset after an edit to 'wanted' still closes)"
    $capT = ConvertTo-Json -InputObject (Get-KioskCapability) -Depth 6 -Compress
    Assert-True ($capT -match '"intentRestored":\{"count":[0-9]+') "the capability report carries the restore count"
    $CfgPath = Join-Path $Sandbox "agent-config.json"
    Set-TestFile $CfgPath ("{`"sessionJsonPath`":" + (ConvertTo-Json -InputObject ([string]$cfg.sessionJsonPath)) + "}")
    Assert-True ((Get-KioskCapability)["sessionJsonPathSharedWithShell"] -eq $true) "the report says the agent and the shell read the same session.json"
    Set-TestFile $CfgPath "{`"sessionJsonPath`":`"C:\\Elsewhere\\session.json`"}"
    Assert-True ((Get-KioskCapability)["sessionJsonPathSharedWithShell"] -eq $false) "...and says so when a platform overlay moved the agent's (the shell would then neither restart nor close)"
    Remove-Item -LiteralPath $CfgPath -Force
    Remove-Item -LiteralPath $KioskIntentPath -Force
    $Global:KioskIntentExpectedText = $null

    Section "K14 the shell's one closer ends only the process it began to close (real process, injected clock)"
    foreach ($st in @($ShellAst.EndBlock.Statements)) {
        if ($st -is [System.Management.Automation.Language.AssignmentStatementAst] -and $st.Left.Extent.Text -match '^\$KioskClose') { . ([scriptblock]::Create($st.Extent.Text)) }
    }
    $dummy = Start-Process -FilePath (Join-Path $env:WINDIR "System32\PING.EXE") -ArgumentList "-n 300 127.0.0.1" -WindowStyle Hidden -PassThru
    try {
        $own = [System.Diagnostics.Process]::GetCurrentProcess().SessionId
        $S14 = @{ Closing = @{}; Cfg = @{ LauncherName = "PING"; LauncherPath = (Join-Path $env:WINDIR "System32\PING.EXE") }; SessionId = $own }
        function Test-DummyAlive { try { $p = Get-Process -Id $dummy.Id -ErrorAction Stop; return (-not $p.HasExited) } catch { return $false } }
        $t0 = (Get-Date).ToUniversalTime()
        Close-KioskLauncher -S $S14 -Procs @(Get-Process -Id $dummy.Id -ErrorAction SilentlyContinue) -NowUtc $t0
        Assert-True ((Test-DummyAlive) -and $S14.Closing.ContainsKey($dummy.Id)) "first pass: asked to close (no window here), recorded, not ended"
        Close-KioskLauncher -S $S14 -Procs @(Get-Process -Id $dummy.Id -ErrorAction SilentlyContinue) -NowUtc $t0.AddSeconds(5)
        Assert-True (Test-DummyAlive) "5 s later: not ended yet (the polite close gets $KioskCloseKillAfterSeconds s)"
        if ($S14.Closing.ContainsKey($dummy.Id)) { $S14.Closing[$dummy.Id]["Start"] = ([DateTime]$S14.Closing[$dummy.Id]["Start"]).AddSeconds(-30) }
        Close-KioskLauncher -S $S14 -Procs @(Get-Process -Id $dummy.Id -ErrorAction SilentlyContinue) -NowUtc $t0.AddSeconds(9)
        Assert-True ((Test-DummyAlive) -and -not $S14.Closing.ContainsKey($dummy.Id)) "a different start time than recorded (a reused id): NOT ended, and forgotten"
        $S14.Cfg = @{ LauncherName = "SomethingElse"; LauncherPath = (Join-Path $env:WINDIR "System32\PING.EXE") }
        Close-KioskLauncher -S $S14 -Procs @(Get-Process -Id $dummy.Id -ErrorAction SilentlyContinue) -NowUtc $t0.AddSeconds(10)
        Close-KioskLauncher -S $S14 -Procs @(Get-Process -Id $dummy.Id -ErrorAction SilentlyContinue) -NowUtc $t0.AddSeconds(19)
        Assert-True (Test-DummyAlive) "a process that is not the configured launcher: NOT ended"
        $S14.Cfg = @{ LauncherName = "PING"; LauncherPath = (Join-Path $env:WINDIR "System32\PING.EXE") }; $S14.SessionId = $own + 1000
        Close-KioskLauncher -S $S14 -Procs @(Get-Process -Id $dummy.Id -ErrorAction SilentlyContinue) -NowUtc $t0.AddSeconds(20)
        Close-KioskLauncher -S $S14 -Procs @(Get-Process -Id $dummy.Id -ErrorAction SilentlyContinue) -NowUtc $t0.AddSeconds(29)
        Assert-True (Test-DummyAlive) "a process in another session: NOT ended"
        $S14.SessionId = $own
        $S14.Cfg = @{ LauncherName = "PING"; LauncherPath = "C:\AbgNoSuch\PING.EXE" }
        Close-KioskLauncher -S $S14 -Procs @(Get-Process -Id $dummy.Id -ErrorAction SilentlyContinue) -NowUtc $t0.AddSeconds(30)
        Close-KioskLauncher -S $S14 -Procs @(Get-Process -Id $dummy.Id -ErrorAction SilentlyContinue) -NowUtc $t0.AddSeconds(39)
        Assert-True ((Test-DummyAlive) -and $S14.Closing.Count -eq 0) "the configured NAME but another PATH (attack R2: a bare name in the bay-writable config): NOT ended, never even asked"
        $S14.Closing.Clear()
        $S14.Cfg = @{ LauncherName = "PING"; LauncherPath = (Join-Path $env:WINDIR "System32\PING.EXE") }
        $me = [System.Diagnostics.Process]::GetCurrentProcess()
        Assert-True (-not (Test-KioskIsConfiguredLauncher -Proc $me -Cfg @{ LauncherName = $me.ProcessName; LauncherPath = $me.Path } -SessionId $own)) "a config naming powershell or pwsh (this test's own process, exact path): never a launcher"
        Close-KioskLauncher -S $S14 -Procs @(Get-Process -Id $dummy.Id -ErrorAction SilentlyContinue) -NowUtc $t0.AddSeconds(30)
        Close-KioskLauncher -S $S14 -Procs @(Get-Process -Id $dummy.Id -ErrorAction SilentlyContinue) -NowUtc $t0.AddSeconds(39)
        $gone = $false; for ($i = 0; $i -lt 20 -and -not $gone; $i++) { if (-not (Test-DummyAlive)) { $gone = $true } else { Start-Sleep -Milliseconds 200 } }
        Assert-True $gone "the configured launcher, same session, same start, 9 s after the polite close: ended"
    } finally {
        try { if (-not $dummy.HasExited) { Stop-Process -Id $dummy.Id -Force -ErrorAction SilentlyContinue } } catch { }
    }
}
finally {
    try { Remove-Item -LiteralPath $Sandbox -Recurse -Force -ErrorAction SilentlyContinue } catch {}
}

Write-Host ""
Write-Host ("RESULT: {0} passed, {1} failed" -f $script:Pass, $script:Fail) -ForegroundColor $(if ($script:Fail -eq 0) { "Green" } else { "Red" })
if ($script:Fail -gt 0) { $script:Failures | ForEach-Object { Write-Host "  - $_" -ForegroundColor Red }; exit 1 }
exit 0
