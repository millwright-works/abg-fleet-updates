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
    if ($lhs -match '^\$(CMD_|AGENTSTATUS_|Kiosk)' -or $lhs -match '^\$Global:Kiosk') { . ([scriptblock]::Create($st.Extent.Text)) }
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
    Assert-True ((Get-KioskIntentForCommand -CommandType $CMD_RESET -Mode "" -Payload ([pscustomobject]@{}) -CurrentIntentRead $none -SameSession $true -EmergencyStopEngaged $false -NowUtc $UtcNow).Launcher -eq "closed") "Reset with nothing wanted: closed"
    Assert-True ($null -eq (Get-KioskIntentForCommand -CommandType $CMD_RESET -Mode "" -Payload ([pscustomobject]@{}) -CurrentIntentRead $curWanted -SameSession $true -EmergencyStopEngaged $false -NowUtc $UtcNow)) "Reset while a session is wanted (a canceled OTHER booking): no change, never closed over a game"
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
    # A readable intent outlives the restart, whatever session.json says.
    Set-TestFile $sj (ConvertTo-Json -InputObject ([ordered]@{ status = "ENDED"; baySessionId = "s-old"; sessionEndUtc = $now6.AddMinutes(-90).ToString("yyyy-MM-ddTHH:mm:ssZ") }))
    [void](Write-KioskIntent -Launcher "wanted" -UntilUtc ($now6.AddMinutes(40)) -SessionId "s-9" -Reason "test")
    Initialize-KioskIntent -NowUtc $now6
    $w = Read-IntentNow6
    Assert-True ($w.Wanted -and $w.SessionId -eq "s-9") "a readable wanted intent is kept although session.json says ENDED for an older session"
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
    Assert-True ($closeCalls.Count -eq 1 -and $closeCalls[0].Parent.Parent.Extent.Text -match '^\{\s*Close-KioskLauncher' -and $closeCalls[0].Parent.Parent.Parent.Extent.Text -match '^switch \(\$action\)') "...reached only from the 'close' clause of the launcher action switch"
    $closeText = Get-DefText $ShellDefs "Close-KioskLauncher"
    Assert-True ($closeText -match '\$fresh\.ProcessName -ine \[string\]\$S\.Cfg\.LauncherName -or \$fresh\.SessionId -ne \$S\.SessionId -or \$null -eq \$fst -or \$fst -ne \$rec\.Start') "...and it re-checks name, session and start time before ending anything"
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
                     "Normalize-SessionModel", "UtcNow-Z", "Get-HelpText", "Get-LauncherConfigFromPayloadOrConfig", "Write-SessionFiles", "Set-EmergencyStopBanner", "Get-SessionJsPath")) {
        . ([scriptblock]::Create((Get-DefText $AgentDefs $n)))
    }
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
    Assert-True ($res.launcher.shell.running -eq $true) "...and the result reports the shell's launcher running"
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
    Assert-True ((Get-IntentNow).Closed) "Reset with nothing playing: closed"

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
    Section "K14 the shell's one closer ends only the process it began to close (real process, injected clock)"
    foreach ($st in @($ShellAst.EndBlock.Statements)) {
        if ($st -is [System.Management.Automation.Language.AssignmentStatementAst] -and $st.Left.Extent.Text -match '^\$KioskClose') { . ([scriptblock]::Create($st.Extent.Text)) }
    }
    $dummy = Start-Process -FilePath (Join-Path $env:WINDIR "System32\PING.EXE") -ArgumentList "-n 300 127.0.0.1" -WindowStyle Hidden -PassThru
    try {
        $own = [System.Diagnostics.Process]::GetCurrentProcess().SessionId
        $S14 = @{ Closing = @{}; Cfg = @{ LauncherName = "PING" }; SessionId = $own }
        function Test-DummyAlive { try { $p = Get-Process -Id $dummy.Id -ErrorAction Stop; return (-not $p.HasExited) } catch { return $false } }
        $t0 = (Get-Date).ToUniversalTime()
        Close-KioskLauncher -S $S14 -Procs @(Get-Process -Id $dummy.Id) -NowUtc $t0
        Assert-True ((Test-DummyAlive) -and $S14.Closing.ContainsKey($dummy.Id)) "first pass: asked to close (no window here), recorded, not ended"
        Close-KioskLauncher -S $S14 -Procs @(Get-Process -Id $dummy.Id) -NowUtc $t0.AddSeconds(5)
        Assert-True (Test-DummyAlive) "5 s later: not ended yet (the polite close gets $KioskCloseKillAfterSeconds s)"
        $S14.Closing[$dummy.Id].Start = ([DateTime]$S14.Closing[$dummy.Id].Start).AddSeconds(-30)
        Close-KioskLauncher -S $S14 -Procs @(Get-Process -Id $dummy.Id) -NowUtc $t0.AddSeconds(9)
        Assert-True ((Test-DummyAlive) -and -not $S14.Closing.ContainsKey($dummy.Id)) "a different start time than recorded (a reused id): NOT ended, and forgotten"
        $S14.Cfg = @{ LauncherName = "SomethingElse" }
        Close-KioskLauncher -S $S14 -Procs @(Get-Process -Id $dummy.Id) -NowUtc $t0.AddSeconds(10)
        Close-KioskLauncher -S $S14 -Procs @(Get-Process -Id $dummy.Id) -NowUtc $t0.AddSeconds(19)
        Assert-True (Test-DummyAlive) "a process that is not the configured launcher: NOT ended"
        $S14.Cfg = @{ LauncherName = "PING" }; $S14.SessionId = $own + 1000
        Close-KioskLauncher -S $S14 -Procs @(Get-Process -Id $dummy.Id) -NowUtc $t0.AddSeconds(20)
        Close-KioskLauncher -S $S14 -Procs @(Get-Process -Id $dummy.Id) -NowUtc $t0.AddSeconds(29)
        Assert-True (Test-DummyAlive) "a process in another session: NOT ended"
        $S14.SessionId = $own
        Close-KioskLauncher -S $S14 -Procs @(Get-Process -Id $dummy.Id) -NowUtc $t0.AddSeconds(30)
        Close-KioskLauncher -S $S14 -Procs @(Get-Process -Id $dummy.Id) -NowUtc $t0.AddSeconds(39)
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
