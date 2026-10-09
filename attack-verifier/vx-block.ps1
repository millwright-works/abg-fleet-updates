    # ================= VERIFIER ATTACK (kiosk-rr1-r7 @ 41ac9ec5, 2026-10-09). Observations, not assertions.
    Section "VX verifier attack on the Reset gate (observations)"
    $script:VX = New-Object System.Collections.ArrayList
    function VX([string]$id, [string]$text) { [void]$script:VX.Add("$id | $text"); Write-Host "  VX $id | $text" }
    $script:DisplayCalls = 0; $script:FacilityModes = @()
    function Invoke-FacilitySetMode { param([string]$Mode, $payloadObj) $script:FacilityModes += $Mode; return @{ ok = $true; scene = $Mode } }
    function Start-SessionDisplay($payloadObj) { $script:DisplayCalls++; return @{ started = $false; reason = "stub" } }
    function Stop-SessionDisplay { $script:DisplayCalls++; return @{ stopped = $false; reason = "stub" } }
    function Reset-Counters { $script:DisplayCalls = 0; $script:FacilityModes = @() }
    $vxSess = Join-Path $Sandbox "session.json"
    function Get-SessStatus { try { $o = [IO.File]::ReadAllText($vxSess) | ConvertFrom-Json; return ("{0}/{1}" -f (Get-PropValue $o "status" "<none>"), (Get-PropValue $o "baySessionId" "<none>")) } catch { return "unreadable" } }
    function Get-IntentText { $w = Get-IntentNow; return ("wanted={0} closed={1} sid={2}" -f $w.Wanted, $w.Closed, $w.SessionId) }
    function Fmt-Reset($r) { return ("reset={0} skipped={1} why=[{2}] display calls={3} facility=[{4}] wall now {5}" -f (Get-PropValue $r "reset" $null), (Get-PropValue $r "skipped" $null), (Get-PropValue $r "reason" $null), $script:DisplayCalls, ($script:FacilityModes -join ","), (Get-SessStatus)) }
    # The REAL emergency stop internals (the suite stubs Invoke-EmergencyStopInternal with one that never touches session.json).
    function Save-EmergencyStopState { param([bool]$Engaged, [string]$Reason) return @{ Ok = $true; Detail = "vx stub persist" } }
    . ([scriptblock]::Create((Get-DefText $AgentDefs "Invoke-EmergencyStopInternal")))
    . ([scriptblock]::Create((Get-DefText $AgentDefs "Clear-EmergencyStopInternal")))
    $Global:EmergencyStopEngaged = $false

    # X0 control: the builder's case.
    [void](Execute-Command -CommandType $CMD_STARTSESSION -PayloadJson (New-Payload "Start" "s-x0") -BayLabel "Bay")
    Reset-Counters; $r = Execute-Command -CommandType $CMD_RESET -PayloadJson $resetJson -BayLabel "Bay"
    VX "X0" ("control: s-x0 ACTIVE, cancel Reset: " + (Fmt-Reset $r))
    [void](Execute-Command -CommandType $CMD_ENDSESSION -PayloadJson (New-Payload "End" "s-x0") -BayLabel "Bay")

    # X1 real e-stop engaged then cleared mid-session (A0.457: the game keeps running), then another booking's cancel Reset.
    [void](Execute-Command -CommandType $CMD_STARTSESSION -PayloadJson (New-Payload "Start" "s-x1") -BayLabel "Bay")
    $a = Get-SessStatus
    [void](Execute-Command -CommandType $CMD_EMERGENCY_STOP -PayloadJson '{"action":"engage","reason":"t"}' -BayLabel "Bay")
    $b = Get-SessStatus
    [void](Execute-Command -CommandType $CMD_EMERGENCY_STOP -PayloadJson '{"action":"clear"}' -BayLabel "Bay")
    $c = Get-SessStatus
    Reset-Counters; $r = Execute-Command -CommandType $CMD_RESET -PayloadJson $resetJson -BayLabel "Bay"
    VX "X1" ("Start -> $a; e-stop engage -> $b; clear -> $c (engaged=$Global:EmergencyStopEngaged); cancel Reset: " + (Fmt-Reset $r) + "; intent " + (Get-IntentText))
    [void](Execute-Command -CommandType $CMD_ENDSESSION -PayloadJson (New-Payload "End" "s-x1") -BayLabel "Bay")

    # X1b RR1 through STOP: P ends (closed P); Q's Start intent write keeps failing; e-stop engage and clear; cancel Reset.
    [void](Execute-Command -CommandType $CMD_STARTSESSION -PayloadJson (New-Payload "Start" "s-P") -BayLabel "Bay")
    [void](Execute-Command -CommandType $CMD_ENDSESSION -PayloadJson (New-Payload "End" "s-P") -BayLabel "Bay")
    $lockX = New-Object IO.FileStream($KioskIntentPath, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
    try {
        [void](Execute-Command -CommandType $CMD_STARTSESSION -PayloadJson (New-Payload "Start" "s-Q") -BayLabel "Bay")
        $v0 = Get-ShellVerdictNow; $s0 = Get-SessStatus
        [void](Execute-Command -CommandType $CMD_EMERGENCY_STOP -PayloadJson '{"action":"engage","reason":"t"}' -BayLabel "Bay")
        [void](Execute-Command -CommandType $CMD_EMERGENCY_STOP -PayloadJson '{"action":"clear"}' -BayLabel "Bay")
        $v1 = Get-ShellVerdictNow; $s1 = Get-SessStatus
        Reset-Counters; $r = Execute-Command -CommandType $CMD_RESET -PayloadJson $resetJson -BayLabel "Bay"
        $v2 = Get-ShellVerdictNow
        VX "X1b" ("Q playing, intent file " + (Get-IntentText) + "; after Q Start: wall $s0 shell=$v0; after e-stop engage+clear: wall $s1 shell=$v1; cancel Reset: " + (Fmt-Reset $r) + "; shell verdict on Q's running launcher=$v2")
    } finally { $lockX.Dispose() }
    $Global:KioskNextReconcileUtc = [DateTime]::MaxValue; Invoke-KioskReconcileTickIfDue -NowUtc ((Get-Date).ToUniversalTime()); $Global:KioskNextReconcileUtc = [DateTime]::MinValue
    [void](Execute-Command -CommandType $CMD_ENDSESSION -PayloadJson (New-Payload "End" "s-Q") -BayLabel "Bay")

    # X2 back-to-back: A plays; B's Prep lands at A's end minus 15 (BayCreateAutomationsPolicy.PrepNotBefore); B is canceled.
    [void](Execute-Command -CommandType $CMD_STARTSESSION -PayloadJson (New-Payload "Start" "s-A2") -BayLabel "Bay")
    [void](Execute-Command -CommandType $CMD_STARTSESSION -PayloadJson (New-Payload "Prep" "s-B2") -BayLabel "Bay")
    $a = Get-SessStatus
    Reset-Counters; $r = Execute-Command -CommandType $CMD_RESET -PayloadJson $resetJson -BayLabel "Bay"
    VX "X2" ("A2 playing, B2 Prep -> wall $a; B2's cancel Reset: " + (Fmt-Reset $r) + "; intent " + (Get-IntentText))
    [void](Execute-Command -CommandType $CMD_ENDSESSION -PayloadJson (New-Payload "End" "s-A2") -BayLabel "Bay")

    # X2b RR1 through Prep, with NO Reset: P2 closed; A's Start write keeps failing; next booking's Prep at A's end minus 15.
    [void](Execute-Command -CommandType $CMD_STARTSESSION -PayloadJson (New-Payload "Start" "s-P2") -BayLabel "Bay")
    [void](Execute-Command -CommandType $CMD_ENDSESSION -PayloadJson (New-Payload "End" "s-P2") -BayLabel "Bay")
    $lockX = New-Object IO.FileStream($KioskIntentPath, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
    try {
        [void](Execute-Command -CommandType $CMD_STARTSESSION -PayloadJson (New-Payload "Start" "s-A2b") -BayLabel "Bay")
        $v0 = Get-ShellVerdictNow
        [void](Execute-Command -CommandType $CMD_STARTSESSION -PayloadJson (New-Payload "Prep" "s-B2b") -BayLabel "Bay")
        $v1 = Get-ShellVerdictNow
        VX "X2b" ("A2b playing (intent write pending), before Prep shell=$v0; after B2b's Prep: wall " + (Get-SessStatus) + " shell=$v1 (no Reset involved)")
    } finally { $lockX.Dispose() }
    $Global:KioskNextReconcileUtc = [DateTime]::MaxValue; Invoke-KioskReconcileTickIfDue -NowUtc ((Get-Date).ToUniversalTime()); $Global:KioskNextReconcileUtc = [DateTime]::MinValue
    [void](Execute-Command -CommandType $CMD_ENDSESSION -PayloadJson (New-Payload "End" "s-A2b") -BayLabel "Bay")

    # X3 back-to-back, B's rows created first: at A's end both A's End and B's Start are due; the agent takes createdon asc.
    [void](Execute-Command -CommandType $CMD_STARTSESSION -PayloadJson (New-Payload "Start" "s-A3") -BayLabel "Bay")
    [void](Execute-Command -CommandType $CMD_STARTSESSION -PayloadJson (New-Payload "Start" "s-B3") -BayLabel "Bay")
    $rEnd = Execute-Command -CommandType $CMD_ENDSESSION -PayloadJson (New-Payload "End" "s-A3") -BayLabel "Bay"
    $a = Get-SessStatus
    Reset-Counters; $r = Execute-Command -CommandType $CMD_RESET -PayloadJson $resetJson -BayLabel "Bay"
    VX "X3" ("B3 playing, A3's End after B3's Start -> wall $a (launcher: $(Get-PropValue (Get-PropValue $rEnd "launcherStopped" $null) "reason" $null)); a cancel Reset: " + (Fmt-Reset $r) + "; intent " + (Get-IntentText))
    [void](Execute-Command -CommandType $CMD_ENDSESSION -PayloadJson (New-Payload "End" "s-B3") -BayLabel "Bay")

    # X4 stale rule: session.json end 16 min / 14 min ago (an extension whose display update was not queued keeps the old end).
    foreach ($ago in @(16, 14)) {
        $e = (Get-Date).ToUniversalTime().AddMinutes(-$ago).ToString("yyyy-MM-ddTHH:mm:ssZ")
        [void](Execute-Command -CommandType $CMD_STARTSESSION -PayloadJson ('{"mode":"Start","baySessionId":"s-x4","startUtc":"2026-10-08T12:00:00Z","playEndUtc":"' + $e + '","endUtc":"' + $e + '"}') -BayLabel "Bay")
        Reset-Counters; $r = Execute-Command -CommandType $CMD_RESET -PayloadJson $resetJson -BayLabel "Bay"
        VX "X4-$ago" ("ACTIVE, session.json end $ago min ago: " + (Fmt-Reset $r))
    }

    # X5 session.json shapes under a running session (end in 30 min), each through the real handler.
    $fut = (Get-Date).ToUniversalTime().AddMinutes(30).ToString("yyyy-MM-ddTHH:mm:ssZ")
    $good = '{"status":"ACTIVE","baySessionId":"s-x5","sessionEndUtc":"' + $fut + '"}'
    $u8 = New-Object Text.UTF8Encoding($false)
    $shapes = [ordered]@{
        "valid ACTIVE" = $u8.GetBytes($good)
        "BOM + valid ACTIVE" = ([byte[]](0xEF, 0xBB, 0xBF) + $u8.GetBytes($good))
        "0 bytes" = [byte[]]@()
        "whitespace" = $u8.GetBytes("   `r`n ")
        "NUL x 64 (power loss)" = (New-Object byte[] 64)
        "BOM only" = [byte[]](0xEF, 0xBB, 0xBF)
        "null" = $u8.GetBytes("null")
        "{}" = $u8.GetBytes("{}")
        "[]" = $u8.GetBytes("[]")
        "truncated mid-write" = $u8.GetBytes($good.Substring(0, 60))
        "status lowercase" = $u8.GetBytes($good.Replace('"ACTIVE"', '"active"'))
        "status trailing space" = $u8.GetBytes($good.Replace('"ACTIVE"', '"ACTIVE "'))
        "status array" = $u8.GetBytes($good.Replace('"ACTIVE"', '["ACTIVE"]'))
        "duplicate status key" = $u8.GetBytes($good.Replace('"status":"ACTIVE"', '"status":"ACTIVE","status":"READY"'))
        "UTF-16LE ACTIVE" = ([Text.Encoding]::Unicode.GetBytes($good))
        "STOP (e-stop wrote it)" = $u8.GetBytes($good.Replace('"ACTIVE"', '"STOP"'))
    }
    foreach ($k in $shapes.Keys) {
        [IO.File]::WriteAllBytes($vxSess, [byte[]]$shapes[$k])
        $m = Read-SessionModelFromDisk
        $g = Get-ResetGate -SessionModel $m -Payload ([pscustomobject]@{ mode = "Full"; reason = "BookingCanceled" }) -NowUtc ((Get-Date).ToUniversalTime())
        VX "X5" ("session.json = {0}: gate Proceed={1} why=[{2}]" -f $k, $g.Proceed, $g.Why)
    }

    # X6 force variants (ACTIVE s-x6 running). [bool] of any non-empty string is True in PowerShell.
    $mR = [pscustomobject]@{ status = "ACTIVE"; baySessionId = "s-x6"; sessionEndUtc = $fut }
    foreach ($pj in @('{"force":"false"}', '{"force":"0"}', '{"force":"no"}', '{"force":0}', '{"force":false}', '{"Force":true}', '{"FORCE":"x"}', '{"force":null}', '{"force":[]}', '{"force":[false]}', '{"force":{}}', '{"force":true}')) {
        $g = Get-ResetGate -SessionModel $mR -Payload ($pj | ConvertFrom-Json) -NowUtc ((Get-Date).ToUniversalTime())
        VX "X6" ("payload {0}: Proceed={1} why=[{2}]" -f $pj, $g.Proceed, $g.Why)
    }

    # X7 id variants against a running GUID session.
    $gid = "8a4f2c10-1d2e-4f50-9a6b-7c8d9e0f1a2b"
    $mG = [pscustomobject]@{ status = "ACTIVE"; baySessionId = $gid; sessionEndUtc = $fut }
    foreach ($pid7 in @($gid, $gid.ToUpperInvariant(), "{$gid}", " $gid", "$gid ", ($gid -replace '-', ''), "", " ")) {
        $g = Get-ResetGate -SessionModel $mG -Payload ([pscustomobject]@{ mode = "Full"; baySessionId = $pid7 }) -NowUtc ((Get-Date).ToUniversalTime())
        VX "X7" ("payload id [{0}]: Proceed={1}" -f $pid7, $g.Proceed)
    }
    $g = Get-ResetGate -SessionModel $mG -Payload ('{"BAYSESSIONID":"' + $gid + '"}' | ConvertFrom-Json) -NowUtc ((Get-Date).ToUniversalTime())
    VX "X7" ("key BAYSESSIONID (other case): Proceed={0}" -f $g.Proceed)
    $g = Get-ResetGate -SessionModel ([pscustomobject]@{ status = "ACTIVE"; sessionEndUtc = $fut }) -Payload ([pscustomobject]@{ baySessionId = "" }) -NowUtc ((Get-Date).ToUniversalTime())
    VX "X7" ("running session with NO id, Reset with empty id: Proceed={0}" -f $g.Proceed)

    # X8 bay clock skew: bay clock fast by N minutes against the platform's end (a real 60-min session with 4 real min left).
    foreach ($skew in @(10, 16, 20, 80)) {
        $realNow = (Get-Date).ToUniversalTime()
        $mS = [pscustomobject]@{ status = "ACTIVE"; baySessionId = "s-x8"; sessionEndUtc = $realNow.AddMinutes(4).ToString("yyyy-MM-ddTHH:mm:ssZ") }
        $g = Get-ResetGate -SessionModel $mS -Payload ([pscustomobject]@{}) -NowUtc $realNow.AddMinutes($skew)
        VX "X8" ("bay clock +{0} min, 4 real min left: Proceed={1}" -f $skew, $g.Proceed)
    }
    # ...and how far fast must the clock be to release a session at its START (60-min session)?
    $realNow = (Get-Date).ToUniversalTime()
    $g = Get-ResetGate -SessionModel ([pscustomobject]@{ status = "ACTIVE"; baySessionId = "s-x8"; sessionEndUtc = $realNow.AddMinutes(60).ToString("yyyy-MM-ddTHH:mm:ssZ") }) -Payload ([pscustomobject]@{}) -NowUtc $realNow.AddMinutes(76)
    VX "X8" ("bay clock +76 min at the START of a 60-min session: Proceed={0}" -f $g.Proceed)

    # X9 reordered End/Reset for the same bay: running A; cancel Reset first (skipped), then A's End.
    [void](Execute-Command -CommandType $CMD_STARTSESSION -PayloadJson (New-Payload "Start" "s-x9") -BayLabel "Bay")
    $r1 = Execute-Command -CommandType $CMD_RESET -PayloadJson $resetJson -BayLabel "Bay"
    [void](Execute-Command -CommandType $CMD_ENDSESSION -PayloadJson (New-Payload "End" "s-x9") -BayLabel "Bay")
    VX "X9" ("Reset before End: first Reset reset=$(Get-PropValue $r1 "reset" $null) skipped=$(Get-PropValue $r1 "skipped" $null); after the End the wall is " + (Get-SessStatus) + " (no retry of the skipped Reset)")

    # X10 the RUNNING booking itself is canceled mid-play: the platform cancels its pending End (CommandStatusCanceled) and sends only the no-id Reset.
    [void](Execute-Command -CommandType $CMD_STARTSESSION -PayloadJson (New-Payload "Start" "s-x10") -BayLabel "Bay")
    Reset-Counters; $r = Execute-Command -CommandType $CMD_RESET -PayloadJson $resetJson -BayLabel "Bay"
    VX "X10" ("running booking canceled mid-play (its End canceled by the platform): " + (Fmt-Reset $r) + "; intent " + (Get-IntentText) + " (nothing else is queued to end it)")
    [void](Execute-Command -CommandType $CMD_ENDSESSION -PayloadJson (New-Payload "End" "s-x10") -BayLabel "Bay")

    # restore the suite's stubs so K19 onward runs as written
    function Invoke-FacilitySetMode { param([string]$Mode, $payloadObj) return @{ ok = $true; scene = $Mode } }
    function Start-SessionDisplay($payloadObj) { return @{ started = $false; reason = "stub" } }
    function Stop-SessionDisplay { return @{ stopped = $false; reason = "stub" } }
    function Invoke-EmergencyStopInternal { param($payloadObj) $Global:EmergencyStopEngaged = $true; return @{ ok = $true; engaged = $true } }
    function Clear-EmergencyStopInternal { $Global:EmergencyStopEngaged = $false; return @{ ok = $true; engaged = $false } }
    $Global:EmergencyStopEngaged = $false
    [IO.File]::WriteAllLines((Join-Path $PSScriptRoot "vx-observations.txt"), [string[]]$script:VX)
