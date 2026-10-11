    # ====================================================================================================================
    # VERIFIER PROBES (kiosk round 2 attack, 2026-10-10). Spliced into a COPY of BayAgent.Kiosk.Tests.ps1 right before the
    # "restore the suite's e-stop stubs" line of K21, so every K21 helper and the real e-stop internals are live.
    # Observations print as "  OBS   ..."; nothing here changes the suite's own assertions. Hyphens only in comments.
    # ====================================================================================================================
    Section "VY verifier probes (kiosk round 2 attack)"
    function Obs([string]$m) { Write-Host ("  OBS   " + $m) }
    function Get-WallBrief {
        $s = Get-Sess; if ($null -eq $s) { return "wall unreadable" }
        $st = Get-PropValue $s "agentRunning" $null
        return ("wall {0}/{1} playEnd={2} banner='{3}' detail='{4}' name='{5}' stamp(running={6} sid={7} cancelEnd={8})" -f (Get-PropValue $s "status" ""), (Get-PropValue $s "baySessionId" ""), (Get-PropValue $s "playEndUtc" ""), (Get-PropValue $s "bannerText" ""), (Get-PropValue $s "statusDetail" ""), (Get-PropValue $s "displayName" ""), (Get-PropValue $st "running" ""), (Get-PropValue $st "baySessionId" ""), (Get-PropValue $st "cancelEndUtc" ""))
    }
    function Get-IntentBrief {
        $w = Get-KioskLauncherWanted -IntentRead (Read-KioskJsonFile -Path $KioskIntentPath) -NowUtc ((Get-Date).ToUniversalTime())
        $u = $(if ($null -ne $w.UntilUtc) { ([DateTime]$w.UntilUtc).ToString("HH:mm:ss") } else { "-" })
        return ("intent wanted={0} closed={1} sid={2} until={3} ({4})" -f $w.Wanted, $w.Closed, $w.SessionId, $u, $w.Reason)
    }
    function Get-RecBrief { return ("record={0} cancelEnd={1} finished=[{2}]" -f (Get-RecSid), (Get-RecCancel), ((@($Global:RunningSessionFinished) | ForEach-Object { [string](Get-KioskProp $_ "id" "") }) -join ",")) }
    function Vy-Reset-Intent {
        Remove-Item -LiteralPath $KioskIntentPath -Force -ErrorAction SilentlyContinue
        $Global:KioskIntentExpectedText = $null; $Global:KioskIntentPending = $false
        Initialize-KioskIntent -NowUtc ((Get-Date).ToUniversalTime())
    }
    function Vy-Fresh { Clear-Bay; Remove-Item -LiteralPath $sessPath -Force -ErrorAction SilentlyContinue; Vy-Reset-Intent }
    $nowHms = { (Get-Date).ToUniversalTime().ToString("HH:mm:ss") }

    $vyBase = ($env:VY_MODE -eq "base")
    if (-not $vyBase) {
    # ---------------------------------------------------------------- VY1: a canceled booking REINSTATED during its warning
    # (unruled choice 4). The platform creates Prep/Start/Warn5/End only for a Scheduled booking that is not over
    # (BayCreateAutomationsPolicy.IsEligible + IsBookingOver, abg-member-web origin/main b01cdf9e), so after a cancel Reset
    # a fresh Start for the same session means the booking is Scheduled again.
    Vy-Fresh
    Obs ("VY1 now=" + (& $nowHms) + " booking end=" + $endIso)
    [void](Invoke-Start "s-y1")
    $script:ControlWarnings.Clear()
    $r = Invoke-BoundReset "s-y1"; $endsY1 = Get-EndsOf $r
    Obs ("VY1 after the cancel Reset:   " + (Get-WallBrief) + " | " + (Get-IntentBrief) + " | " + (Get-RecBrief))
    $rp = Invoke-Start "s-y1" "Prep"
    Obs ("VY1 reinstated, replayed Prep: skipped=" + (Get-PropValue $rp "skipped" "") + " | " + (Get-WallBrief))
    $rs = Invoke-Start "s-y1"
    Obs ("VY1 reinstated, replayed Start: skipped=" + (Get-PropValue $rs "skipped" "") + " ok=" + (Get-PropValue $rs "ok" "") + " | " + (Get-WallBrief) + " | " + (Get-IntentBrief) + " | " + (Get-RecBrief) + " | control-screen messages since the cancel: " + $script:ControlWarnings.Count)
    $script:Patches2.Clear()
    Process-Command -token "t" -cmd (New-CmdRow $CMD_STARTSESSION ('{"mode":"Start","baySessionId":"s-y1","bookingId":"b0000000-0000-0000-0000-0000000000y1","playEndUtc":"' + $endIso + '","closeLauncher":false}'))
    Obs ("VY1 the same replayed Start through Process-Command: booking writes=" + ((@($script:Patches2 | Where-Object { $_.Set -eq "build_bookings" }) | ForEach-Object { "statuscode " + $_.Body["statuscode"] }) -join ";"))
    $e1 = $(if ($null -ne $endsY1) { Invoke-CancelEndIfDue -NowUtc $endsY1.AddSeconds(1) } else { $null })
    Obs ("VY1 at the warning's end:      End scope=" + (Get-PropValue $e1 "scope" "") + " launcherStopped=" + (Get-PropValue (Get-PropValue $e1 "launcherStopped" $null) "reason" "") + " | " + (Get-WallBrief) + " | " + (Get-IntentBrief) + " | " + (Get-RecBrief) + " | shell on a relaunched launcher: " + (Get-ShellVerdictNow))
    $rs2 = Invoke-Start "s-y1"
    Obs ("VY1 a later Start of the reinstated booking: skipped=" + (Get-PropValue $rs2 "skipped" "") + " reason=" + (Get-PropValue $rs2 "reason" ""))
    $script:Patches2.Clear()
    Process-Command -token "t" -cmd (New-CmdRow $CMD_ENDSESSION ('{"mode":"End","baySessionId":"s-y1","bookingId":"b0000000-0000-0000-0000-0000000000y1","closeLauncher":false}'))
    Obs ("VY1 the reinstated booking's own End through Process-Command: booking writes=" + @($script:Patches2 | Where-Object { $_.Set -eq "build_bookings" }).Count + " (0 = the booking is never written Complete)")

    }
    # ---------------------------------------------------------------- VY2: the cancel End really closes a launcher process
    # (the suite's Ends all carry closeLauncher=false; the synthesized cancel End carries none, so the real close code runs).
    Vy-Fresh
    $fakeDir = Join-Path $Sandbox ("vy-launcher-" + [guid]::NewGuid().ToString("N").Substring(0, 8))
    New-Item -ItemType Directory -Force -Path $fakeDir | Out-Null
    $fakeName = "AbgVyStandIn" + [guid]::NewGuid().ToString("N").Substring(0, 8)
    $fakeExe = Join-Path $fakeDir ($fakeName + ".exe")
    $fakeProc = $null
    try {
        Add-Type -TypeDefinition "public static class AbgVyStandInMain { public static void Main() { System.Threading.Thread.Sleep(600000); } }" -OutputAssembly $fakeExe -OutputType ConsoleApplication
        $fakeProc = Start-Process -FilePath $fakeExe -WindowStyle Hidden -PassThru
        Start-Sleep -Milliseconds 700
        $cfg | Add-Member -NotePropertyName launcher -NotePropertyValue ([pscustomobject]@{ path = $fakeExe; processName = $fakeName }) -Force
        if (-not $vyBase) {
        [void](Invoke-Start "s-y2")
        $r = Invoke-BoundReset "s-y2"; $endsY2 = Get-EndsOf $r
        $aliveDuring = -not $fakeProc.HasExited
        $early = Invoke-CancelEndIfDue -NowUtc ((Get-Date).ToUniversalTime().AddMinutes(4))
        $aliveAt4 = -not $fakeProc.HasExited
        $e2 = Invoke-CancelEndIfDue -NowUtc $endsY2.AddSeconds(1)
        Start-Sleep -Milliseconds 500
        $ls = Get-PropValue $e2 "launcherStopped" $null
        Obs ("VY2 stand-in launcher pid " + $fakeProc.Id + ": alive during the warning=" + $aliveDuring + ", alive at 4 min=" + $aliveAt4 + ", exited after the cancel End=" + $fakeProc.HasExited + " (stopped=" + (Get-PropValue $ls "stopped" "") + " method=" + (Get-PropValue $ls "method" "") + " reason=" + (Get-PropValue $ls "reason" "") + ")")
        Assert-True ($aliveDuring -and $aliveAt4 -and $fakeProc.HasExited) "VY2 the cancel End closes a real launcher process (and not before the warning is over)"
        }
        if (-not $fakeProc.HasExited) { try { Stop-Process -Id $fakeProc.Id -Force -ErrorAction SilentlyContinue } catch { } }
        # VY9 (dormant-mode change, F1-R3): back-to-back bookings. A plays, B's Prep lands (start minus 15), A's End.
        $fakeProc = Start-Process -FilePath $fakeExe -WindowStyle Hidden -PassThru
        Start-Sleep -Milliseconds 700
        Vy-Fresh
        [void](Invoke-Start "s-y9a"); [void](Invoke-Start "s-y9b" "Prep")
        $e9 = Execute-Command -CommandType $CMD_ENDSESSION -PayloadJson ('{"mode":"End","baySessionId":"s-y9a","closeApps":true,"resetToLauncher":true}') -BayLabel "Bay"
        Start-Sleep -Milliseconds 500
        $ls9 = Get-PropValue $e9 "launcherStopped" $null
        Obs ("VY9 back-to-back: A's on-time End after B's Prep (platform-shaped End payload): launcher exited=" + $fakeProc.HasExited + " (stopped=" + (Get-PropValue $ls9 "stopped" "") + " reason=" + (Get-PropValue $ls9 "reason" "") + " method=" + (Get-PropValue $ls9 "method" "") + ") | " + (Get-WallBrief))
    } catch { Obs ("VY2/VY9 threw: " + $_.Exception.Message) }
    finally {
        if ($null -ne $fakeProc -and -not $fakeProc.HasExited) { try { Stop-Process -Id $fakeProc.Id -Force -ErrorAction SilentlyContinue } catch { } }
        $cfg | Add-Member -NotePropertyName launcher -NotePropertyValue $null -Force
    }

    if (-not $vyBase) {
    # ---------------------------------------------------------------- VY3: an End that throws after the record is cleared
    Vy-Fresh
    [void](Invoke-Start "s-y3")
    $r = Invoke-BoundReset "s-y3"; $endsY3 = Get-EndsOf $r
    $realStopApps = (Get-Command Stop-AppsIfRequested).Definition
    function Stop-AppsIfRequested($payloadObj) { throw "simulated failure after the wall write" }
    $e3 = Invoke-CancelEndIfDue -NowUtc $endsY3.AddSeconds(1)
    Obs ("VY3 cancel End, a step after the record clear throws: result null=" + ($null -eq $e3) + " | " + (Get-WallBrief) + " | " + (Get-IntentBrief) + " | " + (Get-RecBrief))
    function Stop-AppsIfRequested($payloadObj) { return @{ stopped = $false; reason = "stub" } }
    $e3b = Invoke-CancelEndIfDue -NowUtc $endsY3.AddSeconds(30)
    $e3c = $null; try { $e3c = Invoke-End "s-y3" } catch { $e3c = "threw" }
    Obs ("VY3 next pass (failure gone): retried=" + ($null -ne $e3b) + "; an End of s-y3 sent again: skipped=" + (Get-PropValue $e3c "skipped" "") + " scope=" + (Get-PropValue $e3c "scope" "") + " | " + (Get-IntentBrief) + " | shell on the still-running launcher: " + (Get-ShellVerdictNow))
    # the same for a platform End (no cancel)
    Vy-Fresh
    [void](Invoke-Start "s-y3p")
    function Stop-AppsIfRequested($payloadObj) { throw "simulated failure after the wall write" }
    $p1 = $null; try { $p1 = Invoke-End "s-y3p" } catch { $p1 = "threw" }
    function Stop-AppsIfRequested($payloadObj) { return @{ stopped = $false; reason = "stub" } }
    $p2 = $null; try { $p2 = Invoke-End "s-y3p" } catch { $p2 = "threw" }
    Obs ("VY3 platform End throws mid-way (" + $(if ($p1 -is [string]) { $p1 } else { "returned" }) + "), then the same End again: skipped=" + (Get-PropValue $p2 "skipped" "") + " scope=" + (Get-PropValue $p2 "scope" "") + " | " + (Get-IntentBrief) + " | " + (Get-RecBrief))

    # ---------------------------------------------------------------- VY4: damaged session.json at the cancel and at its End
    $shapes = [ordered]@{ "0 bytes" = ""; "whitespace" = "  `r`n"; "null" = "null"; "array" = "[]"; "number" = "7"; "text" = '"x"'; "truncated" = '{"status":"ACTIVE","baySessionId":"s-'; "customer as text" = '{"status":"ACTIVE","baySessionId":"s-y4","customer":"bob","timing":7}'; "status as object" = '{"status":{"a":1},"baySessionId":["s-y4"]}' }
    foreach ($k in $shapes.Keys) {
        foreach ($when in @("before the cancel Reset", "before the cancel End")) {
            Vy-Fresh
            $line = "VY4 session.json '" + $k + "' " + $when + ": "
            try {
                [void](Invoke-Start "s-y4")
                if ($when -eq "before the cancel Reset") { Set-TestFile $sessPath $shapes[$k] }
                $r = Invoke-BoundReset "s-y4"; $endsY4 = Get-EndsOf $r
                if ($when -eq "before the cancel End") { Set-TestFile $sessPath $shapes[$k] }
                $e4 = $(if ($null -ne $endsY4) { Invoke-CancelEndIfDue -NowUtc $endsY4.AddSeconds(1) } else { $null })
                $wi = Get-IntentNow
                $ok = ($null -ne $endsY4 -and $null -ne $e4 -and (Get-RecSid) -eq "<none>" -and $wi.Closed -and $wi.SessionId -eq "s-y4")
                $line += $(if ($ok) { "ended and closed" } else { "NOT ENDED (warning=" + ($null -ne $endsY4) + " endResult=" + ($null -ne $e4) + " " + (Get-RecBrief) + " " + (Get-IntentBrief) + ")" })
            } catch { $line += "THREW " + $_.Exception.Message }
            Obs $line
        }
    }

    # ---------------------------------------------------------------- VY5: a cancel while the bay is Offline, then Maintenance
    Vy-Fresh
    [void](Invoke-Start "s-y5")
    $Global:EffectiveConfig = @{ "Bay.AgentStatus" = $AGENTSTATUS_OFFLINE; "Bay.AgentStatusReason" = "t" }
    $script:Patches2.Clear()
    $row5 = New-ResetRow "s-y5"
    try { Process-Command -token "t" -cmd $row5 } catch { Obs ("VY5 Process-Command threw: " + $_.Exception.Message) }
    Obs ("VY5 Offline, the running booking's cancel Reset: row writes=" + ((@($script:Patches2) | ForEach-Object { "status " + $_.Body[$Col_Status] }) -join " -> ") + " | " + (Get-RecBrief) + " | " + (Get-WallBrief))
    $Global:EffectiveConfig = $null
    $l5 = Invoke-CancelEndIfDue -NowUtc ((Get-Date).ToUniversalTime().AddMinutes(30))
    Obs ("VY5 Offline lifted, 30 minutes later: anything ended=" + ($null -ne $l5) + " | " + (Get-RecBrief) + " | " + (Get-IntentBrief))
    $Global:EffectiveConfig = @{ "Bay.AgentStatus" = $AGENTSTATUS_MAINTENANCE; "Bay.AgentStatusReason" = "t" }
    $script:Patches2.Clear()
    try { Process-Command -token "t" -cmd (New-ResetRow "s-y5") } catch { Obs ("VY5 Process-Command threw: " + $_.Exception.Message) }
    Obs ("VY5 Maintenance, the same cancel Reset: row writes=" + ((@($script:Patches2) | ForEach-Object { "status " + $_.Body[$Col_Status] }) -join " -> ") + " | " + (Get-RecBrief))
    $Global:EffectiveConfig = $null
    [void](Invoke-CancelEndIfDue -NowUtc ((Get-Date).ToUniversalTime().AddMinutes(30)))

    # ---------------------------------------------------------------- VY6: a restart in every phase of the warning
    Vy-Fresh
    [void](Invoke-Start "s-y6")
    $r = Invoke-BoundReset "s-y6"; $endsY6 = Get-EndsOf $r
    Remove-Item -LiteralPath $RunningSessionPath -Force -ErrorAction SilentlyContinue
    $Global:RunningSession = $null; $Global:RunningSessionFinished = @(); Initialize-RunningSession -NowUtc ((Get-Date).ToUniversalTime())
    Obs ("VY6 restart during the warning with the record file LOST (wall stamp only): " + (Get-RecBrief))
    $Global:RunningSession = $null; $Global:RunningSessionFinished = @(); Initialize-RunningSession -NowUtc $endsY6.AddMinutes(20)
    $e6 = Invoke-CancelEndIfDue -NowUtc $endsY6.AddMinutes(20)
    Obs ("VY6 agent down across the warning's end, restarted 20 minutes late: ended on the first pass=" + ($null -ne $e6) + " | " + (Get-RecBrief) + " | " + (Get-IntentBrief))
    $Global:RunningSession = $null; $Global:RunningSessionFinished = @(); Initialize-RunningSession -NowUtc $endsY6.AddMinutes(21)
    $e6b = Invoke-CancelEndIfDue -NowUtc $endsY6.AddMinutes(21)
    Obs ("VY6 restart AFTER the cancel End: a second End=" + ($null -ne $e6b) + " | " + (Get-RecBrief))
    # both snapshots lost (record file and session.json unreadable) during the warning
    Vy-Fresh
    [void](Invoke-Start "s-y6c")
    $r = Invoke-BoundReset "s-y6c"; $endsY6c = Get-EndsOf $r
    Remove-Item -LiteralPath $RunningSessionPath -Force -ErrorAction SilentlyContinue
    Set-TestFile $sessPath ""
    $Global:RunningSession = $null; $Global:RunningSessionFinished = @(); Initialize-RunningSession -NowUtc ((Get-Date).ToUniversalTime())
    $e6c = Invoke-CancelEndIfDue -NowUtc $endsY6c.AddMinutes(1)
    Obs ("VY6 restart during the warning with BOTH the record file and session.json lost: " + (Get-RecBrief) + " ended=" + ($null -ne $e6c) + " | " + (Get-IntentBrief))

    # ---------------------------------------------------------------- VY8: a Warn5 already claimed when the cancel landed
    Vy-Fresh
    [void](Invoke-Start "s-y8")
    $r = Invoke-BoundReset "s-y8"; $endsY8 = Get-EndsOf $r
    Obs ("VY8 warning started:        " + (Get-WallBrief) + " | " + (Get-IntentBrief))
    $w8 = Execute-Command -CommandType $CMD_UPDATESESSIONDISPLAY -PayloadJson ('{"mode":"Warn5","baySessionId":"s-y8","playEndUtc":"' + $endIso + '","sessionEndUtc":"' + $endIso + '","message":"5 minutes remaining"}') -BayLabel "Bay"
    Obs ("VY8 then the booking's own Warn5: " + (Get-WallBrief) + " | " + (Get-IntentBrief) + " | " + (Get-RecBrief))
    $e8 = Invoke-CancelEndIfDue -NowUtc $endsY8.AddSeconds(1)
    Obs ("VY8 at the warning's end: ended=" + ($null -ne $e8) + " | " + (Get-IntentBrief))

    }
    # ---------------------------------------------------------------- VY10: random command sequences against a simple model
    # Model: the ENTITLED session is the one whose Start the bay last accepted, until its own End, its cancel plus the
    # warning, or a later accepted Start. Checked after every step, as the shell would see the files:
    #   V-CLOSE   someone is entitled and the shell's verdict on a running launcher is "close", or an End for another
    #             session (or naming none) reached the launcher-close branch.
    #   V-467     a canceled running booking is still not ended 6 minutes later.
    # Failure injections: intent file held open, record file held open, agent restarts (with and without the record file).
    $script:VyN = 0
    function Vy-NewSid { $script:VyN++; return ("s-f" + $script:VyN) }
    $vyOps = @("StartNew", "StartNew", "StartNew", "StartPrev", "StartCur", "PrepNext", "PrepNext", "PrepCur", "EndCur", "EndCur", "EndPrev", "EndPrev", "EndNone", "ResetCur", "ResetCur", "ResetPrev", "ResetOther",
               "ResetUnbound", "ResetForce", "EstopOn", "EstopOff", "Restart", "RestartNoFile", "Time", "Time", "UpdCur", "UpdPrev", "LockI", "UnlockI", "LockR", "UnlockR")
    $vyViol = New-Object System.Collections.ArrayList
    $vyIdle = @{}
    $vySteps = 0; $vyThrows = New-Object System.Collections.ArrayList
    [void](Get-Random -SetSeed 20261010)
    $vySeqs = 400; $vyLen = 14
    for ($q = 1; $q -le $vySeqs; $q++) {
        Vy-Fresh
        $ent = ""; $cancel = $false; $prev = ""; $next = ""; $trace = New-Object System.Collections.ArrayList
        $il = $null; $rl = $null
        try {
            for ($i = 0; $i -lt $vyLen; $i++) {
                $op = $vyOps[(Get-Random -Maximum $vyOps.Count)]
                $res = $null; $endFor = $null; $did = $op
                try {
                    switch ($op) {
                        "StartNew" { $sid = $(if ($next) { $next } else { Vy-NewSid }); $next = ""; $res = Invoke-Start $sid; $did = "Start(" + $sid + ")"
                                     if ((Get-PropValue $res "skipped" $null) -ne $true) { if ($ent -and $ent -ne $sid) { $prev = $ent }; $ent = $sid; $cancel = $false } else { $did += "=refused" } }
                        "StartPrev" { if ($prev) { $res = Invoke-Start $prev; $did = "Start(prev " + $prev + ")"
                                     if ((Get-PropValue $res "skipped" $null) -ne $true) { $t = $ent; $ent = $prev; $prev = $t; $cancel = $false } else { $did += "=refused" } } else { $did = "-" } }
                        "StartCur" { if ($ent) { $res = Invoke-Start $ent; $did = "Start(again " + $ent + ")" } else { $did = "-" } }
                        "PrepNext" { if (-not $next) { $next = Vy-NewSid }; [void](Invoke-Start $next "Prep"); $did = "Prep(" + $next + ")" }
                        "PrepCur" { if ($ent) { [void](Invoke-Start $ent "Prep"); $did = "Prep(again " + $ent + ")" } else { $did = "-" } }
                        "EndCur" { if ($ent) { $res = Invoke-End $ent; $did = "End(" + $ent + ")"; $prev = $ent; $ent = ""; $cancel = $false } else { $did = "-" } }
                        "EndPrev" { if ($prev) { $res = Invoke-End $prev; $endFor = $prev; $did = "End(prev " + $prev + ")" } else { $did = "-" } }
                        "EndNone" { $res = Execute-Command -CommandType $CMD_ENDSESSION -PayloadJson '{"mode":"End","closeLauncher":false}' -BayLabel "Bay"; $endFor = "" }
                        "ResetCur" { if ($ent) { [void](Invoke-BoundReset $ent); $cancel = $true; $did = "CancelReset(" + $ent + ")" } else { $did = "-" } }
                        "ResetPrev" { if ($prev) { [void](Invoke-BoundReset $prev); $did = "Reset(prev " + $prev + ")" } else { $did = "-" } }
                        "ResetOther" { [void](Invoke-BoundReset "s-zz") }
                        "ResetUnbound" { [void](Invoke-BoundReset "") }
                        "ResetForce" { [void](Execute-Command -CommandType $CMD_RESET -PayloadJson '{"mode":"Full","force":true}' -BayLabel "Bay") }
                        "EstopOn" { [void](Execute-Command -CommandType $CMD_EMERGENCY_STOP -PayloadJson '{"action":"engage","reason":"t"}' -BayLabel "Bay") }
                        "EstopOff" { [void](Execute-Command -CommandType $CMD_EMERGENCY_STOP -PayloadJson '{"action":"clear"}' -BayLabel "Bay") }
                        "Restart" { $Global:RunningSession = $null; $Global:RunningSessionFinished = @(); $Global:RunningSessionPending = $false; $Global:KioskIntentExpectedText = $null; $Global:KioskIntentPending = $false
                                    Initialize-RunningSession -NowUtc ((Get-Date).ToUniversalTime()); Initialize-KioskIntent -NowUtc ((Get-Date).ToUniversalTime()) }
                        "RestartNoFile" { if ($null -eq $rl) { Remove-Item -LiteralPath $RunningSessionPath -Force -ErrorAction SilentlyContinue }
                                    $Global:RunningSession = $null; $Global:RunningSessionFinished = @(); $Global:RunningSessionPending = $false; $Global:KioskIntentExpectedText = $null; $Global:KioskIntentPending = $false
                                    Initialize-RunningSession -NowUtc ((Get-Date).ToUniversalTime()); Initialize-KioskIntent -NowUtc ((Get-Date).ToUniversalTime()) }
                        "Time" { $res = Invoke-CancelEndIfDue -NowUtc ((Get-Date).ToUniversalTime().AddMinutes(6))
                                 if ($cancel -and $ent) {
                                     $wi = Get-KioskLauncherWanted -IntentRead (Read-KioskJsonFile -Path $KioskIntentPath) -NowUtc ((Get-Date).ToUniversalTime())
                                     $ended = ($null -ne $res -and (Get-RecSid) -ne $ent)
                                     if (-not $ended) { [void]$vyViol.Add(@{ Kind = "V-467"; Seq = $q; Step = $i; Detail = ("canceled " + $ent + " not ended 6 minutes later: " + (Get-RecBrief) + " " + (Get-IntentBrief)); Trace = (($trace -join " > ") + " > Time") }) }
                                     $prev = $ent; $ent = ""; $cancel = $false; $did = "Time(+6m)"
                                 } }
                        "UpdCur" { if ($ent) { [void](Execute-Command -CommandType $CMD_UPDATESESSIONDISPLAY -PayloadJson ('{"mode":"Warn5","baySessionId":"' + $ent + '","playEndUtc":"' + $endIso + '"}') -BayLabel "Bay") } else { $did = "-" } }
                        "UpdPrev" { if ($prev) { [void](Execute-Command -CommandType $CMD_UPDATESESSIONDISPLAY -PayloadJson ('{"mode":"Warn5","baySessionId":"' + $prev + '","playEndUtc":"' + $endIso + '"}') -BayLabel "Bay") } else { $did = "-" } }
                        "LockI" { if ($null -eq $il -and (Test-Path -LiteralPath $KioskIntentPath)) { $il = Lock-Intent } else { $did = "-" } }
                        "UnlockI" { if ($null -ne $il) { $il.Dispose(); $il = $null } else { $did = "-" } }
                        "LockR" { if ($null -eq $rl -and (Test-Path -LiteralPath $RunningSessionPath)) { $rl = New-Object IO.FileStream($RunningSessionPath, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read) } else { $did = "-" } }
                        "UnlockR" { if ($null -ne $rl) { $rl.Dispose(); $rl = $null } else { $did = "-" } }
                    }
                } catch { [void]$vyThrows.Add(("seq {0} step {1} {2}: {3}" -f $q, $i, $op, $_.Exception.Message)) }
                if ($did -eq "-") { continue }
                [void]$trace.Add($did); $vySteps++
                # one main-loop pass (the intent integrity check and the record file sync; a held file just stays pending)
                Release-IntentLock
                if ($null -ne $endFor -and $ent -and $endFor -ne $ent) {
                    $lr = [string](Get-PropValue (Get-PropValue $res "launcherStopped" $null) "reason" "")
                    if ($lr -notin @("late_old_session_skip", "session_already_ended")) { [void]$vyViol.Add(@{ Kind = "V-CLOSE"; Seq = $q; Step = $i; Detail = ("End for '" + $endFor + "' reached the launcher-close branch (" + $lr + ") while " + $ent + " is entitled"); Trace = ($trace -join " > ") }) }
                }
                $verdict = Get-ShellVerdictNow
                if ($ent -and $verdict -eq "close") { [void]$vyViol.Add(@{ Kind = "V-CLOSE"; Seq = $q; Step = $i; Detail = ("shell verdict close while " + $ent + " is entitled (cancel pending=" + $cancel + "): " + (Get-WallBrief) + " | " + (Get-IntentBrief) + " | " + (Get-RecBrief)); Trace = ($trace -join " > ") }) }
                if (-not $ent) {
                    $s = Get-Sess; $wi2 = Get-KioskLauncherWanted -IntentRead (Read-KioskJsonFile -Path $KioskIntentPath) -NowUtc ((Get-Date).ToUniversalTime())
                    $key = ("idle: wall {0} intent {1} -> shell {2}" -f (Get-PropValue $s "status" "none"), $(if ($wi2.Closed) { "closed" } elseif ($wi2.Wanted) { "wanted" } else { "handsoff" }), $verdict)
                    if ($vyIdle.ContainsKey($key)) { $vyIdle[$key]++ } else { $vyIdle[$key] = 1 }
                }
            }
        } finally {
            if ($null -ne $il) { $il.Dispose() }; if ($null -ne $rl) { $rl.Dispose() }
            Release-IntentLock
        }
    }
    Obs ("VY10 fuzz: " + $vySeqs + " sequences, " + $vySteps + " steps, violations=" + $vyViol.Count + " (V-CLOSE=" + @($vyViol | Where-Object { $_.Kind -eq "V-CLOSE" }).Count + ", V-467=" + @($vyViol | Where-Object { $_.Kind -eq "V-467" }).Count + "), handler throws=" + $vyThrows.Count)
    foreach ($v in @($vyViol | Select-Object -First 25)) { Obs ("VY10 " + $v.Kind + " seq " + $v.Seq + " step " + $v.Step + ": " + $v.Detail); Obs ("VY10      trace: " + $v.Trace) }
    foreach ($t in @($vyThrows | Select-Object -First 10)) { Obs ("VY10 throw " + $t) }
    foreach ($k in @($vyIdle.Keys | Sort-Object)) { Obs ("VY10 " + $k + " x" + $vyIdle[$k]) }
    if (-not $vyBase) {
    # ---------------------------------------------------------------- VY11: the next booking's Prep lands AFTER the warning started
    Vy-Fresh
    [void](Invoke-Start "s-y11")
    $r = Invoke-BoundReset "s-y11"; $endsY11 = Get-EndsOf $r
    [void](Invoke-Start "s-n11" "Prep")
    Obs ("VY11 the next booking's Prep during the warning: " + (Get-WallBrief) + " | " + (Get-IntentBrief) + " | " + (Get-RecBrief))
    $e11 = Invoke-CancelEndIfDue -NowUtc $endsY11.AddSeconds(1)
    Obs ("VY11 at the warning's end: End scope=" + (Get-PropValue $e11 "scope" "") + " | " + (Get-WallBrief) + " | " + (Get-IntentBrief) + " | " + (Get-RecBrief) + " | shell on a relaunched launcher: " + (Get-ShellVerdictNow))
    Assert-True ($null -ne $e11 -and (Get-RecSid) -eq "<none>" -and (Get-IntentNow).Closed -and (Get-IntentNow).SessionId -eq "s-y11") "VY11 the canceled booking is ended as ITS session even after the next booking's Prep rewrote the wall"
    # ---------------------------------------------------------------- VY12: the warning wall files, for a real-browser render
    Vy-Fresh
    [void](Execute-Command -CommandType $CMD_STARTSESSION -PayloadJson ('{"mode":"Start","baySessionId":"s-y12","displayName":"Jordan","startUtc":"' + (Get-Date).ToUniversalTime().AddMinutes(-20).ToString($fmtZ) + '","playEndUtc":"' + $endIso + '","endUtc":"' + $endIso + '","closeLauncher":false}') -BayLabel "Bay 1")
    if (-not [string]::IsNullOrWhiteSpace($env:VY_OUT)) {
        $wd = Join-Path $env:VY_OUT "wall-files"; New-Item -ItemType Directory -Force -Path (Join-Path $wd "active") | Out-Null; New-Item -ItemType Directory -Force -Path (Join-Path $wd "warning") | Out-Null
        Copy-Item -LiteralPath $sessPath -Destination (Join-Path $wd "active\session.json") -Force; Copy-Item -LiteralPath ([IO.Path]::ChangeExtension($sessPath, "js")) -Destination (Join-Path $wd "active\session.js") -Force
        [void](Invoke-BoundReset "s-y12")
        Copy-Item -LiteralPath $sessPath -Destination (Join-Path $wd "warning\session.json") -Force; Copy-Item -LiteralPath ([IO.Path]::ChangeExtension($sessPath, "js")) -Destination (Join-Path $wd "warning\session.js") -Force
        Obs ("VY12 wall files written for the render: " + (Get-WallBrief))
    }
    }
    Vy-Fresh
    $Global:EmergencyStopEngaged = $false
