    # ====================================================================================================================
    # RP (release-prep check, 2026-10-10): the End-pending mark now lives in state\running-session.json. Probes for the
    # ways a persisted mark can go wrong: a session wrongly counted as ended, an End retried against the wrong session,
    # a mark that is never cleared, a retry that closes a launcher it does not own, and a restart reader fed a wrong
    # shape. Spliced into a COPY of the Kiosk suite after K22's helpers (row stub, stand-in launcher, failing launcher
    # step, the real-loop case). Observation lines only (OBS); the verdict is read from them. Hyphens only in comments.
    # ====================================================================================================================
    Section "RP release-prep check: the persisted End-pending mark"
    function RpObs([string]$m) { Write-Host ("  OBS   " + $m) }
    function Rp-Fresh {
        Clear-Bay; Remove-Item -LiteralPath $sessPath -Force -ErrorAction SilentlyContinue
        Remove-Item -LiteralPath $KioskIntentPath -Force -ErrorAction SilentlyContinue
        $Global:KioskIntentExpectedText = $null; $Global:KioskIntentPending = $false
        Initialize-KioskIntent -NowUtc ((Get-Date).ToUniversalTime())
        $script:Fac = @(); $script:LogLines.Clear()
    }
    function Rp-Restart {
        $Global:RunningSession = $null; $Global:RunningSessionFinished = @(); $Global:RunningSessionPending = $false
        $Global:RunningSessionEndPending = @(); $Global:RunningSessionOwnEnd = $false
        $Global:KioskIntentExpectedText = $null; $Global:KioskIntentPending = $false
        Initialize-RunningSession -NowUtc ((Get-Date).ToUniversalTime()); Initialize-KioskIntent -NowUtc ((Get-Date).ToUniversalTime())
    }
    function Rp-Row([int]$type, [string]$payload) {
        $script:Patches3.Clear()
        try { Process-Command -token "t" -cmd (New-CmdRow $type $payload) } catch { return ("THREW " + $_.Exception.Message) }
        $rows = @($script:Patches3 | Where-Object { $_.Set -ne "build_bookings" })
        $names = @($rows | ForEach-Object { $v = $_.Body[$Col_Status]; if ($v -eq $STATUS_SKIPPED) { "Skipped" } elseif ($v -eq $STATUS_INPROGRESS) { "InProgress" } elseif ($v -eq $STATUS_SUCCEEDED) { "Succeeded" } elseif ($v -eq $STATUS_FAILED) { "Failed" } else { [string]$v } })
        $res = ""; if ($rows.Count -gt 0) { $lb = $rows[$rows.Count - 1].Body; if ($lb.ContainsKey($Col_Result)) { $res = [string]$lb[$Col_Result] } }
        return (($names -join ">") + $(if ($res -match '"skipped":\s*true') { " (result says skipped)" } else { "" }))
    }
    function Rp-Pend { return ("pending=[" + ((@($Global:RunningSessionEndPending) | Where-Object { $null -ne $_ } | ForEach-Object { [string](Get-KioskProp $_ "id" "") + "/" + [string](Get-KioskProp $_ "scope" "") + "/tries " + [string](Get-KioskProp $_ "tries" "") }) -join ",") + "]") }
    function Rp-State {
        $w = Get-KioskLauncherWanted -IntentRead (Read-KioskJsonFile -Path $KioskIntentPath) -NowUtc ((Get-Date).ToUniversalTime())
        return ("record=" + (Get-RecSid) + " " + (Rp-Pend) + " ended=[" + ((@($Global:RunningSessionFinished) | ForEach-Object { [string](Get-KioskProp $_ "id" "") }) -join ",") + "] | wall " + (Get-SessStatus) + " | intent " + $(if ($w.Closed) { "closed" } elseif ($w.Wanted) { "wanted" } else { "hands off" }) + "/" + $w.SessionId + " | shell (if on) for a launcher that reappears: " + (Get-ShellVerdictNow))
    }
    function Rp-File {
        $o = $null; try { $o = [IO.File]::ReadAllText($RunningSessionPath) | ConvertFrom-Json } catch { return "file unreadable" }
        $pl = Get-KioskProp $o "endPending" $null; $fl = Get-KioskProp $o "finished" $null
        $pp = (@($pl) | Where-Object { $null -ne $_ } | ForEach-Object { [string](Get-KioskProp $_ "id" "") + "/" + [string](Get-KioskProp $_ "scope" "") + "/tries " + [string](Get-KioskProp $_ "tries" "") }) -join ","
        $ff = (@($fl) | Where-Object { $null -ne $_ } | ForEach-Object { [string](Get-KioskProp $_ "id" "") }) -join ","
        return ("file: running=" + [string](Get-KioskProp $o "running" "") + "/" + [string](Get-KioskProp $o "baySessionId" "") + " endPending=[" + $pp + "] finished=[" + $ff + "]")
    }
    function Rp-WithPending([string]$raw) {
        # The record file's own text with its (empty) endPending replaced by the raw JSON given; $null = the field removed.
        $t = [IO.File]::ReadAllText($RunningSessionPath)
        $t = [regex]::Replace($t, '"endPending"\s*:\s*\[\s*\]\s*,', '')
        if ($t -match '"endPending"') { throw "rp: the file still carries an endPending field after the cut" }
        $t = $t.TrimEnd()
        if (-not $t.EndsWith("}")) { throw "rp: the record file does not end with a brace" }
        if ($raw -ne "<absent>") { $t = $t.Substring(0, $t.Length - 1).TrimEnd() + ',"endPending":' + $raw + '}' }
        Set-TestFile $RunningSessionPath $t
    }
    function Rp-Pass { return (Invoke-CancelEndIfDue -NowUtc ((Get-Date).ToUniversalTime())) }
    function Rp-Warn([string]$rx) { return @($script:LogLines | Where-Object { $_ -match $rx }).Count }
    # A step BEFORE the session is listed as ended that can be made to fail (the wall model build), and a step that stands for
    # the process dying right after the mark was persisted (the list write). Both restored at the end of the block.
    $rpRealNorm = Get-DefText $AgentDefs "Normalize-SessionModel"
    . ([scriptblock]::Create($rpRealNorm.Replace("function Normalize-SessionModel", "function script:Rp-RealNormalizeSessionModel")))
    $script:RpDieAtModel = $false; $script:RpModelThrows = 0
    function script:Normalize-SessionModel([hashtable]$model) { if ($script:RpDieAtModel) { $script:RpModelThrows++; throw "rp: the wall model build fails (simulated)" }; return (Rp-RealNormalizeSessionModel $model) }
    $rpRealAddFin = Get-DefText $AgentDefs "Add-FinishedSession"
    . ([scriptblock]::Create($rpRealAddFin.Replace("function Add-FinishedSession", "function script:Rp-RealAddFinishedSession")))
    $script:RpDieAtList = $false
    function script:Add-FinishedSession([string]$SessionId, [string]$Why) { if ($script:RpDieAtList -and $Why -eq "EndSession") { throw "rp: the agent process dies here, right after the mark (simulated)" }; Rp-RealAddFinishedSession -SessionId $SessionId -Why $Why }

    try {
    # ---------------------------------------------------------------- RP1: an End of the RECORDED, paying session that stops
    # between the mark and the ended list. (a) a step throws, the agent lives on; (b) the same, then a restart before the
    # next pass; (c) the process dies right after the mark, then a restart. A real stand-in launcher each time.
    foreach ($v in @("a: a step throws before the ended list, no restart", "b: a step throws before the ended list, then a restart", "c: the process dies right after the mark, then a restart", "d: the process dies right after the mark, a restart, and the platform's End arrives BEFORE the first pass")) {
        Rp-Fresh
        $rpL = New-StandInLauncher
        try {
            [void](Invoke-Start "s-p1"); $script:Fac = @()
            if ($v -match "^[cd]") { $script:RpDieAtList = $true } else { $script:RpDieAtModel = $true }
            $first = Rp-Row $CMD_ENDSESSION '{"mode":"End","baySessionId":"s-p1"}'
            $script:RpDieAtModel = $false; $script:RpDieAtList = $false
            $after = (Rp-State) + " | " + (Rp-File)
            if ($v -notmatch "^a") { Rp-Restart }
            $restarted = (Rp-State)
            if ($v -match "^d") {
                $early = Rp-Row $CMD_ENDSESSION '{"mode":"End","baySessionId":"s-p1"}'
                Start-Sleep -Milliseconds 400
                $restarted += " || the End row before any pass: " + $early + ", launcher still running=" + (Test-StandInAlive $rpL) + ", " + (Rp-State)
            }
            $p1 = Rp-Pass; $p2 = Rp-Pass
            Start-Sleep -Milliseconds 400
            $alive1 = Test-StandInAlive $rpL
            $st2 = (Rp-State) + " | " + (Rp-File) + " | facility calls since the Start=[" + (@($script:Fac) -join ",") + "]"
            $resent = Rp-Row $CMD_ENDSESSION '{"mode":"End","baySessionId":"s-p1"}'
            Start-Sleep -Milliseconds 400
            RpObs ("RP1" + $v + ": End row " + $first + " -> " + $after + " || " + $(if ($v -notmatch "^a") { "after restart: " + $restarted + " || " } else { "" }) + "two passes: retried=" + ($null -ne $p1 -or $null -ne $p2) + ", LAUNCHER STILL RUNNING=" + $alive1 + ", " + $st2 + " || the End sent again: row " + $resent + ", launcher still running=" + (Test-StandInAlive $rpL) + ", " + (Rp-State))
            if ($v -match "^c") {
                Rp-Restart; $p3 = Rp-Pass
                $nx = Rp-Row $CMD_STARTSESSION (New-Payload "Start" "s-p1next")
                RpObs ("RP1c ...a SECOND restart: " + (Rp-State) + "; pass did something=" + ($null -ne $p3) + "; the next booking's Start row " + $nx + " -> record=" + (Get-RecSid))
                [void](Invoke-End "s-p1next")
            }
        } catch { RpObs ("RP1" + $v + " threw: " + $_.Exception.Message) }
        finally { Remove-StandInLauncher $rpL; $script:RpDieAtModel = $false; $script:RpDieAtList = $false }
    }

    # ---------------------------------------------------------------- RP2: the retry CAP when the End fails BEFORE the ended
    # list and nobody is recorded (the mark is now made before the list). Eight passes with the step still failing.
    foreach ($v in @("the wall names the next booking's Prep (a late End of an older booking)", "the wall names the same session (Prep, never started)")) {
        Rp-Fresh
        $rpL = New-StandInLauncher
        try {
            if ($v -match "next booking") { [void](Invoke-Start "s-nx2" "Prep") } else { [void](Invoke-Start "s-p2" "Prep") }
            $script:Fac = @(); $script:RpModelThrows = 0; $script:LogLines.Clear()
            $script:RpDieAtModel = $true
            $first = Rp-Row $CMD_ENDSESSION '{"mode":"End","baySessionId":"s-p2"}'
            $afterFirst = (Rp-Pend)
            $did = 0; for ($i = 0; $i -lt 8; $i++) { if ($null -ne (Rp-Pass)) { $did++ } }
            $mid = "End attempts=" + $script:RpModelThrows + ", facility Cleanup calls=" + @($script:Fac | Where-Object { $_ -eq "Cleanup" }).Count + ", gave-up WARN lines=" + (Rp-Warn "could not finish its protective act") + ", " + (Rp-Pend)
            $script:RpDieAtModel = $false
            $pr = Rp-Pass; Start-Sleep -Milliseconds 400
            RpObs ("RP2 nobody recorded, " + $v + ", the End fails BEFORE the ended list on every try: first row " + $first + " (" + $afterFirst + "); after 8 more passes: " + $mid + "; step repaired, one pass: launcher still running=" + (Test-StandInAlive $rpL) + ", " + (Rp-State))
        } catch { RpObs ("RP2 [" + $v + "] threw: " + $_.Exception.Message) }
        finally { Remove-StandInLauncher $rpL; $script:RpDieAtModel = $false }
    }

    # ---------------------------------------------------------------- RP3: the retry's payload is a cut-down copy. An End that
    # says closeLauncher=false: does the retry still honor it (a) with a small payload, (b) when a launcher block makes the
    # stored copy longer than its 1500-character cap?
    foreach ($v in @("small payload", "launcher block over the 1500-character cap")) {
        Rp-Fresh
        $rpL = New-StandInLauncher
        try {
            [void](Invoke-Start "s-p3")
            $lo = [ordered]@{ path = $rpL.Exe; processName = $rpL.Name }
            if ($v -notmatch "small") { $lo["note"] = ("x" * 1600) }
            $pay = ConvertTo-Json -Compress -Depth 4 -InputObject ([ordered]@{ mode = "End"; baySessionId = "s-p3"; closeLauncher = $false; launcher = $lo })
            Break-LauncherStep; $script:GlThrows = 0
            $first = Rp-Row $CMD_ENDSESSION $pay
            Repair-LauncherStep
            $stored = ""; foreach ($pe in @($Global:RunningSessionEndPending)) { if ($null -ne $pe) { $stored = [string](Get-KioskProp $pe "payload" "") } }
            $p1 = Rp-Pass; Start-Sleep -Milliseconds 400
            RpObs ("RP3 an End with closeLauncher=false, " + $v + " (" + $pay.Length + " chars), fails once after the mark: row " + $first + "; stored retry payload " + $stored.Length + " chars, carries closeLauncher=" + ($stored -match '"closeLauncher":false') + "; retry ran=" + ($null -ne $p1) + ", retry launcher result=" + [string](Get-PropValue (Get-PropValue $p1 "launcherStopped" $null) "reason" (Get-PropValue (Get-PropValue $p1 "launcherStopped" $null) "method" "?")) + "; LAUNCHER STILL RUNNING=" + (Test-StandInAlive $rpL))
        } catch { RpObs ("RP3 [" + $v + "] threw: " + $_.Exception.Message) }
        finally { Remove-StandInLauncher $rpL; Repair-LauncherStep }
    }

    # ---------------------------------------------------------------- RP4: the restart reader fed each shape of the new field,
    # while a member (s-p4) plays and an earlier session (s-prev) is on the ended list. The member must stay recorded, the
    # ended list must survive, and the member's Warn5 and End rows must run.
    $rpShapes = [ordered]@{
        "field absent (a 1.5.0 file)" = "<absent>"
        "[]" = "[]"
        "null" = "null"
        "text" = '"s-other"'
        "number" = "7"
        "true" = "true"
        "{}" = "{}"
        "one object, not a list" = '{"id":"s-other","scope":"owns"}'
        "[null]" = "[null]"
        "[7]" = "[7]"
        "[text]" = '["s-other"]'
        "[[entry]]" = '[[{"id":"s-other"}]]'
        "[{}]" = "[{}]"
        "[id is a number]" = '[{"id":7}]'
        "[id is empty]" = '[{"id":""}]'
        "[wrong-typed tries, scope, payload]" = '[{"id":"s-other","tries":"x","scope":7,"payload":{"a":1}}]'
        "[tries is 1.5]" = '[{"id":"s-other","tries":1.5,"scope":"owns","payload":""}]'
        "[5 entries for other sessions]" = ("[" + ((1..5 | ForEach-Object { '{"id":"s-o' + $_ + '","scope":"owns","tries":0,"payload":""}' }) -join ",") + "]")
    }
    $rp4Bad = New-Object System.Collections.ArrayList; $rp4Ok = New-Object System.Collections.ArrayList
    foreach ($k in $rpShapes.Keys) {
        Rp-Fresh
        try {
            [void](Invoke-Start "s-prev"); [void](Invoke-End "s-prev"); [void](Invoke-Start "s-p4")
            Rp-WithPending $rpShapes[$k]
            $script:LogLines.Clear()
            Rp-Restart
            $rec = Get-RecSid; $prevKept = (Test-SessionFinished "s-prev" $Global:RunningSessionFinished); $initWarn = (Rp-Warn "could not be initialized|could not initialize")
            $pendAfter = Rp-Pend
            [void](Rp-Pass)
            $u = Rp-Row $CMD_UPDATESESSIONDISPLAY ('{"mode":"Warn5","baySessionId":"s-p4","playEndUtc":"' + $endIso + '"}')
            $e = Rp-Row $CMD_ENDSESSION '{"mode":"End","baySessionId":"s-p4","closeLauncher":false}'
            $line = $k + " (record " + $rec + ", s-prev still ended=" + $prevKept + ", init errors logged=" + $initWarn + ", " + $pendAfter + ", Warn5 row " + $u + ", End row " + $e + ", intent closed=" + (Get-IntentNow).Closed + ")"
            if ($rec -eq "s-p4" -and $prevKept -and $initWarn -eq 0 -and $u -eq "InProgress>Succeeded" -and $e -eq "InProgress>Succeeded" -and (Get-IntentNow).Closed) { [void]$rp4Ok.Add($k) } else { [void]$rp4Bad.Add($line) }
        } catch { [void]$rp4Bad.Add($k + " THREW " + $_.Exception.Message) }
    }
    RpObs ("RP4 restart reader, endPending shape while s-p4 plays: member kept, ended list kept, Warn5 and End rows ran for [" + ($rp4Ok -join "; ") + "]")
    RpObs ("RP4 ...NOT so for " + $rp4Bad.Count + $(if ($rp4Bad.Count -gt 0) { ": " + ($rp4Bad -join " || ") } else { "" }))
    # a mark that names the PLAYING session itself (what a restart then does, by design: an End of it was received)
    Rp-Fresh
    $rpL = New-StandInLauncher
    try {
        [void](Invoke-Start "s-p4s")
        Rp-WithPending '[{"id":"s-p4s","payload":"","tries":0,"scope":"owns"}]'
        Rp-Restart; $st = Rp-State; $p1 = Rp-Pass; Start-Sleep -Milliseconds 400
        RpObs ("RP4s a mark naming the playing session, restart: " + $st + "; one pass: retried=" + ($null -ne $p1) + ", launcher still running=" + (Test-StandInAlive $rpL) + ", " + (Rp-State))
    } catch { RpObs ("RP4s threw: " + $_.Exception.Message) }
    finally { Remove-StandInLauncher $rpL }

    # ---------------------------------------------------------------- RP5: a STALE mark for an older session beside a member
    # who plays now. (a) the record file says the member plays and still lists the old mark; (b) the record file is older
    # (nobody, old mark) and the wall stamp, newer, says the member plays. Restart, one pass: the member's launcher?
    foreach ($v in @("a: record file names the member and the old mark", "b: record file stale (nobody + old mark), wall stamp newer names the member")) {
        Rp-Fresh
        $rpL = New-StandInLauncher
        try {
            [void](Invoke-Start "s-old5")
            Break-LauncherStep
            $first = Rp-Row $CMD_ENDSESSION '{"mode":"End","baySessionId":"s-old5"}'
            Repair-LauncherStep
            $lk = $null
            if ($v -match "^b") { Start-Sleep -Milliseconds 1200; $lk = New-Object IO.FileStream($RunningSessionPath, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read) }
            try { [void](Invoke-Start "s-play5") } finally { if ($null -ne $lk) { $lk.Dispose() } }
            $fileBefore = Rp-File
            Rp-Restart
            $st = Rp-State
            $p1 = Rp-Pass; Start-Sleep -Milliseconds 400
            $u = Rp-Row $CMD_UPDATESESSIONDISPLAY ('{"mode":"Warn5","baySessionId":"s-play5","playEndUtc":"' + $endIso + '"}')
            RpObs ("RP5" + $v + ": old End row " + $first + "; " + $fileBefore + "; restart: " + $st + "; one pass: retried=" + ($null -ne $p1) + ", MEMBER'S LAUNCHER STILL RUNNING=" + (Test-StandInAlive $rpL) + ", " + (Rp-State) + " | " + (Rp-File) + "; the member's Warn5 row " + $u)
        } catch { RpObs ("RP5" + $v + " threw: " + $_.Exception.Message) }
        finally { Remove-StandInLauncher $rpL; Repair-LauncherStep }
    }

    # ---------------------------------------------------------------- RP6: F4 ACROSS A RESTART. Nobody recorded, the wall on
    # the next booking's Prep, a late End of an older booking fails once after the mark; the agent restarts; one pass.
    Rp-Fresh
    $rpL = New-StandInLauncher
    try {
        [void](Invoke-Start "s-nx6" "Prep")
        Break-LauncherStep
        try { [void](Execute-Command -CommandType $CMD_ENDSESSION -PayloadJson '{"mode":"End","baySessionId":"s-old6"}' -BayLabel "Bay") } catch { }
        Repair-LauncherStep
        $fileBefore = Rp-File
        Rp-Restart; $st = Rp-State
        $p1 = Rp-Pass; Start-Sleep -Milliseconds 400
        $w6 = Get-IntentNow
        RpObs ("RP6 a late End of an older booking (nobody recorded, wall on the next Prep) fails once, " + $fileBefore + "; RESTART: " + $st + "; one pass: retried=" + ($null -ne $p1) + ", LAUNCHER STILL RUNNING=" + (Test-StandInAlive $rpL) + ", intent closed for s-old6=" + ($w6.Closed -and $w6.SessionId -eq "s-old6") + ", " + (Rp-State))
    } catch { RpObs ("RP6 threw: " + $_.Exception.Message) }
    finally { Remove-StandInLauncher $rpL; Repair-LauncherStep }

    # ---------------------------------------------------------------- RP7: the retry count across a restart.
    Rp-Fresh
    $rpL = New-StandInLauncher
    try {
        [void](Invoke-Start "s-p7")
        Break-LauncherStep; $script:GlThrows = 0; $script:LogLines.Clear()
        $first = Rp-Row $CMD_ENDSESSION '{"mode":"End","baySessionId":"s-p7"}'
        for ($i = 0; $i -lt 3; $i++) { [void](Rp-Pass) }
        $memBefore = Rp-Pend; $fileBefore = Rp-File; $attemptsBefore = $script:GlThrows
        Rp-Restart; $memAfter = Rp-Pend
        for ($i = 0; $i -lt 8; $i++) { [void](Rp-Pass) }
        RpObs ("RP7 a launcher step that keeps failing: first row " + $first + ", 3 passes -> attempts " + $attemptsBefore + ", " + $memBefore + ", " + $fileBefore + "; RESTART -> " + $memAfter + "; 8 more passes -> total attempts " + $script:GlThrows + ", gave-up WARN lines=" + (Rp-Warn "could not finish its protective act") + ", " + (Rp-Pend) + ", launcher still running=" + (Test-StandInAlive $rpL))
    } catch { RpObs ("RP7 threw: " + $_.Exception.Message) }
    finally { Remove-StandInLauncher $rpL; Repair-LauncherStep }

    # ---------------------------------------------------------------- RP8: the mark could not be WRITTEN at the End (the record
    # file held by another reader), the launcher step fails; no restart: does a later pass still retry and land the file?
    Rp-Fresh
    $rpL = New-StandInLauncher
    try {
        [void](Invoke-Start "s-p8")
        Break-LauncherStep
        $lk = New-Object IO.FileStream($RunningSessionPath, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
        try { $first = Rp-Row $CMD_ENDSESSION '{"mode":"End","baySessionId":"s-p8"}' } finally { $lk.Dispose() }
        Repair-LauncherStep
        $fileHeld = Rp-File; $mem = Rp-State
        $p1 = Rp-Pass; Start-Sleep -Milliseconds 400
        RpObs ("RP8 the record file held during the End, launcher step fails: row " + $first + "; " + $fileHeld + "; memory " + $mem + "; next pass (no restart): retried=" + ($null -ne $p1) + ", launcher still running=" + (Test-StandInAlive $rpL) + ", " + (Rp-File))
    } catch { RpObs ("RP8 threw: " + $_.Exception.Message) }
    finally { Remove-StandInLauncher $rpL; Repair-LauncherStep }

    # ---------------------------------------------------------------- RP9: the REAL BayAgent.ps1, stopped (hard exit 77) in
    # the first run AND again inside the retry, then run clean. Reads the wall as well as the launcher after each stage.
    if ((Get-Command Invoke-RealLoopCase).Parameters.ContainsKey("KillAnchor")) {
        function Rp-Stage($c) { return ("exit " + $c.ExitCode + " | wall " + $c.Wall + " | intent " + $c.Intent + " | running=" + $c.Running + " | finished=[" + $c.Finished + "] | pending=[" + $c.Pending + "] | launcher alive=" + $c.LauncherAlive) }
        function Rp-LogCount($c, [string]$rx) { $n = 0; try { foreach ($f in @(Get-ChildItem -LiteralPath (Join-Path $c.Root "logs") -File -ErrorAction SilentlyContinue)) { $n += @(Get-Content -LiteralPath $f.FullName | Where-Object { $_ -match $rx }).Count } } catch { }; return $n }
        $aList = 'Add-FinishedSession -SessionId $endSid -Why "EndSession"'
        $aRec = 'if ($endScope.Scope -eq "running") { $null = Set-RunningSessionForCommand -CommandType $CMD_ENDSESSION -Mode "End" -Payload $payloadObj }'
        $aIntent = '$kioskIntent = Set-KioskIntentForCommand -CommandType $CMD_ENDSESSION -Mode "End" -Payload $payloadObj -SameSession $sameSession'
        $aClose = '$launcherStopped = Stop-ProcessesGracefully $procs 8'
        $aTries = '$e["tries"] = $tries + 1'
        $aMark = 'Add-EndPending -SessionId $endSid -Payload $payloadObj -Scope $(if ($endOwns) { "owns" } else { "leaves" })'
        $rp9 = @(
            @{ N = "first run stopped after the record is cleared, then run clean"; K1 = $aRec; W1 = "after"; K2 = "" },
            @{ N = "first run stopped after the mark, then run clean"; K1 = $aMark; W1 = "after"; K2 = "" },
            @{ N = "first run stopped after the ended list; the RETRY stopped at its start"; K1 = $aList; W1 = "after"; K2 = $aTries; W2 = "after" },
            @{ N = "first run stopped after the ended list; the RETRY stopped after the intent write"; K1 = $aList; W1 = "after"; K2 = $aIntent; W2 = "after" },
            @{ N = "first run stopped after the ended list; the RETRY stopped after the launcher close"; K1 = $aList; W1 = "after"; K2 = $aClose; W2 = "after" }
        )
        $rpi = 0
        foreach ($c9 in $rp9) {
            $rpi++; $s1 = $null
            try {
                $s1 = Invoke-RealLoopCase ("rp9-" + $rpi) -60 -KillAnchor $c9.K1 -KillWhere $c9.W1 -Keep
                $line = "RP9 real agent, " + $c9.N + ": [1] " + (Rp-Stage $s1)
                if (-not [string]::IsNullOrEmpty($c9.K2)) {
                    $s2 = Invoke-RealLoopCase ("rp9-" + $rpi) -60 -KillAnchor $c9.K2 -KillWhere $c9.W2 -Reuse $s1 -Keep
                    $line += " || [2] " + (Rp-Stage $s2)
                }
                $s3 = Invoke-RealLoopCase ("rp9-" + $rpi) -60 -Reuse $s1 -Keep
                $line += " || [clean] " + (Rp-Stage $s3)
                $s4 = Invoke-RealLoopCase ("rp9-" + $rpi) -60 -Reuse $s1 -Keep
                $line += " || [clean again] " + (Rp-Stage $s4) + " || log: retried-the-End lines=" + (Rp-LogCount $s1 "retried the End of session") + ", ended-after-its-warning lines=" + (Rp-LogCount $s1 "ended after its warning") + ", session-ended-here lines=" + (Rp-LogCount $s1 "ended here \(")
                RpObs $line
            } catch { RpObs ("RP9 [" + $c9.N + "] threw: " + $_.Exception.Message) }
            finally { if ($null -ne $s1) { Remove-StandInLauncher $s1.Sl } }
        }
    } else { RpObs "RP9 skipped: this tree's real-loop case has no kill points" }
    } finally {
        $script:RpDieAtModel = $false; $script:RpDieAtList = $false
        . ([scriptblock]::Create($rpRealNorm.Replace("function Normalize-SessionModel", "function script:Normalize-SessionModel")))
        . ([scriptblock]::Create($rpRealAddFin.Replace("function Add-FinishedSession", "function script:Add-FinishedSession")))
        Repair-LauncherStep
        Rp-Fresh
        $Global:EmergencyStopEngaged = $false
    }
    if ($env:RP_STOP -eq "1") { throw "rp-stop: the probe block is done (iteration run)" }
