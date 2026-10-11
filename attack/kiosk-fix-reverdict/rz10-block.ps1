    # ====================================================================================================================
    # RZ10 (kiosk round 2 FIX re-verdict, 2026-10-10): STATE DRIFT. For each store the bay keeps (the ended list and the
    # running-session record in state\running-session.json, the cancel timer in that record and in the wall stamp, the
    # who-plays stamp in session.json, the pending-End mark in memory), what a restart, a failed write or a missing or
    # unreadable file does to the two things that must not fail open: a refusal that should still apply, and a launcher
    # that should be closed. Spliced after K22 (its row stub, stand-in launcher and failing-step helpers are used).
    # Self-contained: no helper from the other probe blocks. Hyphens only in comments.
    # ====================================================================================================================
    Section "RZ10 state drift: restarts, failed writes, missing and unreadable files"
    function RdObs([string]$m) { Write-Host ("  OBS   " + $m) }
    function Rd-Fresh {
        Clear-Bay; Remove-Item -LiteralPath $sessPath -Force -ErrorAction SilentlyContinue
        Remove-Item -LiteralPath $KioskIntentPath -Force -ErrorAction SilentlyContinue
        $Global:KioskIntentExpectedText = $null; $Global:KioskIntentPending = $false
        Initialize-KioskIntent -NowUtc ((Get-Date).ToUniversalTime())
    }
    function Rd-Restart {
        $Global:RunningSession = $null; $Global:RunningSessionFinished = @(); $Global:RunningSessionPending = $false
        $Global:RunningSessionEndPending = @(); $Global:RunningSessionOwnEnd = $false
        $Global:KioskIntentExpectedText = $null; $Global:KioskIntentPending = $false
        Initialize-RunningSession -NowUtc ((Get-Date).ToUniversalTime()); Initialize-KioskIntent -NowUtc ((Get-Date).ToUniversalTime())
    }
    function Rd-Pay([string]$mode, [string]$sid) { return ('{"mode":"' + $mode + '","baySessionId":"' + $sid + '","bookingId":"b0000000-0000-0000-0000-00000000dddd","startUtc":"2026-10-08T12:00:00Z","playEndUtc":"' + $endIso + '","endUtc":"' + $endIso + '","closeLauncher":false}') }
    function Rd-Row([int]$type, [string]$payload) {
        $script:Patches3.Clear()
        try { Process-Command -token "t" -cmd (New-CmdRow $type $payload) } catch { return ("THREW " + $_.Exception.Message) }
        $rows = @($script:Patches3 | Where-Object { $_.Set -ne "build_bookings" })
        $names = @($rows | ForEach-Object { $v = $_.Body[$Col_Status]; if ($v -eq $STATUS_SKIPPED) { "Skipped" } elseif ($v -eq $STATUS_INPROGRESS) { "InProgress" } elseif ($v -eq $STATUS_SUCCEEDED) { "Succeeded" } elseif ($v -eq $STATUS_FAILED) { "Failed" } else { [string]$v } })
        $res = ""; if ($rows.Count -gt 0) { $lb = $rows[$rows.Count - 1].Body; if ($lb.ContainsKey($Col_Result)) { $res = [string]$lb[$Col_Result] } }
        return (($names -join ">") + $(if ($res -match '"skipped":\s*true') { " (result says skipped)" } else { "" }))
    }
    function Rd-Refused([string]$rowText) { return ($rowText -eq "Skipped" -or $rowText -match "result says skipped") }
    function Rd-State {
        $w = Get-KioskLauncherWanted -IntentRead (Read-KioskJsonFile -Path $KioskIntentPath) -NowUtc ((Get-Date).ToUniversalTime())
        return ("record=" + (Get-RecSid) + " cancelEnd=" + (Get-RecCancel) + " ended=[" + ((@($Global:RunningSessionFinished) | ForEach-Object { [string](Get-KioskProp $_ "id" "") }) -join ",") + "] | wall " + (Get-SessStatus) + " | intent " + $(if ($w.Closed) { "closed" } elseif ($w.Wanted) { "wanted" } else { "hands off" }) + "/" + $w.SessionId + " | shell on a running launcher: " + (Get-ShellVerdictNow))
    }
    $nul8 = (New-Object string ([char]0), 8)
    $rdShapes = [ordered]@{
        "kept as written" = $null
        "missing" = "<delete>"
        "0 bytes" = ""
        "whitespace" = "  `r`n"
        "NUL bytes" = $nul8
        "not JSON" = "{ this is not json"
        "truncated" = '{"schema":1,"running":false,"finished":[{"id":"s-d'
        "null" = "null"
        "empty object" = "{}"
        "array" = "[]"
        "valid, no finished key" = '{"schema":1,"running":false,"baySessionId":null,"writtenUtc":"2026-10-10T00:00:00Z"}'
        "valid, finished is text" = '{"schema":1,"running":false,"finished":"s-d1","writtenUtc":"2026-10-10T00:00:00Z"}'
        "valid, finished ids are numbers" = '{"schema":1,"running":false,"finished":[{"id":7,"utc":"x"}],"writtenUtc":"2026-10-10T00:00:00Z"}'
    }

    # ---------------------------------------------------------------- D1: the ENDED LIST. A booking canceled mid-play was ended
    # at its mark; the agent restarts over each shape of the record file; then that booking's Start arrives (reinstated).
    $d1Open = New-Object System.Collections.ArrayList; $d1Held = New-Object System.Collections.ArrayList
    foreach ($k in $rdShapes.Keys) {
        Rd-Fresh
        [void](Invoke-Start "s-d1"); $endsD1 = Get-EndsOf (Invoke-BoundReset "s-d1")
        [void](Invoke-CancelEndIfDue -NowUtc $endsD1.AddSeconds(1))
        if ($rdShapes[$k] -eq "<delete>") { Remove-Item -LiteralPath $RunningSessionPath -Force -ErrorAction SilentlyContinue }
        elseif ($null -ne $rdShapes[$k]) { Set-TestFile $RunningSessionPath $rdShapes[$k] }
        Rd-Restart
        $row = Rd-Row $CMD_STARTSESSION (Rd-Pay "Start" "s-d1")
        if (Rd-Refused $row) { [void]$d1Held.Add($k) } else { [void]$d1Open.Add($k + " (row " + $row + ")") }
    }
    RdObs ("RZ10 D1 ended list, record file shape at a restart AFTER the canceled booking was ended, then its Start: STILL REFUSED for [" + ($d1Held -join "; ") + "]")
    RdObs ("RZ10 D1 ...ACCEPTED (the booking plays again) for [" + ($d1Open -join "; ") + "]")
    # the ended list never reached the file (held open by another reader at the End), then a restart
    Rd-Fresh
    [void](Invoke-Start "s-d1b"); $endsD1b = Get-EndsOf (Invoke-BoundReset "s-d1b")
    $lk = New-Object IO.FileStream($RunningSessionPath, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
    try { [void](Invoke-CancelEndIfDue -NowUtc $endsD1b.AddSeconds(1)) } finally { $lk.Dispose() }
    $memState = Rd-State
    Rd-Restart
    $afterRestart = Rd-State
    $again = Invoke-CancelEndIfDue -NowUtc $endsD1b.AddSeconds(30)
    RdObs ("RZ10 D1b the record file could not be written at the cancel End (in memory: " + $memState + "); agent restarts before it lands: " + $afterRestart + "; first pass ends it again=" + ($null -ne $again) + " -> " + (Rd-State))

    # ---------------------------------------------------------------- D2: the CANCEL TIMER during the warning.
    # (a) record file shapes with the wall (and its stamp) intact; (b) the wall lost with the record file intact;
    # (c) writes that failed at the cancel; (d) both stores gone. After the restart: is the hold still there, and does
    # the game still end at the mark?
    $d2Held = New-Object System.Collections.ArrayList; $d2Lost = New-Object System.Collections.ArrayList
    foreach ($k in $rdShapes.Keys) {
        Rd-Fresh
        [void](Invoke-Start "s-d2"); $endsD2 = Get-EndsOf (Invoke-BoundReset "s-d2")
        if ($rdShapes[$k] -eq "<delete>") { Remove-Item -LiteralPath $RunningSessionPath -Force -ErrorAction SilentlyContinue }
        elseif ($null -ne $rdShapes[$k]) { Set-TestFile $RunningSessionPath $rdShapes[$k] }
        Rd-Restart
        $row = Rd-Row $CMD_STARTSESSION (Rd-Pay "Start" "s-d2")
        $endRes = Invoke-CancelEndIfDue -NowUtc $endsD2.AddSeconds(1)
        $ok = ((Rd-Refused $row) -and $null -ne $endRes -and (Get-RecSid) -eq "<none>" -and (Get-IntentNow).Closed)
        if ($ok) { [void]$d2Held.Add($k) } else { [void]$d2Lost.Add($k + " (Start row " + $row + ", ended at the mark=" + ($null -ne $endRes) + ", " + (Rd-State) + ")") }
    }
    RdObs ("RZ10 D2a cancel timer, record file shape at a restart DURING the warning (wall intact): hold kept and game ended at the mark for [" + ($d2Held -join "; ") + "]")
    RdObs ("RZ10 D2a ...LOST for [" + ($d2Lost -join " || ") + "]")
    $d2bLines = New-Object System.Collections.ArrayList
    foreach ($w in @("0 bytes", "not JSON", "stamp removed (wall readable)")) {
        Rd-Fresh
        [void](Invoke-Start "s-d2w"); $endsD2w = Get-EndsOf (Invoke-BoundReset "s-d2w")
        if ($w -eq "0 bytes") { Set-TestFile $sessPath "" } elseif ($w -eq "not JSON") { Set-TestFile $sessPath "{ nope" }
        else { $o = [IO.File]::ReadAllText($sessPath) | ConvertFrom-Json; $o.PSObject.Properties.Remove("agentRunning"); Set-TestFile $sessPath ($o | ConvertTo-Json -Depth 8) }
        Rd-Restart
        $row = Rd-Row $CMD_STARTSESSION (Rd-Pay "Start" "s-d2w")
        $endRes = Invoke-CancelEndIfDue -NowUtc $endsD2w.AddSeconds(1)
        [void]$d2bLines.Add("wall " + $w + ": Start row " + $row + ", ended at the mark=" + ($null -ne $endRes))
    }
    RdObs ("RZ10 D2b the wall damaged, record file intact, restart during the warning: " + ($d2bLines -join "; "))
    $d2cLines = New-Object System.Collections.ArrayList
    # The restart picks the NEWER of the record file and the wall stamp, to the second, and on a tie the stamp wins. So each
    # case runs twice: the cancel 2 seconds after the last wall write (any real cancel), and in the same second (a tie).
    foreach ($c in @("record file held at the cancel", "wall held at the cancel", "both held at the cancel", "wall held at the cancel, SAME SECOND as the last wall write", "nothing held, SAME SECOND as the last wall write")) {
        Rd-Fresh
        [void](Invoke-Start "s-d2c")
        if ($c -notmatch "SAME SECOND") { Start-Sleep -Milliseconds 2100 }
        $l1 = $null; $l2 = $null
        if ($c -match "^record file held|^both held") { $l1 = New-Object IO.FileStream($RunningSessionPath, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read) }
        if ($c -match "^wall held|^both held") { $l2 = New-Object IO.FileStream($sessPath, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read) }
        $endsD2c = $null
        try { $endsD2c = Get-EndsOf (Invoke-BoundReset "s-d2c") } finally { if ($null -ne $l1) { $l1.Dispose() }; if ($null -ne $l2) { $l2.Dispose() } }
        $inMem = (Get-RecCancel)
        Rd-Restart
        $row = Rd-Row $CMD_STARTSESSION (Rd-Pay "Start" "s-d2c")
        $endRes = $(if ($null -ne $endsD2c) { Invoke-CancelEndIfDue -NowUtc $endsD2c.AddSeconds(1) } else { $null })
        [void]$d2cLines.Add($c + " (timer in memory=" + ($null -ne $inMem) + "), restart before any retry: Start row " + $row + ", ended at the mark=" + ($null -ne $endRes) + ", " + (Rd-State))
    }
    foreach ($l in $d2cLines) { RdObs ("RZ10 D2c " + $l) }
    # the same failed writes WITHOUT a restart: the next pass must land them
    Rd-Fresh
    [void](Invoke-Start "s-d2n")
    $l1 = New-Object IO.FileStream($RunningSessionPath, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
    try { [void](Invoke-BoundReset "s-d2n") } finally { $l1.Dispose() }
    $pendBefore = [bool]$Global:RunningSessionPending
    Release-IntentLock
    $fileNow = $null; try { $fileNow = [IO.File]::ReadAllText($RunningSessionPath) | ConvertFrom-Json } catch { }
    RdObs ("RZ10 D2n record file held at the cancel, no restart: write pending=" + $pendBefore + "; after one reconcile pass pending=" + [bool]$Global:RunningSessionPending + ", file cancelEndUtc=" + (Get-PropValue $fileNow "cancelEndUtc" ""))

    # ---------------------------------------------------------------- D3: the PENDING-END MARK (memory only).
    # The agent dies after the session is listed as ended. (a) after the intent was written closed (the builder's case);
    # (b) BEFORE the intent write; (c) the mark given up after 5 tries. A real stand-in launcher process each time.
    foreach ($when in @("after the intent write", "before the intent write")) {
        Rd-Fresh
        $rdL = New-StandInLauncher
        $realSetIntent = (Get-Command Set-KioskIntentForCommand).Definition
        try {
            [void](Invoke-Start "s-d3")
            if ($when -eq "after the intent write") { Break-LauncherStep }
            else {
                $script:RdIntentBody = $realSetIntent
                function script:Rd-RealSetKioskIntent { param([int]$CommandType, [string]$Mode, $Payload, [bool]$SameSession = $true) & ([scriptblock]::Create($script:RdIntentBody)) -CommandType $CommandType -Mode $Mode -Payload $Payload -SameSession $SameSession }
                function script:Set-KioskIntentForCommand { param([int]$CommandType, [string]$Mode, $Payload, [bool]$SameSession = $true)
                    if ($script:RdDieAtIntent -and $CommandType -eq $CMD_ENDSESSION) { throw "rz10: the agent process dies here (simulated)" }
                    return (Rd-RealSetKioskIntent -CommandType $CommandType -Mode $Mode -Payload $Payload -SameSession $SameSession) }
                $script:RdDieAtIntent = $true
            }
            $first = Rd-Row $CMD_ENDSESSION '{"mode":"End","baySessionId":"s-d3"}'
            Repair-LauncherStep; $script:RdDieAtIntent = $false
            $marks = @($Global:RunningSessionEndPending).Count
            Rd-Restart
            $p1 = Invoke-CancelEndIfDue -NowUtc ((Get-Date).ToUniversalTime()); $p2 = Invoke-CancelEndIfDue -NowUtc ((Get-Date).ToUniversalTime())
            $resent = Rd-Row $CMD_ENDSESSION '{"mode":"End","baySessionId":"s-d3"}'
            Start-Sleep -Milliseconds 500
            RdObs ("RZ10 D3 the End stops " + $when + " (row " + $first + ", marks in memory " + $marks + "), the agent restarts: retried=" + ($null -ne $p1 -or $null -ne $p2) + "; the End sent again: row " + $resent + "; LAUNCHER STILL RUNNING=" + (Test-StandInAlive $rdL) + " | " + (Rd-State))
        } catch { RdObs ("RZ10 D3 [" + $when + "] threw: " + $_.Exception.Message) }
        finally {
            Remove-StandInLauncher $rdL; Repair-LauncherStep; $script:RdDieAtIntent = $false
            . ([scriptblock]::Create((Get-DefText $AgentDefs "Set-KioskIntentForCommand").Replace("function Set-KioskIntentForCommand", "function script:Set-KioskIntentForCommand")))
        }
    }
    # the same stop WITHOUT a restart: the retry closes it
    Rd-Fresh
    $rdL = New-StandInLauncher
    try {
        [void](Invoke-Start "s-d3n")
        Break-LauncherStep
        $first = Rd-Row $CMD_ENDSESSION '{"mode":"End","baySessionId":"s-d3n"}'
        Repair-LauncherStep
        $p1 = Invoke-CancelEndIfDue -NowUtc ((Get-Date).ToUniversalTime())
        Start-Sleep -Milliseconds 500
        RdObs ("RZ10 D3n the same stop with NO restart: next pass retry scope=" + (Get-PropValue $p1 "scope" "none") + "; launcher still running=" + (Test-StandInAlive $rdL) + " | " + (Rd-State))
    } finally { Remove-StandInLauncher $rdL; Repair-LauncherStep }

    # ---------------------------------------------------------------- D4: the record of WHO PLAYS, for a member who is playing
    # (not canceled). Each record file shape at a restart with the wall intact, then that member's Warn5 and End rows:
    # they must still run (a drifted record must not turn a paying member's commands away or leave the End a no-op).
    $d4Bad = New-Object System.Collections.ArrayList
    foreach ($k in $rdShapes.Keys) {
        Rd-Fresh
        [void](Invoke-Start "s-d4")
        if ($rdShapes[$k] -eq "<delete>") { Remove-Item -LiteralPath $RunningSessionPath -Force -ErrorAction SilentlyContinue }
        elseif ($null -ne $rdShapes[$k]) { Set-TestFile $RunningSessionPath $rdShapes[$k] }
        Rd-Restart
        $recAfter = Get-RecSid
        $u = Rd-Row $CMD_UPDATESESSIONDISPLAY ('{"mode":"Warn5","baySessionId":"s-d4","playEndUtc":"' + $endIso + '"}')
        $e = Rd-Row $CMD_ENDSESSION '{"mode":"End","baySessionId":"s-d4","closeLauncher":false}'
        $closed = (Get-IntentNow).Closed
        if ($u -ne "InProgress>Succeeded" -or $e -ne "InProgress>Succeeded" -or -not $closed) { [void]$d4Bad.Add($k + " (record after restart " + $recAfter + ", Warn5 row " + $u + ", End row " + $e + ", intent closed=" + $closed + ")") }
    }
    RdObs ("RZ10 D4 a playing member, record file shape at a restart (wall intact): shapes where the member's Warn5 or End did not run or the End did not close the intent: " + $d4Bad.Count + $(if ($d4Bad.Count -gt 0) { " -> " + ($d4Bad -join " || ") } else { "" }))
    Rd-Fresh
    $Global:EmergencyStopEngaged = $false
