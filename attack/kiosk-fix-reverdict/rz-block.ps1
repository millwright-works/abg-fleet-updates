    # ====================================================================================================================
    # RE-VERDICT PROBES (kiosk round 2 FIX, 2026-10-10). Spliced into a COPY of BayAgent.Kiosk.Tests.ps1 right before the
    # "restore the suite's e-stop stubs" line, AFTER K22, so K22's row stub (Patches3), its stand-in launcher and its
    # failing-step helpers are live. The predecessor's vy-block is spliced earlier in the same copy (before K22), so its
    # helpers (Obs, Vy-Fresh, Get-WallBrief, Get-IntentBrief, Get-RecBrief) exist. Observations print as "  OBS   ...".
    # Hyphens only in comments.
    # ====================================================================================================================
    Section "RZ re-verdict probes (kiosk round 2 fix)"
    $script:RzBk = "b0000000-0000-0000-0000-00000000aaaa"
    function Rz-Pay([string]$mode, [string]$sid, [string]$extra = "") { return ('{"mode":"' + $mode + '","baySessionId":"' + $sid + '","bookingId":"' + $script:RzBk + '","startUtc":"2026-10-08T12:00:00Z","playEndUtc":"' + $endIso + '","endUtc":"' + $endIso + '","closeLauncher":false' + $extra + '}') }
    function Rz-Upd([string]$sid, [int]$addMinutes = 0) {
        $e = (ConvertTo-KioskUtc $endIso).AddMinutes($addMinutes).ToString("yyyy-MM-ddTHH:mm:ssZ")
        $sidPart = $(if ($sid -ne "<none>") { '"baySessionId":"' + $sid + '",' } else { "" })
        return ('{"mode":"Warn5",' + $sidPart + '"playEndUtc":"' + $e + '","sessionEndUtc":"' + $e + '","message":"5 minutes remaining"}')
    }
    function Rz-StatusName($v) {
        if ($null -eq $v) { return "?" }
        if ($v -eq $STATUS_INPROGRESS) { return "InProgress" }; if ($v -eq $STATUS_SUCCEEDED) { return "Succeeded" }
        if ($v -eq $STATUS_FAILED) { return "Failed" }; if ($v -eq $STATUS_SKIPPED) { return "Skipped" }
        return [string]$v
    }
    function Rz-Row([int]$type, [string]$payload) {
        # One command row through the real Process-Command. Returns what the row and the booking were written.
        $script:Patches3.Clear()
        $threw = ""
        try { Process-Command -token "t" -cmd (New-CmdRow $type $payload) } catch { $threw = $_.Exception.Message }
        $rows = @($script:Patches3 | Where-Object { $_.Set -ne "build_bookings" })
        $bk = @($script:Patches3 | Where-Object { $_.Set -eq "build_bookings" })
        $sts = @($rows | ForEach-Object { Rz-StatusName $_.Body[$Col_Status] })
        $resText = ""
        if ($rows.Count -gt 0) { $lb = $rows[$rows.Count - 1].Body; if ($lb.ContainsKey($Col_Result)) { $resText = [string]$lb[$Col_Result] } }
        $o = @{ Statuses = ($sts -join ">"); First = $(if ($sts.Count -gt 0) { $sts[0] } else { "" }); Last = $(if ($sts.Count -gt 0) { $sts[$sts.Count - 1] } else { "" })
                Result = $resText; Booking = ((@($bk | ForEach-Object { [string]$_.Body["statuscode"] })) -join ","); Threw = $threw
                HandlerSkipped = ($resText -match '"skipped":\s*true'); Scope = ""; LauncherReason = ""; Refusal = "" }
        if ($resText -match '"scope":"([^"]+)"') { $o.Scope = $Matches[1] }
        if ($resText -match '"refusal":"([^"]+)"') { $o.Refusal = $Matches[1] }
        if ($resText -match '"launcherStopped":\{[^}]*"reason":"([^"]+)"') { $o.LauncherReason = $Matches[1] }
        return $o
    }
    function Rz-RowBrief($o) { return ("row " + $o.Statuses + $(if ($o.HandlerSkipped) { " (result says skipped)" } else { "" }) + $(if ($o.Booking) { " booking->" + $o.Booking } else { "" }) + $(if ($o.Threw) { " THREW " + $o.Threw } else { "" })) }
    function Rz-Ran($o) { return ($o.First -eq "InProgress" -and $o.Last -eq "Succeeded" -and -not $o.HandlerSkipped -and -not $o.Threw) }
    function Rz-Restart([bool]$DropRecordFile = $false, [bool]$DropWall = $false) {
        # What an agent restart keeps: the record file, the wall files, the intent file. Everything in memory is gone.
        if ($DropRecordFile) { Remove-Item -LiteralPath $RunningSessionPath -Force -ErrorAction SilentlyContinue }
        if ($DropWall) { Set-TestFile $sessPath "" }
        $Global:RunningSession = $null; $Global:RunningSessionFinished = @(); $Global:RunningSessionPending = $false
        $Global:RunningSessionEndPending = @(); $Global:RunningSessionOwnEnd = $false
        $Global:KioskIntentExpectedText = $null; $Global:KioskIntentPending = $false
        Initialize-RunningSession -NowUtc ((Get-Date).ToUniversalTime()); Initialize-KioskIntent -NowUtc ((Get-Date).ToUniversalTime())
    }
    function Rz-Pass { return (Invoke-CancelEndIfDue -NowUtc ((Get-Date).ToUniversalTime())) }
    function Rz-PendBrief { return ("pending=[" + ((@($Global:RunningSessionEndPending) | ForEach-Object { [string](Get-KioskProp $_ "id" "") + "/tries " + [string](Get-KioskProp $_ "tries" "") }) -join ",") + "]") }

    # ---------------------------------------------------------------- RZ3: a paying member's own commands are never refused
    # Every row below is for a booking that was NOT canceled and NOT ended. Each must lock, run and read Succeeded.
    $rz3Bad = New-Object System.Collections.ArrayList
    function Rz-MustRun([string]$label, [int]$type, [string]$payload) {
        $o = Rz-Row $type $payload
        if (-not (Rz-Ran $o)) { [void]$rz3Bad.Add($label + ": " + (Rz-RowBrief $o) + " refusal=" + $o.Refusal) }
        return $o
    }
    # (a) plain session
    Vy-Fresh
    $a1 = Rz-MustRun "a Start" $CMD_STARTSESSION (Rz-Pay "Start" "s-pa")
    $a2 = Rz-MustRun "a duplicate Start" $CMD_STARTSESSION (Rz-Pay "Start" "s-pa")
    $a3 = Rz-MustRun "a Warn5" $CMD_UPDATESESSIONDISPLAY (Rz-Upd "s-pa")
    $a4 = Rz-MustRun "a extension +30" $CMD_UPDATESESSIONDISPLAY (Rz-Upd "s-pa" 30)
    $a5 = Rz-MustRun "a End" $CMD_ENDSESSION (Rz-Pay "End" "s-pa")
    Obs ("RZ3a plain paying session through rows: Start " + $a1.Statuses + " booking->" + $a1.Booking + "; dup Start " + $a2.Statuses + "; Warn5 " + $a3.Statuses + "; extension " + $a4.Statuses + "; End " + $a5.Statuses + " booking->" + $a5.Booking)
    # (b) a restart mid-session, with and without the record file
    foreach ($drop in @($false, $true)) {
        Vy-Fresh
        [void](Rz-MustRun "b Start" $CMD_STARTSESSION (Rz-Pay "Start" "s-pb"))
        Rz-Restart -DropRecordFile $drop
        $b2 = Rz-MustRun ("b Warn5 after restart drop=" + $drop) $CMD_UPDATESESSIONDISPLAY (Rz-Upd "s-pb")
        $b3 = Rz-MustRun ("b extension after restart drop=" + $drop) $CMD_UPDATESESSIONDISPLAY (Rz-Upd "s-pb" 30)
        $b4 = Rz-MustRun ("b End after restart drop=" + $drop) $CMD_ENDSESSION (Rz-Pay "End" "s-pb")
        Obs ("RZ3b restart mid-session (record file dropped=" + $drop + "): Warn5 " + $b2.Statuses + "; extension " + $b3.Statuses + "; End " + $b4.Statuses + " booking->" + $b4.Booking + " | " + (Get-RecBrief))
    }
    # (c) ANOTHER booking on this bay is canceled while this member plays (the platform sends that Reset at once)
    Vy-Fresh
    [void](Rz-MustRun "c Start" $CMD_STARTSESSION (Rz-Pay "Start" "s-pc"))
    [void](Invoke-BoundReset "s-other1"); [void](Invoke-BoundReset "s-other2")
    $c2 = Rz-MustRun "c Warn5 after another booking's cancel" $CMD_UPDATESESSIONDISPLAY (Rz-Upd "s-pc")
    $c3 = Rz-MustRun "c End after another booking's cancel" $CMD_ENDSESSION (Rz-Pay "End" "s-pc")
    Obs ("RZ3c another booking canceled twice while s-pc plays: record cancel=" + (Get-RecCancel) + "; Warn5 " + $c2.Statuses + "; End " + $c3.Statuses)
    # (d) the PREVIOUS booking was canceled mid-play and ended at its mark; then this member's booking
    Vy-Fresh
    [void](Invoke-Start "s-cd"); $endsCd = Get-EndsOf (Invoke-BoundReset "s-cd")
    [void](Invoke-CancelEndIfDue -NowUtc $endsCd.AddSeconds(1))
    $d0 = Rz-MustRun "d Prep after a canceled booking ended" $CMD_STARTSESSION (Rz-Pay "Prep" "s-pd")
    $d1 = Rz-MustRun "d Start after a canceled booking ended" $CMD_STARTSESSION (Rz-Pay "Start" "s-pd")
    Rz-Restart
    $d2 = Rz-MustRun "d Warn5 (after a restart)" $CMD_UPDATESESSIONDISPLAY (Rz-Upd "s-pd")
    $d3 = Rz-MustRun "d End" $CMD_ENDSESSION (Rz-Pay "End" "s-pd")
    Obs ("RZ3d the booking after a canceled-and-ended one: Prep " + $d0.Statuses + "; Start " + $d1.Statuses + "; Warn5 " + $d2.Statuses + "; End " + $d3.Statuses + " | " + (Get-RecBrief))
    # (e) this member's booking takes the bay DURING the canceled booking's warning; the old mark then passes
    Vy-Fresh
    [void](Invoke-Start "s-ce"); $endsCe = Get-EndsOf (Invoke-BoundReset "s-ce")
    $e0 = Rz-MustRun "e Prep during another booking's warning" $CMD_STARTSESSION (Rz-Pay "Prep" "s-pe")
    $e1 = Rz-MustRun "e Start during another booking's warning" $CMD_STARTSESSION (Rz-Pay "Start" "s-pe")
    $e2 = Rz-MustRun "e Warn5" $CMD_UPDATESESSIONDISPLAY (Rz-Upd "s-pe")
    $eMark = Invoke-CancelEndIfDue -NowUtc $endsCe.AddSeconds(5)
    $e3 = Rz-MustRun "e extension after the old mark passed" $CMD_UPDATESESSIONDISPLAY (Rz-Upd "s-pe" 30)
    Obs ("RZ3e a booking that starts during another's warning: Prep " + $e0.Statuses + "; Start " + $e1.Statuses + "; Warn5 " + $e2.Statuses + "; the old mark passing ended something=" + ($null -ne $eMark) + "; extension " + $e3.Statuses + " | " + (Get-RecBrief) + " | " + (Get-IntentBrief) + " | shell on its launcher: " + (Get-ShellVerdictNow))
    $e4 = Rz-MustRun "e End" $CMD_ENDSESSION (Rz-Pay "End" "s-pe")
    # (f) the same session id written with braces and capitals by the platform
    Vy-Fresh
    [void](Rz-MustRun "f Start" $CMD_STARTSESSION (Rz-Pay "Start" "0f0f0f0f-0000-0000-0000-00000000000f"))
    $f2 = Rz-MustRun "f Warn5 braces+caps" $CMD_UPDATESESSIONDISPLAY (Rz-Upd "{0F0F0F0F-0000-0000-0000-00000000000F}")
    $f3 = Rz-MustRun "f End caps" $CMD_ENDSESSION (Rz-Pay "End" "0F0F0F0F-0000-0000-0000-00000000000F")
    Obs ("RZ3 paying-member rows refused or not run: " + $rz3Bad.Count + $(if ($rz3Bad.Count -gt 0) { " -> " + ($rz3Bad -join " || ") } else { "" }))
    Assert-True ($rz3Bad.Count -eq 0) "RZ3 no row of a booking that was neither canceled nor ended is refused, skipped or left unrun"

    # ---------------------------------------------------------------- RZ1: the canceled booking after ANOTHER booking took the bay
    Vy-Fresh
    [void](Invoke-Start "s-z1"); $endsZ1 = Get-EndsOf (Invoke-BoundReset "s-z1")
    [void](Invoke-Start "s-t1")
    Obs ("RZ1 s-z1 canceled, then s-t1 (a new booking) starts during the warning: " + (Get-RecBrief) + " | " + (Get-WallBrief))
    $z1s = Rz-Row $CMD_STARTSESSION (Rz-Pay "Start" "s-z1")
    Obs ("RZ1 then a Start of the canceled s-z1 arrives (reinstated by hand): " + (Rz-RowBrief $z1s) + " | " + (Get-RecBrief) + " | " + (Get-WallBrief) + " | " + (Get-IntentBrief))
    $z1e = Rz-Row $CMD_ENDSESSION (Rz-Pay "End" "s-t1")
    Obs ("RZ1 then s-t1's own End: " + (Rz-RowBrief $z1e) + " scope=" + $z1e.Scope + " launcher=" + $z1e.LauncherReason + " | " + (Get-RecBrief) + " | " + (Get-WallBrief))
    $z1m = Invoke-CancelEndIfDue -NowUtc $endsZ1.AddMinutes(10)
    Obs ("RZ1 10 minutes after the old mark: anything ended=" + ($null -ne $z1m) + " | " + (Get-RecBrief) + " | " + (Get-IntentBrief))

    # ---------------------------------------------------------------- RZ2: commands that name NO session during the warning
    Vy-Fresh
    [void](Invoke-Start "s-z2"); $endsZ2 = Get-EndsOf (Invoke-BoundReset "s-z2")
    $wallZ2 = [IO.File]::ReadAllText($sessPath)
    $z2u = Rz-Row $CMD_UPDATESESSIONDISPLAY (Rz-Upd "<none>" 30)
    Obs ("RZ2 a display update naming NO session during s-z2's warning: " + (Rz-RowBrief $z2u) + " wall changed=" + ([IO.File]::ReadAllText($sessPath) -cne $wallZ2) + " | " + (Get-WallBrief) + " | " + (Get-IntentBrief) + " | " + (Get-RecBrief))
    $z2m = Invoke-CancelEndIfDue -NowUtc $endsZ2.AddSeconds(1)
    Obs ("RZ2 at the mark: ended=" + ($null -ne $z2m) + " | " + (Get-WallBrief) + " | " + (Get-RecBrief))
    Vy-Fresh
    [void](Invoke-Start "s-z2b"); $endsZ2b = Get-EndsOf (Invoke-BoundReset "s-z2b")
    $z2s = Rz-Row $CMD_STARTSESSION ('{"mode":"Start","playEndUtc":"' + $endIso + '","endUtc":"' + $endIso + '","closeLauncher":false}')
    $z2bm = Invoke-CancelEndIfDue -NowUtc $endsZ2b.AddMinutes(1)
    Obs ("RZ2 a Start naming NO session during s-z2b's warning: " + (Rz-RowBrief $z2s) + " | " + (Get-WallBrief) + " | " + (Get-RecBrief) + " | at the old mark ended=" + ($null -ne $z2bm))

    # ---------------------------------------------------------------- RZ4: restarts during and after the warning, then the canceled booking's commands
    foreach ($case in @(@{ N = "record file kept"; F = $false; W = $false }, @{ N = "record file lost (wall stamp only)"; F = $true; W = $false }, @{ N = "record file AND wall lost"; F = $true; W = $true })) {
        Vy-Fresh
        [void](Invoke-Start "s-z4"); $endsZ4 = Get-EndsOf (Invoke-BoundReset "s-z4")
        Rz-Restart -DropRecordFile $case.F -DropWall $case.W
        $r1 = Rz-Row $CMD_STARTSESSION (Rz-Pay "Start" "s-z4")
        $r2 = Rz-Row $CMD_UPDATESESSIONDISPLAY (Rz-Upd "s-z4" 30)
        $r3 = Rz-Row $CMD_ENDSESSION (Rz-Pay "End" "s-z4")
        Obs ("RZ4 restart during the warning, " + $case.N + ": Start " + (Rz-RowBrief $r1) + "; extension " + (Rz-RowBrief $r2) + "; platform End " + (Rz-RowBrief $r3) + " | " + (Get-RecBrief) + " | " + (Get-WallBrief))
    }
    foreach ($case in @(@{ N = "record file kept"; F = $false }, @{ N = "record file lost"; F = $true })) {
        Vy-Fresh
        [void](Invoke-Start "s-z4e"); $endsZ4e = Get-EndsOf (Invoke-BoundReset "s-z4e")
        [void](Invoke-CancelEndIfDue -NowUtc $endsZ4e.AddSeconds(1))
        Rz-Restart -DropRecordFile $case.F
        $r1 = Rz-Row $CMD_STARTSESSION (Rz-Pay "Start" "s-z4e")
        Obs ("RZ4 restart AFTER the canceled booking ended, " + $case.N + ", then its Start again: " + (Rz-RowBrief $r1) + " | " + (Get-RecBrief) + " | " + (Get-WallBrief))
    }

    # ---------------------------------------------------------------- RZ5: the pending-End retry (R2)
    # (a) restart between the ended list and the launcher close: the mark is memory only.
    Vy-Fresh
    $rzL = New-StandInLauncher
    try {
        [void](Invoke-Start "s-z5")
        Break-LauncherStep
        try { [void](Execute-Command -CommandType $CMD_ENDSESSION -PayloadJson '{"mode":"End","baySessionId":"s-z5"}' -BayLabel "Bay") } catch { }
        Repair-LauncherStep
        $before = Rz-PendBrief
        Rz-Restart
        $p1 = Rz-Pass; $p2 = Rz-Pass
        Start-Sleep -Milliseconds 400
        $again = Rz-Row $CMD_ENDSESSION '{"mode":"End","baySessionId":"s-z5"}'
        Start-Sleep -Milliseconds 400
        Obs ("RZ5a End failed after the ended mark (" + $before + "), agent restarted, two passes, the same End sent again: retried=" + ($null -ne $p1 -or $null -ne $p2) + "; resent End " + (Rz-RowBrief $again) + "; launcher still running=" + (Test-StandInAlive $rzL) + " | " + (Get-IntentBrief) + " | shell: " + (Get-ShellVerdictNow))
    } finally { Remove-StandInLauncher $rzL; Repair-LauncherStep }
    # (b) nobody recorded, the wall on the next booking's Prep, a late End of an OLDER session that this bay never listed
    foreach ($broken in @($false, $true)) {
        Vy-Fresh
        $rzL = New-StandInLauncher
        try {
            [void](Invoke-Start "s-n5b" "Prep")
            if ($broken) { Break-LauncherStep }
            $lr = $null; try { $lr = Execute-Command -CommandType $CMD_ENDSESSION -PayloadJson '{"mode":"End","baySessionId":"s-old5b"}' -BayLabel "Bay" } catch { $lr = $null }
            if ($broken) { Repair-LauncherStep }
            $pb = Rz-Pass
            Start-Sleep -Milliseconds 500
            Obs ("RZ5b late End of an older session while the wall shows the next booking's Prep and nobody is recorded (the End's launcher step " + $(if ($broken) { "FAILS once, then the retry runs" } else { "works" }) + "): first run launcher=" + (Get-PropValue (Get-PropValue $lr "launcherStopped" $null) "reason" "threw") + "; retry scope=" + (Get-PropValue $pb "scope" "none") + "; launcher still running=" + (Test-StandInAlive $rzL) + " | " + (Get-WallBrief) + " | " + (Get-IntentBrief))
        } finally { Remove-StandInLauncher $rzL; Repair-LauncherStep }
    }
    # (c) the retry and a member who starts in the SAME pass the first End failed in is not reachable (one command a pass);
    # the reachable order: End fails (pass k), pass k+1 retries BEFORE the next Start is fetched. Launcher closed, then Start.
    Vy-Fresh
    $rzL = New-StandInLauncher
    try {
        [void](Invoke-Start "s-z5c")
        Break-LauncherStep
        $f1 = Rz-Row $CMD_ENDSESSION (Rz-Pay "End" "s-z5c" ',"closeLauncher":true')
        Repair-LauncherStep
        $pc = Rz-Pass
        Start-Sleep -Milliseconds 500
        $aliveAfterRetry = Test-StandInAlive $rzL
        $s2 = Rz-Row $CMD_STARTSESSION (Rz-Pay "Start" "s-t5c")
        $pc2 = Rz-Pass
        Obs ("RZ5c End row fails after the mark (" + (Rz-RowBrief $f1) + "), next pass: retry scope=" + (Get-PropValue $pc "scope" "none") + ", launcher still running=" + $aliveAfterRetry + "; then the next booking's Start " + (Rz-RowBrief $s2) + "; a further pass did something=" + ($null -ne $pc2) + " | " + (Rz-PendBrief) + " | " + (Get-RecBrief) + " | " + (Get-IntentBrief))
    } finally { Remove-StandInLauncher $rzL; Repair-LauncherStep }

    # ---------------------------------------------------------------- RZ6: the row pre-gate
    # Offline mode and a refused row; a payload that is not JSON; a Skipped write refused for an ended session's replay.
    Vy-Fresh
    [void](Invoke-Start "s-z6"); [void](Invoke-BoundReset "s-z6")
    $Global:EffectiveConfig = @{ "Bay.AgentStatus" = $AGENTSTATUS_OFFLINE; "Bay.AgentStatusReason" = "t" }
    $o1 = Rz-Row $CMD_STARTSESSION (Rz-Pay "Start" "s-z6")
    $Global:EffectiveConfig = $null
    $o2 = Rz-Row $CMD_STARTSESSION "this is not json"
    $o3 = Rz-Row $CMD_UPDATESESSIONDISPLAY ""
    Obs ("RZ6 during s-z6's warning: its Start while the bay is Offline " + (Rz-RowBrief $o1) + "; a Start whose payload is not JSON " + (Rz-RowBrief $o2) + "; a display update with an empty payload " + (Rz-RowBrief $o3) + " | " + (Get-RecBrief) + " | " + (Get-WallBrief))
    [void](Invoke-CancelEndIfDue -NowUtc ((Get-Date).ToUniversalTime().AddMinutes(6)))

    # ---------------------------------------------------------------- RZ8: random sequences against a model with an OVER-REFUSAL oracle
    # The predecessor's fuzz (VY10) treats any refused Start as "fine", so it cannot see a refusal of a booking that was
    # never canceled and never ended. Here:
    #   V-REFUSE  a Start, Prep, display update or End naming session X was refused, and X was never the target of a
    #             cancel Reset while it was the recorded session and no End naming X was ever sent.
    #   V-FINAL   X is the recorded session, canceled and in its warning, and a Start, Prep, display update or platform End
    #             naming X was NOT refused (A0.489).
    #   V-WIRE    the handler's or the row's outcome disagrees with the pure rule asked just before.
    #   V-CLOSE   the shell's verdict is "close" while the model says someone is entitled, an End for another session
    #             reached the launcher-close branch, or a pending-End RETRY ran while someone is entitled.
    #   V-467     a canceled running booking is still the recorded session 6 minutes later.
    #   V-PEND    a pending End is still pending two passes after the failing step was repaired and nobody plays.
    # Each op is preceded by one main-loop pass (Invoke-CancelEndIfDue at the real clock) 85% of the time, as the real loop
    # does before it fetches a command. Failure injected: the End's launcher step (after the ended list) throws.
    $script:RzBreak = $false; $script:RzBreakHits = 0
    . ([scriptblock]::Create((Get-DefText $AgentDefs "Get-LauncherConfigFromPayloadOrConfig").Replace("function Get-LauncherConfigFromPayloadOrConfig", "function script:Rz-RealGetLauncherCfg")))
    function script:Get-LauncherConfigFromPayloadOrConfig($payloadObj) {
        if ($script:RzBreak -and ([string](Get-PropValue $payloadObj "mode" "")) -eq "End") { $script:RzBreakHits++; throw "rz: simulated failure after the session was listed as ended" }
        return (Rz-RealGetLauncherCfg $payloadObj)
    }
    $script:RzN = 0
    function Rz-NewSid { $script:RzN++; return ("s-g" + $script:RzN) }
    $rzOps = @("StartNew", "StartNew", "StartNew", "StartPrev", "StartCur", "PrepNext", "PrepNext", "PrepCur", "EndCur", "EndCur", "EndPrev", "EndPrev", "EndNext", "EndNone", "ResetCur", "ResetCur", "ResetCur", "ResetPrev", "ResetOther",
               "ResetUnbound", "ResetForce", "EstopOn", "EstopOff", "Restart", "RestartNoFile", "Time", "Time", "UpdCur", "UpdCur", "UpdExt", "UpdPrev", "UpdNone", "LockI", "UnlockI", "LockR", "UnlockR", "BreakEnd", "RepairEnd", "RepairEnd")
    $rzViol = New-Object System.Collections.ArrayList
    $rzThrows = New-Object System.Collections.ArrayList
    $rzCount = @{ steps = 0; refused = 0; refusedCancel = 0; refusedEnded = 0; rowRoute = 0; retries = 0; cancelEnds = 0; expectedEndThrows = 0; takeoverReplayAccepted = 0 }
    function Rz-Viol([string]$kind, [int]$seq, [int]$step, [string]$detail, $trace) { [void]$rzViol.Add(@{ Kind = $kind; Seq = $seq; Step = $step; Detail = $detail; Trace = ($trace -join " > ") }) }
    function Rz-Send([int]$type, [string]$payload, [bool]$viaRow) {
        # @{ Res (hashtable or $null); Threw; Skipped; Refusal; Scope; LauncherReason }
        $x = @{ Res = $null; Threw = ""; Skipped = $false; Refusal = ""; Scope = ""; LauncherReason = ""; Row = $viaRow; Statuses = ""; RuleSays = $false }
        $rule = Get-CommandRefusal -CommandType $type -Payload (Try-ParseJson $payload) -Running $Global:RunningSession -Finished $Global:RunningSessionFinished -Pending $Global:RunningSessionEndPending
        $x.RuleSays = ($null -ne $rule)
        if ($viaRow) {
            $o = Rz-Row $type $payload
            $x.Statuses = $o.Statuses
            if ($o.First -eq "Skipped") { $x.Skipped = $true; $x.Refusal = "row" }
            elseif ($o.Last -eq "Failed") { $x.Threw = "row Failed" }
            else { $x.Skipped = [bool]$o.HandlerSkipped; $x.Refusal = $o.Refusal; $x.Scope = $o.Scope; $x.LauncherReason = $o.LauncherReason }
            if ($o.Threw) { $x.Threw = $o.Threw }
        } else {
            try {
                $r = Execute-Command -CommandType $type -PayloadJson $payload -BayLabel "Bay"
                $x.Res = $r
                $x.Skipped = ((Get-PropValue $r "skipped" $null) -eq $true)
                $x.Refusal = [string](Get-PropValue $r "refusal" "")
                $x.Scope = [string](Get-PropValue $r "scope" "")
                $x.LauncherReason = [string](Get-PropValue (Get-PropValue $r "launcherStopped" $null) "reason" "")
            } catch { $x.Threw = $_.Exception.Message }
        }
        return $x
    }
    foreach ($rzSeed in @(20261011, 77)) {
    [void](Get-Random -SetSeed $rzSeed)
    $rzSeqs = 300; $rzLen = 16
    for ($q = 1; $q -le $rzSeqs; $q++) {
        Vy-Fresh
        $script:RzBreak = $false
        $ent = ""; $cancel = $false; $prev = ""; $next = ""; $trace = New-Object System.Collections.ArrayList
        $ended = @{}; $armed = @{}
        $il = $null; $rl = $null
        try {
            for ($i = 0; $i -lt $rzLen; $i++) {
                $op = $rzOps[(Get-Random -Maximum $rzOps.Count)]
                $viaRow = ((Get-Random -Maximum 100) -lt 40)
                $did = $op; $endFor = $null; $sent = $null; $sentSid = ""; $sentType = 0; $sentIsEnd = $false
                # one main-loop pass first, as the real loop does
                if ((Get-Random -Maximum 100) -lt 85) {
                    $recP = Get-RecSid
                    $pr = $null; try { $pr = Rz-Pass } catch { [void]$rzThrows.Add(("seq {0} step {1} pass: {2}" -f $q, $i, $_.Exception.Message)) }
                    if ($null -ne $pr -and [string](Get-PropValue $pr "scope" "") -eq "retry") {
                        $rzCount.retries++
                        if ($ent) { Rz-Viol "V-CLOSE" $q $i ("a pending-End retry ran while " + $ent + " is entitled (bay record before the pass: " + $recP + ")") $trace }
                    }
                }
                $recBefore = Get-RecSid; $cancelBefore = Get-RecCancel
                try {
                    switch ($op) {
                        "StartNew" { $sid = $(if ($next) { $next } else { Rz-NewSid }); $next = ""; $sentSid = $sid; $sentType = $CMD_STARTSESSION; $sent = Rz-Send $CMD_STARTSESSION (Rz-Pay "Start" $sid) $viaRow; $did = "Start(" + $sid + ")"
                                     if (-not $sent.Skipped -and -not $sent.Threw) { if ($ent -and $ent -ne $sid) { $prev = $ent }; $ent = $sid; $cancel = $false } else { $did += "=refused" } }
                        "StartPrev" { if ($prev) { $sentSid = $prev; $sentType = $CMD_STARTSESSION; $sent = Rz-Send $CMD_STARTSESSION (Rz-Pay "Start" $prev) $viaRow; $did = "Start(prev " + $prev + ")"
                                     if (-not $sent.Skipped -and -not $sent.Threw) { if ($armed.ContainsKey($prev) -and -not $ended.ContainsKey($prev)) { $rzCount.takeoverReplayAccepted++ }; $t = $ent; $ent = $prev; $prev = $t; $cancel = $false } else { $did += "=refused" } } else { $did = "-" } }
                        "StartCur" { if ($ent) { $sentSid = $ent; $sentType = $CMD_STARTSESSION; $sent = Rz-Send $CMD_STARTSESSION (Rz-Pay "Start" $ent) $viaRow; $did = "Start(again " + $ent + ")" } else { $did = "-" } }
                        "PrepNext" { if (-not $next) { $next = Rz-NewSid }; $sentSid = $next; $sentType = $CMD_STARTSESSION; $sent = Rz-Send $CMD_STARTSESSION (Rz-Pay "Prep" $next) $viaRow; $did = "Prep(" + $next + ")" }
                        "PrepCur" { if ($ent) { $sentSid = $ent; $sentType = $CMD_STARTSESSION; $sent = Rz-Send $CMD_STARTSESSION (Rz-Pay "Prep" $ent) $viaRow; $did = "Prep(again " + $ent + ")" } else { $did = "-" } }
                        "EndCur" { if ($ent) { $sentSid = $ent; $sentType = $CMD_ENDSESSION; $sentIsEnd = $true; $sent = Rz-Send $CMD_ENDSESSION (Rz-Pay "End" $ent) $viaRow; $did = "End(" + $ent + ")"
                                     if ($sent.Skipped -and $cancel) { $did += "=held" } else { $prev = $ent; $ent = ""; $cancel = $false } } else { $did = "-" } }
                        "EndPrev" { if ($prev) { $sentSid = $prev; $sentType = $CMD_ENDSESSION; $sentIsEnd = $true; $sent = Rz-Send $CMD_ENDSESSION (Rz-Pay "End" $prev) $viaRow; $endFor = $prev; $did = "End(prev " + $prev + ")" } else { $did = "-" } }
                        "EndNext" { if ($next) { $sentSid = $next; $sentType = $CMD_ENDSESSION; $sentIsEnd = $true; $sent = Rz-Send $CMD_ENDSESSION (Rz-Pay "End" $next) $viaRow; $endFor = $next; $did = "End(next " + $next + ")" } else { $did = "-" } }
                        "EndNone" { $sentType = $CMD_ENDSESSION; $sent = Rz-Send $CMD_ENDSESSION '{"mode":"End","closeLauncher":false}' $viaRow; $endFor = "" }
                        "ResetCur" { if ($ent) { if ((Get-RecSid) -eq $ent) { $armed[$ent] = $true; $cancel = $true }; [void](Invoke-BoundReset $ent); $did = "CancelReset(" + $ent + ")" } else { $did = "-" } }
                        "ResetPrev" { if ($prev) { if ((Get-RecSid) -eq $prev) { $armed[$prev] = $true }; [void](Invoke-BoundReset $prev); $did = "Reset(prev " + $prev + ")" } else { $did = "-" } }
                        "ResetOther" { [void](Invoke-BoundReset "s-zz") }
                        "ResetUnbound" { [void](Invoke-BoundReset "") }
                        "ResetForce" { [void](Execute-Command -CommandType $CMD_RESET -PayloadJson '{"mode":"Full","force":true}' -BayLabel "Bay") }
                        "EstopOn" { [void](Execute-Command -CommandType $CMD_EMERGENCY_STOP -PayloadJson '{"action":"engage","reason":"t"}' -BayLabel "Bay") }
                        "EstopOff" { [void](Execute-Command -CommandType $CMD_EMERGENCY_STOP -PayloadJson '{"action":"clear"}' -BayLabel "Bay") }
                        "Restart" { Rz-Restart }
                        "RestartNoFile" { if ($null -eq $rl) { Rz-Restart -DropRecordFile $true } else { Rz-Restart } }
                        "Time" { $recT = Get-RecSid; $canT = Get-RecCancel
                                 $res = Invoke-CancelEndIfDue -NowUtc ((Get-Date).ToUniversalTime().AddMinutes(6))
                                 if ($null -ne $res -and [string](Get-PropValue $res "scope" "") -eq "retry") { $rzCount.retries++; if ($ent) { Rz-Viol "V-CLOSE" $q $i ("a pending-End retry ran while " + $ent + " is entitled") $trace } }
                                 if ($null -ne $canT -and $recT -ne "<none>") {
                                     $rzCount.cancelEnds++
                                     if ((Get-RecSid) -eq $recT) { Rz-Viol "V-467" $q $i ("canceled " + $recT + " is still the recorded session 6 minutes later: " + (Get-RecBrief) + " " + (Get-IntentBrief)) $trace }
                                     else { $ended[$recT] = $true }
                                     if ($ent -eq $recT) { $prev = $ent; $ent = ""; $cancel = $false }
                                     $did = "Time(+6m)"
                                 } }
                        "UpdCur" { if ($ent) { $sentSid = $ent; $sentType = $CMD_UPDATESESSIONDISPLAY; $sent = Rz-Send $CMD_UPDATESESSIONDISPLAY (Rz-Upd $ent) $viaRow } else { $did = "-" } }
                        "UpdExt" { if ($ent) { $sentSid = $ent; $sentType = $CMD_UPDATESESSIONDISPLAY; $sent = Rz-Send $CMD_UPDATESESSIONDISPLAY (Rz-Upd $ent 30) $viaRow } else { $did = "-" } }
                        "UpdPrev" { if ($prev) { $sentSid = $prev; $sentType = $CMD_UPDATESESSIONDISPLAY; $sent = Rz-Send $CMD_UPDATESESSIONDISPLAY (Rz-Upd $prev) $viaRow } else { $did = "-" } }
                        "UpdNone" { $sentType = $CMD_UPDATESESSIONDISPLAY; $sent = Rz-Send $CMD_UPDATESESSIONDISPLAY (Rz-Upd "<none>") $viaRow }
                        "LockI" { if ($null -eq $il -and (Test-Path -LiteralPath $KioskIntentPath)) { $il = Lock-Intent } else { $did = "-" } }
                        "UnlockI" { if ($null -ne $il) { $il.Dispose(); $il = $null } else { $did = "-" } }
                        "LockR" { if ($null -eq $rl -and (Test-Path -LiteralPath $RunningSessionPath)) { $rl = New-Object IO.FileStream($RunningSessionPath, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read) } else { $did = "-" } }
                        "UnlockR" { if ($null -ne $rl) { $rl.Dispose(); $rl = $null } else { $did = "-" } }
                        "BreakEnd" { $script:RzBreak = $true }
                        "RepairEnd" { if ($script:RzBreak) { $script:RzBreak = $false } else { $did = "-" } }
                    }
                } catch { [void]$rzThrows.Add(("seq {0} step {1} {2}: {3}" -f $q, $i, $op, $_.Exception.Message)) }
                if ($did -eq "-") { continue }
                [void]$trace.Add($did + $(if ($null -ne $sent -and $sent.Row) { "[row " + $sent.Statuses + "]" } else { "" })); $rzCount.steps++
                if ($null -ne $sent) {
                    if ($sent.Row) { $rzCount.rowRoute++ }
                    if (-not $sent.Threw -and ($sent.RuleSays -ne $sent.Skipped)) { Rz-Viol "V-WIRE" $q $i ($did + ": the pure rule said refuse=" + $sent.RuleSays + " but the " + $(if ($sent.Row) { "row" } else { "handler" }) + " outcome was skipped=" + $sent.Skipped + " (" + $sent.Statuses + ")") $trace }
                    if ($sent.Threw) {
                        if ($script:RzBreak -and $sentType -eq $CMD_ENDSESSION) { $rzCount.expectedEndThrows++ } else { [void]$rzThrows.Add(("seq {0} step {1} {2}: {3}" -f $q, $i, $did, $sent.Threw)) }
                    }
                    if ($sentSid) {
                        if ($sent.Skipped) {
                            $rzCount.refused++
                            if ($sent.Refusal -eq "cancel-warning") { $rzCount.refusedCancel++ } elseif ($sent.Refusal -eq "ended-replay") { $rzCount.refusedEnded++ }
                            if (-not $ended.ContainsKey($sentSid) -and -not $armed.ContainsKey($sentSid)) { Rz-Viol "V-REFUSE" $q $i ($did + " was refused (" + $sent.Refusal + "), but " + $sentSid + " was never canceled while recorded and no End naming it was ever sent | " + (Get-RecBrief)) $trace }
                        } elseif (-not $sent.Threw) {
                            if ($armed.ContainsKey($sentSid) -and $recBefore -eq $sentSid -and $null -ne $cancelBefore) { Rz-Viol "V-FINAL" $q $i ($did + " was NOT refused while " + $sentSid + " is the recorded session in its cancel warning | " + (Get-WallBrief) + " | " + (Get-RecBrief)) $trace }
                        }
                        # an End that was not held by a cancel warning lists its session as ended (also a late End, also one that threw after the list)
                        if ($sentIsEnd -and -not ($sent.Skipped -and $sent.Refusal -ne "ended-replay" -and $armed.ContainsKey($sentSid) -and $recBefore -eq $sentSid)) { $ended[$sentSid] = $true }
                    }
                }
                Release-IntentLock
                if ($null -ne $endFor -and $ent -and $endFor -ne $ent -and $null -ne $sent -and -not $sent.Skipped -and -not $sent.Threw) {
                    if ($sent.LauncherReason -notin @("late_old_session_skip", "session_already_ended", "cancel_warning_holds")) { Rz-Viol "V-CLOSE" $q $i ("End for '" + $endFor + "' reached the launcher-close branch (" + $sent.LauncherReason + ", scope " + $sent.Scope + ") while " + $ent + " is entitled") $trace }
                }
                $verdict = Get-ShellVerdictNow
                if ($ent -and $verdict -eq "close") { Rz-Viol "V-CLOSE" $q $i ("shell verdict close while " + $ent + " is entitled (cancel pending=" + $cancel + "): " + (Get-WallBrief) + " | " + (Get-IntentBrief) + " | " + (Get-RecBrief)) $trace }
            }
            # the failing step is repaired; two passes later nothing may still be pending while nobody plays
            $script:RzBreak = $false
            if ($null -ne $il) { $il.Dispose(); $il = $null }; if ($null -ne $rl) { $rl.Dispose(); $rl = $null }
            Release-IntentLock
            $hadPending = @($Global:RunningSessionEndPending).Count
            $t1 = $null; $t2 = $null
            try { $t1 = Rz-Pass; $t2 = Rz-Pass } catch { }
            if ($null -ne $t1 -and [string](Get-PropValue $t1 "scope" "") -eq "retry") { $rzCount.retries++; if ($ent) { Rz-Viol "V-CLOSE" $q 99 ("a pending-End retry ran at the tail while " + $ent + " is entitled") $trace } }
            if (@($Global:RunningSessionEndPending).Count -gt 0) { Rz-Viol "V-PEND" $q 99 ("still pending two passes after the repair (" + (Rz-PendBrief) + ", had " + $hadPending + ") | " + (Get-RecBrief)) $trace }
        } finally {
            if ($null -ne $il) { $il.Dispose() }; if ($null -ne $rl) { $rl.Dispose() }
            Release-IntentLock
            $script:RzBreak = $false
        }
    }
    }
    Obs ("RZ8 fuzz: 2 seeds x 300 sequences, " + $rzCount.steps + " steps (" + $rzCount.rowRoute + " through Process-Command rows), refusals=" + $rzCount.refused + " (cancel-warning " + $rzCount.refusedCancel + ", ended-replay " + $rzCount.refusedEnded + ", row Skipped " + ($rzCount.refused - $rzCount.refusedCancel - $rzCount.refusedEnded) + "), cancel Ends at the mark=" + $rzCount.cancelEnds + ", pending-End retries=" + $rzCount.retries + ", End throws injected=" + $rzCount.expectedEndThrows + " (failing step hit " + $script:RzBreakHits + " times), canceled booking's Start accepted after another booking took the bay=" + $rzCount.takeoverReplayAccepted)
    Obs ("RZ8 violations=" + $rzViol.Count + " (V-REFUSE=" + @($rzViol | Where-Object { $_.Kind -eq "V-REFUSE" }).Count + ", V-FINAL=" + @($rzViol | Where-Object { $_.Kind -eq "V-FINAL" }).Count + ", V-CLOSE=" + @($rzViol | Where-Object { $_.Kind -eq "V-CLOSE" }).Count + ", V-467=" + @($rzViol | Where-Object { $_.Kind -eq "V-467" }).Count + ", V-PEND=" + @($rzViol | Where-Object { $_.Kind -eq "V-PEND" }).Count + ", V-WIRE=" + @($rzViol | Where-Object { $_.Kind -eq "V-WIRE" }).Count + "), unexpected throws=" + $rzThrows.Count)
    foreach ($k in @("V-REFUSE", "V-FINAL", "V-CLOSE", "V-467", "V-PEND", "V-WIRE")) { foreach ($v in @($rzViol | Where-Object { $_.Kind -eq $k } | Select-Object -First 6)) { Obs ("RZ8 " + $v.Kind + " seq " + $v.Seq + " step " + $v.Step + ": " + $v.Detail); Obs ("RZ8      trace: " + $v.Trace) } }
    foreach ($t in @($rzThrows | Select-Object -First 10)) { Obs ("RZ8 throw " + $t) }
    Repair-LauncherStep
    Vy-Fresh
    $Global:EmergencyStopEngaged = $false
    $Global:EffectiveConfig = $null
