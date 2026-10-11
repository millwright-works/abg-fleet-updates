    # ====================================================================================================================
    # RZ9 (kiosk round 2 FIX re-verdict, 2026-10-10): the one V-CLOSE the RZ8 fuzz found, replayed by hand, on the head AND
    # on the attacked base f191694, to say whether the fix round made it. Spliced right before the K22 section, so it uses
    # only K21 helpers and runs against either agent. Hyphens only in comments.
    # ====================================================================================================================
    Section "RZ9 a Start under an emergency stop, a restart with the record file lost, then the previous booking's End"
    function Rz9Obs([string]$m) { Write-Host ("  OBS   " + $m) }
    function Rz9-State {
        $s = Get-Sess; $st = Get-PropValue $s "agentRunning" $null
        $w = Get-KioskLauncherWanted -IntentRead (Read-KioskJsonFile -Path $KioskIntentPath) -NowUtc ((Get-Date).ToUniversalTime())
        return ("record=" + (Get-RecSid) + " | wall " + (Get-PropValue $s "status" "") + "/" + (Get-PropValue $s "baySessionId" "") + " stamp(running=" + (Get-PropValue $st "running" "") + " sid=" + (Get-PropValue $st "baySessionId" "") + ") | intent wanted=" + $w.Wanted + " closed=" + $w.Closed + " sid=" + $w.SessionId + " | shell: " + (Get-ShellVerdictNow))
    }
    foreach ($variant in @("minimal", "as the fuzz found it")) {
        Clear-Bay; Remove-Item -LiteralPath $sessPath -Force -ErrorAction SilentlyContinue
        Remove-Item -LiteralPath $KioskIntentPath -Force -ErrorAction SilentlyContinue
        $Global:KioskIntentExpectedText = $null; $Global:KioskIntentPending = $false
        Initialize-KioskIntent -NowUtc ((Get-Date).ToUniversalTime())
        $il9 = $null
        try {
            [void](Invoke-Start "s-9a")
            [void](Execute-Command -CommandType $CMD_EMERGENCY_STOP -PayloadJson '{"action":"engage","reason":"t"}' -BayLabel "Bay")
            if ($variant -ne "minimal") {
                [void](Execute-Command -CommandType $CMD_UPDATESESSIONDISPLAY -PayloadJson ('{"mode":"Warn5","baySessionId":"s-9a","playEndUtc":"' + $endIso + '"}') -BayLabel "Bay")
                $il9 = Lock-Intent
                [void](Invoke-BoundReset "s-zz")
            }
            $sb = Invoke-Start "s-9b"
            Rz9Obs ("RZ9 [" + $variant + "] s-9a plays, emergency stop engaged, then the next booking s-9b's Start: note=" + (Get-PropValue $sb "note" "") + " | " + (Rz9-State))
            Remove-Item -LiteralPath $RunningSessionPath -Force -ErrorAction SilentlyContinue
            $Global:RunningSession = $null; $Global:RunningSessionFinished = @(); $Global:RunningSessionPending = $false
            $Global:KioskIntentExpectedText = $null; $Global:KioskIntentPending = $false
            Initialize-RunningSession -NowUtc ((Get-Date).ToUniversalTime()); Initialize-KioskIntent -NowUtc ((Get-Date).ToUniversalTime())
            Rz9Obs ("RZ9 [" + $variant + "] agent restart with the record file lost: " + (Rz9-State))
            [void](Execute-Command -CommandType $CMD_EMERGENCY_STOP -PayloadJson '{"action":"clear"}' -BayLabel "Bay")
            $e9 = Invoke-End "s-9a"
            Rz9Obs ("RZ9 [" + $variant + "] stop cleared, then s-9a's (the previous booking's) End: scope=" + (Get-PropValue $e9 "scope" "") + " launcher=" + (Get-PropValue (Get-PropValue $e9 "launcherStopped" $null) "reason" "") + " | " + (Rz9-State))
            $e9b = Invoke-End "s-9b"
            Rz9Obs ("RZ9 [" + $variant + "] then s-9b's own End: scope=" + (Get-PropValue $e9b "scope" "") + " launcher=" + (Get-PropValue (Get-PropValue $e9b "launcherStopped" $null) "reason" "") + " | " + (Rz9-State))
        } catch { Rz9Obs ("RZ9 [" + $variant + "] threw: " + $_.Exception.Message) }
        finally { if ($null -ne $il9) { $il9.Dispose() }; Release-IntentLock }
    }
    Clear-Bay
    $Global:EmergencyStopEngaged = $false
