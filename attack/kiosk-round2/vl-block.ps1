    # ====================================================================================================================
    # VERIFIER LIVE PROBES (kiosk round 2 attack, 2026-10-10). Spliced into a COPY of BayAgent.KioskShell.Live.Tests.ps1
    # before S5e. The REAL shell process (the suite's installed copy) judges walls stamped as round 2's agent stamps them;
    # the launchers are the suite's own stand-ins, started here and stopped only by the ids recorded here.
    # ====================================================================================================================
    Section "VL verifier live probes: the round 2 READY/PREP close rule on the real shell process"
    function Obs([string]$m) { Write-Host ("  OBS   " + $m) }
    function Set-StampedWall([string]$status, [string]$sid, [bool]$running, [string]$runSid, [int]$stampAgeSec = 0) {
        $at = (Get-Date).ToUniversalTime().AddSeconds(-$stampAgeSec).ToString("yyyy-MM-ddTHH:mm:ssZ")
        $o = [ordered]@{ status = $status; baySessionId = $sid; sessionEndUtc = (Get-Date).ToUniversalTime().AddMinutes(45).ToString("yyyy-MM-ddTHH:mm:ssZ")
            agentRunning = [ordered]@{ schema = 1; running = $running; baySessionId = $runSid; endUtc = $null; since = $null; cancelEndUtc = $null; status = $status; forSessionId = $sid; writtenUtc = $at } }
        Set-Text $SessionJsonPath (ConvertTo-Json -InputObject $o -Depth 5)
    }
    function Get-Held { $h = Read-Hb; if ($null -eq $h) { return "" }; try { return [string]$h.launcher.closeHeld } catch { return "" } }
    $vlPids = New-Object System.Collections.ArrayList
    try {
        # a closed intent left by session s-A ten minutes ago (the stale-closed precondition of RF-K2 and F1-R1)
        Set-Text $IntentPath ("{`"schema`":1,`"launcher`":`"closed`",`"untilUtc`":null,`"baySessionId`":`"s-A`",`"writtenUtc`":`"" + (Get-Date).ToUniversalTime().AddMinutes(-10).ToString("yyyy-MM-ddTHH:mm:ssZ") + "`"}")
        # VL1: s-T plays (its intent write failed); the next booking's Prep rewrote the wall PREP/s-N, stamped "s-T plays".
        Set-StampedWall "PREP" "s-N" $true "s-T"
        $v1 = Start-Process -FilePath $LaunchExe -ArgumentList "noclose" -PassThru; [void]$vlPids.Add($v1.Id)
        Start-Sleep -Seconds 35
        $v1.Refresh()
        Obs ("VL1 stale closed, PREP stamped 's-T plays': launcher still running after 35 s=" + (-not $v1.HasExited) + " | closeHeld='" + (Get-Held) + "'")
        Assert-True (-not $v1.HasExited) "VL1 live: PREP stamped someone-plays under a stale closed: the paying member's launcher is NOT ended"
        # VL2: the same wall, now stamped "nobody plays" (s-T ended, then the Prep): the launcher is ended.
        Set-StampedWall "PREP" "s-N" $false ""
        $c2 = Wait-Until { $v1.Refresh(); $v1.HasExited } 45
        Obs ("VL2 PREP stamped 'nobody plays': launcher ended within 45 s=" + $c2)
        Assert-True $c2 "VL2 live: PREP stamped nobody-plays after the closed intent: a relaunched launcher is ended"
        # VL3: READY (a canceled booking's Reset on the idle bay), stamped nobody.
        Set-StampedWall "READY" "" $false ""
        $v3 = Start-Process -FilePath $LaunchExe -ArgumentList "noclose" -PassThru; [void]$vlPids.Add($v3.Id)
        $c3 = Wait-Until { $v3.Refresh(); $v3.HasExited } 45
        Obs ("VL3 READY stamped 'nobody plays': launcher ended within 45 s=" + $c3)
        Assert-True $c3 "VL3 live: READY stamped nobody-plays: a relaunched launcher is ended"
        # VL4: STOP (an emergency stop on the idle bay), stamped nobody: never closed (A0.457; unruled choice 3).
        Set-StampedWall "STOP" "s-N" $false ""
        $v4 = Start-Process -FilePath $LaunchExe -ArgumentList "noclose" -PassThru; [void]$vlPids.Add($v4.Id)
        Start-Sleep -Seconds 32
        $v4.Refresh()
        Obs ("VL4 STOP stamped 'nobody plays': launcher still running after 32 s=" + (-not $v4.HasExited) + " | closeHeld='" + (Get-Held) + "'")
        # VL5: PREP stamped nobody, but the stamp is OLDER than the closed intent: held.
        Set-StampedWall "PREP" "s-N" $false "" 1200
        Start-Sleep -Seconds 30
        $v4.Refresh()
        Obs ("VL5 PREP stamped 'nobody plays' 20 minutes ago (older than the closed intent): launcher still running after 30 s=" + (-not $v4.HasExited) + " | closeHeld='" + (Get-Held) + "'")
        Assert-True (-not $v4.HasExited) "VL4/VL5 live: STOP, and a stamp older than the closed intent, never end the launcher"
        # VL6: a stamp merged forward (status echo PREP on a READY wall): held.
        $o6 = [ordered]@{ status = "READY"; baySessionId = ""; agentRunning = [ordered]@{ schema = 1; running = $false; baySessionId = ""; status = "PREP"; forSessionId = ""; writtenUtc = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ") } }
        Set-Text $SessionJsonPath (ConvertTo-Json -InputObject $o6 -Depth 5)
        Start-Sleep -Seconds 30
        $v4.Refresh()
        Obs ("VL6 READY wall carrying a PREP stamp (merged forward): launcher still running after 30 s=" + (-not $v4.HasExited) + " | closeHeld='" + (Get-Held) + "'")
        Assert-True (-not $v4.HasExited) "VL6 live: a stamp that does not echo the wall's status never ends the launcher"
    } finally {
        foreach ($id in @($vlPids)) { try { $pp = Get-Process -Id $id -ErrorAction SilentlyContinue; if ($pp) { Stop-Process -Id $id -Force -ErrorAction SilentlyContinue } } catch { } }
    }

