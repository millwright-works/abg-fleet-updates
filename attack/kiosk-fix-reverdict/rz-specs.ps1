# Kiosk round 2 FIX re-verdict (2026-10-10): the verifier's own mutants. Each models a wrong BEHAVIOR that does not crash
# the suite: an over-refusal narrowed to one command type, or to the row pre-gate only. Hyphens only in comments.
$hold = 'if ($null -ne $ce -and (Test-BaySessionIdMatch $sid $runSid)) {'
$fin  = 'if (Test-SessionFinished $sid $Finished) {'
$pre  = 'if ($null -ne $preRef) {'
@(
    # the builder's four ERROR mutants, re-run to read where the suite stops
    @{ Id = "H07";  Why = "builder ERROR: the hold applies to any running session, canceled or not"; Steps = @(@{ File = "agent"; Find = $hold; Replace = 'if ((Test-BaySessionIdMatch $sid $runSid)) {' }) }
    @{ Id = "P06";  Why = "builder ERROR: every Start of any session is refused as ended"; Steps = @(@{ File = "agent"; Find = $fin; Replace = 'if ($true) {' }) }
    @{ Id = "P06b"; Why = "builder ERROR: once any session has ended, every command is refused as a replay"; Steps = @(@{ File = "agent"; Find = $fin; Replace = 'if (@($Finished).Count -gt 0) {' }) }
    @{ Id = "P07";  Why = "builder ERROR: the rule refuses every Start, display update and End outright"; Steps = @(@{ File = "agent"; Find = "Why = `"session '`$sid' already ended on this bay: a replayed command is not run`" }`r`n    }`r`n    return `$null"; Replace = "Why = `"session '`$sid' already ended on this bay: a replayed command is not run`" }`r`n    }`r`n    return @{ Kind = `"ended-replay`"; Why = `"mutant`" }" }) }
    # the verifier's narrowed over-refusals
    @{ Id = "RM1"; Why = "a paying member's DISPLAY UPDATE (Warn5, extension) is refused: the hold covers the running session canceled or not, display updates only"; Steps = @(@{ File = "agent"; Find = $hold; Replace = 'if (($null -ne $ce -or $CommandType -eq $CMD_UPDATESESSIONDISPLAY) -and (Test-BaySessionIdMatch $sid $runSid)) {' }) }
    @{ Id = "RM2"; Why = "a paying member's own END is refused: the hold covers the running session canceled or not, Ends only"; Steps = @(@{ File = "agent"; Find = $hold; Replace = 'if (($null -ne $ce -or $CommandType -eq $CMD_ENDSESSION) -and (Test-BaySessionIdMatch $sid $runSid)) {' }) }
    @{ Id = "RM3"; Why = "a repeated START or Prep of the running session is refused, canceled or not"; Steps = @(@{ File = "agent"; Find = $hold; Replace = 'if (($null -ne $ce -or $CommandType -eq $CMD_STARTSESSION) -and (Test-BaySessionIdMatch $sid $runSid)) {' }) }
    @{ Id = "RM4"; Why = "the ROW pre-gate skips every display update row (the handler is right)"; Steps = @(@{ File = "agent"; Find = $pre; Replace = ('if ($null -eq $preRef -and $type -eq $CMD_UPDATESESSIONDISPLAY) { $preRef = @{ Kind = "m"; Why = "mutant" } }' + "`r`n        " + $pre) }) }
    @{ Id = "RM5"; Why = "the ROW pre-gate skips every End row (the handler is right)"; Steps = @(@{ File = "agent"; Find = $pre; Replace = ('if ($null -eq $preRef -and $type -eq $CMD_ENDSESSION) { $preRef = @{ Kind = "m"; Why = "mutant" } }' + "`r`n        " + $pre) }) }
    @{ Id = "RM6"; Why = "the ROW pre-gate skips every Start and Prep row (the handler is right)"; Steps = @(@{ File = "agent"; Find = $pre; Replace = ('if ($null -eq $preRef -and $type -eq $CMD_STARTSESSION) { $preRef = @{ Kind = "m"; Why = "mutant" } }' + "`r`n        " + $pre) }) }
    @{ Id = "RM7"; Why = "once ANY session has ended here, every later display update is refused as a replay"; Steps = @(@{ File = "agent"; Find = $fin; Replace = 'if ((Test-SessionFinished $sid $Finished) -or ($CommandType -eq $CMD_UPDATESESSIONDISPLAY -and @($Finished).Count -gt 0)) {' }) }
    @{ Id = "RM8"; Why = "once ANY session has ended here, every later End is refused as a replay"; Steps = @(@{ File = "agent"; Find = $fin; Replace = 'if ((Test-SessionFinished $sid $Finished) -or ($CommandType -eq $CMD_ENDSESSION -and @($Finished).Count -gt 0)) {' }) }
    @{ Id = "RM9"; Why = "another booking's Start during the warning INHERITS the cancel mark (that member's commands are then refused and the game ended)"; Steps = @(@{ File = "agent"; Find = 'if ($null -ne $curCancel -and (Test-BaySessionIdMatch $sid $curSid)) { $rec["cancelEndUtc"] = $curCancel }'; Replace = 'if ($null -ne $curCancel) { $rec["cancelEndUtc"] = $curCancel }' }) }
)
