# Release-prep check (2026-10-10): mutants. T* are the builder's (re-run by the verifier with unique anchors), RM3/RM4 are
# the re-verdict's F1 survivors, N* are the verifier's own for the persisted mark. Hyphens only in comments.
$pre  = 'if ($null -ne $preRef) {'
$hold = 'if ($null -ne $ce -and (Test-BaySessionIdMatch $sid $runSid)) {'
$nl = "`r`n"
@(
    @{ Id = "T01";  Why = "F3 (builder): the pending list is never written to the record file"; Steps = @(@{ Find = 'endPending   = @(@($Global:RunningSessionEndPending) | Where-Object'; Replace = 'endPending   = @(@() | Where-Object' }) }
    @{ Id = "T02";  Why = "F3 (builder): a restart does not read the pending list back"; Steps = @(@{ Find = '$Global:RunningSessionEndPending = @($pend)'; Replace = '$Global:RunningSessionEndPending = @()' }) }
    @{ Id = "T03";  Why = "F3 (builder): a pending session is not treated as ended at restart"; Steps = @(@{ Find = '$fin = @(Add-FinishedSessionToList -Finished $fin -SessionId $pid2 -NowUtc $NowUtc -Max $RunningSessionFinishedMax)'; Replace = '$null = $pid2' }) }
    @{ Id = "T05b"; Why = "F3 (builder T05): the mark is made but not written to the file"; Steps = @(@{ Find = ('$Global:RunningSessionEndPending = @($keep)' + $nl + '        Save-EndPendingState'); Replace = ('$Global:RunningSessionEndPending = @($keep)' + $nl + '        $null = 0') }) }
    @{ Id = "T07";  Why = "F4 (builder): a retry ignores the stored decision"; Steps = @(@{ Find = '$endOwns = ([string](Get-KioskProp (Get-EndPendingEntry $endSid $Global:RunningSessionEndPending) "scope" "") -ne "leaves")'; Replace = '$endOwns = $true' }) }
    @{ Id = "T08b"; Why = "F4 (builder): the stored decision is always owns"; Steps = @(@{ Find = 'tries = 0; scope = $Scope }'; Replace = 'tries = 0; scope = "owns" }' }) }
    @{ Id = "RM3";  Why = "F1 (re-verdict, was ERROR): a repeated START or Prep of the running session is refused, canceled or not"; Steps = @(@{ Find = $hold; Replace = 'if (($null -ne $ce -or $CommandType -eq $CMD_STARTSESSION) -and (Test-BaySessionIdMatch $sid $runSid)) {' }) }
    @{ Id = "RM4";  Why = "F1 (re-verdict, SURVIVED 611/0): the ROW pre-gate skips every display update row (the handler is right)"; Steps = @(@{ Find = $pre; Replace = ('if ($null -eq $preRef -and $type -eq $CMD_UPDATESESSIONDISPLAY) { $preRef = @{ Kind = "m"; Why = "mutant" } }' + $nl + '        ' + $pre) }) }
    @{ Id = "N1";   Why = "the mark is dropped in memory but the drop is never written (a stale mark stays in the file)"; Steps = @(@{ Find = ('"id" ""))) }) }' + $nl + '        Save-EndPendingState'); Replace = ('"id" ""))) }) }' + $nl + '        $null = 0') }) }
    @{ Id = "N2";   Why = "F4 across a restart: the stored decision is not read back (a restart turns leaves into owns)"; Steps = @(@{ Find = '[int]$pt } else { 0 }); scope = [string](Get-KioskProp $pe "scope" "") }'; Replace = '[int]$pt } else { 0 }); scope = "" }' }) }
    @{ Id = "N3";   Why = "F4 across a restart: the stored decision is not written to the file"; Steps = @(@{ Find = 'tries = [int](Get-KioskProp $_ "tries" 0); scope = [string](Get-KioskProp $_ "scope" "") } })'; Replace = 'tries = [int](Get-KioskProp $_ "tries" 0); scope = "" } })' }) }
    @{ Id = "RM3b"; Why = "F1 control: the HANDLER refuses a repeated Start of the running session, narrowed to the F1 test's session so the suite does not crash earlier"; Steps = @(@{ Find = $hold; Replace = 'if (($null -ne $ce -or ($CommandType -eq $CMD_STARTSESSION -and $sid -eq "s-f1")) -and (Test-BaySessionIdMatch $sid $runSid)) {' }) }
    @{ Id = "N4";   Why = "the retry payload drops closeLauncher (a retry closes a launcher the End was told to leave)"; Steps = @(@{ Find = 'foreach ($k in @("closeLauncher", "launcher", "reason")) {'; Replace = 'foreach ($k in @("launcher", "reason")) {' }) }
)
