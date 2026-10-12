<#
Recheck-Probes.ps1 - the re-check verifier's own probes of BayAgent.ps1 at bc2e6c6 (BayAgent 1.6.1 release prep).

It reuses the builder's bay model and recorder (the harness lines of tests\BayAgent.Day0Enroll.Tests.ps1, taken at run
time, unchanged). Every scenario runs the real script text in a child powershell.exe 5.1. Nothing here is an
assertion suite: it prints what happened and the verifier reads it. Certificates made carry this run's own subject
and are removed at the end. Hyphens only in comments.

  R1  the sitting in sheet 05's shape: agent-config.json as step 9 writes it (clientId = the bay's own app, the
      template's secret-file path named, no file, logLevel INFO), then steps 11, 13 (early), add-cert, 13, 14.
      The whole console text is printed, so the sheet's Expect lines can be read against it.
  R2  on that bay, after it has run: state\credential.json is emptied. What the console line and the agent do,
      and whether the bay comes back without an erase.
  R3  -EnrollForce from another account, with and without state\agent-alive.json.
  R4  a secret that arrives after enrollment, in each of the three places, then the console line with and without
      -EnrollForce (the guard added in 3541f9e, read at the second run).
#>
[CmdletBinding()]
param(
    [string]$Only = "",
    [int]$RunTimeoutSeconds = 90
)
$ErrorActionPreference = "Stop"
$RcRepo      = "C:\aoc-wt\ba161-recheck"
$AgentScript = Join-Path $RcRepo "src\BayAgent\BayAgent.ps1"

$rcSuiteLines = [IO.File]::ReadAllLines((Join-Path $RcRepo "tests\BayAgent.Day0Enroll.Tests.ps1"))
$rcStart = -1; $rcEnd = -1
for ($rcI = 0; $rcI -lt $rcSuiteLines.Count; $rcI++) {
    if ($rcStart -lt 0 -and $rcSuiteLines[$rcI] -eq 'Set-StrictMode -Version Latest') { $rcStart = $rcI }
    if ($rcSuiteLines[$rcI] -eq '$placeholderCertsAtStart = @(Get-D0PlaceholderCerts)') { $rcEnd = $rcI }
}
if ($rcStart -lt 0 -or $rcEnd -lt $rcStart) { throw "could not find the harness lines in the builder's suite" }
$rcChunk = ($rcSuiteLines[$rcStart..$rcEnd] -join "`r`n")
$rcChunk = $rcChunk.Replace('$PSScriptRoot', "'C:\aoc-wt\ba161-recheck\tests'")
$rcHarnessFile = Join-Path $env:TEMP ("rc-day0-harness-" + [guid]::NewGuid().ToString("N").Substring(0, 8) + ".ps1")
[IO.File]::WriteAllText($rcHarnessFile, $rcChunk, (New-Object Text.UTF8Encoding($true)))
. $rcHarnessFile
Remove-Item -LiteralPath $rcHarnessFile -Force -ErrorAction SilentlyContinue

$RcUtf8Bom = New-Object Text.UTF8Encoding($true)
$RcUtf8 = New-Object Text.UTF8Encoding($false)
function Test-RcWanted([string]$Id) { return ([string]::IsNullOrWhiteSpace($Only) -or (@($Only -split "," | ForEach-Object { $_.Trim() }) -contains $Id)) }
function Write-RcHead([string]$s) { Write-Host ""; Write-Host ("######## " + $s) }
function Write-RcNote([string]$s) { Write-Host ("  " + $s) }
function Show-RcConsole($r, [string]$label) {
    # The WHOLE console of one run, numbered. A line longer than 200 characters (the public certificate) is cut.
    Write-Host ("  [{0}] exit={1} timedOut={2}" -f $label, $r.ExitCode, $r.TimedOut)
    $n = 0
    foreach ($ln in @($r.StdOut -split "`r?`n")) {
        $n++
        $t = $ln; if ($t.Length -gt 200) { $t = $t.Substring(0, 60) + (" ...[{0} characters]" -f $ln.Length) }
        Write-Host ("      out{0:d2}| {1}" -f $n, $t)
    }
    foreach ($ln in @($r.StdErr -split "`r?`n" | Where-Object { $_ })) { Write-Host ("      ERR  | " + $ln) }
}
function Show-RcRun($r, [string]$label) {
    Write-Host ("  [{0}] exit={1} timedOut={2}" -f $label, $r.ExitCode, $r.TimedOut)
    foreach ($ln in @(($r.StdOut + "`n" + $r.StdErr) -split "`r?`n" | Where-Object { $_ -match "RESULT:|REFUSED|ENROLLED|Sign-in|FATAL|Auth mode|\[IDENTITY\]|Reason code|falling back|Top-level|Discarded|Account  |Missing auth|CORRUPT|UNREADABLE" } | Select-Object -First 14)) {
        $t = $ln.Trim(); if ($t.Length -gt 330) { $t = $t.Substring(0, 330) + " ..." }
        Write-Host ("      " + $t)
    }
}
function Get-RcReqLines([int]$Mark) {
    return @(Get-D0RequestsSince $Mark | ForEach-Object {
        $path = (($_.requestLine -split " ")[0..1] -join " ")
        $path = [regex]::Replace($path, '\d{4}-\d{2}-\d{2}T[\d:.]+Z', '<T>')
        if ($path.Length -gt 100) { $path = $path.Substring(0, 100) + "..." }
        "{0} | {1} | as={2} | secret={3} | {4}" -f $_.kind, $path, $(if ($_.clientId -eq $D0OwnApp) { "OWN-APP" } elseif ($_.clientId -eq $D0Shared) { "SHARED-APP" } else { $_.clientId }), $_.hasSecret, $_.outcome })
}
function Show-RcFacts($Bay, [string]$label) {
    $cers = @(Get-ChildItem -LiteralPath (Join-Path $Bay.Root "state") -Filter "bay-cert-*.cer" -ErrorAction SilentlyContinue | ForEach-Object { $_.Name.Substring(9, 8) + ".." })
    $st = $null; $len = -1
    if (Test-Path -LiteralPath $Bay.State) { $txt = [IO.File]::ReadAllText($Bay.State); $len = $txt.Length; try { $st = $txt | ConvertFrom-Json } catch { } }
    $bakLen = -1
    if (Test-Path -LiteralPath ($Bay.State + ".bak")) { $bakLen = ([IO.File]::ReadAllBytes($Bay.State + ".bak")).Length }
    $atp = [string](Get-D0Prop $st "activeThumbprint"); if ($atp.Length -ge 8) { $atp = $atp.Substring(0, 8) + ".." }
    $acl = [string](Get-D0Prop $st "activeClientId"); if ($acl -eq $D0OwnApp) { $acl = "OWN-APP" }
    Write-Host ("  facts[{0}]: state length={1} activeThumbprint={2} activeClientId={3} | .cer files={4} ({5}) | certificates of this run in the store={6} | credential.json.bak length={7} | agent-alive.json={8}" -f $label, $len, $atp, $acl, $cers.Count, ($cers -join ","), @(Get-D0RunCerts).Count, $bakLen, (Test-Path -LiteralPath (Join-Path $Bay.Root "state\agent-alive.json")))
}
function New-RcSheetBay([string]$Name) {
    # agent-config.json as sheet 05 step 9 leaves it: Day0's template, clientId = the bay's OWN app (-BayAppId),
    # the template's clientSecretDpapiPath kept (no file), logLevel INFO as the template has it.
    $b = New-D0Bay -Name $Name -Shape "shared"
    $c = [IO.File]::ReadAllText($b.Config) | ConvertFrom-Json
    $c.clientId = $D0OwnApp
    $c.logLevel = "INFO"
    [IO.File]::WriteAllText($b.Config, ($c | ConvertTo-Json -Depth 6), $RcUtf8Bom)
    return $b
}
function Protect-RcSecretAt([string]$Path) {
    $sealed = [System.Security.Cryptography.ProtectedData]::Protect([Text.Encoding]::UTF8.GetBytes("not-a-real-secret-" + [guid]::NewGuid().ToString("N")), $null, [System.Security.Cryptography.DataProtectionScope]::LocalMachine)
    New-Item -ItemType Directory -Force -Path (Split-Path -Parent $Path) | Out-Null
    [IO.File]::WriteAllBytes($Path, $sealed)
}

$RcEnroll = "-EnrollCert -EnrollClientId {0}"
Write-Host ("RECHECK PROBES  head {0}  {1}" -f ((& git -C $RcRepo rev-parse HEAD) -join ""), (Get-Date).ToString("yyyy-MM-dd HH:mm:ss"))
Write-Host ("own app shown as OWN-APP, the shared app as SHARED-APP; this run's bay id {0}" -f $D0BayId)

try {
    $rcSheetBay = $null; $rcSheetTp = $null
    # ================================================================== R1
    if (Test-RcWanted "R1") {
        Write-RcHead "R1  the sitting in sheet 05's shape (steps 9 to 14 on the model)"
        $b = New-RcSheetBay "r1-sheet"; $rcSheetBay = $b
        $c = [IO.File]::ReadAllText($b.Config) | ConvertFrom-Json
        Write-RcNote ("agent-config.json: clientId is the own app = {0}; clientSecretDpapiPath named = {1}; that file exists = {2}; clientSecret key present = {3}; logLevel = {4}" -f ($c.clientId -eq $D0OwnApp), [bool]$c.PSObject.Properties["clientSecretDpapiPath"], (Test-Path -LiteralPath ([string]$c.clientSecretDpapiPath)), [bool]$c.PSObject.Properties["clientSecret"], $c.logLevel)
        $mark = Get-D0Mark
        $r = Invoke-D0Agent -Bay $b -Arguments ($RcEnroll -f $D0OwnApp) -Sheet; Show-RcConsole $r "STEP 11: the line, first run"
        $rcSheetTp = Get-D0ReportField $r.StdOut "Thumbprint"
        Write-RcNote ("requests sent during step 11: {0}" -f @(Get-D0RequestsSince $mark).Count)
        Show-RcFacts $b "after step 11"
        $mark = Get-D0Mark
        $r = Invoke-D0Agent -Bay $b -Arguments ($RcEnroll -f $D0OwnApp) -Sheet; Show-RcConsole $r "STEP 13 run BEFORE the certificate is registered"
        foreach ($l in @(Get-RcReqLines $mark)) { Write-RcNote $l }
        Register-D0Certificate -AppId $D0OwnApp -CerPath (Join-Path $b.Root ("state\bay-cert-{0}.cer" -f $rcSheetTp))
        Write-RcNote "--- the certificate is now registered on the own app (the model's add-cert)"
        $mark = Get-D0Mark
        $r = Invoke-D0Agent -Bay $b -Arguments ($RcEnroll -f $D0OwnApp) -Sheet; Show-RcConsole $r "STEP 13: the same line, after registration"
        foreach ($l in @(Get-RcReqLines $mark)) { Write-RcNote $l }
        $mark = Get-D0Mark
        $r = Invoke-D0Agent -Bay $b -Arguments "-Once"; Show-RcConsole $r "STEP 14: the agent as the host starts it (one pass)"
        foreach ($l in @(Get-RcReqLines $mark)) { Write-RcNote $l }
        $caps = Get-D0Capabilities @(Get-D0RequestsSince $mark)
        $cred = Get-D0Prop $caps "credential"
        if ($cred) {
            Write-RcNote ("the report the bay wrote: agentVersion={0} | credential.activeClientId is the own app={1} | activeThumbprint is step 11's={2} | pendingThumbprint={3} | lastMintMode={4} | identity.ownIdentity={5} | secretConfigured={6} | configuredMode={7} | stateFileCorrupt={8}" -f (Get-D0Prop $caps "agentVersion"), ((Get-D0Prop $cred "activeClientId") -eq $D0OwnApp), ((Get-D0Prop $cred "activeThumbprint") -eq $rcSheetTp), (Get-D0Prop $cred "pendingThumbprint"), (Get-D0Prop $cred "lastMintMode"), (Get-D0Prop (Get-D0Prop $cred "identity") "ownIdentity"), (Get-D0Prop $cred "secretConfigured"), (Get-D0Prop $cred "configuredMode"), (Get-D0Prop $cred "stateFileCorrupt"))
        } else { Write-RcNote "NO capabilities report was written in that pass" }
        Show-RcFacts $b "after step 14"
    }

    # ================================================================== R2
    if ((Test-RcWanted "R2") -and $rcSheetBay) {
        Write-RcHead "R2  the same bay, enrolled, registered and having run: state\credential.json is emptied (0 bytes)"
        $b = $rcSheetBay
        $goodState = [IO.File]::ReadAllBytes($b.State)
        [IO.File]::WriteAllBytes($b.State, [byte[]]@())
        $mark = Get-D0Mark
        $r = Invoke-D0Agent -Bay $b -Arguments "-Once"; Show-RcRun $r "the agent restarts on the emptied state (one pass)"
        foreach ($l in @(Get-RcReqLines $mark)) { Write-RcNote $l }
        $r = Invoke-D0Agent -Bay $b -Arguments ($RcEnroll -f $D0OwnApp) -Sheet; Show-RcRun $r "the console line, as a person would run it to see what is wrong"
        $tp2 = Get-D0ReportField $r.StdOut "Thumbprint"
        Write-RcNote ("a NEW key was made: {0}" -f ($tp2 -and $tp2 -ne $rcSheetTp))
        Show-RcFacts $b "after the console line"
        $mark = Get-D0Mark
        $r = Invoke-D0Agent -Bay $b -Arguments "-Once"; Show-RcRun $r "the agent again (one pass)"
        foreach ($l in @(Get-RcReqLines $mark)) { Write-RcNote $l }
        $r = Invoke-D0Agent -Bay $b -Arguments ($RcEnroll -f $D0OwnApp) -Sheet; Show-RcRun $r "the console line again"
        Write-RcNote "--- way back 1 (no cloud step): the state file as it was is put back by hand; the first key was never removed"
        $afterState = [IO.File]::ReadAllBytes($b.State)
        [IO.File]::WriteAllBytes($b.State, $goodState)
        $mark = Get-D0Mark
        $r = Invoke-D0Agent -Bay $b -Arguments ($RcEnroll -f $D0OwnApp) -Sheet; Show-RcRun $r "the console line"
        $r = Invoke-D0Agent -Bay $b -Arguments "-Once"; Show-RcRun $r "the agent (one pass)"
        foreach ($l in @(Get-RcReqLines $mark | Where-Object { $_ -like "token*" })) { Write-RcNote $l }
        Show-RcFacts $b "after way back 1 (the second key and its .cer are still on the PC, on no record)"
        Write-RcNote "--- way back 2 (the cloud step): the NEW key's state is kept and its certificate is registered"
        [IO.File]::WriteAllBytes($b.State, $afterState)
        Register-D0Certificate -AppId $D0OwnApp -CerPath (Join-Path $b.Root ("state\bay-cert-{0}.cer" -f $tp2))
        $mark = Get-D0Mark
        $r = Invoke-D0Agent -Bay $b -Arguments ($RcEnroll -f $D0OwnApp) -Sheet; Show-RcRun $r "the console line"
        $r = Invoke-D0Agent -Bay $b -Arguments "-Once"; Show-RcRun $r "the agent (one pass)"
        foreach ($l in @(Get-RcReqLines $mark | Where-Object { $_ -like "token*" })) { Write-RcNote $l }
        Write-RcNote ("certificates the model's own app now trusts: {0} (the real ladder's activate refuses an app that holds a key beside the recorded one)" -f $sync["Apps"][$D0OwnApp].Count)
    }

    # ================================================================== R3
    if (Test-RcWanted "R3") {
        Write-RcHead "R3  -EnrollForce from another Windows account: 'has this bay run' is read from state\agent-alive.json alone"
        $b = New-RcSheetBay "r3-hasrun"
        $r = Invoke-D0Agent -Bay $b -Arguments ($RcEnroll -f $D0OwnApp) -Sheet
        $tp = Get-D0ReportField $r.StdOut "Thumbprint"
        Register-D0Certificate -AppId $D0OwnApp -CerPath (Join-Path $b.Root ("state\bay-cert-{0}.cer" -f $tp))
        $r = Invoke-D0Agent -Bay $b -Arguments "-Once"; Show-RcRun $r "the bay runs one pass"
        Show-RcFacts $b "a working bay"
        # Modeled as the builder's suite models it: the record names another account, and this account's store has no such key.
        Set-D0EnrolledAccount $b "BAY1KIOSK\BayKiosk"
        Remove-Item -LiteralPath ("Cert:\CurrentUser\My\" + $tp) -DeleteKey -Force
        $r = Invoke-D0Agent -Bay $b -Arguments (($RcEnroll -f $D0OwnApp) + " -EnrollForce") -Sheet; Show-RcRun $r "another account, -EnrollForce, agent-alive.json present"
        Remove-Item -LiteralPath (Join-Path $b.Root "state\agent-alive.json") -Force
        $before = Get-D0InstallFingerprint $b.Root
        $r = Invoke-D0Agent -Bay $b -Arguments (($RcEnroll -f $D0OwnApp) + " -EnrollForce") -Sheet; Show-RcRun $r "another account, -EnrollForce, agent-alive.json GONE"
        Write-RcNote ("the PC was changed: {0}" -f ((Get-D0InstallFingerprint $b.Root) -ne $before))
        Show-RcFacts $b "after"
    }

    # ================================================================== R4
    if (Test-RcWanted "R4") {
        Write-RcHead "R4  a secret that arrives AFTER enrollment, in each of the three places; then the console line"
        $cases = @(
            @{ n = "sealed file at the path the configuration names (the standard place)"; kind = "named" },
            @{ n = "sealed file at the standard place, the configuration names another path"; kind = "standard-unnamed" },
            @{ n = "clientSecret key added to agent-config.json beside the path key"; kind = "plaintext" }
        )
        $ci = 0
        foreach ($cs in $cases) {
            $ci++
            Write-RcNote ("--- " + $cs.n)
            $b = New-RcSheetBay ("r4-" + $ci)
            if ($cs.kind -eq "standard-unnamed") {
                $c = [IO.File]::ReadAllText($b.Config) | ConvertFrom-Json
                $c.clientSecretDpapiPath = (Join-Path $b.Root "elsewhere\other.dpapi")
                [IO.File]::WriteAllText($b.Config, ($c | ConvertTo-Json -Depth 6), $RcUtf8Bom)
            }
            $r = Invoke-D0Agent -Bay $b -Arguments ($RcEnroll -f $D0OwnApp) -Sheet
            $tp = Get-D0ReportField $r.StdOut "Thumbprint"
            Write-RcNote ("enrolled: " + (Get-D0FirstResult $r.StdOut))
            Register-D0Certificate -AppId $D0OwnApp -CerPath (Join-Path $b.Root ("state\bay-cert-{0}.cer" -f $tp))
            if ($cs.kind -eq "plaintext") {
                $c = [IO.File]::ReadAllText($b.Config) | ConvertFrom-Json
                $c | Add-Member -NotePropertyName clientSecret -NotePropertyValue ("not-a-real-secret-" + [guid]::NewGuid().ToString("N"))
                [IO.File]::WriteAllText($b.Config, ($c | ConvertTo-Json -Depth 6), $RcUtf8Bom)
            } else { Protect-RcSecretAt (Join-Path $b.Root "secrets\clientsecret.dpapi") }
            $before = Get-D0InstallFingerprint $b.Root
            $r = Invoke-D0Agent -Bay $b -Arguments ($RcEnroll -f $D0OwnApp) -Sheet; Show-RcRun $r "console line, no force"
            $r = Invoke-D0Agent -Bay $b -Arguments (($RcEnroll -f $D0OwnApp) + " -EnrollForce") -Sheet; Show-RcRun $r "console line, -EnrollForce"
            Write-RcNote ("the PC was changed by either: {0}" -f ((Get-D0InstallFingerprint $b.Root) -ne $before))
            $mark = Get-D0Mark
            $r = Invoke-D0Agent -Bay $b -Arguments "-Once"; Show-RcRun $r "the agent (one pass), certificate registered and working"
            foreach ($l in @(Get-RcReqLines $mark | Where-Object { $_ -like "token*" })) { Write-RcNote $l }
            $cred = Get-D0Prop (Get-D0Capabilities @(Get-D0RequestsSince $mark)) "credential"
            if ($cred) { Write-RcNote ("report: lastMintMode={0} secretConfigured={1} plaintextSecretPresent={2}" -f (Get-D0Prop $cred "lastMintMode"), (Get-D0Prop $cred "secretConfigured"), (Get-D0Prop $cred "plaintextSecretPresent")) }
        }
    }

    # ================================================================== R5
    if (Test-RcWanted "R5") {
        Write-RcHead "R5  a sealed secret file is on the PC but THIS account cannot even look at it (access denied): base 6227e4d against head"
        $rcMe = ("{0}\{1}" -f [Environment]::UserDomainName, [Environment]::UserName)
        $rcHeadScript = $AgentScript
        foreach ($side in @(@{ n = "BASE 6227e4d (the attacked head)"; s = "C:\aoc-wt\verdicts\bayagent-161-recheck-evidence\BayAgent-6227e4d.ps1" }, @{ n = "HEAD bc2e6c6"; s = $rcHeadScript })) {
            Write-RcNote ("--- " + $side.n)
            $AgentScript = $side.s
            $b = New-RcSheetBay ("r5-" + $side.n.Substring(0, 4).Trim().ToLowerInvariant())
            $secDir = Join-Path $b.Root "secrets"; $secFile = Join-Path $secDir "clientsecret.dpapi"
            Protect-RcSecretAt $secFile
            # Deny this account the two rights an existence check needs: read-attributes on the file, list on the folder.
            & icacls.exe $secFile /deny ("{0}:(RA)" -f $rcMe) | Out-Null
            & icacls.exe $secDir /deny ("{0}:(RD)" -f $rcMe) | Out-Null
            $seen = "?"
            try { $seen = [string](Test-Path -LiteralPath $secFile) } catch { $seen = "THROWS: " + $_.Exception.Message }
            Write-RcNote ("Test-Path on the secret file, from this account: " + $seen)
            $certsBefore = @(Get-D0RunCerts).Count
            $r = Invoke-D0Agent -Bay $b -Arguments ($RcEnroll -f $D0OwnApp) -Sheet; Show-RcRun $r "the console line (step 11) on that PC"
            Write-RcNote ("RESULT line: '{0}' | reason code: '{1}' | a key was made: {2} | state file written: {3}" -f (Get-D0FirstResult $r.StdOut), (Get-D0ReportField $r.StdOut "Reason code"), (@(Get-D0RunCerts).Count -gt $certsBefore), (Test-Path -LiteralPath $b.State))
            & icacls.exe $secDir /remove:d $rcMe | Out-Null
            & icacls.exe $secFile /remove:d $rcMe | Out-Null
            $r = Invoke-D0Agent -Bay $b -Arguments ($RcEnroll -f $D0OwnApp) -Sheet
            Write-RcNote ("with the file readable again, the same line answers: '{0}' reason '{1}'" -f (Get-D0FirstResult $r.StdOut), (Get-D0ReportField $r.StdOut "Reason code"))
        }
        $AgentScript = $rcHeadScript
    }

    # ================================================================== R6
    if (Test-RcWanted "R6") {
        Write-RcHead "R6  HEAD, the same unreadable secret file, carried through the sitting: steps 11, add-cert, 13, 14"
        $rcMe = ("{0}\{1}" -f [Environment]::UserDomainName, [Environment]::UserName)
        $b = New-RcSheetBay "r6-head"
        $secDir = Join-Path $b.Root "secrets"; $secFile = Join-Path $secDir "clientsecret.dpapi"
        Protect-RcSecretAt $secFile
        & icacls.exe $secFile /deny ("{0}:(RA)" -f $rcMe) | Out-Null
        & icacls.exe $secDir /deny ("{0}:(RD)" -f $rcMe) | Out-Null
        try {
            $r = Invoke-D0Agent -Bay $b -Arguments ($RcEnroll -f $D0OwnApp) -Sheet; Show-RcRun $r "step 11"
            $tp = Get-D0ReportField $r.StdOut "Thumbprint"
            if ($tp -match '^[0-9A-F]{40}$') {
                Register-D0Certificate -AppId $D0OwnApp -CerPath (Join-Path $b.Root ("state\bay-cert-{0}.cer" -f $tp))
                $r = Invoke-D0Agent -Bay $b -Arguments ($RcEnroll -f $D0OwnApp) -Sheet; Show-RcRun $r "step 13"
                $mark = Get-D0Mark
                $r = Invoke-D0Agent -Bay $b -Arguments "-Once"; Show-RcRun $r "step 14: the agent as the host starts it, same account"
                Write-RcNote ("requests the agent sent: {0}" -f @(Get-D0RequestsSince $mark).Count)
            } else { Write-RcNote "step 11 made no certificate, so the rest was not run" }
        } finally {
            & icacls.exe $secDir /remove:d $rcMe | Out-Null
            & icacls.exe $secFile /remove:d $rcMe | Out-Null
        }
    }

    # ================================================================== R7
    if (Test-RcWanted "R7") {
        Write-RcHead "R7  what a FATAL looks like on the console line (sheet step 11's fourth stop): the whole of both streams"
        $b = New-RcSheetBay "r7-fatal"
        # A state folder that is a FILE: the enrollment makes its key, cannot write the .cer, undoes, and throws.
        [IO.File]::WriteAllText((Join-Path $b.Root "state"), "not a folder", $RcUtf8)
        $certsBefore = @(Get-D0RunCerts).Count
        $r = Invoke-D0Agent -Bay $b -Arguments ($RcEnroll -f $D0OwnApp) -Sheet; Show-RcConsole $r "the console line, with state\ unusable"
        Write-RcNote ("standard error stream: {0} characters | keys of this run left in the store by it: {1}" -f $r.StdErr.Length, (@(Get-D0RunCerts).Count - $certsBefore))
    }
}
catch {
    Write-Host ("PROBE RUN STOPPED ON AN ERROR at line {0}: {1}" -f $_.InvocationInfo.ScriptLineNumber, $_.Exception.Message)
}
finally {
    $sync["Stop"] = $true
    try { $mock.PS.Stop() } catch {}
    try { $mock.RS.Close() } catch {}
    $mine = @(Get-D0RunCerts) + @(Get-D0PlaceholderCerts | Where-Object { $placeholderCertsAtStart -notcontains $_ })
    foreach ($tpLeft in $mine) { try { Remove-Item -LiteralPath ("Cert:\CurrentUser\My\" + $tpLeft) -DeleteKey -Force } catch { Write-Host "could not remove probe certificate $tpLeft" } }
    try { Remove-Item -LiteralPath $SandboxRoot -Recurse -Force -ErrorAction SilentlyContinue } catch {}
}
$left = @(Get-D0RunCerts)
Write-Host ""
Write-Host ("recorder errors: {0}" -f $sync["Errors"].Count)
foreach ($e in @($sync["Errors"].ToArray() | Select-Object -First 5)) { Write-Host ("   " + $e) }
Write-Host ("cleanup: certificates of this run left in the store: {0}" -f $left.Count)
Write-Host "PROBES-DONE"
