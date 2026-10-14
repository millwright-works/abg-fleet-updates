<#
Run-Day0EnrollMutations.ps1

Plants one change at a time in the REAL TEXT of src\BayAgent\BayAgent.ps1 (the script's own body and the functions it
calls) and runs tests\BayAgent.Day0Enroll.Tests.ps1 against each changed copy. A change the suite does not notice is a
SURVIVOR: the suite could not fail on it.

Rules this runner holds itself to:
  - a control (the unchanged script) must pass first, or nothing else is counted: the instrument must be able to pass;
  - each change's anchor text must occur EXACTLY ONCE, the copy must differ from the original and must parse; a change
    that could not be applied is NOT APPLIED, never a kill;
  - a kill is read from the suite's own RESULT line and the names of the assertions that failed; a run with no RESULT
    line is NOT RUN, never a kill;
  - the working tree is never touched: every changed copy lives under -OutDir.

Run (pwsh 7 or Windows PowerShell 5.1), from anywhere:
  powershell -NoProfile -ExecutionPolicy Bypass -File attack\Run-Day0EnrollMutations.ps1 -OutDir C:\some\scratch\folder
Hyphens only in comments.
#>
[CmdletBinding()]
param(
    [string]$RepoRoot = "",
    [Parameter(Mandatory = $true)][string]$OutDir,
    [int]$Parallel = 3,
    [string]$Only = ""
)
Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
if ([string]::IsNullOrWhiteSpace($RepoRoot)) { $RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path }
$AgentPath = Join-Path $RepoRoot "src\BayAgent\BayAgent.ps1"
$SuitePath = Join-Path $RepoRoot "tests\BayAgent.Day0Enroll.Tests.ps1"
$HostExe = Join-Path $env:WINDIR "System32\WindowsPowerShell\v1.0\powershell.exe"
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
$nl = "`r`n"
$original = [IO.File]::ReadAllText($AgentPath)
if (-not $original.Contains($nl)) { throw "BayAgent.ps1 is expected with CRLF line ends in the working tree (the multi-line anchors below rely on it)" }

function New-D0Mutant([string]$Id, [string]$What, [object[]]$Edits) { return [pscustomobject]@{ Id = $Id; What = $What; Edits = $Edits } }
function New-D0Edit([string]$From, [string]$To) { return [pscustomobject]@{ From = $From; To = $To } }

$mutants = @(
    # ---- the script's own body (top-level statements) ----
    (New-D0Mutant "B01" "the typed parameter is not what counts: the option is always on" @(
        (New-D0Edit '$EnrollClientIdGiven = $PSBoundParameters.ContainsKey("EnrollClientId")' '$EnrollClientIdGiven = $true'))),
    (New-D0Mutant "B02" "a built-in default becomes the bay's identity when nothing was typed" @(
        (New-D0Edit '[string]$EnrollClientId = ""' '[string]$EnrollClientId = "99999999-9999-4999-8999-999999999999"'),
        (New-D0Edit '$EnrollClientIdGiven = $PSBoundParameters.ContainsKey("EnrollClientId")' '$EnrollClientIdGiven = (-not [string]::IsNullOrWhiteSpace($EnrollClientId))'))),
    (New-D0Mutant "B03" "the configured app is forwarded when the typed value is empty" @(
        (New-D0Edit '$ownIdResult = Invoke-OwnIdentityEnroll -OwnClientId $EnrollClientId -Payload $enrollPayload' '$ownIdResult = Invoke-OwnIdentityEnroll -OwnClientId $(if ($EnrollClientId) { $EnrollClientId } else { $ClientId }) -Payload $enrollPayload'))),
    (New-D0Mutant "B04" "the option silently does nothing: a plain enrollment runs instead" @(
        (New-D0Edit '    if ($EnrollClientIdGiven) {' '    if ($false) {'))),
    (New-D0Mutant "B05" "the exit code is always 0" @(
        (New-D0Edit '        exit ([int]$ownIdResult.exitCode)' '        exit 0'))),
    (New-D0Mutant "B06" "the report is never printed" @(
        (New-D0Edit 'foreach ($ownIdLine in @(Format-OwnIdentityEnrollReport $ownIdResult)) { Write-Host $ownIdLine }' '$null = $ownIdResult'))),
    (New-D0Mutant "B07" "-EnrollClientId without -EnrollCert is ignored" @(
        (New-D0Edit 'if ($EnrollClientIdGiven -and -not $EnrollCert) {' 'if ($false) {'))),
    (New-D0Mutant "B08" "the old start-up refusal is back: a configuration that names no secret cannot start" @(
        (New-D0Edit 'function Get-ClientSecret {' ('if (-not $EnrollCert) { if (-not $CertThumbprintCfg -and -not $HasSecretCredential) { throw "Missing auth config (mutant)" } }' + $nl + 'function Get-ClientSecret {')))),
    (New-D0Mutant "B09" "a remote command can name the app (the console-only rule is broken)" @(
        (New-D0Edit '        "enroll"   { return (Invoke-CredentialEnroll $payloadObj) }' '        "enroll"   { if (Get-PropValue $payloadObj "clientId" $null) { return (Invoke-OwnIdentityEnroll -OwnClientId ([string](Get-PropValue $payloadObj "clientId" "")) -Payload $payloadObj) }; return (Invoke-CredentialEnroll $payloadObj) }'))),

    # ---- what is recorded ----
    (New-D0Mutant "R01" "the app typed is not recorded with the certificate" @(
        (New-D0Edit '            activeClientId      = $own' '            activeClientId      = $null'))),
    (New-D0Mutant "R02" "nothing records that the app is the bay's own" @(
        (New-D0Edit '            ownIdentityEnrolled = [ordered]@{ clientId = $own; thumbprint = $cert.Thumbprint; utc = $nowStr; account = $account }' '            ownIdentityEnrolledMutant = $null'))),
    (New-D0Mutant "R03" "own identity is known only by 'different from the configured app' (F3 again)" @(
        (New-D0Edit '    return ((ConvertTo-AgentGuid ([string](Get-PropValue $enrolledRec "clientId" ""))) -eq $active)' '    return $false'))),
    (New-D0Mutant "R04" "the start-up log no longer names the bay's own app" @(
        (New-D0Edit 'if (Test-OwnIdentityActive) { Write-Log ("[IDENTITY] signing in as this bay' 'if ($false) { Write-Log ("[IDENTITY] signing in as this bay'))),

    # ---- refusals decided before a key is made ----
    (New-D0Mutant "G01" "a value that is not a GUID is accepted" @(
        (New-D0Edit '    if (-not $own) {' '    if ($false) {'))),
    (New-D0Mutant "G02" "a refused value is echoed" @(
        (New-D0Edit 'What was typed is {0} characters long and is not one." -f ([string]$OwnClientId).Length))' 'What was typed is {0} and is not one." -f ([string]$OwnClientId)))'))),
    (New-D0Mutant "G03" "an unfilled configuration is enrolled" @(
        (New-D0Edit '    if ($unfilled.Count -gt 0) {' '    if ($false) {'))),
    (New-D0Mutant "G09" "a tenantId that is still a placeholder is enrolled (the attack's survivor)" @(
        (New-D0Edit "if ([string]::IsNullOrWhiteSpace([string]`$TenantId) -or ([string]`$TenantId -match '[<>\s]')) { `$unfilled += `"tenantId`" }" "if (`$false) { `$unfilled += `"tenantId`" }"))),
    (New-D0Mutant "G10" "an environmentUrl that is not an address is enrolled (the attack's survivor)" @(
        (New-D0Edit "if ([string]`$OrgUrl -notmatch '^https?://[A-Za-z0-9.-]+(:\d+)?`$') { `$unfilled += `"environmentUrl`" }" "if (`$false) { `$unfilled += `"environmentUrl`" }"))),
    (New-D0Mutant "G04" "a PC that holds a client secret is enrolled (A0.529)" @(
        (New-D0Edit '    if ($secretCheck.Found) {' '    if ($false) {'))),
    (New-D0Mutant "G11" "the secret guard reads only what a sign-in would use now: a plaintext secret beside a secret-file path is not seen" @(
        (New-D0Edit 'if (($cfg.PSObject.Properties.Name -contains "clientSecret") -and (-not [string]::IsNullOrWhiteSpace([string]$cfg.clientSecret))) {' 'if ($false) {'))),
    (New-D0Mutant "G12" "the secret guard reads only the configured path: a sealed file at the standard place is not seen" @(
        (New-D0Edit '        if (Test-Path -LiteralPath $standardPlace -PathType Leaf) {' '        if ($false) {'))),
    (New-D0Mutant "G13" "the secret guard no longer reads what a sign-in would use now" @(
        (New-D0Edit 'try { if (Test-HasUsableSecret) { $found +=' 'try { if ($false) { $found +='))),
    # ---- RF-1 (re-check of 2026-10-12): a place that cannot be looked at is a refusal, not "nothing there" ----
    (New-D0Mutant "H01" "an error looking at the secret the configuration names is swallowed again (read as nothing there)" @(
        (New-D0Edit 'catch { $unreadable += ("the secret the configuration names ({0}): {1}" -f $namedPath, $_.Exception.Message) }' 'catch { }'))),
    (New-D0Mutant "H02" "an error reading the clientSecret key of the configuration is swallowed again" @(
        (New-D0Edit 'catch { $unreadable += ("agent-config.json, the clientSecret key: {0}" -f $_.Exception.Message) }' 'catch { }'))),
    (New-D0Mutant "H03" "an error looking at the standard place is swallowed again" @(
        (New-D0Edit 'catch { $unreadable += ("the standard place for the sealed secret ({0}): {1}" -f $standardPlace, $_.Exception.Message) }' 'catch { }'))),
    (New-D0Mutant "H04" "the caller no longer refuses when a place could not be looked at" @(
        (New-D0Edit '    if ($secretCheck.Unreadable) {' '    if ($false) {'))),
    (New-D0Mutant "W3" "-EnrollForce passes the secret guard (the re-check's survivor)" @(
        (New-D0Edit '    if ($secretCheck.Found) {' '    if ($secretCheck.Found -and -not $force) {'))),
    (New-D0Mutant "W3b" "-EnrollForce passes the unreadable-place refusal" @(
        (New-D0Edit '    if ($secretCheck.Unreadable) {' '    if ($secretCheck.Unreadable -and -not $force) {'))),
    (New-D0Mutant "W4" "the standard place is read only when the configuration names no other path (the re-check's survivor)" @(
        (New-D0Edit '        if (Test-Path -LiteralPath $standardPlace -PathType Leaf) {' '        if (-not $script:SecretPath -and (Test-Path -LiteralPath $standardPlace -PathType Leaf)) {'))),
    (New-D0Mutant "W5" "the secret guard is not asked of a bay that already has something on record (the re-check's survivor)" @(
        (New-D0Edit '    $secretCheck = Get-OwnIdentitySecretOnPc' '    $secretCheck = $(if ($stateTp) { [pscustomobject]@{ Found = ""; Unreadable = "" } } else { Get-OwnIdentitySecretOnPc })'))),
    (New-D0Mutant "G05" "a corrupt state file is not a refusal" @(
        (New-D0Edit ('        if ($Global:CredentialStateCorrupt) {' + $nl + '            return (New-OwnIdentityEnrollRefusal "AOC_OWNID_STATE_CORRUPT"') ('        if ($false) {' + $nl + '            return (New-OwnIdentityEnrollRefusal "AOC_OWNID_STATE_CORRUPT"')))),
    (New-D0Mutant "G06" "an identity switch on probation is not a refusal" @(
        (New-D0Edit '    if ($null -ne $probation) {' '    if ($false) {'))),
    (New-D0Mutant "G07" "a waiting rotation is not a refusal" @(
        (New-D0Edit '    if ($pendingTp) {' '    if ($false) {'))),
    (New-D0Mutant "G08" "a certificate named in the configuration is not a refusal" @(
        (New-D0Edit '    if (-not $stateTp -and $CertThumbprintCfg) {' '    if ($false) {'))),

    # ---- the second run, and -EnrollForce ----
    (New-D0Mutant "F01" "the second run is not recognized as the same enrollment" @(
        (New-D0Edit '        if ($sameIdentity -and $certHere -and -not $force) {' '        if ($false) {'))),
    (New-D0Mutant "F02" "any bay whose app matches counts as already enrolled, marker or not" @(
        (New-D0Edit '$sameIdentity = ($enrolledOwn -eq $own) -and ($stateClient -eq $own)' '$sameIdentity = ($recordedClient -eq $own)'))),
    (New-D0Mutant "F03" "the second run's exit code is 0 whether or not the bay can sign in" @(
        (New-D0Edit 'exitCode = $(if ($proof.outcome -eq "works") { 0 } else { 4 })' 'exitCode = 0'))),
    (New-D0Mutant "F04" "an enrollment on record is replaced without -EnrollForce" @(
        (New-D0Edit '        if (-not $force) {' '        if ($false) {'))),
    (New-D0Mutant "F05" "a WORKING identity is replaced with -EnrollForce" @(
        (New-D0Edit '        if ($proof.outcome -eq "works") {' '        if ($false) {'))),
    (New-D0Mutant "F06" "an identity whose state cannot be told is replaced with -EnrollForce" @(
        (New-D0Edit '        if ($proof.outcome -eq "unknown" -or ($proof.outcome -eq "refused" -and -not $proof.unusable)) {' '        if ($false) {'))),
    (New-D0Mutant "F07" "no answer from Entra is read as a refusal" @(
        (New-D0Edit '        else { $r.outcome = "unknown" }' '        else { $r.outcome = "refused" }'))),
    (New-D0Mutant "F08" "a 4xx that does not carry Entra's own code is read as Entra refusing" @(
        (New-D0Edit "if ((`$proofMsg -match '^Token request failed with HTTP 4\d\d') -and `$r.code) {" "if (`$proofMsg -match '^Token request failed with HTTP 4\d\d') {"))),
    (New-D0Mutant "F16" "any refusal by Entra makes the enrollment discardable (a wrong clock would discard a good one)" @(
        (New-D0Edit '            $r.unusable = ($r.code -in @("AADSTS700016", "AADSTS700027"))' '            $r.unusable = $true'))),
    (New-D0Mutant "F17" "a refusal that says nothing about the enrollment is still discarded with -EnrollForce" @(
        (New-D0Edit 'if ($proof.outcome -eq "unknown" -or ($proof.outcome -eq "refused" -and -not $proof.unusable)) {' 'if ($proof.outcome -eq "unknown") {'))),
    (New-D0Mutant "F09" "the sign-in check signs in as the configured app, not the app on record" @(
        (New-D0Edit '$null = Acquire-TokenWithCertificate -Thumbprint $r.thumbprint -ForClientId $r.clientId' '$null = Acquire-TokenWithCertificate -Thumbprint $r.thumbprint -ForClientId $ClientId'))),
    (New-D0Mutant "F10" "the discarded certificate and its key stay on the PC" @(
        (New-D0Edit '        $gone = @(Remove-OwnIdentityCertificate -Thumbprint $discard.thumbprint)' '        $gone = @()'))),
    (New-D0Mutant "F11" "a discarded certificate this account cannot reach is not kept on record" @(
        (New-D0Edit '            if ($sup -notcontains $discard.thumbprint) { $sup += $discard.thumbprint }' '            $sup = @($sup)'))),
    (New-D0Mutant "F12" "a bay that has run is re-enrolled from another Windows account" @(
        (New-D0Edit '            if ($hasRun -and -not $sameAccount) {' '            if ($false) {'))),
    (New-D0Mutant "F13" "any account counts as the account that enrolled" @(
        (New-D0Edit '            $sameAccount = (-not [string]::IsNullOrWhiteSpace($enrolledBy)) -and ($enrolledBy -ieq $account)' '            $sameAccount = $true'))),
    (New-D0Mutant "F15" "the account that enrolled is never recognized (a key lost from its own store cannot be replaced)" @(
        (New-D0Edit '            $sameAccount = (-not [string]::IsNullOrWhiteSpace($enrolledBy)) -and ($enrolledBy -ieq $account)' '            $sameAccount = $false'))),
    (New-D0Mutant "F14" "a bay that has run reads as one that never has" @(
        (New-D0Edit '            $hasRun = Test-Path -LiteralPath (Join-Path $BaseDir "state\agent-alive.json")' '            $hasRun = $false'))),

    # ---- a failure after the key is made ----
    (New-D0Mutant "U01" "a failed enrollment leaves its key and .cer behind" @(
        (New-D0Edit '        [void](Remove-OwnIdentityCertificate -Thumbprint $cert.Thumbprint)' '        $null = $cert'))),

    (New-D0Mutant "U02" "an earlier enrollment is not put back after a failed replace (the attack's survivor)" @(
        (New-D0Edit '            if ($stateExisted) { [IO.File]::WriteAllBytes($CredentialStatePath, $stateBefore) }' '            if ($false) { [IO.File]::WriteAllBytes($CredentialStatePath, $stateBefore) }'))),

    # ---- start-up on the enrolled bay ----
    (New-D0Mutant "S01" "a bay with no credential at all starts its loop" @(
        (New-D0Edit '    if (-not $activeTp -and -not $script:HasSecretCredential) {' '    if ($false) {'))),
    (New-D0Mutant "S02" "a certificate missing from the account's store is reported as a missing secret file" @(
        (New-D0Edit '        } elseif ($activeTp) {' '        } elseif ($false) {')))
)

if (-not [string]::IsNullOrWhiteSpace($Only)) {
    $wantedIds = @($Only -split "," | ForEach-Object { $_.Trim() } | Where-Object { $_ })
    $mutants = @($mutants | Where-Object { $wantedIds -contains $_.Id })
    if ($mutants.Count -ne $wantedIds.Count) { throw "FILTER-MISMATCH: wanted $($wantedIds.Count), found $($mutants.Count)" }
}

function Get-D0OccurrenceCount([string]$Text, [string]$Needle) {
    $count = 0; $at = 0
    while ($true) { $i = $Text.IndexOf($Needle, $at, [StringComparison]::Ordinal); if ($i -lt 0) { break }; $count++; $at = $i + $Needle.Length }
    return $count
}

function New-D0MutantFile($Mutant) {
    # Returns the path of the changed copy, or throws a sentence saying why the change could not be applied.
    $text = $original
    foreach ($e in @($Mutant.Edits)) {
        $n = Get-D0OccurrenceCount $text $e.From
        if ($n -ne 1) { throw ("anchor occurs {0} times, expected exactly 1: {1}" -f $n, $e.From.Substring(0, [Math]::Min(70, $e.From.Length))) }
        $text = $text.Replace($e.From, $e.To)
    }
    if ($text -eq $original) { throw "the copy does not differ from the original" }
    $dir = Join-Path $OutDir ("mutants\" + $Mutant.Id)
    New-Item -ItemType Directory -Force -Path $dir | Out-Null
    $path = Join-Path $dir "BayAgent.ps1"
    [IO.File]::WriteAllText($path, $text, (New-Object Text.UTF8Encoding($true)))
    $tk = $null; $er = $null
    [void][System.Management.Automation.Language.Parser]::ParseFile($path, [ref]$tk, [ref]$er)
    if (@($er).Count -gt 0) { throw ("the copy does not parse: {0}" -f $er[0].Message) }
    return $path
}

function Start-D0SuiteRun([string]$Id, [string]$AgentCopy) {
    $log = Join-Path $OutDir ($Id + ".txt")
    $err = Join-Path $OutDir ($Id + ".stderr.txt")
    $argList = @("-NoProfile", "-ExecutionPolicy", "Bypass", "-File", ('"{0}"' -f $SuitePath), "-AgentScript", ('"{0}"' -f $AgentCopy))
    # A Windows PowerShell child started from pwsh 7 must not inherit pwsh's module path: it then has no Cert: drive, and the
    # suite (which now stops when it cannot read the certificate store) would stop at its first certificate check.
    $savedModulePath = $env:PSModulePath
    try { $env:PSModulePath = $null; $p = Start-Process -FilePath $HostExe -ArgumentList $argList -RedirectStandardOutput $log -RedirectStandardError $err -PassThru -WindowStyle Hidden }
    finally { $env:PSModulePath = $savedModulePath }
    return [pscustomobject]@{ Id = $Id; Process = $p; Log = $log }
}

function Read-D0SuiteOutcome([string]$Log) {
    # Decided from the suite's own RESULT line, never from an exit code.
    $o = [ordered]@{ status = "NOT RUN"; passed = -1; failed = -1; failures = @() }
    if (-not (Test-Path -LiteralPath $Log)) { return $o }
    $lines = @(Get-Content -LiteralPath $Log)
    $res = @($lines | Where-Object { $_ -match '^RESULT: (\d+) passed, (\d+) failed' } | Select-Object -Last 1)
    if ($res.Count -eq 0) { return $o }
    $m = [regex]::Match($res[0], '^RESULT: (\d+) passed, (\d+) failed')
    $o.passed = [int]$m.Groups[1].Value; $o.failed = [int]$m.Groups[2].Value
    $o.failures = @($lines | Where-Object { $_ -match '^  FAIL  ' } | ForEach-Object { $_.Substring(8) })
    $o.status = $(if ($o.failed -gt 0) { "KILLED" } else { "SURVIVED" })
    return $o
}

$summary = New-Object System.Collections.ArrayList
[void]$summary.Add(("HOST {0} | REPO {1} | HEAD {2} | {3}" -f $HostExe, $RepoRoot, ((& git -C $RepoRoot rev-parse HEAD) -join ""), (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")))

# ---- the control: the unchanged script must pass ----
$controlDir = Join-Path $OutDir "mutants\C00"
New-Item -ItemType Directory -Force -Path $controlDir | Out-Null
$controlCopy = Join-Path $controlDir "BayAgent.ps1"
[IO.File]::WriteAllText($controlCopy, $original, (New-Object Text.UTF8Encoding($true)))
$c = Start-D0SuiteRun -Id "C00" -AgentCopy $controlCopy
$c.Process.WaitForExit()
$co = Read-D0SuiteOutcome $c.Log
$controlLine = "C00 | CONTROL (unchanged script) | {0} | {1} passed, {2} failed" -f $(if ($co.status -eq "SURVIVED") { "PASSES" } else { $co.status }), $co.passed, $co.failed
[void]$summary.Add($controlLine); $controlLine
if ($co.status -ne "SURVIVED") {
    [void]$summary.Add("ABORTED: the control did not pass, so no mutant result would mean anything")
    [IO.File]::WriteAllLines((Join-Path $OutDir "mutants-summary.txt"), [string[]]$summary.ToArray())
    "ABORTED"; exit 3
}

# ---- the mutants, at most $Parallel at a time (each run has its own sandbox, bay id, recorder and certificates) ----
$queue = New-Object System.Collections.Queue
foreach ($mu in $mutants) { $queue.Enqueue($mu) }
$running = @(); $results = @{}
while ($queue.Count -gt 0 -or $running.Count -gt 0) {
    while ($queue.Count -gt 0 -and $running.Count -lt $Parallel) {
        $mu = $queue.Dequeue()
        try {
            $copy = New-D0MutantFile $mu
            $run = Start-D0SuiteRun -Id $mu.Id -AgentCopy $copy
            $running += [pscustomobject]@{ Mutant = $mu; Run = $run }
        } catch {
            $results[$mu.Id] = ("{0} | NOT APPLIED | {1} | {2}" -f $mu.Id, $mu.What, $_.Exception.Message)
            $results[$mu.Id]
        }
    }
    $still = @()
    foreach ($item in $running) {
        if ($item.Run.Process.HasExited) {
            $o = Read-D0SuiteOutcome $item.Run.Log
            $line = "{0} | {1} | {2} | {3} passed, {4} failed" -f $item.Mutant.Id, $o.status, $item.Mutant.What, $o.passed, $o.failed
            if ($o.status -eq "KILLED") { $line += (" | first: " + (@($o.failures | Select-Object -First 2) -join " || ")) }
            $results[$item.Mutant.Id] = $line
            $line
        } else { $still += $item }
    }
    $running = $still
    if ($running.Count -gt 0) { Start-Sleep -Seconds 3 }
}

foreach ($mu in $mutants) { [void]$summary.Add([string]$results[$mu.Id]) }
$killed = @($mutants | Where-Object { [string]$results[$_.Id] -like "* | KILLED | *" }).Count
$survived = @($mutants | Where-Object { [string]$results[$_.Id] -like "* | SURVIVED | *" }).Count
$other = $mutants.Count - $killed - $survived
$done = "ALL-DONE mutants={0} killed={1} survived={2} not-applied-or-not-run={3}" -f $mutants.Count, $killed, $survived, $other
[void]$summary.Add($done)
[IO.File]::WriteAllLines((Join-Path $OutDir "mutants-summary.txt"), [string[]]$summary.ToArray())
$done
if ($survived -gt 0 -or $other -gt 0) { exit 1 }
exit 0
