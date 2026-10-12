<#
Run-NoSecretMutations.ps1

Plants one change at a time in the REAL TEXT of src\BayAgent\BayAgent.ps1 (the rule that a bay enrolled on its own
identity never signs in with a client secret) and runs tests\BayAgent.OwnIdentityNoSecret.Tests.ps1 against each copy.
A change the suite does not notice is a SURVIVOR.

Same rules as Run-Day0EnrollMutations.ps1: a control (the unchanged script) must pass first; each anchor must occur
exactly once, the copy must differ and must parse, or the change is NOT APPLIED (never a kill); a kill is read from the
suite's own RESULT line; a run with no RESULT line is NOT RUN; the working tree is never touched.

Run:  powershell -NoProfile -ExecutionPolicy Bypass -File attack\Run-NoSecretMutations.ps1 -OutDir C:\some\scratch\folder
Hyphens only in comments.
#>
[CmdletBinding()]
param(
    [string]$RepoRoot = "",
    [Parameter(Mandatory = $true)][string]$OutDir,
    [string]$Only = ""
)
Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
if ([string]::IsNullOrWhiteSpace($RepoRoot)) { $RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path }
$SetupPath = Join-Path $RepoRoot "src\BayAgent\BayAgent.ps1"
$SuitePath = Join-Path $RepoRoot "tests\BayAgent.OwnIdentityNoSecret.Tests.ps1"
$HostExe = Join-Path $env:WINDIR "System32\WindowsPowerShell\v1.0\powershell.exe"
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
$original = [IO.File]::ReadAllText($SetupPath)

function New-SeMutant([string]$Id, [string]$What, [object[]]$Edits) { return [pscustomobject]@{ Id = $Id; What = $What; Edits = $Edits } }
function New-SeEdit([string]$From, [string]$To) { return [pscustomobject]@{ From = $From; To = $To } }

$nl = "`r`n"
$mutants = @(
    (New-SeMutant "P01" "the one place a client secret is sent no longer refuses on an enrolled bay" @(
        (New-SeEdit ('    if ($enrolledOwn) {' + $nl + '        throw "Client secret refused') ('    if ($false) {' + $nl + '        throw "Client secret refused')))),
    (New-SeMutant "P02" "an enrolled bay 'falls back' again when its certificate fails" @(
        (New-SeEdit '            if ($HasSecretCredential -and -not $enrolledOwn) {' '            if ($HasSecretCredential) {'))),
    (New-SeMutant "P03" "an enrolled bay whose certificate is missing 'runs on the client secret until it is found'" @(
        (New-SeEdit '        } elseif ($script:HasSecretCredential -and -not $enrolledOwn) {' '        } elseif ($script:HasSecretCredential) {'))),
    (New-SeMutant "P04" "no bay is ever seen as enrolled (the rule is off)" @(
        (New-SeEdit '    if ($EnrolledOnly) { return ($null -ne $enrolledRec) }' '    if ($EnrolledOnly) { return $false }'))),
    (New-SeMutant "P05" "every bay is seen as enrolled (a bay on the shared secret goes dark)" @(
        (New-SeEdit '    if ($EnrolledOnly) { return ($null -ne $enrolledRec) }' '    if ($EnrolledOnly) { return $true }'))),
    (New-SeMutant "P06" "a bay moved to its own app by the remote ladder loses its secret to go back to" @(
        (New-SeEdit '    if ($EnrolledOnly) { return ($null -ne $enrolledRec) }' '    if ($EnrolledOnly) { return (($null -ne $enrolledRec) -or ($active -and ($active -ne (ConvertTo-AgentGuid $ClientId)))) }'))),
    (New-SeMutant "P12" "the gate compares the record with the app in force again (it lapses when they disagree)" @(
        (New-SeEdit '    if ($EnrolledOnly) { return ($null -ne $enrolledRec) }' '    if ($EnrolledOnly) { return (($null -ne $enrolledRec) -and ((ConvertTo-AgentGuid ([string](Get-PropValue $enrolledRec "clientId" ""))) -eq $active)) }'))),
    (New-SeMutant "P13" "the secret is read before the refusal" @(
        (New-SeEdit ('    $enrolledOwn = $false' + $nl + '    try { $enrolledOwn = [bool](Test-OwnIdentityActive -EnrolledOnly) } catch { $enrolledOwn = $false }' + $nl + '    if ($enrolledOwn) {' + $nl + '        throw "Client secret refused') ('    $clientSecretEarly = Get-ClientSecret' + $nl + '    $enrolledOwn = $false' + $nl + '    try { $enrolledOwn = [bool](Test-OwnIdentityActive -EnrolledOnly) } catch { $enrolledOwn = $false }' + $nl + '    if ($enrolledOwn) {' + $nl + '        throw "Client secret refused')))),
    (New-SeMutant "P07" "the report does not say the bay is enrolled" @(
        (New-SeEdit '        $identity["enrolledOwn"] = $true' '        $null = $true'))),
    (New-SeMutant "P08" "the report says no secret is being ignored when one is" @(
        (New-SeEdit '        $identity["secretIgnored"] = [bool](($secretMode -ne "none") -or ($SecretPathCfg -and (Test-Path -LiteralPath $SecretPathCfg)))' '        $identity["secretIgnored"] = $false'))),
    (New-SeMutant "P09" "start-up no longer says a secret was found and is ignored" @(
        (New-SeEdit '    if ($enrolledOwn -and $fallbackLabel -ne "none") {' '    if ($false) {'))),
    (New-SeMutant "P10" "a bay that is not enrolled gets the enrolled-bay fields in its report" @(
        (New-SeEdit ('    if ($enrolledOwn) {' + $nl + '        $identity["enrolledOwn"] = $true') ('    if ($true) {' + $nl + '        $identity["enrolledOwn"] = $true')))),
    (New-SeMutant "P11" "a damaged own-identity record is announced as 'Auth mode: SECRET'" @(
        (New-SeEdit ('    } elseif ($enrolledOwn) {' + $nl + '        # The record of the bay') ('    } elseif ($false) {' + $nl + '        # The record of the bay'))))
)
if (-not [string]::IsNullOrWhiteSpace($Only)) {
    $wantedIds = @($Only -split "," | ForEach-Object { $_.Trim() } | Where-Object { $_ })
    $mutants = @($mutants | Where-Object { $wantedIds -contains $_.Id })
    if ($mutants.Count -ne $wantedIds.Count) { throw "FILTER-MISMATCH: wanted $($wantedIds.Count), found $($mutants.Count)" }
}

function Get-SeOccurrenceCount([string]$Text, [string]$Needle) {
    $count = 0; $at = 0
    while ($true) { $i = $Text.IndexOf($Needle, $at, [StringComparison]::Ordinal); if ($i -lt 0) { break }; $count++; $at = $i + $Needle.Length }
    return $count
}
function New-SeMutantFile($Mutant) {
    $text = $original
    foreach ($e in @($Mutant.Edits)) {
        $n = Get-SeOccurrenceCount $text $e.From
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
function Invoke-SeSuite([string]$Id, [string]$SetupCopy) {
    # One run, read from the suite's own RESULT line.
    $log = Join-Path $OutDir ($Id + ".txt")
    & $HostExe -NoProfile -ExecutionPolicy Bypass -File $SuitePath -AgentScript $SetupCopy *> $log
    $o = [ordered]@{ status = "NOT RUN"; passed = -1; failed = -1; failures = @() }
    if (-not (Test-Path -LiteralPath $log)) { return $o }
    $lines = @(Get-Content -LiteralPath $log)
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
$controlDir = Join-Path $OutDir "mutants\C00"
New-Item -ItemType Directory -Force -Path $controlDir | Out-Null
$controlCopy = Join-Path $controlDir "BayAgent.ps1"
[IO.File]::WriteAllText($controlCopy, $original, (New-Object Text.UTF8Encoding($true)))
$co = Invoke-SeSuite -Id "C00" -SetupCopy $controlCopy
$controlLine = "C00 | CONTROL (unchanged script) | {0} | {1} passed, {2} failed" -f $(if ($co.status -eq "SURVIVED") { "PASSES" } else { $co.status }), $co.passed, $co.failed
[void]$summary.Add($controlLine); $controlLine
if ($co.status -ne "SURVIVED") {
    [void]$summary.Add("ABORTED: the control did not pass, so no mutant result would mean anything")
    [IO.File]::WriteAllLines((Join-Path $OutDir "mutants-summary.txt"), [string[]]$summary.ToArray())
    "ABORTED"; exit 3
}
$killed = 0; $survived = 0; $other = 0
foreach ($mu in $mutants) {
    $line = ""
    try {
        $copy = New-SeMutantFile $mu
        $o = Invoke-SeSuite -Id $mu.Id -SetupCopy $copy
        $line = "{0} | {1} | {2} | {3} passed, {4} failed" -f $mu.Id, $o.status, $mu.What, $o.passed, $o.failed
        if ($o.status -eq "KILLED") { $killed++; $line += (" | first: " + (@($o.failures | Select-Object -First 2) -join " || ")) }
        elseif ($o.status -eq "SURVIVED") { $survived++ } else { $other++ }
    } catch {
        $other++
        $line = ("{0} | NOT APPLIED | {1} | {2}" -f $mu.Id, $mu.What, $_.Exception.Message)
    }
    [void]$summary.Add($line); $line
}
$done = "ALL-DONE mutants={0} killed={1} survived={2} not-applied-or-not-run={3}" -f $mutants.Count, $killed, $survived, $other
[void]$summary.Add($done)
[IO.File]::WriteAllLines((Join-Path $OutDir "mutants-summary.txt"), [string[]]$summary.ToArray())
$done
if ($survived -gt 0 -or $other -gt 0) { exit 1 }
exit 0
