<#
Run-SetupEnrollMutations.ps1

Plants one change at a time in the REAL TEXT of src\BayAgent\tools\Setup-BayPC.ps1 (the part that prints and uses the
bay's own app id, -BayAppId, for release 1.6.1) and runs tests\BayAgent.SetupRun.Tests.ps1 against each changed copy.
A change the suite does not notice is a SURVIVOR.

Same rules as Run-Day0EnrollMutations.ps1: a control (the unchanged script) must pass first; each anchor must occur
exactly once, the copy must differ and must parse, or the change is NOT APPLIED (never a kill); a kill is read from the
suite's own RESULT line; a run with no RESULT line is NOT RUN; the working tree is never touched.

Run:  powershell -NoProfile -ExecutionPolicy Bypass -File attack\Run-SetupEnrollMutations.ps1 -OutDir C:\some\scratch\folder
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
$SetupPath = Join-Path $RepoRoot "src\BayAgent\tools\Setup-BayPC.ps1"
$SuitePath = Join-Path $RepoRoot "tests\BayAgent.SetupRun.Tests.ps1"
$HostExe = Join-Path $env:WINDIR "System32\WindowsPowerShell\v1.0\powershell.exe"
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
$original = [IO.File]::ReadAllText($SetupPath)

function New-SeMutant([string]$Id, [string]$What, [object[]]$Edits) { return [pscustomobject]@{ Id = $Id; What = $What; Edits = $Edits } }
function New-SeEdit([string]$From, [string]$To) { return [pscustomobject]@{ From = $From; To = $To } }

$mutants = @(
    (New-SeMutant "E01" "Phase 6 prints the plain 1.6.0 enroll line again (gate G1)" @(
        (New-SeEdit '        "  powershell.exe -NoProfile -ExecutionPolicy Bypass -File `"$Root\BayAgent\current\BayAgent.ps1`" -EnrollCert -EnrollClientId $EnrollAppId",' '        "  powershell.exe -NoProfile -ExecutionPolicy Bypass -File `"$Root\BayAgent\current\BayAgent.ps1`" -EnrollCert",'))),
    (New-SeMutant "E02" "Next Steps prints the plain 1.6.0 enroll line again (gate G1)" @(
        (New-SeEdit '      "     powershell.exe -NoProfile -ExecutionPolicy Bypass -File `"$Root\BayAgent\current\BayAgent.ps1`" -EnrollCert -EnrollClientId $EnrollAppId",' '      "     powershell.exe -NoProfile -ExecutionPolicy Bypass -File `"$Root\BayAgent\current\BayAgent.ps1`" -EnrollCert",'))),
    (New-SeMutant "E03" "-BayAppId counts whether or not it was typed" @(
        (New-SeEdit '$bayAppPlan = Get-BayAppIdPlan -Given $PSBoundParameters.ContainsKey("BayAppId") -Value $BayAppId' '$bayAppPlan = Get-BayAppIdPlan -Given $true -Value $BayAppId'))),
    (New-SeMutant "E04" "a built-in default becomes every bay's own app (an inert default turned into a write)" @(
        (New-SeEdit '  [string]$BayAppId = ""' '  [string]$BayAppId = "0e77dbf6-499d-434c-acfc-b276bc439c38"'),
        (New-SeEdit '$bayAppPlan = Get-BayAppIdPlan -Given $PSBoundParameters.ContainsKey("BayAppId") -Value $BayAppId' '$bayAppPlan = Get-BayAppIdPlan -Given (-not [string]::IsNullOrWhiteSpace($BayAppId)) -Value $BayAppId'))),
    (New-SeMutant "E05" "the typed -ClientId is overwritten by -BayAppId" @(
        (New-SeEdit '  if (-not $ClientIdGiven) {' '  if ($true) {'),
        (New-SeEdit '  if ($PSBoundParameters.ContainsKey("ClientId") -and -not [string]::IsNullOrWhiteSpace($ClientId))             { $day0Args["ConfigClientId"] = $ClientId }' '  if ($false)             { $day0Args["ConfigClientId"] = $ClientId }'))),
    (New-SeMutant "E06" "a -BayAppId that is not one does not stop the run" @(
        (New-SeEdit 'if (-not $bayAppPlan.ok) {' 'if ($false) {'))),
    (New-SeMutant "E07" "-BayAppId is accepted on a bay set up for the shared secret" @(
        (New-SeEdit '  if ($Mode -ne "Certificate") {' '  if ($false) {'))),
    (New-SeMutant "E08" "the enroll line names the -ClientId value (the vendor's default when none was typed)" @(
        (New-SeEdit '  -EnrollAppId ([string]$bayAppPlan.enrollId) -Note ([string]$bayAppPlan.note)' '  -EnrollAppId $ClientId -Note ([string]$bayAppPlan.note)'))),
    (New-SeMutant "E09" "Next Steps' enroll line names the -ClientId value" @(
        (New-SeEdit '-BayKioskUser $BayKioskUser -EnrollAppId ([string]$bayAppPlan.enrollId)' '-BayKioskUser $BayKioskUser -EnrollAppId $ClientId'))),
    (New-SeMutant "E10" "the refusal echoes what was typed" @(
        (New-SeEdit 'What was typed is {0} characters long and is not one. Nothing was changed on this PC." -f ([string]$Value).Length)' 'What was typed is {0} and is not one. Nothing was changed on this PC." -f ([string]$Value))'))),
    (New-SeMutant "E11" "the enroll line shows the id as typed, not in its one written form" @(
        (New-SeEdit '  $plan.enrollId = $plan.appId' '  $plan.enrollId = $Value'))),
    (New-SeMutant "E12" "the bay's own app does not reach agent-config.json" @(
        (New-SeEdit '  if (-not [string]::IsNullOrWhiteSpace([string]$bayAppPlan.configClientId)) { $day0Args["ConfigClientId"] = [string]$bayAppPlan.configClientId }' '  if ($false) { $day0Args["ConfigClientId"] = [string]$bayAppPlan.configClientId }'))),
    (New-SeMutant "E13" "the note that -ClientId is not the bay's own app is never shown" @(
        (New-SeEdit '      ) + $(if ([string]::IsNullOrWhiteSpace($Note)) { @() } else { @("", ("NOTE: " + $Note)) })' '      )'))),
    (New-SeMutant "E14" "the all-zero id is accepted as a bay's own app" @(
        (New-SeEdit ' -or $g -eq [guid]::Empty) {' ') {'))),
    (New-SeMutant "E15" "the screen no longer says that a missing RESULT line means the wrong agent" @(
        (New-SeEdit "NO 'RESULT:' LINE AT ALL means the agent" "A missing line may mean the agent"))),
    (New-SeMutant "E16" "the secret-file warning speaks 1.6.0's language again" @(
        (New-SeEdit '    Write-Host "  the secret, and the enrollment refuses a PC that holds one: find out how it got here." -ForegroundColor Red' '    Write-Host "  running -EnrollCert, or the certificate will enroll as PENDING and cannot activate." -ForegroundColor Red')))
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
    $path = Join-Path $dir "Setup-BayPC.ps1"
    [IO.File]::WriteAllText($path, $text, (New-Object Text.UTF8Encoding($false)))
    $tk = $null; $er = $null
    [void][System.Management.Automation.Language.Parser]::ParseFile($path, [ref]$tk, [ref]$er)
    if (@($er).Count -gt 0) { throw ("the copy does not parse: {0}" -f $er[0].Message) }
    return $path
}
function Invoke-SeSuite([string]$Id, [string]$SetupCopy) {
    # One run, read from the suite's own RESULT line.
    $log = Join-Path $OutDir ($Id + ".txt")
    & $HostExe -NoProfile -ExecutionPolicy Bypass -File $SuitePath -SetupScript $SetupCopy *> $log
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
$controlCopy = Join-Path $controlDir "Setup-BayPC.ps1"
[IO.File]::WriteAllText($controlCopy, $original, (New-Object Text.UTF8Encoding($false)))
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
