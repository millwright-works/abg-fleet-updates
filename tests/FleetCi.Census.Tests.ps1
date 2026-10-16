<#
FleetCi.Census.Tests.ps1

WHY THIS EXISTS (DEV-02, OPS-16)
  The fleet repository had no CI, so a red suite could ship. .github/workflows/fleet-tests.yml now runs every non-Live
  suite on a Windows runner. This suite is the census that keeps that workflow honest. It fails when:
    C1  a non-Live tests\*.Tests.ps1 is neither run by the workflow nor on its explicit, commented exclusion list
    C2  a Live suite is run, or the live-check switch appears anywhere in the workflow
    C3  the workflow has continue-on-error, an or-true tail, a secret, write permission, or pwsh instead of powershell
    C4  the workflow names a suite that does not exist
    C5  any tracked or untracked-but-not-ignored file holds the Dev vault prefix or a literal vault host name (the
        repository is public; a "{0}.vault.azure.net" format string is allowed)
  It also runs tools\ci\Run-FleetSuites.ps1 against a tiny fake repository: a failing suite, an incomplete list and a
  Live suite in the list must each turn it non-zero (T6, local equivalent of a red run).
  Each rule is a function that takes text or a root, so the tests below feed it planted mistakes and see them caught.

RUN (from the repo root)
  powershell -NoProfile -ExecutionPolicy Bypass -File tests\FleetCi.Census.Tests.ps1

Exit code 0 = all assertions passed. Hyphens only in comments.
#>
[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$WorkflowPath = Join-Path $RepoRoot ".github/workflows/fleet-tests.yml"
$RunnerPath = Join-Path $RepoRoot "tools/ci/Run-FleetSuites.ps1"

$script:Pass = 0; $script:Fail = 0; $script:Failures = @()
function Assert-True([bool]$cond, [string]$msg) {
    if ($cond) { $script:Pass++; Write-Host "  PASS  $msg" }
    else { $script:Fail++; $script:Failures += $msg; Write-Host "  FAIL  $msg" -ForegroundColor Red }
}
function Section([string]$name) { Write-Host ""; Write-Host "== $name" -ForegroundColor Cyan }

# Names between two marker lines, one quoted '*.Tests.ps1' per line. A line that is only a comment contributes nothing.
function Get-FleetListed([string]$Text, [string]$Begin, [string]$End) {
    $inside = $false; $out = @()
    foreach ($line in ($Text -split "`r?`n")) {
        if ($line -match ('^\s*#\s*' + $Begin + '\s*$')) { $inside = $true; continue }
        if ($line -match ('^\s*#\s*' + $End + '\s*$')) { $inside = $false; continue }
        if ($inside -and $line -notmatch '^\s*#') {
            foreach ($m in [regex]::Matches($line, "'([^']+)'")) {
                $out += [pscustomobject]@{ Name = $m.Groups[1].Value; HasReason = ($line -match "'\s*#\s*\S") }
            }
        }
    }
    return $out
}

# Returns a list of problem strings; empty means the workflow text is acceptable for this tests directory.
function Get-FleetWorkflowProblems([string]$Text, [string]$TestsDir) {
    $problems = @()
    $disk = @(Get-ChildItem -LiteralPath $TestsDir -Filter '*.Tests.ps1' | ForEach-Object { $_.Name })
    $diskNonLive = @($disk | Where-Object { $_ -notlike '*.Live.*' })
    $run = @(Get-FleetListed $Text 'SUITES-BEGIN' 'SUITES-END')
    $excl = @(Get-FleetListed $Text 'EXCLUDED-BEGIN' 'EXCLUDED-END')
    $runNames = @($run | ForEach-Object { $_.Name })
    $exclNames = @($excl | ForEach-Object { $_.Name })
    foreach ($d in $diskNonLive) {
        if (($runNames -notcontains $d) -and ($exclNames -notcontains $d)) { $problems += "suite not run by the workflow and not excluded: $d" }
    }
    foreach ($n in ($runNames + $exclNames)) {
        if ($n -like '*.Live.*') { $problems += "Live suite named in the workflow: $n" }
        elseif ($disk -notcontains $n) { $problems += "workflow names a suite that does not exist: $n" }
    }
    foreach ($e in $excl) { if (-not $e.HasReason) { $problems += "excluded suite has no reason after a hash sign: $($e.Name)" } }
    foreach ($n in $runNames) { if ($exclNames -contains $n) { $problems += "suite is both run and excluded: $n" } }
    if (@($run).Count -eq 0) { $problems += "the workflow lists no suites between the SUITES markers" }
    $noComment = @(($Text -split "`r?`n") | Where-Object { $_ -notmatch '^\s*#' })
    $code = $noComment -join "`n"
    if ($Text -match '(?i)(?<![A-Za-z0-9])-Live\b') { $problems += "the live-check switch appears in the workflow" }
    if ($code -match '\.Live\.') { $problems += "a .Live. file name appears in a non-comment workflow line" }
    if ($code -match '(?i)continue-on-error') { $problems += "continue-on-error appears in the workflow" }
    if ($code -match '\|\|\s*true\b') { $problems += "an or-true tail appears in the workflow" }
    if ($code -match '(?i)secrets\.') { $problems += "the workflow reads a secret" }
    if ($code -match '(?i)shell:\s*pwsh') { $problems += "a step runs under pwsh; the suites must run under Windows PowerShell 5.1" }
    if ($code -notmatch '(?m)^\s*shell:\s*powershell\s*$') { $problems += "no step runs under shell: powershell (5.1)" }
    if ($code -notmatch '(?m)^\s*runs-on:\s*windows-') { $problems += "the job does not run on a Windows runner" }
    if ($code -notmatch '(?m)^\s*contents:\s*read\s*$') { $problems += "permissions contents: read is missing" }
    if ($code -match '(?im)^\s*(contents|actions|packages|pull-requests|id-token|issues):\s*write') { $problems += "the workflow grants a write permission" }
    if ($code -notmatch 'Run-FleetSuites\.ps1') { $problems += "the workflow does not call tools/ci/Run-FleetSuites.ps1" }
    return $problems
}

# Files that must not carry the Dev vault prefix or a literal vault host. The patterns are built from pieces so this
# file does not match itself.
$script:VaultPrefix = 'kv-' + 'aoc-'
$script:VaultHostRx = '[A-Za-z0-9][A-Za-z0-9-]*\.vault' + '\.azure\.net'
function Get-FleetVaultLeaks([string]$Root) {
    $leaks = @()
    $eapKeep = $ErrorActionPreference; $ErrorActionPreference = 'Continue'
    $list = @(& git -C $Root ls-files --cached --others --exclude-standard 2>$null)
    $gitCode = $LASTEXITCODE
    $ErrorActionPreference = $eapKeep
    if ($gitCode -ne 0 -or $list.Count -eq 0) { throw "git ls-files failed or listed nothing under $Root" }
    foreach ($rel in $list) {
        $p = Join-Path $Root $rel
        if (-not (Test-Path -LiteralPath $p -PathType Leaf)) { continue }
        # Shared read: a file another process is still writing (the runner's own log of this suite) must not abort the scan.
        $fs = New-Object IO.FileStream($p, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::ReadWrite)
        try { $ms = New-Object IO.MemoryStream; $fs.CopyTo($ms); $bytes = $ms.ToArray() } finally { $fs.Dispose() }
        $text = [Text.Encoding]::GetEncoding(28591).GetString($bytes)
        if ($text.IndexOf($script:VaultPrefix, [StringComparison]::OrdinalIgnoreCase) -ge 0 -or [regex]::IsMatch($text, $script:VaultHostRx, 'IgnoreCase')) { $leaks += $rel }
    }
    return $leaks
}

$tmp = Join-Path ([IO.Path]::GetTempPath()) ("fleetci-census-" + [Guid]::NewGuid().ToString("N"))
$null = New-Item -ItemType Directory -Path $tmp
try {
    $wf = [IO.File]::ReadAllText($WorkflowPath)
    $testsDir = Join-Path $RepoRoot "tests"

    Section "C1-C4 the real workflow"
    Assert-True (Test-Path -LiteralPath $WorkflowPath -PathType Leaf) "the workflow file exists at .github/workflows/fleet-tests.yml"
    Assert-True (Test-Path -LiteralPath $RunnerPath -PathType Leaf) "the runner exists at tools/ci/Run-FleetSuites.ps1"
    $real = @(Get-FleetWorkflowProblems $wf $testsDir)
    Assert-True ($real.Count -eq 0) ("the real workflow has no census problem" + $(if ($real.Count) { ": " + ($real -join " | ") } else { "" }))
    $diskNonLive = @(Get-ChildItem -LiteralPath $testsDir -Filter '*.Tests.ps1' | Where-Object { $_.Name -notlike '*.Live.*' })
    $listed = @(Get-FleetListed $wf 'SUITES-BEGIN' 'SUITES-END')
    Assert-True ($diskNonLive.Count -ge 20) ("the census sees the non-Live suites on disk (count $($diskNonLive.Count))")
    Assert-True ($listed.Count + @(Get-FleetListed $wf 'EXCLUDED-BEGIN' 'EXCLUDED-END').Count -eq $diskNonLive.Count) "listed plus excluded equals the non-Live suites on disk, no more and no fewer"
    Assert-True ($wf -match 'actions/checkout@' -and $wf -match 'upload-artifact@') "the workflow checks out and uploads the logs as an artifact"

    Section "T2 one suite removed from the workflow's set"
    $victim = $listed[3].Name
    $removed = ($wf -split "`r?`n" | Where-Object { $_ -notmatch ("'" + [regex]::Escape($victim) + "'") }) -join "`n"
    $p = @(Get-FleetWorkflowProblems $removed $testsDir)
    Assert-True (@($p | Where-Object { $_ -like "*$victim*" }).Count -eq 1) "removing $victim fails the census and names it"
    Assert-True ($removed -ne $wf) "(the removal changed the text)"

    Section "T3 the live-check switch, a Live suite, continue-on-error, or-true"
    $m3 = $wf.Replace("-LogDir fleet-test-logs", "-LogDir fleet-test-logs -Live")
    Assert-True ($m3 -ne $wf -and @(Get-FleetWorkflowProblems $m3 $testsDir | Where-Object { $_ -like '*live-check switch*' }).Count -eq 1) "adding the live-check switch fails"
    $m4 = $wf.Replace("'FleetCi.Census.Tests.ps1'", "'FleetCi.Census.Tests.ps1'`n            'BayAgent.KioskShell.Live.Tests.ps1'")
    Assert-True ($m4 -ne $wf -and @(Get-FleetWorkflowProblems $m4 $testsDir | Where-Object { $_ -like '*Live suite named*' }).Count -ge 1) "listing a Live suite fails"
    $m5 = $wf.Replace("shell: powershell", "shell: powershell`n        continue-on-error: true")
    Assert-True ($m5 -ne $wf -and @(Get-FleetWorkflowProblems $m5 $testsDir | Where-Object { $_ -like '*continue-on-error*' }).Count -eq 1) "continue-on-error fails"
    $m6 = $wf.Replace("exit 0`n", "exit 0 || true`n")
    if ($m6 -eq $wf) { $m6 = $wf.Replace("exit 0`r`n", "exit 0 || true`r`n") }
    Assert-True ($m6 -ne $wf -and @(Get-FleetWorkflowProblems $m6 $testsDir | Where-Object { $_ -like '*or-true*' }).Count -eq 1) "an or-true tail fails"
    $m7 = $wf.Replace("shell: powershell", "shell: pwsh")
    Assert-True ($m7 -ne $wf -and @(Get-FleetWorkflowProblems $m7 $testsDir | Where-Object { $_ -like '*pwsh*' }).Count -ge 1) "running under pwsh fails"
    $m8 = $wf.Replace("contents: read", "contents: write")
    Assert-True ($m8 -ne $wf -and @(Get-FleetWorkflowProblems $m8 $testsDir).Count -ge 1) "a write permission fails"
    $m9 = $wf.Replace("  EXCLUDED-END", "  EXCLUDED-END").Replace("$" + "excluded = @(", "$" + "excluded = @(`n            'BayAgent.Kiosk.Tests.ps1'")
    Assert-True ($m9 -ne $wf -and @(Get-FleetWorkflowProblems $m9 $testsDir | Where-Object { $_ -like '*no reason*' -or $_ -like '*both run and excluded*' }).Count -ge 1) "an excluded suite without a reason (or run and excluded) fails"
    $m10 = $wf.Replace("'FleetCi.Census.Tests.ps1'", "'FleetCi.Census.Tests.ps1'`n            'Not.There.Tests.ps1'")
    Assert-True ($m10 -ne $wf -and @(Get-FleetWorkflowProblems $m10 $testsDir | Where-Object { $_ -like '*does not exist*' }).Count -eq 1) "a suite named but missing on disk fails"

    Section "C5 / T5e vault name census"
    $realLeaks = @(Get-FleetVaultLeaks $RepoRoot)
    Assert-True ($realLeaks.Count -eq 0) ("no tracked or unignored file holds a vault name" + $(if ($realLeaks.Count) { ": " + ($realLeaks -join ", ") } else { "" }))
    Assert-True (@([IO.File]::ReadAllLines((Join-Path $RepoRoot ".gitignore")) | Where-Object { $_.Trim() -eq 'fleet-test-logs/' }).Count -eq 1) "the runner's log folder is git-ignored (the scan must not read logs it is still writing)"
    $gitRepo = Join-Path $tmp "gitrepo"
    $null = New-Item -ItemType Directory -Path (Join-Path $gitRepo "tools")
    $ErrorActionPreference = 'Continue'
    $null = & git -C $gitRepo init -q 2>&1
    $ErrorActionPreference = 'Stop'
    [IO.File]::WriteAllText((Join-Path $gitRepo "tools/clean.ps1"), ('$u = "https://{0}.vault.azure.net/secrets/{1}" -f $v, $s' + "`n"))
    Assert-True (@(Get-FleetVaultLeaks $gitRepo).Count -eq 0) "a {0}.vault.azure.net format string is allowed"
    [IO.File]::WriteAllText((Join-Path $gitRepo "tools/planted.ps1"), ('$v = "' + 'kv-' + 'aoc-test"' + "`n"))
    $l1 = @(Get-FleetVaultLeaks $gitRepo)
    Assert-True ($l1.Count -eq 1 -and $l1[0] -like '*planted.ps1') "the Dev vault prefix planted in a scratch file under tools/ fails and names the file"
    Remove-Item -LiteralPath (Join-Path $gitRepo "tools/planted.ps1") -Force
    [IO.File]::WriteAllText((Join-Path $gitRepo "tools/host.ps1"), ('$h = "myvault' + '.vault.azure' + '.net"' + "`n"))
    $ErrorActionPreference = 'Continue'
    $null = & git -C $gitRepo add tools/host.ps1 2>&1
    $ErrorActionPreference = 'Stop'
    $l2 = @(Get-FleetVaultLeaks $gitRepo)
    Assert-True ($l2.Count -eq 1 -and $l2[0] -like '*host.ps1') "a literal vault host in a TRACKED file fails and names the file"

    Section "T6 the runner turns red (local equivalent of a red workflow run)"
    $fake = Join-Path $tmp "fakerepo"
    $null = New-Item -ItemType Directory -Path (Join-Path $fake "tests")
    [IO.File]::WriteAllText((Join-Path $fake "tests/A.Pass.Tests.ps1"), "Write-Host 'RESULT: 1 passed, 0 failed'; exit 0`r`n")
    [IO.File]::WriteAllText((Join-Path $fake "tests/B.Broken.Tests.ps1"), "Write-Host 'RESULT: 0 passed, 1 failed'; exit 1`r`n")
    [IO.File]::WriteAllText((Join-Path $fake "tests/C.Probe.Live.Tests.ps1"), "exit 0`r`n")
    $logs = Join-Path $tmp "logs"
    function Invoke-Runner([string[]]$Suites, [string[]]$Excluded) {
        $argsRun = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $RunnerPath, '-Root', $fake, '-LogDir', $logs, '-Suites', ($Suites -join ','))
        if ($Excluded.Count -gt 0) { $argsRun += @('-Excluded', ($Excluded -join ',')) }
        $null = & powershell @argsRun *>&1
        return [int]$LASTEXITCODE
    }
    Assert-True ((Invoke-Runner @('A.Pass.Tests.ps1') @('B.Broken.Tests.ps1')) -eq 0) "a passing suite with the broken one explicitly excluded exits 0"
    Assert-True ((Invoke-Runner @('A.Pass.Tests.ps1', 'B.Broken.Tests.ps1') @()) -eq 1) "a deliberately broken assertion in one suite makes the runner exit 1"
    Assert-True ((Invoke-Runner @('A.Pass.Tests.ps1') @()) -eq 2) "a list that leaves a non-Live suite out (not excluded) exits 2, fewer suites than the census expects"
    Assert-True ((Invoke-Runner @('A.Pass.Tests.ps1', 'B.Broken.Tests.ps1', 'C.Probe.Live.Tests.ps1') @()) -eq 2) "a Live suite in the list exits 2"
    Assert-True (Test-Path -LiteralPath (Join-Path $logs "B.Broken.Tests.ps1.log")) "each suite's output is recorded in a log file"
}
finally {
    if ($tmp -like (Join-Path ([IO.Path]::GetTempPath()) "fleetci-census-*")) { try { Remove-Item -LiteralPath $tmp -Recurse -Force -ErrorAction SilentlyContinue } catch {} }
}

Write-Host ""
Write-Host ("RESULT: {0} passed, {1} failed" -f $script:Pass, $script:Fail) -ForegroundColor $(if ($script:Fail -eq 0) { "Green" } else { "Red" })
if ($script:Fail -gt 0) { $script:Failures | ForEach-Object { Write-Host "  - $_" -ForegroundColor Red }; exit 1 }
exit 0
