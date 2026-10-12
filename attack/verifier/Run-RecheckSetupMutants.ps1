<#
Run-RecheckSetupMutants.ps1 - the re-check verifier's own planted changes for Setup-BayPC.ps1's -BayAppId (a85b742),
run through the builder's setup mutation runner unchanged except for its list of changes (its rules stay: a passing
control first, anchors that occur exactly once, kills read from the suite's RESULT line, the working tree never
touched). Hyphens only in comments.
#>
param([Parameter(Mandatory = $true)][string]$OutDir)
$ErrorActionPreference = "Stop"
$rsRepo = "C:\aoc-wt\ba161-recheck"
$rsLines = [IO.File]::ReadAllLines((Join-Path $rsRepo "attack\Run-SetupEnrollMutations.ps1"))
$rsFrom = -1; $rsTo = -1
for ($rsI = 0; $rsI -lt $rsLines.Count; $rsI++) {
    if ($rsFrom -lt 0 -and $rsLines[$rsI] -eq '$mutants = @(') { $rsFrom = $rsI }
    if ($rsTo -lt 0 -and $rsLines[$rsI] -eq 'if (-not [string]::IsNullOrWhiteSpace($Only)) {') { $rsTo = $rsI }
}
if ($rsFrom -lt 0 -or $rsTo -le $rsFrom) { throw "could not find the mutant list in the builder's runner" }
$rsMine = @'
$rsNl = "`r`n"
$mutants = @(
    (New-SeMutant "X1" "Next Steps prints the words to replace even when the bay's own app id was typed" @(
        (New-SeEdit '-BayKioskUser $BayKioskUser -EnrollAppId ([string]$bayAppPlan.enrollId)' '-BayKioskUser $BayKioskUser'))),
    (New-SeMutant "X2" "Phase 6 prints the words to replace even when the bay's own app id was typed" @(
        (New-SeEdit '  -EnrollAppId ([string]$bayAppPlan.enrollId) -Note ([string]$bayAppPlan.note)' '  -Note ([string]$bayAppPlan.note)'))),
    (New-SeMutant "X3" "a -BayAppId that is not one stops the run only AFTER the kiosk account and the automatic sign-in are made" @(
        (New-SeEdit ('if (-not $bayAppPlan.ok) {' + $rsNl + '  Write-Error $bayAppPlan.error' + $rsNl + '  exit 1' + $rsNl + '}') '$null = $bayAppPlan'),
        (New-SeEdit ('if (-not $SkipDay0) {' + $rsNl + '  Write-Step "Phase 3: Running ABG-Day0-Setup.ps1"') ('if (-not $bayAppPlan.ok) { Write-Error $bayAppPlan.error; exit 1 }' + $rsNl + 'if (-not $SkipDay0) {' + $rsNl + '  Write-Step "Phase 3: Running ABG-Day0-Setup.ps1"'))))
)

'@
$rsOut = New-Object System.Collections.ArrayList
for ($rsI = 0; $rsI -lt $rsFrom; $rsI++) { [void]$rsOut.Add($rsLines[$rsI]) }
foreach ($rsL in ($rsMine -split "`r?`n")) { [void]$rsOut.Add($rsL) }
for ($rsI = $rsTo; $rsI -lt $rsLines.Count; $rsI++) { [void]$rsOut.Add($rsLines[$rsI]) }
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
$rsRunner = Join-Path $OutDir "runner-with-recheck-list.ps1"
[IO.File]::WriteAllLines($rsRunner, [string[]]$rsOut.ToArray(), (New-Object Text.UTF8Encoding($true)))
& (Join-Path $env:WINDIR "System32\WindowsPowerShell\v1.0\powershell.exe") -NoProfile -ExecutionPolicy Bypass -File $rsRunner -RepoRoot $rsRepo -OutDir $OutDir
exit $LASTEXITCODE
