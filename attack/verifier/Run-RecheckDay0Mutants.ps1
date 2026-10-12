<#
Run-RecheckDay0Mutants.ps1 - the re-check verifier's own planted changes for the enrollment's secret guard (3541f9e),
run through the builder's mutation runner unchanged except for its list of changes (the runner's rules stay: a passing
control first, anchors that occur exactly once, kills read from the suite's RESULT line, the working tree never
touched). Hyphens only in comments.
#>
param([Parameter(Mandatory = $true)][string]$OutDir, [int]$Parallel = 3)
$ErrorActionPreference = "Stop"
$rmRepo = "C:\aoc-wt\ba161-recheck"
$rmLines = [IO.File]::ReadAllLines((Join-Path $rmRepo "attack\Run-Day0EnrollMutations.ps1"))
$rmFrom = -1; $rmTo = -1
for ($rmI = 0; $rmI -lt $rmLines.Count; $rmI++) {
    if ($rmFrom -lt 0 -and $rmLines[$rmI] -eq '$mutants = @(') { $rmFrom = $rmI }
    if ($rmTo -lt 0 -and $rmLines[$rmI] -eq 'if (-not [string]::IsNullOrWhiteSpace($Only)) {') { $rmTo = $rmI }
}
if ($rmFrom -lt 0 -or $rmTo -le $rmFrom) { throw "could not find the mutant list in the builder's runner" }
$rmMine = @'
$mutants = @(
    (New-D0Mutant "W3" "-EnrollForce passes the secret guard: a PC that holds a secret is enrolled when force is added" @(
        (New-D0Edit '    if ($secretOnPc) {' '    if ($secretOnPc -and -not $force) {'))),
    (New-D0Mutant "W4" "the standard place is read only when the configuration names no secret path (a sealed file there, beside a configuration that names another path, is not seen)" @(
        (New-D0Edit '        if (Test-Path -LiteralPath $standardPlace -PathType Leaf) {' '        if ((-not $script:SecretPathCfg) -and (Test-Path -LiteralPath $standardPlace -PathType Leaf)) {'))),
    (New-D0Mutant "W5" "the secret guard is asked only of a bay with nothing on record: a secret that arrives after the enrollment is not refused at the second run" @(
        (New-D0Edit '    if ($secretOnPc) {' '    if ($secretOnPc -and -not $stateTp) {')))
)

'@
$rmOut = New-Object System.Collections.ArrayList
for ($rmI = 0; $rmI -lt $rmFrom; $rmI++) { [void]$rmOut.Add($rmLines[$rmI]) }
foreach ($rmL in ($rmMine -split "`r?`n")) { [void]$rmOut.Add($rmL) }
for ($rmI = $rmTo; $rmI -lt $rmLines.Count; $rmI++) { [void]$rmOut.Add($rmLines[$rmI]) }
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
$rmRunner = Join-Path $OutDir "runner-with-recheck-list.ps1"
[IO.File]::WriteAllLines($rmRunner, [string[]]$rmOut.ToArray(), (New-Object Text.UTF8Encoding($true)))
& (Join-Path $env:WINDIR "System32\WindowsPowerShell\v1.0\powershell.exe") -NoProfile -ExecutionPolicy Bypass -File $rmRunner -RepoRoot $rmRepo -OutDir $OutDir -Parallel $Parallel
exit $LASTEXITCODE
