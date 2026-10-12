<#
Run-RecheckDay0Mutants.ps1 - the re-check verifier's run of planted changes for the enrollment's secret guard, through
the builder's mutation runner unchanged except for its list of changes (the runner's rules stay: a passing control
first, anchors that occur exactly once, kills read from the suite's RESULT line, the working tree never touched).

2026-10-12, confirmation of the fix head 10ebcbc4. One round: the builder's eight changes for this guard, copied from
its list word for word (H01 to H04, W3, W3b, W4, W5), and one of mine that its list does not hold:
  V2  the UNREADABLE refusal is not asked once something is on record (the builder's W5 skips the whole guard, and
      S2e plants only secrets that can be seen)
Hyphens only in comments.
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
# The builder's eight, taken from its own list by id, so the text run is the text it wrote.
$rmWanted = @("H01", "H02", "H03", "H04", "W3", "W3b", "W4", "W5")
$rmTaken = New-Object System.Collections.ArrayList
for ($rmI = $rmFrom + 1; $rmI -lt $rmTo; $rmI++) {
    $rmM = [regex]::Match($rmLines[$rmI], '^\s*\(New-D0Mutant "([A-Za-z0-9]+)" ')
    if ($rmM.Success -and ($rmWanted -contains $rmM.Groups[1].Value)) {
        # a mutant is its header line plus its edit lines, up to the line that closes it with ")))" (with or without a comma)
        $rmJ = $rmI
        while ($rmJ -lt $rmTo -and $rmLines[$rmJ] -notmatch '\)\)\),?\s*$') { $rmJ++ }
        for ($rmK = $rmI; $rmK -le $rmJ; $rmK++) { [void]$rmTaken.Add($rmLines[$rmK]) }
        $rmI = $rmJ
    }
}
$rmFound = @($rmTaken | ForEach-Object { $rmX = [regex]::Match($_, 'New-D0Mutant "([A-Za-z0-9]+)" '); if ($rmX.Success) { $rmX.Groups[1].Value } })
if ($rmFound.Count -ne $rmWanted.Count) { throw ("wanted {0} of the builder's mutants, found {1}: {2}" -f $rmWanted.Count, $rmFound.Count, ($rmFound -join ",")) }
$rmLast = $rmTaken.Count - 1
if ($rmTaken[$rmLast] -notmatch ',\s*$') { $rmTaken[$rmLast] = [string]$rmTaken[$rmLast] + "," }
$rmMine = @'
    (New-D0Mutant "V2" "the unreadable-place refusal is not asked once something is on record" @(
        (New-D0Edit '    if ($secretCheck.Unreadable) {' '    if ($secretCheck.Unreadable -and -not $stateTp) {')))
)

'@
$rmOut = New-Object System.Collections.ArrayList
for ($rmI = 0; $rmI -le $rmFrom; $rmI++) { [void]$rmOut.Add($rmLines[$rmI]) }
foreach ($rmL in $rmTaken) { [void]$rmOut.Add($rmL) }
foreach ($rmL in ($rmMine -split "`r?`n")) { [void]$rmOut.Add($rmL) }
for ($rmI = $rmTo; $rmI -lt $rmLines.Count; $rmI++) { [void]$rmOut.Add($rmLines[$rmI]) }
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
$rmRunner = Join-Path $OutDir "runner-with-recheck-list.ps1"
[IO.File]::WriteAllLines($rmRunner, [string[]]$rmOut.ToArray(), (New-Object Text.UTF8Encoding($true)))
$rmTk = $null; $rmEr = $null
[void][System.Management.Automation.Language.Parser]::ParseFile($rmRunner, [ref]$rmTk, [ref]$rmEr)
if (@($rmEr).Count -gt 0) { throw ("the assembled runner does not parse: {0}" -f $rmEr[0].Message) }
& (Join-Path $env:WINDIR "System32\WindowsPowerShell\v1.0\powershell.exe") -NoProfile -ExecutionPolicy Bypass -File $rmRunner -RepoRoot $rmRepo -OutDir $OutDir -Parallel $Parallel
exit $LASTEXITCODE
