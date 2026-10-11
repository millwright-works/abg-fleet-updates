#Requires -Version 5.1
# Kiosk round 2 FIX re-verdict (2026-10-10). Mutation runner: the builder's (and the predecessor's) runner with two changes:
# every mutant's full log is KEPT in the output folder, and the tail of a run that printed no RESULT line is recorded.
# Mutants are applied to COPIES of the agent (never the worktree); the suite given runs against the copy.
# Hyphens only in comments.
param([string]$Tree, [string]$Specs, [string]$OutDir, [string]$Only = "", [string]$Lane = "a", [string]$Suite = "")
$ErrorActionPreference = "Stop"
$agentSrc = Join-Path $Tree "src\BayAgent\BayAgent.ps1"
$shellSrc = Join-Path $Tree "src\BayAgent\kiosk\ABG.KioskShell.ps1"
if ([string]::IsNullOrWhiteSpace($Suite)) { $Suite = Join-Path $Tree "tests\BayAgent.Kiosk.Tests.ps1" }
$work = Join-Path $env:TEMP ("kfr-mut-" + $Lane + "-" + [guid]::NewGuid().ToString("N").Substring(0, 8))
New-Item -ItemType Directory -Force -Path $work | Out-Null
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
$agentText = [IO.File]::ReadAllText($agentSrc)
$enc = New-Object Text.UTF8Encoding($true)
$specList = & $Specs
$lines = @()
function Get-Occ([string]$text, [string]$find) { $n = 0; $i = 0; while (($i = $text.IndexOf($find, $i, [StringComparison]::Ordinal)) -ge 0) { $n++; $i += $find.Length }; return $n }
foreach ($m in $specList) {
    if ($Only -and ($Only -split ",") -notcontains $m.Id) { continue }
    $a = $agentText; $bad = ""
    foreach ($st in $m.Steps) {
        $occ = Get-Occ $a $st.Find
        if ($occ -ne 1) { $bad = "anchor found $occ times: " + $st.Find; break }
        $idx = $a.IndexOf($st.Find, [StringComparison]::Ordinal)
        $t2 = $a.Substring(0, $idx) + $st.Replace + $a.Substring($idx + $st.Find.Length)
        if ($t2 -ceq $a) { $bad = "replacement changed nothing"; break }
        if ($t2.IndexOf($st.Replace, [StringComparison]::Ordinal) -lt 0) { $bad = "marker missing"; break }
        $a = $t2
    }
    if ($bad) { $line = "{0} | NOT-APPLIED | {1}" -f $m.Id, $bad; $lines += $line; Write-Host $line; continue }
    $md = Join-Path $work $m.Id; New-Item -ItemType Directory -Force -Path $md | Out-Null
    $ma = Join-Path $md "BayAgent.ps1"
    [IO.File]::WriteAllText($ma, $a, $enc)
    # the suite's real-loop test looks for the manifest beside the agent it was given
    Copy-Item -LiteralPath (Join-Path $Tree "src\BayAgent\manifest.json") -Destination (Join-Path $md "manifest.json") -Force
    $tok = $null; $perr = $null
    [void][System.Management.Automation.Language.Parser]::ParseFile($ma, [ref]$tok, [ref]$perr)
    if (@($perr).Count -gt 0) { $line = "{0} | ERROR | mutant does not parse" -f $m.Id; $lines += $line; Write-Host $line; continue }
    $log = Join-Path $OutDir ($m.Id + ".log")
    $ErrorActionPreference = "Continue"
    & "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -ExecutionPolicy Bypass -File $Suite -AgentScript $ma -ShellScript $shellSrc *> $log
    $code = $LASTEXITCODE
    $ErrorActionPreference = "Stop"
    $all = @(Get-Content -LiteralPath $log)
    $res = @($all | Where-Object { $_ -match '^RESULT: (\d+) passed, (\d+) failed' })
    $fails = @($all | Where-Object { $_ -match '^\s+FAIL\s' })
    if ($res.Count -eq 0) {
        $tail = (@($all | Where-Object { $_.Trim().Length -gt 0 } | Select-Object -Last 4) -join " || ")
        $line = "{0} | ERROR | exit {1}, no RESULT line, {2} FAIL lines before it stopped | {3} | tail: {4}" -f $m.Id, $code, $fails.Count, $m.Why, $tail
    } else {
        [void]($res[-1] -match '^RESULT: (\d+) passed, (\d+) failed')
        $p = [int]$Matches[1]; $f = [int]$Matches[2]
        $verdict = $(if ($f -gt 0) { "KILLED" } else { "SURVIVED" })
        $line = "{0} | {1} | {2}/{3} | exit {4} | {5} | {6}" -f $m.Id, $verdict, $p, $f, $code, $m.Why, ((@($fails | Select-Object -First 3) | ForEach-Object { $_.Trim() }) -join " || ")
    }
    $lines += $line; Write-Host $line
    [IO.File]::WriteAllLines((Join-Path $OutDir ("results-" + $Lane + ".txt")), [string[]]$lines)
}
try { Remove-Item -LiteralPath $work -Recurse -Force } catch { }
