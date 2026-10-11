#Requires -Version 5.1
# Kiosk round 2 attack (2026-10-10). Re-runs the two EARLIER attack probe blocks (vx-block of the 2026-10-09 attack,
# vx2-block of its re-verdict), unchanged, on the base release (4c8851ac tree) and on the round 2 head, each spliced into
# that tree's own Kiosk suite before K19 (the earlier verifier's splice point), and writes the observation lines so the
# two can be compared line by line. Hyphens only in comments.
param([string]$HeadTree, [string]$BaseTree, [string]$Vx1, [string]$Vx2, [string]$OutDir)
$ErrorActionPreference = "Stop"
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
$ps51 = "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe"
foreach ($tree in @(@{ Tag = "base"; Path = $BaseTree }, @{ Tag = "head"; Path = $HeadTree })) {
    foreach ($blk in @(@{ Tag = "vx1"; Path = $Vx1 }, @{ Tag = "vx2"; Path = $Vx2 })) {
        $t = [IO.File]::ReadAllText((Join-Path $tree.Path "tests\BayAgent.Kiosk.Tests.ps1"))
        $b = [IO.File]::ReadAllText($blk.Path)
        $marker = '    Section "K19 the shell'
        $i = $t.IndexOf($marker)
        if ($i -lt 0) { throw "marker not found" }
        $copy = Join-Path $OutDir ("Kiosk." + $blk.Tag + "." + $tree.Tag + ".Tests.ps1")
        [IO.File]::WriteAllText($copy, ($t.Substring(0, $i) + $b + "`r`n" + $t.Substring($i)), (New-Object Text.UTF8Encoding($true)))
        $log = Join-Path $OutDir ($blk.Tag + "-run-" + $tree.Tag + ".txt")
        $ErrorActionPreference = "Continue"
        & $ps51 -NoProfile -ExecutionPolicy Bypass -File $copy -AgentScript (Join-Path $tree.Path "src\BayAgent\BayAgent.ps1") -ShellScript (Join-Path $tree.Path "src\BayAgent\kiosk\ABG.KioskShell.ps1") *> $log
        $code = $LASTEXITCODE
        $ErrorActionPreference = "Stop"
        $all = @(Get-Content -LiteralPath $log)
        $obs = @($all | Where-Object { $_ -match '^\s+VX2?\s' } | ForEach-Object { ($_ -replace '^\s+VX2?\s+', '').Trim() })
        [IO.File]::WriteAllLines((Join-Path $OutDir ($blk.Tag + "-observations-" + $tree.Tag + ".txt")), [string[]]$obs)
        $res = @($all | Where-Object { $_ -match '^RESULT: ' })
        Write-Host ("{0} on {1}: exit {2}, {3} observation lines, {4}" -f $blk.Tag, $tree.Tag, $code, $obs.Count, $(if ($res.Count) { $res[-1] } else { "NO RESULT LINE" }))
    }
}
