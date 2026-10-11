#Requires -Version 5.1
# Release-prep check (2026-10-10). Splices rp-block.ps1 into a COPY of a tree's Kiosk suite (never the tree's own file)
# and runs the copy against that tree's agent. The splice goes before the first of the markers below that is found
# exactly once (after K22's helpers and the real-loop case). Hyphens only in comments.
param([string]$Tree = "", [string]$OutDir = "", [string]$Tag = "head", [string]$HostExe = "", [string]$AgentScript = "", [switch]$StopAfter)
$ErrorActionPreference = "Stop"
if ([string]::IsNullOrWhiteSpace($Tree)) { $Tree = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path }
if ([string]::IsNullOrWhiteSpace($HostExe)) { $HostExe = "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" }
if ([string]::IsNullOrWhiteSpace($AgentScript)) { $AgentScript = Join-Path $Tree "src\BayAgent\BayAgent.ps1" }
$ShellScript = Join-Path $Tree "src\BayAgent\kiosk\ABG.KioskShell.ps1"
if ([string]::IsNullOrWhiteSpace($OutDir)) { throw "OutDir is required" }
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
$suite = [IO.File]::ReadAllText((Join-Path $Tree "tests\BayAgent.Kiosk.Tests.ps1"))
$block = [IO.File]::ReadAllText((Join-Path $PSScriptRoot "rp-block.ps1"))
$markers = @("    # ---- F3: the REAL agent is stopped (hard exit, code 77)", "    # ---- Item 5: the default sender's process handling")
$at = -1; $used = ""
foreach ($marker in $markers) {
    $i = $suite.IndexOf($marker, [StringComparison]::Ordinal)
    if ($i -ge 0 -and $suite.IndexOf($marker, $i + 1, [StringComparison]::Ordinal) -lt 0) { $at = $i; $used = $marker; break }
}
if ($at -lt 0) { throw "no splice marker found exactly once" }
$spliced = $suite.Substring(0, $at) + $block + "`r`n" + $suite.Substring($at)
$copy = Join-Path $OutDir ("BayAgent.Kiosk.RP." + $Tag + ".Tests.ps1")
[IO.File]::WriteAllText($copy, $spliced, (New-Object Text.UTF8Encoding($true)))
Copy-Item -LiteralPath (Join-Path $Tree "src\BayAgent\manifest.json") -Destination (Join-Path $OutDir "manifest.json") -Force
$tok = $null; $perr = $null
[void][System.Management.Automation.Language.Parser]::ParseFile($copy, [ref]$tok, [ref]$perr)
if (@($perr).Count -gt 0) { throw ("the spliced copy does not parse: " + $perr[0].Message + " at line " + $perr[0].Extent.StartLineNumber) }
$log = Join-Path $OutDir ("rp-run-" + $Tag + ".txt")
$ErrorActionPreference = "Continue"
if ($StopAfter) { $env:RP_STOP = "1" } else { $env:RP_STOP = "0" }
& $HostExe -NoProfile -ExecutionPolicy Bypass -File $copy -AgentScript $AgentScript -ShellScript $ShellScript *> $log
$code = $LASTEXITCODE
$all = @(Get-Content -LiteralPath $log)
$obs = @($all | Where-Object { $_ -match '^\s+OBS\s' -or $_ -match '^RESULT: ' -or $_ -match '^\s+FAIL\s' })
[IO.File]::WriteAllLines((Join-Path $OutDir ("rp-observations-" + $Tag + ".txt")), [string[]]$obs)
Write-Host ("spliced before: " + $used.Trim())
Write-Host ("exit " + $code)
$obs | ForEach-Object { Write-Host $_ }
if (@($all | Where-Object { $_ -match '^RESULT: ' }).Count -eq 0) { $all | Select-Object -Last 8 | ForEach-Object { Write-Host $_ } }
