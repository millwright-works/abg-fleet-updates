#Requires -Version 5.1
# Kiosk round 2 FIX re-verdict (2026-10-10). Splices rz10-block.ps1 (state drift) into a COPY of this tree's Kiosk suite
# right before the "restore the suite's e-stop stubs" line (after K22) and runs the copy under Windows PowerShell 5.1.
# Hyphens only in comments.
param([string]$Tree = "", [string]$OutDir = "", [string]$Tag = "head")
$ErrorActionPreference = "Stop"
if ([string]::IsNullOrWhiteSpace($Tree)) { $Tree = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path }
$AgentScript = Join-Path $Tree "src\BayAgent\BayAgent.ps1"
$ShellScript = Join-Path $Tree "src\BayAgent\kiosk\ABG.KioskShell.ps1"
if ([string]::IsNullOrWhiteSpace($OutDir)) { throw "OutDir is required" }
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
$suite = [IO.File]::ReadAllText((Join-Path $Tree "tests\BayAgent.Kiosk.Tests.ps1"))
$block = [IO.File]::ReadAllText((Join-Path $PSScriptRoot "rz10-block.ps1"))
$marker = "    # restore the suite's e-stop stubs for the sections below"
$at = $suite.IndexOf($marker, [StringComparison]::Ordinal)
if ($at -lt 0 -or $suite.IndexOf($marker, $at + 1, [StringComparison]::Ordinal) -ge 0) { throw "splice marker not found exactly once" }
$spliced = $suite.Substring(0, $at) + $block + "`r`n" + $suite.Substring($at)
$copy = Join-Path $OutDir ("BayAgent.Kiosk.RZ10." + $Tag + ".Tests.ps1")
[IO.File]::WriteAllText($copy, $spliced, (New-Object Text.UTF8Encoding($true)))
Copy-Item -LiteralPath (Join-Path $Tree "src\BayAgent\manifest.json") -Destination (Join-Path $OutDir "manifest.json") -Force
$tok = $null; $perr = $null
[void][System.Management.Automation.Language.Parser]::ParseFile($copy, [ref]$tok, [ref]$perr)
if (@($perr).Count -gt 0) { throw ("the spliced copy does not parse: " + $perr[0].Message + " at line " + $perr[0].Extent.StartLineNumber) }
$log = Join-Path $OutDir ("rz10-run-" + $Tag + "-ps51.txt")
$ErrorActionPreference = "Continue"
& "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -ExecutionPolicy Bypass -File $copy -AgentScript $AgentScript -ShellScript $ShellScript *> $log
$code = $LASTEXITCODE
$all = @(Get-Content -LiteralPath $log)
$obs = @($all | Where-Object { $_ -match '^\s+OBS\s' -or $_ -match '^RESULT: ' -or $_ -match '^\s+FAIL\s' })
[IO.File]::WriteAllLines((Join-Path $OutDir ("rz10-observations-" + $Tag + ".txt")), [string[]]$obs)
Write-Host ("exit " + $code)
$obs | ForEach-Object { Write-Host $_ }
if (@($all | Where-Object { $_ -match '^RESULT: ' }).Count -eq 0) { $all | Select-Object -Last 12 | ForEach-Object { Write-Host $_ } }
