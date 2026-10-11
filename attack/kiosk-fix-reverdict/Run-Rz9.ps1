#Requires -Version 5.1
# Kiosk round 2 FIX re-verdict (2026-10-10). Splices rz9-block.ps1 into a COPY of this tree's Kiosk suite right before the
# K22 section and runs the copy under Windows PowerShell 5.1 against the agent script given (the head's, or a copy of the
# attacked base's taken with git show). Hyphens only in comments.
param([string]$Tree = "", [string]$AgentScript = "", [string]$OutDir = "", [string]$Tag = "head")
$ErrorActionPreference = "Stop"
if ([string]::IsNullOrWhiteSpace($Tree)) { $Tree = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path }
if ([string]::IsNullOrWhiteSpace($AgentScript)) { $AgentScript = Join-Path $Tree "src\BayAgent\BayAgent.ps1" }
$ShellScript = Join-Path $Tree "src\BayAgent\kiosk\ABG.KioskShell.ps1"
if ([string]::IsNullOrWhiteSpace($OutDir)) { throw "OutDir is required" }
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
$suite = [IO.File]::ReadAllText((Join-Path $Tree "tests\BayAgent.Kiosk.Tests.ps1"))
$block = [IO.File]::ReadAllText((Join-Path $PSScriptRoot "rz9-block.ps1"))
$marker = "    # ============================================================ K22 (kiosk round 2 FIX"
$at = $suite.IndexOf($marker, [StringComparison]::Ordinal)
if ($at -lt 0 -or $suite.IndexOf($marker, $at + 1, [StringComparison]::Ordinal) -ge 0) { throw "splice marker not found exactly once" }
$spliced = $suite.Substring(0, $at) + $block + "`r`n" + $suite.Substring($at)
$copy = Join-Path $OutDir ("BayAgent.Kiosk.RZ9." + $Tag + ".Tests.ps1")
[IO.File]::WriteAllText($copy, $spliced, (New-Object Text.UTF8Encoding($true)))
$tok = $null; $perr = $null
[void][System.Management.Automation.Language.Parser]::ParseFile($copy, [ref]$tok, [ref]$perr)
if (@($perr).Count -gt 0) { throw ("the spliced copy does not parse: " + $perr[0].Message + " at line " + $perr[0].Extent.StartLineNumber) }
$log = Join-Path $OutDir ("rz9-run-" + $Tag + "-ps51.txt")
$ErrorActionPreference = "Continue"
& "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -ExecutionPolicy Bypass -File $copy -AgentScript $AgentScript -ShellScript $ShellScript *> $log
$code = $LASTEXITCODE
$all = @(Get-Content -LiteralPath $log)
$obs = @($all | Where-Object { $_ -match '^\s+OBS\s' -or $_ -match '^RESULT: ' })
[IO.File]::WriteAllLines((Join-Path $OutDir ("rz9-observations-" + $Tag + ".txt")), [string[]]$obs)
Write-Host ("exit " + $code)
$obs | ForEach-Object { Write-Host $_ }
