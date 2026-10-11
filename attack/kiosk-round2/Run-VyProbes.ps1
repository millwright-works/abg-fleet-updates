#Requires -Version 5.1
# Kiosk round 2 attack (2026-10-10). Splices vy-block.ps1 into a COPY of tests\BayAgent.Kiosk.Tests.ps1 (never the tree's
# own file) right before the "restore the suite's e-stop stubs" line of K21, and runs the copy under Windows PowerShell 5.1
# against the agent and shell given (default: this tree's). Hyphens only in comments.
param([string]$Tree = "", [string]$AgentScript = "", [string]$ShellScript = "", [string]$OutDir = "", [string]$Tag = "head")
$ErrorActionPreference = "Stop"
if ([string]::IsNullOrWhiteSpace($Tree)) { $Tree = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path }
if ([string]::IsNullOrWhiteSpace($AgentScript)) { $AgentScript = Join-Path $Tree "src\BayAgent\BayAgent.ps1" }
if ([string]::IsNullOrWhiteSpace($ShellScript)) { $ShellScript = Join-Path $Tree "src\BayAgent\kiosk\ABG.KioskShell.ps1" }
if ([string]::IsNullOrWhiteSpace($OutDir)) { throw "OutDir is required" }
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
$suite = [IO.File]::ReadAllText((Join-Path $Tree "tests\BayAgent.Kiosk.Tests.ps1"))
$block = [IO.File]::ReadAllText((Join-Path $PSScriptRoot "vy-block.ps1"))
$marker = "    # restore the suite's e-stop stubs for the sections below"
$at = $suite.IndexOf($marker, [StringComparison]::Ordinal)
if ($at -lt 0 -or $suite.IndexOf($marker, $at + 1, [StringComparison]::Ordinal) -ge 0) { throw "splice marker not found exactly once" }
$spliced = $suite.Substring(0, $at) + $block + "`r`n" + $suite.Substring($at)
$copy = Join-Path $OutDir ("BayAgent.Kiosk.VY." + $Tag + ".Tests.ps1")
[IO.File]::WriteAllText($copy, $spliced, (New-Object Text.UTF8Encoding($true)))
$tok = $null; $perr = $null
[void][System.Management.Automation.Language.Parser]::ParseFile($copy, [ref]$tok, [ref]$perr)
if (@($perr).Count -gt 0) { throw ("the spliced copy does not parse: " + $perr[0].Message + " at line " + $perr[0].Extent.StartLineNumber) }
$log = Join-Path $OutDir ("vy-run-" + $Tag + "-ps51.txt")
$ErrorActionPreference = "Continue"
$env:VY_OUT = $OutDir
& "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -ExecutionPolicy Bypass -File $copy -AgentScript $AgentScript -ShellScript $ShellScript *> $log
$code = $LASTEXITCODE
$all = @(Get-Content -LiteralPath $log)
$obs = @($all | Where-Object { $_ -match '^\s+OBS\s' -or $_ -match '^RESULT: ' -or $_ -match '^\s+FAIL\s' })
[IO.File]::WriteAllLines((Join-Path $OutDir ("vy-observations-" + $Tag + ".txt")), [string[]]$obs)
Write-Host ("exit " + $code)
$obs | ForEach-Object { Write-Host $_ }
