#Requires -Version 5.1
# Kiosk round 2 FIX re-verdict (2026-10-10). Builds a COPY of tests\BayAgent.Kiosk.Tests.ps1 (never the tree's own file)
# with two splices and runs it under Windows PowerShell 5.1 against the agent and shell given (default: this tree's):
#   1. the predecessor's vy-block.ps1, UNCHANGED, right before the K22 section (K22 replaces the row stub the VY probes read);
#   2. rz-block.ps1 (this re-verdict's probes) right before the "restore the suite's e-stop stubs" line, after K22.
# -SkipRz runs the predecessor's block alone; -Mode base makes the VY block skip its head-only probes.
# Hyphens only in comments.
param([string]$Tree = "", [string]$AgentScript = "", [string]$ShellScript = "", [string]$OutDir = "", [string]$Tag = "head", [switch]$SkipRz, [switch]$SkipVy)
$ErrorActionPreference = "Stop"
if ([string]::IsNullOrWhiteSpace($Tree)) { $Tree = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path }
if ([string]::IsNullOrWhiteSpace($AgentScript)) { $AgentScript = Join-Path $Tree "src\BayAgent\BayAgent.ps1" }
if ([string]::IsNullOrWhiteSpace($ShellScript)) { $ShellScript = Join-Path $Tree "src\BayAgent\kiosk\ABG.KioskShell.ps1" }
if ([string]::IsNullOrWhiteSpace($OutDir)) { throw "OutDir is required" }
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
$suite = [IO.File]::ReadAllText((Join-Path $Tree "tests\BayAgent.Kiosk.Tests.ps1"))
$vy = [IO.File]::ReadAllText((Join-Path $PSScriptRoot "..\kiosk-round2\vy-block.ps1"))
$rz = [IO.File]::ReadAllText((Join-Path $PSScriptRoot "rz-block.ps1"))
function Splice-Before([string]$text, [string]$marker, [string]$block) {
    $at = $text.IndexOf($marker, [StringComparison]::Ordinal)
    if ($at -lt 0 -or $text.IndexOf($marker, $at + 1, [StringComparison]::Ordinal) -ge 0) { throw ("splice marker not found exactly once: " + $marker) }
    return ($text.Substring(0, $at) + $block + "`r`n" + $text.Substring($at))
}
$spliced = $suite
if (-not $SkipRz) { $spliced = Splice-Before $spliced "    # restore the suite's e-stop stubs for the sections below" $rz }
if (-not $SkipVy) { $spliced = Splice-Before $spliced "    # ============================================================ K22 (kiosk round 2 FIX" $vy }
$copy = Join-Path $OutDir ("BayAgent.Kiosk.RZ." + $Tag + ".Tests.ps1")
[IO.File]::WriteAllText($copy, $spliced, (New-Object Text.UTF8Encoding($true)))
$tok = $null; $perr = $null
[void][System.Management.Automation.Language.Parser]::ParseFile($copy, [ref]$tok, [ref]$perr)
if (@($perr).Count -gt 0) { throw ("the spliced copy does not parse: " + $perr[0].Message + " at line " + $perr[0].Extent.StartLineNumber) }
$log = Join-Path $OutDir ("rz-run-" + $Tag + "-ps51.txt")
$ErrorActionPreference = "Continue"
$env:VY_OUT = $OutDir
& "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -ExecutionPolicy Bypass -File $copy -AgentScript $AgentScript -ShellScript $ShellScript *> $log
$code = $LASTEXITCODE
$all = @(Get-Content -LiteralPath $log)
$obs = @($all | Where-Object { $_ -match '^\s+OBS\s' -or $_ -match '^RESULT: ' -or $_ -match '^\s+FAIL\s' })
[IO.File]::WriteAllLines((Join-Path $OutDir ("rz-observations-" + $Tag + ".txt")), [string[]]$obs)
Write-Host ("exit " + $code)
Write-Host ("lines " + $all.Count + ", observations " + $obs.Count)
