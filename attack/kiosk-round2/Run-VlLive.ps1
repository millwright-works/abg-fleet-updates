#Requires -Version 5.1
# Kiosk round 2 attack (2026-10-10). Splices vl-block.ps1 into a COPY of tests\BayAgent.KioskShell.Live.Tests.ps1 before
# S5e and runs the copy under Windows PowerShell 5.1. The copy sits beside the original while it runs (so the suite's
# relative paths resolve) and is deleted afterwards; a copy of it is kept in OutDir. Hyphens only in comments.
param([string]$Tree = "", [string]$OutDir = "")
$ErrorActionPreference = "Stop"
if ([string]::IsNullOrWhiteSpace($Tree)) { $Tree = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path }
if ([string]::IsNullOrWhiteSpace($OutDir)) { throw "OutDir is required" }
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
$suite = [IO.File]::ReadAllText((Join-Path $Tree "tests\BayAgent.KioskShell.Live.Tests.ps1"))
$block = [IO.File]::ReadAllText((Join-Path $PSScriptRoot "vl-block.ps1"))
$marker = '    Section "S5e source divergence (live)'
$at = $suite.IndexOf($marker, [StringComparison]::Ordinal)
if ($at -lt 0 -or $suite.IndexOf($marker, $at + 1, [StringComparison]::Ordinal) -ge 0) { throw "splice marker not found exactly once" }
$spliced = $suite.Substring(0, $at) + $block + "`r`n" + $suite.Substring($at)
$copy = Join-Path $Tree "tests\VL-probe-copy.KioskShell.Live.ps1"
[IO.File]::WriteAllText($copy, $spliced, (New-Object Text.UTF8Encoding($true)))
try {
    $tok = $null; $perr = $null
    [void][System.Management.Automation.Language.Parser]::ParseFile($copy, [ref]$tok, [ref]$perr)
    if (@($perr).Count -gt 0) { throw ("the spliced copy does not parse: " + $perr[0].Message + " at line " + $perr[0].Extent.StartLineNumber) }
    Copy-Item -LiteralPath $copy -Destination (Join-Path $OutDir "VL-probe-copy.KioskShell.Live.ps1") -Force
    $log = Join-Path $OutDir "vl-run-ps51.txt"
    $ErrorActionPreference = "Continue"
    & "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -ExecutionPolicy Bypass -File $copy *> $log
    $code = $LASTEXITCODE
    $all = @(Get-Content -LiteralPath $log)
    $obs = @($all | Where-Object { $_ -match '^\s+OBS\s' -or $_ -match '^RESULT: ' -or $_ -match '^\s+FAIL\s' -or $_ -match 'VL\d' })
    [IO.File]::WriteAllLines((Join-Path $OutDir "vl-observations.txt"), [string[]]$obs)
    Write-Host ("exit " + $code)
    $obs | ForEach-Object { Write-Host $_ }
} finally { Remove-Item -LiteralPath $copy -Force -ErrorAction SilentlyContinue }
