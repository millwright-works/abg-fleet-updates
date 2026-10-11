#Requires -Version 5.1
# Release-prep check (2026-10-10): runs every suite in a tree under Windows PowerShell 5.1, one at a time, each to its
# own log. -Only limits to suites whose name matches. Hyphens only in comments.
param([string]$Tree, [string]$OutDir, [string]$Only = "", [string]$HostExe = "")
$ErrorActionPreference = "Continue"
if ([string]::IsNullOrWhiteSpace($HostExe)) { $HostExe = "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" }
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
$lines = @()
foreach ($f in @(Get-ChildItem -LiteralPath (Join-Path $Tree "tests") -Filter "*.Tests.ps1" | Sort-Object Name)) {
    if ($Only -and $f.Name -notmatch $Only) { continue }
    $log = Join-Path $OutDir ($f.BaseName + ".txt")
    $sw = [Diagnostics.Stopwatch]::StartNew()
    & $HostExe -NoProfile -ExecutionPolicy Bypass -File $f.FullName *> $log
    $code = $LASTEXITCODE
    $sw.Stop()
    $res = @(Get-Content -LiteralPath $log | Where-Object { $_ -match '^RESULT: ' })
    $r = $(if ($res.Count -gt 0) { $res[-1] } else { "NO RESULT LINE" })
    $line = "{0} | exit {1} | {2}s | {3}" -f $f.Name, $code, [int]$sw.Elapsed.TotalSeconds, $r
    $lines += $line
    [IO.File]::WriteAllLines((Join-Path $OutDir "summary.txt"), [string[]]$lines)
}
[IO.File]::AppendAllText((Join-Path $OutDir "summary.txt"), "ALL-DONE`r`n")
