param([string]$Root, [string]$OutDir)
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
$files = Get-ChildItem -LiteralPath (Join-Path $Root "tests") -Filter "*.Tests.ps1" | Sort-Object Name
$sum = @()
foreach ($f in $files) {
    $log = Join-Path $OutDir ($f.BaseName + ".txt")
    $sw = [Diagnostics.Stopwatch]::StartNew()
    & "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -ExecutionPolicy Bypass -File $f.FullName *> $log
    $code = $LASTEXITCODE
    $sw.Stop()
    $res = @(Get-Content -LiteralPath $log | Where-Object { $_ -match 'RESULT|passed|Passed|failed' } | Select-Object -Last 1)
    $line = "{0} | exit {1} | {2:n0}s | {3}" -f $f.Name, $code, $sw.Elapsed.TotalSeconds, ($res -join " ")
    $sum += $line
    $line
}
[IO.File]::WriteAllLines((Join-Path $OutDir "summary.txt"), [string[]]$sum)
