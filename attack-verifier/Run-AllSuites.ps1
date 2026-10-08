param([string]$Repo = "C:\aoc-wt\kiosk-attack-run", [string]$Out = "C:\aoc-wt\kiosk-attack\attack-verifier\suites")
New-Item -ItemType Directory -Force -Path $Out | Out-Null
$sum = Join-Path $Out "summary.txt"
"run start $((Get-Date).ToString('o')) repo=$Repo head=$(git -C $Repo rev-parse HEAD)" | Set-Content $sum
$hosts = @(@("5.1", (Join-Path $env:WINDIR "System32\WindowsPowerShell\v1.0\powershell.exe")), @("7", "C:\Users\kedah\AppData\Local\Microsoft\WindowsApps\pwsh.exe"))
if ($env:VERIF_ONLY7 -eq "1") { $hosts = @(,$hosts[1]); $sum = Join-Path $Out "summary7.txt"; "run start $((Get-Date).ToString('o'))" | Set-Content $sum }
foreach ($h in $hosts) {
  foreach ($t in (Get-ChildItem (Join-Path $Repo "tests") -Filter "*.Tests.ps1" | Sort-Object Name)) {
    $log = Join-Path $Out ("{0}-{1}.log" -f $h[0], $t.BaseName)
    $res = $null; $code = $null; $global:LASTEXITCODE = -999
    $sw = [Diagnostics.Stopwatch]::StartNew()
    & $h[1] -NoProfile -ExecutionPolicy Bypass -File $t.FullName *> $log
    $code = $LASTEXITCODE
    $sw.Stop()
    if (Test-Path $log) { $res = (Select-String -Path $log -Pattern "RESULT:|passed.*failed" | Select-Object -Last 1) }
    $line = "{0,-4} {1,-38} exit={2,-3} {3,5}s {4}" -f $h[0], $t.BaseName, $code, [int]$sw.Elapsed.TotalSeconds, $(if ($res) { $res.Line.Trim() } else { "NO SUMMARY LINE" })
    Add-Content $sum $line
  }
}
"run end $((Get-Date).ToString('o'))" | Add-Content $sum
