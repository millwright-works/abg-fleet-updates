# Run-FleetSuites.ps1 - runs the named fleet test suites one after another, each in its own Windows PowerShell 5.1
# process, records every suite's exit code and output under -LogDir, and returns non-zero when any suite fails or when
# fewer suites ran than the repository holds (non-Live suites on disk minus the explicit -Excluded list).
# Called by .github/workflows/fleet-tests.yml; run it the same way locally. Exit codes: 0 all passed, 1 a suite failed,
# 2 the list is incomplete or names a Live or missing suite. Hyphens only in comments.
param(
  [Parameter(Mandatory = $true)][string[]]$Suites,
  [string[]]$Excluded = @(),
  [Parameter(Mandatory = $true)][string]$LogDir,
  [string]$Root = ''
)
$ErrorActionPreference = 'Continue'
# Under -File a list arrives as one comma-joined string; split it so both call shapes work.
$Suites = @($Suites | ForEach-Object { $_ -split ',' } | Where-Object { $_ })
$Excluded = @($Excluded | ForEach-Object { $_ -split ',' } | Where-Object { $_ })
if ([string]::IsNullOrWhiteSpace($Root)) { $Root = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path }
$testsDir = Join-Path $Root 'tests'
$null = New-Item -ItemType Directory -Force -Path $LogDir

# Guard 1: the list must cover every non-Live suite on disk (run or explicitly excluded), and name nothing else.
$onDisk = @(Get-ChildItem -LiteralPath $testsDir -Filter '*.Tests.ps1' | Where-Object { $_.Name -notlike '*.Live.*' } | ForEach-Object { $_.Name })
$expected = @($onDisk | Where-Object { $Excluded -notcontains $_ })
$bad = @()
foreach ($s in $Suites) {
  if ($s -like '*.Live.*') { $bad += "Live suite listed: $s" }
  elseif ($onDisk -notcontains $s) { $bad += "no such non-Live suite on disk: $s" }
}
foreach ($e in $expected) { if ($Suites -notcontains $e) { $bad += "suite on disk but not run or excluded: $e" } }
if ($bad.Count -gt 0) { $bad | ForEach-Object { Write-Host ('LIST ERROR: ' + $_) }; exit 2 }
foreach ($e in $Excluded) { Write-Host ('EXCLUDED (reported residual, not run): ' + $e) }

$ran = 0; $failed = @(); $allCodes = @()
Push-Location -LiteralPath $Root
try {
  foreach ($s in $Suites) {
    $log = Join-Path $LogDir ($s + '.log')
    Write-Host ('=== ' + $s)
    $null = & powershell -NoProfile -ExecutionPolicy Bypass -File (Join-Path $testsDir $s) *>&1 | Out-File -Encoding utf8 -LiteralPath $log
    $code = $LASTEXITCODE
    $ran++
    $allCodes += ('{0}={1}' -f $s.Replace('.Tests.ps1', ''), $code)
    $line = (Get-Content -LiteralPath $log -ErrorAction SilentlyContinue | Where-Object { $_ -match 'RESULT:' } | Select-Object -Last 1)
    Write-Host ('{0} exit={1} {2}' -f $s, $code, $line)
    if ($code -ne 0) {
      $failed += $s
      Get-Content -LiteralPath $log -ErrorAction SilentlyContinue | Where-Object { $_ -match 'FAIL' } | Select-Object -First 20 | ForEach-Object { Write-Host ('   ' + $_) }
      # A GitHub error annotation, so the reason is readable on the run page without downloading the log artifact.
      $why = @(Get-Content -LiteralPath $log -ErrorAction SilentlyContinue | Where-Object { $_ -match '^\s*FAIL\s' } | Select-Object -First 8 | ForEach-Object { $_.Trim() })
      if ($why.Count -eq 0) { $why = @(Get-Content -LiteralPath $log -ErrorAction SilentlyContinue | Where-Object { $_ -match 'Exception|CategoryInfo|FullyQualifiedErrorId' } | Select-Object -First 4 | ForEach-Object { $_.Trim() }) }
      $msg = ('{0} exit={1}: {2}' -f $s, $code, ($why -join ' // '))
      if ($msg.Length -gt 1800) { $msg = $msg.Substring(0, 1800) }
      Write-Host ('::error title=suite failed::' + $msg.Replace('%', '%25').Replace("`r", '%0D').Replace("`n", '%0A'))
    }
  }
} finally { Pop-Location }

# Guard 2: fewer suites ran than expected.
if ($ran -lt $expected.Count) { Write-Host ('FAIL: ran {0} suites, expected at least {1}' -f $ran, $expected.Count); exit 1 }
Write-Host ('::notice title=suite exit codes::' + ($allCodes -join ' '))
Write-Host ('SUMMARY: ran {0}, failed {1}, excluded {2}' -f $ran, $failed.Count, @($Excluded).Count)
if ($failed.Count -gt 0) { Write-Host ('FAILED: ' + ($failed -join ', ')); exit 1 }
exit 0
