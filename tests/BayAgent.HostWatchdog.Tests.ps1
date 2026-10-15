<#
BayAgent.HostWatchdog.Tests.ps1

Runs the REAL text of src\BayAgent\bootstrap\AOC.HostWatchdog.ps1 in Windows PowerShell 5.1 (the host a bay uses), on a
scratch folder, with the machine facts it reads (who is signed in, which processes run, what schtasks answers) replaced
by recorders. WHY: on Bay 1 (2026-10-15) the agent task could not be started (0x80070490, "Element not found") and the
watchdog logged "Started scheduled task" every minute for an hour, because it piped schtasks to Out-Null and never read
the exit code. Its fallback, if simply un-hidden, would have started AgentHost as SYSTEM in session 0.

What this proves: the log tells the truth about a failed start (exit code and schtasks text), the watchdog never starts
AgentHost itself, and with nobody signed in it logs and waits. Case E uses the REAL schtasks.exe against a task that does
not exist, so the 5.1 behavior of merged native stderr under $ErrorActionPreference = Stop is exercised for real.
What it does not prove: that the task then starts on a real bay (Bay 1 did, after the re-registration).

Run (from the repo root; Windows only):
  powershell -NoProfile -ExecutionPolicy Bypass -File tests\BayAgent.HostWatchdog.Tests.ps1 [-WatchdogScript <path>]
Exit code 0 = all assertions passed. Hyphens only in comments.
#>
[CmdletBinding()]
param([string]$WatchdogScript = "")

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
if ([string]::IsNullOrWhiteSpace($WatchdogScript)) { $WatchdogScript = Join-Path $RepoRoot "src\BayAgent\bootstrap\AOC.HostWatchdog.ps1" }
$WatchdogScript = (Resolve-Path $WatchdogScript).Path
$Ps51 = Join-Path $env:WINDIR "System32\WindowsPowerShell\v1.0\powershell.exe"

$script:Pass = 0; $script:Fail = 0; $script:Failures = @()
function Assert-True([bool]$cond, [string]$msg) {
    if ($cond) { $script:Pass++; Write-Host "  PASS  $msg" }
    else { $script:Fail++; $script:Failures += $msg; Write-Host "  FAIL  $msg" -ForegroundColor Red }
}
function Section([string]$name) { Write-Host ""; Write-Host "== $name" -ForegroundColor Cyan }

$Scratch = Join-Path $env:TEMP ("bayagent-watchdogtest-" + [guid]::NewGuid().ToString("N").Substring(0, 8))
New-Item -ItemType Directory -Force -Path $Scratch | Out-Null

$SourceText = [IO.File]::ReadAllText($WatchdogScript)
# The watchdog derives its install root from where it sits (Get-BayInstallRoot), so the copy is written to <scratch>baybootstrap.

$taskLine = '$HostTaskName    = "\AOC Bay Agent"'

function Invoke-Watchdog {
    # One run of the watchdog text. $Session: the console user the modeled PC reports ("" = nobody).
    # $HostRunning: an AgentHost process exists. $Schtasks: "ok", "fail" (exit 1 with the Bay 1 text) or "real".
    param([string]$Name, [string]$Session, [bool]$HostRunning, [string]$Schtasks)
    $dir = Join-Path $Scratch $Name
    New-Item -ItemType Directory -Force -Path $dir | Out-Null
    $callsFile = Join-Path $dir "calls.txt"
    $text = $SourceText
    if (-not $text.Contains($taskLine)) { return [pscustomobject]@{ ok = $false; exit = -99; log = "ANCHOR NOT FOUND"; calls = @() } }
    if ($Schtasks -eq "real") { $text = $text.Replace($taskLine, '$HostTaskName    = "\AOC Watchdog Test Task That Does Not Exist 1015"') }
    $over = @"
function Get-CimInstance {
  param([Parameter(Position = 0)][string]`$ClassName, [string]`$Filter)
  if (`$ClassName -eq 'Win32_ComputerSystem') { return [pscustomobject]@{ UserName = '$Session' } }
  if (`$env:WDT_HOST_RUNNING -eq '1') { return @([pscustomobject]@{ ProcessId = 4242; CommandLine = 'powershell.exe -NoProfile -File C:\AllBirdies\BayAgent\bootstrap\AOC.AgentHost.ps1' }) }
  return @()
}
function Start-Process { param([string]`$FilePath, [string]`$ArgumentList, `$WindowStyle) Add-Content -LiteralPath `$env:WDT_CALLS -Value ('Start-Process ' + `$FilePath + ' ' + `$ArgumentList) }

"@
    if ($Schtasks -ne "real") {
        $over += @"
function schtasks.exe {
  Add-Content -LiteralPath `$env:WDT_CALLS -Value ('schtasks ' + (@(`$args) -join ' '))
  if (`$env:WDT_SCHTASKS -eq 'fail') { `$global:LASTEXITCODE = 1; 'ERROR: Element not found.'; return }
  `$global:LASTEXITCODE = 0; 'SUCCESS: Attempted to run the scheduled task.'
}

"@
    }
    $anchor = '$mutex = New-Object'
    if (-not $text.Contains($anchor)) { return [pscustomobject]@{ ok = $false; exit = -99; log = 'ANCHOR NOT FOUND'; calls = @() } }
    $text = $text.Replace($anchor, $over + $anchor)
    New-Item -ItemType Directory -Force -Path (Join-Path $dir "baybootstrap") | Out-Null
    $copy = Join-Path $dir "baybootstrap\watchdog.ps1"
    [IO.File]::WriteAllText($copy, $text, (New-Object Text.UTF8Encoding($false)))
    $env:WDT_CALLS = $callsFile
    $env:WDT_SCHTASKS = $Schtasks
    $env:WDT_HOST_RUNNING = $(if ($HostRunning) { "1" } else { "0" })
    $savedPref = $ErrorActionPreference; $ErrorActionPreference = "Continue"
    $said = & $Ps51 -NoProfile -ExecutionPolicy Bypass -File $copy 2>&1 | ForEach-Object { "$_" }
    $code = $LASTEXITCODE; $ErrorActionPreference = $savedPref
    $logFile = @(Get-ChildItem -LiteralPath (Join-Path $dir "bay\logs") -Filter "HostWatchdog-*.log" -ErrorAction SilentlyContinue | Select-Object -First 1)
    $log = ""
    if ($logFile.Count -eq 1) { $log = [IO.File]::ReadAllText($logFile[0].FullName) }
    $calls = @()
    if (Test-Path -LiteralPath $callsFile) { $calls = @([IO.File]::ReadAllLines($callsFile)) }
    return [pscustomobject]@{ ok = $true; exit = $code; log = $log; calls = $calls; said = (@($said) -join " ") }
}

try {
    Section "A. Nobody is signed in and no AgentHost runs: log, wait, start nothing"
    $a = Invoke-Watchdog "A" "" $false "ok"
    Assert-True ($a.ok -and $a.exit -eq 0) "the run ends cleanly (exit $($a.exit))"
    Assert-True ($a.log -match 'No interactive session is signed in') "it logs that no interactive session exists and that it is waiting"
    Assert-True (@($a.calls | Where-Object { $_ -match '^Start-Process' }).Count -eq 0) "it does not start AgentHost itself"
    Assert-True (@($a.calls | Where-Object { $_ -match '^schtasks' }).Count -eq 0) "it does not even try the agent task (an Interactive task cannot start without a session)"
    Assert-True ($a.log -notmatch 'Started scheduled task') "it does not claim to have started anything"

    Section "B. A session is open and schtasks refuses (the Bay 1 case): the log says so, and nothing runs as SYSTEM"
    $b = Invoke-Watchdog "B" "BAY1KIOSK\BayKiosk" $false "fail"
    Assert-True ($b.ok -and $b.exit -eq 0) "the run ends cleanly (exit $($b.exit))"
    Assert-True ($b.log -notmatch 'Started scheduled task') "it does NOT log 'Started scheduled task' for a start that failed"
    Assert-True ($b.log -match 'Failed to start scheduled task \\AOC Bay Agent: schtasks exit 1: ERROR: Element not found\.') "it logs the failure with the exit code and the schtasks error text"
    Assert-True (@($b.calls | Where-Object { $_ -match '^Start-Process' }).Count -eq 0) "it does NOT start AgentHost directly (that would be SYSTEM in session 0)"
    Assert-True ($b.log -notmatch 'Fallback Start-Process') "...and the old fallback line is gone from the log"
    Assert-True (@($b.calls | Where-Object { $_ -match '^schtasks /Run /TN \\AOC Bay Agent' }).Count -eq 1) "it tried the agent task exactly once"

    Section "C. A session is open and schtasks succeeds"
    $c = Invoke-Watchdog "C" "BAY1KIOSK\BayKiosk" $false "ok"
    Assert-True ($c.log -match 'Started scheduled task \\AOC Bay Agent') "success is logged as started"
    Assert-True (@($c.calls | Where-Object { $_ -match '^Start-Process' }).Count -eq 0) "nothing is started directly"

    Section "D. AgentHost already runs"
    $d = Invoke-Watchdog "D" "BAY1KIOSK\BayKiosk" $true "ok"
    Assert-True ($d.log -match 'Host is running\.' -and $d.calls.Count -eq 0) "it logs 'Host is running.' and touches nothing"

    Section "E. The REAL schtasks.exe, a task that does not exist, under `$ErrorActionPreference = Stop (Windows PowerShell 5.1)"
    $e = Invoke-Watchdog "E" "BAY1KIOSK\BayKiosk" $false "real"
    Assert-True ($e.ok -and $e.exit -eq 0) "the run ends cleanly, not in 'Watchdog fatal' (exit $($e.exit); said: $($e.said))"
    Assert-True ($e.log -notmatch 'Started scheduled task') "a real failing schtasks is not logged as started"
    Assert-True ($e.log -match 'Failed to start scheduled task .*schtasks exit [1-9]\d*: .*ERROR') "the real exit code and the real ERROR text reach the log ($($e.log.Trim()))"
    Assert-True ($e.log -notmatch 'Watchdog fatal') "the native stderr did not turn into a fatal error"
    Assert-True (@($e.calls | Where-Object { $_ -match '^Start-Process' }).Count -eq 0) "and nothing was started directly"
    Assert-True ($e.log -notmatch "RemoteException") "the logged text is the schtasks message only (no .NET type name from the merged stderr)"
}
finally {
    $env:WDT_CALLS = $null; $env:WDT_SCHTASKS = $null; $env:WDT_HOST_RUNNING = $null
    # $Scratch is a folder this run created with a unique name under TEMP (checked below before the delete).
    if ((Split-Path -Leaf $Scratch) -like "bayagent-watchdogtest-*") { try { Remove-Item -LiteralPath $Scratch -Recurse -Force -ErrorAction SilentlyContinue } catch {} }
}

Write-Host ""
Write-Host ("RESULT: {0} passed, {1} failed" -f $script:Pass, $script:Fail) -ForegroundColor $(if ($script:Fail -eq 0) { "Green" } else { "Red" })
if ($script:Fail -gt 0) { $script:Failures | ForEach-Object { Write-Host "  - $_" -ForegroundColor Red }; exit 1 }
exit 0
