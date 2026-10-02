<#
BayAgent.SelfHeal.Live.Tests.ps1

WHY THIS EXISTS
  The unit suite (BayAgent.SelfHeal.Tests.ps1) runs the watchdog through a FAKE process layer. The independent attack of
  2026-10-02 found three changes to the REAL layer that all 155 unit assertions let through (its residual R1):
    V01  the start time left in LOCAL time: on an Eastern-time PC every program looks 4 hours old, so the 2-minute
         launch grace is skipped
    V05  the close done by process NAME: every copy of the program closes, not just the frozen one
    V07  the agent's own Windows session assumed (1) instead of read
  This suite runs the SHIPPED watchdog functions with the REAL process layer and the REAL default detector
  (hungAppWindow) against three tiny WinForms programs it builds and starts itself:
    G-hang   the target name, UI thread hung on purpose        -> must be closed, and only after its launch grace
    G-ok     the SAME name, responding                          -> must never be closed
    O-hang   a DIFFERENT name, hung                             -> must never be closed
  Every process it starts is stopped by the Id it started. It touches nothing else. It takes about 2 minutes.

  The clock the watchdog is given is real UTC for the first phase (the programs are inside their grace) and real UTC
  plus 150 s for the second (past the grace), so the test does not have to wait 2 minutes of real time.

RUN (from the repo root, Windows PowerShell 5.1 or PowerShell 7; the programs are built with 5.1)
  powershell -NoProfile -ExecutionPolicy Bypass -File tests\BayAgent.SelfHeal.Live.Tests.ps1

Exit code 0 = all assertions passed. Hyphens only in comments.
#>
[CmdletBinding()]
param([string]$AgentScript = "")

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
if ([string]::IsNullOrWhiteSpace($AgentScript)) { $AgentScript = Join-Path $PSScriptRoot "..\src\BayAgent\BayAgent.ps1" }
$AgentScript = (Resolve-Path $AgentScript).Path

$script:Pass = 0; $script:Fail = 0; $script:Failures = @()
function Assert-True([bool]$cond, [string]$msg) {
    if ($cond) { $script:Pass++; Write-Host "  PASS  $msg" }
    else { $script:Fail++; $script:Failures += $msg; Write-Host "  FAIL  $msg" -ForegroundColor Red }
}
function Section([string]$name) { Write-Host ""; Write-Host "== $name" -ForegroundColor Cyan }

# ---------------------------------------------------------------- lift the shipped functions and constants
$tokens = $null; $errors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile($AgentScript, [ref]$tokens, [ref]$errors)
if ($errors.Count -gt 0) { throw "BayAgent.ps1 has parse errors" }
$defs = @($ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $true))
$wanted = @("Get-PropValue", "Write-TextAtomic", "Get-BayLabel", "Get-EffectiveConfigValue", "Get-AgentOperationalState") +
          @($defs | Where-Object { $_.Name -match 'SelfHeal' } | ForEach-Object { $_.Name })
foreach ($name in $wanted) {
    $d = $defs | Where-Object { $_.Name -eq $name } | Select-Object -First 1
    if (-not $d) { throw "Function '$name' not found" }
    . ([scriptblock]::Create($d.Extent.Text))
}
$script:LogLines = New-Object System.Collections.ArrayList
function Write-Log { param([string]$Message, [string]$Level = "INFO") [void]$script:LogLines.Add("[$Level] $Message") }
$Sandbox = Join-Path $env:TEMP ("bayagent-selfheal-live-" + [guid]::NewGuid().ToString("N").Substring(0, 8))
$BaseDir = $Sandbox
New-Item -ItemType Directory -Force -Path (Join-Path $BaseDir "state") | Out-Null
$BayId = "33333333-3333-3333-3333-333333333333"; $BayEntitySet = "build_baies"; $OrgUrl = "http://127.0.0.1:1"
$cfg = [pscustomobject]@{ bayLabel = "LIVE" }
$AGENTSTATUS_ONLINE = 100000000; $AGENTSTATUS_DEGRADED = 100000001; $AGENTSTATUS_OFFLINE = 100000002; $AGENTSTATUS_MAINTENANCE = 100000003
$Global:EffectiveConfig = $null; $Global:EmergencyStopEngaged = $false
foreach ($st in @($ast.EndBlock.Statements)) {
    if ($st -isnot [System.Management.Automation.Language.AssignmentStatementAst]) { continue }
    $lhs = $st.Left.Extent.Text
    if ($lhs -match '^\$SelfHeal' -or $lhs -eq '$script:SelfHealDetectors' -or $lhs -eq '$script:SelfHealNativeState') { . ([scriptblock]::Create($st.Extent.Text)) }
}

# ---------------------------------------------------------------- build the programs (Windows PowerShell 5.1 compiles them)
$suffix = [guid]::NewGuid().ToString("N").Substring(0, 6)
$GolfName = "AbgShGolf" + $suffix
$OtherName = "AbgShOther" + $suffix
$buildScript = Join-Path $Sandbox "build-sims.ps1"
$simSource = @'
param([string]$OutDir, [string]$NameA, [string]$NameB)
$ErrorActionPreference = "Stop"
$src = @"
using System;
using System.Threading;
using System.Windows.Forms;
public static class AbgShSim {
    [STAThread]
    public static void Main(string[] args) {
        string mode = args.Length > 0 ? args[0] : "ok";
        var f = new Form();
        f.Text = "BayAgent self-heal live test " + mode + " (closes itself)";
        f.Width = 320; f.Height = 90;
        var t = new System.Windows.Forms.Timer();
        t.Interval = 2000;
        t.Tick += (s, e) => { t.Stop(); if (mode == "hang") { Thread.Sleep(Timeout.Infinite); } };
        t.Start();
        var quit = new System.Windows.Forms.Timer();
        quit.Interval = 600000;
        quit.Tick += (s, e) => { Application.Exit(); };
        quit.Start();
        Application.Run(f);
    }
}
"@
foreach ($n in @($NameA, $NameB)) {
    Add-Type -TypeDefinition $src -ReferencedAssemblies System.Windows.Forms -OutputAssembly (Join-Path $OutDir ($n + ".exe")) -OutputType WindowsApplication
}
'@
[IO.File]::WriteAllText($buildScript, $simSource)
$ps51 = Join-Path $env:WINDIR "System32\WindowsPowerShell\v1.0\powershell.exe"
& $ps51 -NoProfile -ExecutionPolicy Bypass -File $buildScript -OutDir $Sandbox -NameA $GolfName -NameB $OtherName | Out-Null
$golfExe = Join-Path $Sandbox ($GolfName + ".exe")
$otherExe = Join-Path $Sandbox ($OtherName + ".exe")

$started = [ordered]@{}
function Start-Sim([string]$exe, [string]$mode, [string]$label) {
    $p = Start-Process -FilePath $exe -ArgumentList $mode -PassThru
    $started[$label] = $p
}
function Test-Alive([string]$label) { $p = $started[$label]; $p.Refresh(); return (-not $p.HasExited) }

try {
    Section "L0 the programs were built"
    Assert-True ((Test-Path -LiteralPath $golfExe) -and (Test-Path -LiteralPath $otherExe)) "both test programs exist ($GolfName, $OtherName)"

    Section "L1 the real layer reads the session it is told to, not an assumed one"
    $ownSession = [System.Diagnostics.Process]::GetCurrentProcess().SessionId
    $realLayer = New-SelfHealProcessLayer
    Assert-True ($realLayer.OwnSessionId -eq $ownSession) "the agent's layer is in this process's session ($ownSession)"
    $sys = @(Get-Process -ErrorAction SilentlyContinue | Where-Object { $_.Id -gt 0 -and $_.SessionId -ne $ownSession } | Select-Object -First 1)
    Assert-True ($sys.Count -eq 1) "precondition: a process in another session exists (pid $(if ($sys.Count) { $sys[0].Id }), session $(if ($sys.Count) { $sys[0].SessionId }))"
    if ($sys.Count -eq 1) {
        $otherLayer = New-SelfHealProcessLayer -SessionOfProcessId $sys[0].Id
        Assert-True ($otherLayer.OwnSessionId -eq $sys[0].SessionId) "a layer told to use that process's session reads $($sys[0].SessionId), so the session is READ, never assumed"
    }

    Section "L2 the real layer reports start times in UTC"
    Start-Sim $golfExe "ok" "G-ok"
    Start-Sim $golfExe "hang" "G-hang"
    Start-Sim $otherExe "hang" "O-hang"
    $startedUtc = (Get-Date).ToUniversalTime()
    $info = $null
    $deadline = (Get-Date).AddSeconds(30)
    while ($null -eq $info -and (Get-Date) -lt $deadline) { try { $info = & $realLayer.GetById $started["G-hang"].Id } catch {}; if ($null -eq $info) { Start-Sleep -Milliseconds 300 } }
    Assert-True ($null -ne $info -and $null -ne $info.StartTimeUtc -and [Math]::Abs(($info.StartTimeUtc - $startedUtc).TotalSeconds) -lt 60) "start time is UTC (read $(if ($info) { $info.StartTimeUtc.ToString('o') }), started about $($startedUtc.ToString('o')))"
    $offsetH = [TimeZoneInfo]::Local.GetUtcOffset((Get-Date)).TotalHours
    Write-Host ("        local offset on this PC: {0} h (a local-time start would look {1} h off)" -f $offsetH, -$offsetH) -ForegroundColor DarkGray

    # Wait for the windows, so the detector has something to read.
    $deadline = (Get-Date).AddSeconds(60)
    while ((Get-Date) -lt $deadline) {
        $h = @(@(& $realLayer.List $GolfName) | Where-Object { $_.MainWindowHandle -ne 0 }).Count
        if ($h -ge 2) { break }
        Start-Sleep -Milliseconds 500
    }

    $cfgPath = Join-Path $Sandbox "agent-config.json"
    [IO.File]::WriteAllText($cfgPath, ('{"selfHeal":{"enabled":true,"watchdog":{"enabled":true,"targets":[{"processName":"' + $GolfName + '","relaunch":"none"}]}}}'))
    Initialize-SelfHeal -ConfigPath $cfgPath -Now ((Get-Date).ToUniversalTime()) -Layer $realLayer
    Assert-True ($script:SelfHealSettings.WatchdogEnabled -and $script:SelfHealSettings.Detector -eq "hungAppWindow") "watchdog on with the real default detector"

    Section "L3 inside the launch grace (real clock): a hung program is NOT closed"
    # Stop phase 1 well inside the grace, measured from the program's own start.
    $phase1Start = Get-Date
    $phase1End = (Get-Date).AddSeconds(50)
    $graceLimit = $started["G-hang"].StartTime.AddSeconds(110)
    if ($graceLimit -lt $phase1End) { $phase1End = $graceLimit }
    while ((Get-Date) -lt $phase1End) {
        Invoke-SelfHealTick -Now ((Get-Date).ToUniversalTime())
        Start-Sleep -Milliseconds 1500
    }
    $phase1Secs = [int]((Get-Date) - $phase1Start).TotalSeconds
    Assert-True ($phase1Secs -ge 40) "precondition: phase 1 watched the hung program for at least 40 s ($phase1Secs s), long enough that a skipped grace would have closed it"
    Assert-True (Test-Alive "G-hang") "hung for about 45 s but only 50 s old: still running (the 120 s grace holds on the REAL start time)"
    Assert-True ((Test-Alive "G-ok") -and (Test-Alive "O-hang")) "...and the others are running"

    Section "L4 past the grace (clock + 150 s): only the hung copy of the target is closed, by its Id"
    $skew = 150
    $phase2End = (Get-Date).AddSeconds(90)
    $closedAt = $null
    while ((Get-Date) -lt $phase2End) {
        Invoke-SelfHealTick -Now ((Get-Date).ToUniversalTime().AddSeconds($skew))
        if ($null -eq $closedAt -and -not (Test-Alive "G-hang")) { $closedAt = Get-Date; $phase2End = $closedAt.AddSeconds(8) }
        Start-Sleep -Milliseconds 1500
    }
    Assert-True (-not (Test-Alive "G-hang")) "the hung copy of the target was closed"
    Assert-True (Test-Alive "G-ok") "the RESPONDING copy with the SAME name is still running (the close is by Id, never by name)"
    Assert-True (Test-Alive "O-hang") "the hung program with a DIFFERENT name is still running"
    $rr = @(@($script:SelfHealOutbox) | Where-Object { $_.row.build_diagnosticname -like "* | software.golf.restarting" })
    Assert-True ($rr.Count -eq 1) "one 'restarting' report queued"
}
finally {
    foreach ($k in @($started.Keys)) { try { $p = $started[$k]; if (-not $p.HasExited) { Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue } } catch {} }
    Start-Sleep -Milliseconds 500
    try { Remove-Item -LiteralPath $Sandbox -Recurse -Force -ErrorAction SilentlyContinue } catch {}
}

Write-Host ""
Write-Host ("RESULT: {0} passed, {1} failed" -f $script:Pass, $script:Fail) -ForegroundColor $(if ($script:Fail -eq 0) { "Green" } else { "Red" })
if ($script:Fail -gt 0) { $script:Failures | ForEach-Object { Write-Host "  - $_" -ForegroundColor Red }; exit 1 }
exit 0
