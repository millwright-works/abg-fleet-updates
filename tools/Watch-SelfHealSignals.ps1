<#
Watch-SelfHealSignals.ps1 -- READ-ONLY bench probe for A0.327 Phase 2 (bench Test 4).

WHAT IT ANSWERS
  The open question for the self-heal watchdog: when the Uneekor Launcher or one of its games freezes, does Windows
  report it as "not responding"? This prints, every few seconds, for every process with the given name in THIS
  Windows session:
    - what each shipped detector reads (hungAppWindow, processResponding): True / False / blank (cannot tell)
    - CPU use and disk reads since the last sample (the "is it loading" signals)
    - the verdict the watchdog itself would reach (grace / ok / unknown / unresponsive / loading / frozen)
  using the watchdog's OWN functions, lifted from BayAgent.ps1, so the bench sees exactly what the agent would decide.

WHAT IT NEVER DOES
  It never closes, starts or changes any process, and it writes nothing except the optional -CsvPath file.

RUN ON THE BENCH (as the BayKiosk user, in the kiosk session, so it sees the same windows the agent sees)
  powershell -NoProfile -ExecutionPolicy Bypass -File tools\Watch-SelfHealSignals.ps1 -ProcessName UneekorLauncher -Seconds 600 -CsvPath C:\Temp\test4.csv
  Then: load a course normally (expect "loading" or "ok", never "frozen"), and freeze the game on purpose (expect
  "frozen" about 30 seconds after the detector first reads False). If the detector column never reads False while the
  game is visibly frozen, that detector cannot see this freeze: record it, and a new detector is needed (see the
  $script:SelfHealDetectors comment in BayAgent.ps1).

Hyphens only in comments.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$ProcessName,
    [int]$Seconds = 300,
    [int]$IntervalSeconds = 5,
    [string]$CsvPath = "",
    [string]$AgentScript = "",
    [int]$LaunchGraceSeconds = 120
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
if ([string]::IsNullOrWhiteSpace($AgentScript)) {
    $AgentScript = Join-Path $PSScriptRoot "..\src\BayAgent\BayAgent.ps1"
    if (-not (Test-Path -LiteralPath $AgentScript)) { $AgentScript = Join-Path $PSScriptRoot "..\BayAgent.ps1" }
}
$AgentScript = (Resolve-Path $AgentScript).Path

$tk = $null; $er = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile($AgentScript, [ref]$tk, [ref]$er)
if ($er.Count -gt 0) { throw "BayAgent.ps1 has parse errors" }
$defs = @($ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $true))
foreach ($name in @("Get-PropValue", "Initialize-SelfHealNative", "ConvertTo-SelfHealProcInfo", "Get-SelfHealReading",
                    "Get-SelfHealInstanceVerdict", "Read-SelfHealSettings", "Get-SelfHealSettingInt", "Test-SelfHealFlag",
                    "ConvertTo-SelfHealTargetName")) {
    $d = $defs | Where-Object { $_.Name -eq $name } | Select-Object -First 1
    if (-not $d) { throw "Function '$name' not found in $AgentScript" }
    . ([scriptblock]::Create($d.Extent.Text))
}
function Write-Log { param([string]$Message, [string]$Level = "INFO") Write-Host "[$Level] $Message" }
$BaseDir = Join-Path $env:TEMP "selfheal-probe"
foreach ($st in @($ast.EndBlock.Statements)) {
    if ($st -isnot [System.Management.Automation.Language.AssignmentStatementAst]) { continue }
    $lhs = $st.Left.Extent.Text
    if ($lhs -match '^\$SelfHeal' -or $lhs -eq '$script:SelfHealDetectors' -or $lhs -eq '$script:SelfHealNativeState') {
        . ([scriptblock]::Create($st.Extent.Text))
    }
}

# The watchdog's default thresholds, read through its own settings parser.
$tmpCfg = Join-Path $env:TEMP ("selfheal-probe-" + [guid]::NewGuid().ToString("N").Substring(0, 8) + ".json")
[IO.File]::WriteAllText($tmpCfg, ('{"selfHeal":{"enabled":true,"watchdog":{"enabled":true,"launchGraceSeconds":' + $LaunchGraceSeconds + ',"targets":[{"processName":"probe"}]}}}'))
$settings = Read-SelfHealSettings -Path $tmpCfg
Remove-Item -LiteralPath $tmpCfg -Force -ErrorAction SilentlyContinue

$ownSession = [int](Get-Process -Id $PID).SessionId
$states = @{}
$rows = New-Object System.Collections.ArrayList
$end = (Get-Date).AddSeconds($Seconds)
Write-Host ("Watching '{0}' in session {1} every {2}s for {3}s. Thresholds: unresponsive {4}s, grace {5}s, loading bound {6}s, busy at {7}% CPU or {8} KB read." -f `
    $ProcessName, $ownSession, $IntervalSeconds, $Seconds, $settings.UnresponsiveSeconds, $settings.LaunchGraceSeconds,
    $settings.LoadingMaxSeconds, [int]($settings.CpuBusyFraction * 100), [int]($settings.IoBusyBytes / 1024))
while ((Get-Date) -lt $end) {
    $now = (Get-Date).ToUniversalTime()
    foreach ($p in @(Get-Process -Name $ProcessName -ErrorAction SilentlyContinue)) {
        if ($p.ProcessName -ine $ProcessName) { continue }
        $info = ConvertTo-SelfHealProcInfo $p
        if ($info.SessionId -ne $ownSession) { continue }
        $hung = (Get-SelfHealReading $info $null "hungAppWindow")
        $resp = (Get-SelfHealReading $info $null "processResponding")
        $key = "{0}|{1}" -f $info.Id, $(if ($null -ne $info.StartTimeUtc) { $info.StartTimeUtc.Ticks } else { "nostart" })
        $prior = $null; if ($states.ContainsKey($key)) { $prior = $states[$key] }
        $cpuPct = $null; $ioKb = $null
        if ($null -ne $prior -and $null -ne $prior.LastAt) {
            $el = [Math]::Max(0.001, ($now - $prior.LastAt).TotalSeconds)
            if ($null -ne $info.CpuSeconds -and $null -ne $prior.LastCpu) { $cpuPct = [Math]::Round(100 * ($info.CpuSeconds - $prior.LastCpu) / $el, 1) }
            if ($null -ne $info.IoReadBytes -and $null -ne $prior.LastIo) { $ioKb = [Math]::Round(($info.IoReadBytes - $prior.LastIo) / 1024, 0) }
        }
        $sample = @{ Responding = $hung.Responding; CpuSeconds = $info.CpuSeconds; IoReadBytes = $info.IoReadBytes; StartTimeUtc = $info.StartTimeUtc }
        $v = Get-SelfHealInstanceVerdict -PriorState $prior -Sample $sample -Now $now -Settings $settings
        $states[$key] = $v.State
        $age = $(if ($null -ne $info.StartTimeUtc) { [int]($now - $info.StartTimeUtc).TotalSeconds } else { $null })
        $row = [pscustomobject]@{
            utc = $now.ToString("HH:mm:ss"); pid = $info.Id; ageSec = $age; mainWindow = ($info.MainWindowHandle -ne 0)
            respondingByHungAppWindow = $hung.Responding; respondingByProcessResponding = $resp.Responding; cpuPct = $cpuPct; ioReadKb = $ioKb
            verdict = $v.Verdict
        }
        [void]$rows.Add($row)
        Write-Host ("{0} pid={1} age={2}s window={3} responding: hungAppWindow={4} processResponding={5} cpu={6}% read={7}KB -> {8}" -f `
            $row.utc, $row.pid, $row.ageSec, $row.mainWindow, $row.respondingByHungAppWindow, $row.respondingByProcessResponding, $row.cpuPct, $row.ioReadKb, $row.verdict)
    }
    Start-Sleep -Seconds $IntervalSeconds
}
if (-not [string]::IsNullOrWhiteSpace($CsvPath)) { $rows | Export-Csv -LiteralPath $CsvPath -NoTypeInformation; Write-Host "Wrote $($rows.Count) rows to $CsvPath" }
