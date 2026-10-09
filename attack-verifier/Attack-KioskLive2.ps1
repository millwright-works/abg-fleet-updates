<#
Verifier re-verdict live attack (fix round 1f09df74). The shipped shell (companion copy: $BaseDir and the release-mode
constant changed only) runs against intent and session.json files written the way the agent writes them:
  L1  Start (45 paid min) -> emergency stop engaged, cleared -> canceled-booking Reset (session.json rewritten READY, as the
      unchanged Reset handler does). Expect: the paying member's launcher is NOT ended.
  L2  back-to-back: A Start, A End (closed A, session.json ENDED A); B Start: session.json ACTIVE B, but B's intent write
      FAILS (the file held open without FILE_SHARE_DELETE for 45 s). B's launcher runs. Expect: not ended; after the hold
      the pending write lands (main-loop pass simulated every 3 s) and the intent reads wanted B.
  L3  like L2, but while B's write is still failing a canceled-booking Reset rewrites session.json READY.
Intent writes go through the REAL agent functions (lifted by AST). Every process is stopped by the Id recorded here.
#>
param([string]$Repo = "C:\aoc-wt\kiosk-attack-r2", [ValidateSet("L1", "L2", "L3")][string]$Scenario = "L1")
Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
$AgentScript = Join-Path $Repo "src\BayAgent\BayAgent.ps1"
$ShellScript = Join-Path $Repo "src\BayAgent\kiosk\ABG.KioskShell.ps1"
$ps51 = Join-Path $env:WINDIR "System32\WindowsPowerShell\v1.0\powershell.exe"
$Root = Join-Path $env:TEMP ("kiosk-verif-live2-" + [guid]::NewGuid().ToString("N").Substring(0, 8))
foreach ($d in @("releases\1.4.0\kiosk", "current\kiosk", "state", "control", "logs", "sd")) { New-Item -ItemType Directory -Force -Path (Join-Path $Root $d) | Out-Null }
function Set-Text([string]$p, [string]$t) { [IO.File]::WriteAllText($p, $t, (New-Object Text.UTF8Encoding($false))) }
$SessionJson = Join-Path $Root "sd\session.json"
function Set-Session([string]$status, [string]$sid) { Set-Text $SessionJson ((ConvertTo-Json -Compress -InputObject ([ordered]@{ status = $status; baySessionId = $sid; displayName = "Guest" }))) }

$shipped = [IO.File]::ReadAllText($ShellScript)
$ShellCopy = Join-Path $Root "releases\1.4.0\kiosk\ABG.KioskShell.ps1"
$c1 = $shipped.Replace('$BaseDir = "C:\AllBirdies\BayAgent"', ('$BaseDir = "{0}"' -f $Root)).Replace('$KioskShellReleaseMode = "explorer"', '$KioskShellReleaseMode = "companion"')
if ($c1 -eq $shipped) { throw "anchors not found" }
Set-Text $ShellCopy $c1
Set-Text (Join-Path $Root "current\kiosk\kiosk-policy.json") '{"schema":1,"mode":"companion","minShellBytes":4096}'

$suffix = [guid]::NewGuid().ToString("N").Substring(0, 6)
$LaunchName = "AbgVerifLaunch" + $suffix
$build = Join-Path $Root "build.ps1"
Set-Text $build @'
param([string]$Out)
$src = @"
using System; using System.Windows.Forms;
public static class S { [STAThread] public static void Main(string[] a) { var f = new Form(); f.Text = "verifier stand-in: paying member's launcher"; bool leaving = false;
 f.FormClosing += (s, e) => { if (!leaving) { e.Cancel = true; f.WindowState = FormWindowState.Minimized; } };
 var t = new Timer(); t.Interval = 300000; t.Tick += (s, e) => { leaving = true; Application.Exit(); }; t.Start(); Application.Run(f); } }
"@
Add-Type -TypeDefinition $src -ReferencedAssemblies System.Windows.Forms -OutputAssembly $Out -OutputType WindowsApplication
'@
$LaunchExe = Join-Path $Root ($LaunchName + ".exe")
& $ps51 -NoProfile -ExecutionPolicy Bypass -File $build -Out $LaunchExe | Out-Null
Set-Text (Join-Path $Root "agent-config.json") (ConvertTo-Json -Depth 5 -InputObject ([ordered]@{
    sessionJsonPath = $SessionJson
    launcher = [ordered]@{ path = $LaunchExe; processName = $LaunchName }
    sessionDisplay = [ordered]@{ enabled = $false } }))

$tk = $null; $er = $null
$agentAst = [System.Management.Automation.Language.Parser]::ParseFile($AgentScript, [ref]$tk, [ref]$er)
$CMD_UPDATESESSIONDISPLAY = 100000005; $CMD_STARTSESSION = 100000010; $CMD_ENDSESSION = 100000011; $CMD_RESET = 100000012; $CMD_EMERGENCY_STOP = 100000027
$AgentCodeVersion = "1.4.0"; $BaseDir = $Root; $Global:EmergencyStopEngaged = $false
function Write-Log([string]$m, [string]$l = "INFO") { Write-Host ("    [agent log {0}] {1}" -f $l, $m) }
foreach ($st in $agentAst.EndBlock.Statements) { if ($st -is [System.Management.Automation.Language.AssignmentStatementAst] -and $st.Left.Extent.Text -match '^\$(Global:)?Kiosk') { . ([scriptblock]::Create($st.Extent.Text)) } }
foreach ($f in @($agentAst.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -match 'Kiosk' }, $true))) { . ([scriptblock]::Create($f.Extent.Text)) }
function Show-Intent { try { return ([IO.File]::ReadAllText($KioskIntentPath) | ConvertFrom-Json | Select-Object launcher, baySessionId, reason | ConvertTo-Json -Compress) } catch { return "(unreadable)" } }

$started = New-Object System.Collections.ArrayList
$shellProc = $null; $hold = $null
try {
    $now = (Get-Date).ToUniversalTime()
    if ($Scenario -eq "L1") {
        Set-Session "ACTIVE" "S-PAID"
        $null = Set-KioskIntentForCommand -CommandType $CMD_STARTSESSION -Mode "Start" -Payload @{ mode = "Start"; baySessionId = "S-PAID"; playEndUtc = $now.AddMinutes(45).ToString("yyyy-MM-ddTHH:mm:ssZ") }
    } else {
        Set-Session "ACTIVE" "S-A"
        $null = Set-KioskIntentForCommand -CommandType $CMD_STARTSESSION -Mode "Start" -Payload @{ mode = "Start"; baySessionId = "S-A"; playEndUtc = $now.AddMinutes(1).ToString("yyyy-MM-ddTHH:mm:ssZ") }
        Set-Session "ENDED" "S-A"
        $null = Set-KioskIntentForCommand -CommandType $CMD_ENDSESSION -Mode "End" -Payload @{ baySessionId = "S-A" } -SameSession $true
        Write-Host ("after A End: intent {0}" -f (Show-Intent))
        Set-Session "ACTIVE" "S-B"
        $hold = [IO.File]::Open($KioskIntentPath, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
        $r = Set-KioskIntentForCommand -CommandType $CMD_STARTSESSION -Mode "Start" -Payload @{ mode = "Start"; baySessionId = "S-B"; playEndUtc = $now.AddMinutes(60).ToString("yyyy-MM-ddTHH:mm:ssZ") }
        Write-Host ("B Start: written={0}; file still says {1}" -f $r.written, (Show-Intent))
    }
    $game = Start-Process -FilePath $LaunchExe -PassThru; [void]$started.Add($game)
    Write-Host ("paying member's launcher pid {0}" -f $game.Id)

    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = $ps51
    $psi.Arguments = ('-NoProfile -NonInteractive -WindowStyle Hidden -File "{0}" -Companion' -f $ShellCopy)
    $psi.UseShellExecute = $false; $psi.CreateNoWindow = $true
    $psi.EnvironmentVariables["PSExecutionPolicyPreference"] = "Bypass"
    if ($psi.EnvironmentVariables.ContainsKey("PSModulePath")) { $psi.EnvironmentVariables.Remove("PSModulePath") }
    $shellProc = [System.Diagnostics.Process]::Start($psi)
    Write-Host ("shell pid {0}" -f $shellProc.Id)
    Start-Sleep -Seconds 6

    if ($Scenario -eq "L1") {
        $null = Set-KioskIntentForCommand -CommandType $CMD_EMERGENCY_STOP -Mode "" -Payload (ConvertFrom-Json '{"action":"engage","reason":"verifier"}')
        $Global:EmergencyStopEngaged = $true; Start-Sleep -Seconds 3
        $null = Set-KioskIntentForCommand -CommandType $CMD_EMERGENCY_STOP -Mode "" -Payload (ConvertFrom-Json '{"action":"clear"}')
        $Global:EmergencyStopEngaged = $false
        $null = Set-KioskIntentForCommand -CommandType $CMD_RESET -Mode "" -Payload (ConvertFrom-Json '{"mode":"Full","reason":"BookingCanceled"}')
        Set-Session "READY" ""
        Write-Host ("e-stop engaged+cleared, then canceled-booking Reset (session.json READY): intent {0}" -f (Show-Intent))
        $t0 = Get-Date
        do { Start-Sleep -Milliseconds 500; $game.Refresh() } while (-not $game.HasExited -and ((Get-Date) - $t0).TotalSeconds -lt 45)
    } else {
        if ($Scenario -eq "L3") { Start-Sleep -Seconds 4; $null = Set-KioskIntentForCommand -CommandType $CMD_RESET -Mode "" -Payload (ConvertFrom-Json '{"mode":"Full","reason":"BookingCanceled"}'); Set-Session "READY" ""; Write-Host "canceled-booking Reset while B's write still fails: session.json READY" }
        $t0 = Get-Date
        do {
            Start-Sleep -Milliseconds 500; $game.Refresh()
            if (((Get-Date) - $t0).TotalSeconds -ge 40 -and $null -ne $hold) { $hold.Dispose(); $hold = $null; Write-Host "lock released at +40 s" }
            if ($null -eq $hold -and [int]((Get-Date) - $t0).TotalSeconds % 3 -eq 0) { [void](Test-KioskIntentIntegrity) }
        } while (-not $game.HasExited -and ((Get-Date) - $t0).TotalSeconds -lt 55)
        Write-Host ("after the window: pending={0}; intent {1}" -f $Global:KioskIntentPending, (Show-Intent))
    }
    $game.Refresh()
    Write-Host ("RESULT {0}: paying member's launcher {1} after {2:N1} s" -f $Scenario, $(if ($game.HasExited) { "ENDED" } else { "still running" }), ((Get-Date) - $t0).TotalSeconds)
    foreach ($l in @(Get-ChildItem -LiteralPath (Join-Path $Root "logs") -Filter "KioskShell-*.log")) { Write-Host "---- shell log"; Get-Content -LiteralPath $l.FullName | Select-Object -Last 10 | ForEach-Object { Write-Host ("  " + $_) } }
} finally {
    if ($null -ne $hold) { $hold.Dispose() }
    if ($null -ne $shellProc) { try { if (-not $shellProc.HasExited) { Stop-Process -Id $shellProc.Id -Force } } catch { } }
    foreach ($p in @($started)) { try { if (-not $p.HasExited) { Stop-Process -Id $p.Id -Force } } catch { } }
    Start-Sleep -Seconds 1
    Remove-Item -LiteralPath $Root -Recurse -Force -ErrorAction SilentlyContinue
}
