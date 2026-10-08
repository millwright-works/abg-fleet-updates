<#
Verifier live attack (2026-10-08): the shipped shell (companion copy, exactly as the builder's live suite builds it:
$BaseDir and the release-mode constant changed, nothing else) runs against an intent file written by the REAL agent
functions for: Start (member pays and plays) -> emergency stop engaged -> cleared (play resumes) -> Reset for another
canceled booking (the platform's exact payload). A stand-in launcher stands for the paying member's game. Question:
does the shell end it? Every process is stopped by the Id recorded here. Hyphens only.
#>
param([string]$Repo = "C:\aoc-wt\kiosk-attack", [string]$Scenario = "estop")
Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
$AgentScript = Join-Path $Repo "src\BayAgent\BayAgent.ps1"
$ShellScript = Join-Path $Repo "src\BayAgent\kiosk\ABG.KioskShell.ps1"
$ps51 = Join-Path $env:WINDIR "System32\WindowsPowerShell\v1.0\powershell.exe"

$Root = Join-Path $env:TEMP ("kiosk-verif-live-" + [guid]::NewGuid().ToString("N").Substring(0, 8))
foreach ($d in @("releases\1.4.0\kiosk", "current\kiosk", "state", "control", "logs", "edge-profile")) { New-Item -ItemType Directory -Force -Path (Join-Path $Root $d) | Out-Null }
function Set-Text([string]$p, [string]$t) { [IO.File]::WriteAllText($p, $t, (New-Object Text.UTF8Encoding($false))) }

# shell copy as the companion release would build it
$shipped = [IO.File]::ReadAllText($ShellScript)
$ShellCopy = Join-Path $Root "releases\1.4.0\kiosk\ABG.KioskShell.ps1"
Set-Text $ShellCopy ($shipped.Replace('$BaseDir = "C:\AllBirdies\BayAgent"', ('$BaseDir = "{0}"' -f $Root)).Replace('$KioskShellReleaseMode = "explorer"', '$KioskShellReleaseMode = "companion"'))
Set-Text (Join-Path $Root "current\kiosk\kiosk-policy.json") '{"schema":1,"mode":"companion","minShellBytes":4096}'

# stand-in launcher (its X only minimizes, like Uneekor in bench Part B)
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
    launcher = [ordered]@{ path = $LaunchExe; processName = $LaunchName }
    sessionDisplay = [ordered]@{ enabled = $false } }))

# the REAL agent intent writers, lifted by AST, pointed at this sandbox
$tk = $null; $er = $null
$agentAst = [System.Management.Automation.Language.Parser]::ParseFile($AgentScript, [ref]$tk, [ref]$er)
$CMD_UPDATESESSIONDISPLAY = 100000005; $CMD_STARTSESSION = 100000010; $CMD_ENDSESSION = 100000011; $CMD_RESET = 100000012; $CMD_EMERGENCY_STOP = 100000027
$AgentCodeVersion = "1.4.0"; $BaseDir = $Root; $Global:EmergencyStopEngaged = $false
function Write-Log([string]$m, [string]$l = "INFO") { Write-Host ("    [agent log {0}] {1}" -f $l, $m) }
foreach ($st in $agentAst.EndBlock.Statements) { if ($st -is [System.Management.Automation.Language.AssignmentStatementAst] -and $st.Left.Extent.Text -match '^\$(Global:)?Kiosk') { . ([scriptblock]::Create($st.Extent.Text)) } }
foreach ($f in @($agentAst.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -match 'Kiosk' }, $true))) { . ([scriptblock]::Create($f.Extent.Text)) }

$started = New-Object System.Collections.ArrayList
$shellProc = $null
try {
    $now = (Get-Date).ToUniversalTime()
    $null = Set-KioskIntentForCommand -CommandType $CMD_STARTSESSION -Mode "Start" -Payload @{ mode = "Start"; baySessionId = "S-PAID"; playEndUtc = $now.AddMinutes(45).ToString("yyyy-MM-ddTHH:mm:ssZ") }
    $game = Start-Process -FilePath $LaunchExe -PassThru; [void]$started.Add($game)
    Write-Host ("paying member's launcher pid {0} (Start written: {1})" -f $game.Id, [IO.File]::ReadAllText($KioskIntentPath).Replace("`r`n", " "))

    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = $ps51
    $psi.Arguments = ('-NoProfile -NonInteractive -WindowStyle Hidden -File "{0}" -Companion' -f $ShellCopy)
    $psi.UseShellExecute = $false; $psi.CreateNoWindow = $true
    $psi.EnvironmentVariables["PSExecutionPolicyPreference"] = "Bypass"
    if ($psi.EnvironmentVariables.ContainsKey("PSModulePath")) { $psi.EnvironmentVariables.Remove("PSModulePath") }
    $shellProc = [System.Diagnostics.Process]::Start($psi)
    Write-Host ("shell pid {0}" -f $shellProc.Id)
    Start-Sleep -Seconds 8
    $game.Refresh(); Write-Host ("t+8s under 'wanted': launcher alive = {0}" -f (-not $game.HasExited))

    if ($Scenario -eq "estop") {
        $null = Set-KioskIntentForCommand -CommandType $CMD_EMERGENCY_STOP -Mode "" -Payload (ConvertFrom-Json '{"action":"engage","reason":"verifier"}')
        $Global:EmergencyStopEngaged = $true
        Start-Sleep -Seconds 4
        $null = Set-KioskIntentForCommand -CommandType $CMD_EMERGENCY_STOP -Mode "" -Payload (ConvertFrom-Json '{"action":"clear"}')
        $Global:EmergencyStopEngaged = $false
        Write-Host "emergency stop engaged and cleared; member resumes"
    }
    Start-Sleep -Seconds 4
    $null = Set-KioskIntentForCommand -CommandType $CMD_RESET -Mode "" -Payload (ConvertFrom-Json '{"mode":"Full","reason":"BookingCanceled"}')
    Write-Host ("Reset for another canceled booking: intent now {0}" -f [IO.File]::ReadAllText($KioskIntentPath).Replace("`r`n", " "))
    $t0 = Get-Date
    $deadline = $t0.AddSeconds(45)
    do { Start-Sleep -Milliseconds 500; $game.Refresh() } while (-not $game.HasExited -and (Get-Date) -lt $deadline)
    $game.Refresh()
    Write-Host ("RESULT: paying member's launcher {0} {1:N1} s after the Reset" -f $(if ($game.HasExited) { "ENDED" } else { "still running" }), ((Get-Date) - $t0).TotalSeconds)
    $logs = @(Get-ChildItem -LiteralPath (Join-Path $Root "logs") -Filter "KioskShell-*.log")
    foreach ($l in $logs) { Write-Host "---- shell log"; Get-Content -LiteralPath $l.FullName | Select-Object -Last 12 | ForEach-Object { Write-Host ("  " + $_) } }
} finally {
    if ($null -ne $shellProc) { try { if (-not $shellProc.HasExited) { Stop-Process -Id $shellProc.Id -Force } } catch { } }
    foreach ($p in @($started)) { try { if (-not $p.HasExited) { Stop-Process -Id $p.Id -Force } } catch { } }
    Start-Sleep -Seconds 1
    Remove-Item -LiteralPath $Root -Recurse -Force -ErrorAction SilentlyContinue
}
