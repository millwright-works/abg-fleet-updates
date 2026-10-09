<#
BayAgent.KioskShell.Live.Tests.ps1 (A0.363, BayAgent 1.4.0)

WHY THIS EXISTS
  The unit suite lifts the shell's functions by AST. That cannot show the SHIPPED FILE starting, running its loop,
  keeping state across ticks, writing its heartbeat and log, or exiting when it should (the AG-48 lesson: 230 green
  tests and the first bay died in a second). This suite installs the shipped ABG.KioskShell.ps1 into a sandbox with
  exactly one literal repointed ($BaseDir), proves the copy is the shipped file, and starts it in a real Windows
  PowerShell 5.1 with THE ARGUMENT LIST BayAgent builds (Get-KioskShellArgumentList, lifted from BayAgent.ps1), so the
  test cannot drift from what a bay runs. The golf launcher and the wall browser are two tiny WinForms programs this
  suite builds; every assertion reads the shell's own heartbeat, its log, or the real windows.

WHAT IT PROVES
  S0  the copy differs from the shipped file in exactly the $BaseDir line
  S1  heartbeat written; supervising under a companion policy
  S2  no intent: the launcher is NOT started; the wall IS kept up (single-screen PC, nothing wanted)
  S3  intent wanted: launcher started, placed maximized on the control screen; on this one-screen PC the wall is moved
      aside (minimized), never closed
  S4  the launcher is stopped by its id (a member closing it): restarted within seconds, new id
  S5  intent flips to unmanaged: the running launcher is NOT closed; stopped by id, it is NOT restarted; the wall comes
      back from aside
  S5b ACCEPTANCE (Part B Test 11): under a "closed" intent (after End) a launcher a member relaunches is ended, after
      the 15 s grace, even though its close only minimizes it; a second relaunch is ended again
  S6  an expired intent and a garbage intent: no restart
  S7  a second copy exits 0 at once and starts nothing
  S8  the policy flips to explorer: the shell exits 0, leaving the launcher and the wall running
  S9  the kill switch: a fresh companion shell exits 0
  S10 no agent-config.json: the shell runs on defaults and says so
  S11 started WITHOUT -Companion (this release has no shell mode): it supervises nothing, never exits, starts nothing
  S12 induced failures (unstartable programs): the shell DEGRADES (supervision stops, heartbeat says why) and stays up
  S13 the log holds state changes only (no per-tick lines)

WHAT IT CANNOT PROVE (bench items, named in the report): AllSigned on the bay-signed copy; Windows' behavior when a
custom Winlogon shell exits; real Edge kiosk placement on two screens; touch mapping; Uneekor without Explorer.

RUN (from the repo root; Windows PowerShell 5.1 or PowerShell 7; about 3 minutes)
  powershell -NoProfile -ExecutionPolicy Bypass -File tests\BayAgent.KioskShell.Live.Tests.ps1
Exit code 0 = all assertions passed. Every process this suite starts is stopped by its id. Hyphens only in comments.
#>
[CmdletBinding()]
param([string]$ShellScript = "", [string]$AgentScript = "")

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
if ([string]::IsNullOrWhiteSpace($ShellScript)) { $ShellScript = Join-Path $PSScriptRoot "..\src\BayAgent\kiosk\ABG.KioskShell.ps1" }
if ([string]::IsNullOrWhiteSpace($AgentScript)) { $AgentScript = Join-Path $PSScriptRoot "..\src\BayAgent\BayAgent.ps1" }
$ShellScript = (Resolve-Path $ShellScript).Path
$AgentScript = (Resolve-Path $AgentScript).Path

$script:Pass = 0; $script:Fail = 0; $script:Failures = @()
function Assert-True([bool]$cond, [string]$msg) {
    if ($cond) { $script:Pass++; Write-Host "  PASS  $msg" }
    else { $script:Fail++; $script:Failures += $msg; Write-Host "  FAIL  $msg" -ForegroundColor Red }
}
function Section([string]$name) { Write-Host ""; Write-Host "== $name" -ForegroundColor Cyan }

# ---------------------------------------------------------------- lift the agent's command-line builder
$tk = $null; $er = $null
$agentAst = [System.Management.Automation.Language.Parser]::ParseFile($AgentScript, [ref]$tk, [ref]$er)
$argDef = @($agentAst.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq "Get-KioskShellArgumentList" }, $true))
if ($argDef.Count -ne 1) { throw "Get-KioskShellArgumentList not found in BayAgent.ps1" }
. ([scriptblock]::Create($argDef[0].Extent.Text))

# ---------------------------------------------------------------- install
$Root = Join-Path $env:TEMP ("bayagent-kiosk-live-" + [guid]::NewGuid().ToString("N").Substring(0, 8))
$RelKiosk = Join-Path $Root "releases\1.4.0\kiosk"
foreach ($d in @($RelKiosk, (Join-Path $Root "current\kiosk"), (Join-Path $Root "state"), (Join-Path $Root "control"), (Join-Path $Root "logs"), (Join-Path $Root "edge-profile"))) { New-Item -ItemType Directory -Force -Path $d | Out-Null }
$ShellCopy = Join-Path $RelKiosk "ABG.KioskShell.ps1"
$needle = '$BaseDir = "C:\AllBirdies\BayAgent"'
$shipped = [IO.File]::ReadAllText($ShellScript)
if (-not $shipped.Contains($needle)) { throw "the BaseDir literal is not in the shell" }
# Two installs of the shipped file. $ShellCopy is built AS THE COMPANION RELEASE would be (the signed mode constant set to
# companion; security review 2026-10-08: the policy file alone can never turn the shell on). $ShellCopyAsShipped is the
# dormant 1.4.0 file with only $BaseDir repointed (S0b: a companion policy file must not wake it).
$modeNeedle = '$KioskShellReleaseMode = "explorer"'
if (-not $shipped.Contains($modeNeedle)) { throw "the release-mode constant is not in the shell as shipped (explorer)" }
[IO.File]::WriteAllText($ShellCopy, $shipped.Replace($needle, ('$BaseDir = "{0}"' -f $Root)).Replace($modeNeedle, '$KioskShellReleaseMode = "companion"'), (New-Object Text.UTF8Encoding($false)))
$ShellCopyAsShipped = Join-Path $RelKiosk "ABG.KioskShell.asshipped.ps1"
[IO.File]::WriteAllText($ShellCopyAsShipped, $shipped.Replace($needle, ('$BaseDir = "{0}"' -f $Root)), (New-Object Text.UTF8Encoding($false)))
$PolicyPath = Join-Path $Root "current\kiosk\kiosk-policy.json"
$IntentPath = Join-Path $Root "state\kiosk-intent.json"
$HbPath = Join-Path $Root "state\kiosk-shell.json"
$KillPath = Join-Path $Root "control\kiosk.off"
$CfgPath = Join-Path $Root "agent-config.json"
function Set-Text([string]$p, [string]$t) { [IO.File]::WriteAllText($p, $t, (New-Object Text.UTF8Encoding($false))) }
function Set-Policy([string]$mode) { Set-Text $PolicyPath ("{`"schema`":1,`"mode`":`"$mode`",`"minShellBytes`":4096}") }
function Set-Intent([string]$launcher, $untilUtc, [switch]$NoSessionJson) {
    # As the agent does at Start: session.json says the session runs (ACTIVE) before the intent says wanted.
    if ($launcher -eq "wanted" -and -not $NoSessionJson) { Set-SessionJson "ACTIVE" "live" $untilUtc }
    $u = $(if ($null -ne $untilUtc) { '"' + ([DateTime]$untilUtc).ToString("yyyy-MM-ddTHH:mm:ssZ") + '"' } else { "null" })
    Set-Text $IntentPath ("{`"schema`":1,`"launcher`":`"$launcher`",`"untilUtc`":$u,`"baySessionId`":`"live`",`"writtenUtc`":`"" + (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ") + "`"}")
}
function Read-Hb { try { return ([IO.File]::ReadAllText($HbPath) | ConvertFrom-Json) } catch { return $null } }

# ---------------------------------------------------------------- the two stand-in programs (built by Windows PowerShell 5.1)
$suffix = [guid]::NewGuid().ToString("N").Substring(0, 6)
$LaunchName = "AbgKsLaunch" + $suffix
$WallName = "AbgKsWall" + $suffix
$buildScript = Join-Path $Root "build-stubs.ps1"
Set-Text $buildScript @'
param([string]$OutDir, [string]$NameA, [string]$NameB)
$ErrorActionPreference = "Stop"
$src = @"
using System;
using System.Windows.Forms;
public static class AbgKsStub {
    [STAThread]
    public static void Main(string[] args) {
        var f = new Form();
        f.Text = "Kiosk shell live test stand-in (closes itself in 10 minutes)";
        f.Width = 360; f.Height = 120;
        bool noClose = args.Length > 0 && args[0] == "noclose";
        bool leaving = false;
        // "noclose": like the Uneekor launcher measured in bench Part B, its X (a window close) only minimizes it.
        f.FormClosing += (s, e) => { if (noClose && !leaving) { e.Cancel = true; f.WindowState = FormWindowState.Minimized; } };
        var quit = new Timer();
        quit.Interval = 600000;
        quit.Tick += (s, e) => { leaving = true; Application.Exit(); };
        quit.Start();
        Application.Run(f);
    }
}
"@
foreach ($n in @($NameA, $NameB)) {
    Add-Type -TypeDefinition $src -ReferencedAssemblies System.Windows.Forms -OutputAssembly (Join-Path $OutDir ($n + ".exe")) -OutputType WindowsApplication
}
'@
$ps51 = Join-Path $env:WINDIR "System32\WindowsPowerShell\v1.0\powershell.exe"
& $ps51 -NoProfile -ExecutionPolicy Bypass -File $buildScript -OutDir $Root -NameA $LaunchName -NameB $WallName | Out-Null
$LaunchExe = Join-Path $Root ($LaunchName + ".exe")
$WallExe = Join-Path $Root ($WallName + ".exe")
function Write-Config([string]$launcherPath, [string]$wallPath) {
    $c = [ordered]@{
        launcher = [ordered]@{ path = $launcherPath; args = "noclose"; processName = $LaunchName }
        sessionDisplay = [ordered]@{ mode = "kiosk"; url = "about:blank"; profileDir = (Join-Path $Root "edge-profile"); edgePath = $wallPath }
        sessionJsonPath = $SessionJsonPath
    }
    Set-Text $CfgPath (ConvertTo-Json -InputObject $c -Depth 5)
}
$SessionJsonPath = Join-Path $Root "session.json"
function Set-SessionJson([string]$status, [string]$sid, $endUtc) {
    # What BayAgent's Write-SessionFiles leaves for the shell's second check (attack RF1/RF2).
    Set-Text $SessionJsonPath (ConvertTo-Json -InputObject ([ordered]@{ status = $status; baySessionId = $sid; sessionEndUtc = ([DateTime]$endUtc).ToString("yyyy-MM-ddTHH:mm:ssZ") }))
}
Write-Config $LaunchExe $WallExe

# The agent's REAL intent writers (lifted by AST, BaseDir pointed at this sandbox): S5d drives the intent exactly as the
# command handlers do.
$BaseDir = $Root
$Global:EmergencyStopEngaged = $false
function Write-Log { param([string]$Message, [string]$Level = "INFO") }
foreach ($st in @($agentAst.EndBlock.Statements)) {
    if ($st -isnot [System.Management.Automation.Language.AssignmentStatementAst]) { continue }
    if ($st.Left.Extent.Text -match '^\$(CMD_|Kiosk)' -or $st.Left.Extent.Text -match '^\$Global:Kiosk') { . ([scriptblock]::Create($st.Extent.Text)) }
}
foreach ($fn in @("Get-KioskProp", "Read-KioskJsonFile", "ConvertTo-KioskUtc", "Get-KioskLauncherWanted", "Get-KioskIntentForCommand", "Write-KioskIntentText", "Write-KioskIntent", "Test-KioskIntentIntegrity", "Set-KioskIntentForCommand")) {
    $fd = @($agentAst.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq $fn }, $true))
    if ($fd.Count -ne 1) { throw "$fn not found in BayAgent.ps1" }
    . ([scriptblock]::Create($fd[0].Extent.Text))
}

# ---------------------------------------------------------------- native window probes
Add-Type -AssemblyName System.Windows.Forms
if (-not ("AbgKsProbe" -as [type])) {
Add-Type @"
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
public static class AbgKsProbe {
    public delegate bool EnumWindowsProc(IntPtr h, IntPtr l);
    [DllImport("user32.dll")] static extern bool EnumWindows(EnumWindowsProc cb, IntPtr l);
    [DllImport("user32.dll")] static extern uint GetWindowThreadProcessId(IntPtr h, out uint p);
    [DllImport("user32.dll")] static extern bool IsWindowVisible(IntPtr h);
    [DllImport("user32.dll")] public static extern bool IsZoomed(IntPtr h);
    [DllImport("user32.dll")] public static extern bool IsIconic(IntPtr h);
    [DllImport("user32.dll")] public static extern bool ShowWindow(IntPtr h, int c);
    public static IntPtr WindowOf(int pid) {
        IntPtr found = IntPtr.Zero;
        EnumWindowsProc cb = delegate (IntPtr h, IntPtr l) {
            if (!IsWindowVisible(h)) { return true; }
            uint o; GetWindowThreadProcessId(h, out o);
            if (o == (uint)pid) { found = h; return false; }
            return true;
        };
        EnumWindows(cb, IntPtr.Zero); GC.KeepAlive(cb);
        return found;
    }
}
"@
}

$ShellPids = New-Object System.Collections.ArrayList
function Start-Shell([switch]$NoCompanion, [switch]$AsShipped) {
    $argLine = Get-KioskShellArgumentList $(if ($AsShipped) { $ShellCopyAsShipped } else { $ShellCopy })
    if ($NoCompanion) { $argLine = $argLine.Replace(" -Companion", "") }
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = $ps51
    $psi.Arguments = $argLine
    $psi.UseShellExecute = $false
    $psi.CreateNoWindow = $true
    # Stand-in for the bay's AllSigned: the copy is unsigned, so this child runs with Bypass (the one difference, named
    # in the header). PSModulePath is removed so a 5.1 child of PowerShell 7 can load its own modules.
    $psi.EnvironmentVariables["PSExecutionPolicyPreference"] = "Bypass"
    if ($psi.EnvironmentVariables.ContainsKey("PSModulePath")) { $psi.EnvironmentVariables.Remove("PSModulePath") }
    $p = [System.Diagnostics.Process]::Start($psi)
    [void]$ShellPids.Add($p)
    return $p
}
function Wait-Until([scriptblock]$cond, [int]$seconds) {
    $deadline = (Get-Date).AddSeconds($seconds)
    do { if (& $cond) { return $true }; Start-Sleep -Milliseconds 400 } while ((Get-Date) -lt $deadline)
    return [bool](& $cond)
}
function Get-Ours([string]$name) { return @(Get-Process -Name $name -ErrorAction SilentlyContinue) }
function Stop-Ours([string]$name) { foreach ($p in @(Get-Ours $name)) { try { Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue } catch { } } }
function Stop-Shells { foreach ($p in @($ShellPids)) { try { if (-not $p.HasExited) { Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue } } catch { } } }
function Get-LogText { $t = ""; foreach ($f in @(Get-ChildItem -LiteralPath (Join-Path $Root "logs") -Filter "KioskShell-*.log" -ErrorAction SilentlyContinue)) { $t += [IO.File]::ReadAllText($f.FullName) }; return $t }

try {
    Section "S0 the installed copy is the shipped shell with one literal repointed"
    $a = [IO.File]::ReadAllLines($ShellScript); $b = [IO.File]::ReadAllLines($ShellCopy)
    Assert-True ($a.Count -eq $b.Count) "line count identical ($($a.Count))"
    $diff = @(); for ($i = 0; $i -lt $a.Count; $i++) { if ($a[$i] -ne $b[$i]) { $diff += $i } }
    Assert-True ($diff.Count -eq 2 -and $a[$diff[0]].StartsWith('$BaseDir =') -and $b[$diff[1]] -eq '$KioskShellReleaseMode = "companion"') "exactly two lines differ: `$BaseDir, and the release-mode constant set as the companion release sets it"
    $c = [IO.File]::ReadAllLines($ShellCopyAsShipped)
    $diff2 = @(); for ($i = 0; $i -lt $a.Count; $i++) { if ($a[$i] -ne $c[$i]) { $diff2 += $i } }
    Assert-True ($c.Count -eq $a.Count -and $diff2.Count -eq 1 -and $a[$diff2[0]].StartsWith('$BaseDir =')) "the as-shipped copy differs in the `$BaseDir line only"
    function Get-FnMap([string]$p) { $t = $null; $e = $null; $x = [System.Management.Automation.Language.Parser]::ParseFile($p, [ref]$t, [ref]$e); return @($x.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $true) | ForEach-Object { "{0}@{1}" -f $_.Name, $_.Extent.StartLineNumber }) }
    Assert-True (((Get-FnMap $ShellScript) -join "|") -eq ((Get-FnMap $ShellCopy) -join "|")) "every function has the same name, order and line in both"
    Assert-True ((Test-Path -LiteralPath $LaunchExe) -and (Test-Path -LiteralPath $WallExe)) "the two stand-in programs were built"
    $screenCount = @([System.Windows.Forms.Screen]::AllScreens).Count
    Write-Host ("        this PC has {0} screen(s)" -f $screenCount) -ForegroundColor DarkGray

    Section "S0b AUTHORITY: the shell as shipped (built dormant) is not woken by a companion policy file (security review)"
    Set-Policy "companion"
    Set-Intent "wanted" ((Get-Date).ToUniversalTime().AddMinutes(10))
    $sh0 = Start-Shell -AsShipped
    Assert-True ($sh0.WaitForExit(20000) -and $sh0.ExitCode -eq 0) "it exits 0 (Explorer is the desktop; the release says explorer)"
    Assert-True (@(Get-Ours $LaunchName).Count -eq 0 -and @(Get-Ours $WallName).Count -eq 0) "...having started no launcher (the intent said wanted) and no wall"
    $hb0 = Read-Hb
    Assert-True ($null -ne $hb0 -and $hb0.supervising -eq $false -and $hb0.releaseMode -eq "explorer" -and [string]$hb0.stopReason -match "not implemented by this release") "...and its last heartbeat says why"
    # If it did NOT exit (the insecure form), stop it and what it started, so the scenarios below run on a clean bay.
    if (-not $sh0.HasExited) { Stop-Process -Id $sh0.Id -Force -ErrorAction SilentlyContinue; [void]$sh0.WaitForExit(5000) }
    Stop-Ours $LaunchName; Stop-Ours $WallName
    Set-Intent "unmanaged" $null

    Section "S1/S2 companion policy, no intent: heartbeat, no launcher, the wall kept up"
    Set-Policy "companion"
    $sh = Start-Shell
    Assert-True (Wait-Until { $h = Read-Hb; $null -ne $h -and $h.supervising -eq $true } 15) "heartbeat written and supervising"
    $h = Read-Hb
    Assert-True ($null -ne $h -and $h.role -eq "companion" -and $h.policyMode -eq "companion" -and $h.pid -eq $sh.Id -and $h.version -eq "1.5.0") "role companion, policy companion, its own pid, version 1.5.0"
    Assert-True ($null -ne $h -and $h.sha256 -match '^[0-9a-f]{64}$') "it reports the sha256 of the file it runs"
    Start-Sleep -Seconds 6
    Assert-True (@(Get-Ours $LaunchName).Count -eq 0) "no intent: the launcher was not started (6 s)"
    Assert-True (Wait-Until { @(Get-Ours $WallName).Count -ge 1 } 25) "the wall program was started (after the screens were stable 10 s)"
    $wallPid = $(if (@(Get-Ours $WallName).Count) { @(Get-Ours $WallName)[0].Id } else { 0 })
    Assert-True ($wallPid -gt 0 -and ((Get-CimInstance Win32_Process -Filter "ProcessId=$wallPid").CommandLine -like "*$(Join-Path $Root 'edge-profile')*")) "...with the wall's profile folder on its command line (how BayAgent finds it too)"

    Section "S3 intent wanted: started and placed; one screen: the wall stands aside"
    Set-Intent "wanted" ((Get-Date).ToUniversalTime().AddMinutes(10))
    Assert-True (Wait-Until { @(Get-Ours $LaunchName).Count -eq 1 } 10) "the launcher was started within 10 s"
    $l1 = @(Get-Ours $LaunchName)
    $l1Id = $(if ($l1.Count) { $l1[0].Id } else { 0 })
    Assert-True (Wait-Until { $w = [AbgKsProbe]::WindowOf($l1Id); $w -ne [IntPtr]::Zero -and [AbgKsProbe]::IsZoomed($w) } 20) "...and maximized on the control screen"
    if ($screenCount -eq 1) {
        Assert-True (Wait-Until { $w = [AbgKsProbe]::WindowOf($wallPid); $w -ne [IntPtr]::Zero -and [AbgKsProbe]::IsIconic($w) } 20) "one screen and the member needs the launcher: the wall is minimized (aside)"
        Assert-True (@(Get-Ours $WallName).Count -ge 1) "...and still running (never closed)"
        # Something else (BayAgent's routing at Warn5, a person) restores the wall over the only screen: back aside.
        $ww = [AbgKsProbe]::WindowOf($wallPid)
        if ($ww -ne [IntPtr]::Zero) { [void][AbgKsProbe]::ShowWindow($ww, 9) }
        Assert-True (Wait-Until { $w = [AbgKsProbe]::WindowOf($wallPid); $w -ne [IntPtr]::Zero -and -not [AbgKsProbe]::IsIconic($w) } 3) "precondition: the test restored the wall window"
        Assert-True (Wait-Until { $w = [AbgKsProbe]::WindowOf($wallPid); $w -ne [IntPtr]::Zero -and [AbgKsProbe]::IsIconic($w) } 20) "a wall restored over the only screen is moved aside again within 20 s"
    } else {
        Assert-True ((Read-Hb).wall.plan -eq "show") "two or more screens: the wall stays on its own screen"
    }
    Assert-True ((Read-Hb).launcher.wanted -eq $true) "heartbeat says the launcher is wanted"

    Section "S4 a member closes the launcher mid-session: it comes back"
    Stop-Process -Id $l1Id -Force
    Assert-True (Wait-Until { @(Get-Ours $LaunchName | Where-Object { $_.Id -ne $l1Id }).Count -eq 1 } 10) "restarted within 10 s with a new id"

    Section "S5 unmanaged (a Start with no end, an emergency stop): hands off, neither closed nor reopened"
    Set-Intent "unmanaged" $null
    # session.json says no session runs, so only the intent value keeps the closer away (no second layer to hide behind).
    Set-SessionJson "ENDED" "live" ((Get-Date).ToUniversalTime().AddMinutes(-1))
    Start-Sleep -Seconds 20
    $l2 = @(Get-Ours $LaunchName)
    Assert-True ($l2.Count -eq 1) "20 s after 'unmanaged' (session.json ENDED) the running launcher is still running"
    if ($screenCount -eq 1) {
        Assert-True (Wait-Until { $w = [AbgKsProbe]::WindowOf($wallPid); $w -ne [IntPtr]::Zero -and -not [AbgKsProbe]::IsIconic($w) } 20) "the wall comes back from aside"
    }
    if ($l2.Count) { Stop-Process -Id $l2[0].Id -Force }
    Start-Sleep -Seconds 8
    Assert-True (@(Get-Ours $LaunchName).Count -eq 0) "stopped while unmanaged: NOT restarted (8 s)"

    Section "S5b ACCEPTANCE (bench Part B Test 11): after End, a member who relaunches the launcher is closed again"
    # EndSession writes "closed" and closes the launcher itself; the stand-in, like Uneekor, only minimizes on a close.
    Set-SessionJson "ENDED" "live" ((Get-Date).ToUniversalTime().AddMinutes(-1))
    Set-Intent "closed" $null
    $m1 = Start-Process -FilePath $LaunchExe -ArgumentList "noclose" -PassThru
    # 13 s: past the polite-close-plus-8-s an ungraced closer would need (so its absence is visible), inside the 15 s grace.
    Start-Sleep -Seconds 13
    Assert-True (-not $m1.HasExited) "within the 15 s grace after End (EndSession's own close goes first) the shell has not acted"
    Assert-True (Wait-Until { $m1.Refresh(); $m1.HasExited } 40) "then the relaunched launcher is ended (asked to close, then ended after 8 s: its X only minimizes)"
    $m2 = Start-Process -FilePath $LaunchExe -ArgumentList "noclose" -PassThru
    Assert-True (Wait-Until { $m2.Refresh(); $m2.HasExited } 20) "relaunched again later: ended again within 20 s"
    Assert-True ((Get-LogText) -match "running with no session \(intent closed\)") "the log says why"
    Assert-True (@(Get-Ours $LaunchName).Count -eq 0) "and the shell itself started nothing"

    Section "S5c attack RF2 (live): A's closed is still on disk while B pays and plays: B's game is NOT ended"
    # B's Start wrote session.json (ACTIVE, s-B) but its intent write failed, so A's closed (written long ago) remains.
    Set-Text $IntentPath ("{`"schema`":1,`"launcher`":`"closed`",`"untilUtc`":null,`"baySessionId`":`"s-A`",`"writtenUtc`":`"" + (Get-Date).ToUniversalTime().AddMinutes(-10).ToString("yyyy-MM-ddTHH:mm:ssZ") + "`"}")
    Set-SessionJson "ACTIVE" "s-B" ((Get-Date).ToUniversalTime().AddMinutes(45))
    $mB = Start-Process -FilePath $LaunchExe -ArgumentList "noclose" -PassThru
    Start-Sleep -Seconds 35
    Assert-True (-not $mB.HasExited) "B's launcher (45 paid minutes left) is still running 35 s later"
    $hbC = Read-Hb
    Assert-True ($null -ne $hbC -and [string]$hbC.launcher.closeHeld -match "s-B") "the heartbeat says the close is held and why ($(if ($hbC) { $hbC.launcher.closeHeld }))"
    if (-not $mB.HasExited) { Stop-Process -Id $mB.Id -Force -ErrorAction SilentlyContinue }

    Section "S5e source divergence (live): the intent FILE still says wanted, but session.json says the session ended"
    # The End's intent write failed (the agent's own decision is closed, pending); session.json was written ENDED first.
    Set-Intent "wanted" ((Get-Date).ToUniversalTime().AddMinutes(10)) -NoSessionJson
    Set-SessionJson "ENDED" "live" ((Get-Date).ToUniversalTime().AddMinutes(-1))
    Start-Sleep -Seconds 10
    Assert-True (@(Get-Ours $LaunchName).Count -eq 0) "no launcher is (re)started for a session session.json says ended"
    $hbE = Read-Hb
    Assert-True ($null -ne $hbE -and $hbE.launcher.wanted -eq $false -and [string]$hbE.launcher.reason -match "no restart") "the heartbeat says why ($(if ($hbE) { $hbE.launcher.reason }))"
    Set-Intent "unmanaged" $null

    Section "S5d attack RF1 (live, the agent's real intent writers): e-stop engage and clear, then a canceled booking's Reset"
    $Global:KioskIntentExpectedText = $null
    $endD = (Get-Date).ToUniversalTime().AddMinutes(45)
    $payD = [pscustomobject]@{ mode = "Start"; baySessionId = "s-D"; playEndUtc = $endD.ToString("yyyy-MM-ddTHH:mm:ssZ") }
    $wS = Set-KioskIntentForCommand -CommandType $CMD_STARTSESSION -Mode "Start" -Payload $payD
    Set-SessionJson "ACTIVE" "s-D" $endD
    Assert-True ($null -ne $wS -and $wS.launcher -eq "wanted" -and $wS.written) "Start s-D: wanted, written by the agent's own function"
    $mD = @(Get-Ours $LaunchName)
    Assert-True (Wait-Until { @(Get-Ours $LaunchName).Count -eq 1 } 10) "the shell started the member's launcher"
    [void](Set-KioskIntentForCommand -CommandType $CMD_EMERGENCY_STOP -Mode "" -Payload ([pscustomobject]@{ action = "engage" }))
    [void](Set-KioskIntentForCommand -CommandType $CMD_EMERGENCY_STOP -Mode "" -Payload ([pscustomobject]@{ action = "clear" }))
    $rR = Set-KioskIntentForCommand -CommandType $CMD_RESET -Mode "" -Payload ([pscustomobject]@{ mode = "Full"; reason = "BookingCanceled" })
    Assert-True ($null -eq $rR) "the Reset changed nothing"
    $dPid = $(if (@(Get-Ours $LaunchName).Count) { @(Get-Ours $LaunchName)[0].Id } else { 0 })
    Start-Sleep -Seconds 35
    Assert-True ($dPid -gt 0 -and @(Get-Ours $LaunchName | Where-Object { $_.Id -eq $dPid }).Count -eq 1) "35 s after the Reset the paying member's launcher is still the same running process"
    Stop-Ours $LaunchName
    Set-Intent "unmanaged" $null

    Section "S6 an expired intent and a garbage intent restart nothing"
    Set-Intent "wanted" ((Get-Date).ToUniversalTime().AddSeconds(-5))
    Start-Sleep -Seconds 6
    Assert-True (@(Get-Ours $LaunchName).Count -eq 0) "expired: not started"
    Set-Text $IntentPath "{ this is not json"
    Start-Sleep -Seconds 6
    Assert-True (@(Get-Ours $LaunchName).Count -eq 0) "garbage: not started"
    Set-Text $IntentPath "{`"schema`":1,`"launcher`":`"wanted`",`"untilUtc`":`"2099-01-01T00:00:00`"}"
    Start-Sleep -Seconds 6
    Assert-True (@(Get-Ours $LaunchName).Count -eq 0) "an untilUtc without a zone: not started"

    Section "S7 a second copy exits at once"
    $dup = Start-Shell
    Assert-True ($dup.WaitForExit(15000) -and $dup.ExitCode -eq 0) "the second copy exited 0"
    Assert-True (-not $sh.HasExited) "the first copy is still running"
    Assert-True ((Get-LogText) -match "another kiosk shell already runs in this session") "...and the log says why"

    Section "S8 the policy flips to explorer: the shell exits and leaves things as they are"
    Set-Intent "wanted" ((Get-Date).ToUniversalTime().AddMinutes(10))
    Assert-True (Wait-Until { @(Get-Ours $LaunchName).Count -eq 1 } 10) "precondition: the launcher is running"
    Set-Policy "explorer"
    Assert-True ($sh.WaitForExit(15000)) "the shell exited within 15 s"
    Assert-True ($sh.HasExited -and $sh.ExitCode -eq 0) "...with code 0"
    Assert-True (@(Get-Ours $LaunchName).Count -eq 1 -and @(Get-Ours $WallName).Count -ge 1) "the launcher and the wall are still running (the shell closes nothing)"
    $hbEnd = Read-Hb
    Assert-True ($null -ne $hbEnd -and $hbEnd.stopping -eq $true -and [string]$hbEnd.stopReason -match "explorer") "its last heartbeat says it stopped and why"

    Section "S9 the kill switch"
    Set-Policy "companion"
    Set-Text $KillPath ""
    $sh2 = Start-Shell
    Assert-True ($sh2.WaitForExit(20000) -and $sh2.ExitCode -eq 0) "a companion shell with control\kiosk.off present exits 0"
    Remove-Item -LiteralPath $KillPath -Force
    Stop-Ours $LaunchName

    Section "S10 no agent-config.json: defaults, and it says so"
    Remove-Item -LiteralPath $CfgPath -Force
    Set-Intent "unmanaged" $null
    $sh3 = Start-Shell
    Assert-True (Wait-Until { $h = Read-Hb; $null -ne $h -and $h.pid -eq $sh3.Id -and [string]$h.config -match "defaults" } 15) "running, heartbeat says the config is defaults"
    Start-Sleep -Seconds 4
    Assert-True (-not $sh3.HasExited) "...and still running"
    Stop-Process -Id $sh3.Id -Force -ErrorAction SilentlyContinue
    Write-Config $LaunchExe $WallExe

    Section "S11 started without -Companion: supervises nothing, never exits"
    Set-Intent "wanted" ((Get-Date).ToUniversalTime().AddMinutes(10))
    $sh4 = Start-Shell -NoCompanion
    Assert-True (Wait-Until { $h = Read-Hb; $null -ne $h -and $h.pid -eq $sh4.Id } 15) "heartbeat written"
    $h4 = Read-Hb
    Assert-True ($h4.supervising -eq $false -and $h4.role -eq "unsupported") "not supervising; role unsupported"
    Start-Sleep -Seconds 8
    Assert-True (-not $sh4.HasExited) "still running after 8 s (a Windows shell that exits may sign the user out)"
    Assert-True (@(Get-Ours $LaunchName).Count -eq 0) "and it started no launcher, though the intent says wanted"
    Stop-Process -Id $sh4.Id -Force -ErrorAction SilentlyContinue

    Section "S12 induced failures: the shell degrades and stays up"
    Stop-Ours $WallName
    $bad1 = Join-Path $Root "not-a-program-1.exe"; Set-Text $bad1 "this is text, not a program"
    $bad2 = Join-Path $Root "not-a-program-2.exe"; Set-Text $bad2 "this is text, not a program"
    Write-Config $bad1 $bad2
    Set-Intent "unmanaged" $null
    $sh5 = Start-Shell
    # The wall fails to start every 10 s (3 allowed per 5 minutes); then the launcher, once wanted, 4 times.
    Start-Sleep -Seconds 33
    Set-Intent "wanted" ((Get-Date).ToUniversalTime().AddMinutes(10))
    Assert-True (Wait-Until { $h = Read-Hb; $null -ne $h -and $h.pid -eq $sh5.Id -and $h.degraded -eq $true } 40) "degraded after repeated failures"
    $h5 = Read-Hb
    Assert-True ($null -ne $h5 -and $h5.supervising -eq $false -and [string]$h5.degradedReason -match "failures") "...supervision stopped, and the heartbeat says why"
    Start-Sleep -Seconds 20
    $h5b = Read-Hb
    Assert-True ($null -ne $h5b -and $h5b.degraded -eq $true -and $h5b.supervising -eq $false) "...and it stays stopped on later ticks (degraded never supervises again)"
    Start-Sleep -Seconds 4
    Assert-True (-not $sh5.HasExited) "...and the shell is still running (the agent does not restart a degraded companion)"
    Assert-True ((Get-LogText) -match "degraded: supervision stops") "the log records it"
    Stop-Process -Id $sh5.Id -Force -ErrorAction SilentlyContinue

    Section "S13 the log holds state changes only"
    $lines = @((Get-LogText) -split "`r?`n" | Where-Object { $_ })
    $perTick = @($lines | Where-Object { $_ -match "supervision: on" }).Count
    Write-Host ("        log lines: {0}" -f $lines.Count) -ForegroundColor DarkGray
    Assert-True ($lines.Count -lt 200) "under 200 lines for several minutes of shells ($($lines.Count))"
    Assert-True ($perTick -le 8) "'supervision: on' is written once per shell start, not per tick ($perTick)"
}
finally {
    Stop-Shells
    Stop-Ours $LaunchName
    Stop-Ours $WallName
    Start-Sleep -Milliseconds 800
    try { Remove-Item -LiteralPath $Root -Recurse -Force -ErrorAction SilentlyContinue } catch { }
}

Write-Host ""
Write-Host ("RESULT: {0} passed, {1} failed" -f $script:Pass, $script:Fail) -ForegroundColor $(if ($script:Fail -eq 0) { "Green" } else { "Red" })
if ($script:Fail -gt 0) { $script:Failures | ForEach-Object { Write-Host "  - $_" -ForegroundColor Red }; exit 1 }
exit 0
