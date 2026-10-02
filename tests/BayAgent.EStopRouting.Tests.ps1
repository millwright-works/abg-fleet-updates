<#
BayAgent.EStopRouting.Tests.ps1

WHY THIS EXISTS
  Three findings from the verifier of fix/bayagent-pid-param (R7, R2, R3, R4), each pinned by BEHAVIOR on both
  Windows PowerShell 5.1 and pwsh 7:

    E1  (R7, safety) Stop-SessionDisplay had the emergency-stop latch assignments pasted into its body, so any
        EndSession or Reset with closeDisplay=true (and every default Reset, which restarts the display) cleared a
        latch whose own comment says "cleared only by explicit command". Tested by running the SHIPPED
        Execute-Command and Stop-SessionDisplay with the latch engaged and asserting the latch AND its effects still
        hold; only EmergencyStop action=clear releases it. A census also pins every writer of the two globals.
    W1  (R2) Move-ProcessWindowToRole blocked the single command loop for timeoutSec (8 s) per process that shows no
        window. Tested with real processes: a windowless process older than the grace window costs one check, a gone
        process costs one check, and a process that is still opening its window (window appears after 3 s) is still
        routed.
    W2  (R3) The routing outcome is asserted on the REAL window rectangle of a console-free WinForms form (not the
        function's own moved=$true and not the PowerShell console).
    W3  (R4) One monitor: the control and session roles do not move the window.

  Functions are lifted from BayAgent.ps1 with the AST and dot-sourced, so the suite tests the SHIPPED text. Window
  tests are Windows-only (they skip elsewhere). A test form is compiled once by Windows PowerShell 5.1.

RUN (from the repo root)
  powershell -NoProfile -ExecutionPolicy Bypass -File tests\BayAgent.EStopRouting.Tests.ps1
  pwsh -NoProfile -File tests/BayAgent.EStopRouting.Tests.ps1
  -AgentScript <path> runs the same assertions against a mutated copy of the agent (mutation checks).

Exit code 0 = all assertions passed. Hyphens only in comments.
#>
[CmdletBinding()]
param([string]$AgentScript = "")

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
if ([string]::IsNullOrWhiteSpace($AgentScript)) { $AgentScript = Join-Path $RepoRoot "src/BayAgent/BayAgent.ps1" }
$AgentScript = (Resolve-Path $AgentScript).Path
$IsWin = ([Environment]::OSVersion.Platform -eq [PlatformID]::Win32NT)

$script:Pass = 0; $script:Fail = 0; $script:Failures = @()
function Assert-True([bool]$cond, [string]$msg) {
    if ($cond) { $script:Pass++; Write-Host "  PASS  $msg" }
    else { $script:Fail++; $script:Failures += $msg; Write-Host "  FAIL  $msg" -ForegroundColor Red }
}
function Section([string]$name) { Write-Host ""; Write-Host "== $name" -ForegroundColor Cyan }

$tokens = $null; $errors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile($AgentScript, [ref]$tokens, [ref]$errors)
if ($errors.Count -gt 0) { throw "BayAgent.ps1 has parse errors" }
$topFns = @($ast.EndBlock.Statements | Where-Object { $_ -is [System.Management.Automation.Language.FunctionDefinitionAst] })
$allFns = @($ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $true))

$startedIds = New-Object System.Collections.Generic.List[int]
$tmp = Join-Path ([IO.Path]::GetTempPath()) ("bayagent-estoprouting-" + [Guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Force -Path $tmp | Out-Null

function Start-Tracked([string]$exe, [string[]]$argList) {
    $p = Start-Process -FilePath $exe -ArgumentList $argList -PassThru
    $startedIds.Add([int]$p.Id)
    return $p
}

try {
    # ============================================================ E1 census: who writes the latch
    Section "E1 census: only the stop, the explicit clear and the startup initializer write the latch globals"
    $latchNames = @("global:emergencystopengaged", "global:emergencystopreason")
    $writers = @($ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.AssignmentStatementAst] -and
            $n.Left -is [System.Management.Automation.Language.VariableExpressionAst] -and
            ($latchNames -contains $n.Left.VariablePath.UserPath.ToLowerInvariant()) }, $true))
    $badWriters = @()
    foreach ($w in $writers) {
        $fn = $null; $parent = $w.Parent
        while ($null -ne $parent) {
            if ($parent -is [System.Management.Automation.Language.FunctionDefinitionAst]) { $fn = $parent.Name; break }
            $parent = $parent.Parent
        }
        if ($null -ne $fn -and @("Invoke-EmergencyStopInternal", "Clear-EmergencyStopInternal") -notcontains $fn) {
            $badWriters += ("{0} line {1}" -f $fn, $w.Extent.StartLineNumber)
        }
    }
    Assert-True ($writers.Count -ge 6) "the census sees the real writers (found $($writers.Count): 2 initializer, 2 stop, 2 clear)"
    Assert-True ($badWriters.Count -eq 0) "no other function assigns the emergency-stop latch (found: $($badWriters -join '; '))"

    # ============================================================ E1 behavior with the shipped handlers
    Section "E1 behavior: EndSession / Reset never clear the latch; only the explicit clear does"
    foreach ($d in $topFns) { . ([scriptblock]::Create($d.Extent.Text)) }
    foreach ($st in @($ast.EndBlock.Statements)) {
        if ($st -is [System.Management.Automation.Language.AssignmentStatementAst] -and $st.Left.Extent.Text -match '^\$(CMD_|AGENTSTATUS_)') {
            . ([scriptblock]::Create($st.Extent.Text))
        }
    }
    $script:logged = New-Object System.Collections.Generic.List[string]
    # stubs: no files, no display, no hardware. Stop-SessionDisplay, Execute-Command and the facility code stay REAL.
    function Write-Log { param([string]$Message, [string]$Level = "INFO") $script:logged.Add("[$Level] $Message") }
    function Read-SessionModelFromDisk { return @{} }
    function Write-SessionFiles { param($model) return @{ sessionJsonPath = "stub.json"; sessionJsPath = "stub.js" } }
    function Start-SessionDisplay { param($payloadObj) return @{ started = $true; stub = $true } }
    # Stop-SessionDisplay looks at every msedge window by title: never let a unit test touch someone's Edge.
    function Get-Process {
        [CmdletBinding()] param([string[]]$Name, [int[]]$Id)
        if ($PSBoundParameters.ContainsKey("Name") -and ($Name -contains "msedge")) { return @() }
        Microsoft.PowerShell.Management\Get-Process @PSBoundParameters
    }
    $cfg = [pscustomobject]@{}
    $BayId = "00000000-0000-0000-0000-000000000000"; $AgentVersion = "test"
    $Global:SessionDisplayUrl = "file:///C:/bayagent-estop-test-$([Guid]::NewGuid().ToString('N'))/index.html"
    $Global:SessionDisplayProfileDir = Join-Path $tmp "edge-profile-unique"
    $Global:SessionDisplayStatePath = Join-Path $tmp "display-state.json"
    $Global:SessionDisplayProcId = $null

    function Invoke-Cmd([int]$type, [string]$json) { return (Execute-Command -CommandType $type -PayloadJson $json -BayLabel "TestBay") }
    function New-Victim {
        # a windowless process standing in for the Session Display; Stop-SessionDisplay must kill it by Id
        $exe = if ($IsWin) { Join-Path $env:SystemRoot "System32\ping.exe" } else { "/bin/sleep" }
        $a = if ($IsWin) { @("-n", "300", "127.0.0.1") } else { @("300") }
        $p = Start-Process -FilePath $exe -ArgumentList $a -PassThru -WindowStyle Hidden -RedirectStandardOutput (Join-Path $tmp ("v" + [Guid]::NewGuid().ToString("N") + ".out"))
        $startedIds.Add([int]$p.Id)
        return $p
    }
    function Assert-Latched([string]$what) {
        Assert-True (($Global:EmergencyStopEngaged -eq $true) -and ($Global:EmergencyStopReason -eq "bench-test-stop")) "$what : latch still engaged with its reason"
        $sl = Invoke-Cmd $CMD_SETLIGHTS '{"scene":"Active"}'
        Assert-True ($sl.ok -eq $false -and $sl.note -eq "emergency_stop_engaged") "$what : SetLights is still refused"
        $fm = Invoke-FacilitySetMode -Mode "Active" -payloadObj @{}
        Assert-True ($fm.ok -eq $false -and $fm.note -eq "emergency_stop_engaged") "$what : a facility scene change to Active is still refused"
        $ss = Invoke-Cmd $CMD_STARTSESSION '{"mode":"start"}'
        Assert-True ($ss.ok -eq $false -and $ss.note -eq "emergency_stop_engaged") "$what : StartSession is still refused"
    }
    function Engage {
        $null = Invoke-Cmd $CMD_EMERGENCY_STOP '{"reason":"bench-test-stop"}'
        Assert-True (($Global:EmergencyStopEngaged -eq $true) -and ($Global:EmergencyStopReason -eq "bench-test-stop")) "the EmergencyStop command engages the latch with the reason"
    }

    # (a) Stop-SessionDisplay on its own, after the stop
    Engage
    $v = New-Victim
    $Global:SessionDisplayProcId = [int]$v.Id
    $r = Stop-SessionDisplay
    Assert-True ($r.stopped -eq $true -and @($r.killedPids) -contains [int]$v.Id) "Stop-SessionDisplay really ran its stop (killed the display process $($v.Id))"
    $v.Refresh(); Assert-True ($v.HasExited) "the display process is gone"
    Assert-Latched "Stop-SessionDisplay alone"

    # (b) EndSession with closeDisplay=true
    $v = New-Victim; $Global:SessionDisplayProcId = [int]$v.Id
    $es = Invoke-Cmd $CMD_ENDSESSION '{"closeDisplay":true,"closeLauncher":false,"closeApps":false}'
    Assert-True ($es.ok -eq $true -and $es.closeDisplay -eq $true -and $null -ne $es.displayStopped -and $es.displayStopped.stopped -eq $true) "EndSession closeDisplay=true really closed the display"
    Assert-Latched "EndSession closeDisplay=true"

    # (c) Reset with closeDisplay=true
    $v = New-Victim; $Global:SessionDisplayProcId = [int]$v.Id
    $rs = Invoke-Cmd $CMD_RESET '{"closeDisplay":true}'
    Assert-True ($rs.reset -eq $true -and $null -ne $rs.stopped -and $rs.stopped.stopped -eq $true) "Reset closeDisplay=true really closed the display"
    Assert-Latched "Reset closeDisplay=true"

    # (d) default Reset (restartDisplay defaults to true: it stops then restarts the display)
    $v = New-Victim; $Global:SessionDisplayProcId = [int]$v.Id
    $rs = Invoke-Cmd $CMD_RESET '{}'
    Assert-True ($rs.reset -eq $true -and $null -ne $rs.stopped -and $rs.stopped.stopped -eq $true) "a default Reset really stopped the display before restarting it"
    Assert-Latched "default Reset"

    # (e) only the explicit clear releases it
    $null = Invoke-Cmd $CMD_EMERGENCY_STOP '{"action":"clear"}'
    Assert-True (($Global:EmergencyStopEngaged -eq $false) -and ($null -eq $Global:EmergencyStopReason)) "EmergencyStop action=clear releases the latch and its reason"
    $sl = Invoke-Cmd $CMD_SETLIGHTS '{"scene":"Active"}'
    Assert-True ($sl.ok -eq $true) "after the explicit clear SetLights is accepted again (the refusals above were the latch, not something else)"

    # ============================================================ W: real windows (Windows only)
    Section "W window routing on a real console-free form (Windows only)"
    if (-not $IsWin) {
        Write-Host "  SKIP  window routing is Win32-only (EnumWindows)"
    } else {
        Add-Type -AssemblyName System.Windows.Forms
        Add-Type -AssemblyName System.Drawing
        Add-Type -Namespace AbgEsr -Name Native -MemberDefinition '[System.Runtime.InteropServices.DllImport("user32.dll")] public static extern bool IsZoomed(System.IntPtr h);'
        $win32If = $ast.EndBlock.Statements | Where-Object { $_ -is [System.Management.Automation.Language.IfStatementAst] -and $_.Extent.Text -match 'class ABGWin32' } | Select-Object -First 1
        if (-not $win32If) { throw "ABGWin32 block not found in the agent" }
        . ([scriptblock]::Create($win32If.Extent.Text))

        # compile a console-free WinForms exe with Windows PowerShell 5.1 (Add-Type -OutputAssembly is not in pwsh 7)
        $simExe = Join-Path $tmp "AbgEsrForm.exe"
        $buildScript = Join-Path $tmp "build.ps1"
        $src = @'
$src = @"
using System;
using System.Drawing;
using System.Threading;
using System.Windows.Forms;
public static class AbgEsrForm {
    [STAThread]
    public static void Main(string[] args) {
        string mode = args.Length > 0 ? args[0] : "form";
        int delay = args.Length > 1 ? int.Parse(args[1]) : 0;
        if (mode == "none") { Thread.Sleep(300000); return; }
        if (delay > 0) { Thread.Sleep(delay); }
        var f = new Form();
        f.Text = "AbgEsrForm " + Guid.NewGuid().ToString("N");
        f.StartPosition = FormStartPosition.Manual;
        f.Location = new Point(100, 100);
        f.Size = new Size(320, 240);
        var quit = new System.Windows.Forms.Timer();
        quit.Interval = 300000;
        quit.Tick += (s, e) => { Application.Exit(); };
        quit.Start();
        Application.Run(f);
    }
}
"@
Add-Type -TypeDefinition $src -ReferencedAssemblies System.Windows.Forms,System.Drawing -OutputAssembly $args[0] -OutputType WindowsApplication
'@
        [IO.File]::WriteAllText($buildScript, $src)
        $ps51 = Join-Path $env:SystemRoot "System32\WindowsPowerShell\v1.0\powershell.exe"
        & $ps51 -NoProfile -ExecutionPolicy Bypass -File $buildScript $simExe | Out-Null
        Assert-True (Test-Path -LiteralPath $simExe) "the console-free test form compiled"

        foreach ($n in @("Get-PropValue", "Get-DisplayDeviceString", "Resolve-RoleSelectorToScreen", "Get-ScreenForRole",
                         "Get-DisplayRoutingConfigFromPayloadOrConfig", "Get-FirstVisibleWindowHandleForPid",
                         "Move-ProcessWindowToRole", "Safe-RouteProcessWindow")) {
            $d = $topFns | Where-Object { $_.Name -eq $n } | Select-Object -First 1
            if (-not $d) { throw "Function '$n' not found in $AgentScript" }
            . ([scriptblock]::Create($d.Extent.Text))
        }

        function Wait-MainWindow($proc, [int]$sec = 30) {
            $end = (Get-Date).AddSeconds($sec)
            while ((Get-Date) -lt $end) {
                $proc.Refresh()
                if ($proc.HasExited) { return [IntPtr]::Zero }
                if ($proc.MainWindowHandle -ne [IntPtr]::Zero) { return $proc.MainWindowHandle }
                Start-Sleep -Milliseconds 200
            }
            return [IntPtr]::Zero
        }
        function Get-Rect([IntPtr]$h) {
            $r = New-Object ABGWin32+RECT
            [void][ABGWin32]::GetWindowRect($h, [ref]$r)
            return $r
        }

        $screens = @([System.Windows.Forms.Screen]::AllScreens)
        $primary = $screens | Where-Object { $_.Primary } | Select-Object -First 1
        $pb = $primary.Bounds

        # ---- W2: routing really moves the form (play role = primary screen)
        $f1 = Start-Tracked $simExe @("form")
        $h1 = Wait-MainWindow $f1
        Assert-True ($h1 -ne [IntPtr]::Zero) "the test form shows a real window (process $($f1.Id), not a console)"
        $before = Get-Rect $h1
        Assert-True ($before.Left -eq 100 -and $before.Top -eq 100 -and ($before.Right - $before.Left) -eq 320) "before routing the form sits at its own small rectangle ($($before.Left),$($before.Top) $($before.Right - $before.Left)x$($before.Bottom - $before.Top))"
        $res = Move-ProcessWindowToRole -ProcessId ([int]$f1.Id) -role "play" -payloadObj $null -timeoutSec 5
        $after = Get-Rect $h1
        Assert-True ($res.moved -eq $true) "the function reports the move"
        Assert-True ($after.Left -eq $pb.Left -and $after.Top -eq $pb.Top -and ($after.Right - $after.Left) -eq $pb.Width -and ($after.Bottom - $after.Top) -eq $pb.Height) `
            "the REAL window rectangle is now the target screen's bounds ($($after.Left),$($after.Top) $($after.Right - $after.Left)x$($after.Bottom - $after.Top) vs $($pb.Left),$($pb.Top) $($pb.Width)x$($pb.Height))"
        Assert-True (-not [AbgEsr.Native]::IsZoomed($h1)) "without -Maximize the window is not maximized"
        $res = Move-ProcessWindowToRole -ProcessId ([int]$f1.Id) -role "play" -payloadObj $null -timeoutSec 5 -Maximize
        Assert-True ([AbgEsr.Native]::IsZoomed($h1)) "with -Maximize the real window is maximized"
        $z = Get-Rect $h1
        $wa = $primary.WorkingArea
        Assert-True ($z.Left -le $wa.Left -and $z.Top -le $wa.Top -and $z.Right -ge $wa.Right -and $z.Bottom -ge $wa.Bottom -and ($z.Right - $z.Left) -gt 320) "the maximized rectangle covers the target screen work area (taskbar excluded)"
        $script:logged.Clear()
        $sr = Safe-RouteProcessWindow -context "test" -ProcessId ([int]$f1.Id) -role "play" -payloadObj $null -Maximize
        Assert-True ($sr.moved -eq $true -and @($script:logged | Where-Object { $_ -match "moved pid=$($f1.Id) " }).Count -eq 1) "Safe-RouteProcessWindow logs the move for this process"

        # ---- W3: one monitor, control and session do not move
        if ($screens.Count -ne 1) {
            Write-Host "  SKIP  this host has $($screens.Count) monitors; the one-monitor pin needs exactly one"
        } else {
            $f2 = Start-Tracked $simExe @("form")
            $h2 = Wait-MainWindow $f2
            $b2 = Get-Rect $h2
            foreach ($role in @("control", "session")) {
                $rr = Move-ProcessWindowToRole -ProcessId ([int]$f2.Id) -role $role -payloadObj $null -timeoutSec 5 -Maximize
                $a2 = Get-Rect $h2
                Assert-True ($rr.moved -eq $false -and $rr.reason -eq "no_target_screen") "one monitor: role '$role' answers no_target_screen"
                Assert-True ($a2.Left -eq $b2.Left -and $a2.Top -eq $b2.Top -and $a2.Right -eq $b2.Right -and $a2.Bottom -eq $b2.Bottom -and -not [AbgEsr.Native]::IsZoomed($h2)) `
                    "one monitor: the real window for role '$role' did not move and was not maximized"
            }
        }

        # ---- W1: bounded wait
        # a windowless process older than the grace window costs one check, not timeoutSec
        $none = Start-Tracked $simExe @("none")
        Start-Sleep -Milliseconds 2500
        $sw = [Diagnostics.Stopwatch]::StartNew()
        $rn = Move-ProcessWindowToRole -ProcessId ([int]$none.Id) -role "play" -payloadObj $null -timeoutSec 8 -windowGraceSec 1
        $sw.Stop()
        Assert-True ($rn.moved -eq $false -and $rn.reason -eq "no_window_handle") "a windowless process answers no_window_handle"
        Assert-True ($sw.ElapsedMilliseconds -lt 3000) "an old windowless process costs little, not the 8 s timeout (took $($sw.ElapsedMilliseconds) ms)"

        # a process that no longer exists costs one check
        $gone = Start-Tracked $simExe @("none")
        Stop-Process -Id $gone.Id -Force; $gone.WaitForExit(10000) | Out-Null
        $sw = [Diagnostics.Stopwatch]::StartNew()
        $rg = Move-ProcessWindowToRole -ProcessId ([int]$gone.Id) -role "play" -payloadObj $null
        $sw.Stop()
        Assert-True ($rg.moved -eq $false -and $sw.ElapsedMilliseconds -lt 3000) "a process that has exited is not waited for (took $($sw.ElapsedMilliseconds) ms, reason $($rg.reason))"

        # a young process whose window opens 3 s late is still routed (correctness kept)
        $late = Start-Tracked $simExe @("form", "3000")
        $rl = Move-ProcessWindowToRole -ProcessId ([int]$late.Id) -role "play" -payloadObj $null -timeoutSec 8
        $hl = Wait-MainWindow $late 10
        $al = Get-Rect $hl
        Assert-True ($rl.moved -eq $true -and $al.Left -eq $pb.Left -and $al.Top -eq $pb.Top -and ($al.Right - $al.Left) -eq $pb.Width -and ($al.Bottom - $al.Top) -eq $pb.Height) `
            "a young process whose window opens 3 s late is still found and its REAL window is moved (moved=$($rl.moved))"
    }
}
finally {
    foreach ($id in $startedIds) { try { Stop-Process -Id $id -Force -ErrorAction SilentlyContinue } catch {} }
    try { Remove-Item -LiteralPath $tmp -Recurse -Force -ErrorAction SilentlyContinue } catch {}
}

Write-Host ""
Write-Host ("RESULT: {0} passed, {1} failed" -f $script:Pass, $script:Fail) -ForegroundColor $(if ($script:Fail -eq 0) { "Green" } else { "Red" })
if ($script:Fail -gt 0) { $script:Failures | ForEach-Object { Write-Host "  - $_" -ForegroundColor Red }; exit 1 }
exit 0
