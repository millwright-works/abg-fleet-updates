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
    Section "E1 census: the EXACT set of writers of the two latch globals (by name, every shape)"
    # R3 (verifier, fix/bayagent-estop-latch): the first census allowed any top-level writer, did not see
    # Set-Variable or a multi-assignment, and exempted a function by NAME. Now: every writer is found by the VARIABLE
    # NAME (any scope prefix), whatever the shape, and the whole set is pinned as an exact list with each right-hand side.
    $latchRx = '^(?:\w+:)?(emergencystopengaged|emergencystopreason)$'
    function Get-LatchVarName($v) {
        $m = [regex]::Match($v.VariablePath.UserPath.ToLowerInvariant(), $latchRx)
        if ($m.Success) { return $m.Groups[1].Value }
        return $null
    }
    function Get-LatchVarsUnder($node) {
        $found = @()
        $all = @($node.FindAll({ param($n) $n -is [System.Management.Automation.Language.VariableExpressionAst] }, $true))
        foreach ($v in $all) { $nm = Get-LatchVarName $v; if ($null -ne $nm) { $found += $nm } }
        return $found
    }
    function Get-EnclosingFunctions($node) {
        $list = @(); $p = $node.Parent
        while ($null -ne $p) {
            if ($p -is [System.Management.Automation.Language.FunctionDefinitionAst]) { $list += $p }
            $p = $p.Parent
        }
        return $list
    }
    function Get-WriterRecords($rootAst) {
        $recs = @()
        $assigns = @($rootAst.FindAll({ param($n) $n -is [System.Management.Automation.Language.AssignmentStatementAst] }, $true))
        foreach ($a in $assigns) {
            foreach ($nm in @(Get-LatchVarsUnder $a.Left)) { $recs += [pscustomobject]@{ Node = $a; Var = $nm; Kind = "assign"; Rhs = $a.Right.Extent.Text.Trim(); Line = $a.Extent.StartLineNumber } }
        }
        $unary = @($rootAst.FindAll({ param($n) $n -is [System.Management.Automation.Language.UnaryExpressionAst] -and
                (@("PlusPlus", "MinusMinus", "PostfixPlusPlus", "PostfixMinusMinus") -contains [string]$n.TokenKind) }, $true))
        foreach ($u in $unary) { foreach ($nm in @(Get-LatchVarsUnder $u.Child)) { $recs += [pscustomobject]@{ Node = $u; Var = $nm; Kind = "incdec"; Rhs = ""; Line = $u.Extent.StartLineNumber } } }
        $fes = @($rootAst.FindAll({ param($n) $n -is [System.Management.Automation.Language.ForEachStatementAst] }, $true))
        foreach ($fe in $fes) { foreach ($nm in @(Get-LatchVarsUnder $fe.Variable)) { $recs += [pscustomobject]@{ Node = $fe; Var = $nm; Kind = "foreach"; Rhs = ""; Line = $fe.Extent.StartLineNumber } } }
        $refs = @($rootAst.FindAll({ param($n) $n -is [System.Management.Automation.Language.ConvertExpressionAst] -and $n.Type.TypeName.Name -ieq "ref" }, $true))
        foreach ($rf in $refs) { foreach ($nm in @(Get-LatchVarsUnder $rf.Child)) { $recs += [pscustomobject]@{ Node = $rf; Var = $nm; Kind = "ref"; Rhs = ""; Line = $rf.Extent.StartLineNumber } } }
        $cmds = @($rootAst.FindAll({ param($n) $n -is [System.Management.Automation.Language.CommandAst] }, $true))
        foreach ($c in $cmds) {
            $cn = [string]$c.GetCommandName()
            $isVarCmd = ($cn -match '^(set|new|remove|clear)-variable$') -or (@("sv", "set", "nv", "rv", "clv") -contains $cn.ToLowerInvariant()) -or ($c.Extent.Text -match '(?i)variable:')
            if ($c.Extent.Text -match '(?i)emergencystop(engaged|reason)') {
                if ($c.Extent.Text -notmatch '^(?i)(write-log)\b' -and ($isVarCmd -or $c.Extent.Text -match '(?i)(set|new|remove|clear)-(variable|item)|\bsv\b|\bnv\b|\brv\b|\bclv\b')) {
                    $recs += [pscustomobject]@{ Node = $c; Var = "(by command)"; Kind = "variable-cmdlet"; Rhs = $c.Extent.Text; Line = $c.Extent.StartLineNumber }
                }
            } elseif ($isVarCmd) {
                # a *-Variable command whose name argument is not a plain string constant could name the latch dynamically
                $dyn = @($c.CommandElements | Select-Object -Skip 1 | Where-Object { $_ -is [System.Management.Automation.Language.VariableExpressionAst] -or $_ -is [System.Management.Automation.Language.SubExpressionAst] -or $_ -is [System.Management.Automation.Language.ExpandableStringExpressionAst] })
                if ($dyn.Count -gt 0 -and $cn -notmatch '^(?i)get-') { $recs += [pscustomobject]@{ Node = $c; Var = "(dynamic)"; Kind = "variable-cmdlet-dynamic"; Rhs = $c.Extent.Text; Line = $c.Extent.StartLineNumber } }
            }
        }
        # the name inside a plain string (Set-Variable -Name "EmergencyStopEngaged", a split or joined name, a hashtable key)
        $strs = @($rootAst.FindAll({ param($n) ($n -is [System.Management.Automation.Language.StringConstantExpressionAst]) -and ([string]$n.Value) -match '(?i)emergencystop(engaged|reason)' }, $true))
        foreach ($s in $strs) { $recs += [pscustomobject]@{ Node = $s; Var = "(string)"; Kind = "string-mention"; Rhs = [string]$s.Value; Line = $s.Extent.StartLineNumber } }
        return $recs
    }
    function Get-WriterSignature($w, $rootAst) {
        $fns = @(Get-EnclosingFunctions $w.Node)
        $where = "top"
        if ($fns.Count -eq 1) {
            $f = $fns[0]
            $topLevel = ($f.Parent -is [System.Management.Automation.Language.NamedBlockAst]) -and ($f.Parent.Parent -eq $rootAst)
            $where = $(if ($topLevel) { "fn:" + $f.Name } else { "NESTED-FN:" + $f.Name })
        } elseif ($fns.Count -gt 1) { $where = "NESTED-FN:" + (($fns | ForEach-Object { $_.Name }) -join ">") }
        else {
            $ctx = "init"; $p = $w.Node.Parent
            while ($null -ne $p) {
                if ($p -is [System.Management.Automation.Language.CatchClauseAst]) {
                    if ($p.Parent.Body.Extent.Text -match 'Restore-EmergencyStopLatch') { $ctx = "restore-catch" } else { $ctx = "OTHER-CATCH" }
                    break
                }
                if ($p -is [System.Management.Automation.Language.TryStatementAst] -or $p -is [System.Management.Automation.Language.IfStatementAst] -or
                    $p -is [System.Management.Automation.Language.LoopStatementAst] -or $p -is [System.Management.Automation.Language.SwitchStatementAst]) { $ctx = "OTHER-BLOCK"; break }
                $p = $p.Parent
            }
            $where = "top:" + $ctx
        }
        $rhs = $w.Rhs
        if ($rhs -like '"Emergency-stop restore failed*') { $rhs = "RESTORE_FAILED_TEXT" }
        return ("{0}|{1}|{2}|{3}" -f $where, $w.Var, $w.Kind, $rhs)
    }

    $writers = @(Get-WriterRecords $ast)
    $actual = @($writers | ForEach-Object { Get-WriterSignature $_ $ast } | Sort-Object)
    $expected = @(
        'top:init|emergencystopengaged|assign|$false', 'top:init|emergencystopreason|assign|$null',
        'top:restore-catch|emergencystopengaged|assign|$true', 'top:restore-catch|emergencystopreason|assign|RESTORE_FAILED_TEXT',
        'fn:Restore-EmergencyStopLatch|emergencystopengaged|assign|$engaged', 'fn:Restore-EmergencyStopLatch|emergencystopreason|assign|$reason',
        'fn:Invoke-EmergencyStopInternal|emergencystopengaged|assign|$true', 'fn:Invoke-EmergencyStopInternal|emergencystopreason|assign|$reason',
        'fn:Clear-EmergencyStopInternal|emergencystopengaged|assign|$false', 'fn:Clear-EmergencyStopInternal|emergencystopreason|assign|$null'
    ) | Sort-Object
    Assert-True ($actual.Count -eq 10) "exactly 10 writers of the latch (found $($actual.Count): 2 startup initializer, 2 startup restore-failure, 2 restore, 2 stop, 2 clear)"
    $unexpected = @($actual | Where-Object { $expected -cnotcontains $_ })
    $missing = @($expected | Where-Object { $actual -cnotcontains $_ })
    Assert-True ($unexpected.Count -eq 0) "no writer outside the pinned list (unexpected: $($unexpected -join ' ;; '))"
    Assert-True ($missing.Count -eq 0) "every pinned writer is present with its right-hand side (missing: $($missing -join ' ;; '))"

    # the three writer functions exist exactly once, at the top level (a later duplicate would silently win)
    foreach ($fnName in @("Invoke-EmergencyStopInternal", "Clear-EmergencyStopInternal", "Restore-EmergencyStopLatch")) {
        $defs = @($ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -ieq $fnName }, $true))
        $isTop = ($defs.Count -eq 1) -and ($defs[0].Parent -is [System.Management.Automation.Language.NamedBlockAst]) -and ($defs[0].Parent.Parent -eq $ast)
        Assert-True $isTop "$fnName is defined exactly once, at the top level (definitions found: $($defs.Count))"
    }

    # the behavior tests below replace these functions with stand-ins; a writer hidden in the REAL body would never run there
    foreach ($standIn in @("Write-Log", "Read-SessionModelFromDisk", "Write-SessionFiles", "Start-SessionDisplay")) {
        $defs = @($ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -ieq $standIn }, $true))
        $mentions = 0
        foreach ($d in $defs) { $mentions += @(Get-WriterRecords $d).Count }
        Assert-True ($defs.Count -ge 1 -and $mentions -eq 0) "the shipped $standIn (stubbed below) carries no latch writer ($($defs.Count) definition(s), $mentions writer shapes)"
    }
    # the census itself must see every shape: plant one writer per shape in a scratch script and require each to be found
    $shapes = [ordered]@{
        "plain assign"      = '$Global:EmergencyStopEngaged = $false'
        "script scope"      = '$script:EmergencyStopReason = $null'
        "no scope"          = '$EmergencyStopEngaged = $false'
        "multi-assign"      = '$Global:EmergencyStopEngaged, $Global:EmergencyStopReason = $false, $null'
        "typed assign"      = '[bool]$Global:EmergencyStopEngaged = $false'
        "plus-equals"       = '$Global:EmergencyStopReason += "x"'
        "Set-Variable"      = 'Set-Variable -Name EmergencyStopEngaged -Value $false -Scope Global'
        "Set-Variable str"  = 'Set-Variable -Name "EmergencyStopEngaged" -Value $false -Scope Global'
        "Remove-Variable"   = 'Remove-Variable -Name EmergencyStopReason -Scope Global'
        "Clear-Variable"    = 'Clear-Variable EmergencyStopReason -Scope Global'
        "New-Variable"      = 'New-Variable -Name EmergencyStopEngaged -Value $false -Force -Scope Global'
        "sv alias"          = 'sv EmergencyStopEngaged $false -Scope Global'
        "dynamic name"      = 'Set-Variable -Name $someName -Value $false -Scope Global'
        "ref"               = 'Set-Foo -Target ([ref]$Global:EmergencyStopEngaged)'
        "foreach var"       = 'foreach ($Global:EmergencyStopEngaged in 1,2) { }'
        "increment"         = '$Global:EmergencyStopReason++'
        "variable provider" = 'Set-Item -Path variable:EmergencyStopEngaged -Value $false'
    }
    foreach ($sn in $shapes.Keys) {
        $planted = [System.Management.Automation.Language.Parser]::ParseInput("function Start-Planted { " + $shapes[$sn] + " }", [ref]$null, [ref]$null)
        $pw = @(Get-WriterRecords $planted)
        Assert-True ($pw.Count -ge 1) "the census sees a planted writer: $sn ($($pw.Count) found)"
    }
    # and a writer planted inside a function named like an allowed one, nested in another function, is not exempt
    $nestedSrc = "function Stop-Thing { function Clear-EmergencyStopInternal { `$Global:EmergencyStopEngaged = `$false } }"
    $nestedAst = [System.Management.Automation.Language.Parser]::ParseInput($nestedSrc, [ref]$null, [ref]$null)
    $nw = @(Get-WriterRecords $nestedAst)
    $nsig = if ($nw.Count -eq 1) { Get-WriterSignature $nw[0] $nestedAst } else { "" }
    Assert-True ($nsig -like "NESTED-FN:*") "a writer in a nested function named like an allowed writer is reported as NESTED, not exempt ($nsig)"
    # a top-level writer outside the startup lines (a clear in the main loop) does not match the pinned initializer
    $loopAst = [System.Management.Automation.Language.Parser]::ParseInput('while ($true) { $Global:EmergencyStopEngaged = $false }', [ref]$null, [ref]$null)
    $lw = @(Get-WriterRecords $loopAst)
    $lsig = if ($lw.Count -eq 1) { Get-WriterSignature $lw[0] $loopAst } else { "" }
    Assert-True ($lsig -like "top:OTHER-BLOCK*" -and ($expected -cnotcontains $lsig)) "a clear planted in the main loop is not a pinned startup writer ($lsig)"
    $loopAst2 = [System.Management.Automation.Language.Parser]::ParseInput('$Global:EmergencyStopEngaged = $false', [ref]$null, [ref]$null)
    $lw2 = @(Get-WriterRecords $loopAst2)
    Assert-True ($lw2.Count -eq 1) "(sanity) a bare top-level initializer-shaped statement is itself one writer, so the pinned count of exactly 2 initializer lines catches a third"

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
    # the latch is persisted: point it at a scratch file (the persistence behavior has its own suite, BayAgent.EStopPersist.Tests.ps1)
    $Global:EmergencyStopStatePath = Join-Path $tmp "state\emergency-stop.json"
    $Global:EmergencyStopPersistOk = $true
    $Global:NextCapabilitiesUtc = [DateTime]::MaxValue
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
