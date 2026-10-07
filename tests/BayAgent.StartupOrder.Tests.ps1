<#
BayAgent.StartupOrder.Tests.ps1

WHY THIS EXISTS
  BayAgent 1.2.0 (release fleet-v2026.09.14, package sha256 467a3c80) shipped with 230 green tests and
  died in under a second on the first real bay it reached:

      FATAL (pid=18400): The term 'Get-PropValue' is not recognized ...
      STACK: at Get-ActiveCertThumbprint, BayAgent.ps1: line 564
             at Write-CredentialStartupSummary, BayAgent.ps1: line 903
             at <ScriptBlock>, BayAgent.ps1: line 937

  PowerShell defines a function when the interpreter REACHES its definition, not when it parses the file.
  Script-level line 937 called Write-CredentialStartupSummary, which reached Get-PropValue, which is
  defined at line 1563 -- six hundred lines further down than the interpreter had got. On a bay the
  script is run as a FILE (powershell.exe -File BayAgent.ps1) so the whole top-of-file sequence runs in
  order, and the call fails.

  The existing credential suite could never have seen this: it lifts the functions it wants out of the
  file by AST and dot-sources them, so by the time it calls anything, EVERY function exists. That is
  true of any suite that pre-loads. The defect lives in the ORDER of the file, which pre-loading erases.

WHAT THIS TEST DOES
  It reads the order back out of the file with the PowerShell AST, and it does it by analysis rather
  than by eye:

    1. Builds the call graph of every function in the script.
    2. Walks every SCRIPT-LEVEL statement in source order. At the moment that statement runs, only the
       functions whose definitions appear ABOVE it exist.
    3. Takes the transitive closure of everything that statement can reach, and fails if anything in
       that closure -- at any depth -- is defined below the statement.
    4. Does the same for script-level VARIABLES: a function reached from a script-level statement that
       reads a script variable first assigned below that statement gets the same verdict (under
       Set-StrictMode that is a terminating error, not an empty value).
    5. Applies the same rule inside function bodies for functions defined INSIDE other functions.
    6. Treats a TRAP as executing at the first statement in its block that can throw, because a trap is
       hoisted -- it fires for errors raised ABOVE the line it is written on. This is measured, not
       assumed; see the comment at the trap branch. It is how the other seven instances of this class
       were found, and they were the silent ones: the handler that exists to say why the agent died,
       failing to say anything, for exactly the earliest failures.

  It is the class, not the instance: any new call added above its callee's definition fails here.

WHAT IT DOES NOT DO
  It does not run the agent. BayAgent.Launch.Tests.ps1 does that, in a real child powershell.exe, and
  is the instrument that reproduced this morning's failure end to end. This one is the cheap, total
  sweep; that one is the expensive, realistic proof. Neither replaces the other.

  Commands invoked indirectly (a name in a variable, `&$sb`, Invoke-Expression) are invisible to any
  static analysis, this one included. The launch test covers what this cannot.

RUN (from the repo root)
  powershell -NoProfile -ExecutionPolicy Bypass -File tests\BayAgent.StartupOrder.Tests.ps1

Exit code 0 = all assertions passed. Hyphens only in comments (em-dashes break AllSigned parsing).
#>
[CmdletBinding()]
param(
    # Analyze one file instead of the whole shipped set (used to prove the analyzer red against an old commit).
    [string]$OnlyPath = ""
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# ---------------------------------------------------------------- harness (same shape as the credential suite)
$script:Pass = 0; $script:Fail = 0; $script:Failures = @()
function Assert-True([bool]$cond, [string]$msg) {
    if ($cond) { $script:Pass++; Write-Host "  PASS  $msg" }
    else { $script:Fail++; $script:Failures += $msg; Write-Host "  FAIL  $msg" -ForegroundColor Red }
}
function Section([string]$name) { Write-Host ""; Write-Host "== $name" -ForegroundColor Cyan }

$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path

# Every .ps1 that reaches a bay. The four package entries (Build-ReleasePackage.ps1 $Entries, minus
# tools\Publish-Current.ps1 which is JavaScript misfiled as .ps1 and never executed), plus the bootstrap
# scripts and provisioning tools that Setup-BayPC.ps1 lays down and the Scheduled Tasks run.
$ShippedScripts = @(
    "src\BayAgent\BayAgent.ps1"
    "src\BayAgent\RestartBayAgent.ps1"
    "src\BayAgent\tools\Update-BayAgent.ps1"
    "src\BayAgent\tools\Update-SessionDisplay.ps1"
    "src\BayAgent\tools\Update-PromosPack.ps1"
    "src\BayAgent\tools\Watch-BayAgentUpdate.ps1"
    "src\BayAgent\tools\Setup-BayPC.ps1"
    "src\BayAgent\bootstrap\ABG.AgentHost.ps1"
    "src\BayAgent\bootstrap\ABG.HostWatchdog.ps1"
    "src\BayAgent\bootstrap\ABG.LauncherShell.ps1"
    "src\BayAgent\bootstrap\ABG.ReleaseFinalize.ps1"
    "src\BayAgent\bootstrap\ABG.RotateClientSecretDpapiAndTest.ps1"
    "src\BayAgent\bootstrap\ABG.SetClientSecretDpapi.ps1"
    "tools\ABG-Day0-Setup.ps1"
)

# ---------------------------------------------------------------- automatic and built-in variables
# Present before the first line of the script runs, so reading one is never an ordering defect.
$script:AutoVars = @(
    "_", "psitem", "args", "input", "error", "null", "true", "false", "this", "pid", "home", "profile",
    "psscriptroot", "pscommandpath", "myinvocation", "host", "executioncontext", "pwd", "matches",
    "lastexitcode", "psversiontable", "psboundparameters", "pscmdlet", "psdefaultparametervalues",
    "shellid", "stacktrace", "outputencoding", "nestedpromptlevel", "iswindows", "islinux", "ismacos",
    "erroractionpreference", "verbosepreference", "debugpreference", "warningpreference",
    "progresspreference", "informationpreference", "confirmpreference", "whatifpreference",
    "psnativecommandusearglist", "psemailserver", "formatenumerationlimit", "maximumhistorycount",
    "consolefilename", "eventsubscriber", "sender", "eventargs", "event", "sourceeventargs",
    "sourceargs", "foreach", "switch", "ofs"
)

function Get-SoVarKey([string]$rawName) {
    # Strip a scope qualifier; $Global:X, $script:X and $X are the same storage for our purposes.
    $n = $rawName
    $i = $n.IndexOf(":")
    if ($i -ge 0) {
        $scope = $n.Substring(0, $i).ToLowerInvariant()
        if ($scope -in @("global", "script", "local", "private", "using")) { $n = $n.Substring($i + 1) }
        else { return $null }   # $env:X, $function:X, drive-qualified: not script state
    }
    return $n.ToLowerInvariant()
}

function Get-SoInnermostFunction($node) {
    $p = $node.Parent
    while ($null -ne $p) {
        if ($p -is [System.Management.Automation.Language.FunctionDefinitionAst]) { return $p }
        $p = $p.Parent
    }
    return $null
}

# ---------------------------------------------------------------- the analyzer
function Get-StartupOrderDefects {
    <#
      Returns one object per defect:
        Kind      Function | Variable | NestedFunction | DuplicateDefinition
        Line      the script-level (or in-body) line whose execution hits the defect
        Name      the function or variable that does not exist yet
        DefLine   the line where it comes into existence
        Path      how the statement reaches it, e.g. "L937 -> Write-CredentialStartupSummary -> Get-ActiveCertThumbprint -> Get-PropValue"
    #>
    param([Parameter(Mandatory = $true)][string]$Path)

    $toks = $null; $errs = $null
    $fileAst = [System.Management.Automation.Language.Parser]::ParseFile($Path, [ref]$toks, [ref]$errs)
    if (@($errs).Count -gt 0) {
        throw ("{0} has {1} parse error(s): {2}" -f $Path, @($errs).Count, (@($errs)[0].Message))
    }

    $defects = New-Object System.Collections.ArrayList

    $allFuncs = @($fileAst.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $true))

    # --- index the functions -------------------------------------------------
    # DefinedAt is the END of the definition: the function exists only once the interpreter has run past it.
    $funcByName = @{}          # lowercase name -> node record (first definition wins: that is when the name first exists)
    $nodeOf     = @{}          # the FunctionDefinitionAst itself -> record
    foreach ($fd in $allFuncs) {
        $owner = Get-SoInnermostFunction $fd
        $rec = [ordered]@{
            Name      = $fd.Name
            Key       = $fd.Name.ToLowerInvariant()
            Ast       = $fd
            Owner     = $owner
            DefinedAt = $fd.Extent.EndOffset
            StartLine = $fd.Extent.StartLineNumber
            Calls     = $null
            FreeVars  = $null
        }
        $nodeOf[$fd] = $rec
        if ($funcByName.ContainsKey($rec.Key)) {
            $first = $funcByName[$rec.Key]
            [void]$defects.Add([pscustomobject]@{
                Kind = "DuplicateDefinition"; Line = $fd.Extent.StartLineNumber; Name = $fd.Name
                DefLine = $first.StartLine
                Path = ("'{0}' is defined twice (lines {1} and {2}); which body runs depends on where the caller sits" -f $fd.Name, $first.StartLine, $fd.Extent.StartLineNumber)
            })
        } else {
            $funcByName[$rec.Key] = $rec
        }
    }

    # --- per-function: the commands it issues and the free variables it reads ---
    foreach ($fd in $allFuncs) {
        $rec = $nodeOf[$fd]

        # Commands attributed to THIS function only (not to a function nested inside it).
        $cmds = @($fd.Body.FindAll({ param($n) $n -is [System.Management.Automation.Language.CommandAst] }, $true)) |
                Where-Object { (Get-SoInnermostFunction $_) -eq $fd }
        $names = New-Object System.Collections.ArrayList
        foreach ($c in $cmds) {
            $cn = $null
            try { $cn = $c.GetCommandName() } catch {}
            if ($cn) { [void]$names.Add($cn.ToLowerInvariant()) }
        }
        $rec.Calls = @($names | Select-Object -Unique)

        # Parameters and locally assigned names are not free.
        $bound = New-Object System.Collections.Generic.HashSet[string]
        $pars = @()
        if ($fd.Parameters) { $pars = @($fd.Parameters) }
        elseif ($fd.Body.ParamBlock -and $fd.Body.ParamBlock.Parameters) { $pars = @($fd.Body.ParamBlock.Parameters) }
        foreach ($p in $pars) { [void]$bound.Add($p.Name.VariablePath.UserPath.ToLowerInvariant()) }

        $assigns = @($fd.Body.FindAll({ param($n) $n -is [System.Management.Automation.Language.AssignmentStatementAst] }, $true)) |
                   Where-Object { (Get-SoInnermostFunction $_) -eq $fd }
        foreach ($a in $assigns) {
            foreach ($v in @($a.Left.FindAll({ param($n) $n -is [System.Management.Automation.Language.VariableExpressionAst] }, $true))) {
                $k = Get-SoVarKey $v.VariablePath.UserPath
                if ($k) { [void]$bound.Add($k) }
            }
        }
        # foreach ($x in ...) binds $x; so does a catch/trap variable and a data statement.
        foreach ($fe in @($fd.Body.FindAll({ param($n) $n -is [System.Management.Automation.Language.ForEachStatementAst] }, $true))) {
            $k = Get-SoVarKey $fe.Variable.VariablePath.UserPath
            if ($k) { [void]$bound.Add($k) }
        }

        $free = New-Object System.Collections.ArrayList
        $vars = @($fd.Body.FindAll({ param($n) $n -is [System.Management.Automation.Language.VariableExpressionAst] }, $true)) |
                Where-Object { (Get-SoInnermostFunction $_) -eq $fd }
        foreach ($v in $vars) {
            $k = Get-SoVarKey $v.VariablePath.UserPath
            if (-not $k) { continue }
            if ($bound.Contains($k)) { continue }
            if ($script:AutoVars -contains $k) { continue }
            [void]$free.Add($k)
        }
        $rec.FreeVars = @($free | Select-Object -Unique)
    }

    # --- script-level variable assignments, in source order --------------------
    $scriptAssignFirst = @{}   # var key -> offset of its first script-level assignment
    $scriptAssignLine  = @{}
    foreach ($a in @($fileAst.FindAll({ param($n) $n -is [System.Management.Automation.Language.AssignmentStatementAst] }, $true))) {
        if ($null -ne (Get-SoInnermostFunction $a)) { continue }      # inside a function: not script state we can order
        foreach ($v in @($a.Left.FindAll({ param($n) $n -is [System.Management.Automation.Language.VariableExpressionAst] }, $true))) {
            $k = Get-SoVarKey $v.VariablePath.UserPath
            if (-not $k) { continue }
            if (-not $scriptAssignFirst.ContainsKey($k) -or $a.Extent.EndOffset -lt $scriptAssignFirst[$k]) {
                $scriptAssignFirst[$k] = $a.Extent.EndOffset
                $scriptAssignLine[$k]  = $a.Extent.StartLineNumber
            }
        }
    }
    # The script's own param() block exists before the first statement runs.
    $paramVars = New-Object System.Collections.Generic.HashSet[string]
    if ($fileAst.ParamBlock -and $fileAst.ParamBlock.Parameters) {
        foreach ($p in $fileAst.ParamBlock.Parameters) { [void]$paramVars.Add($p.Name.VariablePath.UserPath.ToLowerInvariant()) }
    }

    # --- the walk --------------------------------------------------------------
    # For an execution point at $atOffset, report everything reachable that does not exist yet.
    function Test-SoReachable {
        # $StmtEndOffset bounds the statement being analyzed. A script-level LOOP re-runs its body, so a
        # variable first assigned INSIDE the statement is not evidence of an ordering defect -- on the second
        # iteration it exists. Assignments that fall inside the statement are therefore not counted.
        param($StartNames, [int]$AtOffset, [int]$AtLine, [string]$Origin, [string]$Kind,
              [int]$StmtStartOffset = -1, [int]$StmtEndOffset = -1)
        if ($StmtStartOffset -lt 0) { $StmtStartOffset = $AtOffset }
        if ($StmtEndOffset -lt 0) { $StmtEndOffset = $AtOffset }

        $seen = New-Object System.Collections.Generic.HashSet[string]
        $queue = New-Object System.Collections.Queue
        $pathOf = @{}
        foreach ($n in $StartNames) {
            if (-not $funcByName.ContainsKey($n)) { continue }
            if ($seen.Add($n)) { $pathOf[$n] = "$Origin -> $($funcByName[$n].Name)"; $queue.Enqueue($n) }
        }

        while ($queue.Count -gt 0) {
            $cur = [string]$queue.Dequeue()
            $rec = $funcByName[$cur]

            if ($rec.DefinedAt -gt $AtOffset) {
                [void]$defects.Add([pscustomobject]@{
                    Kind = $Kind; Line = $AtLine; Name = $rec.Name; DefLine = $rec.StartLine; Path = $pathOf[$cur]
                })
                # Keep walking: the same statement usually reaches several missing names, and reporting
                # only the first would make this a one-defect-per-run instrument.
            }

            foreach ($vk in $rec.FreeVars) {
                if ($paramVars.Contains($vk)) { continue }
                if (-not $scriptAssignFirst.ContainsKey($vk)) { continue }   # never a script variable: a typo or an external
                if ($scriptAssignFirst[$vk] -gt $StmtStartOffset -and $scriptAssignFirst[$vk] -le $StmtEndOffset) { continue }
                if ($scriptAssignFirst[$vk] -gt $AtOffset) {
                    [void]$defects.Add([pscustomobject]@{
                        Kind = "Variable"; Line = $AtLine; Name = ("$" + $vk); DefLine = $scriptAssignLine[$vk]
                        Path = ("{0} reads `${1}" -f $pathOf[$cur], $vk)
                    })
                }
            }

            foreach ($callee in $rec.Calls) {
                if (-not $funcByName.ContainsKey($callee)) { continue }
                if ($seen.Add($callee)) {
                    $pathOf[$callee] = "$($pathOf[$cur]) -> $($funcByName[$callee].Name)"
                    $queue.Enqueue($callee)
                }
            }
        }
    }

    # 1. Every script-level statement, in order.
    $blocks = @($fileAst.BeginBlock, $fileAst.ProcessBlock, $fileAst.EndBlock) | Where-Object { $null -ne $_ }
    foreach ($b in $blocks) {
        # A trap does not live in .Statements -- the parser hangs it off the block in .Traps, which is the
        # AST telling you plainly that it is not executed in source position. Analyze both.
        $blockStatements = @($b.Statements)
        if ($b.Traps) { $blockStatements += @($b.Traps) }

        # The earliest moment a hoisted trap can fire is the first statement in the block that can throw.
        # A function DEFINITION cannot throw -- it only registers a name -- so a file that puts its
        # definitions first and its executable prologue after the trap is safe, and this is what lets a
        # trap legitimately call a function. Everything else is a candidate first-failure.
        $firstThrowable = [int]::MaxValue
        foreach ($s0 in @($b.Statements)) {
            if ($s0 -is [System.Management.Automation.Language.FunctionDefinitionAst]) { continue }
            if ($s0.Extent.StartOffset -lt $firstThrowable) { $firstThrowable = $s0.Extent.StartOffset }
        }
        if ($firstThrowable -eq [int]::MaxValue) { $firstThrowable = 0 }
        foreach ($stmt in $blockStatements) {
            if ($stmt -is [System.Management.Automation.Language.FunctionDefinitionAst]) { continue }

            $stmtCmds = @($stmt.FindAll({ param($n) $n -is [System.Management.Automation.Language.CommandAst] }, $true)) |
                        Where-Object { $null -eq (Get-SoInnermostFunction $_) }
            $callNames = New-Object System.Collections.ArrayList
            foreach ($c in $stmtCmds) {
                $cn = $null
                try { $cn = $c.GetCommandName() } catch {}
                if ($cn) { [void]$callNames.Add($cn.ToLowerInvariant()) }
            }
            # A TRAP IS HOISTED. MEASURED 2026-09-21 on Windows PowerShell 5.1: a trap declared at line 4
            # fires for a throw at line 3, and a function defined at line 5 is NOT available to it. So a
            # trap's execution point is the START of the block it guards, not where it is written -- which
            # makes the ordinary reading of "the log line is written by the trap above" wrong for every
            # error raised before the trap's own dependencies are defined. Analyze it at offset 0.
            $atOffset = $stmt.Extent.StartOffset
            $origin   = "L" + $stmt.Extent.StartLineNumber
            if ($stmt -is [System.Management.Automation.Language.TrapStatementAst]) {
                $atOffset = $firstThrowable
                $origin   = ("L{0} (trap, hoisted: it fires for the first throw in the block)" -f $stmt.Extent.StartLineNumber)
            }

            if ($callNames.Count -gt 0) {
                Test-SoReachable -StartNames (@($callNames | Select-Object -Unique)) `
                                 -AtOffset $atOffset -AtLine $stmt.Extent.StartLineNumber `
                                 -StmtStartOffset $stmt.Extent.StartOffset -StmtEndOffset $stmt.Extent.EndOffset `
                                 -Origin $origin -Kind "Function"
            }

            # Variables the statement reads DIRECTLY (not through a function). This matters almost only for
            # the hoisted trap, whose whole job is to log -- and which cannot, if the log variables are set
            # below it.
            foreach ($v in @($stmt.FindAll({ param($n) $n -is [System.Management.Automation.Language.VariableExpressionAst] }, $true))) {
                if ($null -ne (Get-SoInnermostFunction $v)) { continue }
                $vk = Get-SoVarKey $v.VariablePath.UserPath
                if (-not $vk) { continue }
                if ($script:AutoVars -contains $vk) { continue }
                if ($paramVars.Contains($vk)) { continue }
                if (-not $scriptAssignFirst.ContainsKey($vk)) { continue }
                if ($scriptAssignFirst[$vk] -gt $stmt.Extent.StartOffset -and $scriptAssignFirst[$vk] -le $stmt.Extent.EndOffset) { continue }
                if ($scriptAssignFirst[$vk] -gt $atOffset) {
                    [void]$defects.Add([pscustomobject]@{
                        Kind = "Variable"; Line = $v.Extent.StartLineNumber; Name = ("$" + $vk); DefLine = $scriptAssignLine[$vk]
                        Path = ("{0} reads `${1} directly" -f $origin, $vk)
                    })
                }
            }
        }
    }

    # 2. Functions defined inside other functions: the same rule applies inside the body.
    foreach ($fd in $allFuncs) {
        $rec = $nodeOf[$fd]
        if ($null -eq $rec.Owner) { continue }
        $ownerRec = $nodeOf[$rec.Owner]
        $callsInOwner = @($rec.Owner.Body.FindAll({ param($n) $n -is [System.Management.Automation.Language.CommandAst] }, $true)) |
                        Where-Object { (Get-SoInnermostFunction $_) -eq $rec.Owner }
        foreach ($c in $callsInOwner) {
            $cn = $null
            try { $cn = $c.GetCommandName() } catch {}
            if (-not $cn) { continue }
            if ($cn.ToLowerInvariant() -ne $rec.Key) { continue }
            if ($c.Extent.StartOffset -lt $rec.DefinedAt) {
                [void]$defects.Add([pscustomobject]@{
                    Kind = "NestedFunction"; Line = $c.Extent.StartLineNumber; Name = $rec.Name; DefLine = $rec.StartLine
                    Path = ("{0} calls nested '{1}' at line {2}, before its definition at line {3}" -f $ownerRec.Name, $rec.Name, $c.Extent.StartLineNumber, $rec.StartLine)
                })
            }
        }
    }

    return @($defects)
}

# ---------------------------------------------------------------- run it
$targets = @()
if (-not [string]::IsNullOrWhiteSpace($OnlyPath)) {
    $targets = @((Resolve-Path $OnlyPath).Path)
} else {
    foreach ($rel in $ShippedScripts) {
        $p = Join-Path $RepoRoot $rel
        if (Test-Path -LiteralPath $p) { $targets += (Resolve-Path $p).Path }
        else { Write-Host "  SKIP  not present: $rel" -ForegroundColor Yellow }
    }
}

Section "S1 the analyzer detects the shape it exists to detect (self-test on a known-bad fixture)"
# An instrument that reports "clean" is only worth something if it is known to be capable of reporting dirty.
$fixtureDir = Join-Path $env:TEMP ("bayagent-sotest-" + [guid]::NewGuid().ToString("N").Substring(0, 8))
New-Item -ItemType Directory -Force -Path $fixtureDir | Out-Null
try {
    # Reproduces this morning's shape exactly: script-level call -> function -> helper defined later.
    $bad = Join-Path $fixtureDir "bad.ps1"
    Set-Content -LiteralPath $bad -Encoding ASCII -Value @'
function Outer {
    $x = Helper "a"
    return $x
}
Outer
function Helper([string]$s) { return $s.ToUpper() }
'@
    $badDefects = @(Get-StartupOrderDefects -Path $bad)
    Assert-True (@($badDefects | Where-Object { $_.Name -eq "Helper" -and $_.Kind -eq "Function" }).Count -ge 1) `
        "a script-level call reaching a helper defined below it is reported (found $($badDefects.Count) defect(s))"

    # And the variable half.
    $badVar = Join-Path $fixtureDir "badvar.ps1"
    Set-Content -LiteralPath $badVar -Encoding ASCII -Value @'
function Show { Write-Output $Later }
Show
$Later = "too late"
'@
    $varDefects = @(Get-StartupOrderDefects -Path $badVar)
    Assert-True (@($varDefects | Where-Object { $_.Kind -eq "Variable" -and $_.Name -eq "`$later" }).Count -ge 1) `
        "a function reached at script level reading a script variable assigned below it is reported"

    # The hoisted trap. MEASURED, not assumed: see the comment at the trap branch below.
    $badTrap = Join-Path $fixtureDir "badtrap.ps1"
    Set-Content -LiteralPath $badTrap -Encoding ASCII -Value @'
throw "fails before the trap is written"
trap { Log-It $_.Exception.Message; exit 1 }
function Log-It([string]$m) { Write-Host $m }
'@
    $trapDefects = @(Get-StartupOrderDefects -Path $badTrap)
    Assert-True (@($trapDefects | Where-Object { $_.Name -eq "Log-It" }).Count -ge 1) `
        "a trap that calls a function defined below it is reported (a trap fires for throws ABOVE its own line)"

    # ...and the legitimate layout is accepted, or the rule would be unsatisfiable rather than strict.
    $okTrap = Join-Path $fixtureDir "oktrap.ps1"
    Set-Content -LiteralPath $okTrap -Encoding ASCII -Value @'
function Log-It([string]$m) { Write-Host $m }
trap { Log-It $_.Exception.Message; exit 1 }
$ErrorActionPreference = "Stop"
throw "fails after the trap is armed with a function that exists"
'@
    Assert-True (@(Get-StartupOrderDefects -Path $okTrap).Count -eq 0) `
        "a trap whose helpers are defined before the first statement that can throw is accepted"

    # A correctly ordered file must come back clean, or the analyzer is just an alarm that always rings.
    $good = Join-Path $fixtureDir "good.ps1"
    Set-Content -LiteralPath $good -Encoding ASCII -Value @'
function Helper([string]$s) { return $s.ToUpper() }
function Outer {
    $x = Helper "a"
    return $x
}
$Config = "ok"
function Show { Write-Output $Config }
Outer
Show
'@
    Assert-True (@(Get-StartupOrderDefects -Path $good).Count -eq 0) `
        "a correctly ordered file reports no defects (no false positive)"
}
finally { try { Remove-Item -LiteralPath $fixtureDir -Recurse -Force -ErrorAction SilentlyContinue } catch {} }

Section "S2 every shipped script: nothing is used before it is defined"
foreach ($t in $targets) {
    $rel = $t
    if ($t.StartsWith($RepoRoot)) { $rel = $t.Substring($RepoRoot.Length).TrimStart("\") }
    $d = @(Get-StartupOrderDefects -Path $t)
    if ($d.Count -gt 0) {
        Write-Host ""
        foreach ($x in $d) {
            Write-Host ("        {0}: line {1} uses '{2}' which comes into existence at line {3}" -f $x.Kind, $x.Line, $x.Name, $x.DefLine) -ForegroundColor Red
            Write-Host ("            via {0}" -f $x.Path) -ForegroundColor DarkGray
        }
    }
    Assert-True ($d.Count -eq 0) ("{0}: no use-before-definition on any startup path ({1} found)" -f $rel, $d.Count)
}

Write-Host ""
Write-Host ("RESULT: {0} passed, {1} failed" -f $script:Pass, $script:Fail) -ForegroundColor $(if ($script:Fail -eq 0) { "Green" } else { "Red" })
if ($script:Fail -gt 0) { $script:Failures | ForEach-Object { Write-Host "  - $_" -ForegroundColor Red }; exit 1 }
exit 0
