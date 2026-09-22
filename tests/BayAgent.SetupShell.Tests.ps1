<#
BayAgent.SetupShell.Tests.ps1

AG-47: Setup-BayPC.ps1 Phase 5A used to set HKLM Winlogon Shell to
C:\AllBirdies\BayAgent\bootstrap\ABG.LauncherShell.ps1 UNCONDITIONALLY -- the Set-ItemProperty call ran
first, and only afterward did the script Test-Path the file and print a warning if it was missing. On Bay
1, 2026-09-21 07:45 ET, that file was absent (Day0 does not download it and no fleet package ships it; it
exists only in this repo's source tree). The next BayKiosk logon would have started a missing file and
shown no desktop -- Kevin caught it and repaired the machine by hand.

This suite lifts Get-ShellActivationPlan out of Setup-BayPC.ps1 by AST (the same pattern
BayAgent.Credential.Tests.ps1's T28 uses for Get-Day0CredentialGuidance) and exercises it against real
files in a throwaway sandbox -- no registry writes, so this needs no admin rights and touches nothing on
the machine it runs on.

WHAT THIS PROVES
  - the decision "activate the launcher shell, or fall back to explorer.exe" is a function that can be
    tested, not inline logic that runs blind
  - the file is verified (existence AND a size floor, sha256 captured for the log) BEFORE the plan says
    to activate it
  - when the wrapper is absent, or present but implausibly small (0 bytes, a truncated download), the
    plan falls back to explorer.exe and says so truthfully -- it never asks the caller to point Shell at
    a file that was not just checked
  - in the actual script, the Set-ItemProperty call that writes HKLM Shell happens strictly AFTER the
    Get-ShellActivationPlan call that decided its value -- not before it, which is exactly the ordering
    defect that shipped

WHAT THIS DOES NOT PROVE
  It does not touch the registry, and it does not prove the launcher shell script itself is fit to run as
  a Windows shell (ABG.LauncherShell.ps1 is a separate, unrelated question). It also does not close the
  residual: nothing today places ABG.LauncherShell.ps1 onto a bay at all, so on every bay running the
  fixed script, the plan below will fall back to explorer.exe until that residual is closed (see
  REPORT.md).

RUN AGAINST THE SHIPPED (PRE-FIX) SCRIPT, this suite is expected to FAIL: Get-ShellActivationPlan does not
exist yet, so the lift step reports a failed assertion instead of throwing and stopping every other test
in the file cold.

Run (from the repo root):
  powershell -NoProfile -ExecutionPolicy Bypass -File tests\BayAgent.SetupShell.Tests.ps1
  powershell -NoProfile -ExecutionPolicy Bypass -File tests\BayAgent.SetupShell.Tests.ps1 -SetupScript "C:\path\to\pre-fix\Setup-BayPC.ps1"
Exit code 0 = all assertions passed. Hyphens only in comments (em-dashes break AllSigned parsing).
#>
[CmdletBinding()]
param(
    [string]$SetupScript = ""
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

if ([string]::IsNullOrWhiteSpace($SetupScript)) {
    $SetupScript = Join-Path $PSScriptRoot "..\src\BayAgent\tools\Setup-BayPC.ps1"
}
$SetupScript = (Resolve-Path $SetupScript).Path

# ---------------------------------------------------------------- harness (same shape as the other suites)
$script:Pass = 0; $script:Fail = 0; $script:Failures = @()
function Assert-True([bool]$cond, [string]$msg) {
    if ($cond) { $script:Pass++; Write-Host "  PASS  $msg" }
    else { $script:Fail++; $script:Failures += $msg; Write-Host "  FAIL  $msg" -ForegroundColor Red }
}
function Section([string]$name) { Write-Host ""; Write-Host "== $name" -ForegroundColor Cyan }

$BaseDir = Join-Path $env:TEMP ("bayagent-setupshelltest-" + [guid]::NewGuid().ToString("N").Substring(0, 8))
New-Item -ItemType Directory -Force -Path $BaseDir | Out-Null

try {
    Section "AST: Setup-BayPC.ps1 parses, and declares Get-ShellActivationPlan"
    $tokens = $null; $errors = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseFile($SetupScript, [ref]$tokens, [ref]$errors)
    Assert-True (@($errors).Count -eq 0) "Setup-BayPC.ps1 parses cleanly"

    $fnDefs = @($ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $true) |
        Where-Object { $_.Name -eq "Get-ShellActivationPlan" })
    $fnExists = ($fnDefs.Count -eq 1)
    Assert-True $fnExists "Setup-BayPC.ps1 declares Get-ShellActivationPlan (the decision is a function, not inline logic)"

    if (-not $fnExists) {
        Write-Host ""
        Write-Host "Get-ShellActivationPlan not found -- this is the shipped (pre-fix) script." -ForegroundColor Yellow
        Write-Host "Every remaining assertion in this file is scored as a failure below; none of it can run." -ForegroundColor Yellow
        # Score every planned functional/ordering assertion as an explicit failure rather than silently
        # skipping it, so the FAIL count reflects what the fix is actually worth.
        1..9 | ForEach-Object { Assert-True $false "skipped -- Get-ShellActivationPlan does not exist in $SetupScript" }
    }
    else {
        . ([scriptblock]::Create($fnDefs[0].Extent.Text))

        Section "Ordering: the registry write happens strictly AFTER the plan that decided its value"
        $planCalls = @($ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.CommandAst] -and $n.GetCommandName() -eq "Get-ShellActivationPlan" }, $true))
        Assert-True ($planCalls.Count -eq 1) "Get-ShellActivationPlan is called exactly once in the script body"

        $hklmShellSets = @($ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.CommandAst] -and $n.GetCommandName() -eq "Set-ItemProperty" }, $true) |
            Where-Object { $_.Extent.Text -match "winlogonHKLM" -and $_.Extent.Text -match 'Name\s+"Shell"' })
        Assert-True ($hklmShellSets.Count -eq 1) "there is exactly one Set-ItemProperty call that writes HKLM Winlogon Shell (no earlier unconditional write survives beside the guarded one)"

        if ($planCalls.Count -ge 1 -and $hklmShellSets.Count -ge 1) {
            Assert-True ($planCalls[0].Extent.StartOffset -lt $hklmShellSets[0].Extent.StartOffset) `
                "Get-ShellActivationPlan runs BEFORE the HKLM Shell write, not after (this is the exact ordering defect that shipped: Set-ItemProperty ran first, Test-Path ran second)"
        }
        else {
            Assert-True $false "cannot check ordering -- one of the two call sites above was not found"
        }

        $hklcuShellSets = @($ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.CommandAst] -and $n.GetCommandName() -eq "Set-ItemProperty" }, $true) |
            Where-Object { $_.Extent.Text -match "winlogonHKCU" -and $_.Extent.Text -match 'Name\s+"Shell"' })
        Assert-True ($hklcuShellSets.Count -eq 1 -and $hklcuShellSets[0].Extent.Text -match "explorer\.exe") `
            "the admin HKCU override is untouched by this fix: still set unconditionally to explorer.exe"

        Section "Binding: the HKLM Shell write uses the PLAN'S value, not just runs after it"
        # AG-47 QA (VERDICT.txt B1): the ordering check above proves Get-ShellActivationPlan runs before
        # the write, but it never inspected what the write actually WRITES. A mutant that restores the
        # shipped defect in a single identifier -- Set-ItemProperty ... -Value $shellCommand, plan
        # computed and then ignored -- passed every assertion above (mutant M5, verifier's tree). This
        # section closes that: it resolves the BINDING, not the spelling. It finds the variable the
        # Get-ShellActivationPlan call result was assigned to, then requires the -Value argument of the
        # HKLM Shell Set-ItemProperty call to be a member access on that same variable (".shellValue" in
        # the current source, but this asserts the binding, not the literal member name, so a rename
        # doesn't false-fail it).
        function Get-AG47CommandParamValueAst {
            param(
                [Parameter(Mandatory = $true)][System.Management.Automation.Language.CommandAst]$CommandAst,
                [Parameter(Mandatory = $true)][string]$ParamName
            )
            for ($i = 0; $i -lt $CommandAst.CommandElements.Count; $i++) {
                $el = $CommandAst.CommandElements[$i]
                if ($el -is [System.Management.Automation.Language.CommandParameterAst] -and $el.ParameterName -eq $ParamName) {
                    if ($el.Argument) { return $el.Argument }
                    if ($i + 1 -lt $CommandAst.CommandElements.Count) { return $CommandAst.CommandElements[$i + 1] }
                }
            }
            return $null
        }

        $planVarName = $null
        if ($planCalls.Count -ge 1) {
            $walk = $planCalls[0]
            while ($walk -and -not ($walk -is [System.Management.Automation.Language.AssignmentStatementAst])) {
                $walk = $walk.Parent
            }
            if ($walk -and $walk.Left -is [System.Management.Automation.Language.VariableExpressionAst]) {
                $planVarName = $walk.Left.VariablePath.UserPath
            }
        }
        Assert-True (-not [string]::IsNullOrEmpty($planVarName)) `
            "Get-ShellActivationPlan's call site is a direct assignment to a variable (found: `$$planVarName)"

        $bindingOk = $false
        $valueArg = $null
        if ($hklmShellSets.Count -ge 1) {
            $valueArg = Get-AG47CommandParamValueAst -CommandAst $hklmShellSets[0] -ParamName "Value"
        }
        if ($valueArg -and $planVarName -and ($valueArg -is [System.Management.Automation.Language.MemberExpressionAst])) {
            $baseExpr = $valueArg.Expression
            if ($baseExpr -is [System.Management.Automation.Language.VariableExpressionAst] -and
                $baseExpr.VariablePath.UserPath -eq $planVarName) {
                $bindingOk = $true
            }
        }
        Assert-True $bindingOk `
            "the HKLM Shell Set-ItemProperty -Value is a member access on `$$planVarName (the variable the plan's result was assigned to) -- not a re-derived, hardcoded, or bypassed value (catches mutant M5: -Value `$shellCommand, plan computed and then ignored)"

        Section "Behavior: wrapper file absent -> fall back to explorer.exe, and say so truthfully"
        $missingPath = Join-Path $BaseDir "does-not-exist\ABG.LauncherShell.ps1"
        $planMissing = Get-ShellActivationPlan -WrapperPath $missingPath -ShellCommand "powershell -File `"$missingPath`""
        Assert-True ($planMissing.action -ne "ActivateLauncher") "absent wrapper: action is not ActivateLauncher"
        Assert-True ($planMissing.shellValue -eq "explorer.exe") "absent wrapper: shellValue is explorer.exe"
        Assert-True ($planMissing.verified -eq $false) "absent wrapper: verified is false"
        Assert-True ($planMissing.message -match "(?i)not found") "absent wrapper: message says truthfully that the file was not found"
        Assert-True ($planMissing.message -notmatch "(?i)deployed by the first fleet update") `
            "absent wrapper: message does NOT repeat the shipped script's false claim that a fleet update deploys the file"

        Section "Behavior: wrapper present but implausibly small (0 bytes) -> also falls back, not activated"
        $tinyPath = Join-Path $BaseDir "tiny\ABG.LauncherShell.ps1"
        New-Item -ItemType Directory -Force -Path (Split-Path $tinyPath) | Out-Null
        [IO.File]::WriteAllBytes($tinyPath, [byte[]]@())
        $planTiny = Get-ShellActivationPlan -WrapperPath $tinyPath -ShellCommand "powershell -File `"$tinyPath`""
        Assert-True ($planTiny.action -ne "ActivateLauncher") "0-byte wrapper: not activated"
        Assert-True ($planTiny.shellValue -eq "explorer.exe") "0-byte wrapper: shellValue is explorer.exe"
        Assert-True ($planTiny.verified -eq $false) "0-byte wrapper: verified is false"

        Section "Behavior: wrapper present and a real size -> activated, with a read-back size and hash recorded"
        $realPath = Join-Path $BaseDir "real\ABG.LauncherShell.ps1"
        New-Item -ItemType Directory -Force -Path (Split-Path $realPath) | Out-Null
        $sourceWrapper = Join-Path $PSScriptRoot "..\src\BayAgent\bootstrap\ABG.LauncherShell.ps1"
        Copy-Item -LiteralPath (Resolve-Path $sourceWrapper).Path -Destination $realPath -Force
        $expectedHash = (Get-FileHash -LiteralPath $realPath -Algorithm SHA256).Hash
        $shellCmd = "powershell -NoProfile -WindowStyle Hidden -File `"$realPath`""
        $planReal = Get-ShellActivationPlan -WrapperPath $realPath -ShellCommand $shellCmd
        Assert-True ($planReal.action -eq "ActivateLauncher") "real wrapper: action is ActivateLauncher"
        Assert-True ($planReal.shellValue -eq $shellCmd) "real wrapper: shellValue is exactly the shell command passed in"
        Assert-True ($planReal.verified -eq $true) "real wrapper: verified is true"
        Assert-True ($planReal.sizeBytes -gt 1024) "real wrapper: sizeBytes reflects the actual file (read back, not assumed)"
        Assert-True ("$($planReal.sha256)" -eq $expectedHash) "real wrapper: sha256 matches an independently computed hash of the same file"
    }
}
finally {
    try { Remove-Item -LiteralPath $BaseDir -Recurse -Force -ErrorAction SilentlyContinue } catch {}
}

Write-Host ""
Write-Host ("RESULT: {0} passed, {1} failed" -f $script:Pass, $script:Fail) -ForegroundColor $(if ($script:Fail -eq 0) { "Green" } else { "Red" })
if ($script:Fail -gt 0) { $script:Failures | ForEach-Object { Write-Host "  - $_" -ForegroundColor Red }; exit 1 }
exit 0
