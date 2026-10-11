<#
BayAgent.SetupBlankPc.Tests.ps1

What Setup-BayPC.ps1 and ABG-Day0-Setup.ps1 tell and do to a BLANK PC, pinned without touching the machine.

WHY THIS SUITE EXISTS (PC swap preparation, 2026-10-11). No record shows Setup-BayPC.ps1 run start to finish on a blank
PC; its one recorded run changed a working bay. Reading it against the rulings found five things a first blank-PC run
would have hit:
  1. Phase 5C turned Remote Desktop ON on every run and Phase 7 scored "enabled" as PASS. The designed lockdown has it
     off (A0.216).
  2. On the default certificate credential, Phase 7 said "DPAPI secret exists: PENDING (run SetClientSecretDpapi)" and
     Next Steps said "1. Run ABG.SetClientSecretDpapi.ps1", directly under a Phase 6 that says DO NOT create one. A
     secret file makes the Day-0 certificate enroll as waiting instead of active, and it then cannot activate.
  3. Phase 6 printed the enroll command with a path that never exists (BayAgent\BayAgent.ps1); the agent is installed
     to BayAgent\current\, and only by the first run of Update-BayAgent.ps1, which nothing mentioned.
  4. The secret-credential tool the script points at (bootstrap\ABG.SetClientSecretDpapi.ps1) was put on a bay by
     nothing: Day0 did not download it and the release package does not ship it. So the fallback did not exist either.
  5. Automatic sign-in was written with the computer's CURRENT name after Phase 1d had just renamed it, and both
     download addresses named the repository's previous owner (working only through a redirect).

This suite lifts the decision functions out of both scripts by AST (the pattern of BayAgent.SetupShell.Tests.ps1) and
checks the call sites bind to them. No registry write, no download, no admin rights.

FIX ROUND (same day, after the independent attack). Three stops that kept the script from finishing any run are
fixed and pinned here as functions: a missing registry value under strict mode, Set-ExecutionPolicy's terminating
error in a process started with -ExecutionPolicy Bypass, and .Count on zero rows or one. Also here: the script policy
is set on every run and the task rows fail when it cannot run them; only values the operator typed reach the
configuration; a certificate bay gets neither the secret tool nor a fallback (A0.529).

THIS SUITE CANNOT FAIL ON WHAT THE SCRIPT BODY DOES, only on its lifted functions and pinned call sites. The attack
showed that: 17 of 17 changes planted in the body passed it. tests\BayAgent.SetupRun.Tests.ps1 runs the real text
top to bottom and is the suite that answers for the script as a whole. Keep both.

WHAT THIS DOES NOT PROVE
  It does not run either script. A blank-PC run on real hardware is still the first one. It does not prove that
  Windows accepts an automatic sign-in whose domain value is the new computer name before the first reboot (that
  needs the real machine), nor anything about BayAgent.ps1 itself.

Run (from the repo root):
  powershell -NoProfile -ExecutionPolicy Bypass -File tests\BayAgent.SetupBlankPc.Tests.ps1
Exit code 0 = all assertions passed. Hyphens only in comments.
#>
[CmdletBinding()]
param(
    [string]$SetupScript = "",
    [string]$Day0Script = ""
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

if ([string]::IsNullOrWhiteSpace($SetupScript)) { $SetupScript = Join-Path $PSScriptRoot "..\src\BayAgent\tools\Setup-BayPC.ps1" }
if ([string]::IsNullOrWhiteSpace($Day0Script))  { $Day0Script  = Join-Path $PSScriptRoot "..\tools\ABG-Day0-Setup.ps1" }
$SetupScript = (Resolve-Path $SetupScript).Path
$Day0Script  = (Resolve-Path $Day0Script).Path

$script:Pass = 0; $script:Fail = 0; $script:Failures = @()
function Assert-True([bool]$cond, [string]$msg) {
    if ($cond) { $script:Pass++; Write-Host "  PASS  $msg" }
    else { $script:Fail++; $script:Failures += $msg; Write-Host "  FAIL  $msg" -ForegroundColor Red }
}
function Section([string]$name) { Write-Host ""; Write-Host "== $name" -ForegroundColor Cyan }

function Get-BlankPcFunctionText($Ast, [string]$Name) {
    $defs = @($Ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $true) | Where-Object { $_.Name -eq $Name })
    if ($defs.Count -ne 1) { return $null }
    return $defs[0].Extent.Text
}
function Get-BlankPcCommands($Ast, [string]$Name) {
    return @($Ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.CommandAst] }, $true) | Where-Object { $_.GetCommandName() -eq $Name })
}
function Get-BlankPcParamValueAst($CommandAst, [string]$ParamName) {
    for ($i = 0; $i -lt $CommandAst.CommandElements.Count; $i++) {
        $el = $CommandAst.CommandElements[$i]
        if ($el -is [System.Management.Automation.Language.CommandParameterAst] -and $el.ParameterName -eq $ParamName) {
            if ($el.Argument) { return $el.Argument }
            if ($i + 1 -lt $CommandAst.CommandElements.Count) { return $CommandAst.CommandElements[$i + 1] }
        }
    }
    return $null
}
function Get-BlankPcStringLiterals($Ast) {
    # Every string the code can act on (constants and the text of expandable strings); comments are not in the AST.
    $out = @()
    foreach ($n in $Ast.FindAll({ param($x) ($x -is [System.Management.Automation.Language.StringConstantExpressionAst]) -or ($x -is [System.Management.Automation.Language.ExpandableStringExpressionAst]) }, $true)) { $out += [string]$n.Value }
    return $out
}

$BaseDir = Join-Path $env:TEMP ("bayagent-blankpctest-" + [guid]::NewGuid().ToString("N").Substring(0, 8))
New-Item -ItemType Directory -Force -Path $BaseDir | Out-Null
$planned = 118  # assertions scored as failures when a function this suite needs is missing (a pre-fix script)

try {
    Section "AST: both scripts parse, and the decisions are functions"
    $tok = $null; $err = $null
    $setupAst = [System.Management.Automation.Language.Parser]::ParseFile($SetupScript, [ref]$tok, [ref]$err)
    Assert-True (@($err).Count -eq 0) "Setup-BayPC.ps1 parses cleanly"
    $tok2 = $null; $err2 = $null
    $day0Ast = [System.Management.Automation.Language.Parser]::ParseFile($Day0Script, [ref]$tok2, [ref]$err2)
    Assert-True (@($err2).Count -eq 0) "ABG-Day0-Setup.ps1 parses cleanly"

    $needSetup = @("Get-RemoteDesktopPlan", "Get-RemoteDesktopCheck", "Get-CredentialFileCheck", "Get-Day0NextSteps", "Get-Day0CredentialGuidance",
        "Get-RegistryValueOrNull", "Set-MachineScriptPolicy", "Test-ScriptPolicyRunsTasks", "Get-ScriptPolicyCheck", "Get-ScheduledTaskCheck", "Get-LockdownRowResult")
    $needDay0 = @("Set-AgentConfigTemplateValues", "Write-AgentConfigTemplateIfMissing", "Ensure-Dir")
    $missing = @()
    foreach ($f in $needSetup) { if ($null -eq (Get-BlankPcFunctionText $setupAst $f)) { $missing += "Setup-BayPC.ps1: $f" } }
    foreach ($f in $needDay0)  { if ($null -eq (Get-BlankPcFunctionText $day0Ast $f))  { $missing += "ABG-Day0-Setup.ps1: $f" } }
    Assert-True ($missing.Count -eq 0) ("every decision this suite checks is a function (missing: " + $(if ($missing.Count) { $missing -join "; " } else { "none" }) + ")")

    if ($missing.Count -gt 0) {
        Write-Host ""
        Write-Host "A function is missing -- this is a script from before the blank-PC fix. Nothing below can run." -ForegroundColor Yellow
        1..$planned | ForEach-Object { Assert-True $false "skipped -- a needed function does not exist" }
    }
    else {
        foreach ($f in $needSetup) { . ([scriptblock]::Create((Get-BlankPcFunctionText $setupAst $f))) }
        foreach ($f in $needDay0)  { . ([scriptblock]::Create((Get-BlankPcFunctionText $day0Ast $f))) }
        $setupText = [IO.File]::ReadAllText($SetupScript)

        # ------------------------------------------------------------------------------------------ Remote Desktop
        Section "Remote Desktop is OFF unless asked for (A0.216)"
        $rdpParam = @($setupAst.ParamBlock.Parameters | Where-Object { $_.Name.VariablePath.UserPath -eq "EnableRemoteDesktop" })
        Assert-True ($rdpParam.Count -eq 1 -and "$($rdpParam[0].StaticType.Name)" -eq "SwitchParameter") "Setup-BayPC.ps1 declares -EnableRemoteDesktop as a switch"
        Assert-True ($rdpParam.Count -eq 1 -and $null -eq $rdpParam[0].DefaultValue) "...with no default value (a switch that defaults to on is not a choice)"

        $planOff = Get-RemoteDesktopPlan
        Assert-True ([int]$planOff.denyValue -eq 1) "default plan: fDenyTSConnections value is 1 (Remote Desktop off)"
        Assert-True ($planOff.enable -eq $false -and $planOff.firewallAction -eq "Disable") "default plan: not enabled, firewall group disabled"
        $planOffExplicit = Get-RemoteDesktopPlan -Enable $false
        Assert-True ([int]$planOffExplicit.denyValue -eq 1 -and $planOffExplicit.enable -eq $false) "explicit -Enable `$false gives the same off plan"
        $planOn = Get-RemoteDesktopPlan -Enable $true
        Assert-True ([int]$planOn.denyValue -eq 0 -and $planOn.enable -eq $true -and $planOn.firewallAction -eq "Enable") "asked-for plan: value 0, enabled, firewall group enabled"

        $planCalls = @(Get-BlankPcCommands $setupAst "Get-RemoteDesktopPlan")
        Assert-True ($planCalls.Count -eq 1) "Get-RemoteDesktopPlan is called exactly once in the script body"
        $planArg = $null
        if ($planCalls.Count -eq 1) { $planArg = Get-BlankPcParamValueAst $planCalls[0] "Enable" }
        Assert-True ($null -ne $planArg -and $planArg.Extent.Text -match '\$EnableRemoteDesktop' -and $planArg.Extent.Text -notmatch '(?i)\$true|-not|!') "...and its -Enable is the -EnableRemoteDesktop switch itself (not a constant, not negated)"
        $planVar = $null
        if ($planCalls.Count -eq 1) {
            $walk = $planCalls[0]
            while ($walk -and -not ($walk -is [System.Management.Automation.Language.AssignmentStatementAst])) { $walk = $walk.Parent }
            if ($walk -and $walk.Left -is [System.Management.Automation.Language.VariableExpressionAst]) { $planVar = $walk.Left.VariablePath.UserPath }
        }
        Assert-True (-not [string]::IsNullOrEmpty($planVar)) "the plan is assigned to a variable (found: `$$planVar)"

        $denySets = @(Get-BlankPcCommands $setupAst "Set-ItemProperty" | Where-Object { $_.Extent.Text -match "fDenyTSConnections" })
        Assert-True ($denySets.Count -eq 1) "exactly one Set-ItemProperty writes fDenyTSConnections (no unconditional write survives beside the planned one)"
        $bindOk = $false
        if ($denySets.Count -eq 1 -and $planVar) {
            $v = Get-BlankPcParamValueAst $denySets[0] "Value"
            if ($v -is [System.Management.Automation.Language.MemberExpressionAst] -and $v.Expression -is [System.Management.Automation.Language.VariableExpressionAst] -and
                $v.Expression.VariablePath.UserPath -eq $planVar -and "$($v.Member.Extent.Text)" -eq "denyValue") { $bindOk = $true }
        }
        Assert-True $bindOk "the fDenyTSConnections write takes `$$planVar.denyValue (the plan's value), not a literal"
        if ($denySets.Count -eq 1 -and $planCalls.Count -eq 1) { Assert-True ($planCalls[0].Extent.StartOffset -lt $denySets[0].Extent.StartOffset) "the plan is made BEFORE the registry write" }
        else { Assert-True $false "cannot check ordering -- a call site above was not found" }

        $fwEnable = @(Get-BlankPcCommands $setupAst "Enable-NetFirewallRule" | Where-Object { $_.Extent.Text -match "Remote Desktop" })
        $fwDisable = @(Get-BlankPcCommands $setupAst "Disable-NetFirewallRule" | Where-Object { $_.Extent.Text -match "Remote Desktop" })
        Assert-True ($fwEnable.Count -eq 1 -and $fwDisable.Count -eq 1) "the Remote Desktop firewall group is enabled in one place and disabled in one place"
        $fwGuarded = $false
        if ($fwEnable.Count -eq 1 -and $planVar) {
            $p = $fwEnable[0].Parent
            while ($p -and -not ($p -is [System.Management.Automation.Language.IfStatementAst])) { $p = $p.Parent }
            if ($p -and $p.Clauses.Count -ge 1 -and $p.Clauses[0].Item1.Extent.Text -match ('^\s*\$' + [regex]::Escape($planVar) + '\.enable\s*$') -and
                $fwEnable[0].Extent.StartOffset -ge $p.Clauses[0].Item2.Extent.StartOffset -and $fwEnable[0].Extent.EndOffset -le $p.Clauses[0].Item2.Extent.EndOffset -and
                $null -ne $p.ElseClause -and $fwDisable[0].Extent.StartOffset -ge $p.ElseClause.Extent.StartOffset) { $fwGuarded = $true }
        }
        Assert-True $fwGuarded "the firewall group is enabled only inside `if (`$$planVar.enable)`, and disabled in its else"

        Section "Remote Desktop: the checklist row scores what was asked for"
        $c = Get-RemoteDesktopCheck -DenyValue 1 -WantEnabled $false
        Assert-True ($c.Result -eq "PASS" -and $c.Check -eq "Remote Desktop off") "default run, Remote Desktop off: PASS, and the row is named 'Remote Desktop off'"
        $c = Get-RemoteDesktopCheck -DenyValue 0 -WantEnabled $false
        Assert-True ($c.Result -match "^FAIL") "default run, Remote Desktop ON: FAIL (this is the reading the old row scored PASS)"
        $c = Get-RemoteDesktopCheck -DenyValue $null -WantEnabled $false
        Assert-True ($c.Result -match "^FAIL") "default run, value unreadable: FAIL (unknown is not off)"
        Assert-True ($c.Result -match "^FAIL \(could not read") "...and it says the value could not be read, not that Remote Desktop is on"
        $c = Get-RemoteDesktopCheck -DenyValue 2 -WantEnabled $false
        Assert-True ($c.Result -match "^FAIL \(could not read") "default run, a value that is neither 0 nor 1: FAIL as unreadable (never guessed)"
        $c = Get-RemoteDesktopCheck -DenyValue $null -WantEnabled $true
        Assert-True ($c.Result -match "^FAIL \(could not read") "asked for, value unreadable: FAIL as unreadable"
        $c = Get-RemoteDesktopCheck -DenyValue 0 -WantEnabled $true
        Assert-True ($c.Result -eq "PASS") "asked for and on: PASS"
        $c = Get-RemoteDesktopCheck -DenyValue 1 -WantEnabled $true
        Assert-True ($c.Result -match "^FAIL") "asked for and off: FAIL"
        $checkCalls = @(Get-BlankPcCommands $setupAst "Get-RemoteDesktopCheck")
        $wantArg = $null
        if ($checkCalls.Count -eq 1) { $wantArg = Get-BlankPcParamValueAst $checkCalls[0] "WantEnabled" }
        Assert-True ($checkCalls.Count -eq 1 -and $null -ne $wantArg -and $wantArg.Extent.Text -match '\$EnableRemoteDesktop' -and $wantArg.Extent.Text -notmatch '(?i)\$true|-not|!') "the checklist calls it once, with -WantEnabled bound to the switch itself"
        Assert-True ($setupText -notmatch 'Check\s*=\s*"Remote Desktop enabled"') "the old row (a literal 'Remote Desktop enabled' scored PASS when on) is gone"

        # ------------------------------------------------------------------------------------------ credential
        Section "Certificate bay: nothing tells the operator to create the secret"
        $r = Get-CredentialFileCheck -Mode "Certificate" -DpapiExists $false
        Assert-True ($r.Result -eq "PASS") "certificate bay, no secret file: PASS (absence is the pass)"
        $r = Get-CredentialFileCheck -Mode "Certificate" -DpapiExists $true
        Assert-True ($r.Result -match "^FAIL") "certificate bay WITH a secret file: FAIL (it would make the certificate enroll as waiting)"
        Assert-True ($r.Result -notmatch "SetClientSecretDpapi") "...and that row does not name the tool that creates one"
        $r = Get-CredentialFileCheck -Mode "Secret" -DpapiExists $false
        Assert-True ($r.Result -match "^PENDING" -and $r.Result -match "SetClientSecretDpapi") "secret bay, no file: PENDING, naming the tool (the legacy path is unchanged)"
        $r = Get-CredentialFileCheck -Mode "Secret" -DpapiExists $true
        Assert-True ($r.Result -eq "PASS") "secret bay, file present: PASS"
        $credCheckCalls = @(Get-BlankPcCommands $setupAst "Get-CredentialFileCheck")
        Assert-True ($credCheckCalls.Count -eq 1 -and "$((Get-BlankPcParamValueAst $credCheckCalls[0] 'Mode').Extent.Text)" -eq '$Credential') "the checklist calls it once, with -Mode `$Credential"
        Assert-True ($setupText -notmatch 'Check\s*=\s*"DPAPI secret exists"\s*\r?\n\s*Result\s*=\s*if') "the old unconditional 'DPAPI secret exists' row is gone"

        Section "Summary buckets: every row text falls in exactly one of PASS / FAIL / PENDING"
        $rows = @()
        foreach ($m in @("Certificate", "Secret")) { foreach ($e in @($true, $false)) { $rows += (Get-CredentialFileCheck -Mode $m -DpapiExists $e).Result } }
        foreach ($d in @(0, 1, $null)) { foreach ($w in @($true, $false)) { $rows += (Get-RemoteDesktopCheck -DenyValue $d -WantEnabled $w).Result } }
        foreach ($pol in @("AllSigned", "Undefined", "Restricted", "")) {
            $rows += (Get-ScriptPolicyCheck -MachinePolicy $pol).Result
            foreach ($ex in @($true, $false)) { $rows += (Get-ScheduledTaskCheck -TaskName "T" -Exists $ex -State "Ready" -MachinePolicy $pol).Result }
        }
        foreach ($ok in @($true, $false)) { foreach ($sk in @($true, $false)) { $rows += (Get-LockdownRowResult -Ok $ok -LockdownSkipped $sk) } }
        $bad = @($rows | Where-Object { $row = $_; $n = 0; foreach ($k in @("PASS", "FAIL", "PENDING")) { if ($row -match $k) { $n++ } }; $n -ne 1 })
        Assert-True ($bad.Count -eq 0) ("each of the $($rows.Count) possible row texts matches exactly one summary bucket (offenders: " + $(if ($bad.Count) { $bad -join " | " } else { "none" }) + ")")

        # ------------------------------------------------------------------------------------------ the three stops (fix round)
        Section "A missing registry value is an answer, not a stop (strict mode)"
        Assert-True ($null -eq (Get-RegistryValueOrNull -Path "HKCU:\Software\AocNoSuchKey-$([guid]::NewGuid().ToString('N'))" -Name "Anything")) "a key that does not exist: null, no error"
        Assert-True ($null -eq (Get-RegistryValueOrNull -Path "HKCU:\Environment" -Name "AocNoSuchValue-$([guid]::NewGuid().ToString('N'))")) "a value that does not exist under a real key: null, no error (the read that stopped the run)"
        Assert-True (-not [string]::IsNullOrWhiteSpace([string](Get-RegistryValueOrNull -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion" -Name "ProductName"))) "a value that exists comes back as its value"
        $memberReads = @($setupAst.FindAll({ param($n) $n -is [System.Management.Automation.Language.MemberExpressionAst] -and $n.Expression -is [System.Management.Automation.Language.ParenExpressionAst] -and $n.Expression.Extent.Text -match 'Get-ItemProperty' }, $true))
        Assert-True ($memberReads.Count -eq 0) ("no statement reads a property straight off (Get-ItemProperty ...) any more (found " + $memberReads.Count + ")")
        $rawReads = @(Get-BlankPcCommands $setupAst "Get-ItemProperty")
        $rawOutside = @($rawReads | Where-Object { $p = $_.Parent; $inHelper = $false; while ($p) { if ($p -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $p.Name -eq "Get-RegistryValueOrNull") { $inHelper = $true }; $p = $p.Parent }; -not $inHelper })
        Assert-True ($rawReads.Count -eq 1 -and $rawOutside.Count -eq 0) "Get-ItemProperty is called in one place only: inside Get-RegistryValueOrNull"
        Assert-True (@(Get-BlankPcCommands $setupAst "Get-RegistryValueOrNull").Count -eq 7) "the seven registry readings of the checklist all go through it"
        $parenCounts = @($setupAst.FindAll({ param($n) $n -is [System.Management.Automation.Language.MemberExpressionAst] -and "$($n.Member.Extent.Text)" -eq "Count" -and $n.Expression -is [System.Management.Automation.Language.ParenExpressionAst] -and $n.Expression.Extent.Text -match 'Where-Object' }, $true))
        Assert-True ($parenCounts.Count -eq 0) "no .Count is taken straight off a (... | Where-Object ...) pipeline (zero rows or one row stopped the summary)"

        Section "The machine script policy: set through one function that cannot stop the run, on every run"
        $spCalls = @(Get-BlankPcCommands $setupAst "Set-ExecutionPolicy")
        $spInside = @($spCalls | Where-Object { $p = $_.Parent; $inFn = $false; $inTry = $false; while ($p) { if ($p -is [System.Management.Automation.Language.TryStatementAst]) { $inTry = $true }; if ($p -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $p.Name -eq "Set-MachineScriptPolicy") { $inFn = $true }; $p = $p.Parent }; $inFn -and $inTry })
        Assert-True ($spCalls.Count -eq 1 -and $spInside.Count -eq 1) "Set-ExecutionPolicy is called once, inside Set-MachineScriptPolicy's try"
        $smCalls = @(Get-BlankPcCommands $setupAst "Set-MachineScriptPolicy")
        $smConditional = @($smCalls | Where-Object { $p = $_.Parent; $inIf = $false; while ($p) { if ($p -is [System.Management.Automation.Language.IfStatementAst] -or $p -is [System.Management.Automation.Language.FunctionDefinitionAst]) { $inIf = $true }; $p = $p.Parent }; $inIf })
        Assert-True ($smCalls.Count -eq 1 -and $smConditional.Count -eq 0) "Set-MachineScriptPolicy is called once, under no if at all: not inside the lockdown phase, not behind any skip switch"
        # The function, with the two cmdlets it calls replaced by stand-ins (a function outranks a cmdlet).
        $script:FakePolicy = "Undefined"; $script:FakeTakes = $true; $script:FakeThrows = $true
        function Get-ExecutionPolicy { param([string]$Scope) return $script:FakePolicy }
        function Set-ExecutionPolicy {
            [CmdletBinding()] param([string]$ExecutionPolicy, [string]$Scope, [switch]$Force)
            if ($script:FakeTakes) { $script:FakePolicy = $ExecutionPolicy }
            if ($script:FakeThrows) { throw "Windows PowerShell updated your execution policy successfully, but the setting is overridden by a policy defined at a more specific scope." }
        }
        $threw = $false; $res = $null
        try { $res = Set-MachineScriptPolicy -Wanted "AllSigned" } catch { $threw = $true }
        Assert-True (-not $threw -and $null -ne $res -and $res.ok -eq $true -and $res.policy -eq "AllSigned") "the override error after a write that took: no throw, ok, read back as AllSigned"
        Assert-True ($null -ne $res -and "$($res.note)" -match "overridden") "...and the error text is kept as a note, not swallowed"
        $script:FakePolicy = "Undefined"; $script:FakeTakes = $false; $script:FakeThrows = $true
        $threw = $false; $res = $null
        try { $res = Set-MachineScriptPolicy -Wanted "AllSigned" } catch { $threw = $true }
        Assert-True (-not $threw -and $null -ne $res -and $res.ok -eq $false -and $res.policy -eq "Undefined") "an error after a write that did NOT take: no throw, and NOT ok (the read-back decides, never the absence of an error)"
        $script:FakePolicy = "Undefined"; $script:FakeTakes = $true; $script:FakeThrows = $false
        $res = Set-MachineScriptPolicy -Wanted "AllSigned"
        Assert-True ($res.ok -eq $true -and "$($res.note)" -eq "") "no error and a write that took: ok, no note"
        Remove-Item function:Get-ExecutionPolicy, function:Set-ExecutionPolicy -ErrorAction SilentlyContinue

        Section "The checklist rows about the policy, the tasks and the lockdown"
        Assert-True ((Get-ScriptPolicyCheck -MachinePolicy "AllSigned").Result -eq "PASS") "policy AllSigned: PASS"
        foreach ($pol in @("Undefined", "Restricted", "")) { Assert-True ((Get-ScriptPolicyCheck -MachinePolicy $pol).Result -match "^FAIL") "policy '$pol': FAIL (it used to read WARN, a text in no summary bucket)" }
        Assert-True ((Test-ScriptPolicyRunsTasks -MachinePolicy "AllSigned") -and -not (Test-ScriptPolicyRunsTasks -MachinePolicy "Undefined") -and -not (Test-ScriptPolicyRunsTasks -MachinePolicy "Restricted") -and -not (Test-ScriptPolicyRunsTasks -MachinePolicy "")) "the tasks can start under AllSigned; not under Undefined, Restricted or an unreadable policy"
        Assert-True ((Get-ScheduledTaskCheck -TaskName "ABG Bay Agent" -Exists $true -State "Ready" -MachinePolicy "AllSigned").Result -eq "PASS (Ready)") "a registered task under AllSigned: PASS"
        Assert-True ((Get-ScheduledTaskCheck -TaskName "ABG Bay Agent" -Exists $true -State "Ready" -MachinePolicy "Undefined").Result -match "^FAIL \(registered, but") "a registered task the policy will not start: FAIL, saying why (it used to read PASS)"
        Assert-True ((Get-ScheduledTaskCheck -TaskName "ABG Bay Agent" -Exists $false -MachinePolicy "AllSigned").Result -eq "FAIL") "a task that is not registered: FAIL"
        Assert-True ((Get-ScheduledTaskCheck -TaskName "ABG Host Watchdog" -Exists $true -State "Ready" -MachinePolicy "AllSigned").Check -eq "Scheduled task: ABG Host Watchdog") "the row keeps its name"
        Assert-True ((Get-LockdownRowResult -Ok $true -LockdownSkipped $false) -eq "PASS" -and (Get-LockdownRowResult -Ok $true -LockdownSkipped $true) -eq "PASS") "a lockdown row that holds: PASS, skipped or not"
        Assert-True ((Get-LockdownRowResult -Ok $false -LockdownSkipped $true) -match "^PENDING") "not set, and the lockdown was skipped on purpose: PENDING"
        Assert-True ((Get-LockdownRowResult -Ok $false -LockdownSkipped $false) -eq "FAIL") "not set after a lockdown run: FAIL"
        $lockCalls = @(Get-BlankPcCommands $setupAst "Get-LockdownRowResult")
        Assert-True ($lockCalls.Count -eq 4 -and @($lockCalls | Where-Object { "$((Get-BlankPcParamValueAst $_ 'LockdownSkipped').Extent.Text)" -eq '([bool]$SkipLockdown)' }).Count -eq 4) "the four lockdown rows use it, each told from -SkipLockdown itself"
        Assert-True (@(Get-BlankPcStringLiterals $setupAst | Where-Object { $_ -match '^WARN\b' }).Count -eq 0) "no string the code can print as a result starts with WARN any more"

        Section "Next Steps: the order a blank PC needs, and no secret on a certificate bay"
        $s = @(Get-Day0NextSteps -Mode "Certificate" -DpapiExists $false -NameOk $true -ExpectedName "BAY9KIOSK" -AgentInstalled $false -Root "C:\AllBirdies" -BayKioskUser "BayKiosk")
        $joined = $s -join "`n"
        Assert-True ($joined -notmatch "SetClientSecretDpapi") "certificate bay: Next Steps never names SetClientSecretDpapi"
        Assert-True ($joined -match "(?i)do not create a DPAPI secret") "...and says not to create one"
        $iInstall = -1; $iEnroll = -1
        for ($i = 0; $i -lt $s.Count; $i++) { if ($iInstall -lt 0 -and $s[$i] -match "Update-BayAgent\.ps1") { $iInstall = $i }; if ($iEnroll -lt 0 -and $s[$i] -match "-EnrollCert") { $iEnroll = $i } }
        Assert-True ($iInstall -ge 0) "blank PC (agent not installed): the first install with Update-BayAgent.ps1 is a step"
        Assert-True ($iEnroll -ge 0 -and $s[$iEnroll].Contains('"C:\AllBirdies\BayAgent\current\BayAgent.ps1" -EnrollCert')) "the enroll step runs BayAgent.ps1 from BayAgent\current\ (where the install puts it)"
        Assert-True ($iInstall -ge 0 -and $iEnroll -gt $iInstall) "the install step comes BEFORE the enroll step"
        Assert-True ($joined -notmatch '\\BayAgent\\BayAgent\.ps1') "no step names the path BayAgent\BayAgent.ps1 (nothing is ever installed there)"
        $nums = @($s | Where-Object { $_ -match '^\d+\. ' } | ForEach-Object { [int]($_ -replace '^(\d+)\..*$', '$1') })
        Assert-True ($nums.Count -ge 5 -and (($nums -join ",") -eq ((1..$nums.Count) -join ","))) "steps are numbered 1..n with no gap and no repeat"
        Assert-True ($s[0] -notmatch "(?i)reboot to apply the computer name") "name already right: no rename reboot step"

        $s2 = @(Get-Day0NextSteps -Mode "Certificate" -DpapiExists $false -NameOk $false -ExpectedName "BAY9KIOSK" -AgentInstalled $true)
        Assert-True ($s2[0] -match "^1\. Reboot to apply the computer name change to 'BAY9KIOSK'") "rename pending: the reboot is step 1"
        Assert-True (($s2 -join "`n") -notmatch "Update-BayAgent\.ps1") "agent already installed: no install step"
        $s3 = @(Get-Day0NextSteps -Mode "Secret" -DpapiExists $false -AgentInstalled $true)
        Assert-True (($s3 -join "`n") -match "SetClientSecretDpapi") "secret bay without the file: the step to create it is there"
        Assert-True (($s3 -join "`n") -notmatch "-EnrollCert") "...and no enroll step"
        $s4 = @(Get-Day0NextSteps -Mode "Secret" -DpapiExists $true -AgentInstalled $true)
        Assert-True (($s4 -join "`n") -notmatch "SetClientSecretDpapi") "secret bay with the file: no step to create it"
        $stepCalls = @(Get-BlankPcCommands $setupAst "Get-Day0NextSteps")
        Assert-True ($stepCalls.Count -eq 1 -and "$((Get-BlankPcParamValueAst $stepCalls[0] 'Mode').Extent.Text)" -eq '$Credential') "the script builds Next Steps once, with -Mode `$Credential"
        Assert-True ($setupText -notmatch '\$nextSteps\s*\+=\s*"1\. Run ABG\.SetClientSecretDpapi') "the old hard-coded step 1 is gone"

        Section "Phase 6 guidance: a command that can run on a blank PC"
        $g = Get-Day0CredentialGuidance -Mode "Certificate" -DpapiPath "C:\AllBirdies\BayAgent\secrets\clientsecret.dpapi" -Root "C:\AllBirdies" -BayKioskUser "BayKiosk"
        $gl = $g.lines -join "`n"
        Assert-True ($gl.Contains('"C:\AllBirdies\BayAgent\current\BayAgent.ps1" -EnrollCert')) "certificate guidance runs current\BayAgent.ps1 -EnrollCert"
        Assert-True ($gl -notmatch '\\BayAgent\\BayAgent\.ps1') "...and never the path that does not exist"
        Assert-True ($gl -match "(?i)first install the agent package" -and $gl -match "Update-BayAgent\.ps1") "...and says the agent package is installed first"
        Assert-True ($gl -match "BayKiosk") "...and says which account runs it (the key is made in that account's store)"
        Assert-True ($gl -notmatch "SetClientSecretDpapi" -and $gl -match "(?i)do not create") "...and still forbids the secret (T28's rule kept)"
        Assert-True ($gl -match "IF ENROLLMENT FAILS, STOP HERE" -and $gl -match "(?i)do not switch this bay to the shared client secret") "...and says a failed enrollment is a stop, not a reason to fall back to the shared secret (A0.529)"
        $gs = Get-Day0CredentialGuidance -Mode "Secret" -DpapiPath "C:\AllBirdies\BayAgent\secrets\clientsecret.dpapi" -Root "C:\AllBirdies" -BayKioskUser "BayKiosk"
        Assert-True (($gs.lines -join "`n").Contains('"C:\AllBirdies\BayAgent\bootstrap\ABG.SetClientSecretDpapi.ps1"')) "secret guidance still runs the tool from bootstrap\ (where Day0 now puts it)"

        # ------------------------------------------------------------------------------------------ names and addresses
        Section "Automatic sign-in uses the name the PC will have, and the addresses name the current owner"
        $domSets = @(Get-BlankPcCommands $setupAst "Set-ItemProperty" | Where-Object { $_.Extent.Text -match '"DefaultDomainName"' })
        $domVal = $null
        if ($domSets.Count -eq 1) { $domVal = Get-BlankPcParamValueAst $domSets[0] "Value" }
        Assert-True ($domSets.Count -eq 1 -and $domVal -is [System.Management.Automation.Language.VariableExpressionAst] -and $domVal.VariablePath.UserPath -eq "expectedName") "DefaultDomainName is written from `$expectedName (the name after the rename), not `$env:COMPUTERNAME"
        foreach ($pn in @("FleetRawBaseUrl", "Day0Url")) {
            $pp = @($setupAst.ParamBlock.Parameters | Where-Object { $_.Name.VariablePath.UserPath -eq $pn })
            Assert-True ($pp.Count -eq 1 -and "$($pp[0].DefaultValue.Value)" -match '^https://raw\.githubusercontent\.com/millwright-works/abg-fleet-updates/main/') "-$pn defaults to the repository's current owner"
        }
        $day0Param = @($setupAst.ParamBlock.Parameters | Where-Object { $_.Name.VariablePath.UserPath -eq "Day0Url" })
        Assert-True ($day0Param.Count -eq 1 -and "$($day0Param[0].DefaultValue.Value)" -match '/tools/ABG-Day0-Setup\.ps1$') "-Day0Url points at tools/ABG-Day0-Setup.ps1"
        $iwr = @(Get-BlankPcCommands $setupAst "Invoke-WebRequest")
        $iwrUri = $null
        if ($iwr.Count -eq 1) { $iwrUri = Get-BlankPcParamValueAst $iwr[0] "Uri" }
        Assert-True ($iwr.Count -eq 1 -and $iwrUri -is [System.Management.Automation.Language.VariableExpressionAst] -and $iwrUri.VariablePath.UserPath -eq "Day0Url") "the one download in Setup-BayPC.ps1 fetches `$Day0Url (no literal address)"
        $oldOwner = @((Get-BlankPcStringLiterals $setupAst) + (Get-BlankPcStringLiterals $day0Ast) | Where-Object { $_ -match "(?i)kedaheaven" })
        Assert-True ($oldOwner.Count -eq 0) "no string the code can act on, in either script, names the previous owner"

        Section "Only values the operator TYPED reach the configuration; a default never does"
        $allAssign = @($setupAst.FindAll({ param($n) $n -is [System.Management.Automation.Language.AssignmentStatementAst] }, $true))
        foreach ($k in @("EnvironmentUrl", "TenantId", "ClientId", "BayId")) {
            $cfgAssign = @($allAssign | Where-Object { $_.Left.Extent.Text -eq ('$day0Args["Config' + $k + '"]') -and $_.Right.Extent.Text -eq ('$' + $k) })
            $guarded = @($cfgAssign | Where-Object {
                $p = $_.Parent; $ok = $false
                while ($p) { if ($p -is [System.Management.Automation.Language.IfStatementAst] -and $p.Clauses[0].Item1.Extent.Text -match ('^\s*\$PSBoundParameters\.ContainsKey\("' + $k + '"\)\s+-and\s')) { $ok = $true }; $p = $p.Parent }
                $ok })
            Assert-True ($cfgAssign.Count -eq 1 -and $guarded.Count -eq 1) "`$day0Args[`"Config$k`"] is set from `$$k, and only when -$k was actually passed (`$PSBoundParameters)"
            $plain = @($allAssign | Where-Object { $_.Left.Extent.Text -eq ('$day0Args["' + $k + '"]') })
            $plainOutside = @($plain | Where-Object {
                $p = $_.Parent; $inRegister = $false
                while ($p) { if ($p -is [System.Management.Automation.Language.IfStatementAst] -and $p.Clauses[0].Item1.Extent.Text -match '^\s*\$RegisterConfigItems\s*$') { $inRegister = $true }; $p = $p.Parent }
                -not $inRegister })
            Assert-True ($plainOutside.Count -eq 0) "the registration value `$day0Args[`"$k`"] (which may be a default) is set nowhere outside the -RegisterConfigItems branch"
        }
        $toolAssign = @($allAssign | Where-Object { $_.Left.Extent.Text -eq '$day0Args["PlaceSecretTool"]' })
        $toolGuarded = @($toolAssign | Where-Object { $p = $_.Parent; $ok = $false; while ($p) { if ($p -is [System.Management.Automation.Language.IfStatementAst] -and $p.Clauses[0].Item1.Extent.Text -match '^\s*\$Credential\s+-eq\s+"Secret"\s*$') { $ok = $true }; $p = $p.Parent }; $ok })
        Assert-True ($toolAssign.Count -eq 1 -and $toolGuarded.Count -eq 1) "Day0 is asked to place the secret tool in one place only: under if (`$Credential -eq `"Secret`")"

        # ------------------------------------------------------------------------------------------ Day0
        Section "Day0: the config template takes real values, and refuses a value that is not one"
        $tenant = "11111111-2222-3333-4444-555555555555"; $client = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"; $bay = "99999999-8888-7777-6666-555555555555"
        $p1 = Join-Path $BaseDir "full\agent-config.json"
        Write-AgentConfigTemplateIfMissing -path $p1 -envUrl "https://example-org.crm.dynamics.com/" -tenant $tenant -client $client -bay $bay 6>$null
        $j1 = Get-Content -LiteralPath $p1 -Raw | ConvertFrom-Json
        Assert-True ($j1.environmentUrl -eq "https://example-org.crm.dynamics.com" -and $j1.tenantId -eq $tenant -and $j1.clientId -eq $client -and $j1.bayId -eq $bay) "four good values: the file parses as JSON and holds exactly those values"
        Assert-True ((Get-Content -LiteralPath $p1 -Raw) -notmatch "<[a-z-]+>") "...and no <placeholder> is left"
        Assert-True ($j1.clientSecretDpapiPath -eq "C:\AllBirdies\BayAgent\secrets\clientsecret.dpapi" -and "$($j1.clientCertThumbprint)" -eq "") "...and the credential fields are as shipped (the path is named, no thumbprint): the shape a Day-0 enroll activates on"

        $p2 = Join-Path $BaseDir "none\agent-config.json"
        Write-AgentConfigTemplateIfMissing -path $p2 6>$null
        $t2 = Get-Content -LiteralPath $p2 -Raw
        Assert-True ($t2.Contains("<your-org>") -and $t2.Contains("<tenant-guid>") -and $t2.Contains("<app-client-id>") -and $t2.Contains("<bay-guid>")) "no values given: all four placeholders stay (the old behavior)"

        $r3 = Set-AgentConfigTemplateValues -Template $t2 -EnvironmentUrl "builds-apps-dev.crm.dynamics.com" -TenantId "not-a-guid" -ClientId $client -BayId "00000000-0000-0000-0000-000000000000"
        Assert-True ($r3.text.Contains("<your-org>") -and $r3.text.Contains("<tenant-guid>") -and $r3.text.Contains("<bay-guid>")) "an address without https, a non-GUID and the empty GUID are NOT written: their placeholders stay"
        Assert-True ($r3.text.Contains($client) -and -not $r3.text.Contains("<app-client-id>")) "...while the one good value beside them is written"
        Assert-True (@($r3.unfilled).Count -eq 3 -and (@($r3.unfilled) -contains "<bay-guid>")) "...and the three unfilled fields are reported by name"
        $r4 = Set-AgentConfigTemplateValues -Template $t2 -EnvironmentUrl ('https://evil.example.com/x","client' + 'Secret' + '":"y') -TenantId $tenant -ClientId $client -BayId $bay
        Assert-True ($r4.text.Contains("<your-org>") -and $r4.text -notmatch "evil") "an address carrying a quote or a path cannot inject into the JSON: it is not written"

        [IO.File]::WriteAllText($p1, '{"keep":"me"}')
        Write-AgentConfigTemplateIfMissing -path $p1 -envUrl "https://other.crm.dynamics.com" -tenant $tenant -client $client -bay $bay 6>$null
        Assert-True ((Get-Content -LiteralPath $p1 -Raw).Trim() -eq '{"keep":"me"}') "an existing agent-config.json is never overwritten"
        $tplCalls = @(Get-BlankPcCommands $day0Ast "Write-AgentConfigTemplateIfMissing")
        Assert-True ($tplCalls.Count -eq 1 -and "$((Get-BlankPcParamValueAst $tplCalls[0] 'bay').Extent.Text)" -eq '$ConfigBayId' -and "$((Get-BlankPcParamValueAst $tplCalls[0] 'client').Extent.Text)" -eq '$ConfigClientId' -and
            "$((Get-BlankPcParamValueAst $tplCalls[0] 'tenant').Extent.Text)" -eq '$ConfigTenantId' -and "$((Get-BlankPcParamValueAst $tplCalls[0] 'envUrl').Extent.Text)" -eq '$ConfigEnvironmentUrl') "Day0 calls the template writer once, each value bound to its own Config parameter (never to the registration parameters)"
        foreach ($cp in @("ConfigEnvironmentUrl", "ConfigTenantId", "ConfigClientId", "ConfigBayId")) {
            $dp = @($day0Ast.ParamBlock.Parameters | Where-Object { $_.Name.VariablePath.UserPath -eq $cp })
            Assert-True ($dp.Count -eq 1 -and "$($dp[0].DefaultValue.Value)" -eq "") "Day0 declares -$cp, empty by default"
        }

        Section "Day0: the secret-credential tool goes only where it is asked for, unsigned, and is run by nobody"
        $dl = @(Get-BlankPcCommands $day0Ast "Download-File" | Where-Object { $_.Extent.Text -match '/bootstrap/ABG\.SetClientSecretDpapi\.ps1' })
        Assert-True ($dl.Count -eq 1) "Day0 downloads bootstrap/ABG.SetClientSecretDpapi.ps1 in exactly one place"
        $dlGuarded = $false
        if ($dl.Count -eq 1) { $p = $dl[0].Parent; while ($p) { if ($p -is [System.Management.Automation.Language.IfStatementAst] -and $p.Clauses[0].Item1.Extent.Text -match '^\s*\$PlaceSecretTool\s*$') { $dlGuarded = $true }; $p = $p.Parent } }
        Assert-True $dlGuarded "...and only under if (`$PlaceSecretTool): a certificate bay does not get the tool (A0.529)"
        $toolParam = @($day0Ast.ParamBlock.Parameters | Where-Object { $_.Name.VariablePath.UserPath -eq "PlaceSecretTool" })
        Assert-True ($toolParam.Count -eq 1 -and "$($toolParam[0].StaticType.Name)" -eq "SwitchParameter" -and "$($toolParam[0].DefaultValue)" -match '^\$false$') "-PlaceSecretTool is a switch that is off unless given"
        $outVar = $null
        if ($dl.Count -eq 1) { $o = Get-BlankPcParamValueAst $dl[0] "outPath"; if ($o -is [System.Management.Automation.Language.VariableExpressionAst]) { $outVar = $o.VariablePath.UserPath } }
        $outAssign = @($day0Ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.AssignmentStatementAst] }, $true) | Where-Object { $outVar -and $_.Left.Extent.Text -eq ('$' + $outVar) })
        Assert-True ($outVar -and $outAssign.Count -eq 1 -and $outAssign[0].Right.Extent.Text -match 'bootstrap\\ABG\.SetClientSecretDpapi\.ps1') "...to BayAgent\bootstrap\ABG.SetClientSecretDpapi.ps1, the path Setup-BayPC.ps1 prints"
        $signed = @(Get-BlankPcCommands $day0Ast "Sign-File" | Where-Object { $outVar -and $_.Extent.Text -match ('\$' + [regex]::Escape($outVar) + '\b') })
        Assert-True ($signed.Count -eq 0) "...and it is NOT in the signing list (deliberately unsigned, ruled 2026-08-03 in that script's own header)"
        $runs = @($day0Ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.CommandAst] }, $true) | Where-Object { $_.InvocationOperator -ne [System.Management.Automation.Language.TokenKind]::Unknown -and $outVar -and $_.Extent.Text -match ('\$' + [regex]::Escape($outVar) + '\b') })
        Assert-True ($runs.Count -eq 0) "...and Day0 never RUNS it (downloading it creates no secret)"
        Assert-True (Test-Path (Join-Path (Split-Path -Parent $Day0Script) "..\src\BayAgent\bootstrap\ABG.SetClientSecretDpapi.ps1")) "the file exists in the repository at src/BayAgent/bootstrap, so the address resolves at this commit"
        $five = @("/bootstrap/ABG.AgentHost.ps1", "/bootstrap/ABG.HostWatchdog.ps1", "/tools/Update-BayAgent.ps1", "/tools/Update-SessionDisplay.ps1", "/tools/Update-PromosPack.ps1")
        $allDl = @(Get-BlankPcCommands $day0Ast "Download-File" | ForEach-Object { $_.Extent.Text })
        Assert-True (@($five | Where-Object { $f = $_; @($allDl | Where-Object { $_.Contains($f) }).Count -eq 1 }).Count -eq 5 -and $allDl.Count -eq 6) "the five downloads that were there are still there, once each; six in all"
    }
}
finally {
    try { Remove-Item -LiteralPath $BaseDir -Recurse -Force -ErrorAction SilentlyContinue } catch {}
}

Write-Host ""
Write-Host ("RESULT: {0} passed, {1} failed" -f $script:Pass, $script:Fail) -ForegroundColor $(if ($script:Fail -eq 0) { "Green" } else { "Red" })
if ($script:Fail -gt 0) { $script:Failures | ForEach-Object { Write-Host "  - $_" -ForegroundColor Red }; exit 1 }
exit 0
