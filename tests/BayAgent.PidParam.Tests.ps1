<#
BayAgent.PidParam.Tests.ps1

WHY THIS EXISTS
  Three pre-existing defects found by the self-heal Phase 2 builder (2026-10-02). Each is pinned by BEHAVIOR, on both
  Windows PowerShell 5.1 and pwsh 7:

    P1  The window-routing functions declared a parameter named after the automatic variable $pid. Binding it throws
        "Cannot overwrite variable PID because it is read-only or constant", so moving program windows to their screens
        always failed (caught and logged as a WARN). Tested by calling the SHIPPED functions with the real Id of a
        process this test starts, and with a name scan for any parameter named after an automatic variable.
    P2  Invoke-DvSafe's "Dataverse response body" line read the already-consumed response stream, which is empty on 5.1.
        Tested against a real local HTTP listener that answers 400 with a Dataverse-shaped JSON body.
    P3  src\BayAgent\agent-config.json is a template with unquoted placeholders (not valid JSON) and the release package
        ships it. Tested by parsing it, building the real package, and replaying the installer's copy steps over a bay
        that already has its own agent-config.json.

  Functions are lifted from BayAgent.ps1 with the AST and dot-sourced, so the suite tests the SHIPPED text.

RUN (from the repo root)
  powershell -NoProfile -ExecutionPolicy Bypass -File tests\BayAgent.PidParam.Tests.ps1
  pwsh -NoProfile -File tests/BayAgent.PidParam.Tests.ps1

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
$defs = @($ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $true))

$startedIds = New-Object System.Collections.Generic.List[int]
$tmp = Join-Path ([IO.Path]::GetTempPath()) ("bayagent-pidparam-" + [Guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Force -Path $tmp | Out-Null
$listenerPs = $null; $listener = $null

try {
    # ============================================================ P1 automatic-variable parameter names
    Section "P1 no function parameter or assignment is named after a read-only automatic variable"
    # Read-only or constant in BOTH hosts: assigning or binding these throws. ($args, $input, $error, $matches and
    # $this are writable and are reported separately, not failed here.)
    $readOnly = @("pid", "pshome", "home", "host", "true", "false", "psversiontable", "shellid", "pscommandpath",
                  "psscriptroot", "myinvocation", "executioncontext", "pscmdlet", "psitem", "_")
    $paramNames = @($ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.ParameterAst] }, $true) |
        ForEach-Object { $_.Name.VariablePath.UserPath.ToLowerInvariant() })
    $badParams = @($paramNames | Where-Object { $readOnly -contains $_ } | Sort-Object -Unique)
    Assert-True ($badParams.Count -eq 0) "no parameter is named after a read-only automatic variable (found: $($badParams -join ','))"
    $assigned = @($ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.AssignmentStatementAst] -and
            $n.Left -is [System.Management.Automation.Language.VariableExpressionAst] }, $true) |
        ForEach-Object { $_.Left.VariablePath.UserPath.ToLowerInvariant() })
    $badAssign = @($assigned | Where-Object { $readOnly -contains $_ } | Sort-Object -Unique)
    Assert-True ($badAssign.Count -eq 0) "no assignment targets a read-only automatic variable (found: $($badAssign -join ','))"
    $callText = [IO.File]::ReadAllText($AgentScript)
    Assert-True ($callText -notmatch '(?i)Safe-RouteProcessWindow[^\r\n]*\s-pid\b' -and $callText -notmatch '(?i)Move-ProcessWindowToRole\s+-pid\b') `
        "no caller still passes -pid to the routing functions"

    # ============================================================ P1b real calls with a real process Id
    Section "P1b the window-routing functions run with the Id of a real process (Windows only)"
    if (-not $IsWin) {
        Write-Host "  SKIP  window routing is Win32-only (EnumWindows); the P1 name scan above covers Linux"
    } else {
        Add-Type -AssemblyName System.Windows.Forms
        Add-Type -AssemblyName System.Drawing
        # the Win32 helper type, lifted verbatim from the agent
        $win32If = $ast.EndBlock.Statements | Where-Object { $_ -is [System.Management.Automation.Language.IfStatementAst] -and $_.Extent.Text -match 'class ABGWin32' } | Select-Object -First 1
        if (-not $win32If) { throw "ABGWin32 block not found in the agent" }
        . ([scriptblock]::Create($win32If.Extent.Text))
        # 1.3.1: routing reads the screens through Get-CurrentScreens (fresh EnumDisplayMonitors), which needs the
        # ABGDisplayInfo type; lift it verbatim too, or the routing would silently use its cached-WinForms fallback.
        $dispIf = $ast.EndBlock.Statements | Where-Object { $_ -is [System.Management.Automation.Language.IfStatementAst] -and $_.Extent.Text -match 'class ABGDisplayInfo' } | Select-Object -First 1
        if (-not $dispIf) { throw "ABGDisplayInfo block not found in the agent" }
        . ([scriptblock]::Create($dispIf.Extent.Text))
        $script:logged = New-Object System.Collections.Generic.List[string]
        function Write-Log { param([string]$Message, [string]$Level = "INFO") $script:logged.Add("[$Level] $Message") }
        $cfg = [pscustomobject]@{}
        foreach ($n in @("Get-PropValue", "Get-DisplayDeviceString", "Resolve-RoleSelectorToScreen", "Get-ScreenForRole",
                         "Get-DisplayRoutingConfigFromPayloadOrConfig", "Get-FirstVisibleWindowHandleForPid",
                         "Move-ProcessWindowToRole", "Safe-RouteProcessWindow", "Get-CurrentScreens", "Save-LastDisplayRouting")) {
            $d = $defs | Where-Object { $_.Name -eq $n } | Select-Object -First 1
            if (-not $d) { throw "Function '$n' not found in $AgentScript" }
            . ([scriptblock]::Create($d.Extent.Text))
        }

        # a child process that shows a real minimized window; Windows PowerShell 5.1 hosts it on every machine
        $winPs = Join-Path $env:SystemRoot "System32\WindowsPowerShell\v1.0\powershell.exe"
        $formCmd = 'Add-Type -AssemblyName System.Windows.Forms; $f = New-Object System.Windows.Forms.Form; $f.Text = "bayagent-pidparam-test"; $f.WindowState = "Minimized"; [System.Windows.Forms.Application]::Run($f)'
        $child = Start-Process -FilePath $winPs -ArgumentList @("-NoProfile", "-STA", "-Command", $formCmd) -PassThru
        $startedIds.Add([int]$child.Id)
        $h = [IntPtr]::Zero
        $deadline = (Get-Date).AddSeconds(30)
        while ($h -eq [IntPtr]::Zero -and (Get-Date) -lt $deadline) { Start-Sleep -Milliseconds 300; $h = Get-FirstVisibleWindowHandleForPid ([int]$child.Id) }
        Assert-True ($h -ne [IntPtr]::Zero) "Get-FirstVisibleWindowHandleForPid finds the visible window of process $($child.Id) (handle $h)"
        $none = Get-FirstVisibleWindowHandleForPid 2147483000
        Assert-True ($none -eq [IntPtr]::Zero) "Get-FirstVisibleWindowHandleForPid returns Zero for an Id with no window"

        $threw = $null; $res = $null
        try { $res = Move-ProcessWindowToRole -ProcessId ([int]$child.Id) -role "play" -payloadObj $null -timeoutSec 2 } catch { $threw = $_.Exception.Message }
        Assert-True ($null -eq $threw) "Move-ProcessWindowToRole -ProcessId <real Id> does not throw (threw: $threw)"
        Assert-True ($null -ne $res -and $res.moved -eq $true -and [int]$res.pid -eq [int]$child.Id) "the window of the real process is reported moved, pid=$($child.Id) in the result"

        $script:logged.Clear()
        $threw = $null; $res2 = $null
        try { $res2 = Safe-RouteProcessWindow -context "test" -ProcessId ([int]$child.Id) -role "play" -payloadObj $null } catch { $threw = $_.Exception.Message }
        Assert-True ($null -eq $threw -and $null -ne $res2 -and $res2.moved -eq $true) "Safe-RouteProcessWindow -ProcessId <real Id> moves the window (threw: $threw)"
        Assert-True (@($script:logged | Where-Object { $_ -match 'DisplayRouting: exception' }).Count -eq 0) "Safe-RouteProcessWindow logs no 'DisplayRouting: exception' line (the old quiet failure)"
        Assert-True (@($script:logged | Where-Object { $_ -match "moved pid=$($child.Id) " }).Count -eq 1) "the success line carries the process Id"

        $off = [pscustomobject]@{ displayRouting = [pscustomobject]@{ enabled = $false } }
        $r3 = Safe-RouteProcessWindow -context "test" -ProcessId ([int]$child.Id) -role "play" -payloadObj $off
        Assert-True ($r3.moved -eq $false -and $r3.reason -eq "no_target_screen" -and [int]$r3.pid -eq [int]$child.Id) "routing disabled in the payload answers no_target_screen with the pid, no exception"

        try { Stop-Process -Id $child.Id -Force -ErrorAction SilentlyContinue } catch {}
    }

    # ============================================================ P2 error body logging
    Section "P2 Invoke-DvSafe logs the Dataverse error body (real HTTP 400 from a local listener)"
    # NOTE (measured 2026-10-02): over plain HTTP from a local listener, Windows PowerShell 5.1 still lets the OLD code
    # read the response stream, so on 5.1 these assertions are a regression guard; the defect itself reproduces on
    # pwsh 7 (no GetResponseStream on HttpResponseMessage), where the stream-only code logs nothing.
    if (-not (Get-Variable -Name logged -Scope Script -ErrorAction SilentlyContinue)) { $script:logged = New-Object System.Collections.Generic.List[string] }
    if (-not (Get-Command Write-Log -ErrorAction SilentlyContinue)) {
        function Write-Log { param([string]$Message, [string]$Level = "INFO") $script:logged.Add("[$Level] $Message") }
    }
    $dv = $defs | Where-Object { $_.Name -eq "Invoke-DvSafe" } | Select-Object -First 1
    . ([scriptblock]::Create($dv.Extent.Text))

    $port = 0
    $listener = $null
    foreach ($try in 1..20) {
        $port = Get-Random -Minimum 20000 -Maximum 60000
        $l = New-Object System.Net.HttpListener
        $l.Prefixes.Add("http://127.0.0.1:$port/")
        try { $l.Start(); $listener = $l; break } catch { try { $l.Close() } catch {} }
    }
    if (-not $listener) { throw "could not bind a local test listener" }
    $marker = "AOC-TEST-BODY-" + [Guid]::NewGuid().ToString("N").Substring(0, 8)
    $listenerPs = [powershell]::Create()
    [void]$listenerPs.AddScript({
        param($l, $m)
        for ($i = 0; $i -lt 4; $i++) {
            $ctx = $l.GetContext()
            $bytes = [Text.Encoding]::UTF8.GetBytes('{"error":{"code":"0x80040265","message":"' + $m + ' business rule failed"}}')
            $ctx.Response.StatusCode = 400
            $ctx.Response.ContentType = "application/json"
            $ctx.Response.OutputStream.Write($bytes, 0, $bytes.Length)
            $ctx.Response.Close()
        }
    }).AddArgument($listener).AddArgument($marker)
    $async = $listenerPs.BeginInvoke()

    $script:logged.Clear()
    $threw = $false
    try { Invoke-DvSafe -Method GET -Uri "http://127.0.0.1:$port/api/data/v9.2/x" -Headers @{ Accept = "application/json" } | Out-Null } catch { $threw = $true }
    Assert-True $threw "the failure is still rethrown to the caller"
    Assert-True (@($script:logged | Where-Object { $_ -match '^\[ERROR\] Dataverse call failed: GET' }).Count -eq 1) "the 'Dataverse call failed' line is logged once"
    $bodyLines = @($script:logged | Where-Object { $_ -match '^\[ERROR\] Dataverse response body: ' })
    Assert-True ($bodyLines.Count -eq 1) "exactly one 'Dataverse response body' line is logged (found $($bodyLines.Count))"
    Assert-True ($bodyLines.Count -ge 1 -and $bodyLines[0] -match [regex]::Escape($marker) -and $bodyLines[0] -match '0x80040265') "the body line carries the server's error code and message ($($PSVersionTable.PSVersion))"

    $script:logged.Clear()
    $threw = $false
    try { Invoke-DvSafe -Method PATCH -Uri "http://127.0.0.1:$port/api/data/v9.2/x(1)" -Headers @{ Accept = "application/json" } -BodyJson '{"a":1}' | Out-Null } catch { $threw = $true }
    Assert-True ($threw -and @($script:logged | Where-Object { $_ -match "(?s)Dataverse response body: .*$([regex]::Escape($marker))" }).Count -eq 1) "a PATCH failure logs the body too"

    # ============================================================ P3 agent-config.json template + package
    Section "P3 agent-config.json is valid JSON, and the package never overwrites a bay's own config"
    $cfgPath = Join-Path $RepoRoot "src/BayAgent/agent-config.json"
    $cfgText = [IO.File]::ReadAllText($cfgPath)
    $parsed = $null; $parseErr = $null
    try { $parsed = $cfgText | ConvertFrom-Json } catch { $parseErr = $_.Exception.Message }
    Assert-True ($null -ne $parsed) "src/BayAgent/agent-config.json parses as JSON ($parseErr)"
    if ($null -ne $parsed) {
        foreach ($k in @("tenantId", "clientId", "bayId", "environmentUrl")) {
            $v = [string]$parsed.$k
            Assert-True ($v -match '<[^>]*placeholder[^>]*>|<[^>]+>' -and $v -notmatch '^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$' -and $v -notmatch 'builds-apps') `
                "$k is an obvious placeholder, not a real id or environment ('$v')"
        }
        Assert-True (-not ($parsed.PSObject.Properties.Name -contains "clientSecret")) "the template carries no plaintext clientSecret"
    }

    # the agent reads the bay-root config, never the one inside current\
    $agentSrc = [IO.File]::ReadAllText($AgentScript)
    Assert-True ($agentSrc -match '(?m)^\$BaseDir = "C:\\AllBirdies\\BayAgent"' -and $agentSrc -match '(?m)^\$CfgPath = Join-Path \$BaseDir "agent-config\.json"') `
        "the agent reads <BayAgent root>\agent-config.json (not current\)"
    # the installer only ever writes to releases\<v>, current\ and tools\
    $installer = Join-Path $RepoRoot "src/BayAgent/tools/Update-BayAgent.ps1"
    $iAst = [System.Management.Automation.Language.Parser]::ParseFile($installer, [ref]$null, [ref]$null)
    $roboCalls = @($iAst.FindAll({ param($n) $n -is [System.Management.Automation.Language.CommandAst] -and $n.GetCommandName() -eq "Invoke-Robo" }, $true))
    $dests = @($roboCalls | ForEach-Object { $_.CommandElements[2].Extent.Text })
    # 1.3.1 (A0.437) adds the rollback snapshot (rollback\current, rollback\tools), the restore of that snapshot into
    # current\ and tools\ ($ToolsDir), and the link-to-folder rebuild of current\ ($linkPath). Still an EXACT set: a new
    # destination fails here until someone decides it is safe, and Convert-LinkToFolder is pinned to current\ below.
    # Since 1.3.1 every tree copy but the staging one goes through Sync-TreeExact (robocopy, then an explicit copy of any
    # file whose bytes still differ), whose own robocopy writes to its -dst parameter. So: robocopy writes only to
    # releases\<v> or to Sync-TreeExact's $dst, and every Sync-TreeExact -dst is in the exact set.
    $allowedDests = @('$CurrentDir', '$destTools', '$ToolsDir', '$SnapCurrent', '$SnapTools', '$linkPath')
    Assert-True ($roboCalls.Count -eq 2 -and @($dests | Where-Object { $_ -notin @('$relDir', '$dst') }).Count -eq 0) "robocopy writes only to releases\<v> (staging) or inside Sync-TreeExact (destinations: $($dests -join ', '))"
    $syncCalls = @($iAst.FindAll({ param($n) $n -is [System.Management.Automation.Language.CommandAst] -and $n.GetCommandName() -eq "Sync-TreeExact" }, $true))
    $syncDests = @($syncCalls | ForEach-Object { $m = [regex]::Match($_.Extent.Text, '-dst\s+(\$\w+)'); if ($m.Success) { $m.Groups[1].Value } else { "(no -dst)" } })
    Assert-True ($syncCalls.Count -ge 6 -and @($syncDests | Where-Object { $_ -notin $allowedDests }).Count -eq 0) "every installer tree copy lands in current\, tools\ or the rollback snapshot (Sync-TreeExact destinations: $($syncDests -join ', '))"
    $linkCalls = @($iAst.FindAll({ param($n) $n -is [System.Management.Automation.Language.CommandAst] -and $n.GetCommandName() -eq "Convert-LinkToFolder" }, $true))
    Assert-True ($linkCalls.Count -ge 1 -and @($linkCalls | Where-Object { $_.Extent.Text -notmatch '-linkPath \$CurrentDir\b' }).Count -eq 0) "Convert-LinkToFolder is only ever pointed at current\ ($($linkCalls.Count) call(s))"
    $snapAssign = [regex]::Matches([IO.File]::ReadAllText($installer), '(?m)^\$(SnapCurrent|SnapTools)\s*=\s*Join-Path \$RollbackDir "(current|tools)"\s*$').Count
    Assert-True ($snapAssign -eq 2 -and [IO.File]::ReadAllText($installer) -match '(?m)^\$RollbackDir\s*=\s*Join-Path \$BaseDir "rollback"\s*$') "the snapshot folders are rollback\current and rollback\tools under the bay root"
    $iText = [IO.File]::ReadAllText($installer)
    Assert-True ($iText -match '(?m)^\$CurrentDir\s*=\s*Join-Path \$BaseDir "current"' -and $iText -notmatch '(?i)agent-config') "the installer never names agent-config.json and current\ is a subfolder of the bay root"

    # build the REAL package and read the config out of it
    $hostExe = (Get-Process -Id $PID).Path
    $manifest = Get-Content -LiteralPath (Join-Path $RepoRoot "src/BayAgent/manifest.json") -Raw | ConvertFrom-Json
    $dist = Join-Path $tmp "dist"
    $buildOut = & $hostExe -NoProfile -File (Join-Path $RepoRoot "tools/Build-ReleasePackage.ps1") -Version $manifest.version -OutDir $dist 2>&1
    $buildExit = $LASTEXITCODE
    Assert-True ($buildExit -eq 0) "tools/Build-ReleasePackage.ps1 builds the package (exit $buildExit)"
    $zipPath = Join-Path $dist ("BayAgent-{0}.zip" -f $manifest.version)
    Assert-True (Test-Path -LiteralPath $zipPath) "the package zip exists"
    if (Test-Path -LiteralPath $zipPath) {
        Add-Type -AssemblyName System.IO.Compression.FileSystem
        $zip = [IO.Compression.ZipFile]::OpenRead($zipPath)
        try {
            $entry = $zip.Entries | Where-Object { $_.FullName -eq "agent-config.json" } | Select-Object -First 1
            Assert-True ($null -ne $entry) "the package carries agent-config.json at its root (inside the release, never at the bay root)"
            if ($null -ne $entry) {
                $sr = New-Object IO.StreamReader($entry.Open())
                try { $zipCfg = $sr.ReadToEnd() } finally { $sr.Dispose() }
                $zp = $null; try { $zp = $zipCfg | ConvertFrom-Json } catch {}
                Assert-True ($null -ne $zp) "the agent-config.json inside the package parses as JSON"
            }
        } finally { $zip.Dispose() }

        # replay the installer's copy steps over a bay that already has its own config
        if ($IsWin -and (Get-Command robocopy.exe -ErrorAction SilentlyContinue)) {
            $bay = Join-Path $tmp "bay"
            New-Item -ItemType Directory -Force -Path (Join-Path $bay "releases") | Out-Null
            $realCfg = '{"bayId":"11111111-1111-1111-1111-111111111111","note":"this bay''s own config"}'
            [IO.File]::WriteAllText((Join-Path $bay "agent-config.json"), $realCfg)
            $expand = Join-Path $bay "staging"
            Expand-Archive -LiteralPath $zipPath -DestinationPath $expand -Force
            $rel = Join-Path $bay "releases\v"; $cur = Join-Path $bay "current"
            & robocopy.exe $expand $rel /MIR /R:1 /W:1 /NFL /NDL /NJH /NJS /NP | Out-Null
            & robocopy.exe $rel $cur /MIR /R:1 /W:1 /NFL /NDL /NJH /NJS /NP | Out-Null
            & robocopy.exe (Join-Path $rel "tools") (Join-Path $bay "tools") /E /R:1 /W:1 /NFL /NDL /NJH /NJS /NP | Out-Null
            Assert-True ([IO.File]::ReadAllText((Join-Path $bay "agent-config.json")) -eq $realCfg) "after the install steps the bay's own agent-config.json is byte-for-byte unchanged"
            Assert-True ((Test-Path (Join-Path $cur "BayAgent.ps1")) -and (Test-Path (Join-Path $bay "tools\Update-BayAgent.ps1"))) "the replayed install did place the agent and tools (the check is not vacuous)"
        } else {
            Write-Host "  SKIP  robocopy replay of the installer copy steps (Windows only); the static installer checks above hold on every host"
        }
    }
}
finally {
    foreach ($id in $startedIds) { try { Stop-Process -Id $id -Force -ErrorAction SilentlyContinue } catch {} }
    if ($null -ne $listener) { try { $listener.Stop(); $listener.Close() } catch {} }
    if ($null -ne $listenerPs) { try { $listenerPs.Stop(); $listenerPs.Dispose() } catch {} }
    try { Remove-Item -LiteralPath $tmp -Recurse -Force -ErrorAction SilentlyContinue } catch {}
}

Write-Host ""
Write-Host ("RESULT: {0} passed, {1} failed" -f $script:Pass, $script:Fail) -ForegroundColor $(if ($script:Fail -eq 0) { "Green" } else { "Red" })
if ($script:Fail -gt 0) { $script:Failures | ForEach-Object { Write-Host "  - $_" -ForegroundColor Red }; exit 1 }
exit 0
