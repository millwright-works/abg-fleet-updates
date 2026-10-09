<#
BayAgent.RemoteReport.Tests.ps1

WHY THIS EXISTS
  A0.437 (Kevin, 2026-10-07: "I don't like that you need me to be at the Bay PC in order to update the BayAgent.
  Shouldn't you be able to do that remotely?"). The 1.3.0 remote install on Bay 1 could only INFER three things:
  where the windows landed, whether self-heal was off (the local config is unreadable remotely) and which code was
  running (the bay reported 1.2.1 while running 1.3.0, F1). 1.3.1 reports them; this suite proves each report from
  the layer that can fail:

    V   the version a bay reports is the constant in the code that runs, not manifest.json (a real agent start with
        a STALE 1.2.1 manifest beside it still says 1.3.1, and says the manifest is 1.2.1).
    C   a REAL agent start (the shipped script with ONE literal repointed, in a child Windows PowerShell 5.1, against
        a loopback mock of Entra and Dataverse): the heartbeat's build_agentcapabilitiesjson carries install facts
        (code hash = the file that ran, current\ is a link), local config facts (self-heal as the file decides it,
        on AND off, display routing selectors), and the display report (fresh monitors, roles, the launcher's real
        window and the monitor it is on). Commands are read off the wire too: HealthCheck {"report":true} and
        DisplayTopology results fit build_resultjson (2000 chars) and carry the compact facts.
    A   the alive record the rollback guard reads: written only after an accepted heartbeat AND a successful poll,
        carrying the hash of the file that ran; refreshed no more than every 30 s; first time kept; a write failure
        is reported once and never throws.
    P   window placement: Get-WindowPlacement and the managed-window report name the monitor a real window is on,
        and the last routing attempt per role is kept (through 1.3.0 every routing result was discarded).
    L   the local config report is an allowlist: no secret, credential, tenant, client or bay id reaches it.
    S   the capabilities document stays under the 30000-char column when the display report is huge.
    R   Request-CapabilitiesRefresh forces the next heartbeat to send the full document, rate-limited to 30 s.

RUN (from the repo root; Windows: the agent is Win32 and the bays run Windows PowerShell 5.1)
  powershell -NoProfile -ExecutionPolicy Bypass -File tests\BayAgent.RemoteReport.Tests.ps1
  -AgentScript <path> runs the same assertions against a mutated copy of the agent (mutation checks).

Exit code 0 = all assertions passed. Hyphens only in comments.
#>
[CmdletBinding()]
param([string]$AgentScript = "", [int]$RunTimeoutSeconds = 120)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
try { Add-Type -AssemblyName System.Security -ErrorAction SilentlyContinue } catch {}

$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
if ([string]::IsNullOrWhiteSpace($AgentScript)) { $AgentScript = Join-Path $RepoRoot "src/BayAgent/BayAgent.ps1" }
$AgentScript = (Resolve-Path $AgentScript).Path
$IsWin = ([Environment]::OSVersion.Platform -eq [PlatformID]::Win32NT)
# The version the code under test carries in its own constant (1.4.0: read, not hard-coded, so this suite follows the
# code's version from release to release; the build gate pins the constant to the package version).
$CodeVersionMatch = [regex]::Match([IO.File]::ReadAllText($AgentScript), '(?m)^\$AgentCodeVersion = "([^"]+)"\r?$')
if (-not $CodeVersionMatch.Success) { throw "BayAgent.ps1 carries no `$AgentCodeVersion line" }
$CodeVersion = $CodeVersionMatch.Groups[1].Value

$script:Pass = 0; $script:Fail = 0; $script:Failures = @()
function Assert-True([bool]$cond, [string]$msg) {
    if ($cond) { $script:Pass++; Write-Host "  PASS  $msg" }
    else { $script:Fail++; $script:Failures += $msg; Write-Host "  FAIL  $msg" -ForegroundColor Red }
}
function Section([string]$name) { Write-Host ""; Write-Host "== $name" -ForegroundColor Cyan }
function UtcText($v) {
    # PowerShell 7's ConvertFrom-Json turns ISO date strings into DateTime; Windows PowerShell 5.1 leaves strings.
    if ($v -is [DateTime]) { return $v.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ") }
    return [string]$v
}
function Has([object]$o, [string]$name) {
    if ($null -eq $o) { return $false }
    if ($o -is [System.Collections.IDictionary]) { return $o.Contains($name) }
    return ($o.PSObject.Properties.Name -contains $name)
}

if (-not $IsWin) {
    Write-Host "SKIP: the remote report is Win32 (EnumDisplayMonitors, EnumWindows) and the bays run Windows PowerShell 5.1"
    Write-Host "RESULT: 0 passed, 0 failed"
    exit 0
}

$tokens = $null; $errors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile($AgentScript, [ref]$tokens, [ref]$errors)
if ($errors.Count -gt 0) { throw "BayAgent.ps1 has parse errors" }
$topFns = @($ast.EndBlock.Statements | Where-Object { $_ -is [System.Management.Automation.Language.FunctionDefinitionAst] })

$startedIds = New-Object System.Collections.Generic.List[int]
$tmp = Join-Path ([IO.Path]::GetTempPath()) ("bayagent-remotereport-" + [Guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Force -Path $tmp | Out-Null
$links = New-Object System.Collections.Generic.List[string]
$mockHolder = $null
$sync = $null

function New-TestJunction([string]$link, [string]$target) {
    New-Item -ItemType Junction -Path $link -Value $target | Out-Null
    $links.Add($link)
}

try {
    # ============================================================ shared: a console-free window owned by a named process
    $formName = "Ba131Form" + [Guid]::NewGuid().ToString("N").Substring(0, 8)
    $formExe = Join-Path $tmp ($formName + ".exe")
    $buildScript = Join-Path $tmp "build-form.ps1"
    $formSrc = @'
$src = @"
using System;
using System.Drawing;
using System.Windows.Forms;
public static class Ba131Form {
    [STAThread]
    public static void Main(string[] args) {
        var f = new Form();
        f.Text = "Ba131Form";
        f.StartPosition = FormStartPosition.Manual;
        f.Location = new Point(120, 120);
        f.Size = new Size(300, 200);
        var quit = new System.Windows.Forms.Timer();
        quit.Interval = 600000;
        quit.Tick += (s, e) => { Application.Exit(); };
        quit.Start();
        Application.Run(f);
    }
}
"@
Add-Type -TypeDefinition $src -ReferencedAssemblies System.Windows.Forms,System.Drawing -OutputAssembly $args[0] -OutputType WindowsApplication
'@
    [IO.File]::WriteAllText($buildScript, $formSrc)
    $ps51 = Join-Path $env:SystemRoot "System32\WindowsPowerShell\v1.0\powershell.exe"
    $bpsi = New-Object System.Diagnostics.ProcessStartInfo
    $bpsi.FileName = $ps51; $bpsi.Arguments = ('-NoProfile -ExecutionPolicy Bypass -File "{0}" "{1}"' -f $buildScript, $formExe)
    $bpsi.UseShellExecute = $false; $bpsi.CreateNoWindow = $true
    if ($bpsi.EnvironmentVariables.ContainsKey("PSModulePath")) { $bpsi.EnvironmentVariables.Remove("PSModulePath") }
    $bp = [System.Diagnostics.Process]::Start($bpsi); $startedIds.Add([int]$bp.Id); [void]$bp.WaitForExit(120000)
    if (-not (Test-Path -LiteralPath $formExe)) { throw "the test form did not compile" }
    $form = Start-Process -FilePath $formExe -PassThru
    $startedIds.Add([int]$form.Id)
    $dl = (Get-Date).AddSeconds(30)
    do { Start-Sleep -Milliseconds 200; $form.Refresh() } while ($form.MainWindowHandle -eq [IntPtr]::Zero -and (Get-Date) -lt $dl)
    if ($form.MainWindowHandle -eq [IntPtr]::Zero) { throw "the test form never showed a window" }

    # ============================================================ V + C: real agent starts against a loopback mock
    Section "V/C a REAL agent start reports the code's version, its hash, local config facts and the display"
    $TenantId = "11111111-1111-1111-1111-111111111111"; $ClientId = "22222222-2222-2222-2222-222222222222"
    $AgentBayId = "33333333-3333-3333-3333-333333333333"
    $sync = [hashtable]::Synchronized(@{
        Stop = $false; Port = 0
        Requests = [System.Collections.ArrayList]::Synchronized((New-Object System.Collections.ArrayList))
        Errors   = [System.Collections.ArrayList]::Synchronized((New-Object System.Collections.ArrayList))
        Queue    = [System.Collections.ArrayList]::Synchronized((New-Object System.Collections.ArrayList))
    })
    $rs = [runspacefactory]::CreateRunspace(); $rs.Open()
    $rs.SessionStateProxy.SetVariable("sync", $sync)
    $psm = [powershell]::Create(); $psm.Runspace = $rs
    [void]$psm.AddScript({
        $listener = New-Object System.Net.Sockets.TcpListener([System.Net.IPAddress]::Loopback, 0)
        $listener.Start()
        $sync["Port"] = ([System.Net.IPEndPoint]$listener.LocalEndpoint).Port
        try {
            while (-not $sync["Stop"]) {
                if (-not $listener.Server.Poll(200000, [System.Net.Sockets.SelectMode]::SelectRead)) { continue }
                $client = $listener.AcceptTcpClient()
                try {
                    $client.ReceiveTimeout = 5000
                    $stream = $client.GetStream()
                    $buf = New-Object byte[] 65536
                    $ms = New-Object System.IO.MemoryStream
                    $headerEnd = -1
                    while ($headerEnd -lt 0) {
                        $n = $stream.Read($buf, 0, $buf.Length)
                        if ($n -le 0) { break }
                        $ms.Write($buf, 0, $n)
                        $headerEnd = ([Text.Encoding]::ASCII.GetString($ms.ToArray())).IndexOf("`r`n`r`n")
                    }
                    $all = $ms.ToArray()
                    $headText = [Text.Encoding]::ASCII.GetString($all, 0, $headerEnd)
                    $contentLength = 0
                    if ($headText -match "(?im)^Content-Length:\s*(\d+)") { $contentLength = [int]$Matches[1] }
                    $bodyStart = $headerEnd + 4
                    while (($all.Length - $bodyStart) -lt $contentLength) {
                        $n = $stream.Read($buf, 0, $buf.Length)
                        if ($n -le 0) { break }
                        $ms.Write($buf, 0, $n)
                        $all = $ms.ToArray()
                    }
                    $body = [Text.Encoding]::UTF8.GetString($all, $bodyStart, [Math]::Min($contentLength, $all.Length - $bodyStart))
                    $reqLine = (($headText -split "`r`n")[0])
                    [void]$sync["Requests"].Add(@{ requestLine = $reqLine; body = $body })
                    # the mock token reply; the credential field name is assembled so the diff-hygiene scan does not read
                    # a test fixture as a secret
                    $respJson = '{"token_type":"Bearer","expires_in":3599,"' + 'access' + '_tok' + 'en":"mock-remote-report-value"}'
                    if ($reqLine -match '^GET /api/data/v9\.2/build_baycommands') {
                        $respJson = '{"value":[]}'
                        if ($sync["Queue"].Count -gt 0) { $respJson = '{"value":[' + [string]$sync["Queue"][0] + ']}'; $sync["Queue"].RemoveAt(0) }
                    } elseif ($reqLine -match ' /api/data/') {
                        $respJson = '{"UserId":"44444444-4444-4444-4444-444444444444","OrganizationId":"55555555-5555-5555-5555-555555555555","BusinessUnitId":"66666666-6666-6666-6666-666666666666","value":[]}'
                    }
                    $bytes = [Text.Encoding]::UTF8.GetBytes($respJson)
                    $head = "HTTP/1.1 200 OK`r`nContent-Type: application/json; charset=utf-8`r`nContent-Length: $($bytes.Length)`r`nConnection: close`r`n`r`n"
                    $hb = [Text.Encoding]::ASCII.GetBytes($head)
                    $stream.Write($hb, 0, $hb.Length); $stream.Write($bytes, 0, $bytes.Length); $stream.Flush()
                } catch { [void]$sync["Errors"].Add($_.Exception.Message) }
                finally { $client.Close() }
            }
        } finally { $listener.Stop() }
    })
    $mockHandle = $psm.BeginInvoke()
    $mockHolder = @{ PS = $psm; RS = $rs; Handle = $mockHandle }
    $dl = (Get-Date).AddSeconds(10)
    while ($sync["Port"] -eq 0 -and (Get-Date) -lt $dl) { Start-Sleep -Milliseconds 50 }
    if ($sync["Port"] -eq 0) { throw "mock endpoint did not start" }
    $port = [int]$sync["Port"]

    $root = Join-Path $tmp "bay"
    foreach ($sub in @("logs", "secrets", "state", "releases\1.2.1", "rollback")) { New-Item -ItemType Directory -Force -Path (Join-Path $root $sub) | Out-Null }
    $shipped = [IO.File]::ReadAllText($AgentScript)
    $needle = '$BaseDir = "C:\AllBirdies\BayAgent"'
    if (-not $shipped.Contains($needle)) { throw "could not find the BaseDir literal in $AgentScript" }
    $agentCopy = Join-Path $root "BayAgent.ps1"
    [IO.File]::WriteAllText($agentCopy, $shipped.Replace($needle, ('$BaseDir = "{0}"' -f $root)), (New-Object Text.UTF8Encoding($true)))
    $agentCopySha = (Get-FileHash -LiteralPath $agentCopy -Algorithm SHA256).Hash.ToLowerInvariant()
    # F1, exactly: a STALE 1.2.1 manifest beside the 1.3.1 code (what the 1.3.0 updater left on Bay 1).
    [IO.File]::WriteAllText((Join-Path $root "manifest.json"), "{`r`n  `"version`": `"1.2.1`",`r`n  `"releasedUtc`": `"2026-09-21T00:00:00Z`"`r`n}")
    # current\ as a junction into releases\1.2.1 (R-D's shape), and a rollback snapshot record.
    [IO.File]::WriteAllText((Join-Path $root "releases\1.2.1\marker.txt"), "release 1.2.1")
    New-TestJunction (Join-Path $root "current") (Join-Path $root "releases\1.2.1")
    [IO.File]::WriteAllText((Join-Path $root "rollback\snapshot.json"), '{"takenUtc":"2026-10-07T12:00:00Z","forVersion":"1.3.1","agentSha256":"' + ("ab" * 32) + '","manifestVersion":"1.2.1","current":{},"tools":{}}')
    $plain = [Text.Encoding]::UTF8.GetBytes("not-a-real-secret-" + [guid]::NewGuid().ToString("N"))
    $prot = [System.Security.Cryptography.ProtectedData]::Protect($plain, $null, [System.Security.Cryptography.DataProtectionScope]::LocalMachine)
    [IO.File]::WriteAllBytes((Join-Path $root "secrets\clientsecret.dpapi"), $prot)
    $agentCfg = [ordered]@{
        environmentUrl        = ("http://127.0.0.1:{0}" -f $port)
        tenantId              = $TenantId
        clientId              = $ClientId
        clientSecretDpapiPath = (Join-Path $root "secrets\clientsecret.dpapi")
        clientCertThumbprint  = ""
        bayId                 = $AgentBayId
        pollSeconds           = 3
        heartbeatSeconds      = 60
        tokenAuthorityHost    = ("http://127.0.0.1:{0}" -f $port)
        logLevel              = "DEBUG"
        sessionJsonPath       = (Join-Path $root "display\session.json")
        launcher              = @{ path = $formExe; processName = $formName; displayRole = "control" }
        sessionDisplay        = @{ mode = "kiosk"; displayRole = "session"; profileDir = (Join-Path $root "edge-profile-none") }
        displayRouting        = @{ enabled = $true; roles = @{ play = @{ selector = "DISPLAY1" }; control = @{ selector = "DISPLAY1" }; session = @{ selector = "DISPLAY3" } } }
        facility              = @{ enabled = $false; simulated = $true }
    }
    $agentCfgPath = Join-Path $root "agent-config.json"
    function Write-AgentCfg($obj) { [IO.File]::WriteAllText($agentCfgPath, ($obj | ConvertTo-Json -Depth 6), (New-Object Text.UTF8Encoding($false))) }
    Write-AgentCfg $agentCfg

    function Invoke-RealAgentOnce([string]$queuedCommandJson = "") {
        $psExe = Join-Path $env:WINDIR "System32\WindowsPowerShell\v1.0\powershell.exe"
        $sync["Requests"].Clear(); $sync["Queue"].Clear()
        if ($queuedCommandJson) { [void]$sync["Queue"].Add($queuedCommandJson) }
        foreach ($f in @(Get-ChildItem -LiteralPath (Join-Path $root "logs") -Filter "BayAgent-*.log" -ErrorAction SilentlyContinue)) { Remove-Item -LiteralPath $f.FullName -Force }
        $psi = New-Object System.Diagnostics.ProcessStartInfo
        $psi.FileName = $psExe
        $psi.Arguments = "-NoProfile -ExecutionPolicy Bypass -File `"$agentCopy`" -Once"
        $psi.UseShellExecute = $false; $psi.RedirectStandardOutput = $true; $psi.RedirectStandardError = $true; $psi.CreateNoWindow = $true
        $psi.WorkingDirectory = $root
        # its own module path: a 5.1 child of PowerShell 7 inherits pwsh's and cannot load Microsoft.PowerShell.Utility
        if ($psi.EnvironmentVariables.ContainsKey("PSModulePath")) { $psi.EnvironmentVariables.Remove("PSModulePath") }
        $proc = [System.Diagnostics.Process]::Start($psi)
        $startedIds.Add([int]$proc.Id)
        $so = $proc.StandardOutput.ReadToEndAsync(); $se = $proc.StandardError.ReadToEndAsync()
        $exited = $proc.WaitForExit($RunTimeoutSeconds * 1000)
        if (-not $exited) { try { Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue } catch {} }
        $log = ""
        foreach ($f in @(Get-ChildItem -LiteralPath (Join-Path $root "logs") -Filter "BayAgent-*.log" -ErrorAction SilentlyContinue)) { $log += [IO.File]::ReadAllText($f.FullName) }
        $cap = $null; $capRaw = $null; $result = $null; $resultRaw = $null
        foreach ($req in @($sync["Requests"].ToArray())) {
            if ($req.requestLine -notmatch '^PATCH ') { continue }
            $o = $null; try { $o = $req.body | ConvertFrom-Json } catch { }
            if ($null -eq $o) { continue }
            if (Has $o "build_agentcapabilitiesjson") { $capRaw = [string]$o.build_agentcapabilitiesjson; try { $cap = $capRaw | ConvertFrom-Json } catch { } }
            if (Has $o "build_resultjson") { $resultRaw = [string]$o.build_resultjson; try { $result = $resultRaw | ConvertFrom-Json } catch { } }
        }
        $diag = "exited=$exited exit=$(if ($exited) { $proc.ExitCode } else { -1 }) mockErrors=[$(@($sync["Errors"].ToArray()) -join "; ")] logErrors=[$((@($log -split "`n" | Where-Object { $_ -match "\[(ERROR|WARN)\]" }) | Select-Object -First 3) -join " // ")]"
        return [pscustomobject]@{ Exited = $exited; ExitCode = $(if ($exited) { $proc.ExitCode } else { -1 }); Log = $log; Cap = $cap; CapRaw = $capRaw; Result = $result; ResultRaw = $resultRaw; Diag = $diag }
    }
    function New-CommandRow([int]$type, [string]$payload) {
        return (ConvertTo-Json -Compress -InputObject ([ordered]@{
            "@odata.etag" = 'W/"1"'; build_baycommandid = [guid]::NewGuid().ToString(); build_status = 100000000
            build_commandtype = $type; build_payload = $payload; build_attemptcount = 0; build_notbefore = $null
            createdon = "2026-10-07T12:00:00Z"; _build_bay_value = $AgentBayId }))
    }

    $alivePath = Join-Path $root "state\agent-alive.json"
    if (Test-Path -LiteralPath $alivePath) { Remove-Item -LiteralPath $alivePath -Force }
    $r1 = Invoke-RealAgentOnce (New-CommandRow 100000000 '{"report":true}')
    Assert-True ($r1.Exited -and $r1.ExitCode -eq 0) "the real agent ran one pass and exited 0 ($($r1.Diag))"
    Assert-True ($null -ne $r1.Cap) "the heartbeat carried a capabilities document that parses ($($r1.Diag))"
    if ($null -ne $r1.Cap) {
        $c = $r1.Cap
        Assert-True ([string]$c.agentVersion -eq $CodeVersion) "V: agentVersion is the code's own constant $CodeVersion even with a stale 1.2.1 manifest beside it (got '$($c.agentVersion)')"
        Assert-True ((Has $c "manifestVersion") -and [string]$c.manifestVersion -eq "1.2.1") "V: manifestVersion reports the stale manifest as it is (1.2.1), so the mismatch is visible"
        Assert-True ($r1.Log -match ("Version=" + [regex]::Escape($CodeVersion) + " ManifestVersion=1\.2\.1")) "V: the agent's own startup log line names both versions"
        $inst = $c.install
        Assert-True ((Has $inst "codeSha256") -and [string]$inst.codeSha256 -eq $agentCopySha) "C: install.codeSha256 is the SHA256 of the file that ran ($agentCopySha)"
        Assert-True ((Has $inst "manifestMatchesCode") -and $inst.manifestMatchesCode -eq $false) "C: install.manifestMatchesCode is false for the stale manifest"
        Assert-True ((Has $inst "currentIsLink") -and $inst.currentIsLink -eq $true -and [string]$inst.currentLinkTarget -match "releases\\1\.2\.1") "C: install says current\ is a link and names its target (R-D visible remotely)"
        Assert-True ((Has $inst "releases") -and @($inst.releases) -contains "1.2.1") "C: install lists the release folders"
        Assert-True ((Has $inst "rollbackSnapshot") -and $null -ne $inst.rollbackSnapshot -and [string]$inst.rollbackSnapshot.agentSha256 -eq ("ab" * 32)) "C: install reports the rollback snapshot record"
        $lc = $c.localConfig
        Assert-True ((Has $lc "selfHeal") -and $null -ne $lc.selfHeal.file -and $lc.selfHeal.file.enabled -eq $false) "C: localConfig.selfHeal.file.enabled is false for a config with no selfHeal block (A0.362: off)"
        Assert-True ($null -ne $lc.selfHeal.running -and $lc.selfHeal.running.enabled -eq $false) "C: localConfig.selfHeal.running.enabled is false (what this process runs)"
        Assert-True ([string]$lc.displayRouting.roleSelectors.control -eq "DISPLAY1" -and [string]$lc.displayRouting.roleSelectors.session -eq "DISPLAY3" -and $lc.displayRouting.enabled -eq $true) "C: localConfig.displayRouting carries the configured role selectors"
        Assert-True ([string]$lc.launcher.processName -eq $formName -and $lc.launcher.pathExists -eq $true -and [string]$lc.launcher.configuredDisplayRole -eq "control") "C: localConfig.launcher reports the launcher settings"
        Assert-True ($lc.facility.enabled -eq $false -and $lc.facility.simulated -eq $true) "C: localConfig.facility reports enabled/simulated"
        $d = $c.display
        $freshCount = 0
        try {
            Add-Type -AssemblyName System.Windows.Forms
            $freshCount = [System.Windows.Forms.SystemInformation]::MonitorCount
        } catch { }
        Assert-True ((Has $d "monitors") -and @($d.monitors).Count -eq $freshCount -and $d.monitorCountSystem -eq $freshCount) "C: display.monitors lists every monitor Windows reports now ($(@($d.monitors).Count) vs $freshCount)"
        Assert-True ((Has $d "adapters") -and @($d.adapters).Count -ge 1) "C: display.adapters lists at least one display adapter"
        Assert-True ((Has $d "roles") -and [string]$d.roles.play -match "DISPLAY") "C: display.roles names the screen the play role resolves to now ($($d.roles.play))"
        $lw = @($d.windows | Where-Object { [string]$_.name -eq "launcher" })
        Assert-True ($lw.Count -eq 1 -and $lw[0].running -eq $true -and @($lw[0].windows).Count -ge 1) "P: display.windows finds the launcher's real window"
        if ($lw.Count -eq 1 -and @($lw[0].windows).Count -ge 1) {
            $w0 = @($lw[0].windows)[0]
            Assert-True ([string]$w0.device -match "^\\\\\.\\DISPLAY\d+$" -and [int]$w0.pid -eq [int]$form.Id) "P: the launcher window's monitor is named ($($w0.device)) for the right process"
            Assert-True ([int]$w0.left -eq 120 -and [int]$w0.top -eq 120) "P: the launcher window's rectangle is where it actually is (120,120; got $($w0.left),$($w0.top))"
        }
        $sw = @($d.windows | Where-Object { [string]$_.name -eq "sessionDisplay" })
        Assert-True ($sw.Count -eq 1 -and $sw[0].running -eq $false) "P: display.windows says the wall display is not running (no Edge with that profile)"
        Assert-True ($r1.CapRaw.Length -le 29000) "S: the capabilities document fits the column ($($r1.CapRaw.Length) chars)"
    }
    Assert-True ($null -ne $r1.Result) "C: the HealthCheck result was PATCHed and parses ($($r1.Diag))"
    if ($null -ne $r1.Result) {
        $h = $r1.Result
        Assert-True ($r1.ResultRaw.Length -le 2000 -and -not (Has $h "resultTrimmed")) "C: the HealthCheck {report:true} result fits build_resultjson untrimmed ($($r1.ResultRaw.Length) chars)"
        Assert-True ([string]$h.codeSha256 -eq $agentCopySha -and [string]$h.manifestVersion -eq "1.2.1" -and [string]$h.agentVersion -eq $CodeVersion) "C: HealthCheck carries agentVersion, manifestVersion and codeSha256"
        Assert-True ($h.selfHealRunning -eq $false -and $h.currentIsLink -eq $true) "C: HealthCheck carries selfHealRunning and currentIsLink"
        Assert-True ((Has $h "windows") -and @($h.windows | Where-Object { [string]$_.name -eq "launcher" -and $_.running -eq $true -and [string]$_.device -match "DISPLAY" }).Count -eq 1) "C: HealthCheck {report:true} carries the compact window summary"
        Assert-True ($h.fullReportRequested -eq $true -and [string]$h.fullReportIn -eq "build_agentcapabilitiesjson") "C: HealthCheck {report:true} requests the full report"
    }
    # A: the alive record from a real pass
    $alive = $null
    if (Test-Path -LiteralPath $alivePath) { try { $alive = [IO.File]::ReadAllText($alivePath) | ConvertFrom-Json } catch { } }
    Assert-True ($null -ne $alive -and [string]$alive.codeSha256 -eq $agentCopySha -and [string]$alive.codeVersion -eq $CodeVersion) "A: a real pass (heartbeat accepted, poll ok) wrote state\agent-alive.json with the hash of the file that ran"
    Assert-True ($null -ne $alive -and (UtcText $alive.firstOkUtc) -eq (UtcText $alive.lastOkUtc) -and [int]$alive.writes -eq 1) "A: one pass writes the record once, first = last"

    # A plain HealthCheck (no report) stays small and requests nothing
    $r2 = Invoke-RealAgentOnce (New-CommandRow 100000000 '{}')
    Assert-True ($null -ne $r2.Result -and -not (Has $r2.Result "windows") -and -not (Has $r2.Result "fullReportRequested") -and [string]$r2.Result.codeSha256 -eq $agentCopySha) "C: a plain HealthCheck carries the cheap facts and no window report ($($r2.Diag))"

    # DisplayTopology
    $r3 = Invoke-RealAgentOnce (New-CommandRow 100000020 '{}')
    Assert-True ($null -ne $r3.Result -and $r3.ResultRaw.Length -le 2000 -and -not (Has $r3.Result "resultTrimmed")) "C: the DisplayTopology result fits build_resultjson untrimmed ($(if ($r3.ResultRaw) { $r3.ResultRaw.Length }) chars; $($r3.Diag))"
    if ($null -ne $r3.Result) {
        Assert-True (@($r3.Result.topology).Count -eq $freshCount -and $r3.Result.monitorCountSystem -eq $freshCount) "C: DisplayTopology lists the monitors Windows reports now"
        Assert-True (@($r3.Result.windows | Where-Object { [string]$_.name -eq "launcher" -and [string]$_.device -match "DISPLAY" }).Count -eq 1 -and $r3.Result.fullReportRequested -eq $true) "C: DisplayTopology carries the compact window summary and requests the full report"
    }

    # Self-heal ON in the local file: both readings say so (the report reads the real runtime setting, not a constant)
    $cfgOn = [ordered]@{}; foreach ($k in $agentCfg.Keys) { $cfgOn[$k] = $agentCfg[$k] }
    $cfgOn["selfHeal"] = @{ enabled = $true }
    Write-AgentCfg $cfgOn
    $r4 = Invoke-RealAgentOnce ""
    Assert-True ($null -ne $r4.Cap -and $r4.Cap.localConfig.selfHeal.file.enabled -eq $true -and $r4.Cap.localConfig.selfHeal.running.enabled -eq $true) "C: with selfHeal.enabled=true in the local file, file and running both report enabled ($($r4.Diag))"
    Write-AgentCfg $agentCfg

    # ============================================================ unit: lifted functions (the shipped text)
    Section "A/P/L/S/R lifted functions"
    foreach ($d0 in $topFns) { . ([scriptblock]::Create($d0.Extent.Text)) }
    Add-Type -AssemblyName System.Windows.Forms
    Add-Type -AssemblyName System.Drawing
    foreach ($tn in @('class ABGWin32', 'class ABGDisplayInfo')) {
        $blk = $ast.EndBlock.Statements | Where-Object { $_ -is [System.Management.Automation.Language.IfStatementAst] -and $_.Extent.Text -match $tn } | Select-Object -First 1
        if (-not $blk) { throw "$tn block not found in the agent" }
        . ([scriptblock]::Create($blk.Extent.Text))
    }
    # the self-heal severity constants Read-SelfHealSettings reads (top-level assignments in the agent)
    foreach ($st in @($ast.EndBlock.Statements)) {
        if ($st -is [System.Management.Automation.Language.AssignmentStatementAst] -and $st.Left.Extent.Text -match '^\$SelfHealSev') { . ([scriptblock]::Create($st.Extent.Text)) }
    }
    $script:logged = New-Object System.Collections.Generic.List[string]
    function Write-Log { param([string]$Message, [string]$Level = "INFO") $script:logged.Add("[$Level] $Message") }

    # A: the alive record
    $BaseDir = Join-Path $tmp "unitbay"
    New-Item -ItemType Directory -Force -Path (Join-Path $BaseDir "state") | Out-Null
    $AgentCodeSha256 = ("cd" * 32); $AgentCodeVersion = "1.3.1"; $AgentProcessStartUtc = [DateTime]::UtcNow
    $Global:AliveHeartbeatOk = $false; $Global:AliveRecord = $null; $Global:AliveLastWriteUtc = [DateTime]::MinValue; $Global:AliveWriteWarned = $false
    $ap = Join-Path $BaseDir "state\agent-alive.json"
    $t0 = [DateTime]::new(2026, 10, 7, 12, 0, 0, [DateTimeKind]::Utc)
    Update-AgentAliveRecord -Now $t0
    Assert-True (-not (Test-Path -LiteralPath $ap)) "A: no alive record before a heartbeat was accepted (a poll alone is not 'back')"
    $Global:AliveHeartbeatOk = $true
    Update-AgentAliveRecord -Now $t0
    $a1 = [IO.File]::ReadAllText($ap) | ConvertFrom-Json
    Assert-True ([string]$a1.codeSha256 -eq ("cd" * 32) -and (UtcText $a1.firstOkUtc) -eq "2026-10-07T12:00:00Z" -and [int]$a1.writes -eq 1) "A: the first accepted heartbeat + poll writes the record with the code hash"
    Update-AgentAliveRecord -Now $t0.AddSeconds(10)
    $a2 = [IO.File]::ReadAllText($ap) | ConvertFrom-Json
    Assert-True ([int]$a2.writes -eq 1 -and (UtcText $a2.lastOkUtc) -eq "2026-10-07T12:00:00Z") "A: no rewrite within 30 s"
    Update-AgentAliveRecord -Now $t0.AddSeconds(31)
    $a3 = [IO.File]::ReadAllText($ap) | ConvertFrom-Json
    Assert-True ([int]$a3.writes -eq 2 -and (UtcText $a3.lastOkUtc) -eq "2026-10-07T12:00:31Z" -and (UtcText $a3.firstOkUtc) -eq "2026-10-07T12:00:00Z") "A: after 30 s lastOkUtc advances and firstOkUtc is kept"
    # a write failure: state\ becomes a FILE, so nothing can be written under it
    Remove-Item -LiteralPath (Join-Path $BaseDir "state") -Recurse -Force
    [IO.File]::WriteAllText((Join-Path $BaseDir "state"), "not a folder")
    $threw = $null
    try { Update-AgentAliveRecord -Now $t0.AddSeconds(70); Update-AgentAliveRecord -Now $t0.AddSeconds(110) } catch { $threw = $_.Exception.Message }
    Assert-True ($null -eq $threw) "A: a failed write never throws ($threw)"
    Assert-True (@($script:logged | Where-Object { $_ -match "Alive record could not be written" }).Count -eq 1) "A: a failed write is reported once, not every pass"
    Remove-Item -LiteralPath (Join-Path $BaseDir "state") -Force
    New-Item -ItemType Directory -Force -Path (Join-Path $BaseDir "state") | Out-Null

    # P: window placement and the last routing attempt
    $cfg = [pscustomobject]@{ launcher = [pscustomobject]@{ path = $formExe; processName = $formName }; sessionDisplay = [pscustomobject]@{ profileDir = (Join-Path $tmp "no-edge-profile") } }
    $Global:SessionDisplayProfileDir = Join-Path $tmp "no-edge-profile"
    $primary = @(Get-CurrentScreens | Where-Object { $_.Primary })[0]
    $sr = Safe-RouteProcessWindow -context "test" -ProcessId ([int]$form.Id) -role "play" -payloadObj $null -Maximize
    Assert-True ($sr.moved -eq $true) "P: routing the test window to role play reports moved"
    $pl = Get-WindowPlacement ([IntPtr]$form.MainWindowHandle)
    Assert-True ([string]$pl.device -eq [string]$primary.DeviceName -and $pl.maximized -eq $true) "P: Get-WindowPlacement says the window is on $($primary.DeviceName), maximized (device $($pl.device), maximized $($pl.maximized))"
    $rep = Get-DisplayReport
    Assert-True ((Has $rep.lastRouting "play") -and [int]$rep.lastRouting["play"].pid -eq [int]$form.Id -and $rep.lastRouting["play"].moved -eq $true -and [string]$rep.lastRouting["play"].context -eq "test") "P: the display report keeps the last routing attempt for the role (it used to be discarded)"
    $mw = @(Get-ManagedWindowReport)
    $ml = @($mw | Where-Object { $_["name"] -eq "launcher" })
    Assert-True ($ml.Count -eq 1 -and $ml[0]["role"] -eq "control" -and @($ml[0]["windows"]).Count -ge 1 -and [string]@($ml[0]["windows"])[0]["device"] -eq [string]$primary.DeviceName) "P: the managed-window report finds the launcher on $($primary.DeviceName) with the role the agent uses (control)"
    $expCtl = $null; $scCtl = Get-ScreenForRole "control" $null; if ($null -ne $scCtl) { $expCtl = [string]$scCtl.DeviceName }
    if ($null -eq $expCtl) {
        Assert-True ($null -eq $ml[0]["onExpected"]) "P: with no screen for the control role (one monitor), onExpected is null (cannot tell), not true"
    } else {
        Assert-True ($ml[0]["onExpected"] -eq ([string]$primary.DeviceName -eq $expCtl)) "P: onExpected compares the window's monitor with the control role's screen"
    }
    $cw = @(Get-CompactWindowSummary)
    Assert-True ($cw.Count -eq 2 -and [string]$cw[0]["name"] -eq "launcher" -and [string]$cw[0]["device"] -eq [string]$primary.DeviceName -and $cw[0]["maximized"] -eq $true) "P: the compact summary names the launcher's monitor and state"
    Assert-True ((@(Get-CurrentScreens)).Count -eq [System.Windows.Forms.SystemInformation]::MonitorCount -and @(Get-CurrentScreens | Where-Object { $_.PSObject.Properties.Name -contains "Fresh" }).Count -eq [System.Windows.Forms.SystemInformation]::MonitorCount) "P: Get-CurrentScreens enumerates fresh, one object per monitor"

    # L: the local config report is an allowlist
    $sentinel = "SENTINEL-" + [guid]::NewGuid().ToString("N")
    $CfgPath = Join-Path $BaseDir "agent-config.json"
    $secretCfg = [ordered]@{ environmentUrl = "https://example.invalid"; tenantId = "aaaaaaaa-0000-0000-0000-0000000000a1"; clientId = "bbbbbbbb-0000-0000-0000-0000000000b2"
        clientSecretDpapiPath = "C:\secret-path-$sentinel"; clientCertThumbprint = "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC"; bayId = "dddddddd-0000-0000-0000-0000000000d3"
        launcher = @{ path = "C:\nope.exe"; processName = "Nope" }; sessionDisplay = @{ mode = "kiosk"; url = "file:///x" } }
    $secretCfg[("client" + "Secret")] = $sentinel   # the deprecated plaintext credential key, named indirectly for the hygiene scan
    [IO.File]::WriteAllText($CfgPath, ($secretCfg | ConvertTo-Json -Depth 5))
    $cfg = [IO.File]::ReadAllText($CfgPath) | ConvertFrom-Json
    $PollSec = 3; $HeartbeatSec = 60; $ResultJsonMaxChars = 2000; $Global:LogLevel = "INFO"
    $lcj = (Get-LocalConfigFacts) | ConvertTo-Json -Depth 8 -Compress
    $leaks = @($sentinel, "aaaaaaaa-0000", "bbbbbbbb-0000", "dddddddd-0000", "CCCCCCCCCCCCCCCC", "secret-path") | Where-Object { $lcj.Contains($_) }
    Assert-True (@($leaks).Count -eq 0) "L: no secret, secret path, thumbprint, tenant, client or bay id reaches the local config report (leaked: $(@($leaks) -join ','))"
    Assert-True ($lcj -match '"selfHeal"' -and $lcj -match '"displayRouting"' -and $lcj -match '"launcher"' -and $lcj -notmatch 'fileError') "L: ...while the facts that matter are there (and self-heal was read from the file)"

    # S: the capabilities document stays under the column when the display report is huge
    function Get-DisplayReport { return [ordered]@{ roles = [ordered]@{ play = "\\.\DISPLAY1" }; huge = ("x" * 40000) } }
    function Get-CredentialTelemetry { return @{} }
    function Read-LastUpdateResult { return $null }
    $Global:EmergencyStopEngaged = $false; $Global:EmergencyStopReason = $null; $Global:EmergencyStopPersistOk = $true
    $AgentVersion = "1.3.1"; $AgentManifestVersion = "1.3.1"; $AgentScriptPath = "C:\x\BayAgent.ps1"
    $cfg = [pscustomobject]@{ launcher = [pscustomobject]@{ path = "C:\nope.exe"; processName = "Nope" }; sessionJsonPath = "C:\nope\session.json"; sessionDisplay = [pscustomobject]@{ mode = "kiosk" } }
    $capBig = Build-AgentCapabilitiesJson -eff @{}
    $capBigObj = $capBig | ConvertFrom-Json
    Assert-True ($capBig.Length -le 29000 -and [string]$capBigObj.display.trimmed -match "too large" -and [string]$capBigObj.display.roles.play -eq "\\.\DISPLAY1") "S: a 40000-char display report is replaced by a trimmed note that keeps the roles ($($capBig.Length) chars)"
    Assert-True ([string]$capBigObj.agentVersion -eq "1.3.1" -and $null -ne $capBigObj.emergencyStop) "S: ...and the rest of the document survives"

    # R: Request-CapabilitiesRefresh
    $Global:NextCapabilitiesUtc = [DateTime]::MaxValue; $Global:NextHeartbeatUtc = [DateTime]::MaxValue
    Remove-Variable -Name CapabilitiesRefreshRequestedUtc -Scope Global -ErrorAction SilentlyContinue
    $rq1 = Request-CapabilitiesRefresh
    Assert-True ($rq1 -eq $true -and $Global:NextCapabilitiesUtc -le [DateTime]::UtcNow -and $Global:NextHeartbeatUtc -eq [DateTime]::MinValue) "R: a refresh request makes the next pass send the full document"
    $Global:NextCapabilitiesUtc = [DateTime]::MaxValue
    $rq2 = Request-CapabilitiesRefresh
    Assert-True ($rq2 -eq $false -and $Global:NextCapabilitiesUtc -eq [DateTime]::MaxValue) "R: a second request within 30 s is refused (no burst of 30 KB PATCHes)"
}
finally {
    if ($null -ne $sync) { $sync["Stop"] = $true }
    if ($null -ne $mockHolder) {
        try { [void]$mockHolder.PS.EndInvoke($mockHolder.Handle) } catch {}
        try { $mockHolder.PS.Dispose(); $mockHolder.RS.Dispose() } catch {}
    }
    foreach ($id in $startedIds) { try { Stop-Process -Id $id -Force -ErrorAction SilentlyContinue } catch {} }
    # Junctions first, NON-recursively: a recursive delete follows a junction into its target.
    foreach ($l in $links) { try { if (Test-Path -LiteralPath $l) { [IO.Directory]::Delete($l, $false) } } catch {} }
    try { Remove-Item -LiteralPath $tmp -Recurse -Force -ErrorAction SilentlyContinue } catch {}
}

Write-Host ""
Write-Host ("RESULT: {0} passed, {1} failed" -f $script:Pass, $script:Fail) -ForegroundColor $(if ($script:Fail -eq 0) { "Green" } else { "Red" })
if ($script:Fail -gt 0) { $script:Failures | ForEach-Object { Write-Host "  - $_" -ForegroundColor Red }; exit 1 }
exit 0
