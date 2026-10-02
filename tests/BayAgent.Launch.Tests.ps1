<#
BayAgent.Launch.Tests.ps1

WHY THIS EXISTS
  On 2026-09-21 BayAgent 1.2.0 was installed on a live bay and died in under a second, every start,
  exit code 1:

      FATAL (pid=18400): The term 'Get-PropValue' is not recognized ...
      STACK: at Get-ActiveCertThumbprint, BayAgent.ps1: line 564
             at Write-CredentialStartupSummary, BayAgent.ps1: line 903
             at <ScriptBlock>, BayAgent.ps1: line 937

  230 tests were green when it shipped. Every one of them reached the agent's functions by lifting them
  out of the file with the AST and dot-sourcing them, so all 112 functions existed before the first
  assertion ran. Nothing in the suite had ever STARTED the script.

  This test starts the script. In a real child powershell.exe 5.1, launched with the argument list
  ABG.AgentHost.ps1 uses on a bay, against a real on-disk install layout, and then reads the agent's own
  log file the way a person standing at the bay would.

WHAT IT COVERS
  Four starting states, because the startup path BRANCHES on what is on disk and the branch that killed
  the bay is the commonest one:

    L1  secret-only bay, no state\credential.json         <- this morning's bay, exactly
    L2  credential.json present, certificate PENDING      <- reads the state file through Get-PropValue
    L3  credential.json present, certificate ACTIVE but not in the store, secret still there
    L4  fresh bay: config names a DPAPI secret file that does not exist yet
    L5  no agent-config.json at all: the failure that happens BEFORE logging is initialized

  L1-L3 must reach the end of startup and exit 0 with no FATAL in the log. L4 must FAIL, but fail the way
  it was DESIGNED to -- naming the missing file -- rather than on a missing function. L5 is the case the
  hoisted trap used to be silent for: measured against 1.2.0 it produces ZERO bytes of output, because
  Write-Log did not exist that early and the try/catch around it swallowed that failure too.

HOW THE INSTALL PATH IS HANDLED, AND WHY THE FILE UNDER TEST IS A COPY
  BayAgent.ps1 hardcodes $BaseDir = "C:\AllBirdies\BayAgent". A test may not write there: on a bay that
  is the live install, and on any other machine it is a system location. So the test installs a copy into
  a sandbox with that ONE literal repointed, and then proves the copy is the shipped file in every
  respect this test is measuring:

    - identical line count
    - exactly one line differs, and it is the $BaseDir assignment
    - identical function names, in identical order, at identical line numbers

  The defect class here is ORDER. The equivalence assertions above pin the order exactly, so a pass on
  the copy is a pass on the shipped file. They are asserted, not assumed -- see L0.

  What this therefore does NOT prove: AllSigned. The bay runs machine execution policy AllSigned against
  an Authenticode signature, and a rewritten copy cannot carry one. Signature and policy behaviour stay a
  real-bay proof.

RUN (from the repo root)
  powershell -NoProfile -ExecutionPolicy Bypass -File tests\BayAgent.Launch.Tests.ps1

  To prove it red against the code that failed on the bay:
    git show 5402b2e:src/BayAgent/BayAgent.ps1 > $env:TEMP\BayAgent-1.2.0.ps1
    powershell -NoProfile -ExecutionPolicy Bypass -File tests\BayAgent.Launch.Tests.ps1 -AgentScript $env:TEMP\BayAgent-1.2.0.ps1

Exit code 0 = all assertions passed. Hyphens only in comments (em-dashes break AllSigned parsing).
#>
[CmdletBinding()]
param(
    [string]$AgentScript = "",
    [int]$LaunchTimeoutSeconds = 60
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
try { Add-Type -AssemblyName System.Security -ErrorAction SilentlyContinue } catch {}

if ([string]::IsNullOrWhiteSpace($AgentScript)) { $AgentScript = Join-Path $PSScriptRoot "..\src\BayAgent\BayAgent.ps1" }
$AgentScript = (Resolve-Path $AgentScript).Path
$ManifestSrc = Join-Path $PSScriptRoot "..\src\BayAgent\manifest.json"

# ---------------------------------------------------------------- harness
$script:Pass = 0; $script:Fail = 0; $script:Failures = @()
function Assert-True([bool]$cond, [string]$msg) {
    if ($cond) { $script:Pass++; Write-Host "  PASS  $msg" }
    else { $script:Fail++; $script:Failures += $msg; Write-Host "  FAIL  $msg" -ForegroundColor Red }
}
function Section([string]$name) { Write-Host ""; Write-Host "== $name" -ForegroundColor Cyan }

$TenantId = "11111111-1111-1111-1111-111111111111"
$ClientId = "22222222-2222-2222-2222-222222222222"
$BayId    = "33333333-3333-3333-3333-333333333333"
# A syntactically valid thumbprint for a certificate that is deliberately NOT in any store.
$FakeThumb = "A1B2C3D4E5F60718293A4B5C6D7E8F9012345678"

$SandboxRoot = Join-Path $env:TEMP ("bayagent-launch-" + [guid]::NewGuid().ToString("N").Substring(0, 8))
New-Item -ItemType Directory -Force -Path $SandboxRoot | Out-Null

# ---------------------------------------------------------------- mock token endpoint
# Same shape as the one in BayAgent.Credential.Tests.ps1: a TcpListener on 127.0.0.1 in a background
# runspace. The agent reaches it because agent-config.json carries tokenAuthorityHost.
function Start-MockTokenEndpoint([hashtable]$Sync) {
    $rs = [runspacefactory]::CreateRunspace()
    $rs.Open()
    $rs.SessionStateProxy.SetVariable("sync", $Sync)
    $ps = [powershell]::Create()
    $ps.Runspace = $rs
    [void]$ps.AddScript({
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
                    $respJson = '{"token_type":"Bearer","expires_in":3599,"access_token":"mock-launch-token"}'
                    if ($reqLine -match ' /api/data/') {
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
    $handle = $ps.BeginInvoke()
    return @{ PS = $ps; RS = $rs; Handle = $handle }
}

# ---------------------------------------------------------------- install a bay
function New-BayInstall {
    <#
      Lays down a realistic install under the sandbox and returns its paths:
        <root>\BayAgent.ps1        the shipped script with ONLY $BaseDir repointed at <root>
        <root>\manifest.json       verbatim
        <root>\agent-config.json
        <root>\logs\  state\  secrets\
    #>
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][int]$TokenPort,
        [switch]$WithSecretFile,
        [string]$CredentialStateJson = "",
        [string]$CertThumbprintCfg = "",
        [switch]$WithoutConfig,
        [string]$EnvironmentUrl = "https://mock-org.crm.dynamics.com",
        $ExtraConfig = $null
    )

    $root = Join-Path $SandboxRoot $Name
    New-Item -ItemType Directory -Force -Path $root | Out-Null
    New-Item -ItemType Directory -Force -Path (Join-Path $root "logs") | Out-Null
    New-Item -ItemType Directory -Force -Path (Join-Path $root "secrets") | Out-Null

    # The one edited literal. BayAgent.ps1 is ASCII-only (Build-ReleasePackage gate 2), so reading and
    # rewriting as text cannot change a byte other than the ones intended.
    $shipped = [IO.File]::ReadAllText($AgentScript)
    $needle  = '$BaseDir = "C:\AllBirdies\BayAgent"'
    if (-not $shipped.Contains($needle)) { throw "could not find the BaseDir literal in $AgentScript" }
    $patched = $shipped.Replace($needle, ('$BaseDir = "{0}"' -f $root))
    $agentCopy = Join-Path $root "BayAgent.ps1"
    [IO.File]::WriteAllText($agentCopy, $patched, (New-Object Text.UTF8Encoding($false)))
    Copy-Item -LiteralPath $ManifestSrc -Destination (Join-Path $root "manifest.json") -Force

    if ($WithSecretFile) {
        $plain = [Text.Encoding]::UTF8.GetBytes("not-a-real-secret-" + [guid]::NewGuid().ToString("N"))
        $prot  = [System.Security.Cryptography.ProtectedData]::Protect(
                    $plain, $null, [System.Security.Cryptography.DataProtectionScope]::LocalMachine)
        [IO.File]::WriteAllBytes((Join-Path $root "secrets\clientsecret.dpapi"), $prot)
    }

    if (-not [string]::IsNullOrWhiteSpace($CredentialStateJson)) {
        New-Item -ItemType Directory -Force -Path (Join-Path $root "state") | Out-Null
        [IO.File]::WriteAllText((Join-Path $root "state\credential.json"), $CredentialStateJson,
                                (New-Object Text.UTF8Encoding($false)))
    }

    $cfg = [ordered]@{
        environmentUrl        = $EnvironmentUrl
        tenantId              = $TenantId
        clientId              = $ClientId
        clientSecretDpapiPath = (Join-Path $root "secrets\clientsecret.dpapi")
        clientCertThumbprint  = $CertThumbprintCfg
        bayId                 = $BayId
        pollSeconds           = 3
        heartbeatSeconds      = 60
        tokenAuthorityHost    = ("http://127.0.0.1:{0}" -f $TokenPort)
        logLevel              = "DEBUG"
    }
    if ($null -ne $ExtraConfig) { foreach ($k in $ExtraConfig.Keys) { $cfg[$k] = $ExtraConfig[$k] } }
    if (-not $WithoutConfig) {
        [IO.File]::WriteAllText((Join-Path $root "agent-config.json"),
            ($cfg | ConvertTo-Json -Depth 5), (New-Object Text.UTF8Encoding($false)))
    }

    return [pscustomobject]@{ Root = $root; Agent = $agentCopy }
}

function Start-BayAgentLikeAgentHost {
    <#
      Launches exactly as bootstrap\ABG.AgentHost.ps1 does:
         powershell.exe -NoProfile -WindowStyle Minimized -File "<agent>"
      plus the switch that makes it a bounded test rather than a 24/7 loop. No -ExecutionPolicy flag,
      same as AgentHost: on a bay that is deliberate, so AllSigned is enforced.
    #>
    # NOT named $Switch: $switch is the automatic variable the switch statement binds its enumerator to,
    # and PowerShell variable names are case-insensitive. Distinctive names for anything that could
    # collide with an automatic.
    param([Parameter(Mandatory = $true)]$Install, [string]$BoundingSwitch = "-TokenOnly")

    # The argument string is character-for-character the one AgentHost builds, plus the bounding switch.
    # Started through ProcessStartInfo rather than Start-Process -PassThru because the exit code is the
    # thing being asserted and Start-Process -PassThru does not reliably keep the handle that carries it:
    # MEASURED in this suite, every ExitCode read back EMPTY, so all four exit-code assertions were
    # deciding on $null. A test whose oracle silently returns nothing is worse than no test. CreateNoWindow
    # replaces -WindowStyle Minimized; that is a cosmetic difference in the PARENT's call, and the child's
    # own argument list still carries -WindowStyle Minimized exactly as on a bay.
    $psExe = Join-Path $env:WINDIR "System32\WindowsPowerShell\v1.0\powershell.exe"
    $argList = "-NoProfile -WindowStyle Minimized -File `"$($Install.Agent)`" $BoundingSwitch"

    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName               = $psExe
    $psi.Arguments              = $argList
    $psi.UseShellExecute        = $false
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError  = $true
    $psi.CreateNoWindow         = $true
    $psi.WorkingDirectory       = $Install.Root

    $proc = [System.Diagnostics.Process]::Start($psi)
    # Drained ASYNCHRONOUSLY, and started before the wait. A synchronous ReadToEnd() blocks until the
    # child closes its pipes, which makes $LaunchTimeoutSeconds unenforceable -- and the agent's DEFAULT
    # mode is a 24/7 loop, so the one failure this timeout exists for (the bounding switch stops working)
    # is exactly the one a blocking read would turn into a hung test instead of a red one. Not draining at
    # all is equally wrong: a full pipe buffer deadlocks the child.
    $soTask = $proc.StandardOutput.ReadToEndAsync()
    $seTask = $proc.StandardError.ReadToEndAsync()
    $exited = $proc.WaitForExit($LaunchTimeoutSeconds * 1000)
    if (-not $exited) { try { $proc.Kill() } catch {} }

    $so = ""; $se = ""
    try { if ($soTask.Wait(5000)) { $so = [string]$soTask.Result } } catch {}
    try { if ($seTask.Wait(5000)) { $se = [string]$seTask.Result } } catch {}
    if (-not $exited) {
        return [pscustomobject]@{ TimedOut = $true; ExitCode = -1; Log = ""; StdOut = $so; StdErr = $se }
    }
    $exitCode = $proc.ExitCode

    $log = ""
    $logDir = Join-Path $Install.Root "logs"
    if (Test-Path -LiteralPath $logDir) {
        foreach ($f in @(Get-ChildItem -LiteralPath $logDir -Filter "BayAgent-*.log" -ErrorAction SilentlyContinue)) {
            $log += ([IO.File]::ReadAllText($f.FullName))
        }
    }
    return [pscustomobject]@{ TimedOut = $false; ExitCode = $exitCode; Log = $log; StdOut = $so; StdErr = $se }
}

function Show-Evidence($r, [string]$label) {
    Write-Host ("        [{0}] exit={1} logChars={2}" -f $label, $r.ExitCode, $r.Log.Length) -ForegroundColor DarkGray
    foreach ($ln in @($r.Log -split "`r?`n" | Where-Object { $_ -match "Auth mode|FATAL|STACK|TokenOnly|ERROR|not recognized" } | Select-Object -First 6)) {
        Write-Host ("            $ln") -ForegroundColor DarkGray
    }
}

$sync = [hashtable]::Synchronized(@{
    Stop = $false; Port = 0
    Requests = [System.Collections.ArrayList]::Synchronized((New-Object System.Collections.ArrayList))
    Errors   = [System.Collections.ArrayList]::Synchronized((New-Object System.Collections.ArrayList))
})
$mock = Start-MockTokenEndpoint -Sync $sync
$deadline = (Get-Date).AddSeconds(10)
while ($sync["Port"] -eq 0 -and (Get-Date) -lt $deadline) { Start-Sleep -Milliseconds 50 }
if ($sync["Port"] -eq 0) { throw "mock token endpoint did not start" }
$port = [int]$sync["Port"]
Write-Host "Agent under test : $AgentScript"
Write-Host "Sandbox          : $SandboxRoot"
Write-Host "Mock token endpoint listening on http://127.0.0.1:$port (a MOCK, not Entra)"

try {
    # ============================================================ L0 the copy is the shipped file
    Section "L0 the installed copy differs from the shipped script in exactly one literal"
    $probe = New-BayInstall -Name "equivalence" -TokenPort $port -WithSecretFile

    $shippedLines = [IO.File]::ReadAllLines($AgentScript)
    $copyLines    = [IO.File]::ReadAllLines($probe.Agent)
    Assert-True ($shippedLines.Count -eq $copyLines.Count) `
        "line count identical ($($shippedLines.Count) vs $($copyLines.Count)) - the order under test IS the shipped order"

    $diffIdx = @()
    for ($i = 0; $i -lt [Math]::Min($shippedLines.Count, $copyLines.Count); $i++) {
        if ($shippedLines[$i] -ne $copyLines[$i]) { $diffIdx += $i }
    }
    Assert-True ($diffIdx.Count -eq 1) "exactly one line differs (differing lines: $($diffIdx.Count))"
    if ($diffIdx.Count -eq 1) {
        Assert-True ($shippedLines[$diffIdx[0]].Trim().StartsWith('$BaseDir =')) `
            "...and it is the `$BaseDir assignment (line $($diffIdx[0] + 1))"
    }

    # The strongest form of the claim: every function is in the same place in both files.
    function Get-FuncMap([string]$p) {
        $tk = $null; $er = $null
        $a = [System.Management.Automation.Language.Parser]::ParseFile($p, [ref]$tk, [ref]$er)
        if (@($er).Count -gt 0) { throw "$p has parse errors" }
        return @($a.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $true) |
                 ForEach-Object { "{0}@{1}" -f $_.Name, $_.Extent.StartLineNumber })
    }
    $mapShipped = Get-FuncMap $AgentScript
    $mapCopy    = Get-FuncMap $probe.Agent
    Assert-True (($mapShipped -join "|") -eq ($mapCopy -join "|")) `
        "all $($mapShipped.Count) function definitions have the same names, order and line numbers in both files"

    # ============================================================ L1 this morning's bay
    Section "L1 secret-only bay, no state\credential.json (the bay that failed this morning)"
    $l1 = New-BayInstall -Name "secret-only" -TokenPort $port -WithSecretFile
    Assert-True (-not (Test-Path -LiteralPath (Join-Path $l1.Root "state\credential.json"))) `
        "precondition: there is no credential state file, as on the failed bay"
    $r1 = Start-BayAgentLikeAgentHost -Install $l1
    Show-Evidence $r1 "L1"
    Assert-True (-not $r1.TimedOut) "the process exited rather than hanging"
    Assert-True ($r1.ExitCode -eq 0) "exit code 0 (got $($r1.ExitCode)) - startup completed and the token was minted"
    Assert-True ($r1.Log.Length -gt 0) "the agent wrote a log at all"
    Assert-True ($r1.Log -notmatch "FATAL") "no FATAL in the log"
    Assert-True ($r1.Log -notmatch "is not recognized as the name of a cmdlet") `
        "no 'is not recognized' anywhere in the log - nothing was used before it was defined"
    Assert-True ($r1.Log -match "BayAgent starting") "startup banner reached"
    Assert-True ($r1.Log -match "Auth mode: SECRET") "the credential startup summary ran and chose the secret"
    Assert-True ($r1.Log -match "TokenOnly mode: token acquired") "reached the main loop and minted a token"
    Assert-True ($sync["Requests"].Count -gt 0) "the mock token endpoint actually received the request"

    # ============================================================ L2 pending certificate
    Section "L2 credential.json present with a PENDING certificate (Get-PropValue reads it)"
    $stateJson = @"
{
  "pendingThumbprint": "$FakeThumb",
  "pendingCreatedUtc": "2026-09-20T12:00:00Z",
  "fallbackCountTotal": 0,
  "updatedUtc": "2026-09-20T12:00:00Z"
}
"@
    $l2 = New-BayInstall -Name "pending-cert" -TokenPort $port -WithSecretFile -CredentialStateJson $stateJson
    $r2 = Start-BayAgentLikeAgentHost -Install $l2
    Show-Evidence $r2 "L2"
    Assert-True (-not $r2.TimedOut) "the process exited rather than hanging"
    Assert-True ($r2.ExitCode -eq 0) "exit code 0 (got $($r2.ExitCode))"
    Assert-True ($r2.Log -notmatch "FATAL") "no FATAL in the log"
    Assert-True ($r2.Log -notmatch "is not recognized as the name of a cmdlet") "no 'is not recognized' in the log"
    Assert-True ($r2.Log -match "Auth mode: SECRET") "a pending-only certificate leaves the bay on its secret, as designed"
    Assert-True ($r2.Log -match "TokenOnly mode: token acquired") "reached the main loop"

    # ============================================================ L3 active thumbprint, cert absent
    Section "L3 credential.json names an ACTIVE certificate that is not in the store; secret still present"
    $stateJson3 = @"
{
  "activeThumbprint": "$FakeThumb",
  "activatedUtc": "2026-09-20T12:00:00Z",
  "fallbackCountTotal": 2,
  "updatedUtc": "2026-09-20T12:00:00Z"
}
"@
    $l3 = New-BayInstall -Name "active-cert-missing" -TokenPort $port -WithSecretFile -CredentialStateJson $stateJson3
    $r3 = Start-BayAgentLikeAgentHost -Install $l3
    Show-Evidence $r3 "L3"
    Assert-True (-not $r3.TimedOut) "the process exited rather than hanging"
    Assert-True ($r3.ExitCode -eq 0) "exit code 0 (got $($r3.ExitCode)) - it falls back rather than bricking"
    Assert-True ($r3.Log -notmatch "FATAL") "no FATAL in the log"
    Assert-True ($r3.Log -notmatch "is not recognized as the name of a cmdlet") "no 'is not recognized' in the log"
    Assert-True ($r3.Log -match "is configured but NOT FOUND") "it says plainly that the active certificate is missing"
    Assert-True ($r3.Log -match "TokenOnly mode: token acquired") "reached the main loop on the secret"

    # ============================================================ L4 fresh bay
    Section "L4 fresh bay: the configured DPAPI secret file does not exist yet"
    # This one is EXPECTED to fail. What is being tested is that it fails on its own designed check and
    # that the trap can still write the log line -- the property that did not hold before 1.2.1, because
    # a trap is hoisted above the statements that set up logging.
    $l4 = New-BayInstall -Name "fresh" -TokenPort $port      # no -WithSecretFile
    $r4 = Start-BayAgentLikeAgentHost -Install $l4
    Show-Evidence $r4 "L4"
    Assert-True (-not $r4.TimedOut) "the process exited rather than hanging"
    Assert-True ($r4.ExitCode -eq 1) "exit code 1 (got $($r4.ExitCode)) - a refusal, not a crash loop"
    Assert-True ($r4.Log -match "FATAL") "the trap wrote its FATAL line: a fresh bay says why it will not start"
    Assert-True ($r4.Log -match "clientSecretDpapiPath is set but file not found") `
        "...and the reason is the DESIGNED one, naming the missing file"
    Assert-True ($r4.Log -notmatch "is not recognized as the name of a cmdlet") `
        "...not a missing function (this is the assertion 1.2.0 fails)"

    # ============================================================ L5 the earliest possible failure
    Section "L5 agent-config.json missing: the failure that happens BEFORE logging is initialized"
    # This is the case the hoisted trap was silent for. The throw is at the config check, which runs
    # before $LogFile is assigned, so the trap takes its fallback branch. The evidence has to be stdout:
    # there is no log file yet, by definition. On 1.2.0 this produced NOTHING at all -- Write-Log did not
    # exist that early and the try/catch wrapped around it swallowed the second failure as well.
    $l5 = New-BayInstall -Name "no-config" -TokenPort $port -WithoutConfig
    Assert-True (-not (Test-Path -LiteralPath (Join-Path $l5.Root "agent-config.json"))) `
        "precondition: there is no agent-config.json"
    $r5 = Start-BayAgentLikeAgentHost -Install $l5
    Write-Host ("        [L5] exit={0} stdoutChars={1}" -f $r5.ExitCode, $r5.StdOut.Length) -ForegroundColor DarkGray
    foreach ($ln in @($r5.StdOut -split "`r?`n" | Where-Object { $_ -match "FATAL|STACK" } | Select-Object -First 2)) {
        Write-Host ("            $ln") -ForegroundColor DarkGray
    }
    Assert-True (-not $r5.TimedOut) "the process exited rather than hanging"
    Assert-True ($r5.ExitCode -eq 1) "exit code 1 (got $($r5.ExitCode))"
    Assert-True ($r5.StdOut -match "FATAL") `
        "the trap SAYS SOMETHING for a failure that happens before logging is set up (1.2.0 said nothing)"
    Assert-True ($r5.StdOut -match "Config file not found") "...and it names the missing config file"
    Assert-True ($r5.StdOut -match "\[ERROR\]") "...in the same format Write-Log would have produced"

    # ============================================================ L6 self-heal ON (A0.327 Phase 2)
    Section "L6 selfHeal.enabled = true: the real agent starts, ticks once, and posts its health rows"
    # The watchdog's target is a process name that cannot exist on this machine, so nothing real is ever judged or
    # closed; the health reports read this machine's real screens and Core Audio (read only). environmentUrl points at
    # the MOCK, so the rows go to 127.0.0.1, never to Dataverse.
    Assert-True ($r1.Log -match "\[SELFHEAL\] off") "L1 (no selfHeal block) logged that self-heal is off"
    Assert-True ($r1.Log -notmatch "\[SELFHEAL\] on:") "...and never turned it on"
    $shCfg = [ordered]@{
        selfHeal = [ordered]@{
            enabled = $true
            watchdog = [ordered]@{ enabled = $true; targets = @([ordered]@{ processName = "AbgNoSuchGolfProgram"; relaunch = "shell" }) }
            healthReports = [ordered]@{ enabled = $true }
        }
    }
    $before6 = $sync["Requests"].Count
    $l6 = New-BayInstall -Name "selfheal-on" -TokenPort $port -WithSecretFile -EnvironmentUrl ("http://127.0.0.1:{0}" -f $port) -ExtraConfig $shCfg
    $r6 = Start-BayAgentLikeAgentHost -Install $l6 -BoundingSwitch "-Once"
    Show-Evidence $r6 "L6"
    foreach ($ln in @($r6.Log -split "`r?`n" | Where-Object { $_ -match "SELFHEAL" } | Select-Object -First 8)) { Write-Host ("            $ln") -ForegroundColor DarkGray }
    Assert-True (-not $r6.TimedOut) "the process exited rather than hanging"
    Assert-True ($r6.ExitCode -eq 0) "exit code 0 (got $($r6.ExitCode))"
    Assert-True ($r6.Log -notmatch "FATAL") "no FATAL in the log"
    Assert-True ($r6.Log -notmatch "is not recognized as the name of a cmdlet") "no 'is not recognized' in the log"
    Assert-True ($r6.Log -match "\[SELFHEAL\] on: watchdog=True health=True detector=hungAppWindow targets=AbgNoSuchGolfProgram\(shell\)") "the startup line shows what is on, with the default detector"
    Assert-True ($r6.Log -notmatch "\[SELFHEAL\].*(tick failed|could not start)") "no self-heal tick failed"
    $posts = @($sync["Requests"] | Select-Object -Skip $before6 | Where-Object { $_.requestLine -match '^POST /api/data/v9\.2/build_diagnosticlogs ' })
    Assert-True ($posts.Count -eq 3) "three rows POSTed to build_diagnosticlogs (got $($posts.Count))"
    $postBodies = ($posts | ForEach-Object { $_.body }) -join "`n"
    Assert-True ($postBodies -match '"build_diagnosticname":"Bay \| software\.golf\.responding"' -and $postBodies -match 'display\.screens' -and $postBodies -match 'pc\.audio') "...the golf program, screens and audio rows"
    Assert-True ($postBodies -match ('"build_Bay@odata.bind":"/build_baies\({0}\)"' -f $BayId)) "...each bound to this bay"
    Assert-True ($r6.Log -match "\[SELFHEAL\] delivered 3 report") "the agent logged the delivery"
    $outboxFile = Join-Path $l6.Root "state\selfheal-outbox.json"
    Assert-True ((Test-Path -LiteralPath $outboxFile) -and ((Get-Content -LiteralPath $outboxFile -Raw) -match '^\s*\[\s*\]\s*$')) "the outbox file exists in the install's state folder and is empty after delivery"
}
finally {
    $sync["Stop"] = $true
    try { $mock.PS.Stop() } catch {}
    try { $mock.RS.Close() } catch {}
    try { Remove-Item -LiteralPath $SandboxRoot -Recurse -Force -ErrorAction SilentlyContinue } catch {}
}

Write-Host ""
if ($sync["Errors"].Count -gt 0) { Write-Host "mock endpoint errors: $($sync['Errors'] -join ' | ')" -ForegroundColor Yellow }
Write-Host ("RESULT: {0} passed, {1} failed" -f $script:Pass, $script:Fail) -ForegroundColor $(if ($script:Fail -eq 0) { "Green" } else { "Red" })
if ($script:Fail -gt 0) { $script:Failures | ForEach-Object { Write-Host "  - $_" -ForegroundColor Red }; exit 1 }
exit 0
