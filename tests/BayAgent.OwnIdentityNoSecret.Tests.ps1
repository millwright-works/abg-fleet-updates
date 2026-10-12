<#
BayAgent.OwnIdentityNoSecret.Tests.ps1

WHAT THIS PROVES
  A0.529, held by the agent itself: once a bay is ENROLLED on its own certificate identity (BayAgent.ps1 -EnrollCert
  -EnrollClientId), it never signs in with a client secret and never reports its own identity while signed in as
  another app -- whatever appears on the PC afterward. And a bay that is NOT enrolled that way (a bay on the shared
  secret, a bay with a certificate on the shared app, a bay moved to its own app by the remote ladder) behaves exactly
  as it did.

WHERE IT COMES FROM
  The independent attack on the 1.6.1 enrollment (2026-10-11, residual R1) put a sealed secret on an enrolled bay
  whose certificate was not yet registered: the agent logged "falling back to the client secret", signed in AS THE
  SHARED APP with the secret, wrote the bay's row as the shared app, and reported ownIdentity = True. The enrollment
  suite could not have seen it: its recorder refused every client secret, so "no run sent a secret" held by
  construction. In THIS suite the recorder has apps whose client secret WORKS, and the secret is planted after the
  guard at the door (the enrollment) has passed.

HOW
  Every scenario runs the REAL TEXT of src\BayAgent\BayAgent.ps1, top to bottom, in a child powershell.exe 5.1, as
  the agent host starts it (-Once) or as a person runs it. The bay is modeled as in BayAgent.Day0Enroll.Tests.ps1:
  a sandbox install (one literal repointed), agent-config.json from Day0's own template, a recorder on 127.0.0.1 for
  Entra's token endpoint and Dataverse, and the real CurrentUser certificate store (every certificate carries a
  subject unique to this run and exactly those are removed).

WHAT IT DOES NOT PROVE
  Entra and Dataverse themselves; a secret file that appears while the agent is already running (the agent reads the
  configured path at start; the refusal itself does not depend on that reading); a real bay.

RUN (from the repo root)
  powershell -NoProfile -ExecutionPolicy Bypass -File tests\BayAgent.OwnIdentityNoSecret.Tests.ps1
  Against a script without the rule (sections N fail, sections C pass):
    ... -AgentScript <path to that BayAgent.ps1>
Exit code 0 = all assertions passed. Hyphens only in comments.
#>
[CmdletBinding()]
param(
    [string]$AgentScript = "",
    [int]$RunTimeoutSeconds = 90
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
try { Add-Type -AssemblyName System.Security -ErrorAction SilentlyContinue } catch {}

if ([string]::IsNullOrWhiteSpace($AgentScript)) { $AgentScript = Join-Path $PSScriptRoot "..\src\BayAgent\BayAgent.ps1" }
$AgentScript = (Resolve-Path $AgentScript).Path
$ManifestSrc = (Resolve-Path (Join-Path $PSScriptRoot "..\src\BayAgent\manifest.json")).Path
$Day0Script  = (Resolve-Path (Join-Path $PSScriptRoot "..\tools\ABG-Day0-Setup.ps1")).Path

$script:Pass = 0; $script:Fail = 0; $script:Failures = @()
function Assert-True([bool]$cond, [string]$msg) {
    if ($cond) { $script:Pass++; Write-Host "  PASS  $msg" }
    else { $script:Fail++; $script:Failures += $msg; Write-Host "  FAIL  $msg" -ForegroundColor Red }
}
function Section([string]$name) { Write-Host ""; Write-Host "== $name" -ForegroundColor Cyan }

$NsTenant   = "11111111-1111-1111-1111-111111111111"
$NsBayId    = [guid]::NewGuid().ToString("D")
$NsOwnApp   = [guid]::NewGuid().ToString("D")
$NsOtherApp = [guid]::NewGuid().ToString("D")   # a second own app, for the bay "moved by the ladder"
$NsShared   = [guid]::NewGuid().ToString("D")   # stands for the shared bay-agent app; ITS CLIENT SECRET WORKS in the recorder
$NsSubject  = "CN=ABG-BayAgent $NsBayId"
# The "secret" is a random marker. The recorder accepts ANY secret for an app listed in SecretApps.
$NsSecretMarker = "not-a-real-secret-" + [guid]::NewGuid().ToString("N")

$SandboxRoot = Join-Path $env:TEMP ("bayagent-nosecret-" + [guid]::NewGuid().ToString("N").Substring(0, 8))
New-Item -ItemType Directory -Force -Path $SandboxRoot | Out-Null

function Get-NsRunCerts {
    return @(Get-ChildItem -LiteralPath "Cert:\CurrentUser\My" -ErrorAction SilentlyContinue |
        Where-Object { $_.Subject -eq $NsSubject } | ForEach-Object { $_.Thumbprint } | Sort-Object)
}

# ---------------------------------------------------------------- the recorder (a client secret WORKS for SecretApps)
function Start-NsMock([hashtable]$Sync) {
    $rs = [runspacefactory]::CreateRunspace(); $rs.Open(); $rs.SessionStateProxy.SetVariable("sync", $Sync)
    $ps = [powershell]::Create(); $ps.Runspace = $rs
    [void]$ps.AddScript({
        $listener = New-Object System.Net.Sockets.TcpListener([System.Net.IPAddress]::Loopback, 0)
        $listener.Start(); $sync["Port"] = ([System.Net.IPEndPoint]$listener.LocalEndpoint).Port
        function Get-MockField([string]$body, [string]$name) {
            foreach ($kv in $body.Split("&")) { $i = $kv.IndexOf("="); if ($i -gt 0 -and $kv.Substring(0, $i) -eq $name) { return [uri]::UnescapeDataString($kv.Substring($i + 1)) } }
            return $null
        }
        function ConvertFrom-MockB64Url([string]$s) {
            $t = $s.Replace("-", "+").Replace("_", "/")
            switch ($t.Length % 4) { 2 { $t += "==" } 3 { $t += "=" } }
            return [Convert]::FromBase64String($t)
        }
        function ConvertTo-MockB64Url([byte[]]$b) { return [Convert]::ToBase64String($b).TrimEnd("=").Replace("+", "-").Replace("/", "_") }
        function Send-MockAnswer($stream, [int]$status, [string]$json) {
            $bytes = [Text.Encoding]::UTF8.GetBytes($json)
            $word = $(if ($status -eq 200) { "OK" } elseif ($status -eq 400) { "Bad Request" } elseif ($status -eq 401) { "Unauthorized" } else { "Not Found" })
            $head = "HTTP/1.1 $status $word`r`nContent-Type: application/json; charset=utf-8`r`nContent-Length: $($bytes.Length)`r`nConnection: close`r`n`r`n"
            $hb = [Text.Encoding]::ASCII.GetBytes($head)
            $stream.Write($hb, 0, $hb.Length); $stream.Write($bytes, 0, $bytes.Length); $stream.Flush()
        }
        try {
            while (-not $sync["Stop"]) {
                if (-not $listener.Server.Poll(200000, [System.Net.Sockets.SelectMode]::SelectRead)) { continue }
                $client = $listener.AcceptTcpClient()
                try {
                    $client.ReceiveTimeout = 5000
                    $stream = $client.GetStream(); $buf = New-Object byte[] 65536; $ms = New-Object System.IO.MemoryStream; $he = -1
                    while ($he -lt 0) { $n = $stream.Read($buf, 0, $buf.Length); if ($n -le 0) { break }; $ms.Write($buf, 0, $n); $he = ([Text.Encoding]::ASCII.GetString($ms.ToArray())).IndexOf("`r`n`r`n") }
                    if ($he -lt 0) { continue }
                    $all = $ms.ToArray(); $head = [Text.Encoding]::ASCII.GetString($all, 0, $he); $cl = 0
                    if ($head -match "(?im)^Content-Length:\s*(\d+)") { $cl = [int]$Matches[1] }
                    $bs = $he + 4
                    while (($all.Length - $bs) -lt $cl) { $n = $stream.Read($buf, 0, $buf.Length); if ($n -le 0) { break }; $ms.Write($buf, 0, $n); $all = $ms.ToArray() }
                    $body = [Text.Encoding]::UTF8.GetString($all, $bs, [Math]::Min($cl, $all.Length - $bs))
                    $reqLine = (($head -split "`r`n")[0])
                    $auth = ""
                    if ($head -match "(?im)^Authorization:\s*(.+)$") { $auth = $Matches[1].Trim() }
                    # The request body is kept only for Dataverse calls (the capability report). A token request's body
                    # may carry the planted secret, so it is never kept: only what was asked, as whom, and how.
                    $rec = @{ requestLine = $reqLine; body = ""; kind = "other"; clientId = ""; outcome = ""; hasSecret = $false }
                    $status = 404; $answer = '{"error":"not found (mock)"}'

                    if ($reqLine -match '^POST /[^/ ]+/oauth2/v2\.0/token ') {
                        $rec.kind = "token"
                        $cid = [string](Get-MockField $body "client_id"); $rec.clientId = $cid
                        $rec.hasSecret = [bool]($body -match '(^|&)client_secret=')
                        if ($rec.hasSecret) {
                            if ($sync["SecretApps"].ContainsKey($cid)) {
                                # A CLIENT SECRET THAT WORKS: this is what makes "it never used one" a result, not a given.
                                $sync["Serial"] = [int]$sync["Serial"] + 1
                                $tok = "st-{0}-{1}" -f $cid, $sync["Serial"]
                                $sync["Issued"][$tok] = $cid
                                $status = 200; $answer = '{"token_type":"Bearer","expires_in":3599,"access_token":"' + $tok + '"}'; $rec.outcome = "issued-by-secret"
                            } else {
                                $status = 401; $answer = '{"error":"invalid_client","error_description":"AADSTS7000215: Invalid client secret provided (mock)."}'; $rec.outcome = "secret-refused"
                            }
                        }
                        elseif (-not $sync["Apps"].ContainsKey($cid)) {
                            $status = 400; $rec.outcome = "no-such-app"
                            $answer = '{"error":"unauthorized_client","error_description":"AADSTS700016: Application with identifier was not found in the directory (mock)."}'
                        } else {
                            $assertion = [string](Get-MockField $body "client_assertion")
                            $parts = $assertion.Split(".")
                            $verdict = "key-not-registered"
                            if ($parts.Count -eq 3) {
                                $hdr = [Text.Encoding]::UTF8.GetString((ConvertFrom-MockB64Url $parts[0])) | ConvertFrom-Json
                                $claims = [Text.Encoding]::UTF8.GetString((ConvertFrom-MockB64Url $parts[1])) | ConvertFrom-Json
                                foreach ($b64 in @($sync["Apps"][$cid])) {
                                    $x = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2 -ArgumentList (, [Convert]::FromBase64String([string]$b64))
                                    $sha1 = [System.Security.Cryptography.SHA1]::Create().ComputeHash($x.RawData)
                                    if ((ConvertTo-MockB64Url $sha1) -ne [string]$hdr.x5t) { continue }
                                    $pub = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPublicKey($x)
                                    $signed = [Text.Encoding]::UTF8.GetBytes($parts[0] + "." + $parts[1])
                                    $sigOk = $pub.VerifyData($signed, (ConvertFrom-MockB64Url $parts[2]), [System.Security.Cryptography.HashAlgorithmName]::SHA256, [System.Security.Cryptography.RSASignaturePadding]::Pkcs1)
                                    $claimsOk = ([string]$claims.iss -eq $cid) -and ([string]$claims.sub -eq $cid)
                                    $verdict = $(if ($sigOk -and $claimsOk) { "issued" } else { "bad-signature" })
                                }
                            }
                            $rec.outcome = $verdict
                            if ($verdict -eq "issued") {
                                $sync["Serial"] = [int]$sync["Serial"] + 1
                                $tok = "at-{0}-{1}" -f $cid, $sync["Serial"]
                                $sync["Issued"][$tok] = $cid
                                $status = 200; $answer = '{"token_type":"Bearer","expires_in":3599,"access_token":"' + $tok + '"}'
                            } else {
                                $status = 401
                                $answer = '{"error":"invalid_client","error_description":"AADSTS700027: The certificate with identifier used to sign the client assertion is not registered on application (mock)."}'
                            }
                        }
                    } elseif ($reqLine -match ' /api/data/') {
                        $rec.kind = "dataverse"; $rec.body = $body
                        $tok = ($auth -replace '^Bearer\s+', '')
                        if ($sync["Issued"].ContainsKey($tok)) {
                            $rec.clientId = [string]$sync["Issued"][$tok]; $rec.outcome = $(if ($tok.StartsWith("st-")) { "ok-secret-token" } else { "ok" }); $status = 200
                            $answer = '{"UserId":"44444444-4444-4444-4444-444444444444","OrganizationId":"55555555-5555-5555-5555-555555555555","BusinessUnitId":"66666666-6666-6666-6666-666666666666","value":[]}'
                        } else {
                            $rec.outcome = "unauthorized"; $status = 401; $answer = '{"error":{"code":"0x80040220","message":"The token was not issued by this recorder (mock)."}}'
                        }
                    }
                    [void]$sync["Requests"].Add($rec)
                    Send-MockAnswer $stream $status $answer
                } catch { [void]$sync["Errors"].Add($_.Exception.Message) }
                finally { $client.Close() }
            }
        } finally { $listener.Stop() }
    })
    $handle = $ps.BeginInvoke()
    return @{ PS = $ps; RS = $rs; Handle = $handle }
}

$sync = [hashtable]::Synchronized(@{
    Stop = $false; Port = 0; Serial = 0
    Apps       = [hashtable]::Synchronized(@{})   # app id -> public certificates registered on it
    SecretApps = [hashtable]::Synchronized(@{})   # app ids whose client secret WORKS
    Issued     = [hashtable]::Synchronized(@{})
    Requests   = [System.Collections.ArrayList]::Synchronized((New-Object System.Collections.ArrayList))
    Errors     = [System.Collections.ArrayList]::Synchronized((New-Object System.Collections.ArrayList))
})
foreach ($a in @($NsOwnApp, $NsOtherApp, $NsShared)) { $sync["Apps"][$a] = [System.Collections.ArrayList]::Synchronized((New-Object System.Collections.ArrayList)) }
# The shared app's secret works. So does a secret presented for the bay's own app (the hardest case for the rule).
$sync["SecretApps"][$NsShared] = $true
$sync["SecretApps"][$NsOwnApp] = $true

$mock = Start-NsMock -Sync $sync
$deadline = (Get-Date).AddSeconds(10)
while ($sync["Port"] -eq 0 -and (Get-Date) -lt $deadline) { Start-Sleep -Milliseconds 50 }
if ($sync["Port"] -eq 0) { throw "the recorder did not start" }
$MockUrl = "http://127.0.0.1:$([int]$sync['Port'])"

function Get-NsMark { return [int]$sync["Requests"].Count }
function Get-NsRequestsSince([int]$Mark) { return @($sync["Requests"].ToArray() | Select-Object -Skip $Mark) }
function Register-NsCertificate([string]$AppId, [string]$CerPath) { [void]$sync["Apps"][$AppId].Add([Convert]::ToBase64String([IO.File]::ReadAllBytes($CerPath))) }

$day0Text = [IO.File]::ReadAllText($Day0Script)
$tm = [regex]::Match($day0Text, '(?s)\$template = @"\r?\n(\{.*?\})\r?\n"@')
if (-not $tm.Success) { throw "could not find the agent-config.json template in $Day0Script" }
$Day0TemplateJson = $tm.Groups[1].Value

function New-NsBay {
    # A freshly installed bay, modeled (see BayAgent.Day0Enroll.Tests.ps1). -ConfigClient: "shared" names the shared
    # app in agent-config.json (what a bay on the secret has, and what the bay sheet passed before 1.6.1); "own" names
    # the bay's own app. The secret file path is the one the template names, pointed into the sandbox; no file is made.
    param([Parameter(Mandatory = $true)][string]$Name, [ValidateSet("shared", "own")][string]$ConfigClient = "shared")
    $root = Join-Path $SandboxRoot $Name
    foreach ($d in @("", "current", "logs", "secrets")) { New-Item -ItemType Directory -Force -Path (Join-Path $root $d) | Out-Null }
    $shipped = [IO.File]::ReadAllText($AgentScript)
    $needle  = '$BaseDir = "C:\AllBirdies\BayAgent"'
    if (-not $shipped.Contains($needle)) { throw "could not find the BaseDir literal in $AgentScript" }
    $agentCopy = Join-Path $root "current\BayAgent.ps1"
    [IO.File]::WriteAllText($agentCopy, $shipped.Replace($needle, ('$BaseDir = "{0}"' -f $root)), (New-Object Text.UTF8Encoding($false)))
    Copy-Item -LiteralPath $ManifestSrc -Destination (Join-Path $root "current\manifest.json") -Force
    $cfg = $Day0TemplateJson | ConvertFrom-Json
    $cfg.environmentUrl = $MockUrl; $cfg.tenantId = $NsTenant; $cfg.bayId = $NsBayId
    $cfg.clientId = $(if ($ConfigClient -eq "own") { $NsOwnApp } else { $NsShared })
    $cfg.clientSecretDpapiPath = (Join-Path $root "secrets\clientsecret.dpapi")
    $cfg.sessionJsonPath = (Join-Path $root "session.json")
    $cfg.launcher.path = "C:\AbgNoSuchLauncher\NoSuch.exe"; $cfg.launcher.processName = "AbgNoSuchLauncher"
    $cfg.sessionDisplay.url = "about:blank"; $cfg.sessionDisplay.profileDir = "C:\AbgNoSuchProfile"
    $cfg | Add-Member -NotePropertyName tokenAuthorityHost -NotePropertyValue $MockUrl
    $cfg.logLevel = "DEBUG"
    [IO.File]::WriteAllText((Join-Path $root "agent-config.json"), ($cfg | ConvertTo-Json -Depth 6), (New-Object Text.UTF8Encoding($true)))
    return [pscustomobject]@{ Root = $root; Agent = $agentCopy; State = (Join-Path $root "state\credential.json"); Config = (Join-Path $root "agent-config.json"); SecretPath = (Join-Path $root "secrets\clientsecret.dpapi") }
}
function Add-NsSealedSecret($Bay) {
    # What "someone put the shared secret on the bay" is: the sealed file at the path the configuration names.
    $sealed = [System.Security.Cryptography.ProtectedData]::Protect([Text.Encoding]::UTF8.GetBytes($NsSecretMarker), $null, [System.Security.Cryptography.DataProtectionScope]::LocalMachine)
    [IO.File]::WriteAllBytes($Bay.SecretPath, $sealed)
}
function Add-NsPlaintextSecret($Bay) {
    # The deprecated form: a clientSecret in agent-config.json, and no sealed-file path.
    $c = [IO.File]::ReadAllText($Bay.Config) | ConvertFrom-Json
    $c.PSObject.Properties.Remove("clientSecretDpapiPath")
    $c | Add-Member -NotePropertyName clientSecret -NotePropertyValue $NsSecretMarker
    [IO.File]::WriteAllText($Bay.Config, ($c | ConvertTo-Json -Depth 6), (New-Object Text.UTF8Encoding($true)))
}

function Invoke-NsAgent {
    param([Parameter(Mandatory = $true)]$Bay, [Parameter(Mandatory = $true)][string]$Arguments, [switch]$Sheet)
    $psExe = Join-Path $env:WINDIR "System32\WindowsPowerShell\v1.0\powershell.exe"
    $lead = $(if ($Sheet) { "-NoProfile -ExecutionPolicy Bypass" } else { "-NoProfile -WindowStyle Minimized" })
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = $psExe
    $psi.Arguments = ('{0} -File "{1}" {2}' -f $lead, $Bay.Agent, $Arguments)
    $psi.UseShellExecute = $false; $psi.RedirectStandardOutput = $true; $psi.RedirectStandardError = $true
    $psi.CreateNoWindow = $true; $psi.WorkingDirectory = $Bay.Root
    $psi.EnvironmentVariables["PSExecutionPolicyPreference"] = "Bypass"
    if ($psi.EnvironmentVariables.ContainsKey("PSModulePath")) { $psi.EnvironmentVariables.Remove("PSModulePath") }
    $logDir = Join-Path $Bay.Root "logs"
    $logBefore = 0
    foreach ($f in @(Get-ChildItem -LiteralPath $logDir -Filter "BayAgent-*.log" -ErrorAction SilentlyContinue)) { $logBefore += ([IO.File]::ReadAllText($f.FullName)).Length }
    $proc = [System.Diagnostics.Process]::Start($psi)
    $soTask = $proc.StandardOutput.ReadToEndAsync(); $seTask = $proc.StandardError.ReadToEndAsync()
    $exited = $proc.WaitForExit($RunTimeoutSeconds * 1000)
    if (-not $exited) { try { $proc.Kill() } catch {} }    # the one process this call started, by its own handle
    $so = ""; $se = ""
    try { if ($soTask.Wait(5000)) { $so = [string]$soTask.Result } } catch {}
    try { if ($seTask.Wait(5000)) { $se = [string]$seTask.Result } } catch {}
    $log = ""
    foreach ($f in @(Get-ChildItem -LiteralPath $logDir -Filter "BayAgent-*.log" -ErrorAction SilentlyContinue)) { $log += ([IO.File]::ReadAllText($f.FullName)) }
    $newLog = $(if ($log.Length -ge $logBefore) { $log.Substring($logBefore) } else { $log })
    return [pscustomobject]@{ TimedOut = (-not $exited); ExitCode = $(if ($exited) { $proc.ExitCode } else { -1 }); StdOut = $so; StdErr = $se; Log = $newLog }
}
function Show-NsRun($r, [string]$label) {
    Write-Host ("        [{0}] exit={1} timedOut={2}" -f $label, $r.ExitCode, $r.TimedOut) -ForegroundColor DarkGray
    foreach ($ln in @(($r.StdOut + "`n" + $r.Log) -split "`r?`n" | Where-Object { $_ -match "RESULT:|FATAL|Auth mode|\[IDENTITY\]|falling back|Client secret refused|Top-level exception" } | Select-Object -Unique -First 7)) {
        Write-Host ("            " + $ln.Trim()) -ForegroundColor DarkGray
    }
}
function Get-NsProp($obj, [string]$name) {
    if ($null -eq $obj) { return $null }
    $p = $obj.PSObject.Properties[$name]
    if ($null -eq $p) { return $null }
    return $p.Value
}
function Get-NsReportField([string]$StdOut, [string]$Label) {
    $m = [regex]::Match($StdOut, ("(?m)^\s*" + [regex]::Escape($Label) + "\s*:\s*(.+?)\s*$"))
    if ($m.Success) { return $m.Groups[1].Value.Trim() }
    return $null
}
function Get-NsCredentialReport([object[]]$Requests) {
    # The credential block of the last capability report written to the bay's row.
    $cred = $null
    foreach ($q in @($Requests | Where-Object { $_.kind -eq "dataverse" -and $_.requestLine -match '^PATCH /api/data/v9\.2/build_baies\(' })) {
        try { $j = Get-NsProp ($q.body | ConvertFrom-Json) "build_agentcapabilitiesjson"; if ($j) { $cred = Get-NsProp ([string]$j | ConvertFrom-Json) "credential" } } catch { }
    }
    return $cred
}
function Get-NsSummary([object[]]$Requests) {
    # What was asked, as whom, and how, in order. Used to say what a run did in one line.
    return (@($Requests | ForEach-Object { "{0}:{1}:{2}{3}" -f $_.kind, $(if ($_.clientId -eq $NsOwnApp) { "own" } elseif ($_.clientId -eq $NsShared) { "shared" } elseif ($_.clientId -eq $NsOtherApp) { "other" } else { "?" }), $_.outcome, $(if ($_.hasSecret) { "(SECRET)" } else { "" }) } | Group-Object | ForEach-Object { "{0} x{1}" -f $_.Name, $_.Count }) -join ", ")
}
function New-NsEnrolledBay([string]$Name, [string]$ConfigClient, [switch]$Register) {
    # A bay enrolled on its own identity at the console, as the bay sheet does it. Returns the bay with its thumbprint.
    $b = New-NsBay -Name $Name -ConfigClient $ConfigClient
    $r = Invoke-NsAgent -Bay $b -Arguments ("-EnrollCert -EnrollClientId " + $NsOwnApp) -Sheet
    $tp = Get-NsReportField $r.StdOut "Thumbprint"
    if ($r.ExitCode -ne 0 -or $tp -notmatch '^[0-9A-F]{40}$') { throw "could not enroll the bay '$Name' (exit $($r.ExitCode))" }
    if ($Register) { Register-NsCertificate -AppId $NsOwnApp -CerPath (Join-Path $b.Root ("state\bay-cert-{0}.cer" -f $tp)) }
    $b | Add-Member -NotePropertyName Thumbprint -NotePropertyValue $tp
    return $b
}
function New-NsPlainCertBay([string]$Name) {
    # A bay with a certificate enrolled the 1.6.0 way (plain -EnrollCert, no app named): the certificate signs in as the
    # app the configuration names (the shared app). NOT enrolled on its own identity.
    $b = New-NsBay -Name $Name -ConfigClient "shared"
    $r = Invoke-NsAgent -Bay $b -Arguments "-EnrollCert" -Sheet
    $st = [IO.File]::ReadAllText($b.State) | ConvertFrom-Json
    $tp = [string](Get-NsProp $st "activeThumbprint")
    if ($r.ExitCode -ne 0 -or $tp -notmatch '^[0-9A-F]{40}$') { throw "could not make the certificate bay '$Name' (exit $($r.ExitCode))" }
    $b | Add-Member -NotePropertyName Thumbprint -NotePropertyValue $tp
    return $b
}

Write-Host "Agent under test : $AgentScript"
Write-Host "Sandbox          : $SandboxRoot"
Write-Host "Recorder         : $MockUrl (a MOCK; a client secret WORKS here for the shared app and for the bay's own app)"

try {
    Assert-True (@(Get-NsRunCerts).Count -eq 0) "precondition: no certificate with this run's subject exists"

    # ============================================================ the instrument: a secret really does work here
    Section "C1 control, and proof of the instrument: a bay on the shared secret signs in with it (unchanged)"
    $c1 = New-NsBay -Name "c1-secret-only"
    Add-NsSealedSecret $c1
    $mark = Get-NsMark
    $r = Invoke-NsAgent -Bay $c1 -Arguments "-Once"
    $q = @(Get-NsRequestsSince $mark); Show-NsRun $r "C1"; Write-Host ("            requests: " + (Get-NsSummary $q)) -ForegroundColor DarkGray
    Assert-True ($r.ExitCode -eq 0 -and $r.Log -match "Auth mode: SECRET \(DPAPI") "it starts in secret mode"
    Assert-True (@($q | Where-Object { $_.kind -eq "token" -and $_.hasSecret -and $_.clientId -eq $NsShared -and $_.outcome -eq "issued-by-secret" }).Count -ge 1) "the recorder ISSUED a token for the shared app's client secret (so a secret that is sent here is seen, and works)"
    Assert-True (@($q | Where-Object { $_.kind -eq "dataverse" -and $_.clientId -eq $NsShared }).Count -ge 3) "...and the bay wrote its row as the shared app"
    $cred = Get-NsCredentialReport $q
    Assert-True ([string](Get-NsProp $cred "lastMintMode") -eq "secret" -and (Get-NsProp (Get-NsProp $cred "identity") "ownIdentity") -eq $false) "its report says so: lastMintMode secret, ownIdentity false"
    Assert-True ($null -eq (Get-NsProp (Get-NsProp $cred "identity") "enrolledOwn") -and $null -eq (Get-NsProp (Get-NsProp $cred "identity") "secretIgnored")) "...and carries no field that only an enrolled bay has (its report is what it was)"

    # ============================================================ N1: the attack's residual R1, exactly
    Section "N1 (the attack's R1) enrolled on its own app, certificate NOT yet registered, then a sealed secret is put on the bay"
    $n1 = New-NsEnrolledBay -Name "n1-r1" -ConfigClient "shared"
    Add-NsSealedSecret $n1
    foreach ($startLabel in @("first start", "second start")) {
        $mark = Get-NsMark
        $r = Invoke-NsAgent -Bay $n1 -Arguments "-Once"
        $q = @(Get-NsRequestsSince $mark); Show-NsRun $r ("N1 " + $startLabel); Write-Host ("            requests: " + (Get-NsSummary $q)) -ForegroundColor DarkGray
        Assert-True (-not $r.TimedOut -and $r.ExitCode -eq 0) "[$startLabel] the agent starts and ends its one pass (exit $($r.ExitCode))"
        Assert-True (@($q | Where-Object { $_.hasSecret }).Count -eq 0) "[$startLabel] NO request carried a client secret (a working one was on the bay)"
        Assert-True (@($q | Where-Object { $_.kind -eq "token" }).Count -ge 1 -and @($q | Where-Object { $_.kind -eq "token" -and ($_.clientId -ne $NsOwnApp -or $_.outcome -ne "key-not-registered") }).Count -eq 0) "[$startLabel] every sign-in was tried as the bay's own app, with its certificate, and was refused (not registered yet)"
        Assert-True (@($q | Where-Object { $_.kind -eq "dataverse" }).Count -eq 0) "[$startLabel] nothing reached Dataverse: the bay is dark, not running as the shared app"
        Assert-True ($r.Log -match "\[IDENTITY\] a client secret is present on this bay \(sealed file .*\) and is IGNORED") "[$startLabel] the log says a secret was found and is ignored"
        Assert-True ($r.Log -notmatch "falling back to the client secret") "[$startLabel] ...and never says it is falling back to it"
        Assert-True ($r.Log -match "fallbackSecret=ignored") "[$startLabel] the Auth mode line reads fallbackSecret=ignored"
    }
    $mark = Get-NsMark
    $r = Invoke-NsAgent -Bay $n1 -Arguments "-TokenOnly -Once" -Sheet
    Assert-True (@(Get-NsRequestsSince $mark | Where-Object { $_.hasSecret }).Count -eq 0 -and $r.Log -notmatch "token acquired via secret") "-TokenOnly -Once on that bay: no secret sent, no token 'via secret'"
    Assert-True (-not (($r.StdOut + $r.Log + $r.StdErr).Contains($NsSecretMarker))) "the secret's text is in nothing the runs printed or logged"

    # ============================================================ N2: registered; the secret changes nothing and is reported
    Section "N2 enrolled and registered, a sealed secret on the bay: it runs as its own app and reports the secret as ignored"
    $n2 = New-NsEnrolledBay -Name "n2-registered" -ConfigClient "shared" -Register
    Add-NsSealedSecret $n2
    $mark = Get-NsMark
    $r = Invoke-NsAgent -Bay $n2 -Arguments "-Once"
    $q = @(Get-NsRequestsSince $mark); Show-NsRun $r "N2"; Write-Host ("            requests: " + (Get-NsSummary $q)) -ForegroundColor DarkGray
    Assert-True ($r.ExitCode -eq 0 -and @($q | Where-Object { $_.hasSecret }).Count -eq 0) "no request carried a client secret"
    Assert-True (@($q | Where-Object { $_.kind -eq "dataverse" }).Count -ge 3 -and @($q | Where-Object { $_.clientId -ne $NsOwnApp }).Count -eq 0) "every request, token and Dataverse, was the bay's own app"
    $cred = Get-NsCredentialReport $q; $ident = Get-NsProp $cred "identity"
    Assert-True ([string](Get-NsProp $cred "activeClientId") -eq $NsOwnApp -and [string](Get-NsProp $cred "lastMintMode") -eq "certificate" -and (Get-NsProp $ident "ownIdentity") -eq $true) "report: its own app, lastMintMode certificate, ownIdentity true"
    Assert-True ((Get-NsProp $ident "enrolledOwn") -eq $true -and (Get-NsProp $ident "secretIgnored") -eq $true) "report: enrolledOwn true and secretIgnored TRUE (an operator can see a secret is sitting on the bay)"
    Assert-True ([string](Get-NsProp $cred "secretConfigured") -eq "dpapi" -and [int](Get-NsProp $cred "fallbackCount") -eq 0) "report: the secret's presence is still stated (secretConfigured dpapi) and no fallback was counted"
    # The second run of the console line on such a bay: refused because a secret is on the PC, and nothing is sent.
    $mark = Get-NsMark
    $r = Invoke-NsAgent -Bay $n2 -Arguments ("-EnrollCert -EnrollClientId " + $NsOwnApp) -Sheet
    Assert-True ($r.ExitCode -eq 2 -and (Get-NsReportField $r.StdOut "Reason code") -eq "ABG_OWNID_SECRET_PRESENT" -and @(Get-NsRequestsSince $mark).Count -eq 0) "the console line on that bay is refused (ABG_OWNID_SECRET_PRESENT) and sends nothing"

    # ============================================================ N3: a plaintext secret, and a secret that would work for the bay's own app
    Section "N3 enrolled (the configuration names the bay's own app), certificate not registered, then a plaintext clientSecret is added"
    $n3 = New-NsEnrolledBay -Name "n3-plaintext" -ConfigClient "own"
    Add-NsPlaintextSecret $n3
    $mark = Get-NsMark
    $r = Invoke-NsAgent -Bay $n3 -Arguments "-Once"
    $q = @(Get-NsRequestsSince $mark); Show-NsRun $r "N3"; Write-Host ("            requests: " + (Get-NsSummary $q)) -ForegroundColor DarkGray
    Assert-True ($r.ExitCode -eq 0 -and @($q | Where-Object { $_.hasSecret }).Count -eq 0 -and @($q | Where-Object { $_.kind -eq "dataverse" }).Count -eq 0) "no secret sent (the recorder would have accepted one for the bay's own app), nothing reached Dataverse"
    Assert-True ($r.Log -match "\[IDENTITY\] a client secret is present on this bay \(plaintext clientSecret in agent-config\.json\) and is IGNORED") "the log names the plaintext secret as ignored"
    Assert-True (-not (($r.StdOut + $r.Log + $r.StdErr).Contains($NsSecretMarker))) "the secret's text is in nothing the run printed or logged"

    # ============================================================ N4: the certificate is gone
    Section "N4 enrolled, ran, then its certificate is gone from the store and a sealed secret is on the bay: dark, and it says why"
    $n4 = New-NsEnrolledBay -Name "n4-cert-gone" -ConfigClient "shared" -Register
    $r = Invoke-NsAgent -Bay $n4 -Arguments "-Once"
    Assert-True ($r.ExitCode -eq 0) "precondition: the bay ran one pass on its own identity"
    Remove-Item -LiteralPath ("Cert:\CurrentUser\My\" + $n4.Thumbprint) -DeleteKey -Force     # this run made this certificate
    Add-NsSealedSecret $n4
    $mark = Get-NsMark
    $r = Invoke-NsAgent -Bay $n4 -Arguments "-Once"
    $q = @(Get-NsRequestsSince $mark); Show-NsRun $r "N4"
    Assert-True (-not $r.TimedOut -and $r.ExitCode -eq 1) "the agent does not start (exit $($r.ExitCode)); it does not 'run on the client secret until the certificate is found'"
    Assert-True ($q.Count -eq 0) "nothing was sent anywhere"
    Assert-True ($r.Log -match "FATAL" -and $r.Log -match "no certificate with a private key was found" -and $r.Log -match "never signs in with a client secret" -and $r.Log -match "the one found on it is ignored") "the reason names the missing certificate, says the bay never uses a secret, and that the one found is ignored"
    Assert-True ($r.Log -match "-EnrollCert -EnrollClientId .* -EnrollForce" -and $r.Log -notmatch "running on the client secret") "...and names the way back (enroll again at the console), not the secret"

    # ============================================================ N5: a damaged record
    Section "N5 the record of the bay's own identity survives but names no certificate (a damaged state file), and a secret is on the bay"
    $n5 = New-NsEnrolledBay -Name "n5-damaged" -ConfigClient "shared"
    $s5 = [IO.File]::ReadAllText($n5.State) | ConvertFrom-Json
    $s5.PSObject.Properties.Remove("activeThumbprint")
    [IO.File]::WriteAllText($n5.State, ($s5 | ConvertTo-Json -Depth 6), (New-Object Text.UTF8Encoding($false)))
    Add-NsSealedSecret $n5
    $mark = Get-NsMark
    $r = Invoke-NsAgent -Bay $n5 -Arguments "-Once"
    $q = @(Get-NsRequestsSince $mark); Show-NsRun $r "N5"; Write-Host ("            requests: " + (Get-NsSummary $q)) -ForegroundColor DarkGray
    Assert-True (-not $r.TimedOut -and @($q | Where-Object { $_.hasSecret }).Count -eq 0 -and @($q | Where-Object { $_.kind -eq "dataverse" }).Count -eq 0) "no secret is sent and nothing reaches Dataverse"
    Assert-True ($r.Log -match "Client secret refused: this bay is enrolled on its own certificate identity") "the one place a secret is sent refuses it, and says why"
    Assert-True ($r.Log -match "Auth mode: NONE" -and $r.Log -notmatch "Auth mode: SECRET") "start-up does not announce the secret as this bay's credential"

    # ============================================================ N6, N7: the record and what is in force disagree
    # An automated review of this change raised the class "the gate reads one field, the action reads another". The
    # gate here is the enrollment record; the action is a sign-in with the secret as the CONFIGURED app. These two
    # scenarios make everything else disagree with the record and show the gate still holds.
    Section "N6 enrolled, then a later identity switch puts ANOTHER app in force (the record stays), and a secret is on the bay"
    $n6 = New-NsEnrolledBay -Name "n6-switched" -ConfigClient "shared"
    $s6 = [IO.File]::ReadAllText($n6.State) | ConvertFrom-Json
    $s6.activeClientId = $NsOtherApp      # what a later CredentialRotate action=activate with another app records
    [IO.File]::WriteAllText($n6.State, ($s6 | ConvertTo-Json -Depth 6), (New-Object Text.UTF8Encoding($false)))
    Add-NsSealedSecret $n6
    $mark = Get-NsMark
    $r = Invoke-NsAgent -Bay $n6 -Arguments "-Once"
    $q = @(Get-NsRequestsSince $mark); Show-NsRun $r "N6"; Write-Host ("            requests: " + (Get-NsSummary $q)) -ForegroundColor DarkGray
    Assert-True (-not $r.TimedOut -and @($q | Where-Object { $_.hasSecret }).Count -eq 0 -and @($q | Where-Object { $_.kind -eq "dataverse" }).Count -eq 0) "no secret is sent although the app in force is no longer the enrolled one; nothing reaches Dataverse"
    Assert-True (@($q | Where-Object { $_.kind -eq "token" -and $_.clientId -eq $NsOtherApp -and -not $_.hasSecret }).Count -ge 1) "the only sign-in tried is the certificate, as the app in force"
    Assert-True ($r.Log -match "IGNORED" -and $r.Log -notmatch "falling back to the client secret") "the secret is named as ignored; no fallback"

    Section "N7 enrolled, then the state file loses its activeClientId (the configuration names the shared app), and a secret is on the bay"
    $n7 = New-NsEnrolledBay -Name "n7-lost-field" -ConfigClient "shared"
    $s7 = [IO.File]::ReadAllText($n7.State) | ConvertFrom-Json
    $s7.PSObject.Properties.Remove("activeClientId")
    [IO.File]::WriteAllText($n7.State, ($s7 | ConvertTo-Json -Depth 6), (New-Object Text.UTF8Encoding($false)))
    Add-NsSealedSecret $n7
    $mark = Get-NsMark
    $r = Invoke-NsAgent -Bay $n7 -Arguments "-Once"
    $q = @(Get-NsRequestsSince $mark); Show-NsRun $r "N7"; Write-Host ("            requests: " + (Get-NsSummary $q)) -ForegroundColor DarkGray
    Assert-True (-not $r.TimedOut -and @($q | Where-Object { $_.hasSecret }).Count -eq 0 -and @($q | Where-Object { $_.kind -eq "dataverse" }).Count -eq 0) "no secret is sent although the app in force now reads as the shared one; nothing reaches Dataverse"
    $cred7 = Get-NsCredentialReport $q
    Assert-True ($null -eq $cred7) "and it writes no report at all (it cannot sign in), so it cannot report its own identity while being another app"

    Section "N8 census on the real text: one sender of a client secret, and the refusal stands in front of it"
    $ctk = $null; $cer = $null
    $cAst = [System.Management.Automation.Language.Parser]::ParseFile($AgentScript, [ref]$ctk, [ref]$cer)
    $cFns = @($cAst.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $true))
    $senders = @($cFns | Where-Object { $_.Extent.Text -match 'client_secret=' } | ForEach-Object { $_.Name })
    Assert-True (($senders -join ",") -eq "Acquire-TokenWithSecret" -and [regex]::Matches([IO.File]::ReadAllText($AgentScript), 'client_secret=').Count -eq 1) ("exactly one place in the script builds a request with client_secret, in Acquire-TokenWithSecret (found: " + ($senders -join ", ") + ")")
    $readers = @($cAst.FindAll({ param($n) $n -is [System.Management.Automation.Language.CommandAst] -and $n.GetCommandName() -eq "Get-ClientSecret" }, $true))
    $senderFn = @($cFns | Where-Object { $_.Name -eq "Acquire-TokenWithSecret" })
    $readerInside = ($readers.Count -eq 1 -and $senderFn.Count -eq 1 -and $readers[0].Extent.StartOffset -gt $senderFn[0].Extent.StartOffset -and $readers[0].Extent.EndOffset -lt $senderFn[0].Extent.EndOffset)
    Assert-True $readerInside ("the secret is read in exactly one place, inside that function (calls of Get-ClientSecret: " + $readers.Count + ")")
    if ($senderFn.Count -eq 1) {
        $throws = @($senderFn[0].FindAll({ param($n) $n -is [System.Management.Automation.Language.ThrowStatementAst] -and $n.Extent.Text -match 'Client secret refused' }, $true))
        $gate = @($senderFn[0].FindAll({ param($n) $n -is [System.Management.Automation.Language.CommandAst] -and $n.GetCommandName() -eq "Test-OwnIdentityActive" -and $n.Extent.Text -match '-EnrolledOnly' }, $true))
        Assert-True ($throws.Count -eq 1 -and $gate.Count -eq 1 -and $readers.Count -eq 1 -and $gate[0].Extent.StartOffset -lt $throws[0].Extent.StartOffset -and $throws[0].Extent.EndOffset -lt $readers[0].Extent.StartOffset) "inside it: the enrollment gate, then the refusal, and only then the read of the secret"
    } else { Assert-True $false "Acquire-TokenWithSecret was not found exactly once" }
    $gateFn = @($cFns | Where-Object { $_.Name -eq "Test-OwnIdentityActive" })
    $gateOk = $false
    if ($gateFn.Count -eq 1) {
        # Everything the function does BEFORE it answers -EnrolledOnly: it may read the state file and nothing else.
        $gateText = $gateFn[0].Extent.Text
        $cut = $gateText.IndexOf('if ($EnrolledOnly) {')
        $closing = $(if ($cut -ge 0) { $gateText.IndexOf('$active = Get-ActiveClientId', $cut) } else { -1 })
        if ($cut -gt 0 -and $closing -gt $cut) {
            $beforeAnswer = (($gateText.Substring(0, $closing) -split "`r?`n") | Where-Object { $_ -notmatch '^\s*#' }) -join "`n"
            $gateOk = ($beforeAnswer -notmatch 'Get-ActiveClientId|Get-ActiveCertThumbprint|\$ClientId|\$cfg\b|ConvertTo-AgentGuid') -and ($beforeAnswer -match 'Read-CredentialState') -and ($beforeAnswer -match '\$recordPresent = \(\$null -ne \$stateProp\.Value\)') -and ($beforeAnswer -match 'return \(\$recordPresent -or ')
        }
    }
    Assert-True $gateOk "the gate's answer is the existence of the enrollment record and nothing else: before it answers, the function reads the state file only (not the app in force, the certificate or the configuration)"
    $swallowed = @($cFns | Where-Object { $_.Name -in @("Acquire-TokenWithSecret", "Acquire-Token", "Write-CredentialStartupSummary") -and $_.Extent.Text -match 'try \{[^\r\n}]*Test-OwnIdentityActive -EnrolledOnly' } | ForEach-Object { $_.Name })
    Assert-True ($swallowed.Count -eq 0) ("none of the three places that DECIDE on the gate catches its error (a gate that cannot answer must not read as 'not enrolled'): " + $(if ($swallowed.Count) { $swallowed -join ", " } else { "none do" }))

    # ============================================================ D: when the gate's one piece of state is not what it should be
    # An automated review raised a second class: a gate that reads one piece of stored state, where losing or damaging
    # that state makes it answer "not enrolled" and opens what it was closing. Every bay below WAS enrolled at the
    # console (certificate not registered), then its state file was changed as the label says and a working secret was
    # put on it. Each case is on one side, on purpose, and the side is what is asserted:
    #   REFUSE  the agent sends no secret and reaches nothing;
    #   OPEN    the agent behaves as a bay that was never enrolled and signs in with the secret. These are the cases
    #           the rule does NOT cover. They are stated here so that nobody has to find them.
    Section "D the enrollment record after the fact: which damage keeps the rule, and which lets a secret through (a stated choice per case)"
    function Set-NsRecord($Bay, [string]$JsonValue) {
        # Rewrites ONLY the ownIdentityEnrolled value in the state file, as raw JSON text.
        $t = [IO.File]::ReadAllText($Bay.State)
        $m = [regex]::Match($t, '(?s)"ownIdentityEnrolled"\s*:\s*\{.*?\}')
        if (-not $m.Success) { throw "could not find the record in the state file" }
        [IO.File]::WriteAllText($Bay.State, $t.Replace($m.Value, ('"ownIdentityEnrolled": ' + $JsonValue)), (New-Object Text.UTF8Encoding($false)))
    }
    $driftCases = @(
        @{ side = "REFUSE"; label = "the record is an empty object";                  change = { param($b) Set-NsRecord $b '{}' } },
        @{ side = "REFUSE"; label = "the record is a piece of text";                  change = { param($b) Set-NsRecord $b '"yes"' } },
        @{ side = "REFUSE"; label = "the record is false";                            change = { param($b) Set-NsRecord $b 'false' } },
        @{ side = "REFUSE"; label = "the record is 0";                                change = { param($b) Set-NsRecord $b '0' } },
        @{ side = "REFUSE"; label = "the record is an empty list";                    change = { param($b) Set-NsRecord $b '[]' } },
        @{ side = "REFUSE"; label = "the record's name is in another letter case";    change = { param($b) [IO.File]::WriteAllText($b.State, ([IO.File]::ReadAllText($b.State)).Replace('"ownIdentityEnrolled"', '"OWNIDENTITYENROLLED"'), (New-Object Text.UTF8Encoding($false))) } },
        @{ side = "REFUSE"; label = "the record is all that is left of the state file"; change = { param($b) $o = [IO.File]::ReadAllText($b.State) | ConvertFrom-Json; [IO.File]::WriteAllText($b.State, ('{ "ownIdentityEnrolled": ' + ($o.ownIdentityEnrolled | ConvertTo-Json -Compress) + ' }'), (New-Object Text.UTF8Encoding($false))) } },
        @{ side = "OPEN";   label = "the state file is deleted";                      change = { param($b) Remove-Item -LiteralPath $b.State -Force } },
        @{ side = "OPEN";   label = "the state file is emptied (zero bytes)";         change = { param($b) [IO.File]::WriteAllBytes($b.State, (New-Object byte[] 0)) } },
        @{ side = "OPEN";   label = "the record alone is removed from the state file"; change = { param($b) $o = [IO.File]::ReadAllText($b.State) | ConvertFrom-Json; $o.PSObject.Properties.Remove("ownIdentityEnrolled"); [IO.File]::WriteAllText($b.State, ($o | ConvertTo-Json -Depth 6), (New-Object Text.UTF8Encoding($false))) } },
        @{ side = "OPEN";   label = "the record's value is JSON null";                change = { param($b) Set-NsRecord $b 'null' } },
        @{ side = "OPEN";   label = "the state file is truncated (does not parse)";   change = { param($b) $t = [IO.File]::ReadAllText($b.State); [IO.File]::WriteAllText($b.State, $t.Substring(0, [int]($t.Length / 2)), (New-Object Text.UTF8Encoding($false))) }; says = "credential\.json is CORRUPT" },
        @{ side = "OPEN";   label = "the state file cannot be read (held open by another program)"; change = { param($b) }; lock = $true; says = "credential\.json is present but UNREADABLE" },
        @{ side = "REFUSE"; label = "the state file is a one-item list around the same object (PowerShell hands the item back)"; change = { param($b) [IO.File]::WriteAllText($b.State, ('[ ' + [IO.File]::ReadAllText($b.State) + ' ]'), (New-Object Text.UTF8Encoding($false))) } }
    )
    $driftIndex = 0
    foreach ($dc in $driftCases) {
        $driftIndex++
        $db = New-NsEnrolledBay -Name ("d-" + $driftIndex) -ConfigClient "shared"
        & $dc.change $db
        Add-NsSealedSecret $db
        $held = $null
        if ($dc.ContainsKey("lock")) { $held = [IO.File]::Open($db.State, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::None) }
        $mark = Get-NsMark
        try { $r = Invoke-NsAgent -Bay $db -Arguments "-Once" } finally { if ($null -ne $held) { $held.Dispose() } }
        $q = @(Get-NsRequestsSince $mark)
        $secretSent = @($q | Where-Object { $_.hasSecret }).Count
        Write-Host ("        [{0}] {1}: exit={2} requests: {3}" -f $dc.side, $dc.label, $r.ExitCode, (Get-NsSummary $q)) -ForegroundColor DarkGray
        if ($dc.side -eq "REFUSE") {
            Assert-True (-not $r.TimedOut -and $secretSent -eq 0 -and @($q | Where-Object { $_.kind -eq "dataverse" }).Count -eq 0) ("REFUSE  " + $dc.label + ": no secret is sent and nothing reaches Dataverse")
            Assert-True ($r.Log -match "IGNORED|Client secret refused") ("REFUSE  " + $dc.label + ": the log says the secret is ignored or refused")
        } else {
            Assert-True (-not $r.TimedOut -and $r.ExitCode -eq 0 -and @($q | Where-Object { $_.hasSecret -and $_.outcome -eq "issued-by-secret" -and $_.clientId -eq $NsShared }).Count -ge 1) ("OPEN    " + $dc.label + ": the agent signs in with the secret as the configured app, as a bay that was never enrolled would (the rule does not cover this case)")
            if ($dc.ContainsKey("says")) {
                $credD = Get-NsCredentialReport $q
                Assert-True ($r.Log -match $dc.says -and (Get-NsProp $credD "stateFileCorrupt") -eq $true) ("OPEN    " + $dc.label + ": ...and it says so: an ERROR line in the log and stateFileCorrupt = true in its report")
            }
        }
    }

    Section "D2 (lifted, and said so) two cases no run of the script can reach: the record vanishes during a run, and the gate itself fails"
    # A run with -Once signs in once, so "there at the start, gone later in the same run" needs the functions in this
    # process. The gate, the one sender of a secret and what they call are lifted out of the script; the token endpoint
    # and the reader of the secret are stand-ins that count their calls.
    $liftD = @("Get-PropValue", "ConvertTo-AgentGuid", "Normalize-Thumbprint", "Read-CredentialState", "Get-ActiveClientId", "Get-ActiveCertThumbprint", "Test-OwnIdentityActive", "Get-TokenUrl", "Acquire-TokenWithSecret")
    $dDefs = @{}
    foreach ($d in $cFns) { $dDefs[$d.Name] = $d.Extent.Text }
    $dMissing = @($liftD | Where-Object { -not $dDefs.ContainsKey($_) })
    Assert-True ($dMissing.Count -eq 0) ("the functions this check needs exist in the script (missing: " + $(if ($dMissing.Count) { $dMissing -join ", " } else { "none" }) + ")")
    if ($dMissing.Count -eq 0) {
        foreach ($ln in $liftD) { . ([scriptblock]::Create($dDefs[$ln])) }
        function Write-Log { param([string]$Message, [string]$Level = "INFO") }
        $script:NsSecretReads = 0; $script:NsTokenPosts = 0
        function Get-ClientSecret { $script:NsSecretReads++; return "stand-in" }
        function Invoke-TokenEndpoint { param([string]$TokenUrl, [string]$FormBody) $script:NsTokenPosts++; return [pscustomobject]@{ access_token = "stand-in"; expires_in = 3599 } }
        $liftRootD = Join-Path $SandboxRoot "lifted-latch"
        New-Item -ItemType Directory -Force -Path (Join-Path $liftRootD "state") | Out-Null
        $CredentialStatePath = Join-Path $liftRootD "state\credential.json"
        $TenantId = $NsTenant; $ClientId = $NsShared; $OrgUrl = $MockUrl; $TokenAuthorityHost = $MockUrl; $CertThumbprintCfg = $null
        $Global:CredentialStateCorrupt = $false
        Remove-Variable -Name OwnIdentityEnrolledSeen -Scope Global -ErrorAction SilentlyContinue
        # control first: with no record the lifted sender does send (so a refusal below is the gate's doing)
        $null = Acquire-TokenWithSecret
        Assert-True ($script:NsSecretReads -eq 1 -and $script:NsTokenPosts -eq 1) "control: with no enrollment record the lifted sender reads the secret and posts it (once)"
        [IO.File]::WriteAllText($CredentialStatePath, ('{ "activeClientId": "' + $NsOwnApp + '", "ownIdentityEnrolled": { "clientId": "' + $NsOwnApp + '" } }'), (New-Object Text.UTF8Encoding($false)))
        Assert-True ((Test-OwnIdentityActive -EnrolledOnly) -eq $true) "the record is there: the gate answers enrolled"
        Remove-Item -LiteralPath $CredentialStatePath -Force
        Assert-True ((Test-OwnIdentityActive -EnrolledOnly) -eq $true) "the record is GONE later in the same run: the gate still answers enrolled (it was seen once by this process)"
        $threwD = ""
        try { $null = Acquire-TokenWithSecret } catch { $threwD = [string]$_.Exception.Message }
        Assert-True ($threwD -match "Client secret refused" -and $script:NsSecretReads -eq 1 -and $script:NsTokenPosts -eq 1) "...and the sender refuses: the secret is not read again and nothing is posted"
        # the gate itself fails: the read of the state throws something the reader does not catch
        Remove-Variable -Name OwnIdentityEnrolledSeen -Scope Global -ErrorAction SilentlyContinue
        function Read-CredentialState { throw "stand-in: the state could not be read at all" }
        $threwG = ""
        try { $null = Acquire-TokenWithSecret } catch { $threwG = [string]$_.Exception.Message }
        Assert-True ($threwG -match "the state could not be read at all" -and $script:NsSecretReads -eq 1 -and $script:NsTokenPosts -eq 1) "when the gate itself fails, the sender fails with it: no secret is read, nothing is posted (it is not read as 'not enrolled')"
        Remove-Variable -Name OwnIdentityEnrolledSeen -Scope Global -ErrorAction SilentlyContinue
    }

    # ============================================================ controls: bays that are NOT enrolled keep 1.6.0's behavior
    Section "C2 control: a certificate on the SHARED app (plain -EnrollCert), not registered, with the secret: it falls back to the secret (unchanged)"
    $c2 = New-NsPlainCertBay -Name "c2-plain-cert"
    Add-NsSealedSecret $c2
    $mark = Get-NsMark
    $r = Invoke-NsAgent -Bay $c2 -Arguments "-Once"
    $q = @(Get-NsRequestsSince $mark); Show-NsRun $r "C2"; Write-Host ("            requests: " + (Get-NsSummary $q)) -ForegroundColor DarkGray
    Assert-True ($r.ExitCode -eq 0 -and $r.Log -match "falling back to the client secret") "the transitional fallback still works: 'falling back to the client secret'"
    Assert-True (@($q | Where-Object { $_.kind -eq "token" -and -not $_.hasSecret -and $_.clientId -eq $NsShared -and $_.outcome -eq "key-not-registered" }).Count -ge 1 -and @($q | Where-Object { $_.kind -eq "token" -and $_.hasSecret -and $_.outcome -eq "issued-by-secret" }).Count -ge 1) "the certificate was tried first as the shared app, then the secret was sent and worked"
    $cred = Get-NsCredentialReport $q
    Assert-True ([string](Get-NsProp $cred "lastMintMode") -eq "secret" -and [int](Get-NsProp $cred "fallbackCount") -ge 1 -and $null -eq (Get-NsProp (Get-NsProp $cred "identity") "enrolledOwn")) "report: lastMintMode secret, a fallback counted, no enrolled-bay field"
    Assert-True ($r.Log -notmatch "IGNORED" -and $r.Log -match "fallbackSecret=dpapi") "nothing is 'ignored' on this bay; the Auth mode line reads fallbackSecret=dpapi"

    Section "C3 control: a bay moved to its own app by the remote ladder (no console enrollment on record) keeps its secret to go back to (unchanged)"
    $c3 = New-NsPlainCertBay -Name "c3-ladder-moved"
    $s3 = [IO.File]::ReadAllText($c3.State) | ConvertFrom-Json
    $s3 | Add-Member -NotePropertyName activeClientId -NotePropertyValue $NsOtherApp      # what CredentialRotate action=activate records; no ownIdentityEnrolled
    [IO.File]::WriteAllText($c3.State, ($s3 | ConvertTo-Json -Depth 6), (New-Object Text.UTF8Encoding($false)))
    Add-NsSealedSecret $c3
    $mark = Get-NsMark
    $r = Invoke-NsAgent -Bay $c3 -Arguments "-Once"
    $q = @(Get-NsRequestsSince $mark); Show-NsRun $r "C3"; Write-Host ("            requests: " + (Get-NsSummary $q)) -ForegroundColor DarkGray
    Assert-True ($r.ExitCode -eq 0 -and $r.Log -match "falling back to the client secret" -and @($q | Where-Object { $_.hasSecret -and $_.outcome -eq "issued-by-secret" }).Count -ge 1) "its certificate is refused as its own app and it goes back to the secret, as the ladder's design has it"
    $cred = Get-NsCredentialReport $q
    Assert-True ($null -ne $cred -and $null -eq (Get-NsProp (Get-NsProp $cred "identity") "enrolledOwn")) "...and it is not treated as a console-enrolled bay"

    Section "C4 control: a certificate bay whose certificate is missing, with the secret: it runs on the secret until the certificate is found (unchanged)"
    $c4 = New-NsPlainCertBay -Name "c4-cert-missing"
    Remove-Item -LiteralPath ("Cert:\CurrentUser\My\" + $c4.Thumbprint) -DeleteKey -Force     # this run made this certificate
    Add-NsSealedSecret $c4
    $mark = Get-NsMark
    $r = Invoke-NsAgent -Bay $c4 -Arguments "-Once"
    $q = @(Get-NsRequestsSince $mark); Show-NsRun $r "C4"
    Assert-True ($r.ExitCode -eq 0 -and $r.Log -match "running on the client secret" -and @($q | Where-Object { $_.hasSecret -and $_.outcome -eq "issued-by-secret" }).Count -ge 1) "'running on the client secret (dpapi) until it is', and the secret is sent and works"
}
catch {
    Assert-True $false ("the suite stopped on an error at line {0}: {1}" -f $_.InvocationInfo.ScriptLineNumber, $_.Exception.Message)
}
finally {
    $sync["Stop"] = $true
    try { $mock.PS.Stop() } catch {}
    try { $mock.RS.Close() } catch {}
    foreach ($tpLeft in @(Get-NsRunCerts)) {
        try { Remove-Item -LiteralPath ("Cert:\CurrentUser\My\" + $tpLeft) -DeleteKey -Force } catch { Write-Host "could not remove test certificate $tpLeft" -ForegroundColor Yellow }
    }
    try { Remove-Item -LiteralPath $SandboxRoot -Recurse -Force -ErrorAction SilentlyContinue } catch {}
}

Write-Host ""
Assert-True (@(Get-NsRunCerts).Count -eq 0) "cleanup: no certificate of this run is left in the store"
if ($sync["Errors"].Count -gt 0) { Write-Host "recorder errors: $($sync['Errors'] -join ' | ')" -ForegroundColor Yellow }
Assert-True ($sync["Errors"].Count -eq 0) "the recorder itself raised no error ($($sync['Errors'].Count))"
Write-Host ("RESULT: {0} passed, {1} failed" -f $script:Pass, $script:Fail) -ForegroundColor $(if ($script:Fail -eq 0) { "Green" } else { "Red" })
if ($script:Fail -gt 0) { $script:Failures | ForEach-Object { Write-Host "  - $_" -ForegroundColor Red }; exit 1 }
exit 0
