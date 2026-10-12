<#
BayAgent.Day0Enroll.Tests.ps1

WHAT THIS PROVES
  A0.524 / A0.528: a freshly installed bay PC that has never held a credential starts on its OWN certificate identity
  on its first day, through `BayAgent.ps1 -EnrollCert -EnrollClientId <the bay's own app id>`, and never needs the
  shared secret (A0.529).

HOW, AND WHY IT IS BUILT THIS WAY
  Every scenario runs the REAL TEXT of src\BayAgent\BayAgent.ps1, top to bottom, in a real child powershell.exe 5.1
  (the host a bay uses), in the argument shapes a run sheet uses:
      powershell.exe -NoProfile -ExecutionPolicy Bypass -File "<bay>\current\BayAgent.ps1" -EnrollCert -EnrollClientId <guid>
      powershell.exe -NoProfile -WindowStyle Minimized -File "<bay>\current\BayAgent.ps1" -Once      (as ABG.AgentHost.ps1 starts it)
  No function is lifted out of the script to be tested apart from it. An attack on a sibling branch (2026-10-11)
  planted 17 changes in a script's body and all 17 passed a suite that only tested lifted functions; this suite is
  written so a change to the script's own body is what it reads.

  The bay is MODELED:
    - the install is a sandbox folder; the script under test is a copy with ONE literal repointed ($BaseDir), and S0
      proves the copy is the shipped file in every other respect;
    - agent-config.json is built from the template ABG-Day0-Setup.ps1 itself writes (read out of that file, so a
      changed template is what is tested), filled the way an operator fills it, in three shapes;
    - Entra and Dataverse are ONE recorder on 127.0.0.1. It answers a token request the way Entra does: an app it does
      not know is AADSTS700016; a certificate not registered on the app is AADSTS700027; a registered certificate must
      have really signed the assertion (the signature is verified against the PUBLIC .cer file the bay wrote, which
      is what the operator's add-cert would register). Every request is recorded, with who it was sent as.
  The certificate store is REAL (CurrentUser\My): keys are made and removed there. Every certificate this suite makes
  carries a subject unique to this run, and exactly those are removed at the end.

THE SECRET GUARD (A0.529) AND "COULD NOT LOOK" (the re-check of 2026-10-12, RF-1)
  S2/S2b/S2e pin the guard that refuses a PC holding a client secret: each of its three places (a sealed file the
  configuration names, a plaintext key in the configuration, the sealed file at the standard place even when another path is named); that
  -EnrollForce does not pass it; that it is asked of a bay that already has an enrollment; and that a place this account
  cannot LOOK AT (a sealed file with the rights the product's own secret tool leaves: SYSTEM and Administrators only; a
  path with an illegal character) is a refusal that names the place (ABG_OWNID_SECRET_UNREADABLE), never "nothing there".
  The unreadable file is built with icacls, not a mocked throw. This suite must be started so the child has a Cert: drive
  (call powershell.exe directly; a Start-Process child of pwsh 7 inherits pwsh's module path and has none): the
  certificate helpers fail loudly instead of reading an unreadable store as "no certificates".

WHAT IT DOES NOT PROVE (a real blank PC and a person's sign-in)
  Entra itself, the directory write that registers the certificate, the command guard, Dataverse's own answers, the
  AllSigned script policy (a rewritten copy cannot carry the bay's signature), Smart App Control, the BayKiosk
  account's own certificate store, and the first install of the package.

RUN (from the repo root), under either host; the bay under test is always a powershell.exe 5.1 child
  powershell -NoProfile -ExecutionPolicy Bypass -File tests\BayAgent.Day0Enroll.Tests.ps1
  pwsh -NoProfile -File tests\BayAgent.Day0Enroll.Tests.ps1

  Red against the release that cannot do it (F3):
    git show 2496cfc:src/BayAgent/BayAgent.ps1 > $env:TEMP\BayAgent-1.6.0.ps1
    powershell -NoProfile -ExecutionPolicy Bypass -File tests\BayAgent.Day0Enroll.Tests.ps1 -AgentScript $env:TEMP\BayAgent-1.6.0.ps1

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

# ---------------------------------------------------------------- harness
$script:Pass = 0; $script:Fail = 0; $script:Failures = @()
function Assert-True([bool]$cond, [string]$msg) {
    if ($cond) { $script:Pass++; Write-Host "  PASS  $msg" }
    else { $script:Fail++; $script:Failures += $msg; Write-Host "  FAIL  $msg" -ForegroundColor Red }
}
function Section([string]$name) { Write-Host ""; Write-Host "== $name" -ForegroundColor Cyan }

# Ids unique to THIS run. The bay id is in every certificate subject, which is how the suite finds and removes exactly
# the certificates it made and no others.
$D0Tenant   = "11111111-1111-1111-1111-111111111111"
$D0BayId    = [guid]::NewGuid().ToString("D")
$D0OwnApp   = [guid]::NewGuid().ToString("D")
$D0OtherApp = [guid]::NewGuid().ToString("D")   # a second bay's app, also known to the mock directory
$D0Shared   = [guid]::NewGuid().ToString("D")   # stands for a shared bay-agent app named in agent-config.json
$D0WrongApp = [guid]::NewGuid().ToString("D")   # a mistyped id: no such app in the mock directory
$D0Subject  = "CN=ABG-BayAgent $D0BayId"
$D0PlaceholderBayId = "<bay-guid-" + $D0BayId.Substring(0, 8) + ">"
$D0PlaceholderSubject = "CN=ABG-BayAgent $D0PlaceholderBayId"
# A syntactically valid thumbprint for a certificate that is in no store.
$D0FakeThumb = "A1B2C3D4E5F60718293A4B5C6D7E8F9012345678"

$SandboxRoot = Join-Path $env:TEMP ("bayagent-day0-" + [guid]::NewGuid().ToString("N").Substring(0, 8))
New-Item -ItemType Directory -Force -Path $SandboxRoot | Out-Null

function Get-D0Sha256Hex([byte[]]$Bytes) {
    $h = [System.Security.Cryptography.SHA256]::Create()
    try { return (($h.ComputeHash($Bytes) | ForEach-Object { $_.ToString("x2") }) -join "") } finally { $h.Dispose() }
}

function Get-D0RunCerts {
    # Every certificate in CurrentUser\My whose subject is this run's. Thumbprints, sorted.
    # It FAILS when the store cannot be read (-ErrorAction Stop): "could not look" must never read as "none made". A
    # process started with Start-Process -WindowStyle Hidden has no Cert: drive here (measured 2026-10-12), and with
    # SilentlyContinue here every certificate check passed or failed on an empty list without saying why.
    return @(Get-ChildItem -LiteralPath "Cert:\CurrentUser\My" -ErrorAction Stop |
        Where-Object { $_.Subject -eq $D0Subject } | ForEach-Object { $_.Thumbprint } | Sort-Object)
}

function Get-D0InstallFingerprint([string]$Root) {
    # Everything a run could have changed on the modeled PC, except the log (a refusal is allowed to write its reason
    # there): every file under the install with its sha256, and this run's certificates. Two equal fingerprints mean
    # nothing was made, removed or rewritten. An unreadable file gets a value that can never equal another's.
    $rows = @()
    foreach ($f in @(Get-ChildItem -LiteralPath $Root -Recurse -File -ErrorAction SilentlyContinue | Sort-Object FullName)) {
        $rel = $f.FullName.Substring($Root.Length).TrimStart("\")
        if ($rel -like "logs\*") { continue }
        $hash = $null
        try { $hash = Get-D0Sha256Hex ([IO.File]::ReadAllBytes($f.FullName)) } catch { $hash = "UNREADABLE-" + [guid]::NewGuid().ToString("N") }
        $rows += ("{0}|{1}" -f $rel, $hash)
    }
    $rows += ("certs|" + ((@(Get-D0RunCerts) + @(Get-D0PlaceholderCerts)) -join ","))
    return ($rows -join "`n")
}

function Get-D0InstallFiles([string]$Root) {
    return @(Get-ChildItem -LiteralPath $Root -Recurse -File -ErrorAction SilentlyContinue |
        ForEach-Object { $_.FullName.Substring($Root.Length).TrimStart("\") } | Sort-Object)
}

# ---------------------------------------------------------------- the recorder (Entra token endpoint + Dataverse)
function Start-D0Mock([hashtable]$Sync) {
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
            $word = $(if ($status -eq 200) { "OK" } elseif ($status -eq 400) { "Bad Request" } elseif ($status -eq 401) { "Unauthorized" } elseif ($status -eq 403) { "Forbidden" } elseif ($status -eq 503) { "Service Unavailable" } else { "Not Found" })
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
                    $rec = @{ requestLine = $reqLine; body = $body; kind = "other"; clientId = ""; outcome = ""; hasSecret = $false; scope = "" }
                    $status = 404; $answer = '{"error":"not found (mock)"}'; $drop = $false

                    if ($reqLine -match '^POST /[^/ ]+/oauth2/v2\.0/token ') {
                        $rec.kind = "token"
                        $cid = [string](Get-MockField $body "client_id"); $rec.clientId = $cid
                        $rec.scope = [string](Get-MockField $body "scope")
                        $rec.hasSecret = [bool]($body -match '(^|&)client_secret=')
                        $mode = [string]$sync["TokenMode"]
                        if ($mode -eq "503") { $status = 503; $answer = '{"error":"temporarily_unavailable"}'; $rec.outcome = "503" }
                        elseif ($mode -eq "drop") { $drop = $true; $rec.outcome = "dropped" }
                        elseif ($mode -eq "proxy403") { $status = 403; $answer = '{"blocked":"by something that is not Entra (mock)"}'; $rec.outcome = "proxy403" }
                        elseif ($mode -eq "clock") { $status = 401; $answer = '{"error":"invalid_client","error_description":"AADSTS700024: Client assertion is not within its valid time range (mock)."}'; $rec.outcome = "clock" }
                        elseif ($rec.hasSecret) { $status = 401; $answer = '{"error":"invalid_client","error_description":"AADSTS7000215: Invalid client secret provided (mock)."}'; $rec.outcome = "secret-refused" }
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
                                    $claimsOk = ([string]$claims.iss -eq $cid) -and ([string]$claims.sub -eq $cid) -and ([string]$claims.aud -like "*/oauth2/v2.0/token")
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
                        $rec.kind = "dataverse"
                        $tok = ($auth -replace '^Bearer\s+', '')
                        if ($sync["Issued"].ContainsKey($tok)) {
                            $rec.clientId = [string]$sync["Issued"][$tok]; $rec.outcome = "ok"; $status = 200
                            $answer = '{"UserId":"44444444-4444-4444-4444-444444444444","OrganizationId":"55555555-5555-5555-5555-555555555555","BusinessUnitId":"66666666-6666-6666-6666-666666666666","value":[]}'
                        } else {
                            $rec.outcome = "unauthorized"; $status = 401; $answer = '{"error":{"code":"0x80040220","message":"The token was not issued by this recorder (mock)."}}'
                        }
                    }
                    [void]$sync["Requests"].Add($rec)
                    if (-not $drop) { Send-MockAnswer $stream $status $answer }
                } catch { [void]$sync["Errors"].Add($_.Exception.Message) }
                finally { $client.Close() }
            }
        } finally { $listener.Stop() }
    })
    $handle = $ps.BeginInvoke()
    return @{ PS = $ps; RS = $rs; Handle = $handle }
}

$sync = [hashtable]::Synchronized(@{
    Stop = $false; Port = 0; TokenMode = "entra"; Serial = 0
    Apps     = [hashtable]::Synchronized(@{})     # app id -> list of base64 DER public certificates registered on it
    Issued   = [hashtable]::Synchronized(@{})     # access token -> the app it was issued to
    Requests = [System.Collections.ArrayList]::Synchronized((New-Object System.Collections.ArrayList))
    Errors   = [System.Collections.ArrayList]::Synchronized((New-Object System.Collections.ArrayList))
})
# The mock directory: the bay's own app and another bay's app exist with no certificate; the mistyped id does not.
$sync["Apps"][$D0OwnApp]   = [System.Collections.ArrayList]::Synchronized((New-Object System.Collections.ArrayList))
$sync["Apps"][$D0OtherApp] = [System.Collections.ArrayList]::Synchronized((New-Object System.Collections.ArrayList))
$sync["Apps"][$D0Shared]   = [System.Collections.ArrayList]::Synchronized((New-Object System.Collections.ArrayList))

$mock = Start-D0Mock -Sync $sync
$deadline = (Get-Date).AddSeconds(10)
while ($sync["Port"] -eq 0 -and (Get-Date) -lt $deadline) { Start-Sleep -Milliseconds 50 }
if ($sync["Port"] -eq 0) { throw "the recorder did not start" }
$port = [int]$sync["Port"]
$MockUrl = "http://127.0.0.1:$port"

function Get-D0Mark { return [int]$sync["Requests"].Count }
function Get-D0RequestsSince([int]$Mark) { return @($sync["Requests"].ToArray() | Select-Object -Skip $Mark) }
function Register-D0Certificate([string]$AppId, [string]$CerPath) {
    # What the operator's add-cert does, on the mock directory: the PUBLIC .cer file the bay wrote goes on the app.
    [void]$sync["Apps"][$AppId].Add([Convert]::ToBase64String([IO.File]::ReadAllBytes($CerPath)))
}

# ---------------------------------------------------------------- the modeled blank bay
# agent-config.json as ABG-Day0-Setup.ps1 writes it: the template is READ OUT OF THAT SCRIPT.
$day0Text = [IO.File]::ReadAllText($Day0Script)
$tm = [regex]::Match($day0Text, '(?s)\$template = @"\r?\n(\{.*?\})\r?\n"@')
if (-not $tm.Success) { throw "could not find the agent-config.json template in $Day0Script" }
$Day0TemplateJson = $tm.Groups[1].Value

function New-D0Bay {
    <#
      A freshly installed bay, modeled: <root>\current\BayAgent.ps1 (the script under test with ONLY $BaseDir repointed),
      current\manifest.json, agent-config.json from Day0's own template, and the empty folders Day0 makes. No state\, no
      credential, no secret file. -Shape is how the operator filled clientId:
        placeholder  clientId left as the template's placeholder; the secret file path named (as the template names it), no file
        own          clientId is the bay's own app; NO secret path in the configuration at all
        shared       clientId is another (shared) app; the secret file path named, no file
    #>
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        [ValidateSet("placeholder", "own", "shared")][string]$Shape = "placeholder",
        [switch]$LeaveBayIdPlaceholder,
        [switch]$LeaveTenantPlaceholder,
        [string]$EnvironmentUrlAs = "",
        [string]$PlaintextSecret = "",
        [switch]$KeepSecretPathBesidePlaintext,
        [switch]$SecretPathElsewhere,
        [string]$CertThumbprintCfg = "",
        [string]$SeedStateJson = ""
    )
    $root = Join-Path $SandboxRoot $Name
    foreach ($d in @("", "current", "logs", "secrets")) { New-Item -ItemType Directory -Force -Path (Join-Path $root $d) | Out-Null }

    $shipped = [IO.File]::ReadAllText($AgentScript)
    $needle  = '$BaseDir = "C:\AllBirdies\BayAgent"'
    if (-not $shipped.Contains($needle)) { throw "could not find the BaseDir literal in $AgentScript" }
    $agentCopy = Join-Path $root "current\BayAgent.ps1"
    [IO.File]::WriteAllText($agentCopy, $shipped.Replace($needle, ('$BaseDir = "{0}"' -f $root)), (New-Object Text.UTF8Encoding($false)))
    Copy-Item -LiteralPath $ManifestSrc -Destination (Join-Path $root "current\manifest.json") -Force

    $cfg = $Day0TemplateJson | ConvertFrom-Json
    # What the operator fills in (the values a run sheet names).
    # -EnvironmentUrlAs "template" keeps the template's own unfilled address; any other text is written as typed.
    if ($EnvironmentUrlAs -eq "template") { } elseif ($EnvironmentUrlAs) { $cfg.environmentUrl = $EnvironmentUrlAs } else { $cfg.environmentUrl = $MockUrl }
    if (-not $LeaveTenantPlaceholder) { $cfg.tenantId = $D0Tenant }
    # Left unfilled, bayId keeps the template's <placeholder> with this run's tag inside it: still not a GUID, and a
    # certificate wrongly made for it carries a subject that only this run can have made.
    if ($LeaveBayIdPlaceholder) { $cfg.bayId = $D0PlaceholderBayId } else { $cfg.bayId = $D0BayId }
    if ($CertThumbprintCfg) { $cfg.clientCertThumbprint = $CertThumbprintCfg }
    if ($Shape -eq "own") { $cfg.clientId = $D0OwnApp } elseif ($Shape -eq "shared") { $cfg.clientId = $D0Shared }
    # The template's secret file path, pointed into the sandbox (the file is NOT made). The "own" shape names none.
    $cfg.clientSecretDpapiPath = (Join-Path $root "secrets\clientsecret.dpapi")
    # -SecretPathElsewhere: the configuration names a sealed-secret path that is NOT the standard place.
    if ($SecretPathElsewhere) { New-Item -ItemType Directory -Force -Path (Join-Path $root "elsewhere") | Out-Null; $cfg.clientSecretDpapiPath = (Join-Path $root "elsewhere\bay-secret.dpapi") }
    if ($Shape -eq "own") { $cfg.PSObject.Properties.Remove("clientSecretDpapiPath") }
    # Machine-touching values made inert, as BayAgent.Launch.Tests.ps1 L7 does: no real launcher, no real wall.
    $cfg.sessionJsonPath = (Join-Path $root "session.json")
    $cfg.launcher.path = "C:\AbgNoSuchLauncher\NoSuch.exe"; $cfg.launcher.processName = "AbgNoSuchLauncher"
    $cfg.sessionDisplay.url = "about:blank"; $cfg.sessionDisplay.profileDir = "C:\AbgNoSuchProfile"
    # The test seam the agent documents: where the token endpoint is.
    $cfg | Add-Member -NotePropertyName tokenAuthorityHost -NotePropertyValue $MockUrl
    $cfg.logLevel = "DEBUG"
    if ($PlaintextSecret) {
        $cfg | Add-Member -NotePropertyName clientSecret -NotePropertyValue $PlaintextSecret
        # With -KeepSecretPathBesidePlaintext the configuration carries BOTH keys: the agent's start-up then loads only
        # the path, so the plaintext secret is in the file but is not what a sign-in would use.
        if (-not $KeepSecretPathBesidePlaintext -and $cfg.PSObject.Properties["clientSecretDpapiPath"]) { $cfg.PSObject.Properties.Remove("clientSecretDpapiPath") }
    }
    # With a byte-order mark, as Day0 writes it (Set-Content -Encoding UTF8 under Windows PowerShell 5.1).
    [IO.File]::WriteAllText((Join-Path $root "agent-config.json"), ($cfg | ConvertTo-Json -Depth 6), (New-Object Text.UTF8Encoding($true)))
    if ($SeedStateJson) {
        # NOT a blank bay: a state file something earlier left. Used only by the refusal scenarios that say so.
        New-Item -ItemType Directory -Force -Path (Join-Path $root "state") | Out-Null
        [IO.File]::WriteAllText((Join-Path $root "state\credential.json"), $SeedStateJson, (New-Object Text.UTF8Encoding($false)))
    }

    return [pscustomobject]@{ Root = $root; Agent = $agentCopy; Shape = $Shape
        State = (Join-Path $root "state\credential.json"); Config = (Join-Path $root "agent-config.json") }
}

function Invoke-D0Agent {
    <#
      Runs the bay's BayAgent.ps1 in a child powershell.exe 5.1 and returns exit code, console text and the log.
        -Sheet   the run-sheet shape:  -NoProfile -ExecutionPolicy Bypass -File "<agent>" <arguments>
        default  the AgentHost shape:  -NoProfile -WindowStyle Minimized -File "<agent>" <arguments>
      The AgentHost shape carries no policy switch (on a bay AllSigned applies and the file is signed); here the copy is
      unsigned, so the child is given PSExecutionPolicyPreference, which is what a parent started with Bypass passes on.
    #>
    param([Parameter(Mandatory = $true)]$Bay, [Parameter(Mandatory = $true)][string]$Arguments, [switch]$Sheet)
    $psExe = Join-Path $env:WINDIR "System32\WindowsPowerShell\v1.0\powershell.exe"
    $lead = $(if ($Sheet) { "-NoProfile -ExecutionPolicy Bypass" } else { "-NoProfile -WindowStyle Minimized" })
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = $psExe
    $psi.Arguments = ('{0} -File "{1}" {2}' -f $lead, $Bay.Agent, $Arguments)
    $psi.UseShellExecute = $false; $psi.RedirectStandardOutput = $true; $psi.RedirectStandardError = $true
    $psi.CreateNoWindow = $true; $psi.WorkingDirectory = $Bay.Root
    $psi.EnvironmentVariables["PSExecutionPolicyPreference"] = "Bypass"
    # A Windows PowerShell child of pwsh 7 must not inherit pwsh's module path.
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
    return [pscustomobject]@{ TimedOut = (-not $exited); ExitCode = $(if ($exited) { $proc.ExitCode } else { -1 }); StdOut = $so; StdErr = $se; Log = $newLog; Command = $psi.Arguments }
}

function Show-D0Run($r, [string]$label) {
    Write-Host ("        [{0}] exit={1} timedOut={2}" -f $label, $r.ExitCode, $r.TimedOut) -ForegroundColor DarkGray
    foreach ($ln in @(($r.StdOut + "`n" + $r.Log) -split "`r?`n" | Where-Object { $_ -match "RESULT:|REFUSED|ENROLLED|Sign-in|FATAL|Auth mode|\[IDENTITY\]|TokenOnly mode|Reason code" } | Select-Object -Unique -First 8)) {
        Write-Host ("            " + $ln.Trim()) -ForegroundColor DarkGray
    }
}

function Read-D0State($Bay) {
    if (-not (Test-Path -LiteralPath $Bay.State)) { return $null }
    return ([IO.File]::ReadAllText($Bay.State) | ConvertFrom-Json)
}
function Set-D0EnrolledAccount($Bay, [string]$Account) {
    # MODELS another Windows account: rewrites, in the bay's state file, which account the record says enrolled.
    $s = Read-D0State $Bay
    $s.ownIdentityEnrolled.account = $Account
    [IO.File]::WriteAllText($Bay.State, ($s | ConvertTo-Json -Depth 6), (New-Object Text.UTF8Encoding($false)))
}
function Get-D0Prop($obj, [string]$name) {
    if ($null -eq $obj) { return $null }
    $p = $obj.PSObject.Properties[$name]
    if ($null -eq $p) { return $null }
    return $p.Value
}
function Get-D0ReportField([string]$StdOut, [string]$Label) {
    $m = [regex]::Match($StdOut, ("(?m)^\s*" + [regex]::Escape($Label) + "\s*:\s*(.+?)\s*$"))
    if ($m.Success) { return $m.Groups[1].Value.Trim() }
    return $null
}
function Get-D0ResultLines([string]$StdOut) { return @($StdOut -split "`r?`n" | Where-Object { $_ -match "^RESULT:" }) }
function Get-D0FirstResult([string]$StdOut) {
    # The first RESULT line, or "" when the run printed none (never an index into nothing).
    $all = @(Get-D0ResultLines $StdOut)
    if ($all.Count -eq 0) { return "" }
    return [string]$all[0]
}
function Get-D0Capabilities([object[]]$Requests) {
    # The credential block of the LAST capabilities report the bay wrote to its own row, as the operator ladder reads it.
    $caps = $null
    foreach ($q in @($Requests | Where-Object { $_.kind -eq "dataverse" -and $_.requestLine -match '^PATCH /api/data/v9\.2/build_baies\(' })) {
        try {
            $b = $q.body | ConvertFrom-Json
            $j = Get-D0Prop $b "build_agentcapabilitiesjson"
            if ($j) { $caps = ([string]$j | ConvertFrom-Json) }
        } catch { }
    }
    return $caps
}

# ---------------------------------------------------------------- a secret file this account cannot look at (RF-1)
# The rights are the ones the product's OWN tool writes (src\BayAgent\bootstrap\ABG.SetClientSecretDpapi.ps1, lines 57 to
# 70, run with no -AgentAccount, which is its default): inheritance removed from the folder and the file, SYSTEM and
# Administrators granted, nobody else. The enrolling account (BayKiosk on a bay; this suite's account here) is in neither
# list, so a plain existence test of the file THROWS "Access is denied" under $ErrorActionPreference = "Stop". Nothing
# here mocks a throw. The tool runs elevated and does the folder first; this suite is not elevated, so it does the FILE
# first (a locked folder would stop it reaching the file). The rights each ends with are the same.
$script:D0Locked = New-Object System.Collections.ArrayList
function Invoke-D0Icacls([string[]]$IcaclsArgs) {
    & icacls.exe @IcaclsArgs | Out-Null
    if ($LASTEXITCODE -ne 0) { throw ("icacls {0} failed with exit code {1}" -f ($IcaclsArgs -join " "), $LASTEXITCODE) }
}
function Test-D0CannotLook([string]$Path) {
    # True when the existence test the agent uses THROWS for this path from this account (the shape RF-1 is about). It is
    # asked of the HOST THE BAY RUNS (a child Windows PowerShell 5.1 with $ErrorActionPreference = "Stop", as the agent
    # sets it), not of this suite's own host: pwsh 7 does not throw for a path with an illegal character, 5.1 does.
    $psExe = Join-Path $env:WINDIR "System32\WindowsPowerShell\v1.0\powershell.exe"
    $probeText = '$ErrorActionPreference = "Stop"; try { [void](Test-Path -LiteralPath ''' + $Path.Replace("'", "''") + ''' -PathType Leaf); "no-throw" } catch { "throws" }'
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = $psExe
    $psi.Arguments = "-NoProfile -NonInteractive -EncodedCommand " + [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($probeText))
    $psi.UseShellExecute = $false; $psi.RedirectStandardOutput = $true; $psi.RedirectStandardError = $true; $psi.CreateNoWindow = $true
    if ($psi.EnvironmentVariables.ContainsKey("PSModulePath")) { $psi.EnvironmentVariables.Remove("PSModulePath") }
    $proc = [System.Diagnostics.Process]::Start($psi)
    $soTask = $proc.StandardOutput.ReadToEndAsync(); $seTask = $proc.StandardError.ReadToEndAsync()
    if (-not $proc.WaitForExit(30000)) { try { $proc.Kill() } catch {}; throw "the existence probe for $Path did not finish" }
    $answer = ([string]$soTask.Result).Trim()
    if ($answer -ne "throws" -and $answer -ne "no-throw") { throw ("the existence probe for {0} answered neither 'throws' nor 'no-throw': '{1}' {2}" -f $Path, $answer, [string]$seTask.Result) }
    return ($answer -eq "throws")
}
function Lock-D0LikeTheSecretTool([string]$Dir, [string]$File) {
    # Returns a sentence saying which rights this account ended up with. Registers both for unlocking.
    [void]$script:D0Locked.Add($File); [void]$script:D0Locked.Add($Dir)
    Invoke-D0Icacls @($File, "/inheritance:r")
    Invoke-D0Icacls @($File, "/grant", "SYSTEM:F", "Administrators:F")
    Invoke-D0Icacls @($Dir, "/inheritance:r")
    Invoke-D0Icacls @($Dir, "/grant", "SYSTEM:(OI)(CI)F", "Administrators:(OI)(CI)F")
    $how = "the tool's rights only (SYSTEM and Administrators)"
    if (-not (Test-D0CannotLook $File)) {
        # An elevated run is in Administrators, so the tool's rights let it look. Deny this account the two rights an
        # existence check needs (read attributes on the file, list on the folder) so the same situation is modeled.
        $me = ("{0}\{1}" -f [Environment]::UserDomainName, [Environment]::UserName)
        Invoke-D0Icacls @($File, "/deny", ("{0}:(RA)" -f $me))
        Invoke-D0Icacls @($Dir, "/deny", ("{0}:(RD)" -f $me))
        $how = "the tool's rights plus an explicit deny for this account (this run is elevated)"
    }
    return $how
}
function Unlock-D0All {
    # The owner may always rewrite the rights: put inheritance back so the sandbox can be read and removed. FOLDERS FIRST:
    # icacls lists a path's parent before it acts, so once a folder is locked the file inside it cannot be reached until
    # the folder is reset (they are registered file then folder, so walk the list backward).
    $lockedNow = @($script:D0Locked.ToArray()); [array]::Reverse($lockedNow)
    foreach ($p in $lockedNow) {
        try { if (Test-Path -LiteralPath $p -ErrorAction SilentlyContinue) { & icacls.exe $p /reset | Out-Null } } catch { Write-Host ("could not put the rights back on " + $p) -ForegroundColor Yellow }
    }
    $script:D0Locked.Clear()
}

# THE ARGUMENTS UNDER TEST ARE THE ONES Setup-BayPC.ps1 PRINTS. They are read out of that script's text (Phase 6 and
# Next Steps), so the line a person is shown at the bay is the line every scenario below runs.
$SetupScriptText = [IO.File]::ReadAllText((Resolve-Path (Join-Path $PSScriptRoot "..\src\BayAgent\tools\Setup-BayPC.ps1")).Path)
$PrintedEnroll = @([regex]::Matches($SetupScriptText, '(powershell\.exe -NoProfile -ExecutionPolicy Bypass) -File `"\$Root\\BayAgent\\current\\BayAgent\.ps1`" (-EnrollCert[^"\r\n]*)"') | ForEach-Object { $_.Groups[1].Value + "|" + $_.Groups[2].Value } | Sort-Object -Unique)
$SheetEnroll = "-EnrollCert -EnrollClientId {0}"
if ($PrintedEnroll.Count -eq 1) { $SheetEnroll = ($PrintedEnroll[0] -split "\|", 2)[1].Replace('$EnrollAppId', '{0}') }

Write-Host "Agent under test : $AgentScript"
Write-Host "Sandbox          : $SandboxRoot"
Write-Host "Recorder         : $MockUrl (a MOCK of Entra's token endpoint and of Dataverse, not either)"
Write-Host "This run's bay   : $D0BayId   own app: $D0OwnApp"

$certsAtStart = @(Get-D0RunCerts)
# A script that lacks the "configuration not filled in" refusal (an older release, a mutant) makes a certificate whose
# subject carries the unfilled bayId instead of this run's bay id. That placeholder carries this run's tag, so these
# too are this run's and no other's (two runs side by side cannot remove each other's).
function Get-D0PlaceholderCerts {
    return @(Get-ChildItem -LiteralPath "Cert:\CurrentUser\My" -ErrorAction Stop |
        Where-Object { $_.Subject -eq $D0PlaceholderSubject } | ForEach-Object { $_.Thumbprint } | Sort-Object)
}
$placeholderCertsAtStart = @(Get-D0PlaceholderCerts)

try {
    # ============================================================ S0 the copy is the shipped file
    Section "S0 the script each bay runs differs from the shipped script in exactly one literal"
    $probe = New-D0Bay -Name "equivalence"
    $shippedLines = [IO.File]::ReadAllLines($AgentScript)
    $copyLines = [IO.File]::ReadAllLines($probe.Agent)
    Assert-True ($shippedLines.Count -eq $copyLines.Count) "line count identical ($($shippedLines.Count) vs $($copyLines.Count))"
    $diffIdx = @()
    for ($i = 0; $i -lt [Math]::Min($shippedLines.Count, $copyLines.Count); $i++) { if ($shippedLines[$i] -ne $copyLines[$i]) { $diffIdx += $i } }
    Assert-True ($diffIdx.Count -eq 1 -and $shippedLines[$diffIdx[0]].Trim().StartsWith('$BaseDir =')) "exactly one line differs, and it is the `$BaseDir assignment (differing lines: $($diffIdx.Count))"
    Assert-True ($certsAtStart.Count -eq 0) "precondition: no certificate with this run's subject exists"
    Assert-True ($PrintedEnroll.Count -eq 1 -and $PrintedEnroll[0] -eq 'powershell.exe -NoProfile -ExecutionPolicy Bypass|-EnrollCert -EnrollClientId $EnrollAppId') ("Setup-BayPC.ps1 prints ONE enroll line, in both places it prints it, and it is the line these scenarios run (found: " + ($PrintedEnroll -join " || ") + ")")
    Assert-True ($SheetEnroll -eq "-EnrollCert -EnrollClientId {0}") "...so the arguments under test are: -EnrollCert -EnrollClientId <the bay's own app id>"
    $cfgProbe = [IO.File]::ReadAllText($probe.Config) | ConvertFrom-Json
    Assert-True ([string]$cfgProbe.clientId -eq "<app-client-id>") "the modeled configuration is Day0's own template: clientId still holds its placeholder when the operator passed none"
    Assert-True (-not (Test-Path -LiteralPath (Join-Path $probe.Root "state"))) "precondition: a blank bay has no state folder, no credential.json"
    Assert-True (@(Get-ChildItem -LiteralPath (Join-Path $probe.Root "secrets") -ErrorAction SilentlyContinue).Count -eq 0) "precondition: no secret file exists on the modeled bay"

    # ============================================================ S1 the blank bay is dark, and says why
    Section "S1 before enrollment the bay does not start, tries no sign-in, and names the reason (A0.529: dark, not on a secret)"
    foreach ($shape in @("placeholder", "own", "shared")) {
        $b1 = New-D0Bay -Name ("dark-" + $shape) -Shape $shape
        $mark = Get-D0Mark
        $r = Invoke-D0Agent -Bay $b1 -Arguments "-Once"
        Show-D0Run $r ("S1-" + $shape)
        Assert-True (-not $r.TimedOut -and $r.ExitCode -eq 1) "[$shape] a bay with no credential exits 1 (got $($r.ExitCode))"
        Assert-True ($r.Log -match "FATAL" -and $r.Log -match "This bay has no credential|this bay has no credential") "[$shape] the log says the bay has no credential"
        Assert-True ($r.Log -match "-EnrollCert") "[$shape] ...and names enrollment as the way forward"
        Assert-True ($r.Log -notmatch "is not recognized as the name of a cmdlet") "[$shape] ...not a missing function"
        Assert-True (@(Get-D0RequestsSince $mark).Count -eq 0) "[$shape] nothing was sent anywhere: no sign-in was tried"
    }

    # ============================================================ S2 refusals on a blank bay change nothing
    Section "S2 every refusal on a blank bay is decided before a key is made: exit 2, RESULT: REFUSED, nothing changed"
    $b2 = New-D0Bay -Name "refusals"
    $typedMarker = "ZZ-typed-by-mistake-" + [guid]::NewGuid().ToString("N")
    $refusals = @(
        @{ label = "not a GUID";      arguments = ("-EnrollCert -EnrollClientId " + $typedMarker); reason = "ABG_OWNID_CLIENT_ID_NOT_A_GUID" },
        @{ label = "all-zero GUID";   arguments = "-EnrollCert -EnrollClientId 00000000-0000-0000-0000-000000000000"; reason = "ABG_OWNID_CLIENT_ID_NOT_A_GUID" },
        @{ label = "a short id";      arguments = "-EnrollCert -EnrollClientId 12345"; reason = "ABG_OWNID_CLIENT_ID_NOT_A_GUID" }
    )
    $allRefusalText = ""
    foreach ($case in $refusals) {
        $before = Get-D0InstallFingerprint $b2.Root; $mark = Get-D0Mark
        $r = Invoke-D0Agent -Bay $b2 -Arguments $case.arguments -Sheet
        $allRefusalText += ($r.StdOut + "`n" + $r.StdErr + "`n" + $r.Log + "`n")
        Show-D0Run $r ("S2 " + $case.label)
        Assert-True (-not $r.TimedOut -and $r.ExitCode -eq 2) "[$($case.label)] exit code 2 (got $($r.ExitCode))"
        $resLines = @(Get-D0ResultLines $r.StdOut)
        Assert-True ($resLines.Count -eq 1 -and $resLines[0] -eq "RESULT: REFUSED") "[$($case.label)] exactly one RESULT line, and it is REFUSED"
        Assert-True ((Get-D0ReportField $r.StdOut "Reason code") -eq $case.reason) "[$($case.label)] reason code $($case.reason) (got $(Get-D0ReportField $r.StdOut 'Reason code'))"
        Assert-True ($r.StdOut -match "Nothing was changed on this PC") "[$($case.label)] it says nothing was changed"
        Assert-True ((Get-D0InstallFingerprint $b2.Root) -eq $before) "[$($case.label)] ...and nothing was: no key, no state file, no .cer"
        Assert-True (@(Get-D0RequestsSince $mark).Count -eq 0) "[$($case.label)] nothing was sent anywhere"
    }
    # Every refusal's console text and log, not only the last one's: the value typed by mistake is in the FIRST case.
    Assert-True ($allRefusalText.Contains("ABG_OWNID_CLIENT_ID_NOT_A_GUID") -and -not $allRefusalText.Contains($typedMarker)) "a refused value is never echoed: nothing any of these refusals printed or logged carries what was typed"
    Assert-True ($allRefusalText -match "What was typed is 52 characters long") "...the refusal says how long the value was instead"
    $allS2Log = ""
    foreach ($f in @(Get-ChildItem -LiteralPath (Join-Path $b2.Root "logs") -Filter "*.log" -ErrorAction SilentlyContinue)) { $allS2Log += [IO.File]::ReadAllText($f.FullName) }
    Assert-True (-not $allS2Log.Contains($typedMarker)) "...and the bay's log never carries it either"

    # -EnrollClientId with its value missing: PowerShell refuses the command line itself. The script must not run.
    $before = Get-D0InstallFingerprint $b2.Root; $mark = Get-D0Mark
    $r = Invoke-D0Agent -Bay $b2 -Arguments "-EnrollCert -EnrollClientId" -Sheet
    Show-D0Run $r "S2 value missing"
    Assert-True (-not $r.TimedOut -and $r.ExitCode -ne 0) "[value missing] a non-zero exit (got $($r.ExitCode))"
    Assert-True (($r.StdOut + $r.StdErr) -notmatch "ENROLLED") "[value missing] nothing claims an enrollment"
    Assert-True ((Get-D0InstallFingerprint $b2.Root) -eq $before -and @(Get-D0RequestsSince $mark).Count -eq 0) "[value missing] nothing was changed and nothing was sent"

    # -EnrollClientId without -EnrollCert: it must not be ignored (the agent would start its normal loop).
    $before = Get-D0InstallFingerprint $b2.Root; $mark = Get-D0Mark
    $r = Invoke-D0Agent -Bay $b2 -Arguments ("-EnrollClientId " + $D0OwnApp) -Sheet
    Show-D0Run $r "S2 without -EnrollCert"
    Assert-True (-not $r.TimedOut -and $r.ExitCode -eq 1) "[without -EnrollCert] it stops with exit 1 instead of starting the agent (got $($r.ExitCode), timedOut=$($r.TimedOut))"
    Assert-True ($r.Log -match "-EnrollClientId is used only together with -EnrollCert") "[without -EnrollCert] ...and says why"
    Assert-True ((Get-D0InstallFingerprint $b2.Root) -eq $before -and @(Get-D0RequestsSince $mark).Count -eq 0) "[without -EnrollCert] nothing was changed and nothing was sent"

    # A configuration that still holds a placeholder for the bay is not a bay yet.
    $b2c = New-D0Bay -Name "refusal-config" -LeaveBayIdPlaceholder
    $before = Get-D0InstallFingerprint $b2c.Root
    $r = Invoke-D0Agent -Bay $b2c -Arguments ($SheetEnroll -f $D0OwnApp) -Sheet
    Show-D0Run $r "S2 placeholder bayId"
    Assert-True ($r.ExitCode -eq 2 -and (Get-D0ReportField $r.StdOut "Reason code") -eq "ABG_OWNID_CONFIG_NOT_FILLED_IN") "[bayId not filled in] refused with ABG_OWNID_CONFIG_NOT_FILLED_IN (exit $($r.ExitCode))"
    Assert-True ($r.StdOut -match "bayId") "[bayId not filled in] ...naming the field"
    Assert-True ((Get-D0InstallFingerprint $b2c.Root) -eq $before) "[bayId not filled in] nothing was changed"
    Assert-True (((Get-D0PlaceholderCerts) -join ",") -eq ($placeholderCertsAtStart -join ",")) "[bayId not filled in] no certificate was made for a placeholder"

    # The same refusal for the other two fields the enrollment needs (the attack's surviving changes: only bayId was pinned).
    foreach ($unfilledCase in @(
            @{ label = "tenantId not filled in"; field = "tenantId"; bay = (New-D0Bay -Name "refusal-tenant" -LeaveTenantPlaceholder) },
            @{ label = "environmentUrl still the template's"; field = "environmentUrl"; bay = (New-D0Bay -Name "refusal-org-template" -EnvironmentUrlAs "template") },
            @{ label = "environmentUrl not an address"; field = "environmentUrl"; bay = (New-D0Bay -Name "refusal-org-text" -EnvironmentUrlAs "example-club.crm.dynamics.com") })) {
        $before = Get-D0InstallFingerprint $unfilledCase.bay.Root; $mark = Get-D0Mark; $certsBeforeCase = @(Get-D0RunCerts).Count
        $r = Invoke-D0Agent -Bay $unfilledCase.bay -Arguments ($SheetEnroll -f $D0OwnApp) -Sheet
        Show-D0Run $r ("S2 " + $unfilledCase.label)
        Assert-True ($r.ExitCode -eq 2 -and (Get-D0ReportField $r.StdOut "Reason code") -eq "ABG_OWNID_CONFIG_NOT_FILLED_IN") "[$($unfilledCase.label)] refused with ABG_OWNID_CONFIG_NOT_FILLED_IN (exit $($r.ExitCode), $(Get-D0ReportField $r.StdOut 'Reason code'))"
        Assert-True ($r.StdOut -match ("does not hold this bay's values yet \(" + $unfilledCase.field + "\)")) "[$($unfilledCase.label)] ...naming exactly that field"
        Assert-True ((Get-D0InstallFingerprint $unfilledCase.bay.Root) -eq $before -and @(Get-D0RequestsSince $mark).Count -eq 0 -and @(Get-D0RunCerts).Count -eq $certsBeforeCase) "[$($unfilledCase.label)] nothing was changed, no key was made, nothing was sent"
    }

    # A0.529: a secret on the machine means this is not a new bay. Sealed file, then plaintext in the configuration.
    $b2s = New-D0Bay -Name "refusal-secret"
    $secretMarker = "not-a-real-secret-" + [guid]::NewGuid().ToString("N")
    $sealed = [System.Security.Cryptography.ProtectedData]::Protect([Text.Encoding]::UTF8.GetBytes($secretMarker), $null, [System.Security.Cryptography.DataProtectionScope]::LocalMachine)
    [IO.File]::WriteAllBytes((Join-Path $b2s.Root "secrets\clientsecret.dpapi"), $sealed)
    $before = Get-D0InstallFingerprint $b2s.Root; $mark = Get-D0Mark
    $r = Invoke-D0Agent -Bay $b2s -Arguments ($SheetEnroll -f $D0OwnApp) -Sheet
    Show-D0Run $r "S2 sealed secret present"
    Assert-True ($r.ExitCode -eq 2 -and (Get-D0ReportField $r.StdOut "Reason code") -eq "ABG_OWNID_SECRET_PRESENT") "[sealed secret present] refused with ABG_OWNID_SECRET_PRESENT (exit $($r.ExitCode))"
    Assert-True ((Get-D0InstallFingerprint $b2s.Root) -eq $before -and @(Get-D0RequestsSince $mark).Count -eq 0) "[sealed secret present] nothing was changed, nothing was sent (the secret was not used)"
    Assert-True (-not (($r.StdOut + $r.Log + $r.StdErr).Contains($secretMarker))) "[sealed secret present] the secret's text is not on the console or in the log"
    $b2p = New-D0Bay -Name "refusal-plaintext" -PlaintextSecret $secretMarker
    $before = Get-D0InstallFingerprint $b2p.Root; $mark = Get-D0Mark
    $r = Invoke-D0Agent -Bay $b2p -Arguments ($SheetEnroll -f $D0OwnApp) -Sheet
    Show-D0Run $r "S2 plaintext secret present"
    Assert-True ($r.ExitCode -eq 2 -and (Get-D0ReportField $r.StdOut "Reason code") -eq "ABG_OWNID_SECRET_PRESENT") "[plaintext secret present] refused with ABG_OWNID_SECRET_PRESENT (exit $($r.ExitCode))"
    Assert-True ((Get-D0InstallFingerprint $b2p.Root) -eq $before -and @(Get-D0RequestsSince $mark).Count -eq 0) "[plaintext secret present] nothing was changed, nothing was sent"
    Assert-True (-not (($r.StdOut + $r.Log + $r.StdErr).Contains($secretMarker))) "[plaintext secret present] the secret's text is not on the console or in the log"

    # An automated review raised the class "the gate reads one field, the action another". Here the gate must read
    # the PLACES a secret can be, not only what a sign-in would use now. Two secrets a sign-in would NOT use now:
    $b2x = New-D0Bay -Name "refusal-plaintext-shadowed" -PlaintextSecret $secretMarker -KeepSecretPathBesidePlaintext
    $before = Get-D0InstallFingerprint $b2x.Root; $mark = Get-D0Mark
    $r = Invoke-D0Agent -Bay $b2x -Arguments ($SheetEnroll -f $D0OwnApp) -Sheet
    Show-D0Run $r "S2 plaintext secret beside a secret-file path"
    Assert-True ($r.ExitCode -eq 2 -and (Get-D0ReportField $r.StdOut "Reason code") -eq "ABG_OWNID_SECRET_PRESENT") "[a clientSecret in the configuration beside a secret-file path, no file] refused with ABG_OWNID_SECRET_PRESENT (exit $($r.ExitCode), $(Get-D0ReportField $r.StdOut 'Reason code'))"
    Assert-True ((Get-D0InstallFingerprint $b2x.Root) -eq $before -and @(Get-D0RequestsSince $mark).Count -eq 0 -and -not (($r.StdOut + $r.Log + $r.StdErr).Contains($secretMarker))) "[...beside a secret-file path] nothing was changed, nothing was sent, the secret's text is nowhere"
    $b2y = New-D0Bay -Name "refusal-sealed-unnamed" -Shape "own"
    [IO.File]::WriteAllBytes((Join-Path $b2y.Root "secrets\clientsecret.dpapi"), $sealed)
    $before = Get-D0InstallFingerprint $b2y.Root; $mark = Get-D0Mark
    $r = Invoke-D0Agent -Bay $b2y -Arguments ($SheetEnroll -f $D0OwnApp) -Sheet
    Show-D0Run $r "S2 sealed secret file the configuration does not name"
    Assert-True ($r.ExitCode -eq 2 -and (Get-D0ReportField $r.StdOut "Reason code") -eq "ABG_OWNID_SECRET_PRESENT") "[a sealed secret file at the standard place, named by no configuration key] refused with ABG_OWNID_SECRET_PRESENT (exit $($r.ExitCode), $(Get-D0ReportField $r.StdOut 'Reason code'))"
    Assert-True ((Get-D0InstallFingerprint $b2y.Root) -eq $before -and @(Get-D0RequestsSince $mark).Count -eq 0) "[...named by no configuration key] nothing was changed, nothing was sent"

    # ...and the third place: a sealed file the configuration DOES name, somewhere other than the standard place.
    # (Planted change G13 survived until this was added: in every other scenario the named path is the standard one.)
    $b2z = New-D0Bay -Name "refusal-sealed-elsewhere" -SecretPathElsewhere
    [IO.File]::WriteAllBytes((Join-Path $b2z.Root "elsewhere\bay-secret.dpapi"), $sealed)
    $before = Get-D0InstallFingerprint $b2z.Root; $mark = Get-D0Mark
    $r = Invoke-D0Agent -Bay $b2z -Arguments ($SheetEnroll -f $D0OwnApp) -Sheet
    Show-D0Run $r "S2 sealed secret file at a path of the configuration's own choosing"
    Assert-True ($r.ExitCode -eq 2 -and (Get-D0ReportField $r.StdOut "Reason code") -eq "ABG_OWNID_SECRET_PRESENT" -and $r.StdOut -match "the sealed secret file the configuration names") "[a sealed secret file at a path only the configuration names] refused with ABG_OWNID_SECRET_PRESENT, naming it (exit $($r.ExitCode), $(Get-D0ReportField $r.StdOut 'Reason code'))"
    Assert-True ((Get-D0InstallFingerprint $b2z.Root) -eq $before -and @(Get-D0RequestsSince $mark).Count -eq 0) "[...at a path only the configuration names] nothing was changed, nothing was sent"

    # ...and the standard place when the configuration names ANOTHER path (a planted "read the standard place only when no
    # path is named" survived the re-check: the "unnamed" scenario above names no path at all, so it cannot tell).
    $b2w = New-D0Bay -Name "refusal-sealed-standard-other-path" -SecretPathElsewhere
    [IO.File]::WriteAllBytes((Join-Path $b2w.Root "secrets\clientsecret.dpapi"), $sealed)
    Assert-True ($b2w.Root -and -not (Test-Path -LiteralPath (Join-Path $b2w.Root "elsewhere\bay-secret.dpapi"))) "precondition: the path the configuration names holds no file; the sealed secret is only at the standard place"
    $before = Get-D0InstallFingerprint $b2w.Root; $mark = Get-D0Mark
    $r = Invoke-D0Agent -Bay $b2w -Arguments ($SheetEnroll -f $D0OwnApp) -Sheet
    Show-D0Run $r "S2 sealed secret at the standard place, the configuration names another path"
    Assert-True ($r.ExitCode -eq 2 -and (Get-D0ReportField $r.StdOut "Reason code") -eq "ABG_OWNID_SECRET_PRESENT" -and $r.StdOut.Contains("a sealed secret file at " + (Join-Path $b2w.Root "secrets\clientsecret.dpapi"))) "[the standard place, another path named] refused with ABG_OWNID_SECRET_PRESENT, naming the standard place (exit $($r.ExitCode), $(Get-D0ReportField $r.StdOut 'Reason code'))"
    Assert-True ((Get-D0InstallFingerprint $b2w.Root) -eq $before -and @(Get-D0RequestsSince $mark).Count -eq 0) "[the standard place, another path named] nothing was changed, nothing was sent"

    # -EnrollForce does not pass the secret guard (a planted "force passes it" survived the re-check: the scenarios above
    # never typed -EnrollForce). A secret on the PC means this is not a new bay, whatever the person typed.
    foreach ($fc in @(
            @{ label = "sealed file the configuration names"; bay = $b2s },
            @{ label = "plaintext clientSecret in the configuration"; bay = $b2p },
            @{ label = "plaintext clientSecret beside a secret-file path"; bay = $b2x },
            @{ label = "sealed file at the standard place, named by no key"; bay = $b2y },
            @{ label = "sealed file at a path only the configuration names"; bay = $b2z },
            @{ label = "sealed file at the standard place, another path named"; bay = $b2w })) {
        $before = Get-D0InstallFingerprint $fc.bay.Root; $mark = Get-D0Mark; $certsBeforeF = @(Get-D0RunCerts).Count
        $r = Invoke-D0Agent -Bay $fc.bay -Arguments (($SheetEnroll -f $D0OwnApp) + " -EnrollForce") -Sheet
        Show-D0Run $r ("S2 -EnrollForce, " + $fc.label)
        Assert-True ($r.ExitCode -eq 2 -and (Get-D0ReportField $r.StdOut "Reason code") -eq "ABG_OWNID_SECRET_PRESENT") "[$($fc.label), with -EnrollForce] refused with ABG_OWNID_SECRET_PRESENT: -EnrollForce does not pass the secret guard (exit $($r.ExitCode), $(Get-D0ReportField $r.StdOut 'Reason code'))"
        Assert-True ((Get-D0InstallFingerprint $fc.bay.Root) -eq $before -and @(Get-D0RequestsSince $mark).Count -eq 0 -and @(Get-D0RunCerts).Count -eq $certsBeforeF) "[$($fc.label), with -EnrollForce] nothing was changed, no key was made, nothing was sent"
    }

    # RF-1 (BayAgent 1.6.1 re-check): "could not look" is not "nothing there". A secret file this account has no rights to
    # look at is still a secret on the PC. The rights are the ones the product's own secret tool leaves by default.
    # (On bc2e6c67 each of these enrolled, printed ENROLLED, and the agent then could not start: a dark bay.)
    Section "S2b a secret file this account cannot LOOK AT is a refusal that names the place, not 'nothing there' (RF-1)"
    foreach ($uc in @(
            @{ kind = "standard-named";   label = "sealed file at the standard place, which the configuration names";   place = "the secret the configuration names" },
            @{ kind = "standard-unnamed"; label = "sealed file at the standard place, the configuration names no path";  place = "the standard place for the sealed secret" },
            @{ kind = "named-elsewhere";  label = "sealed file at another path the configuration names";                place = "the secret the configuration names" },
            @{ kind = "illegal-path";     label = "the configuration names a path with an illegal character";           place = "the secret the configuration names" })) {
        $ub = $null; $lockedFile = $null; $how = "none"
        if ($uc.kind -eq "standard-named")   { $ub = New-D0Bay -Name "unreadable-named" }
        if ($uc.kind -eq "standard-unnamed") { $ub = New-D0Bay -Name "unreadable-unnamed" -Shape "own" }
        if ($uc.kind -eq "named-elsewhere")  { $ub = New-D0Bay -Name "unreadable-elsewhere" -SecretPathElsewhere }
        if ($uc.kind -eq "illegal-path") {
            $ub = New-D0Bay -Name "unreadable-illegal"
            $illegalPath = (Join-Path $ub.Root "secrets") + "\a|b.dpapi"
            $cfgIll = [IO.File]::ReadAllText($ub.Config) | ConvertFrom-Json
            $cfgIll.clientSecretDpapiPath = $illegalPath
            [IO.File]::WriteAllText($ub.Config, ($cfgIll | ConvertTo-Json -Depth 6), (New-Object Text.UTF8Encoding($true)))
            Assert-True (Test-D0CannotLook $illegalPath) "[$($uc.label)] precondition: the existence test throws for that path"
        } else {
            $lockedFile = $(if ($uc.kind -eq "named-elsewhere") { Join-Path $ub.Root "elsewhere\bay-secret.dpapi" } else { Join-Path $ub.Root "secrets\clientsecret.dpapi" })
        }
        try {
            if ($lockedFile) {
                [IO.File]::WriteAllBytes($lockedFile, $sealed)
                $how = Lock-D0LikeTheSecretTool -Dir (Split-Path -Parent $lockedFile) -File $lockedFile
                Assert-True (Test-D0CannotLook $lockedFile) "[$($uc.label)] precondition: this account cannot look at the secret file; the existence test throws (rights: $how)"
            }
            foreach ($extra in @("", " -EnrollForce")) {
                $tag = $(if ($extra) { $uc.label + ", with -EnrollForce" } else { $uc.label })
                $before = Get-D0InstallFingerprint $ub.Root; $mark = Get-D0Mark; $certsBeforeU = @(Get-D0RunCerts).Count
                $r = Invoke-D0Agent -Bay $ub -Arguments (($SheetEnroll -f $D0OwnApp) + $extra) -Sheet
                Show-D0Run $r ("S2b " + $tag)
                Assert-True (-not $r.TimedOut -and $r.ExitCode -eq 2) "[$tag] exit code 2 (got $($r.ExitCode))"
                $resU = @(Get-D0ResultLines $r.StdOut)
                Assert-True ($resU.Count -eq 1 -and $resU[0] -eq "RESULT: REFUSED") "[$tag] exactly one RESULT line, and it is REFUSED (got: $($resU -join ' | '))"
                Assert-True ((Get-D0ReportField $r.StdOut "Reason code") -eq "ABG_OWNID_SECRET_UNREADABLE") "[$tag] reason code ABG_OWNID_SECRET_UNREADABLE (got $(Get-D0ReportField $r.StdOut 'Reason code'))"
                Assert-True ($r.StdOut.Contains($uc.place)) "[$tag] the refusal names the place that could not be looked at ('$($uc.place)')"
                Assert-True ($r.StdOut -match "nothing was made" -and $r.StdOut -match "Nothing was changed on this PC") "[$tag] it says nothing was made"
                Assert-True (@(Get-D0RunCerts).Count -eq $certsBeforeU) "[$tag] no key was made"
                Assert-True (-not (Test-Path -LiteralPath $ub.State)) "[$tag] no state\credential.json was written"
                Assert-True ((Get-D0InstallFingerprint $ub.Root) -eq $before -and @(Get-D0RequestsSince $mark).Count -eq 0) "[$tag] nothing was changed and nothing was sent"
                Assert-True (-not (($r.StdOut + $r.Log + $r.StdErr).Contains($secretMarker))) "[$tag] the secret's text is not on the console or in the log"
            }
        } finally { Unlock-D0All }
    }

    # The guard is asked once something is on record too (a planted "not asked of a bay that already holds an enrollment"
    # survived the re-check, because every scenario above runs on a blank bay). A bay enrolled and working, and then a
    # secret arrives in each of the three places: the same line must be refused, with and without -EnrollForce, and
    # change nothing. The control first: the same line on the same bay, before the secret, answers READY.
    Section "S2e a secret that ARRIVES after the enrollment is refused by the same line (the guard is asked of a bay with something on record)"
    foreach ($lc in @(
            @{ kind = "named";          label = "sealed file at the path the configuration names (the standard place)" },
            @{ kind = "standard-other"; label = "sealed file at the standard place, the configuration names another path" },
            @{ kind = "plaintext";      label = "a clientSecret key added beside the secret-file path" })) {
        $lb = New-D0Bay -Name ("late-" + $lc.kind) -Shape "placeholder" -SecretPathElsewhere:($lc.kind -eq "standard-other")
        $r = Invoke-D0Agent -Bay $lb -Arguments ($SheetEnroll -f $D0OwnApp) -Sheet
        $tpLate = Get-D0ReportField $r.StdOut "Thumbprint"
        Assert-True ($r.ExitCode -eq 0 -and (Get-D0FirstResult $r.StdOut) -like "RESULT: ENROLLED*") "[$($lc.label)] the bay is enrolled first (exit $($r.ExitCode), $(Get-D0FirstResult $r.StdOut))"
        if ($tpLate -notmatch '^[0-9A-F]{40}$') { Assert-True $false "[$($lc.label)] no enrollment happened, so the late secret could not be tested"; continue }
        Register-D0Certificate -AppId $D0OwnApp -CerPath (Join-Path $lb.Root ("state\bay-cert-{0}.cer" -f $tpLate))
        $r = Invoke-D0Agent -Bay $lb -Arguments ($SheetEnroll -f $D0OwnApp) -Sheet
        Assert-True ($r.ExitCode -eq 0 -and (Get-D0FirstResult $r.StdOut) -like "RESULT: READY*") "[$($lc.label)] control: before the secret arrives, the same line answers READY (exit $($r.ExitCode), $(Get-D0FirstResult $r.StdOut))"
        if ($lc.kind -eq "plaintext") {
            $cfgLate = [IO.File]::ReadAllText($lb.Config) | ConvertFrom-Json
            $cfgLate | Add-Member -NotePropertyName clientSecret -NotePropertyValue $secretMarker
            [IO.File]::WriteAllText($lb.Config, ($cfgLate | ConvertTo-Json -Depth 6), (New-Object Text.UTF8Encoding($true)))
        } else {
            [IO.File]::WriteAllBytes((Join-Path $lb.Root "secrets\clientsecret.dpapi"), $sealed)
        }
        foreach ($extra in @("", " -EnrollForce")) {
            $tag = $(if ($extra) { $lc.label + ", with -EnrollForce" } else { $lc.label })
            $before = Get-D0InstallFingerprint $lb.Root; $mark = Get-D0Mark
            $r = Invoke-D0Agent -Bay $lb -Arguments (($SheetEnroll -f $D0OwnApp) + $extra) -Sheet
            Show-D0Run $r ("S2e " + $tag)
            Assert-True ($r.ExitCode -eq 2 -and (Get-D0ReportField $r.StdOut "Reason code") -eq "ABG_OWNID_SECRET_PRESENT") "[$tag] refused with ABG_OWNID_SECRET_PRESENT (exit $($r.ExitCode), $(Get-D0ReportField $r.StdOut 'Reason code'))"
            Assert-True ((Get-D0InstallFingerprint $lb.Root) -eq $before -and @(Get-D0RequestsSince $mark).Count -eq 0) "[$tag] nothing was changed and nothing was sent (not even a sign-in check)"
            Assert-True (-not (($r.StdOut + $r.Log + $r.StdErr).Contains($secretMarker))) "[$tag] the secret's text is not on the console or in the log"
        }
    }

    # A PC that already holds something is not a new bay: each of these is refused, with or without -EnrollForce, and
    # the state file is left byte for byte as it was.
    $notBlank = @(
        @{ label = "state file corrupt";            reason = "ABG_OWNID_STATE_CORRUPT";          state = '{ "activeThumbprint": "A1B2' ; thumbCfg = "" },
        @{ label = "state value unreadable";        reason = "ABG_OWNID_STATE_NOT_UNDERSTOOD";   state = '{ "activeThumbprint": "not-a-thumbprint" }'; thumbCfg = "" },
        @{ label = "a rotation is waiting";         reason = "ABG_OWNID_ROTATION_IN_PROGRESS";   state = ('{ "pendingThumbprint": "' + $D0FakeThumb + '" }'); thumbCfg = "" },
        @{ label = "an identity switch on probation"; reason = "ABG_OWNID_SWITCH_IN_PROGRESS";   state = ('{ "activeThumbprint": "' + $D0FakeThumb + '", "activeClientId": "' + $D0OtherApp + '", "identityProbation": { "clientId": "' + $D0OtherApp + '", "sinceUtc": "2026-10-11T00:00:00Z", "previousThumbprint": null, "previousClientId": null } }'); thumbCfg = "" },
        @{ label = "a certificate named in the configuration"; reason = "ABG_OWNID_CONFIGURED_CERTIFICATE"; state = ""; thumbCfg = $D0FakeThumb }
    )
    $nbIndex = 0
    foreach ($case in $notBlank) {
        $nbIndex++
        $bn = New-D0Bay -Name ("not-blank-" + $nbIndex) -SeedStateJson $case.state -CertThumbprintCfg $case.thumbCfg
        foreach ($extra in @("", " -EnrollForce")) {
            $before = Get-D0InstallFingerprint $bn.Root; $mark = Get-D0Mark
            $r = Invoke-D0Agent -Bay $bn -Arguments (($SheetEnroll -f $D0OwnApp) + $extra) -Sheet
            if (-not $extra) { Show-D0Run $r ("S2 " + $case.label) }
            $tag = $(if ($extra) { $case.label + ", with -EnrollForce" } else { $case.label })
            Assert-True ($r.ExitCode -eq 2 -and (Get-D0ReportField $r.StdOut "Reason code") -eq $case.reason) "[$tag] refused with $($case.reason) (exit $($r.ExitCode), $(Get-D0ReportField $r.StdOut 'Reason code'))"
            Assert-True ((Get-D0InstallFingerprint $bn.Root) -eq $before -and @(Get-D0RequestsSince $mark).Count -eq 0) "[$tag] nothing was changed and nothing was sent"
        }
    }

    # ============================================================ S3..S8 the whole first day, in each configuration shape
    foreach ($shape in @("placeholder", "own", "shared")) {
        Section "S3 [$shape] first run on the blank bay: enrolled on its own app, one write, no sign-in tried"
        $bay = New-D0Bay -Name ("day0-" + $shape) -Shape $shape
        $certsBefore = @(Get-D0RunCerts); $mark = Get-D0Mark
        # The id is typed in UPPER CASE on the placeholder shape and in braces on the shared shape: what reaches the
        # state file must be the same canonical id either way.
        $typed = $(if ($shape -eq "placeholder") { $D0OwnApp.ToUpperInvariant() } elseif ($shape -eq "shared") { "{" + $D0OwnApp + "}" } else { $D0OwnApp })
        $r = Invoke-D0Agent -Bay $bay -Arguments ($SheetEnroll -f $typed) -Sheet
        Show-D0Run $r ("S3-" + $shape)
        Assert-True (-not $r.TimedOut -and $r.ExitCode -eq 0) "[$shape] exit code 0 (got $($r.ExitCode))"
        $resLines = @(Get-D0ResultLines $r.StdOut)
        Assert-True ($resLines.Count -eq 1 -and $resLines[0] -like "RESULT: ENROLLED*") "[$shape] exactly one RESULT line: ENROLLED (got: $($resLines -join ' | '))"
        Assert-True ($r.StdOut -match ("ENROLLED: bay " + [regex]::Escape($D0BayId) + " now has its own identity")) "[$shape] the headline names this bay"
        $tp = Get-D0ReportField $r.StdOut "Thumbprint"
        Assert-True ($tp -match '^[0-9A-F]{40}$') "[$shape] a thumbprint is printed ($tp)"
        if ($tp -notmatch '^[0-9A-F]{40}$') { Assert-True $false "[$shape] no enrollment happened, so the rest of this bay's first day (S4 to S9) could not run"; continue }
        Assert-True ((Get-D0ReportField $r.StdOut "Signs in as") -like ($D0OwnApp + "*")) "[$shape] 'Signs in as' is the bay's own app, in canonical form"
        Assert-True ((Get-D0ReportField $r.StdOut "Account") -like ("{0}\{1}*" -f [Environment]::UserDomainName, [Environment]::UserName)) "[$shape] the Windows account that holds the key is printed"
        $st = Read-D0State $bay
        Assert-True ($null -ne $st) "[$shape] state\credential.json exists"
        Assert-True ([string](Get-D0Prop $st "activeThumbprint") -eq $tp) "[$shape] ...its active certificate is the printed one"
        Assert-True ([string](Get-D0Prop $st "activeClientId") -eq $D0OwnApp) "[$shape] ...its active app is the bay's own app (got '$(Get-D0Prop $st 'activeClientId')')"
        $rec = Get-D0Prop $st "ownIdentityEnrolled"
        Assert-True ($null -ne $rec -and [string](Get-D0Prop $rec "clientId") -eq $D0OwnApp -and [string](Get-D0Prop $rec "thumbprint") -eq $tp) "[$shape] ...and it records that this app is the bay's own, with the same certificate"
        Assert-True ($null -eq (Get-D0Prop $st "pendingThumbprint") -and $null -eq (Get-D0Prop $st "identityProbation")) "[$shape] nothing is pending and no probation is open (there is nothing to go back to)"
        $stateGuids = @([regex]::Matches([IO.File]::ReadAllText($bay.State), '[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}') | ForEach-Object { $_.Value.ToLowerInvariant() } | Sort-Object -Unique)
        Assert-True ($stateGuids.Count -eq 1 -and $stateGuids[0] -eq $D0OwnApp) "[$shape] the ONLY id written into the state file is the one typed (found: $($stateGuids -join ', '))"
        $certsAfter = @(Get-D0RunCerts)
        Assert-True ($certsAfter.Count -eq ($certsBefore.Count + 1) -and ($certsAfter -contains $tp)) "[$shape] exactly one certificate was made, the printed one"
        $c = Get-Item -LiteralPath ("Cert:\CurrentUser\My\" + $tp)
        $exportPolicy = "?"
        try { $exportPolicy = [string]([System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($c)).Key.ExportPolicy } catch { $exportPolicy = "unreadable: " + $_.Exception.Message }
        Assert-True ($c.HasPrivateKey -and $exportPolicy -eq "None") "[$shape] its private key is in the store and cannot be exported (export policy: $exportPolicy)"
        $cerPath = Get-D0ReportField $r.StdOut "Public cert"
        Assert-True ($cerPath -eq (Join-Path $bay.Root ("state\bay-cert-{0}.cer" -f $tp)) -and (Test-Path -LiteralPath $cerPath)) "[$shape] the public certificate file is where the report says"
        $cerBytes = [IO.File]::ReadAllBytes($cerPath)
        $cerObj = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2 -ArgumentList (, $cerBytes)
        Assert-True ($cerObj.Thumbprint -eq $tp -and -not $cerObj.HasPrivateKey) "[$shape] ...it is the same certificate, public half only"
        Assert-True ($r.StdOut.Contains([Convert]::ToBase64String($cerBytes))) "[$shape] ...and the base64 printed on the console is that file"
        Assert-True (@(Get-D0RequestsSince $mark).Count -eq 0) "[$shape] the first run sent nothing anywhere"
        $madeFiles = @(Get-D0InstallFiles $bay.Root | Where-Object { $_ -notlike "logs\*" -and $_ -notin @("agent-config.json", "current\BayAgent.ps1", "current\manifest.json") })
        Assert-True ((($madeFiles | Sort-Object) -join ",") -eq ((@("state\credential.json", ("state\bay-cert-{0}.cer" -f $tp)) | Sort-Object) -join ",")) "[$shape] the run wrote exactly two files besides its log: the state file and the public certificate (found: $($madeFiles -join ', '))"
        Assert-True (@(Get-ChildItem -LiteralPath (Join-Path $bay.Root "secrets")).Count -eq 0) "[$shape] no secret file was made"
        $cfgAfter = [IO.File]::ReadAllText($bay.Config) | ConvertFrom-Json
        Assert-True ([string]$cfgAfter.clientId -eq $(if ($shape -eq "placeholder") { "<app-client-id>" } elseif ($shape -eq "own") { $D0OwnApp } else { $D0Shared })) "[$shape] agent-config.json was not rewritten"

        Section "S4 [$shape] the same command again BEFORE the certificate is registered: nothing changed, NOT READY, exit 4"
        $before = Get-D0InstallFingerprint $bay.Root; $mark = Get-D0Mark
        $r = Invoke-D0Agent -Bay $bay -Arguments ($SheetEnroll -f $D0OwnApp) -Sheet
        Show-D0Run $r ("S4-" + $shape)
        Assert-True (-not $r.TimedOut -and $r.ExitCode -eq 4) "[$shape] exit code 4 (got $($r.ExitCode))"
        Assert-True ($r.StdOut -match "ALREADY ENROLLED: nothing was changed") "[$shape] it says it is already enrolled"
        Assert-True ((Get-D0ReportField $r.StdOut "Sign-in") -eq "REFUSED (AADSTS700027)") "[$shape] Sign-in: REFUSED (AADSTS700027) (got '$(Get-D0ReportField $r.StdOut 'Sign-in')')"
        Assert-True ($r.StdOut -match "Register the public certificate on the bay's app") "[$shape] ...with what to do about it"
        $resLines = @(Get-D0ResultLines $r.StdOut)
        Assert-True ($resLines.Count -eq 1 -and $resLines[0] -like "RESULT: NOT READY*") "[$shape] RESULT: NOT READY"
        Assert-True ((Get-D0ReportField $r.StdOut "Thumbprint") -eq $tp) "[$shape] the SAME certificate is printed again"
        Assert-True ((Get-D0InstallFingerprint $bay.Root) -eq $before) "[$shape] nothing on the PC changed: same state file bytes, same single certificate"
        $tok = @(Get-D0RequestsSince $mark)
        Assert-True ($tok.Count -eq 1 -and $tok[0].kind -eq "token" -and $tok[0].clientId -eq $D0OwnApp -and $tok[0].outcome -eq "key-not-registered" -and -not $tok[0].hasSecret) "[$shape] exactly one sign-in was tried, as the bay's own app, with a certificate and no secret"

        Section "S5 [$shape] the operator registers the public .cer; the same command again: READY, exit 0"
        Register-D0Certificate -AppId $D0OwnApp -CerPath $cerPath
        $before = Get-D0InstallFingerprint $bay.Root; $mark = Get-D0Mark
        $r = Invoke-D0Agent -Bay $bay -Arguments ($SheetEnroll -f $D0OwnApp) -Sheet
        Show-D0Run $r ("S5-" + $shape)
        Assert-True (-not $r.TimedOut -and $r.ExitCode -eq 0) "[$shape] exit code 0 (got $($r.ExitCode))"
        Assert-True ((Get-D0ReportField $r.StdOut "Sign-in") -eq "WORKS") "[$shape] Sign-in: WORKS (got '$(Get-D0ReportField $r.StdOut 'Sign-in')')"
        $resLines = @(Get-D0ResultLines $r.StdOut)
        Assert-True ($resLines.Count -eq 1 -and $resLines[0] -like "RESULT: READY*") "[$shape] RESULT: READY"
        Assert-True ((Get-D0InstallFingerprint $bay.Root) -eq $before) "[$shape] nothing on the PC changed"
        $tok = @(Get-D0RequestsSince $mark)
        Assert-True ($tok.Count -eq 1 -and $tok[0].outcome -eq "issued" -and $tok[0].clientId -eq $D0OwnApp) "[$shape] the recorder verified the assertion's signature against the registered .cer and issued a token to the bay's own app"

        Section "S6 [$shape] and a third time: the same answer, still nothing changed"
        $r = Invoke-D0Agent -Bay $bay -Arguments ($SheetEnroll -f $D0OwnApp) -Sheet
        Assert-True ($r.ExitCode -eq 0 -and (Get-D0FirstResult $r.StdOut) -like "RESULT: READY*") "[$shape] READY again, exit 0"
        Assert-True ((Get-D0InstallFingerprint $bay.Root) -eq $before) "[$shape] nothing on the PC changed"

        Section "S7 [$shape] the bay starts as the agent host starts it, and runs on its own identity"
        $mark = Get-D0Mark
        $r = Invoke-D0Agent -Bay $bay -Arguments "-Once"
        Show-D0Run $r ("S7-" + $shape)
        Assert-True (-not $r.TimedOut -and $r.ExitCode -eq 0) "[$shape] the agent started and finished one pass, exit 0 (got $($r.ExitCode))"
        Assert-True ($r.Log -notmatch "FATAL" -and $r.Log -notmatch "is not recognized as the name of a cmdlet") "[$shape] no FATAL, nothing used before it was defined"
        Assert-True ($r.Log -match ("Auth mode: CERTIFICATE thumbprint=" + $tp) -and $r.Log -match "fallbackSecret=none") "[$shape] Auth mode: CERTIFICATE with this certificate, and no secret to fall back to"
        Assert-True ($r.Log -match ("\[IDENTITY\] signing in as this bay's own app " + [regex]::Escape($D0OwnApp))) "[$shape] the log names the bay's own app"
        $reqs = @(Get-D0RequestsSince $mark)
        $tokens = @($reqs | Where-Object { $_.kind -eq "token" })
        $dv = @($reqs | Where-Object { $_.kind -eq "dataverse" })
        Assert-True ($tokens.Count -ge 1 -and @($tokens | Where-Object { $_.clientId -ne $D0OwnApp }).Count -eq 0) "[$shape] every sign-in was as the bay's own app ($($tokens.Count) of them)"
        Assert-True (@($tokens | Where-Object { $_.hasSecret }).Count -eq 0) "[$shape] no sign-in carried a client secret"
        Assert-True ($dv.Count -ge 3 -and @($dv | Where-Object { $_.outcome -ne "ok" -or $_.clientId -ne $D0OwnApp }).Count -eq 0) "[$shape] every Dataverse call carried a token issued to the bay's own app ($($dv.Count) calls)"
        Assert-True (@($dv | Where-Object { $_.requestLine -match '^GET /api/data/v9\.2/WhoAmI' }).Count -ge 1) "[$shape] WhoAmI was asked"
        Assert-True (@($dv | Where-Object { $_.requestLine -match ('^PATCH /api/data/v9\.2/build_baies\(' + [regex]::Escape($D0BayId) + '\)') }).Count -ge 1) "[$shape] the bay wrote its own row (the heartbeat)"
        $caps = Get-D0Capabilities $reqs
        $cred = Get-D0Prop $caps "credential"
        Assert-True ($null -ne $cred) "[$shape] the capabilities report carries a credential block"
        # The four things the operator ladder's activate reads from the bay's own report (BayIdentityLadder.JudgeBayProof).
        Assert-True ([string](Get-D0Prop $cred "activeClientId") -eq $D0OwnApp) "[$shape] report: activeClientId is the bay's own app"
        Assert-True ([string](Get-D0Prop $cred "activeThumbprint") -eq $tp) "[$shape] report: activeThumbprint is the enrolled certificate"
        Assert-True ([string](Get-D0Prop $cred "lastMintMode") -eq "certificate") "[$shape] report: lastMintMode is certificate"
        Assert-True (-not [string]::IsNullOrWhiteSpace([string](Get-D0Prop $caps "lastUpdatedUtc"))) "[$shape] report: lastUpdatedUtc is present"
        $ident = Get-D0Prop $cred "identity"
        Assert-True ((Get-D0Prop $ident "ownIdentity") -eq $true) "[$shape] report: identity.ownIdentity is TRUE (what the wall pass waits on)"
        Assert-True ([string](Get-D0Prop $cred "secretConfigured") -eq "none" -and (Get-D0Prop $cred "plaintextSecretPresent") -eq $false) "[$shape] report: no secret is configured on this bay"
        Assert-True ([string]::IsNullOrEmpty([string](Get-D0Prop $ident "probationSinceUtc"))) "[$shape] report: no probation"

        Section "S8 [$shape] a second start, and the sign-in test a person can run"
        $mark = Get-D0Mark
        $r = Invoke-D0Agent -Bay $bay -Arguments "-Once"
        $reqs = @(Get-D0RequestsSince $mark)
        Assert-True ($r.ExitCode -eq 0 -and $r.Log -notmatch "FATAL" -and @($reqs | Where-Object { $_.kind -eq "token" -and ($_.clientId -ne $D0OwnApp -or $_.hasSecret) }).Count -eq 0) "[$shape] the second start is the same: own app, no secret, exit 0"
        $r = Invoke-D0Agent -Bay $bay -Arguments "-TokenOnly -Once" -Sheet
        Assert-True ($r.ExitCode -eq 0 -and $r.Log -match "TokenOnly mode: token acquired via certificate") "[$shape] -TokenOnly -Once: 'token acquired via certificate'"
        Assert-True (@(Get-D0RunCerts | Where-Object { $_ -eq $tp }).Count -eq 1) "[$shape] the bay still holds exactly its one certificate"

        Section "S9 [$shape] an identity that works is never replaced from the console, even with -EnrollForce"
        $before = Get-D0InstallFingerprint $bay.Root
        foreach ($attempt in @(@{ id = $D0OtherApp; label = "another app" }, @{ id = $D0OwnApp; label = "the same app" })) {
            $r = Invoke-D0Agent -Bay $bay -Arguments (($SheetEnroll -f $attempt.id) + " -EnrollForce") -Sheet
            Assert-True ($r.ExitCode -eq 2 -and (Get-D0ReportField $r.StdOut "Reason code") -eq "ABG_OWNID_IDENTITY_WORKS") "[$shape] -EnrollForce for $($attempt.label): refused, ABG_OWNID_IDENTITY_WORKS (exit $($r.ExitCode), $(Get-D0ReportField $r.StdOut 'Reason code'))"
            Assert-True ((Get-D0InstallFingerprint $bay.Root) -eq $before) "[$shape] ...and nothing was changed"
        }
        $r = Invoke-D0Agent -Bay $bay -Arguments ($SheetEnroll -f $D0OtherApp) -Sheet
        Assert-True ($r.ExitCode -eq 2 -and (Get-D0ReportField $r.StdOut "Reason code") -eq "ABG_OWNID_ALREADY_ENROLLED" -and (Get-D0InstallFingerprint $bay.Root) -eq $before) "[$shape] another app without -EnrollForce: refused, ABG_OWNID_ALREADY_ENROLLED, nothing changed"
    }

    # ============================================================ S10 a mistyped app id is found, and corrected
    Section "S10 a mistyped app id: found by the second run, corrected with -EnrollForce, the wrong key removed"
    $bw = New-D0Bay -Name "wrong-id"
    $r = Invoke-D0Agent -Bay $bw -Arguments ($SheetEnroll -f $D0WrongApp) -Sheet
    $tp1 = Get-D0ReportField $r.StdOut "Thumbprint"
    Assert-True ($r.ExitCode -eq 0 -and $tp1 -match '^[0-9A-F]{40}$') "the first run enrolls on the id that was typed (it cannot know it is wrong)"
    $r = Invoke-D0Agent -Bay $bw -Arguments ($SheetEnroll -f $D0WrongApp) -Sheet
    Show-D0Run $r "S10 second run, wrong id"
    Assert-True ($r.ExitCode -eq 4 -and (Get-D0ReportField $r.StdOut "Sign-in") -eq "REFUSED (AADSTS700016)") "the second run says Entra knows no such app: REFUSED (AADSTS700016), exit 4"
    Assert-True ($r.StdOut -match "Check the id typed after -EnrollClientId") "...and says to check the id"
    $mark = Get-D0Mark
    $rs = Invoke-D0Agent -Bay $bw -Arguments "-Once"
    Assert-True ($rs.ExitCode -eq 0 -and $rs.Log -match "AADSTS700016" -and @(Get-D0RequestsSince $mark | Where-Object { $_.kind -eq "dataverse" }).Count -eq 0) "started anyway, the bay reaches nothing: the sign-in is refused and no Dataverse call is made (dark)"
    Assert-True (@(Get-D0RequestsSince $mark | Where-Object { $_.hasSecret }).Count -eq 0) "...and it tried no secret"
    $before = Get-D0InstallFingerprint $bw.Root
    $r = Invoke-D0Agent -Bay $bw -Arguments ($SheetEnroll -f $D0OwnApp) -Sheet
    Assert-True ($r.ExitCode -eq 2 -and (Get-D0ReportField $r.StdOut "Reason code") -eq "ABG_OWNID_ALREADY_ENROLLED") "the right id without -EnrollForce is refused: ABG_OWNID_ALREADY_ENROLLED"
    Assert-True ($r.StdOut -match "-EnrollForce" -and $r.StdOut.Contains($tp1)) "...and the refusal names the certificate on record and -EnrollForce"
    Assert-True ((Get-D0InstallFingerprint $bw.Root) -eq $before) "...nothing was changed"
    # -EnrollForce discards only on Entra's own word that the enrollment cannot work as it is. Not on silence (503, a
    # dropped connection), not on a 4xx that is not Entra's (a proxy), not on a refusal that says nothing about the
    # enrollment (a wrong clock, AADSTS700024).
    foreach ($mode in @("503", "drop", "proxy403", "clock")) {
        $sync["TokenMode"] = $mode
        $r = Invoke-D0Agent -Bay $bw -Arguments (($SheetEnroll -f $D0OwnApp) + " -EnrollForce") -Sheet
        $sync["TokenMode"] = "entra"
        Show-D0Run $r ("S10 force, token endpoint answers: " + $mode)
        Assert-True ($r.ExitCode -eq 2 -and (Get-D0ReportField $r.StdOut "Reason code") -eq "ABG_OWNID_CANNOT_TELL") "when the answer is '$mode', -EnrollForce is refused: ABG_OWNID_CANNOT_TELL (exit $($r.ExitCode), $(Get-D0ReportField $r.StdOut 'Reason code'))"
        Assert-True ((Get-D0InstallFingerprint $bw.Root) -eq $before) "...nothing was changed"
    }
    $sync["TokenMode"] = "proxy403"
    $r = Invoke-D0Agent -Bay $bw -Arguments ($SheetEnroll -f $D0WrongApp) -Sheet
    $sync["TokenMode"] = "clock"
    $r2 = Invoke-D0Agent -Bay $bw -Arguments ($SheetEnroll -f $D0WrongApp) -Sheet
    $sync["TokenMode"] = "entra"
    Assert-True ($r.ExitCode -eq 4 -and (Get-D0ReportField $r.StdOut "Sign-in") -eq "UNKNOWN") "the second run reads a 403 that is not Entra's as UNKNOWN, not as a refusal (got '$(Get-D0ReportField $r.StdOut 'Sign-in')', exit $($r.ExitCode))"
    Assert-True ($r2.ExitCode -eq 4 -and (Get-D0ReportField $r2.StdOut "Sign-in") -eq "REFUSED (AADSTS700024)") "...and Entra's clock refusal as REFUSED (AADSTS700024) (got '$(Get-D0ReportField $r2.StdOut 'Sign-in')', exit $($r2.ExitCode))"
    Assert-True ((Get-D0InstallFingerprint $bw.Root) -eq $before) "...nothing was changed by either"
    $r = Invoke-D0Agent -Bay $bw -Arguments (($SheetEnroll -f $D0OwnApp) + " -EnrollForce") -Sheet
    Show-D0Run $r "S10 force, Entra answering"
    $tp2 = Get-D0ReportField $r.StdOut "Thumbprint"
    Assert-True ($r.ExitCode -eq 0 -and $r.StdOut -match "ENROLLED AGAIN: the earlier enrollment was discarded") "with Entra refusing the old enrollment, -EnrollForce enrolls again, exit 0"
    Assert-True ($tp2 -match '^[0-9A-F]{40}$' -and $tp2 -ne $tp1) "a NEW key was made ($tp2), not the old one offered to a second app"
    Assert-True ((Get-D0ReportField $r.StdOut "Discarded") -like ("certificate {0} (AADSTS700016); removed from this PC with its key*" -f $tp1)) "the report names what was discarded and why"
    Assert-True (-not (Test-Path -LiteralPath ("Cert:\CurrentUser\My\" + $tp1))) "the discarded certificate and its key are gone from the store"
    Assert-True (-not (Test-Path -LiteralPath (Join-Path $bw.Root ("state\bay-cert-{0}.cer" -f $tp1)))) "its public .cer is gone too, so it cannot be registered by mistake"
    $st = Read-D0State $bw
    Assert-True ([string](Get-D0Prop $st "activeThumbprint") -eq $tp2 -and [string](Get-D0Prop $st "activeClientId") -eq $D0OwnApp) "the state names the new certificate and the right app"
    Assert-True (@(Get-D0Prop $st "retiredThumbprints") -contains $tp1) "the discarded certificate is on record as retired"
    Register-D0Certificate -AppId $D0OwnApp -CerPath (Join-Path $bw.Root ("state\bay-cert-{0}.cer" -f $tp2))
    $r = Invoke-D0Agent -Bay $bw -Arguments ($SheetEnroll -f $D0OwnApp) -Sheet
    Assert-True ($r.ExitCode -eq 0 -and (Get-D0FirstResult $r.StdOut) -like "RESULT: READY*") "after registering the new certificate: READY"

    # ============================================================ S11 a failure after the key is made is undone
    Section "S11 a failure AFTER the key is made leaves nothing: no key, no .cer, no state; the next run enrolls cleanly"
    $bf = New-D0Bay -Name "undo"
    # The state file cannot be written: its temp path is occupied by a folder. Export of the .cer still succeeds first.
    New-Item -ItemType Directory -Force -Path (Join-Path $bf.Root "state\credential.json.tmp") | Out-Null
    $certsBefore = @(Get-D0RunCerts)
    $r = Invoke-D0Agent -Bay $bf -Arguments ($SheetEnroll -f $D0OwnApp) -Sheet
    Show-D0Run $r "S11 state write fails"
    Assert-True (-not $r.TimedOut -and $r.ExitCode -eq 1) "exit code 1 (got $($r.ExitCode))"
    Assert-True ($r.Log -match "FATAL" -and $r.Log -match "Own-identity enrollment failed and was undone") "the log says the enrollment failed and was undone"
    Assert-True (@(Get-D0ResultLines $r.StdOut).Count -eq 0 -and $r.StdOut -notmatch "(?m)^ENROLLED") "nothing on the console claims an enrollment"
    Assert-True (((Get-D0RunCerts) -join ",") -eq ($certsBefore -join ",")) "the key made for the attempt was removed: the store holds what it held before"
    Assert-True (-not (Test-Path -LiteralPath $bf.State)) "there is no state\credential.json"
    Assert-True (@(Get-ChildItem -LiteralPath (Join-Path $bf.Root "state") -Filter "bay-cert-*.cer" -ErrorAction SilentlyContinue).Count -eq 0) "there is no public .cer left to register by mistake"
    Remove-Item -LiteralPath (Join-Path $bf.Root "state\credential.json.tmp") -Force -Recurse
    $r = Invoke-D0Agent -Bay $bf -Arguments ($SheetEnroll -f $D0OwnApp) -Sheet
    Assert-True ($r.ExitCode -eq 0 -and (Get-D0FirstResult $r.StdOut) -like "RESULT: ENROLLED*" -and (@(Get-D0RunCerts).Count -eq ($certsBefore.Count + 1))) "with the cause fixed, the same command enrolls: one certificate, exit 0"

    # ============================================================ S11b the one check that is NOT a run of the script
    Section "S11b (lifted, and said so) a replace that fails AFTER the state file changed puts the earlier enrollment back"
    # Every other section runs the script's real text. This branch cannot be reached that way: the state write is the
    # last thing that can fail, and when it fails the file has not changed. So here, and only here, the enrollment
    # function and what it calls are lifted out of the script and run in this process, with ONE stand-in:
    # Update-CredentialState writes a changed state file and THEN fails. An independent attack planted "the earlier
    # enrollment is not put back" and the suite passed; this is the assertion that was missing.
    $liftNames = @("Get-OwnIdentitySecretOnPc", "Get-PropValue", "Normalize-Thumbprint", "ConvertTo-AgentGuid", "Read-CredentialState", "Get-ActiveCertThumbprint", "Get-PendingCertThumbprint",
        "Get-ActiveClientId", "Test-OwnIdentityActive", "Get-IdentityProbation", "Test-HasUsableSecret", "Get-CertStoreSearchOrder", "Get-CertStoreName",
        "Find-ClientCertificate", "New-BayClientCertificate", "Export-PublicCertificate", "Build-CredentialEnrollResult", "Get-AadstsCode",
        "Get-OwnIdentitySignInProof", "Remove-OwnIdentityCertificate", "New-OwnIdentityEnrollRefusal", "Invoke-OwnIdentityEnroll")
    $ltk = $null; $ler = $null
    $liftAst = [System.Management.Automation.Language.Parser]::ParseFile($AgentScript, [ref]$ltk, [ref]$ler)
    $liftDefs = @{}
    foreach ($d in @($liftAst.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $true))) { $liftDefs[$d.Name] = $d.Extent.Text }
    $liftMissing = @($liftNames | Where-Object { -not $liftDefs.ContainsKey($_) })
    Assert-True ($liftMissing.Count -eq 0) ("the functions this check needs exist in the script (missing: " + $(if ($liftMissing.Count) { $liftMissing -join ", " } else { "none" }) + ")")
    if ($liftMissing.Count -eq 0) {
        foreach ($ln in $liftNames) { . ([scriptblock]::Create($liftDefs[$ln])) }
        function Write-Log { param([string]$Message, [string]$Level = "INFO") }
        $liftRoot = Join-Path $SandboxRoot "lifted-restore"
        New-Item -ItemType Directory -Force -Path (Join-Path $liftRoot "state") | Out-Null
        # The script-level names those functions read, as the script sets them on a bay with no secret configured.
        $BaseDir = $liftRoot; $CredentialStatePath = Join-Path $liftRoot "state\credential.json"
        $BayId = $D0BayId; $TenantId = $D0Tenant; $OrgUrl = $MockUrl; $ClientId = "<app-client-id>"
        $CertThumbprintCfg = $null; $CertStoreCfg = $null
        # ...and the configuration object the secret guard reads (the real script always has it; before the guard failed
        # closed, reading it here threw, the guard's catch swallowed that, and this check passed without it).
        $cfg = [pscustomobject]@{ bayId = $D0BayId }
        Set-Variable -Name Secret -Value $null; Set-Variable -Name SecretPath -Value $null
        $Global:CredentialStateCorrupt = $false
        # An earlier enrollment on record whose certificate is not in this account's store, on a bay that never ran:
        # the case -EnrollForce is allowed to replace.
        $earlier = '{ "activeThumbprint": "' + $D0FakeThumb + '", "activeClientId": "' + $D0OtherApp + '", "ownIdentityEnrolled": { "clientId": "' + $D0OtherApp + '", "thumbprint": "' + $D0FakeThumb + '", "utc": "2026-10-11T00:00:00Z", "account": "X\\Y" }, "fallbackCountTotal": 0 }'
        [IO.File]::WriteAllText($CredentialStatePath, $earlier, (New-Object Text.UTF8Encoding($false)))
        $earlierHash = Get-D0Sha256Hex ([IO.File]::ReadAllBytes($CredentialStatePath))
        $certsBeforeLift = @(Get-D0RunCerts)
        # THE STAND-IN: the state file is changed, then the write fails.
        function Update-CredentialState([hashtable]$changes) {
            [IO.File]::WriteAllText($CredentialStatePath, '{ "activeThumbprint": "HALF-WRITTEN" }', (New-Object Text.UTF8Encoding($false)))
            throw "stand-in: the state write failed after the file had changed"
        }
        $liftThrew = ""; $liftResult = $null
        try { $liftResult = Invoke-OwnIdentityEnroll -OwnClientId $D0OwnApp -Payload @{ force = $true; validityDays = 730 } } catch { $liftThrew = [string]$_.Exception.Message }
        Assert-True ($liftThrew -match "Own-identity enrollment failed and was undone" -and $null -eq $liftResult) ("the enrollment fails and says it was undone (" + $liftThrew + ")")
        Assert-True ((Test-Path -LiteralPath $CredentialStatePath) -and (Get-D0Sha256Hex ([IO.File]::ReadAllBytes($CredentialStatePath))) -eq $earlierHash) "the state file is byte for byte the earlier enrollment again (not the half-written one)"
        Assert-True (((Get-D0RunCerts) -join ",") -eq ($certsBeforeLift -join ",")) "the key made for the failed attempt is gone from the store"
        Assert-True (@(Get-ChildItem -LiteralPath (Join-Path $liftRoot "state") -Filter "bay-cert-*.cer" -ErrorAction SilentlyContinue).Count -eq 0) "...and so is its public .cer"

        # The guard's second read (the clientSecret key of the configuration) fails closed too. It cannot fail in a real run
        # (the script stops at start-up without its configuration), so this is the one place it is pinned: lifted, with a
        # configuration object that is NOT THERE (under strict mode, reading a variable that was never set throws; a
        # ScriptProperty stand-in does not work, PowerShell swallows an error raised inside a script property's getter).
        Remove-Variable -Name cfg
        $liftGuard = Get-OwnIdentitySecretOnPc
        $liftU = [string](Get-D0Prop $liftGuard "Unreadable"); $liftF = [string](Get-D0Prop $liftGuard "Found")
        Assert-True (($liftU -match "agent-config\.json, the clientSecret key") -and -not $liftF) ("a configuration key that cannot be read is reported as unreadable, not as nothing there (Unreadable: '" + $liftU + "', Found: '" + $liftF + "')")
        $cfg = [pscustomobject]@{ bayId = $D0BayId }
        $liftClean = Get-OwnIdentitySecretOnPc
        Assert-True ($null -ne (Get-D0Prop $liftClean "Found") -and -not [string](Get-D0Prop $liftClean "Found") -and -not [string](Get-D0Prop $liftClean "Unreadable")) "control: with nothing on the lifted PC, the guard finds nothing and reports nothing unreadable"
    }

    # ============================================================ S12 the key was made under another Windows account
    Section "S12 the certificate on record is not in this account's store (made under another account): dark, said plainly, correctable"
    $ba = New-D0Bay -Name "other-account"
    $r = Invoke-D0Agent -Bay $ba -Arguments ($SheetEnroll -f $D0OwnApp) -Sheet
    $tpGone = Get-D0ReportField $r.StdOut "Thumbprint"
    # Modeled: this account cannot see the key. (The suite made this certificate one line above, by this thumbprint.)
    Remove-Item -LiteralPath ("Cert:\CurrentUser\My\" + $tpGone) -DeleteKey -Force
    $rs = Invoke-D0Agent -Bay $ba -Arguments "-Once"
    Assert-True ($rs.ExitCode -eq 1 -and $rs.Log -match "no certificate with a private key was found") "the agent does not start, and says the certificate is not in this account's stores"
    $before = Get-D0InstallFingerprint $ba.Root
    $r = Invoke-D0Agent -Bay $ba -Arguments ($SheetEnroll -f $D0OwnApp) -Sheet
    Show-D0Run $r "S12 same id, key not here"
    Assert-True ($r.ExitCode -eq 2 -and (Get-D0ReportField $r.StdOut "Reason code") -eq "ABG_OWNID_ALREADY_ENROLLED" -and $r.StdOut -match "not in a store this Windows account") "the same command is refused and says the certificate is not in a store this account can read"
    Assert-True ((Get-D0InstallFingerprint $ba.Root) -eq $before) "...nothing was changed"
    $r = Invoke-D0Agent -Bay $ba -Arguments (($SheetEnroll -f $D0OwnApp) + " -EnrollForce") -Sheet
    Show-D0Run $r "S12 force"
    $tpNew = Get-D0ReportField $r.StdOut "Thumbprint"
    Assert-True ($r.ExitCode -eq 0 -and $tpNew -ne $tpGone -and $r.StdOut -match "NOT removed: it is not in this account's stores") "-EnrollForce enrolls again under this account and says the old key was not removed"
    $st = Read-D0State $ba
    Assert-True (@(Get-D0Prop $st "superseded") -contains $tpGone -and [string](Get-D0Prop $st "activeThumbprint") -eq $tpNew) "the unreachable certificate stays on record as superseded; the new one is active"

    Section "S12b a bay that HAS RUN is never re-enrolled from another Windows account, even with -EnrollForce"
    $bh = New-D0Bay -Name "has-run"
    $r = Invoke-D0Agent -Bay $bh -Arguments ($SheetEnroll -f $D0OwnApp) -Sheet
    $tpRun = Get-D0ReportField $r.StdOut "Thumbprint"
    if ($tpRun -notmatch '^[0-9A-F]{40}$') { throw "S12b could not enroll its bay" }
    Register-D0Certificate -AppId $D0OwnApp -CerPath (Join-Path $bh.Root ("state\bay-cert-{0}.cer" -f $tpRun))
    $r = Invoke-D0Agent -Bay $bh -Arguments "-Once"
    Assert-True ($r.ExitCode -eq 0 -and (Test-Path -LiteralPath (Join-Path $bh.Root "state\agent-alive.json"))) "the bay ran one pass and left the record of it (state\agent-alive.json)"
    $realAccount = [string](Get-D0Prop (Get-D0Prop (Read-D0State $bh) "ownIdentityEnrolled") "account")
    # Modeled: this console is NOT the account that enrolled (the record names another), and so cannot see the key.
    Set-D0EnrolledAccount $bh "BAY1KIOSK\SomeoneElse"
    Remove-Item -LiteralPath ("Cert:\CurrentUser\My\" + $tpRun) -DeleteKey -Force
    $before = Get-D0InstallFingerprint $bh.Root; $mark = Get-D0Mark
    $r = Invoke-D0Agent -Bay $bh -Arguments (($SheetEnroll -f $D0OwnApp) + " -EnrollForce") -Sheet
    Show-D0Run $r "S12b force from another account"
    Assert-True ($r.ExitCode -eq 2 -and (Get-D0ReportField $r.StdOut "Reason code") -eq "ABG_OWNID_BAY_HAS_RUN") "refused: ABG_OWNID_BAY_HAS_RUN (exit $($r.ExitCode), $(Get-D0ReportField $r.StdOut 'Reason code'))"
    Assert-True ($r.StdOut -match "enrolled by BAY1KIOSK\\SomeoneElse" -and $r.StdOut -match "Run this signed in as the account the agent runs as") "...naming the account that enrolled and what to do"
    Assert-True ((Get-D0InstallFingerprint $bh.Root) -eq $before -and @(Get-D0RequestsSince $mark).Count -eq 0) "...nothing was changed and nothing was sent"
    # The account that enrolled, whose own store no longer holds the key: the key is truly gone, so it may enroll again.
    Set-D0EnrolledAccount $bh $realAccount
    $r = Invoke-D0Agent -Bay $bh -Arguments (($SheetEnroll -f $D0OwnApp) + " -EnrollForce") -Sheet
    Assert-True ($r.ExitCode -eq 0 -and $r.StdOut -match "ENROLLED AGAIN" -and (Get-D0ReportField $r.StdOut "Thumbprint") -ne $tpRun) "the account that enrolled, with its key gone from its own store, enrolls again (exit $($r.ExitCode))"

    Section "S12c a bay that has NEVER run: a certificate made under another account is discarded with -EnrollForce"
    $bv = New-D0Bay -Name "never-ran-other-account"
    $r = Invoke-D0Agent -Bay $bv -Arguments ($SheetEnroll -f $D0OwnApp) -Sheet
    $tpNever = Get-D0ReportField $r.StdOut "Thumbprint"
    if ($tpNever -notmatch '^[0-9A-F]{40}$') { throw "S12c could not enroll its bay" }
    Set-D0EnrolledAccount $bv "BAY1KIOSK\TheAdministrator"
    Remove-Item -LiteralPath ("Cert:\CurrentUser\My\" + $tpNever) -DeleteKey -Force
    Assert-True (-not (Test-Path -LiteralPath (Join-Path $bv.Root "state\agent-alive.json"))) "precondition: this bay has never run"
    $r = Invoke-D0Agent -Bay $bv -Arguments (($SheetEnroll -f $D0OwnApp) + " -EnrollForce") -Sheet
    Show-D0Run $r "S12c force, never ran"
    Assert-True ($r.ExitCode -eq 0 -and $r.StdOut -match "ENROLLED AGAIN" -and $r.StdOut -match "NOT removed: it is not in this account's stores") "enrolled again under this account; the report says the other account's key was not removed (exit $($r.ExitCode))"
    $st = Read-D0State $bv
    Assert-True ([string](Get-D0Prop (Get-D0Prop $st "ownIdentityEnrolled") "account") -eq $realAccount) "the record now names this account as the one that enrolled"
    $cersLeft = @(Get-ChildItem -LiteralPath (Join-Path $bv.Root "state") -Filter "bay-cert-*.cer" | ForEach-Object { $_.Name })
    Assert-True ($cersLeft.Count -eq 1 -and $cersLeft[0] -eq ("bay-cert-{0}.cer" -f (Get-D0ReportField $r.StdOut "Thumbprint"))) "exactly one public .cer is left in state\, the new one (the discarded one's file is gone: $($cersLeft -join ', '))"

    # ============================================================ S13 without the parameter, nothing new happens
    Section "S13 plain -EnrollCert is unchanged: no app id is written unless one was typed"
    $bp = New-D0Bay -Name "plain" -Shape "own"
    $r = Invoke-D0Agent -Bay $bp -Arguments "-EnrollCert" -Sheet
    Show-D0Run $r "S13 plain"
    Assert-True ($r.ExitCode -eq 0 -and $r.StdOut -match "ENROLLED certificate credential for bay" -and $r.StdOut -match "ACTIVE \(no prior credential\)") "plain -EnrollCert prints what 1.6.0 prints"
    Assert-True (@(Get-D0ResultLines $r.StdOut).Count -eq 0) "...and none of the own-identity report"
    $st = Read-D0State $bp
    Assert-True ($null -ne $st -and $null -eq (Get-D0Prop $st "activeClientId") -and $null -eq (Get-D0Prop $st "ownIdentityEnrolled")) "the state file names NO app: nothing was filled in that the operator did not pass"
    Assert-True (([IO.File]::ReadAllText($bp.State)) -notmatch '[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}') "...no id of any kind is in it"
    # The control for F3: this bay signs in as its own app (the configuration names it) but nothing says the app is its
    # own, so the wall pass would never be fetched. That is exactly what -EnrollClientId adds.
    Register-D0Certificate -AppId $D0OwnApp -CerPath (Join-Path $bp.Root ("state\bay-cert-{0}.cer" -f [string](Get-D0Prop $st "activeThumbprint")))
    $mark = Get-D0Mark
    $r = Invoke-D0Agent -Bay $bp -Arguments "-Once"
    $credPlain = Get-D0Prop (Get-D0Capabilities (Get-D0RequestsSince $mark)) "credential"
    Assert-True ($r.ExitCode -eq 0 -and $null -ne $credPlain -and (Get-D0Prop (Get-D0Prop $credPlain "identity") "ownIdentity") -eq $false) "control: a bay enrolled WITHOUT -EnrollClientId reports ownIdentity false, even when agent-config.json names its own app"
    $r = Invoke-D0Agent -Bay $bp -Arguments ($SheetEnroll -f $D0OwnApp) -Sheet
    Assert-True ($r.ExitCode -eq 2 -and (Get-D0ReportField $r.StdOut "Reason code") -eq "ABG_OWNID_ALREADY_ENROLLED") "...and -EnrollClientId on that bay is refused without -EnrollForce (it holds an enrollment)"

    # ============================================================ S14 the argument order a person might type
    Section "S14 argument order and the optional enrollment switches"
    $bo = New-D0Bay -Name "order"
    $r = Invoke-D0Agent -Bay $bo -Arguments ("-EnrollClientId " + $D0OwnApp + " -EnrollValidityDays 400 -EnrollStore CurrentUser -EnrollCert") -Sheet
    $tpo = Get-D0ReportField $r.StdOut "Thumbprint"
    Assert-True ($r.ExitCode -eq 0 -and $tpo -match '^[0-9A-F]{40}$') "-EnrollClientId first and -EnrollCert last enrolls just the same"
    $co = Get-Item -LiteralPath ("Cert:\CurrentUser\My\" + $tpo)
    $days = ($co.NotAfter - (Get-Date)).TotalDays
    Assert-True ($days -gt 398 -and $days -lt 401) "-EnrollValidityDays 400 reached the certificate (valid for $([int]$days) days)"

    # ============================================================ S15 census on the real text
    Section "S15 census: one caller, one writer, console only, and the parameter has no meaningful default"
    $tk = $null; $er = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseFile($AgentScript, [ref]$tk, [ref]$er)
    Assert-True (@($er).Count -eq 0) "the agent script parses"
    $calls = @($ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.CommandAst] -and $n.GetCommandName() -eq "Invoke-OwnIdentityEnroll" }, $true))
    Assert-True ($calls.Count -eq 1) "Invoke-OwnIdentityEnroll is called from exactly one place (found $($calls.Count))"
    if ($calls.Count -eq 1) {
        $inFunction = $false; $conds = @(); $p = $calls[0].Parent
        while ($null -ne $p) {
            if ($p -is [System.Management.Automation.Language.FunctionDefinitionAst]) { $inFunction = $true }
            if ($p -is [System.Management.Automation.Language.IfStatementAst]) { $conds += $p.Clauses[0].Item1.Extent.Text.Trim() }
            $p = $p.Parent
        }
        Assert-True (-not $inFunction) "...at script level, not inside any function (no BayCommand handler reaches it)"
        Assert-True (($conds -join " < ") -eq '$EnrollClientIdGiven < $EnrollCert') "...inside 'if (`$EnrollCert)' and 'if (`$EnrollClientIdGiven)' and nothing else (found: $($conds -join ' < '))"
        $callText = $calls[0].Extent.Text
        Assert-True ($callText -match '-OwnClientId\s+\$EnrollClientId(\s|$)') "...and it is handed the typed parameter itself (`$EnrollClientId), not a configured or built-in id"
    }
    $given = @($ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.AssignmentStatementAst] -and $n.Left.Extent.Text -eq '$EnrollClientIdGiven' }, $true))
    Assert-True ($given.Count -eq 1 -and $given[0].Right.Extent.Text.Trim() -eq '$PSBoundParameters.ContainsKey("EnrollClientId")') "`$EnrollClientIdGiven is assigned once, from `$PSBoundParameters: only a typed parameter counts"
    $prm = @($ast.ParamBlock.Parameters | Where-Object { $_.Name.VariablePath.UserPath -eq "EnrollClientId" })
    Assert-True ($prm.Count -eq 1 -and $null -ne $prm[0].DefaultValue -and $prm[0].DefaultValue.Extent.Text -eq '""') "-EnrollClientId exists and its default is the empty string"
    $fns = @{}
    foreach ($d in @($ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $true))) { $fns[$d.Name] = $d.Extent.Text }
    $writers = @($fns.Keys | Where-Object { $fns[$_] -match 'ownIdentityEnrolled\s*=' } | Sort-Object)
    Assert-True (($writers -join ",") -eq "Invoke-OwnIdentityEnroll") "the only function that writes ownIdentityEnrolled is Invoke-OwnIdentityEnroll (found: $($writers -join ', '))"
    foreach ($remote in @("Invoke-CredentialRotate", "Invoke-CredentialEnroll", "Execute-Command", "Process-Command")) {
        Assert-True ($fns.ContainsKey($remote) -and $fns[$remote] -notmatch 'OwnIdentityEnroll|EnrollClientId|ownIdentityEnrolled') "the command path ($remote) does not touch the console enrollment"
    }
    $shippedText = [IO.File]::ReadAllText($AgentScript)
    Assert-True ([regex]::Matches($shippedText, 'ownIdentityEnrolled\s*=').Count -eq 1) "...and the whole script writes that key in exactly one place"
    Assert-True ($shippedText -match '(?m)^\$AgentCodeVersion = "1\.6\.0"') "the version constant is untouched by this change (1.6.0; the bump is the release's act)"
}
catch {
    # A suite that stops on an error must still end with a RESULT line that is red, never with silence.
    Assert-True $false ("the suite stopped on an error at line {0}: {1}" -f $_.InvocationInfo.ScriptLineNumber, $_.Exception.Message)
}
finally {
    $sync["Stop"] = $true
    try { $mock.PS.Stop() } catch {}
    try { $mock.RS.Close() } catch {}
    Unlock-D0All
    try { Remove-Item -LiteralPath $SandboxRoot -Recurse -Force -ErrorAction SilentlyContinue } catch {}
    # Remove exactly the certificates this run made: the subject carries this run's own bay id.
    try {
        $mine = @(Get-D0RunCerts) + @(Get-D0PlaceholderCerts | Where-Object { $placeholderCertsAtStart -notcontains $_ })
        foreach ($tpLeft in $mine) {
            try { Remove-Item -LiteralPath ("Cert:\CurrentUser\My\" + $tpLeft) -DeleteKey -Force } catch { Write-Host "could not remove test certificate $tpLeft" -ForegroundColor Yellow }
        }
    } catch { Assert-True $false ("cleanup could not read the certificate store, so certificates this run made may be left in it: " + $_.Exception.Message) }
}

Write-Host ""
$left = @()
try { $left = @(Get-D0RunCerts) + @(Get-D0PlaceholderCerts | Where-Object { $placeholderCertsAtStart -notcontains $_ }) }
catch { Assert-True $false ("cleanup check could not read the certificate store: " + $_.Exception.Message) }
Assert-True ($left.Count -eq 0) "cleanup: no certificate of this run is left in the store (left: $($left.Count))"
if ($sync["Errors"].Count -gt 0) { Write-Host "recorder errors: $($sync['Errors'] -join ' | ')" -ForegroundColor Yellow }
Assert-True ($sync["Errors"].Count -eq 0) "the recorder itself raised no error ($($sync['Errors'].Count))"
Write-Host ("RESULT: {0} passed, {1} failed" -f $script:Pass, $script:Fail) -ForegroundColor $(if ($script:Fail -eq 0) { "Green" } else { "Red" })
if ($script:Fail -gt 0) { $script:Failures | ForEach-Object { Write-Host "  - $_" -ForegroundColor Red }; exit 1 }
exit 0
