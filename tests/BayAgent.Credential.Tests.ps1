<#
BayAgent.Credential.Tests.ps1

Exercises the certificate-credential path of src\BayAgent\BayAgent.ps1 WITHOUT running the agent:
the credential functions are lifted out of the script by AST and run against
  - a throwaway self-signed certificate created in Cert:\CurrentUser\My (deleted at the end), and
  - a LOCAL MOCK token endpoint (a TcpListener on 127.0.0.1 in a background runspace) that records
    every request the agent sends and answers with whatever the test tells it to.

What the mock proves and what it does not:
  PROVES   the exact form body the agent posts (client_assertion_type, client_assertion, scope, client_id,
           grant_type), that the assertion verifies against the certificate's public key, the aud/iss/sub/
           jti/nbf/exp claims, the token-cache behaviour, the secret FALLBACK on a certificate failure,
           the activate-only-after-proof rule, and the retire guards.
  DOES NOT prove that Entra accepts the assertion. The -Live switch adds one real check with no Azure
           write: an assertion signed by the UNREGISTERED test certificate is posted to the real Entra
           endpoint for the real app id, and Entra is expected to answer AADSTS700027 (signature valid
           in form, key not found) rather than a malformed-assertion error.

Run (from the repo root):
  powershell -NoProfile -ExecutionPolicy Bypass -File tests\BayAgent.Credential.Tests.ps1
  powershell -NoProfile -ExecutionPolicy Bypass -File tests\BayAgent.Credential.Tests.ps1 -Live
Exit code 0 = all assertions passed. Hyphens only in comments (em-dashes break AllSigned parsing).
#>
[CmdletBinding()]
param(
    [switch]$Live,
    [string]$AgentScript = "",
    # Real values used ONLY by -Live (no writes: a token request with an unregistered key is rejected).
    [string]$LiveTenantId = "cc551e6a-be6a-42d2-add4-231f5891a179",
    [string]$LiveClientId = "0e77dbf6-499d-434c-acfc-b276bc439c38",
    [string]$LiveOrgUrl   = "https://builds-apps-dev.crm.dynamics.com",
    [string]$LiveForeignTenantId = "9c568879-aa66-44cd-b5c0-a2ce64adc958"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
try { Add-Type -AssemblyName System.Security -ErrorAction SilentlyContinue } catch {}
try { [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 } catch {}

if ([string]::IsNullOrWhiteSpace($AgentScript)) { $AgentScript = Join-Path $PSScriptRoot "..\src\BayAgent\BayAgent.ps1" }
$AgentScript = (Resolve-Path $AgentScript).Path

# ---------------------------------------------------------------- harness
$script:Pass = 0; $script:Fail = 0; $script:Failures = @()
function Assert-True([bool]$cond, [string]$msg) {
    if ($cond) { $script:Pass++; Write-Host "  PASS  $msg" }
    else { $script:Fail++; $script:Failures += $msg; Write-Host "  FAIL  $msg" -ForegroundColor Red }
}
function Assert-Throws([scriptblock]$sb, [string]$pattern, [string]$msg) {
    $threw = $false; $text = ""
    try { & $sb | Out-Null } catch { $threw = $true; $text = $_.Exception.Message }
    if (-not $threw) { Assert-True $false "$msg (did NOT throw)"; return }
    Assert-True ($text -match $pattern) "$msg (threw: $text)"
}
function Section([string]$name) { Write-Host ""; Write-Host "== $name" -ForegroundColor Cyan }

# ---------------------------------------------------------------- lift functions out of BayAgent.ps1
$tokens = $null; $errors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile($AgentScript, [ref]$tokens, [ref]$errors)
if ($errors.Count -gt 0) { throw "BayAgent.ps1 has parse errors: $($errors | ForEach-Object { $_.Message } | Out-String)" }

$wanted = @(
    "Read-WebExceptionBody", "Get-ClientSecret", "Get-PropValue",
    "ConvertTo-Base64Url", "ConvertFrom-Base64Url", "Normalize-Thumbprint",
    "Read-CredentialState", "Write-CredentialState", "Update-CredentialState",
    "Get-ActiveCertThumbprint", "Get-PendingCertThumbprint", "Get-CertStoreSearchOrder", "Get-CertStoreName",
    "Find-ClientCertificate", "New-ClientAssertionJwt", "Get-AadstsCode", "Get-TokenUrl", "Invoke-TokenEndpoint",
    "Acquire-TokenWithCertificate", "Acquire-TokenWithSecret", "Acquire-Token", "Get-CredentialTelemetry",
    "Write-CredentialStartupSummary", "Get-AccessToken",
    "New-BayClientCertificate", "Export-PublicCertificate", "Build-CredentialEnrollResult",
    "Invoke-CredentialEnroll", "Invoke-CredentialTest", "Invoke-CredentialActivate", "Invoke-CredentialRetire",
    "Invoke-CredentialStatus", "Invoke-CredentialRotate",
    "Limit-ResultJson", "New-BayClientCertificate", "Test-IsAgentOwnedCertificate", "Sync-FallbackTelemetry",
    "Start-GenericProcess", "Read-LastUpdateResult", "Test-HasUsableSecret", "New-EnrollCertPayload"
)
$defs = $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $true)
$lifted = 0
foreach ($name in $wanted) {
    $d = $defs | Where-Object { $_.Name -eq $name } | Select-Object -First 1
    if (-not $d) { throw "Function '$name' not found in $AgentScript" }
    . ([scriptblock]::Create($d.Extent.Text))
    $lifted++
}
Write-Host "Lifted $lifted functions from $AgentScript"

# Agent-side script variables the lifted functions read (mirrors the top of BayAgent.ps1).
$script:LogLines = New-Object System.Collections.ArrayList
function Write-Log { param([string]$Message, [string]$Level = "INFO") [void]$script:LogLines.Add("[$Level] $Message") }

$BaseDir = Join-Path $env:TEMP ("bayagent-credtest-" + [guid]::NewGuid().ToString("N").Substring(0, 8))
New-Item -ItemType Directory -Force -Path (Join-Path $BaseDir "state") | Out-Null
$CredentialStatePath = Join-Path $BaseDir "state\credential.json"
$TenantId  = "11111111-1111-1111-1111-111111111111"
$ClientId  = "22222222-2222-2222-2222-222222222222"
$OrgUrl    = "https://mock-org.crm.dynamics.com"
$BayId     = "33333333-3333-3333-3333-333333333333"
$TokenAuthorityHost  = "http://127.0.0.1:1"      # replaced once the mock is up
$AssertionAlg        = "RS256"
$ResultJsonMaxChars  = 2000      # MEASURED against Dev: build_resultjson is Memo(2000)
$CertThumbprintCfg   = $null
$CertStoreCfg        = $null
$Secret              = $null
$SecretPath          = $null
$SecretPathCfg       = $null
$HasSecretCredential = $false
$Global:AccessToken     = $null
$Global:TokenExpiresUtc = [DateTime]::MinValue
$Global:CredentialTelemetry = @{
    lastMintMode = $null; lastMintUtc = $null; lastCertMintUtc = $null; lastSecretMintUtc = $null
    lastCertError = $null; lastSecretError = $null; fallbackCount = 0; lastTest = $null
    fallbackFlushed = 0; lastFallbackUtc = $null
}
function Reset-TelemetryAsIfRestarted {
    # Exactly what a Host Watchdog restart does to the in-memory counters: wipes them.
    $Global:CredentialTelemetry = @{
        lastMintMode = $null; lastMintUtc = $null; lastCertMintUtc = $null; lastSecretMintUtc = $null
        lastCertError = $null; lastSecretError = $null; fallbackCount = 0; lastTest = $null
        fallbackFlushed = 0; lastFallbackUtc = $null
    }
}
$script:CreatedCerts = New-Object System.Collections.ArrayList

function Reset-TokenState {
    $Global:AccessToken = $null
    $Global:TokenExpiresUtc = [DateTime]::MinValue
}

# ---------------------------------------------------------------- mock token endpoint (background runspace)
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
                    [void]$sync["Requests"].Add(@{ requestLine = (($headText -split "`r`n")[0]); headers = $headText; body = $body })
                    $resp = if ($body.Contains("client_assertion=")) { $sync["CertResponse"] } else { $sync["SecretResponse"] }
                    $status = [int]$resp.status
                    $reason = "OK"; if ($status -eq 401) { $reason = "Unauthorized" } elseif ($status -ge 400) { $reason = "Bad Request" }
                    $bytes = [Text.Encoding]::UTF8.GetBytes([string]$resp.body)
                    $head = "HTTP/1.1 $status $reason`r`nContent-Type: application/json; charset=utf-8`r`nContent-Length: $($bytes.Length)`r`nConnection: close`r`n`r`n"
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

$sync = [hashtable]::Synchronized(@{
    Stop = $false; Port = 0
    Requests = [System.Collections.ArrayList]::Synchronized((New-Object System.Collections.ArrayList))
    Errors   = [System.Collections.ArrayList]::Synchronized((New-Object System.Collections.ArrayList))
    CertResponse   = @{ status = 200; body = '{"token_type":"Bearer","expires_in":3599,"access_token":"mock-cert-token"}' }
    SecretResponse = @{ status = 200; body = '{"token_type":"Bearer","expires_in":3599,"access_token":"mock-secret-token"}' }
})
$mock = Start-MockTokenEndpoint -Sync $sync
$deadline = (Get-Date).AddSeconds(10)
while ($sync["Port"] -eq 0 -and (Get-Date) -lt $deadline) { Start-Sleep -Milliseconds 50 }
if ($sync["Port"] -eq 0) { throw "mock token endpoint did not start" }
$TokenAuthorityHost = "http://127.0.0.1:$($sync['Port'])"
Write-Host "Mock token endpoint listening on $TokenAuthorityHost (this is a MOCK, not Entra)"

function Get-FormField([string]$body, [string]$name) {
    foreach ($kv in $body.Split("&")) {
        $i = $kv.IndexOf("=")
        if ($i -lt 0) { continue }
        if ($kv.Substring(0, $i) -eq $name) { return [uri]::UnescapeDataString($kv.Substring($i + 1)) }
    }
    return $null
}
function Get-JwtPart([string]$jwt, [int]$index) {
    return ([Text.Encoding]::UTF8.GetString((ConvertFrom-Base64Url $jwt.Split(".")[$index])) | ConvertFrom-Json)
}
function Test-JwtSignature([string]$jwt, $cert, [string]$alg = "RS256") {
    $parts = $jwt.Split(".")
    $data = [Text.Encoding]::UTF8.GetBytes("$($parts[0]).$($parts[1])")
    $sig = ConvertFrom-Base64Url $parts[2]
    $rsa = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPublicKey($cert)
    $pad = if ($alg -eq "PS256") { [System.Security.Cryptography.RSASignaturePadding]::Pss } else { [System.Security.Cryptography.RSASignaturePadding]::Pkcs1 }
    return $rsa.VerifyData($data, $sig, [System.Security.Cryptography.HashAlgorithmName]::SHA256, $pad)
}

try {
    # ================================================================ INVARIANTS, RUN FIRST
    # These three used to sit near the end, and that made them unreachable by the mutations they exist to
    # catch. MEASURED: mutant M6 (certificate no longer preferred over the secret) dies inside T2 with an
    # unhandled "SecretPath not configured" -- so the suite never reached the assertion written for it, and
    # the mutation harness scored the crash. A crash truncates the run: an assertion that exists but is not
    # REACHED pins nothing. Foundational invariants therefore run before anything that can throw.
    # Each restores every global it touches, so T1 onward sees the state it always did.

    $__sv = @{ Secret = $Secret; SecretPath = $SecretPath; SecretPathCfg = $SecretPathCfg;
               HasSecretCredential = $HasSecretCredential; CertThumbprintCfg = $CertThumbprintCfg;
               TokenAuthorityHost = $TokenAuthorityHost; TenantId = $TenantId; StatePath = $CredentialStatePath }

    # ============================================================ T23: the token endpoint comes from CONFIG.
    # Asserted directly on the string rather than observed via a request, because mutation M12 (endpoint
    # hardcoded to another host) previously killed the suite with a WebException deep inside
    # Invoke-TokenEndpoint. A crash is evidence the suite noticed something; it is not evidence the suite
    # ASSERTS the behavior, and roughly 160 of the 181 assertions never ran under that mutant.
    Section "T23 the token endpoint is built from config, asserted without a network call"
    $savedHost = $TokenAuthorityHost
    $TokenAuthorityHost = "https://login.example.invalid"
    $TenantId = "44444444-4444-4444-4444-444444444444"
    $url = Get-TokenUrl
    Assert-True ($url -eq "https://login.example.invalid/44444444-4444-4444-4444-444444444444/oauth2/v2.0/token") `
        "Get-TokenUrl is exactly <configured authority>/<configured tenant>/oauth2/v2.0/token (got '$url')"
    Assert-True ($url.StartsWith($TokenAuthorityHost)) "...and the host half is the CONFIGURED authority, not a literal"
    $TokenAuthorityHost = "https://login.microsoftonline.com"
    Assert-True ((Get-TokenUrl) -eq "https://login.microsoftonline.com/44444444-4444-4444-4444-444444444444/oauth2/v2.0/token") `
        "...it tracks the config value rather than being fixed at load"
    $TokenAuthorityHost = $savedHost
    $TenantId = "11111111-1111-1111-1111-111111111111"

    # ============================================================ T24: the CERTIFICATE is preferred when both
    # credentials are present. Mutation M6 (skip the certificate branch entirely) previously died on an
    # unhandled "SecretPath not configured" with ZERO failed assertions -- the suite had no case where a
    # certificate and a secret were both usable at once, which is precisely the transitional state every bay
    # is in between KH-18 step 7 and step 8.
    Section "T24 with BOTH a certificate and a secret configured, the certificate is the one that mints"
    Remove-Item -LiteralPath $CredentialStatePath -Force -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath "$CredentialStatePath.bak" -Force -ErrorAction SilentlyContinue
    $bothCert = New-BayClientCertificate -Subject "CN=ABG-BayAgent both-$([guid]::NewGuid().ToString('N').Substring(0,8))" -ValidityDays 60 -Store "CurrentUser"
    [void]$script:CreatedCerts.Add($bothCert.Thumbprint)
    Update-CredentialState @{ activeThumbprint = $bothCert.Thumbprint } | Out-Null
    $bothDpapi = Join-Path $BaseDir "secrets\both.dpapi"
    New-Item -ItemType Directory -Force -Path (Split-Path $bothDpapi) | Out-Null
    [IO.File]::WriteAllBytes($bothDpapi, [byte[]](7, 7, 7))
    $Secret = $null; $SecretPath = $bothDpapi; $SecretPathCfg = $bothDpapi; $HasSecretCredential = $true
    $CertThumbprintCfg = $null
    Reset-TokenState; Reset-TelemetryAsIfRestarted
    $sync["Requests"].Clear()
    $sync["CertResponse"]   = @{ status = 200; body = '{"token_type":"Bearer","expires_in":3599,"access_token":"tok-from-certificate"}' }
    $sync["SecretResponse"] = @{ status = 200; body = '{"token_type":"Bearer","expires_in":3599,"access_token":"tok-from-secret"}' }
    # Guarded: with the certificate branch removed, Acquire-Token falls through to the secret and throws
    # on the throwaway DPAPI bytes -- which killed the run before this section's own assertion could fail.
    # A test that cannot fail cleanly cannot report what it found, and the harness scores the crash.
    $t24Err = ""
    try { $null = Acquire-Token } catch { $t24Err = $_.Exception.Message }
    Assert-True ($t24Err -eq "") "Acquire-Token succeeds with both credentials present (err: $t24Err)"
    Assert-True ($Global:CredentialTelemetry.lastMintMode -eq "certificate") `
        "the certificate mints even though a working secret is configured beside it (mode=$($Global:CredentialTelemetry.lastMintMode))"
    Assert-True ($Global:CredentialTelemetry.fallbackCount -eq 0) "...and it is not counted as a fallback"
    Assert-True (@($sync["Requests"]).Count -eq 1) "...exactly one token request was made"
    $bodyBoth = "$($sync["Requests"][0].body)"
    Assert-True ($bodyBoth -match "client_assertion=") "...and it carried a client_assertion (the certificate path)"
    Assert-True (-not ($bodyBoth -match "client_secret=")) "...and NOT a client_secret (the secret was never reached)"

    # ============================================================ T26 (V3b): EVERY write leaves a .bak.
    # "Never writes one" was already pinned; "every" was not -- a mutant that skipped the backup on the first
    # write of each process stayed green. The backup must not depend on anything the process remembers.
    Section "T26 (V3b) every write that replaces a state file leaves a .bak of what it replaced"
    $bakDir = Join-Path $BaseDir "bakstate"
    New-Item -ItemType Directory -Force -Path $bakDir | Out-Null
    $savedStatePath = $CredentialStatePath
    $CredentialStatePath = Join-Path $bakDir "credential.json"
    $Global:CredentialStateCorrupt = $false
    # Guarded for the same reason as T24: a mutant that gates the backup on a remembered flag reads that
    # flag before setting it, which under StrictMode is a terminating error, not a failed assertion.
    function Write-Marker([string]$m) {
        try { Update-CredentialState @{ marker = $m } | Out-Null; return "" } catch { return $_.Exception.Message }
    }
    function Read-Bak {
        if (-not (Test-Path "$CredentialStatePath.bak")) { return "<no .bak>" }
        try { return (Get-Content "$CredentialStatePath.bak" -Raw | ConvertFrom-Json).marker } catch { return "<unreadable>" }
    }
    $e1 = Write-Marker "one"
    Assert-True ($e1 -eq "") "the first write succeeds (err: $e1)"
    Assert-True (-not (Test-Path "$CredentialStatePath.bak")) "the very first write has nothing to back up, so no .bak (correct, not a miss)"
    $e2 = Write-Marker "two"
    Assert-True ($e2 -eq "") "the second write succeeds (err: $e2)"
    Assert-True (Test-Path "$CredentialStatePath.bak") "the next write leaves a .bak"
    Assert-True ((Read-Bak) -eq "one") "...holding exactly what it replaced"
    $e3 = Write-Marker "three"
    Assert-True ($e3 -eq "") "the third write succeeds (err: $e3)"
    Assert-True ((Read-Bak) -eq "two") "...and it is REFRESHED on the next write, not written once and left stale"
    $e4 = Write-Marker "four"
    Assert-True ($e4 -eq "") "the fourth write succeeds (err: $e4)"
    Assert-True ((Read-Bak) -eq "three") "...and again, so the .bak is always one write behind"
    # The structural half: a backup that depends on a remembered flag is not "every write". Write-CredentialState
    # must carry no per-process state at all -- that is what a first-call skip requires.
    # Parsed here rather than reusing a variable from a later section -- this block now runs FIRST, and a
    # test that depends on another section having run is a test that stops working the moment order changes.
    $wcsErr = $null; $wcsTok = $null
    $wcsAst = [System.Management.Automation.Language.Parser]::ParseFile($AgentScript, [ref]$wcsTok, [ref]$wcsErr)
    $wcsDef = @($wcsAst.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $true) |
                Where-Object { $_.Name -eq "Write-CredentialState" })[0]
    $wcsText = $wcsDef.Extent.Text
    Assert-True ($wcsText -match "\.bak") "Write-CredentialState is the function that writes the .bak"
    Assert-True (-not ($wcsText -match '\$script:' -or $wcsText -match '\$Global:')) `
        "...and it keeps NO per-process state, so the backup cannot be skipped on a first call"
    $CredentialStatePath = $savedStatePath


    # Put every global back exactly as T1 expects to find it.
    $Secret = $__sv.Secret; $SecretPath = $__sv.SecretPath; $SecretPathCfg = $__sv.SecretPathCfg
    $HasSecretCredential = $__sv.HasSecretCredential; $CertThumbprintCfg = $__sv.CertThumbprintCfg
    $TokenAuthorityHost = $__sv.TokenAuthorityHost; $TenantId = $__sv.TenantId
    $CredentialStatePath = $__sv.StatePath
    Remove-Item -LiteralPath $CredentialStatePath -Force -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath "$CredentialStatePath.bak" -Force -ErrorAction SilentlyContinue
    $Global:CredentialStateCorrupt = $false
    Reset-TokenState; Reset-TelemetryAsIfRestarted
    $sync["Requests"].Clear()
    $sync["CertResponse"]   = @{ status = 200; body = '{"token_type":"Bearer","expires_in":3599,"access_token":"mock-cert-token"}' }
    $sync["SecretResponse"] = @{ status = 200; body = '{"token_type":"Bearer","expires_in":3599,"access_token":"mock-secret-token"}' }

    # ============================================================ T1: certificate creation + JWT shape
    Section "T1 enrollment creates a non-exportable key and the assertion has the documented shape"
    $cert = New-BayClientCertificate -Subject "CN=ABG-BayAgent credtest $BayId" -ValidityDays 30 -Store CurrentUser
    [void]$script:CreatedCerts.Add($cert.Thumbprint)
    Assert-True ($cert.HasPrivateKey) "certificate has a private key"
    Assert-True ((Get-CertStoreName $cert) -eq "CurrentUser\My") "certificate landed in CurrentUser\My (got '$(Get-CertStoreName $cert)')"
    $exportable = $true
    try { $null = $cert.PrivateKey.ExportParameters($true) } catch { $exportable = $false }
    try { $k = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($cert); $null = $k.ExportParameters($true); $exportable = $true } catch { $exportable = $false }
    Assert-True (-not $exportable) "private key is NOT exportable"
    Assert-True ($cert.NotAfter -gt (Get-Date).AddDays(29)) "validity honoured (NotAfter $($cert.NotAfter.ToString('u')))"

    $aud = "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token"
    $jwt = New-ClientAssertionJwt -Certificate $cert -ClientId $ClientId -Audience $aud
    $parts = $jwt.Split(".")
    Assert-True ($parts.Count -eq 3) "JWT has three dot-separated parts"
    Assert-True (($jwt -notmatch "[=+/]")) "JWT uses base64url alphabet (no = + /)"
    $hdr = Get-JwtPart $jwt 0
    Assert-True ($hdr.alg -eq "RS256" -and $hdr.typ -eq "JWT") "header alg=RS256 typ=JWT"
    $expX5t = ConvertTo-Base64Url ([System.Security.Cryptography.SHA1]::Create().ComputeHash($cert.RawData))
    $expX5tS256 = ConvertTo-Base64Url ([System.Security.Cryptography.SHA256]::Create().ComputeHash($cert.RawData))
    Assert-True ($hdr.x5t -eq $expX5t) "header x5t = base64url(SHA-1 of DER) = thumbprint"
    Assert-True ($hdr.'x5t#S256' -eq $expX5tS256) "header x5t#S256 = base64url(SHA-256 of DER)"
    $tpFromX5t = -join ((ConvertFrom-Base64Url $hdr.x5t) | ForEach-Object { $_.ToString("X2") })
    Assert-True ($tpFromX5t -eq $cert.Thumbprint) "x5t decodes back to the certificate thumbprint"
    $claims = Get-JwtPart $jwt 1
    $now = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
    Assert-True ($claims.aud -eq $aud) "aud = token endpoint URL"
    Assert-True ($claims.iss -eq $ClientId -and $claims.sub -eq $ClientId) "iss = sub = client id"
    Assert-True ([guid]::TryParse([string]$claims.jti, [ref]([guid]::Empty))) "jti is a GUID"
    Assert-True ($claims.nbf -le $now -and $claims.nbf -ge ($now - 120)) "nbf is now minus skew allowance"
    Assert-True ($claims.iat -le $now -and $claims.iat -ge ($now - 5)) "iat is now"
    Assert-True ($claims.exp -gt $now -and ($claims.exp - $claims.nbf) -le 600) "exp is short-lived (exp-nbf = $($claims.exp - $claims.nbf)s, documented max 600s)"
    Assert-True (Test-JwtSignature $jwt $cert) "RS256 signature verifies with the certificate public key"
    $tampered = $parts[0] + "." + $parts[1].Substring(0, $parts[1].Length - 2) + "AA." + $parts[2]
    Assert-True (-not (Test-JwtSignature $tampered $cert)) "tampered payload fails signature verification"
    $jwt2 = New-ClientAssertionJwt -Certificate $cert -ClientId $ClientId -Audience $aud
    Assert-True ((Get-JwtPart $jwt2 1).jti -ne $claims.jti) "each assertion carries a fresh jti"
    $jwtPs = New-ClientAssertionJwt -Certificate $cert -ClientId $ClientId -Audience $aud -Alg "PS256"
    Assert-True ((Get-JwtPart $jwtPs 0).alg -eq "PS256" -and (Test-JwtSignature $jwtPs $cert "PS256")) "PS256 variant signs with PSS padding and verifies"

    # ============================================================ T2: certificate mint against the mock
    Section "T2 Acquire-Token uses the ACTIVE certificate: form body, assertion, cache (MOCK endpoint)"
    Update-CredentialState @{ activeThumbprint = $cert.Thumbprint } | Out-Null
    Assert-True ((Get-ActiveCertThumbprint) -eq $cert.Thumbprint) "state\credential.json activeThumbprint is honoured"
    $sync["Requests"].Clear(); Reset-TokenState
    $tok = Get-AccessToken
    Assert-True ($tok -eq "mock-cert-token") "token returned from the certificate path"
    Assert-True ($sync["Requests"].Count -eq 1) "exactly one token request sent"
    $req = $sync["Requests"][0]
    Assert-True ($req.requestLine -eq "POST /$TenantId/oauth2/v2.0/token HTTP/1.1") "POST to /{tenant}/oauth2/v2.0/token (got '$($req.requestLine)')"
    Assert-True ($req.headers -match "(?im)^Content-Type:\s*application/x-www-form-urlencoded") "form-encoded body"
    $body = $req.body
    Assert-True ((Get-FormField $body "grant_type") -eq "client_credentials") "grant_type=client_credentials"
    Assert-True ((Get-FormField $body "client_assertion_type") -eq "urn:ietf:params:oauth:client-assertion-type:jwt-bearer") "client_assertion_type=jwt-bearer"
    Assert-True ((Get-FormField $body "client_id") -eq $ClientId) "client_id present"
    Assert-True ((Get-FormField $body "scope") -eq "$OrgUrl/.default") "scope={orgUrl}/.default"
    Assert-True ($null -eq (Get-FormField $body "client_secret")) "NO client_secret in the certificate request"
    $sentJwt = Get-FormField $body "client_assertion"
    Assert-True (Test-JwtSignature $sentJwt $cert) "sent assertion verifies with the certificate public key"
    Assert-True ((Get-JwtPart $sentJwt 1).aud -eq "$TokenAuthorityHost/$TenantId/oauth2/v2.0/token") "aud matches the endpoint actually posted to"
    Assert-True ($Global:CredentialTelemetry.lastMintMode -eq "certificate") "telemetry lastMintMode=certificate"
    Assert-True ($Global:CredentialTelemetry.fallbackCount -eq 0) "no fallback counted"
    $expectedExp = (Get-Date).ToUniversalTime().AddSeconds(3599 - 300)
    Assert-True ([Math]::Abs(($Global:TokenExpiresUtc - $expectedExp).TotalSeconds) -lt 10) "cache expiry = expires_in - 300s"
    $tok2 = Get-AccessToken
    Assert-True ($tok2 -eq "mock-cert-token" -and $sync["Requests"].Count -eq 1) "second call served from cache (no new request)"

    # ============================================================ T3: fallback to the secret on certificate failure
    Section "T3 certificate failure falls back to the client secret, loudly (MOCK endpoint)"
    $sync["CertResponse"] = @{ status = 401; body = '{"error":"invalid_client","error_description":"AADSTS700027: Client assertion contains an invalid signature. [Reason - The key was not found.]"}' }
    $Secret = "mock-secret-value"; $HasSecretCredential = $true
    $sync["Requests"].Clear(); $script:LogLines.Clear(); Reset-TokenState
    $tok = Acquire-Token
    Assert-True ($tok -eq "mock-secret-token") "token returned from the secret path"
    Assert-True ($sync["Requests"].Count -eq 2) "two requests: certificate attempt then secret attempt"
    Assert-True ($sync["Requests"][0].body.Contains("client_assertion=")) "first attempt was the certificate"
    Assert-True ((Get-FormField $sync["Requests"][1].body "client_secret") -eq "mock-secret-value") "second attempt carried the secret"
    Assert-True ($Global:CredentialTelemetry.lastMintMode -eq "secret") "telemetry lastMintMode=secret"
    Assert-True ($Global:CredentialTelemetry.fallbackCount -eq 1) "fallback counted"
    Assert-True (([string]$Global:CredentialTelemetry.lastCertError).Contains("AADSTS700027")) "lastCertError carries the AADSTS code"
    Assert-True ((($script:LogLines | Where-Object { $_ -match "^\[WARN\].*falling back" }) | Measure-Object).Count -eq 1) "fallback logged at WARN"
    Assert-True ((($script:LogLines | Where-Object { $_ -match "mock-secret-value" }) | Measure-Object).Count -eq 0) "secret value never logged"

    # ============================================================ T4: no fallback available -> hard failure
    Section "T4 certificate failure with no secret configured throws (nothing silently succeeds)"
    $Secret = $null; $HasSecretCredential = $false
    $sync["Requests"].Clear(); Reset-TokenState
    Assert-Throws { Acquire-Token } "HTTP 401.*AADSTS700027" "Acquire-Token throws with the HTTP status and AADSTS code"
    Assert-True ($null -eq $Global:AccessToken) "no token cached after failure"
    Assert-True ($sync["Requests"].Count -eq 1) "only the certificate attempt was made"

    # ============================================================ T5: secret-only bay (today's Bay 1) is unchanged
    Section "T5 secret-only configuration (no certificate) keeps the original client_secret request"
    Remove-Item -LiteralPath $CredentialStatePath -Force
    $CertThumbprintCfg = $null
    $Secret = "mock-secret-value"; $HasSecretCredential = $true
    $sync["Requests"].Clear(); Reset-TokenState
    $before = $Global:CredentialTelemetry.fallbackCount
    $tok = Get-AccessToken
    Assert-True ($tok -eq "mock-secret-token") "token from the secret path"
    Assert-True ($sync["Requests"].Count -eq 1 -and -not $sync["Requests"][0].body.Contains("client_assertion")) "single client_secret request, no assertion"
    Assert-True ((Get-FormField $sync["Requests"][0].body "grant_type") -eq "client_credentials" -and (Get-FormField $sync["Requests"][0].body "scope") -eq "$OrgUrl/.default") "secret request body unchanged"
    Assert-True ($Global:CredentialTelemetry.fallbackCount -eq $before) "not counted as a fallback"
    Assert-True ((Get-CredentialTelemetry).configuredMode -eq "secret") "telemetry configuredMode=secret"

    # ============================================================ T6: enroll is PENDING on a credentialed bay; activate proves first
    Section "T6 enroll -> pending; activate switches ONLY after a successful mint (MOCK endpoint)"
    $sync["CertResponse"] = @{ status = 401; body = '{"error":"invalid_client","error_description":"AADSTS700027: Client assertion contains an invalid signature. [Reason - The key was not found.]"}' }
    $enroll = Invoke-CredentialRotate ([pscustomobject]@{ action = "enroll"; validityDays = 45; subject = "CN=ABG-BayAgent credtest2 $BayId" })
    [void]$script:CreatedCerts.Add($enroll.thumbprint)
    Assert-True ($enroll.ok -and -not $enroll.activatedDirectly -and -not $enroll.reused) "enroll on a bay with a secret returns a PENDING certificate"
    Assert-True ((Get-PendingCertThumbprint) -eq $enroll.thumbprint) "state pendingThumbprint set"
    Assert-True ($null -eq (Get-ActiveCertThumbprint)) "active credential unchanged (none)"
    Assert-True ((Test-Path $enroll.publicCertPath) -and ([IO.File]::ReadAllBytes($enroll.publicCertPath).Length -gt 200)) "public .cer written to state\"
    $pub = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2 (,[Convert]::FromBase64String($enroll.publicCertBase64))
    Assert-True ($pub.Thumbprint -eq $enroll.thumbprint -and -not $pub.HasPrivateKey) "publicCertBase64 is the public half only"
    $again = Invoke-CredentialRotate ([pscustomobject]@{ action = "enroll" })
    Assert-True ($again.reused -and $again.thumbprint -eq $enroll.thumbprint) "a retried enroll is idempotent (returns the pending cert, no new key)"

    $stateBefore = Get-Content -LiteralPath $CredentialStatePath -Raw
    Assert-Throws { Invoke-CredentialRotate ([pscustomobject]@{ action = "activate" }) } "AADSTS700027" "activate FAILS when the pending certificate cannot mint"
    Assert-True ((Get-Content -LiteralPath $CredentialStatePath -Raw) -eq $stateBefore) "state untouched after failed activate"
    Assert-True ($null -eq (Get-ActiveCertThumbprint)) "active credential still unchanged"

    $test = Invoke-CredentialRotate ([pscustomobject]@{ action = "test"; includeSecret = $true })
    Assert-True (-not $test.ok -and -not $test.certificate.ok -and $test.secret.ok) "test reports certificate=fail, secret=ok while the key is unregistered"

    $sync["CertResponse"] = @{ status = 200; body = '{"token_type":"Bearer","expires_in":3599,"access_token":"mock-cert-token-2"}' }
    $Global:AccessToken = "stale-cached-token"; $Global:TokenExpiresUtc = (Get-Date).ToUniversalTime().AddMinutes(30)
    $act = Invoke-CredentialRotate ([pscustomobject]@{ action = "activate" })
    Assert-True ($act.ok -and $act.activeThumbprint -eq $enroll.thumbprint -and $act.proof.mintedWithCertificate) "activate succeeds after a live proof mint"
    Assert-True ((Get-ActiveCertThumbprint) -eq $enroll.thumbprint -and $null -eq (Get-PendingCertThumbprint)) "state: active=new, pending cleared"
    Assert-True ($null -eq $Global:AccessToken) "cached token dropped so the next loop mints with the new certificate"
    $sync["Requests"].Clear()
    $tok = Get-AccessToken
    Assert-True ($tok -eq "mock-cert-token-2") "next mint uses the certificate"
    $sentJwt = Get-FormField $sync["Requests"][0].body "client_assertion"
    Assert-True ((Get-JwtPart $sentJwt 0).x5t -eq (ConvertTo-Base64Url ([System.Security.Cryptography.SHA1]::Create().ComputeHash($pub.RawData)))) "assertion signed by the NEW certificate"

    # ============================================================ T7: retire guards
    Section "T7 retire never removes the active credential; secret retire needs a live certificate proof"
    Assert-Throws { Invoke-CredentialRotate ([pscustomobject]@{ action = "retire"; thumbprint = $enroll.thumbprint }) } "ACTIVE credential" "retiring the active certificate is refused"
    $dpapiFile = Join-Path $BaseDir "secrets\clientsecret.dpapi"
    New-Item -ItemType Directory -Force -Path (Split-Path $dpapiFile) | Out-Null
    [IO.File]::WriteAllBytes($dpapiFile, [byte[]](1, 2, 3))
    $Secret = $null; $SecretPath = $dpapiFile; $SecretPathCfg = $dpapiFile; $HasSecretCredential = $true
    $sync["CertResponse"] = @{ status = 401; body = '{"error":"invalid_client","error_description":"AADSTS700027: key not found"}' }
    Assert-Throws { Invoke-CredentialRotate ([pscustomobject]@{ action = "retire"; secret = $true }) } "AADSTS700027" "secret retire refused while the active certificate cannot mint"
    Assert-True (Test-Path $dpapiFile) "DPAPI file untouched after refused retire"
    $sync["CertResponse"] = @{ status = 200; body = '{"token_type":"Bearer","expires_in":3599,"access_token":"mock-cert-token-2"}' }
    # $cert is only retirable because the agent RECORDED it. In a real rotation Invoke-CredentialActivate
    # writes previousThumbprint as it switches; this section reached T6 with no active certificate, so that
    # never happened and the record has to be made here. Before F3 this line was unnecessary -- the ownership
    # guard accepted $cert on its SUBJECT alone, which is the hole F3 closed (see T17).
    Update-CredentialState @{ previousThumbprint = $cert.Thumbprint } | Out-Null
    Assert-True ((Test-IsAgentOwnedCertificate -Thumbprint $cert.Thumbprint) -eq $true) "a recorded previous certificate is retirable"
    $ret = Invoke-CredentialRotate ([pscustomobject]@{ action = "retire"; secret = $true; thumbprint = $cert.Thumbprint })
    Assert-True ($ret.ok -and $ret.secret.dpapiFileRemoved -and -not (Test-Path $dpapiFile)) "secret retired after a live certificate proof"
    Assert-True ($null -eq $SecretPath -and -not $HasSecretCredential) "in-memory fallback cleared"
    Assert-True ($ret.certificate.wasInStore -and $null -eq (Get-ChildItem "Cert:\CurrentUser\My\$($cert.Thumbprint)" -ErrorAction SilentlyContinue)) "old certificate removed from the store"
    # Read through Get-PropValue, not as a direct property. Under Set-StrictMode -Version Latest a MISSING
    # property is a terminating PropertyNotFoundStrict error, not $null -- so when mutation M25 removed the
    # `$changes.retiredThumbprints = $retired` line, this assertion did not FAIL, it took the whole suite
    # down. The harness then scored the crash as "caught", which made an unasserted behavior look pinned.
    # A test that cannot fail cleanly cannot report what it found.
    Assert-True (@(Get-PropValue (Read-CredentialState) "retiredThumbprints" @()) -contains $cert.Thumbprint) "state records the retired thumbprint"
    [void]$script:CreatedCerts.Remove($cert.Thumbprint)

    # ============================================================ T8: telemetry / capabilities payload
    Section "T8 telemetry is JSON-safe and carries no secret"
    $Secret = "mock-secret-value"; $HasSecretCredential = $true
    $tele = Get-CredentialTelemetry
    $json = $tele | ConvertTo-Json -Depth 6 -Compress
    Assert-True ($json.Length -gt 50 -and -not $json.Contains("mock-secret-value")) "capabilities credential block serialises without the secret value"
    Assert-True ($tele.plaintextSecretPresent -eq $true -and $tele.secretConfigured -eq "plaintext") "plaintext secret is FLAGGED in telemetry"
    Assert-True ($tele.activeCertificate.found -and $tele.activeCertificate.daysToExpiry -ge 44 -and $tele.activeCertificate.daysToExpiry -le 45) "active certificate expiry surfaced (daysToExpiry=$($tele.activeCertificate.daysToExpiry))"
    $status = Invoke-CredentialRotate ([pscustomobject]@{ action = "status" })
    Assert-True ($status.ok -and (@($status.certificates | Where-Object { $_.thumbprint -eq $enroll.thumbprint })).Count -eq 1) "status lists the bay certificate"
    Assert-Throws { Invoke-CredentialRotate ([pscustomobject]@{ action = "bogus" }) } "unknown action" "unknown action is rejected"

    # ============================================================ T9: startup rules
    Section "T9 startup fail-fast: missing DPAPI file is fatal only when the secret is the ONLY credential"
    $missing = Join-Path $BaseDir "secrets\gone.dpapi"
    $Secret = $null; $SecretPath = $missing; $SecretPathCfg = $missing; $HasSecretCredential = $true
    $script:LogLines.Clear()
    Write-CredentialStartupSummary
    Assert-True ($null -eq $SecretPath -and -not $HasSecretCredential) "with a certificate active: missing DPAPI file downgraded to certificate-only"
    Assert-True ((($script:LogLines | Where-Object { $_ -match "^\[WARN\].*file is missing" }) | Measure-Object).Count -eq 1) "...and logged at WARN"
    Assert-True ((($script:LogLines | Where-Object { $_ -match "^\[INFO\] Auth mode: CERTIFICATE" }) | Measure-Object).Count -eq 1) "startup names the certificate mode"
    Remove-Item -LiteralPath $CredentialStatePath -Force
    $SecretPath = $missing; $SecretPathCfg = $missing; $HasSecretCredential = $true
    Assert-Throws { Write-CredentialStartupSummary } "file not found" "with NO certificate: missing DPAPI file is fatal (original behaviour)"

    # ============================================================ T10: -EnrollCert semantics on a bay with no credential
    Section "T10 enroll on a bay with NO credential at all activates directly (Day-0)"
    $Secret = $null; $SecretPath = $null; $SecretPathCfg = $null; $HasSecretCredential = $false; $CertThumbprintCfg = $null
    $day0 = Invoke-CredentialEnroll @{ validityDays = 40; force = $true; subject = "CN=ABG-BayAgent credtest3 $BayId" }
    [void]$script:CreatedCerts.Add($day0.thumbprint)
    Assert-True ($day0.activatedDirectly -and (Get-ActiveCertThumbprint) -eq $day0.thumbprint) "no prior credential: enrolled certificate becomes active immediately"

    # ============================================================ T12 the enroll result must survive build_resultjson
    Section "T12 command results always fit build_resultjson (Memo, MaxLength 2000)"

    # Small results are passed through byte-for-byte - the guard must not disturb the normal path.
    $small = [ordered]@{ ok = $true; action = "status"; note = "tiny" }
    $smallJson = Limit-ResultJson -ResultObj $small
    Assert-True ($smallJson -eq ($small | ConvertTo-Json -Depth 10 -Compress)) "a small result is unchanged by the guard"
    Assert-True ($smallJson -notmatch "resultTrimmed") "a small result is not marked trimmed"

    # A REAL enroll result at the default key length must fit with room to spare.
    $sizeCert = New-BayClientCertificate -Subject "CN=ABG-BayAgent 44d35503-6d63-f011-bec2-0022480b527b" -ValidityDays 730 -Store "CurrentUser" -KeyLength 2048
    [void]$script:CreatedCerts.Add($sizeCert.Thumbprint)
    $enrollRes = Build-CredentialEnrollResult -cert $sizeCert -cerPath "C:\AllBirdies\BayAgent\state\bay-cert-$($sizeCert.Thumbprint).cer" -reused $false -activatedDirectly $false
    $rawLen = (($enrollRes | ConvertTo-Json -Depth 10 -Compress)).Length
    $enrollJson = Limit-ResultJson -ResultObj $enrollRes
    Write-Host ("  enroll result RSA2048: raw={0} chars, stored={1} chars, cap={2}" -f $rawLen, $enrollJson.Length, $ResultJsonMaxChars)
    Assert-True ($rawLen -le $ResultJsonMaxChars) "RSA2048 enroll result fits build_resultjson untrimmed ($rawLen chars)"
    Assert-True ($enrollJson -eq ($enrollRes | ConvertTo-Json -Depth 10 -Compress)) "...so the guard leaves it alone"
    $back = $enrollJson | ConvertFrom-Json
    Assert-True ($back.publicCertBase64 -eq [Convert]::ToBase64String($sizeCert.RawData)) "the public certificate survives the round trip intact"

    # 4096 is refused up front, and the refusal says WHY (this is the regression that matters: without the
    # message the next person just widens the allow-list and reintroduces a result that cannot be returned).
    Assert-Throws { New-BayClientCertificate -Subject "CN=ABG-BayAgent test" -KeyLength 4096 } "build_resultjson" `
        "keyLength 4096 is refused because its public cert cannot be returned in build_resultjson"
    Assert-Throws { New-BayClientCertificate -Subject ("CN=" + ("x" * 200)) -KeyLength 2048 } "120 characters" `
        "an over-long subject is refused before it can eat the result budget"

    # An over-cap result is TRIMMED, never dropped and never silently mangled: the key material and the
    # identity survive, and the result says what was removed.
    $fat = [ordered]@{
        ok = $true; action = "enroll"; reused = $false; activatedDirectly = $false
        thumbprint = $sizeCert.Thumbprint
        subject = $sizeCert.Subject; store = "CurrentUser\My"
        notBeforeUtc = "2026-08-29T00:00:00Z"; notAfterUtc = "2028-08-28T00:00:00Z"
        publicCertBase64 = [Convert]::ToBase64String($sizeCert.RawData)
        publicCertPath = "C:\AllBirdies\BayAgent\state\bay-cert-x.cer"
        next = ("N" * 600)
    }
    $fatRaw = (($fat | ConvertTo-Json -Depth 10 -Compress)).Length
    $fatJson = Limit-ResultJson -ResultObj $fat
    $fatBack = $fatJson | ConvertFrom-Json
    Assert-True ($fatRaw -gt $ResultJsonMaxChars) "the oversized fixture really is over the cap ($fatRaw chars)"
    Assert-True ($fatJson.Length -le $ResultJsonMaxChars) "trimmed result fits the column ($($fatJson.Length) chars)"
    Assert-True ($fatBack.publicCertBase64 -eq [Convert]::ToBase64String($sizeCert.RawData)) "the public certificate is preserved while prose is dropped"
    Assert-True ($fatBack.thumbprint -eq $sizeCert.Thumbprint) "the thumbprint is preserved"
    Assert-True ($fatBack.resultTrimmed -eq $true) "the result is FLAGGED as trimmed (a reader cannot mistake it for complete)"
    Assert-True ($fatBack.resultDroppedKeys -match "next") "the dropped keys are named"

    # A result that cannot fit even after pruning says so instead of shipping a half certificate.
    $huge = [ordered]@{ ok = $true; action = "enroll"; thumbprint = $sizeCert.Thumbprint; publicCertBase64 = ("A" * 2500) }
    $hugeBack = (Limit-ResultJson -ResultObj $huge) | ConvertFrom-Json
    Assert-True ($null -eq $hugeBack.publicCertBase64) "an unfittable certificate is nulled, not half-written"
    Assert-True ([string]$hugeBack.publicCertBase64Omitted -match "bay-cert") "...and the result points at the on-disk copy"

    # Strings (the legacy result shape) are truncated, not passed through over-length.
    $strOut = Limit-ResultJson -ResultObj ("z" * 5000)
    Assert-True ($strOut.Length -le $ResultJsonMaxChars) "an over-long string result is truncated to the cap"
    Assert-True ($strOut.EndsWith("...[truncated]")) "...and marked as truncated"

    # ============================================================ T13 payload boundary (security review, 2026-08-29)
    Section "T13 the CredentialRotate PAYLOAD cannot reach past the credential it manages"

    # retire is the only DESTRUCTIVE action and its thumbprint is caller-supplied. A certificate this agent
    # did not create and has not recorded must be untouchable - otherwise the payload is a
    # delete-any-private-key primitive aimed at the bay's certificate stores.
    $foreign = New-SelfSignedCertificate -Type Custom -Subject "CN=Some Other Thing" -CertStoreLocation "Cert:\CurrentUser\My" -KeyAlgorithm RSA -KeyLength 2048 -HashAlgorithm sha256 -KeyExportPolicy NonExportable -KeyUsage DigitalSignature -NotAfter (Get-Date).AddDays(60) -FriendlyName "credtest foreign"
    [void]$script:CreatedCerts.Add($foreign.Thumbprint)
    Assert-True (-not (Test-IsAgentOwnedCertificate -Thumbprint $foreign.Thumbprint)) "a non-ABG certificate is not agent-owned"
    Assert-Throws { Invoke-CredentialRetire @{ thumbprint = $foreign.Thumbprint } } "not an agent-owned certificate" `
        "retire REFUSES a certificate this agent did not create"
    Assert-True (Test-Path -LiteralPath "Cert:\CurrentUser\My\$($foreign.Thumbprint)") "...and the foreign certificate is still in the store"

    # The positive half: an agent-RECORDED certificate IS retirable, so the guard has not simply disabled retire.
    # ⚠️ This used to assert that the SUBJECT alone made a certificate agent-owned. It no longer does, and that
    # is the F3 fix: a subject is chosen by whoever creates the certificate, so trusting it re-opened the
    # delete-any-private-key primitive in weaker form. T17 pins the refusal; this pins that the record still works.
    $ownDead = New-BayClientCertificate -Subject "CN=ABG-BayAgent retire-me" -ValidityDays 60 -Store "CurrentUser" -KeyLength 2048
    [void]$script:CreatedCerts.Add($ownDead.Thumbprint)
    Assert-True ((Test-IsAgentOwnedCertificate -Thumbprint $ownDead.Thumbprint) -eq $false) "an ABG-subjected certificate is NOT agent-owned on its subject alone"
    Update-CredentialState @{ previousThumbprint = $ownDead.Thumbprint } | Out-Null
    Assert-True (Test-IsAgentOwnedCertificate -Thumbprint $ownDead.Thumbprint) "...but a RECORDED certificate is agent-owned"
    $retOwn = Invoke-CredentialRetire @{ thumbprint = $ownDead.Thumbprint }
    Assert-True ($retOwn.ok -eq $true) "retire still works on an agent-owned certificate"
    Assert-True (-not (Test-Path -LiteralPath "Cert:\CurrentUser\My\$($ownDead.Thumbprint)")) "...and it is actually gone"

    # keyProvider reaches New-SelfSignedCertificate -Provider from the payload. Closed set, not free text.
    Assert-Throws { New-BayClientCertificate -Subject "CN=ABG-BayAgent x" -KeyProvider "Some Arbitrary Provider" } "keyProvider must be" `
        "an arbitrary keyProvider string is refused"

    # THE ONE THAT MATTERS MOST: no payload field can move the token endpoint. The authority comes from
    # agent-config.json only, so a command cannot point the bay at credential material the caller controls.
    $sync["Requests"].Clear(); Reset-TokenState
    $sync["CertResponse"] = @{ status = 200; body = '{"access_token":"tok-authority","expires_in":3600,"token_type":"Bearer"}' }
    $poison = @{ action = "test"; thumbprint = $day0.thumbprint; tokenAuthorityHost = "http://127.0.0.1:9/evil"; authority = "http://evil.invalid"; url = "http://evil.invalid"; tokenUrl = "http://evil.invalid"; scope = "http://evil.invalid/.default" }
    $poisonRes = Invoke-CredentialRotate $poison
    Assert-True ($poisonRes.certificate.ok -eq $true) "a payload stuffed with authority/url fields still mints"
    Assert-True (@($sync["Requests"]).Count -eq 1) "...and it made exactly one token request"
    $preq = $sync["Requests"][0]
    Assert-True ($preq.requestLine -eq "POST /$TenantId/oauth2/v2.0/token HTTP/1.1") "...to the CONFIGURED authority path, not one named in the payload (got '$($preq.requestLine)')"
    Assert-True ($preq.headers -notmatch "evil") "...no payload-supplied host reached the request headers"
    Assert-True ($preq.body -notmatch "evil") "...and no payload-supplied value reached the request body"
    Assert-True ((Get-FormField $preq.body "scope") -eq "$OrgUrl/.default") "...the scope is still the CONFIGURED org, not the payload's"

    # ============================================================ T14 enrollment input bounds + durable fallback count
    Section "T14 enrollment input bounds are pinned, and the fallback count survives a restart"

    # Same class of caller-supplied input as keyLength, which is already refused. Pin the rest of the bounds so
    # a later edit cannot quietly widen them.
    Assert-Throws { New-BayClientCertificate -Subject "CN=ABG-BayAgent b" -ValidityDays 29 } "validityDays must be between 30 and 1825" `
        "validityDays below the floor is refused"
    Assert-Throws { New-BayClientCertificate -Subject "CN=ABG-BayAgent b" -ValidityDays 1826 } "validityDays must be between 30 and 1825" `
        "validityDays above the ceiling is refused"
    Assert-Throws { New-BayClientCertificate -Subject "CN=ABG-BayAgent b" -Store "Bogus" } "store must be CurrentUser or LocalMachine" `
        "an unknown certificate store is refused"
    Assert-Throws { Invoke-CredentialEnroll @{ store = "\attacker\share" } } "store must be CurrentUser or LocalMachine" `
        "...including when it arrives through the CredentialRotate payload"

    # THE POINT: a bay whose certificate fails every loop, running on the secret, must not be able to hide that
    # by restarting. The Host Watchdog restarts the agent routinely, so an in-memory-only counter reads zero on
    # a bay that has been silently falling back for days.
    # Start from a clean slate on BOTH halves: the durable total AND the flush watermark. Earlier tests
    # (T3 exercises the fallback path) have already advanced both, and setting fallbackCount absolutely
    # without resetting fallbackFlushed would measure a delta, not a total.
    Update-CredentialState @{ fallbackCountTotal = 0 } | Out-Null
    Reset-TelemetryAsIfRestarted
    $Global:CredentialTelemetry.fallbackCount = 3
    $Global:CredentialTelemetry.lastFallbackUtc = "2026-08-29T12:00:00Z"
    $tel1 = Get-CredentialTelemetry
    Assert-True ($tel1.fallbackCountTotal -eq 3) "three fallbacks are folded into the durable total"
    Assert-True ($tel1.fallbackCount -eq 3) "...and the session counter still reports this process"

    $tel2 = Get-CredentialTelemetry
    Assert-True ($tel2.fallbackCountTotal -eq 3) "flushing twice does NOT double-count (the flush is idempotent)"

    Reset-TelemetryAsIfRestarted
    $tel3 = Get-CredentialTelemetry
    Assert-True ($tel3.fallbackCount -eq 0) "after a restart the SESSION counter is zero, as it must be"
    Assert-True ($tel3.fallbackCountTotal -eq 3) "...but the DURABLE total survives the restart - the bay cannot hide it"
    Assert-True ([string](Get-PropValue (Read-CredentialState) "lastFallbackUtc" "") -eq "2026-08-29T12:00:00Z") `
        "...and WHEN it last fell back is on disk too, so the monitor can age it"

    $Global:CredentialTelemetry.fallbackCount = 2
    $tel4 = Get-CredentialTelemetry
    Assert-True ($tel4.fallbackCountTotal -eq 5) "post-restart fallbacks ACCUMULATE onto the durable total (3 + 2)"
    $stTotal = [int](Get-PropValue (Read-CredentialState) "fallbackCountTotal" 0)
    Assert-True ($stTotal -eq 5) "...and the total is actually on disk in credential.json, not just in memory"

    # ============================================================ T15 (F1): retire secret=true must NOT report success
    # while a PLAINTEXT clientSecret is still in agent-config.json and still mints a token.
    Section "T15 (F1) retire secret=true refuses to report success while a plaintext secret survives"
    Remove-Item -LiteralPath $CredentialStatePath -Force -ErrorAction SilentlyContinue
    $f1cert = New-BayClientCertificate -Subject "CN=ABG-BayAgent f1-$([guid]::NewGuid().ToString('N').Substring(0,8))" -ValidityDays 60 -Store "CurrentUser"
    [void]$script:CreatedCerts.Add($f1cert.Thumbprint)
    Update-CredentialState @{ activeThumbprint = $f1cert.Thumbprint } | Out-Null
    $CertThumbprintCfg = $null
    $Secret = "plaintext-secret-that-still-works"; $SecretPath = $null; $SecretPathCfg = $null; $HasSecretCredential = $true
    $sync["CertResponse"] = @{ status = 200; body = '{"token_type":"Bearer","expires_in":3599,"access_token":"mock-f1"}' }
    $f1 = Invoke-CredentialRotate ([pscustomobject]@{ action = "retire"; secret = $true })
    Assert-True ($f1.ok -eq $false) "a plaintext secret that survives the retire makes the RESULT NOT ok (it still mints a token)"
    Assert-True (@($f1.secret.Keys) -contains "plaintextSecretStillInConfig" -and $f1.secret.plaintextSecretStillInConfig -eq $true) `
        "...and plaintextSecretStillInConfig is stated explicitly, not implied by a note"
    Assert-True (@($f1.secret.Keys) -contains "dpapiFileRemoved" -and $f1.secret.dpapiFileRemoved -eq $false) `
        "...and dpapiFileRemoved is stated explicitly even when there was no DPAPI file"
    Assert-True ("$(Get-PropValue $f1.secret 'reason' '')" -match "PLAINTEXT") "...and carries a coded reason naming the plaintext secret"
    # The clean case still reports ok, so the guard is not simply always-false.
    $Secret = $null; $HasSecretCredential = $false
    $f1b = Invoke-CredentialRotate ([pscustomobject]@{ action = "retire"; secret = $true })
    Assert-True ($f1b.ok -eq $true -and $f1b.secret.plaintextSecretStillInConfig -eq $false) "with no plaintext secret the same call reports ok (the guard is not always-false)"

    # ============================================================ T16 (F2): a corrupt credential.json must never be
    # silently rewritten -- that would permanently zero activeThumbprint / retiredThumbprints / fallbackCountTotal.
    Section "T16 (F2) a truncated credential.json fails CLOSED and is never overwritten"
    Update-CredentialState @{ activeThumbprint = $f1cert.Thumbprint; fallbackCountTotal = 17; retiredThumbprints = @("AAAA") } | Out-Null
    $goodBytes = [IO.File]::ReadAllBytes($CredentialStatePath)
    Assert-True (Test-Path "$CredentialStatePath.bak") "every write leaves a .bak behind"
    # Truncate it the way a power cut would.
    $truncated = '{"activeThumbprint":"' + $f1cert.Thumbprint + '","fallbackCountT'
    [IO.File]::WriteAllText($CredentialStatePath, $truncated, (New-Object Text.UTF8Encoding($false)))
    $script:LogLines.Clear()
    $readBack = Read-CredentialState
    Assert-True ($null -eq $readBack) "a corrupt state file reads as no-state so the agent can still run on what it can prove"
    Assert-True ((($script:LogLines | Where-Object { $_ -match "^\[ERROR\].*corrupt" }) | Measure-Object).Count -ge 1) `
        "...and it is logged at ERROR, not WARN -- this is not a routine absence"
    Assert-Throws { Update-CredentialState @{ pendingThumbprint = $f1cert.Thumbprint } } "corrupt" `
        "a write over a corrupt state file is REFUSED"
    Assert-True ([IO.File]::ReadAllText($CredentialStatePath) -eq $truncated) `
        "...and the corrupt file is left exactly as it was, so it can still be recovered by hand"
    $telC = Get-CredentialTelemetry
    Assert-True ($telC.stateFileCorrupt -eq $true) "the heartbeat SURFACES the corruption (a silent corrupt state is the whole failure mode)"
    # ⚠️ THE GATE UNDER THE IRREVERSIBLE STEP. KH-18 step 8 is unlocked by an operator reading
    # fallbackCountTotal and seeing zero. A corrupt state file must therefore NOT render as zero -- that is
    # the one value that would let corruption unlock the estate's only irreversible act.
    Assert-True ($null -eq $telC.fallbackCountTotal) "a corrupt state file reports the durable total as UNKNOWN, never as a clean zero"
    Assert-True ((($script:LogLines | Where-Object { $_ -match "^\[ERROR\].*UNKNOWN" }) | Measure-Object).Count -ge 1) `
        "...and says so at ERROR, naming the retirement gate"
    # Recovering by hand from the .bak restores the numbers the truncation would have zeroed.
    [IO.File]::WriteAllBytes($CredentialStatePath, $goodBytes)
    Assert-True ([int](Get-PropValue (Read-CredentialState) "fallbackCountTotal" 0) -eq 17) "after recovery the durable total is intact (it was never zeroed)"
    Assert-True ((Get-CredentialTelemetry).stateFileCorrupt -eq $false) "...and the corruption flag clears once the file parses again"

    # ============================================================ T17 (F3): the ownership guard must not trust a SUBJECT
    # STRING. Anyone who can create a certificate can choose its subject.
    Section "T17 (F3) retire refuses an ABG-subjected certificate this agent never recorded"
    $imposter = New-SelfSignedCertificate -Type Custom -Subject "CN=ABG-BayAgent imposter" -CertStoreLocation "Cert:\CurrentUser\My" `
        -KeyAlgorithm RSA -KeyLength 2048 -HashAlgorithm sha256 -KeyExportPolicy NonExportable -KeyUsage DigitalSignature `
        -NotAfter (Get-Date).AddDays(60)
    [void]$script:CreatedCerts.Add($imposter.Thumbprint)
    Assert-True ((Test-IsAgentOwnedCertificate -Thumbprint $imposter.Thumbprint) -eq $false) `
        "a certificate whose SUBJECT merely looks like ours is NOT agent-owned (the subject is caller-chosen)"
    Assert-Throws { Invoke-CredentialRotate ([pscustomobject]@{ action = "retire"; thumbprint = $imposter.Thumbprint }) } "not an agent-owned" `
        "retire refuses it"
    Assert-True ($null -ne (Get-ChildItem "Cert:\CurrentUser\My\$($imposter.Thumbprint)" -ErrorAction SilentlyContinue)) `
        "...and the certificate is still in the store"
    # A certificate this agent actually recorded IS retirable -- the guard is not simply always-false.
    Update-CredentialState @{ previousThumbprint = $imposter.Thumbprint } | Out-Null
    Assert-True ((Test-IsAgentOwnedCertificate -Thumbprint $imposter.Thumbprint) -eq $true) "a RECORDED thumbprint is agent-owned"
    Update-CredentialState @{ previousThumbprint = $null } | Out-Null

    # ============================================================ T18 (F4): a combined {thumbprint, secret:true} payload
    # must prove the certificate mints BEFORE it destroys anything. There is no rollback for a deleted private key.
    Section "T18 (F4) a combined retire proves first and deletes after -- a failed proof destroys nothing"
    $f4old = New-BayClientCertificate -Subject "CN=ABG-BayAgent f4old-$([guid]::NewGuid().ToString('N').Substring(0,8))" -ValidityDays 60 -Store "CurrentUser"
    [void]$script:CreatedCerts.Add($f4old.Thumbprint)
    $f4dpapi = Join-Path $BaseDir "secrets\f4.dpapi"
    New-Item -ItemType Directory -Force -Path (Split-Path $f4dpapi) | Out-Null
    [IO.File]::WriteAllBytes($f4dpapi, [byte[]](9, 9, 9))
    Update-CredentialState @{ activeThumbprint = $f1cert.Thumbprint; previousThumbprint = $f4old.Thumbprint } | Out-Null
    $Secret = $null; $SecretPath = $f4dpapi; $SecretPathCfg = $f4dpapi; $HasSecretCredential = $true
    $sync["CertResponse"] = @{ status = 401; body = '{"error":"invalid_client","error_description":"AADSTS700027: key not found"}' }
    Assert-Throws { Invoke-CredentialRotate ([pscustomobject]@{ action = "retire"; thumbprint = $f4old.Thumbprint; secret = $true }) } "AADSTS700027" `
        "the combined retire fails on the live proof"
    Assert-True ($null -ne (Get-ChildItem "Cert:\CurrentUser\My\$($f4old.Thumbprint)" -ErrorAction SilentlyContinue)) `
        "...and the certificate was NOT deleted first (no rollback exists for a destroyed private key)"
    Assert-True (Test-Path $f4dpapi) "...and the DPAPI secret is untouched"
    # With a working proof the same call does both, in one go.
    $sync["CertResponse"] = @{ status = 200; body = '{"token_type":"Bearer","expires_in":3599,"access_token":"mock-f4"}' }
    $f4 = Invoke-CredentialRotate ([pscustomobject]@{ action = "retire"; thumbprint = $f4old.Thumbprint; secret = $true })
    Assert-True ($f4.ok -and $f4.certificate.wasInStore -and -not (Test-Path $f4dpapi)) "with a valid proof the same call retires both"
    [void]$script:CreatedCerts.Remove($f4old.Thumbprint)

    # ============================================================ T19 (F5): superseding a pending certificate must record
    # the thumbprint it replaced, or the old private key is orphaned on the machine with nothing pointing at it.
    Section "T19 (F5) a superseded pending certificate is recorded, and force is not the default"
    Remove-Item -LiteralPath $CredentialStatePath -Force -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath "$CredentialStatePath.bak" -Force -ErrorAction SilentlyContinue
    Update-CredentialState @{ activeThumbprint = $f1cert.Thumbprint } | Out-Null
    $Secret = $null; $SecretPath = $null; $SecretPathCfg = $null; $HasSecretCredential = $false
    $e1 = Invoke-CredentialEnroll @{ validityDays = 60 }
    [void]$script:CreatedCerts.Add($e1.thumbprint)
    $e1again = Invoke-CredentialEnroll @{ validityDays = 60 }
    Assert-True ($e1again.reused -eq $true -and $e1again.thumbprint -eq $e1.thumbprint) "without force, a repeated enroll REUSES the pending certificate (it does not mint another key)"
    $e2 = Invoke-CredentialEnroll @{ validityDays = 60; force = $true }
    [void]$script:CreatedCerts.Add($e2.thumbprint)
    Assert-True ($e2.thumbprint -ne $e1.thumbprint) "force mints a new one"
    $sup = @(Get-PropValue (Read-CredentialState) "superseded" @())
    Assert-True ($sup -contains $e1.thumbprint) "...and the SUPERSEDED thumbprint is recorded, so its orphaned private key can still be found and retired"
    Assert-True ((Test-IsAgentOwnedCertificate -Thumbprint $e1.thumbprint) -eq $true) "...which also makes the superseded certificate retirable"

    # ============================================================ T20 (F7): a fleet update that dies before it installs
    # must not report Succeeded. The bench-day failure is a bay PC with no code-signing certificate.
    Section "T20 (F7) a failed update is recorded durably instead of reporting Succeeded"
    $f7base = Join-Path $BaseDir "f7"
    New-Item -ItemType Directory -Force -Path $f7base | Out-Null
    # Resolved from the REPO, never from -AgentScript. The mutation harness points -AgentScript at a lone
    # mutated copy of BayAgent.ps1 in a temp folder with no tools\ beside it; resolving relatively there made
    # this section explode and every single mutant register as "CRASH", which silently hid whether the suite
    # actually catches anything. The updater is not the thing under mutation.
    $updater = Join-Path $PSScriptRoot "..\src\BayAgent\tools\Update-BayAgent.ps1"
    Assert-True (Test-Path $updater) "the updater is where the package puts it"
    $updater = (Resolve-Path $updater).Path
    # A Dataverse URL is refused by name, which is the cheapest way to make the updater die early.
    # The updater writes its refusal to stderr and exits non-zero; with $ErrorActionPreference=Stop that would
    # abort the test harness itself, so the child is run with its own preference and its streams swallowed.
    $prevEap = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    try {
        & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $updater -Version "9.9.9" `
            -PackageUrl "https://builds-apps-dev.crm.dynamics.com/api/data/v9.2/build_fleetreleases(x)/build_packagefile/value" `
            -Sha256 ("0" * 64) -BaseDir $f7base 2>&1 | Out-Null
    } catch { }
    $ErrorActionPreference = $prevEap
    $marker = Join-Path $f7base "state\last-update-result.json"
    Assert-True (Test-Path $marker) "a failed update writes a durable result marker"
    # Guarded. An unguarded Get-Content here turns ONE failed assertion into a dead suite: under a mutant
    # that stops the marker being written, Test-Path fails, this line throws on a file that is not there,
    # and the five sections after it never run. MEASURED: that cost five sections of coverage under the
    # crash mutants. A test that cannot fail cleanly cannot report what it found -- fourth instance of the
    # same shape in this file (see also M25's property read, T24, T26).
    $mk = $null
    if (Test-Path $marker) { try { $mk = Get-Content -LiteralPath $marker -Raw | ConvertFrom-Json } catch { } }
    Assert-True ($null -ne $mk -and $mk.ok -eq $false) "...saying it FAILED"
    Assert-True ($null -ne $mk -and "$($mk.reason)" -match "Dataverse") "...and why, in the reason"
    $f7log = @(Get-ChildItem (Join-Path $f7base "logs") -Filter *.log -ErrorAction SilentlyContinue)
    $f7logText = ""
    if ($f7log.Count -ge 1) { try { $f7logText = (Get-Content $f7log[0].FullName -Raw) } catch { } }
    Assert-True ($f7log.Count -ge 1 -and ($f7logText -match "UPDATE FAILED")) `
        "...and the failure reaches the log, which it did not before (Get-CodeSigningCert threw into silence)"
    Assert-True ((Read-LastUpdateResult -Base $f7base).ok -eq $false) "the agent can read the marker back for the heartbeat"
    # A missing executable is refused up front and always was -- that check is correct and is pinned here so
    # the F7 change cannot be mistaken for having weakened it.
    Assert-Throws { Start-GenericProcess ([pscustomobject]@{ path = "C:\definitely\not\here\nope.exe" }) } "Executable not found" `
        "StartProcess still refuses a path that does not exist"
    # The gap was a file that EXISTS but cannot be launched: Start-Process threw, and the throw escaped as an
    # opaque command failure rather than a result saying the process never ran.
    $unlaunchable = Join-Path $BaseDir "not-a-program.abgnope"
    [IO.File]::WriteAllText($unlaunchable, "this is not an executable")
    $bad = Start-GenericProcess ([pscustomobject]@{ path = $unlaunchable })
    Assert-True ($bad.started -eq $false -and "$($bad.error)".Length -gt 0) "StartProcess reports started=false with a reason when the launch itself fails"
    Assert-True ((($script:LogLines | Where-Object { $_ -match "^\[ERROR\] StartProcess FAILED to launch" }) | Measure-Object).Count -ge 1) `
        "...and says so in the log"
    # And a launch that DOES work still says started=true, flagged as a launch rather than a completion.
    $good = Start-GenericProcess ([pscustomobject]@{ path = "C:\Windows\System32\cmd.exe"; args = "/c exit 0" })
    Assert-True ($good.started -eq $true -and $good.launchedOnly -eq $true) "a real launch reports started=true, labelled launchedOnly (it does not claim the work succeeded)"

    # ============================================================ T21 (F9): the Day-0 trap. A shipped config names a DPAPI
    # path whose file does not exist; the bay has no usable credential at all, so enroll must ACTIVATE, not go pending.
    Section "T21 (F9) enroll reads ACTUAL credential availability, not the config's claim"
    Remove-Item -LiteralPath $CredentialStatePath -Force -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath "$CredentialStatePath.bak" -Force -ErrorAction SilentlyContinue
    $ghost = Join-Path $BaseDir "secrets\never-created.dpapi"
    $Secret = $null; $SecretPath = $ghost; $SecretPathCfg = $ghost; $HasSecretCredential = $true
    $CertThumbprintCfg = $null
    $day0b = Invoke-CredentialEnroll @{ validityDays = 60 }
    [void]$script:CreatedCerts.Add($day0b.thumbprint)
    Assert-True ($day0b.activatedDirectly -eq $true) "a config that NAMES a DPAPI file which does not exist is not a credential; the new certificate activates"
    Assert-True ((Get-ActiveCertThumbprint) -eq $day0b.thumbprint) "...and it is the active credential"
    $script:LogLines.Clear()
    Write-CredentialStartupSummary
    Assert-True ((($script:LogLines | Where-Object { $_ -match "^\[INFO\] Auth mode: CERTIFICATE" }) | Measure-Object).Count -eq 1) `
        "...so startup no longer throws on the missing DPAPI file (the Day-0 trap is closed end to end)"
    # And a DPAPI file that DOES exist still counts as a credential, so enroll still goes pending.
    Remove-Item -LiteralPath $CredentialStatePath -Force -ErrorAction SilentlyContinue
    $realDpapi = Join-Path $BaseDir "secrets\real.dpapi"
    [IO.File]::WriteAllBytes($realDpapi, [byte[]](4, 5, 6))
    $Secret = $null; $SecretPath = $realDpapi; $SecretPathCfg = $realDpapi; $HasSecretCredential = $true
    $pend = Invoke-CredentialEnroll @{ validityDays = 60 }
    [void]$script:CreatedCerts.Add($pend.thumbprint)
    Assert-True ($pend.activatedDirectly -eq $false) "a DPAPI file that EXISTS is a credential, so enroll still goes pending (the fix is not simply always-activate)"

    # ============================================================ T22: pins on the behaviours the attack found already
    # holding, so a later edit cannot quietly remove them.
    Section "T22 pins on the survivors (M2, M17, M18, M24, M26)"
    # M2 -- retire secret must refuse outright when there is no active certificate to fall back to.
    Remove-Item -LiteralPath $CredentialStatePath -Force -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath "$CredentialStatePath.bak" -Force -ErrorAction SilentlyContinue
    $CertThumbprintCfg = $null
    $Secret = $null; $SecretPath = $realDpapi; $SecretPathCfg = $realDpapi; $HasSecretCredential = $true
    Assert-Throws { Invoke-CredentialRotate ([pscustomobject]@{ action = "retire"; secret = $true }) } "no active certificate" `
        "M2: retiring the secret with NO active certificate is refused -- it is the only credential"
    # M17 -- an expired certificate is refused before any network call.
    $expired = New-SelfSignedCertificate -Type Custom -Subject "CN=ABG-BayAgent expired" -CertStoreLocation "Cert:\CurrentUser\My" `
        -KeyAlgorithm RSA -KeyLength 2048 -HashAlgorithm sha256 -KeyExportPolicy NonExportable -KeyUsage DigitalSignature `
        -NotBefore (Get-Date).AddDays(-40) -NotAfter (Get-Date).AddDays(-1)
    [void]$script:CreatedCerts.Add($expired.Thumbprint)
    Assert-Throws { Acquire-TokenWithCertificate -Thumbprint $expired.Thumbprint } "expired" `
        "M17: an expired certificate is refused locally, before a token request is made"
    # M18 -- state wins over config. A stale config thumbprint must never pin a revoked certificate.
    Update-CredentialState @{ activeThumbprint = $f1cert.Thumbprint } | Out-Null
    $CertThumbprintCfg = $expired.Thumbprint
    Assert-True ((Get-ActiveCertThumbprint) -eq $f1cert.Thumbprint) `
        "M18: state\credential.json activeThumbprint OUTRANKS agent-config.json clientCertThumbprint"
    Update-CredentialState @{ activeThumbprint = $null } | Out-Null
    Assert-True ((Get-ActiveCertThumbprint) -eq $expired.Thumbprint) "...and the config value is the fallback only when state names none"
    $CertThumbprintCfg = $null
    # M24 -- the result cap constant, read out of THE AGENT rather than out of this harness.
    # ⚠️ The obvious assertion here is `$ResultJsonMaxChars -eq 2000`, and it is worthless: this test file
    # declares its own $ResultJsonMaxChars at the top, so that assertion pins the HARNESS and would pass no
    # matter what the shipped agent says. Mutation M24 (cap raised to 100000) survived exactly that way.
    # Pin the value the agent actually ships.
    $agentSrc = [IO.File]::ReadAllText($AgentScript)
    $capMatch = [regex]::Match($agentSrc, '(?m)^\$ResultJsonMaxChars\s*=\s*(\d+)')
    Assert-True ($capMatch.Success) "M24: the agent declares a build_resultjson cap"
    Assert-True ([int]$capMatch.Groups[1].Value -eq 2000) `
        "M24: the cap THE AGENT SHIPS is 2000 (measured against Dev; over-large silently makes the result PATCH fail, which lands in the catch that marks the command Failed)"

    # M19 -- activate's own private-key check must be the one that fires. Without it the call still fails,
    # because Acquire-TokenWithCertificate looks the certificate up again -- but it fails LATER and with a
    # message about token minting rather than about the certificate the operator named. Pin the early,
    # specific refusal, not merely "something threw".
    $ghostTp = "0123456789ABCDEF0123456789ABCDEF01234567"
    $m19 = ""
    try { Invoke-CredentialActivate ([pscustomobject]@{ thumbprint = $ghostTp }) } catch { $m19 = $_.Exception.Message }
    Assert-True ($m19 -match "^activate:") "M19: activate refuses a thumbprint with no private key in ITS OWN check (message: $m19)"
    Assert-True ($m19 -match "private key") "M19: ...and says the private key is what is missing"
    # M26 -- thumbprints are exactly 40 hex characters.
    Assert-Throws { Normalize-Thumbprint ("A" * 39) } "40 hex" "M26: a 39-character thumbprint is refused"
    Assert-Throws { Normalize-Thumbprint ("A" * 41) } "40 hex" "M26: a 41-character thumbprint is refused"
    Assert-True ((Normalize-Thumbprint ("a1b2c3d4e5" * 4)) -eq ("A1B2C3D4E5" * 4)) "M26: a valid thumbprint normalizes to upper case"

    # ============================================================ T25: the -EnrollCert console path. The suite
    # lifts functions by AST, so param() and top-level code are invisible to it -- an independent verifier
    # flipped [switch]$EnrollForce to default $true, restoring the F5 defect on the Day-0 path the bench day
    # actually runs, and all 181 assertions stayed green. Pin the default by PARSING the agent, and pin the
    # payload assembly by making it a real function.
    Section "T25 (V4a) the -EnrollCert entry path: force is opt-in, pinned against the parsed param block"
    $agentAstErr = $null; $agentAstTok = $null
    $agentAst = [System.Management.Automation.Language.Parser]::ParseFile($AgentScript, [ref]$agentAstTok, [ref]$agentAstErr)
    $paramBlock = $agentAst.ParamBlock
    Assert-True ($null -ne $paramBlock) "the agent declares a script-level param block"
    $efParam = @($paramBlock.Parameters | Where-Object { $_.Name.VariablePath.UserPath -eq "EnrollForce" })
    Assert-True ($efParam.Count -eq 1) "-EnrollForce exists as a script parameter"
    Assert-True (($efParam[0].StaticType.Name -eq "SwitchParameter") -or ("$($efParam[0].Attributes)" -match "switch")) "-EnrollForce is a [switch]"
    Assert-True ($null -eq $efParam[0].DefaultValue) `
        "-EnrollForce carries NO default, so it is OFF unless the operator types it (a default of \$true silently restores the F5 defect on the Day-0 path)"
    $vdParam = @($paramBlock.Parameters | Where-Object { $_.Name.VariablePath.UserPath -eq "EnrollValidityDays" })
    Assert-True ($vdParam.Count -eq 1 -and "$($vdParam[0].DefaultValue)" -eq "730") "-EnrollValidityDays still defaults to 730"

    # And the payload the console path builds, now that it is a liftable function rather than top-level code.
    $pDefault = New-EnrollCertPayload -ValidityDays 730
    Assert-True ($pDefault.force -eq $false) "New-EnrollCertPayload defaults force to FALSE"
    Assert-True (-not $pDefault.ContainsKey("store")) "...and omits store when none is given"
    $pForced = New-EnrollCertPayload -ValidityDays 400 -Store "LocalMachine" -Force
    Assert-True ($pForced.force -eq $true -and $pForced.validityDays -eq 400 -and $pForced.store -eq "LocalMachine") `
        "...and passes force/validityDays/store through when they are given"
    # The top-level path must go through it, not rebuild the payload inline with a literal.
    $agentText = [IO.File]::ReadAllText($AgentScript)
    Assert-True ($agentText -match "New-EnrollCertPayload\s+-ValidityDays\s+\`$EnrollValidityDays") `
        "the -EnrollCert block builds its payload through the function"
    Assert-True (-not ($agentText -match "force\s*=\s*\`$true")) "no code path hardcodes force = \$true"

    # ============================================================ T27 (V5 residual): retire must not act on a
    # credential it inferred from a config file while declaring its own state untrustworthy.
    Section "T27 (V5 residual) retire refuses outright while credential.json is corrupt"
    $corruptDir = Join-Path $BaseDir "corruptstate"
    New-Item -ItemType Directory -Force -Path $corruptDir | Out-Null
    $savedStatePath2 = $CredentialStatePath
    $CredentialStatePath = Join-Path $corruptDir "credential.json"
    [IO.File]::WriteAllText($CredentialStatePath, '{"activeThumbprint":"trunc')
    $CertThumbprintCfg = $bothCert.Thumbprint     # the config fallback that would otherwise become "active"
    $Secret = $null; $SecretPath = $bothDpapi; $SecretPathCfg = $bothDpapi; $HasSecretCredential = $true
    [IO.File]::WriteAllBytes($bothDpapi, [byte[]](7, 7, 7))
    $null = Read-CredentialState     # sets the corruption flag
    Assert-True ($Global:CredentialStateCorrupt -eq $true) "the state file is corrupt"
    Assert-Throws { Invoke-CredentialRotate ([pscustomobject]@{ action = "retire"; secret = $true }) } "corrupt" `
        "retire refuses while state is corrupt, rather than acting on the config-inferred thumbprint"
    Assert-True (Test-Path $bothDpapi) "...and the DPAPI secret is untouched"
    $CredentialStatePath = $savedStatePath2
    $CertThumbprintCfg = $null
    $Global:CredentialStateCorrupt = $false

    # ============================================================ T28 (F9 install half): Day-0 credential
    # choice. The agent half of F9 is closed, but Setup-BayPC.ps1's Phase 6 still told the operator to create
    # a DPAPI secret on the bay -- which is exactly the credential 1.2.0 exists to remove. A DPAPI file on
    # BENCH-01 puts Test-HasUsableSecret back to true, so the Day-0 enroll goes PENDING instead of ACTIVE and
    # the bench proof changes shape. The provisioning script must make this a CHOICE, not a reminder.
    Section "T28 (F9 install half) Day-0 credential mode is a deliberate choice, and it defaults to certificate"
    $setupPath = Join-Path $PSScriptRoot "..\src\BayAgent\tools\Setup-BayPC.ps1"
    Assert-True (Test-Path $setupPath) "Setup-BayPC.ps1 is where the package puts it"
    $setupPath = (Resolve-Path $setupPath).Path
    $suErr = $null; $suTok = $null
    $suAst = [System.Management.Automation.Language.Parser]::ParseFile($setupPath, [ref]$suTok, [ref]$suErr)
    Assert-True (@($suErr).Count -eq 0) "Setup-BayPC.ps1 parses"
    $credParam = @($suAst.ParamBlock.Parameters | Where-Object { $_.Name.VariablePath.UserPath -eq "Credential" })
    Assert-True ($credParam.Count -eq 1) "Setup-BayPC.ps1 declares a -Credential parameter"
    Assert-True ("$($credParam[0].DefaultValue)" -match "Certificate") `
        "...and it DEFAULTS to Certificate, so the safe path is the one an operator gets by not deciding"
    Assert-True ("$($credParam[0].Attributes)" -match "Certificate" -and "$($credParam[0].Attributes)" -match "Secret") `
        "...constrained to Certificate or Secret (a typo must not silently pick a mode)"

    $gdef = @($suAst.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $true) |
              Where-Object { $_.Name -eq "Get-Day0CredentialGuidance" })
    Assert-True ($gdef.Count -eq 1) "the decision is a function, so it can be tested rather than only printed"
    . ([scriptblock]::Create($gdef[0].Extent.Text))

    $gCert = Get-Day0CredentialGuidance -Mode "Certificate" -DpapiPath "C:\AllBirdies\BayAgent\secrets\clientsecret.dpapi" -Root "C:\AllBirdies" -BayKioskUser "BayKiosk"
    Assert-True ($gCert.dpapiRequired -eq $false) "certificate mode does NOT require a DPAPI secret"
    Assert-True (($gCert.lines -join " ") -match "EnrollCert") "...and it tells the operator to run -EnrollCert"
    Assert-True (-not (($gCert.lines -join " ") -match "SetClientSecretDpapi")) `
        "...and does NOT tell them to create the secret 1.2.0 exists to remove"
    Assert-True (($gCert.lines -join " ") -match "(?i)do not create") "...it says so in words, not by omission"

    $gSec = Get-Day0CredentialGuidance -Mode "Secret" -DpapiPath "C:\AllBirdies\BayAgent\secrets\clientsecret.dpapi" -Root "C:\AllBirdies" -BayKioskUser "BayKiosk"
    Assert-True ($gSec.dpapiRequired -eq $true) "secret mode still requires the DPAPI file (the legacy path is not removed, only un-defaulted)"
    Assert-True (($gSec.lines -join " ") -match "SetClientSecretDpapi") "...and still gives the exact command"
    Assert-True (($gSec.lines -join " ") -match "(?i)pending") `
        "...and warns that a secret makes the Day-0 enroll go PENDING, which changes the bench proof"

    # ============================================================ T11 (opt-in): the real Entra endpoint parses the assertion
    if ($Live) {
        Section "T11 LIVE: real Entra rejects an assertion from the UNREGISTERED test key with AADSTS700027 (no write)"
        $TokenAuthorityHost = "https://login.microsoftonline.com"
        $TenantId = $LiveTenantId; $ClientId = $LiveClientId; $OrgUrl = $LiveOrgUrl
        $liveCert = Find-ClientCertificate $day0.thumbprint
        $threw = $false; $msg = ""; $bodyLine = ""
        $script:LogLines.Clear()
        try { $null = Acquire-TokenWithCertificate -Thumbprint $liveCert.Thumbprint } catch { $threw = $true; $msg = $_.Exception.Message }
        $bodyLine = ($script:LogLines | Where-Object { $_ -match "Token failed" } | Select-Object -First 1)
        Write-Host "  entra said: $bodyLine"
        Assert-True ($threw -and $msg -match "HTTP 401") "home tenant: request rejected with HTTP 401 (threw: $msg)"
        Assert-True ($msg -match "AADSTS700027") "home tenant: AADSTS700027 = assertion parsed, thumbprint looked up, key not registered (NOT a malformed-assertion error)"
        Assert-True ($bodyLine -match [regex]::Escape($liveCert.Thumbprint)) "Entra echoes the thumbprint it looked up = our x5t was read correctly"
        # Informational: the single-tenant app is invisible to a customer tenant (census cell 1, now with a certificate).
        $TenantId = $LiveForeignTenantId
        $script:LogLines.Clear(); $msg2 = ""
        try { $null = Acquire-TokenWithCertificate -Thumbprint $liveCert.Thumbprint } catch { $msg2 = $_.Exception.Message }
        Write-Host "  INFO foreign tenant $LiveForeignTenantId answered: $msg2  (expect AADSTS700016 until the app is multi-tenant + consented)"
        $TenantId = $LiveTenantId
    } else {
        Write-Host ""; Write-Host "T11 LIVE Entra probe skipped (pass -Live to run it; it makes no Azure write)" -ForegroundColor Yellow
    }
}
finally {
    $sync["Stop"] = $true
    try { $mock.PS.Stop() } catch {}
    try { $mock.RS.Close() } catch {}
    foreach ($tp in @($script:CreatedCerts)) {
        try { Remove-Item -LiteralPath "Cert:\CurrentUser\My\$tp" -DeleteKey -Force -ErrorAction SilentlyContinue } catch {}
    }
    try { Remove-Item -LiteralPath $BaseDir -Recurse -Force -ErrorAction SilentlyContinue } catch {}
}

Write-Host ""
if ($sync["Errors"].Count -gt 0) { Write-Host "mock endpoint errors: $($sync['Errors'] -join ' | ')" -ForegroundColor Yellow }
Write-Host ("RESULT: {0} passed, {1} failed" -f $script:Pass, $script:Fail) -ForegroundColor $(if ($script:Fail -eq 0) { "Green" } else { "Red" })
if ($script:Fail -gt 0) { $script:Failures | ForEach-Object { Write-Host "  - $_" -ForegroundColor Red }; exit 1 }
exit 0
