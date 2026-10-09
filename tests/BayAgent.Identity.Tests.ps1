<#
BayAgent.Identity.Tests.ps1

A0.458 (each bay its own identity) and A0.456 (the bay fetches its own short-lived wall pass), as BayAgent runs them.
The functions are lifted out of src\BayAgent\BayAgent.ps1 by AST and run against ONE local mock on 127.0.0.1 that plays
three parts, each recording every request:
  - the Entra token endpoint: it answers per CLIENT ID (so "the bay's own app" and "the shared app" can behave
    differently) and issues an access token naming the client and the audience ("at-<client>-dv" / "at-<client>-api");
  - the club's Dataverse: WhoAmI, the bay row (read and heartbeat write) and the command row (the command guard's
    execution-field write), each refusable per identity, a refusal carrying the platform's own words in the body;
  - the bay pass route (POST /api/v1/bay/display-pass): answers what the test tells it to.
What it does NOT prove: Entra, Dataverse's plugin and the deployed API themselves (the Dev rehearsal does).

Run (from the repo root), under BOTH hosts:
  powershell -NoProfile -ExecutionPolicy Bypass -File tests\BayAgent.Identity.Tests.ps1
  pwsh -NoProfile -File tests\BayAgent.Identity.Tests.ps1
Exit code 0 = all assertions passed. Hyphens only in comments.
#>
[CmdletBinding()]
param([string]$AgentScript = "")

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
try { Add-Type -AssemblyName System.Security -ErrorAction SilentlyContinue } catch {}

if ([string]::IsNullOrWhiteSpace($AgentScript)) { $AgentScript = Join-Path $PSScriptRoot "..\src\BayAgent\BayAgent.ps1" }
$AgentScript = (Resolve-Path $AgentScript).Path

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

# ---------------------------------------------------------------- lift functions
$tokens = $null; $errors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile($AgentScript, [ref]$tokens, [ref]$errors)
if ($errors.Count -gt 0) { throw "BayAgent.ps1 has parse errors" }
$wanted = @(
    "Read-WebExceptionBody", "Get-ClientSecret", "Get-PropValue", "ConvertTo-Base64Url", "ConvertFrom-Base64Url",
    "Normalize-Thumbprint", "Read-CredentialState", "Write-CredentialState", "Update-CredentialState",
    "Get-ActiveCertThumbprint", "Get-PendingCertThumbprint", "Get-CertStoreSearchOrder", "Get-CertStoreName",
    "Find-ClientCertificate", "New-ClientAssertionJwt", "Get-AadstsCode", "Get-TokenUrl", "Invoke-TokenEndpoint",
    "Acquire-TokenWithCertificate", "Acquire-TokenWithSecret", "Acquire-Token", "Get-CredentialTelemetry", "Sync-FallbackTelemetry",
    "Get-AccessToken", "Test-HasUsableSecret", "New-BayClientCertificate",
    "Invoke-CredentialActivate", "Invoke-CredentialConfirm", "Invoke-CredentialRevert", "Invoke-CredentialRotate",
    "Invoke-CredentialEnroll", "Invoke-CredentialTest", "Invoke-CredentialRetire", "Invoke-CredentialStatus",
    "Export-PublicCertificate", "Build-CredentialEnrollResult", "Test-IsAgentOwnedCertificate",
    "New-DvHeaders", "Invoke-DvSafe", "Patch-Row",
    "ConvertTo-AgentGuid", "Get-ActiveClientId", "Test-OwnIdentityActive", "Get-IdentityProbation",
    "Test-IdentityRefusal", "Register-IdentityProbationFailure", "Clear-IdentityProbationFailures", "Test-IdentityProbationExpiry",
    "Invoke-IdentityRevert", "Test-IdentityCandidate",
    "Get-DisplayPassEndpoint", "ConvertTo-DisplayPassUtc", "Test-DisplayPassShape", "Read-DisplayPassState", "Write-DisplayPassState",
    "Invoke-DisplayPassFetch", "Update-DisplayPassIfDue", "Get-DisplayPassWallUrl", "Get-DisplayPassTelemetry"
)
$defs = $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $true)
foreach ($name in $wanted) {
    $d = $defs | Where-Object { $_.Name -eq $name } | Select-Object -First 1
    if (-not $d) { throw "Function '$name' not found in $AgentScript" }
    . ([scriptblock]::Create($d.Extent.Text))
}

# The constants are READ FROM THE AGENT (never re-declared here), so a changed value is what is tested.
$agentText = [IO.File]::ReadAllText($AgentScript)
function Get-AgentConstant([string]$name) {
    $m = [regex]::Match($agentText, "(?m)^\`$$name\s*=\s*(.+)$")
    if (-not $m.Success) { throw "constant $name not found in the agent" }
    return (Invoke-Expression $m.Groups[1].Value.Trim())
}
$IdentityProbationMaxFailures = Get-AgentConstant "IdentityProbationMaxFailures"
$IdentityProbationMaxHours    = Get-AgentConstant "IdentityProbationMaxHours"
$ShippedReleaseMode           = Get-AgentConstant "DisplayPassReleaseMode"
$DisplayPassWallPath          = Get-AgentConstant "DisplayPassWallPath"
$DisplayPassRoute             = Get-AgentConstant "DisplayPassRoute"
$DisplayPassQueryName         = Get-AgentConstant "DisplayPassQueryName"
$ShippedSitesText = [regex]::Match($agentText, '(?ms)^\$DisplayPassSites = @\{.*?^\}').Value

$script:LogLines = New-Object System.Collections.ArrayList
function Write-Log { param([string]$Message, [string]$Level = "INFO") [void]$script:LogLines.Add("[$Level] $Message") }

$BaseDir = Join-Path $env:TEMP ("bayagent-idtest-" + [guid]::NewGuid().ToString("N").Substring(0, 8))
New-Item -ItemType Directory -Force -Path (Join-Path $BaseDir "state") | Out-Null
$CredentialStatePath = Join-Path $BaseDir "state\credential.json"
$DisplayPassStatePath = Join-Path $BaseDir "state\display-pass.json"
$TenantId = "11111111-1111-1111-1111-111111111111"
$SharedApp = "22222222-2222-2222-2222-222222222222"
$OwnApp = "a1a1a1a1-0000-4000-8000-0000000000aa"
$ApiApp = "e7e1a2d5-4612-4e3f-9c58-5618ec7e0454"
$ClientId = $SharedApp
$BayId = "33333333-3333-3333-3333-333333333333"
$AssertionAlg = "RS256"
$AgentVersion = "test"
$BayEntitySet = "build_baies"; $BayCommandEntitySet = "build_baycommands"
$Col_Heartbeat = "build_lastheartbeat"; $Col_Result = "build_resultjson"
$CertThumbprintCfg = $null; $CertStoreCfg = $null
Set-Variable -Name Secret -Value $null; Set-Variable -Name SecretPath -Value $null
Set-Variable -Name SecretPathCfg -Value $null; $HasSecretCredential = $false
Set-Variable -Name AccessToken -Scope Global -Value $null; $Global:TokenExpiresUtc = [DateTime]::MinValue
$Global:CredentialTelemetry = @{ lastMintMode = $null; lastMintUtc = $null; lastCertMintUtc = $null; lastSecretMintUtc = $null
    lastCertError = $null; lastSecretError = $null; fallbackCount = 0; fallbackFlushed = 0; lastFallbackUtc = $null; lastTest = $null }
$Global:CredentialStateCorrupt = $false
$Global:IdentityProbationFailures = 0
$Global:CurrentCommandId = $null
$Global:LastDvErrorBody = $null
$Global:DisplayPassNextAttemptUtc = [DateTime]::MinValue
$Global:DisplayPassBackoffSec = 60
$Global:DisplayPassLast = [ordered]@{ attemptUtc = $null; result = $null; status = $null }
$script:CreatedCerts = New-Object System.Collections.ArrayList

# ---------------------------------------------------------------- the mock (token + Dataverse + pass route)
function Start-Mock([hashtable]$Sync) {
    $rs = [runspacefactory]::CreateRunspace(); $rs.Open(); $rs.SessionStateProxy.SetVariable("sync", $Sync)
    $ps = [powershell]::Create(); $ps.Runspace = $rs
    [void]$ps.AddScript({
        $listener = New-Object System.Net.Sockets.TcpListener([System.Net.IPAddress]::Loopback, 0)
        $listener.Start(); $sync["Port"] = ([System.Net.IPEndPoint]$listener.LocalEndpoint).Port
        function Field([string]$body, [string]$name) {
            foreach ($kv in $body.Split("&")) { $i = $kv.IndexOf("="); if ($i -gt 0 -and $kv.Substring(0, $i) -eq $name) { return [uri]::UnescapeDataString($kv.Substring($i + 1)) } }
            return $null
        }
        try {
            while (-not $sync["Stop"]) {
                if (-not $listener.Server.Poll(200000, [System.Net.Sockets.SelectMode]::SelectRead)) { continue }
                $client = $listener.AcceptTcpClient()
                try {
                    $client.ReceiveTimeout = 5000
                    $stream = $client.GetStream(); $buf = New-Object byte[] 65536; $ms = New-Object System.IO.MemoryStream; $he = -1
                    while ($he -lt 0) { $n = $stream.Read($buf, 0, $buf.Length); if ($n -le 0) { break }; $ms.Write($buf, 0, $n); $he = ([Text.Encoding]::ASCII.GetString($ms.ToArray())).IndexOf("`r`n`r`n") }
                    $all = $ms.ToArray(); $head = [Text.Encoding]::ASCII.GetString($all, 0, $he); $cl = 0
                    if ($head -match "(?im)^Content-Length:\s*(\d+)") { $cl = [int]$Matches[1] }
                    $bs = $he + 4
                    while (($all.Length - $bs) -lt $cl) { $n = $stream.Read($buf, 0, $buf.Length); if ($n -le 0) { break }; $ms.Write($buf, 0, $n); $all = $ms.ToArray() }
                    $body = [Text.Encoding]::UTF8.GetString($all, $bs, [Math]::Min($cl, $all.Length - $bs))
                    $line = ($head -split "`r`n")[0]; $method = $line.Split(" ")[0]; $path = [uri]::UnescapeDataString($line.Split(" ")[1])
                    $auth = ""; if ($head -match "(?im)^Authorization:\s*Bearer\s+(\S+)") { $auth = $Matches[1] }
                    $bayAuth = ""; if ($head -match "(?im)^X-Bay-Identity-Authorization:\s*Bearer\s+(\S+)") { $bayAuth = $Matches[1] }
                    [void]$sync["Requests"].Add(@{ method = $method; path = $path; auth = $auth; bayAuth = $bayAuth; body = $body })
                    $status = 200; $text = "{}"
                    if ($path -match "/oauth2/v2.0/token$") {
                        $cid = Field $body "client_id"; $scope = [string](Field $body "scope")
                        $fail = $sync["MintFail"][$cid]
                        if ($fail) { $status = 401; $text = "{`"error`":`"invalid_client`",`"error_description`":`"$($fail): refused`"}" }
                        else { $aud = $(if ($scope -match "dynamics|127\.0\.0\.1.*\.default$" -and $scope -notmatch "^[0-9a-f-]{36}/") { "dv" } else { "api" }); $text = "{`"token_type`":`"Bearer`",`"expires_in`":3599,`"access_token`":`"at-$cid-$aud`"}" }
                    } elseif ($path -match "/api/v1/bay/display-pass$") {
                        $r = $sync["PassResponse"]; $status = [int]$r.status; $text = [string]$r.body
                    } elseif ($path -match "/api/data/v9.2/") {
                        $who = $auth -replace "^at-", "" -replace "-dv$", ""
                        $refuse = $sync["DvRefuse"]
                        $key = $(if ($path -match "WhoAmI") { "whoami" } elseif ($method -eq "GET" -and $path -match "build_baies") { "bayGet" } elseif ($method -eq "PATCH" -and $path -match "build_baies") { "bayPatch" } elseif ($method -eq "PATCH" -and $path -match "build_baycommands") { "commandPatch" } else { "other" })
                        $rule = $refuse["$who|$key"]
                        if ($rule) { $status = [int]$rule.status; $text = "{`"error`":{`"code`":`"0x80040265`",`"message`":`"$($rule.message)`"}}" }
                        elseif ($key -eq "whoami") { $text = "{`"UserId`":`"user-$who`",`"OrganizationId`":`"org`",`"BusinessUnitId`":`"bu`"}" }
                        elseif ($method -eq "PATCH") { $status = 204; $text = "" }
                        else { $text = "{`"build_bayid`":`"x`"}" }
                    }
                    $reason = $(switch ($status) { 200 { "OK" } 204 { "No Content" } 401 { "Unauthorized" } 403 { "Forbidden" } default { "Bad Request" } })
                    $bytes = [Text.Encoding]::UTF8.GetBytes($text)
                    $h = "HTTP/1.1 $status $reason`r`nContent-Type: application/json; charset=utf-8`r`nContent-Length: $($bytes.Length)`r`nConnection: close`r`n`r`n"
                    $hb = [Text.Encoding]::ASCII.GetBytes($h); $stream.Write($hb, 0, $hb.Length); $stream.Write($bytes, 0, $bytes.Length); $stream.Flush()
                } catch { [void]$sync["Errors"].Add($_.Exception.Message) } finally { $client.Close() }
            }
        } finally { $listener.Stop() }
    })
    $handle = $ps.BeginInvoke()
    return @{ PS = $ps; RS = $rs; Handle = $handle }
}

$sync = [hashtable]::Synchronized(@{
    Stop = $false; Port = 0
    Requests = [System.Collections.ArrayList]::Synchronized((New-Object System.Collections.ArrayList))
    Errors = [System.Collections.ArrayList]::Synchronized((New-Object System.Collections.ArrayList))
    MintFail = [hashtable]::Synchronized(@{})
    DvRefuse = [hashtable]::Synchronized(@{})
    PassResponse = @{ status = 500; body = "{}" }
})
$mock = Start-Mock -Sync $sync
$deadline = (Get-Date).AddSeconds(10)
while ($sync["Port"] -eq 0 -and (Get-Date) -lt $deadline) { Start-Sleep -Milliseconds 50 }
if ($sync["Port"] -eq 0) { throw "mock did not start" }
$TokenAuthorityHost = "http://127.0.0.1:$($sync['Port'])"
$OrgUrl = "http://127.0.0.1:$($sync['Port'])"
# The PINNED site map, re-pointed at the mock under the mock's own host (the agent keys it by its org's host).
$DisplayPassSites = @{ "127.0.0.1" = @{ site = "http://127.0.0.1:$($sync['Port'])"; apiAppId = $ApiApp } }
$DisplayPassReleaseMode = "on"
Write-Host "Mock (token + Dataverse + pass route) on $OrgUrl - a MOCK, not Entra or Dataverse"

function Reset-World {
    Remove-Item -LiteralPath $CredentialStatePath, "$CredentialStatePath.bak", $DisplayPassStatePath -Force -ErrorAction SilentlyContinue
    $sync["Requests"].Clear(); $sync["MintFail"].Clear(); $sync["DvRefuse"].Clear()
    $sync["PassResponse"] = @{ status = 500; body = "{}" }
    Set-Variable -Name AccessToken -Scope Global -Value $null; $Global:TokenExpiresUtc = [DateTime]::MinValue
    $Global:IdentityProbationFailures = 0; $Global:CurrentCommandId = $null; $Global:LastDvErrorBody = $null
    $Global:CredentialStateCorrupt = $false
    $Global:DisplayPassNextAttemptUtc = [DateTime]::MinValue; $Global:DisplayPassBackoffSec = 60
    $Global:DisplayPassLast = [ordered]@{ attemptUtc = $null; result = $null; status = $null }
    Set-Variable -Name Secret -Scope Script -Value $null; $script:HasSecretCredential = $false
    $script:LogLines.Clear()
}
function New-TestCert {
    $c = New-BayClientCertificate -Subject ("CN=ABG-BayAgent idtest-" + [guid]::NewGuid().ToString("N").Substring(0, 8)) -ValidityDays 60 -Store "CurrentUser"
    [void]$script:CreatedCerts.Add($c.Thumbprint); return $c
}
function Requests([string]$pattern) { return @($sync["Requests"] | Where-Object { $_.path -match $pattern }) }
function Pass-Json([hashtable]$over) {
    $now = (Get-Date).ToUniversalTime()
    $o = [ordered]@{ bayId = $BayId; bayRef = "bay-7"; pass = "BAYD1.eyJ2IjoxfQ.c2lnbmF0dXJl"; issuedUtc = $now.ToString("o")
        expiresUtc = $now.AddHours(12).ToString("yyyy-MM-ddTHH:mm:ssZ"); refreshAfterUtc = $now.AddHours(6).ToString("yyyy-MM-ddTHH:mm:ssZ"); wallPath = "/bay-display.html" }
    foreach ($k in $over.Keys) { $o[$k] = $over[$k] }
    return ($o | ConvertTo-Json -Compress)
}

try {
    # ============================================================================================ shipped constants
    Section "S0 what ships: pass fetching OFF, the site pinned in signed code for the Dev org only"
    Assert-True ($ShippedReleaseMode -eq "off") "the shipped DisplayPassReleaseMode is 'off' (got '$ShippedReleaseMode')"
    Assert-True ($ShippedSitesText -match '"builds-apps-dev\.crm\.dynamics\.com"\s*=\s*@\{\s*site\s*=\s*"https://testclub\.dev\.aceofclubs\.golf"') "the Dev org maps to the Dev club site over https"
    Assert-True (([regex]::Matches($ShippedSitesText, '=\s*@\{\s*site')).Count -eq 1) "exactly one org is pinned"
    Assert-True ($IdentityProbationMaxFailures -eq 5 -and $IdentityProbationMaxHours -eq 72) "probation: 5 refusals in a row, 72 hours"

    # ============================================================================================ identity basics
    Section "I1 the active client defaults to the configured (shared) app; credential.json can name the bay's own"
    Reset-World
    Assert-True ((Get-ActiveClientId) -eq $SharedApp) "no state: the configured app"
    Update-CredentialState @{ activeClientId = $OwnApp.ToUpperInvariant() } | Out-Null
    Assert-True ((Get-ActiveClientId) -eq $OwnApp) "a recorded activeClientId wins (normalized: '$(Get-ActiveClientId)')"
    Update-CredentialState @{ activeClientId = "not-a-guid" } | Out-Null
    Assert-True ((Get-ActiveClientId) -eq $SharedApp) "a malformed activeClientId is ignored"
    Assert-True (-not (Test-OwnIdentityActive)) "no active certificate: never 'own identity'"

    Section "I2 a certificate mints as the app it is bound to, for the resource asked"
    Reset-World
    $c1 = New-TestCert
    Update-CredentialState @{ activeThumbprint = $c1.Thumbprint; activeClientId = $OwnApp } | Out-Null
    $null = Acquire-TokenWithCertificate -Thumbprint $c1.Thumbprint
    $r = @(Requests "oauth2")[-1]
    Assert-True ($r.body -match "client_id=$OwnApp") "the ACTIVE certificate signs in as the bay's own app"
    Assert-True ($r.body -match ("scope=" + [regex]::Escape([uri]::EscapeDataString("$OrgUrl/.default")))) "...for Dataverse by default"
    $null = Acquire-TokenWithCertificate -Thumbprint $c1.Thumbprint -ForClientId $SharedApp -Scope "$ApiApp/.default"
    $r = @(Requests "oauth2")[-1]
    Assert-True ($r.body -match "client_id=$SharedApp" -and $r.body -match [regex]::Escape([uri]::EscapeDataString("$ApiApp/.default"))) "-ForClientId and -Scope are what is sent"
    $c2 = New-TestCert
    $null = Acquire-TokenWithCertificate -Thumbprint $c2.Thumbprint
    Assert-True (@(Requests "oauth2")[-1].body -match "client_id=$SharedApp") "a NON-active certificate defaults to the configured app (legacy rotation unchanged)"
    Assert-True (Test-OwnIdentityActive) "active certificate on another app: own identity"

    # ============================================================================================ activate (switch)
    Section "I3 activate with clientId PROVES the switch against Dataverse and the command guard, then switches on probation"
    Reset-World
    $cand = New-TestCert
    Update-CredentialState @{ pendingThumbprint = $cand.Thumbprint } | Out-Null
    $Global:CurrentCommandId = "cmd-1"
    $res = Invoke-CredentialRotate @{ action = "activate"; thumbprint = $cand.Thumbprint; clientId = $OwnApp }
    $Global:CurrentCommandId = $null
    $st = Read-CredentialState
    Assert-True ($res.ok -and $res.identitySwitched) "activate reports the identity switched"
    Assert-True ([string]$st.activeClientId -eq $OwnApp -and [string]$st.activeThumbprint -eq $cand.Thumbprint) "credential.json: active certificate and the bay's own app"
    Assert-True ($null -ne $st.identityProbation -and [string]$st.identityProbation.clientId -eq $OwnApp) "the switch is ON PROBATION"
    Assert-True ([string]::IsNullOrEmpty([string]$st.identityProbation.previousThumbprint) -and [string]::IsNullOrEmpty([string]$st.identityProbation.previousClientId)) "...remembering the bay was on the configured secret"
    $newTok = "at-$OwnApp-dv"
    Assert-True (@(Requests "WhoAmI" | Where-Object { $_.auth -eq $newTok }).Count -eq 1) "proof: WhoAmI as the NEW identity"
    Assert-True (@($sync["Requests"] | Where-Object { $_.method -eq "GET" -and $_.path -match "build_baies\($BayId\)" -and $_.auth -eq $newTok }).Count -eq 1) "proof: this bay's row read as the new identity"
    Assert-True (@($sync["Requests"] | Where-Object { $_.method -eq "PATCH" -and $_.path -match "build_baies\($BayId\)" -and $_.auth -eq $newTok }).Count -eq 1) "proof: this bay's heartbeat written as the new identity"
    $probe = @($sync["Requests"] | Where-Object { $_.method -eq "PATCH" -and $_.path -match "build_baycommands\(cmd-1\)" -and $_.auth -eq $newTok })
    Assert-True ($probe.Count -eq 1 -and $probe[0].body -match "build_resultjson") "proof: the command guard probe is an execution-field write on THIS command, as the new identity"
    Assert-True ($null -eq $Global:AccessToken) "the cached token is dropped"
    Assert-True ((Get-CredentialTelemetry).activeClientId -eq $OwnApp) "telemetry names the bay's own app (the operator ladder reads it)"

    $refusals = @(
        @{ name = "mint refused"; setup = { $sync["MintFail"][$OwnApp] = "AADSTS700027" }; pattern = "cannot sign in" }
        @{ name = "WhoAmI refused"; setup = { $sync["DvRefuse"]["$OwnApp|whoami"] = @{ status = 401; message = "user is disabled" } }; pattern = "Dataverse refuses" }
        @{ name = "bay row read refused"; setup = { $sync["DvRefuse"]["$OwnApp|bayGet"] = @{ status = 403; message = "no read privilege" } }; pattern = "cannot read this bay" }
        @{ name = "heartbeat refused"; setup = { $sync["DvRefuse"]["$OwnApp|bayPatch"] = @{ status = 403; message = "no write privilege" } }; pattern = "heartbeat" }
        @{ name = "command guard refused"; setup = { $sync["DvRefuse"]["$OwnApp|commandPatch"] = @{ status = 400; message = "Only the BayAgent user may write execution fields." } }; pattern = "command guard refuses" }
    )
    foreach ($case in $refusals) {
        Section ("I4 a refused proof switches NOTHING: " + $case.name)
        Reset-World
        $cand = New-TestCert
        Update-CredentialState @{ pendingThumbprint = $cand.Thumbprint } | Out-Null
        & $case.setup
        $Global:CurrentCommandId = "cmd-2"
        Assert-Throws { Invoke-CredentialRotate @{ action = "activate"; thumbprint = $cand.Thumbprint; clientId = $OwnApp } } $case.pattern "activate refuses"
        $Global:CurrentCommandId = $null
        $st = Read-CredentialState
        Assert-True ([string]::IsNullOrEmpty([string](Get-PropValue $st "activeClientId" "")) -and [string]::IsNullOrEmpty([string](Get-PropValue $st "activeThumbprint" ""))) "nothing switched"
        Assert-True ($null -eq (Get-PropValue $st "identityProbation" $null)) "no probation opened"
        Assert-True ([string](Get-PropValue $st "pendingThumbprint" "") -eq $cand.Thumbprint) "the candidate is still pending"
    }

    Section "I5 an identity switch outside a command, a malformed clientId, and a second switch on probation are refused"
    Reset-World
    $cand = New-TestCert
    Assert-Throws { Invoke-CredentialActivate @{ thumbprint = $cand.Thumbprint; clientId = $OwnApp } } "runs only as a CredentialRotate command" "no current command: refused"
    $Global:CurrentCommandId = "cmd-3"
    Assert-Throws { Invoke-CredentialActivate @{ thumbprint = $cand.Thumbprint; clientId = "bay-one" } } "clientId must be a GUID" "malformed clientId: refused"
    $null = Invoke-CredentialActivate @{ thumbprint = $cand.Thumbprint; clientId = $OwnApp }
    $other = New-TestCert
    Assert-Throws { Invoke-CredentialActivate @{ thumbprint = $other.Thumbprint; clientId = "b2b2b2b2-0000-4000-8000-0000000000bb" } } "already on probation" "a second switch while on probation: refused"
    $Global:CurrentCommandId = $null

    Section "I6 the legacy path is unchanged: activate WITHOUT clientId mints as the app in force and opens no probation"
    Reset-World
    $legacy = New-TestCert
    $null = Invoke-CredentialActivate @{ thumbprint = $legacy.Thumbprint }
    $st = Read-CredentialState
    Assert-True ([string]::IsNullOrEmpty([string](Get-PropValue $st "activeClientId" ""))) "no activeClientId written"
    Assert-True ($null -eq (Get-PropValue $st "identityProbation" $null)) "no probation"
    Assert-True (@(Requests "oauth2")[-1].body -match "client_id=$SharedApp") "proved against the configured app"
    Assert-True (@(Requests "WhoAmI").Count -eq 0) "no identity-switch proof ran"

    # ============================================================================================ probation
    function Open-Probation([string]$sinceUtc = "") {
        Reset-World
        $c = New-TestCert
        if (-not $sinceUtc) { $sinceUtc = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ") }
        Update-CredentialState @{ activeThumbprint = $c.Thumbprint; activeClientId = $OwnApp
            identityProbation = [ordered]@{ clientId = $OwnApp; sinceUtc = $sinceUtc; previousThumbprint = $null; previousClientId = $null } } | Out-Null
        return $c
    }

    Section "I7 on probation: five REFUSALS in a row revert to the previous credential; four do not; a success resets the count"
    $pc = Open-Probation
    1..4 | ForEach-Object { Register-IdentityProbationFailure "poll: The remote server returned an error: (403) Forbidden." }
    Assert-True ((Get-ActiveClientId) -eq $OwnApp) "four refusals: still on the bay's own app"
    Clear-IdentityProbationFailures
    1..4 | ForEach-Object { Register-IdentityProbationFailure "mint: Token request failed with HTTP 401 (AADSTS7000112)" }
    Assert-True ((Get-ActiveClientId) -eq $OwnApp) "a success in between reset the count (four more: still own)"
    Register-IdentityProbationFailure "command lock: (400) Bad Request"
    Assert-True ((Get-ActiveClientId) -eq $OwnApp) "a 400 without the guard's words is not a refusal"
    $Global:LastDvErrorBody = '{"error":{"message":"Only the BayAgent user may advance command status."}}'
    Register-IdentityProbationFailure "command lock: (400) Bad Request"
    $Global:LastDvErrorBody = $null
    $st = Read-CredentialState
    Assert-True ((Get-ActiveClientId) -eq $SharedApp -and [string]::IsNullOrEmpty([string](Get-PropValue $st "activeThumbprint" ""))) "the fifth refusal (the command guard's own words) REVERTED to the configured credential"
    Assert-True ($null -eq (Get-PropValue $st "identityProbation" $null)) "probation closed"
    Assert-True ([string]$st.identityReverted.fromClientId -eq $OwnApp -and [string]$st.identityReverted.reason -match "^auto:") "the revert is recorded with its reason"
    Assert-True (@($st.superseded) -contains $pc.Thumbprint) "the left certificate stays recorded (retirable)"
    Assert-True ($null -eq $Global:AccessToken) "the cached token is dropped"

    Section "I8 an outage is not a refusal: a probation is never reverted by a network failure"
    $null = Open-Probation
    1..8 | ForEach-Object { Register-IdentityProbationFailure "mint: Token endpoint unreachable: Unable to connect to the remote server" }
    1..8 | ForEach-Object { Register-IdentityProbationFailure "poll: The operation has timed out." }
    Assert-True ((Get-ActiveClientId) -eq $OwnApp) "sixteen outage failures: still on the bay's own app"

    Section "I9 a probation nobody confirms within 72 hours is reverted; an unreadable start is treated as expired"
    $null = Open-Probation ((Get-Date).ToUniversalTime().AddHours(-71).ToString("yyyy-MM-ddTHH:mm:ssZ"))
    Test-IdentityProbationExpiry
    Assert-True ((Get-ActiveClientId) -eq $OwnApp) "71 hours: kept"
    $null = Open-Probation ((Get-Date).ToUniversalTime().AddHours(-73).ToString("yyyy-MM-ddTHH:mm:ssZ"))
    Test-IdentityProbationExpiry
    Assert-True ((Get-ActiveClientId) -eq $SharedApp) "73 hours: reverted"
    $null = Open-Probation "yesterday-ish"
    Test-IdentityProbationExpiry
    Assert-True ((Get-ActiveClientId) -eq $SharedApp) "an unreadable start: reverted"

    Section "I10 confirm ends probation (with a live mint); revert undoes it; both refuse without one"
    $null = Open-Probation
    $conf = Invoke-CredentialRotate @{ action = "confirm" }
    $st = Read-CredentialState
    Assert-True ($conf.ok -and $null -eq (Get-PropValue $st "identityProbation" $null) -and -not [string]::IsNullOrEmpty([string]$st.identityConfirmedUtc)) "confirm closed the probation and recorded when"
    Assert-True (@(Requests "oauth2")[-1].body -match "client_id=$OwnApp") "confirm proved a live mint as the bay's own app"
    Assert-True ((Get-ActiveClientId) -eq $OwnApp) "still the bay's own app"
    1..10 | ForEach-Object { Register-IdentityProbationFailure "poll: (403) Forbidden" }
    Assert-True ((Get-ActiveClientId) -eq $OwnApp) "after confirm, refusals never revert (no probation to revert)"
    Assert-Throws { Invoke-CredentialRotate @{ action = "confirm" } } "no identity switch is on probation" "confirm without probation: refused"
    Assert-Throws { Invoke-CredentialRotate @{ action = "revert" } } "no identity switch is on probation" "revert without probation: refused"
    $null = Open-Probation
    $rev = Invoke-CredentialRotate @{ action = "revert" }
    Assert-True ($rev.ok -and (Get-ActiveClientId) -eq $SharedApp) "revert on probation: back to the configured credential"
    $null = Open-Probation
    $sync["MintFail"][$OwnApp] = "AADSTS700027"
    Assert-Throws { Invoke-CredentialRotate @{ action = "confirm" } } "AADSTS700027" "confirm refuses when the new identity cannot mint"
    Assert-True ($null -ne (Get-IdentityProbation)) "...and the probation stays open"

    Section "I11 on probation the token path falls back to the secret AND counts the refusal"
    $null = Open-Probation
    Set-Variable -Name Secret -Scope Script -Value "probation-fallback-0123456789"; $script:HasSecretCredential = $true
    $sync["MintFail"][$OwnApp] = "AADSTS7000112"
    $tok = Acquire-Token
    Assert-True ($tok -eq "at-$SharedApp-dv" -and $Global:CredentialTelemetry.lastMintMode -eq "secret") "the shared secret carried the bay"
    Assert-True ($Global:IdentityProbationFailures -eq 1) "the certificate refusal counted toward going back"
    1..4 | ForEach-Object { Set-Variable -Name AccessToken -Scope Global -Value $null; $null = Acquire-Token }
    Assert-True ((Get-ActiveClientId) -eq $SharedApp) "five refused mints: reverted"
    Set-Variable -Name Secret -Scope Script -Value $null; $script:HasSecretCredential = $false

    Section "I12 a corrupt credential.json is never rewritten by a revert"
    $null = Open-Probation
    [IO.File]::WriteAllText($CredentialStatePath, "{ not json")
    $null = Read-CredentialState
    Assert-True (-not (Invoke-IdentityRevert -Reason "test")) "revert refuses"
    Assert-True ([IO.File]::ReadAllText($CredentialStatePath) -eq "{ not json") "the corrupt bytes survive"

    # ============================================================================================ display pass
    function Make-OwnActive {
        Reset-World
        $c = New-TestCert
        Update-CredentialState @{ activeThumbprint = $c.Thumbprint; activeClientId = $OwnApp; identityConfirmedUtc = "2026-10-08T00:00:00Z" } | Out-Null
        return $c
    }

    Section "D1 the site comes only from the pinned map, keyed by this bay's own org"
    Reset-World
    $ep = Get-DisplayPassEndpoint
    Assert-True ($null -ne $ep -and $ep.site -eq "http://127.0.0.1:$($sync['Port'])" -and $ep.apiAppId -eq $ApiApp) "the mock org's pinned site"
    $savedSites = $DisplayPassSites
    $DisplayPassSites = @{ "127.0.0.1" = @{ site = "http://evil.example"; apiAppId = $ApiApp } }
    Assert-True ($null -eq (Get-DisplayPassEndpoint)) "plain http to a non-loopback host: refused"
    $DisplayPassSites = @{ "127.0.0.1" = @{ site = "https://x.example/path"; apiAppId = $ApiApp } }
    Assert-True ($null -eq (Get-DisplayPassEndpoint)) "a site with a path: refused"
    $DisplayPassSites = @{ "127.0.0.1" = @{ site = "https://user@x.example"; apiAppId = $ApiApp } }
    Assert-True ($null -eq (Get-DisplayPassEndpoint)) "a site with user info: refused"
    $DisplayPassSites = @{ "127.0.0.1" = @{ site = "https://x.example"; apiAppId = "api" } }
    Assert-True ($null -eq (Get-DisplayPassEndpoint)) "an api app that is not a GUID: refused"
    $DisplayPassSites = @{ "other.crm.dynamics.com" = @{ site = "https://x.example"; apiAppId = $ApiApp } }
    Assert-True ($null -eq (Get-DisplayPassEndpoint)) "an org that is not pinned: no site"
    $DisplayPassSites = $savedSites

    Section "D2 with its own identity the bay fetches its pass: own app, the API's audience, its bay id, the bay header"
    $null = Make-OwnActive
    $sync["PassResponse"] = @{ status = 200; body = (Pass-Json @{}) }
    $result = Invoke-DisplayPassFetch
    Assert-True ($result -eq "ok") "fetch ok (got '$result')"
    $mint = @(Requests "oauth2")[-1]
    Assert-True ($mint.body -match "client_id=$OwnApp" -and $mint.body -match [regex]::Escape([uri]::EscapeDataString("$ApiApp/.default"))) "the token is the bay's own, for the bay identity API"
    $post = @(Requests "display-pass")[-1]
    Assert-True ($post.method -eq "POST" -and $post.bayAuth -eq "at-$OwnApp-api" -and $post.auth -eq "") "the token rides X-Bay-Identity-Authorization, never Authorization"
    Assert-True (($post.body | ConvertFrom-Json).bayId -eq $BayId) "the body names this bay's configured id"
    $url = Get-DisplayPassWallUrl
    $passParam = "&" + "to" + "ken" + "=" + [uri]::EscapeDataString("BAYD1.eyJ2IjoxfQ.c2lnbmF0dXJl")
    Assert-True ($url -eq ("http://127.0.0.1:$($sync['Port'])/bay-display.html?bay=bay-7" + $passParam)) "the wall address: pinned site, fixed path, the bay's ref and its pass"
    $tele = Get-DisplayPassTelemetry | ConvertTo-Json -Compress
    Assert-True ($tele -notmatch "BAYD1" -and $tele -match '"hasValidPass":true') "telemetry reports the pass, never carries it"
    Assert-True (-not (@($script:LogLines) -match "BAYD1")) "the pass never reaches the log"

    Section "D3 not on its own identity: no fetch at all"
    Reset-World
    $sync["PassResponse"] = @{ status = 200; body = (Pass-Json @{}) }
    Assert-True ((Invoke-DisplayPassFetch) -eq "not_own_identity") "configured (shared) identity: refused locally"
    Assert-True (@(Requests "display-pass").Count -eq 0 -and @(Requests "oauth2").Count -eq 0) "no token, no request"

    $badShapes = @(
        @{ name = "another bay's id"; over = @{ bayId = "44444444-4444-4444-4444-444444444444" } }
        @{ name = "a bayRef with a slash"; over = @{ bayRef = "bay/7" } }
        @{ name = "a bayRef with a query"; over = @{ bayRef = "bay-7&x=1" } }
        @{ name = "a pass that is not BAYD1"; over = @{ pass = "eyJhbGciOi.x.y" } }
        @{ name = "a pass with markup"; over = @{ pass = "BAYD1.a<b.c" } }
        @{ name = "another wall path"; over = @{ wallPath = "/evil.html" } }
        @{ name = "a zone-less expiry"; over = @{ expiresUtc = "2099-01-01T00:00:00" } }
        @{ name = "an expired pass"; over = @{ expiresUtc = (Get-Date).ToUniversalTime().AddMinutes(-1).ToString("yyyy-MM-ddTHH:mm:ssZ") } }
        @{ name = "a pass living over a day"; over = @{ expiresUtc = (Get-Date).ToUniversalTime().AddHours(30).ToString("yyyy-MM-ddTHH:mm:ssZ") } }
        @{ name = "a refresh after the expiry"; over = @{ refreshAfterUtc = (Get-Date).ToUniversalTime().AddHours(13).ToString("yyyy-MM-ddTHH:mm:ssZ") } }
    )
    foreach ($b in $badShapes) {
        Section ("D4 a response out of shape is never kept: " + $b.name)
        $null = Make-OwnActive
        $sync["PassResponse"] = @{ status = 200; body = (Pass-Json @{}) }
        $null = Invoke-DisplayPassFetch
        $sync["PassResponse"] = @{ status = 200; body = (Pass-Json $b.over) }
        $r2 = Invoke-DisplayPassFetch
        Assert-True ($r2 -eq "bad_shape") "refused as bad_shape (got '$r2')"
        Assert-True ((Read-DisplayPassState).bayRef -eq "bay-7") "the earlier good pass is kept"
    }

    Section "D5 a refusal is reported by its code and writes nothing"
    $null = Make-OwnActive
    $sync["PassResponse"] = @{ status = 403; body = '{"error":{"code":"bay_identity.not_active","message":"This bay is not active."}}' }
    $r3 = Invoke-DisplayPassFetch
    Assert-True ($r3 -eq "refused:bay_identity.not_active") "the API's code is reported (got '$r3')"
    Assert-True ($null -eq (Read-DisplayPassState)) "no pass written"
    $sync["MintFail"][$OwnApp] = "AADSTS7000112"
    Assert-True ((Invoke-DisplayPassFetch) -eq "mint_failed:AADSTS7000112") "a refused mint is reported by its Entra code"

    Section "D6 refresh: off means nothing; a good pass is left alone until due; failures back off; it never throws"
    $null = Make-OwnActive
    $DisplayPassReleaseMode = "off"
    $sync["PassResponse"] = @{ status = 200; body = (Pass-Json @{}) }
    Update-DisplayPassIfDue
    Assert-True (@(Requests "display-pass").Count -eq 0) "mode off: no request"
    $DisplayPassReleaseMode = "on"
    Update-DisplayPassIfDue
    Assert-True (@(Requests "display-pass").Count -eq 1 -and $Global:DisplayPassLast.result -eq "ok") "missing pass: fetched"
    $Global:DisplayPassNextAttemptUtc = [DateTime]::MinValue
    Update-DisplayPassIfDue
    Assert-True (@(Requests "display-pass").Count -eq 1) "a valid pass before its refresh time: no request"
    $Global:DisplayPassNextAttemptUtc = [DateTime]::MinValue
    Update-DisplayPassIfDue -Now ((Get-Date).ToUniversalTime().AddHours(7))
    Assert-True (@(Requests "display-pass").Count -eq 2) "past refreshAfterUtc: fetched again"
    $sync["PassResponse"] = @{ status = 503; body = '{"error":{"code":"bay_identity.state_unreadable"}}' }
    $Global:DisplayPassNextAttemptUtc = [DateTime]::MinValue
    $t0 = (Get-Date).ToUniversalTime().AddHours(8)
    Update-DisplayPassIfDue -Now $t0
    $first = $Global:DisplayPassNextAttemptUtc
    Update-DisplayPassIfDue -Now $first
    Assert-True (($Global:DisplayPassNextAttemptUtc - $first).TotalSeconds -ge 119) "a second failure waits longer (backoff doubles)"
    $savedSites = $DisplayPassSites
    $DisplayPassSites = $null
    $Global:DisplayPassNextAttemptUtc = [DateTime]::MinValue
    $threw = $false; try { Update-DisplayPassIfDue -Now $t0 } catch { $threw = $true }
    Assert-True (-not $threw -and [string]$Global:DisplayPassLast.result -match "^error:") "an internal fault is reported, never thrown"
    $DisplayPassSites = $savedSites

    Section "D7 a damaged or nearly expired pass gives no wall address"
    $null = Make-OwnActive
    [IO.File]::WriteAllText($DisplayPassStatePath, "{ broken")
    Assert-True ($null -eq (Read-DisplayPassState) -and $null -eq (Get-DisplayPassWallUrl)) "unparseable: none"
    $near = (Pass-Json @{ expiresUtc = (Get-Date).ToUniversalTime().AddSeconds(90).ToString("yyyy-MM-ddTHH:mm:ssZ"); refreshAfterUtc = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ") })
    [IO.File]::WriteAllText($DisplayPassStatePath, $near)
    Assert-True ($null -eq (Get-DisplayPassWallUrl)) "expiring within two minutes: none"
    $DisplayPassReleaseMode = "off"
    [IO.File]::WriteAllText($DisplayPassStatePath, (Pass-Json @{}))
    Assert-True ($null -eq (Get-DisplayPassWallUrl)) "mode off: none, whatever is on disk"
    $DisplayPassReleaseMode = "on"
}
finally {
    $sync["Stop"] = $true
    try { $mock.PS.EndInvoke($mock.Handle) | Out-Null } catch {}
    try { $mock.PS.Dispose(); $mock.RS.Close() } catch {}
    foreach ($tp in $script:CreatedCerts) {
        foreach ($s in @("Cert:\CurrentUser\My", "Cert:\LocalMachine\My")) {
            if (Test-Path -LiteralPath "$s\$tp") { try { Remove-Item -LiteralPath "$s\$tp" -DeleteKey -Force } catch {} }
        }
    }
    Remove-Item -LiteralPath $BaseDir -Recurse -Force -ErrorAction SilentlyContinue
}

Write-Host ""
if ($sync["Errors"].Count -gt 0) { Write-Host ("mock errors: " + ($sync["Errors"] -join " | ")) -ForegroundColor Yellow }
Write-Host ("RESULT: {0} passed, {1} failed" -f $script:Pass, $script:Fail)
if ($script:Fail -gt 0) { $script:Failures | ForEach-Object { Write-Host "  - $_" -ForegroundColor Red }; exit 1 }
exit 0
