# Independent red-first attacks on the BayAgent 1.2.0 certificate-credential path.
# Same lifting technique as the shipped suite (AST extraction from the REAL BayAgent.ps1),
# a local mock token endpoint, a temp state dir and throwaway certificates in CurrentUser\My
# that are deleted at the end. No Dev writes, no bay rows, no Entra writes.
# Hyphens only in comments.
[CmdletBinding()]
param([string]$AgentScript = "")

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
try { Add-Type -AssemblyName System.Security -ErrorAction SilentlyContinue } catch {}

if ([string]::IsNullOrWhiteSpace($AgentScript)) { $AgentScript = Join-Path $PSScriptRoot "..\src\BayAgent\BayAgent.ps1" }
$AgentScript = (Resolve-Path $AgentScript).Path

$script:Land = 0; $script:Hold = 0; $script:Rows = @()
function Attack([string]$id, [string]$claim, [bool]$landed, [string]$evidence) {
    if ($landed) { $script:Land++; $tag = "LANDED " } else { $script:Hold++; $tag = "held   " }
    Write-Host ("  {0} {1}  {2}" -f $tag, $id, $claim)
    Write-Host ("           {0}" -f $evidence)
    $script:Rows += [pscustomobject]@{ Id = $id; Landed = $landed; Claim = $claim; Evidence = $evidence }
}
function Section([string]$n) { Write-Host ""; Write-Host "== $n" -ForegroundColor Cyan }

# ---------------------------------------------------------------- lift
$tokens = $null; $errors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile($AgentScript, [ref]$tokens, [ref]$errors)
if ($errors.Count -gt 0) { throw "parse errors in $AgentScript" }
$wanted = @(
    "Read-WebExceptionBody","Get-ClientSecret","Get-PropValue","ConvertTo-Base64Url","ConvertFrom-Base64Url",
    "Normalize-Thumbprint","Read-CredentialState","Write-CredentialState","Update-CredentialState",
    "Get-ActiveCertThumbprint","Get-PendingCertThumbprint","Get-CertStoreSearchOrder","Get-CertStoreName",
    "Find-ClientCertificate","New-ClientAssertionJwt","Get-AadstsCode","Get-TokenUrl","Invoke-TokenEndpoint",
    "Acquire-TokenWithCertificate","Acquire-TokenWithSecret","Acquire-Token","Get-CredentialTelemetry",
    "Write-CredentialStartupSummary","Get-AccessToken","New-BayClientCertificate","Export-PublicCertificate",
    "Build-CredentialEnrollResult","Invoke-CredentialEnroll","Invoke-CredentialTest","Invoke-CredentialActivate",
    "Invoke-CredentialRetire","Invoke-CredentialStatus","Invoke-CredentialRotate","Limit-ResultJson",
    "Test-IsAgentOwnedCertificate","Sync-FallbackTelemetry","Test-HasUsableSecret","Read-LastUpdateResult",
    # A0.458: the identity helpers the token path and activate now reach.
    "ConvertTo-AgentGuid","Get-ActiveClientId","Test-OwnIdentityActive","Get-IdentityProbation","Test-IdentityRefusal",
    "Register-IdentityProbationFailure","Clear-IdentityProbationFailures","Invoke-IdentityRevert","Test-IdentityCandidate",
    "Invoke-CredentialConfirm","Invoke-CredentialRevert"
)
$defs = $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $true)
foreach ($name in $wanted) {
    $d = $defs | Where-Object { $_.Name -eq $name } | Select-Object -First 1
    if (-not $d) { throw "function '$name' not found" }
    . ([scriptblock]::Create($d.Extent.Text))
}

$script:LogLines = New-Object System.Collections.ArrayList
function Write-Log { param([string]$Message, [string]$Level = "INFO") [void]$script:LogLines.Add("[$Level] $Message") }

$BaseDir = Join-Path $env:TEMP ("bayagent-attack-" + [guid]::NewGuid().ToString("N").Substring(0,8))
New-Item -ItemType Directory -Force -Path (Join-Path $BaseDir "state") | Out-Null
$CredentialStatePath = Join-Path $BaseDir "state\credential.json"
$TenantId = "11111111-1111-1111-1111-111111111111"
$ClientId = "22222222-2222-2222-2222-222222222222"
$OrgUrl   = "https://mock-org.crm.dynamics.com"
$BayId    = "33333333-3333-3333-3333-333333333333"
$TokenAuthorityHost = "http://127.0.0.1:1"
$AssertionAlg = "RS256"
# Read from THE AGENT, not declared here. The identical fault was found and fixed in the test file
# (it declared its own copy, so an assertion on it pinned the harness and passed whatever the agent
# shipped) and then left standing in this file, 280 lines from where it was written up as worth naming.
# A11 printed "ResultJsonMaxChars=2000" as a measurement when it was this script's own constant.
$ResultJsonMaxChars = 2000
$__capM = [regex]::Match([IO.File]::ReadAllText($AgentScript), '(?m)^\$ResultJsonMaxChars\s*=\s*(\d+)')
if ($__capM.Success) { $ResultJsonMaxChars = [int]$__capM.Groups[1].Value }
$CertThumbprintCfg = $null; $CertStoreCfg = $null
$Secret = $null; $SecretPath = $null; $SecretPathCfg = $null; $HasSecretCredential = $false
$Global:AccessToken = $null; $Global:TokenExpiresUtc = [DateTime]::MinValue
$Global:CredentialTelemetry = @{ lastMintMode=$null; lastMintUtc=$null; lastCertMintUtc=$null; lastSecretMintUtc=$null
    lastCertError=$null; lastSecretError=$null; fallbackCount=0; fallbackFlushed=0; lastFallbackUtc=$null; lastTest=$null }
# A0.458 script state the identity helpers read (mirrors BayAgent.ps1).
$IdentityProbationMaxFailures = 5; $IdentityProbationMaxHours = 72
$Global:IdentityProbationFailures = 0; $Global:CurrentCommandId = $null; $Global:LastDvErrorBody = $null
$script:MadeCerts = New-Object System.Collections.ArrayList

# ---------------------------------------------------------------- mock token endpoint
function Start-MockTokenEndpoint([hashtable]$Sync) {
    $rs = [runspacefactory]::CreateRunspace(); $rs.Open()
    $rs.SessionStateProxy.SetVariable("sync", $Sync)
    $ps = [powershell]::Create(); $ps.Runspace = $rs
    [void]$ps.AddScript({
        $listener = New-Object System.Net.Sockets.TcpListener([System.Net.IPAddress]::Loopback, 0)
        $listener.Start(); $sync["Port"] = ([System.Net.IPEndPoint]$listener.LocalEndpoint).Port
        try {
            while (-not $sync["Stop"]) {
                if (-not $listener.Server.Poll(200000, [System.Net.Sockets.SelectMode]::SelectRead)) { continue }
                $client = $listener.AcceptTcpClient()
                try {
                    $client.ReceiveTimeout = 5000; $stream = $client.GetStream()
                    $buf = New-Object byte[] 65536; $ms = New-Object System.IO.MemoryStream; $headerEnd = -1
                    while ($headerEnd -lt 0) {
                        $n = $stream.Read($buf, 0, $buf.Length); if ($n -le 0) { break }
                        $ms.Write($buf, 0, $n)
                        $headerEnd = ([Text.Encoding]::ASCII.GetString($ms.ToArray())).IndexOf("`r`n`r`n")
                    }
                    $all = $ms.ToArray(); $headText = [Text.Encoding]::ASCII.GetString($all, 0, $headerEnd)
                    $contentLength = 0
                    if ($headText -match "(?im)^Content-Length:\s*(\d+)") { $contentLength = [int]$Matches[1] }
                    $bodyStart = $headerEnd + 4
                    while (($all.Length - $bodyStart) -lt $contentLength) {
                        $n = $stream.Read($buf, 0, $buf.Length); if ($n -le 0) { break }
                        $ms.Write($buf, 0, $n); $all = $ms.ToArray()
                    }
                    $body = [Text.Encoding]::UTF8.GetString($all, $bodyStart, [Math]::Min($contentLength, $all.Length - $bodyStart))
                    [void]$sync["Requests"].Add(@{ requestLine = (($headText -split "`r`n")[0]); headers = $headText; body = $body })
                    $resp = if ($body.Contains("client_assertion=")) { $sync["CertResponse"] } else { $sync["SecretResponse"] }
                    $status = [int]$resp.status
                    $reason = "OK"; if ($status -eq 401) { $reason = "Unauthorized" } elseif ($status -ge 400) { $reason = "Bad Request" }
                    $bytes = [Text.Encoding]::UTF8.GetBytes([string]$resp.body)
                    $head = "HTTP/1.1 $status $reason`r`nContent-Type: application/json`r`nContent-Length: $($bytes.Length)`r`nConnection: close`r`n`r`n"
                    $hb = [Text.Encoding]::ASCII.GetBytes($head)
                    $stream.Write($hb,0,$hb.Length); $stream.Write($bytes,0,$bytes.Length); $stream.Flush()
                } catch { [void]$sync["Errors"].Add($_.Exception.Message) } finally { $client.Close() }
            }
        } finally { $listener.Stop() }
    })
    $h = $ps.BeginInvoke(); return @{ PS=$ps; RS=$rs; Handle=$h }
}
$sync = [hashtable]::Synchronized(@{ Stop=$false; Port=0
    Requests=[System.Collections.ArrayList]::Synchronized((New-Object System.Collections.ArrayList))
    Errors=[System.Collections.ArrayList]::Synchronized((New-Object System.Collections.ArrayList))
    CertResponse=@{ status=200; body='{"token_type":"Bearer","expires_in":3599,"access_token":"mock-cert-token"}' }
    SecretResponse=@{ status=200; body='{"token_type":"Bearer","expires_in":3599,"access_token":"mock-secret-token"}' } })
$mock = Start-MockTokenEndpoint -Sync $sync
$dl = (Get-Date).AddSeconds(10)
while ($sync["Port"] -eq 0 -and (Get-Date) -lt $dl) { Start-Sleep -Milliseconds 50 }
if ($sync["Port"] -eq 0) { throw "mock did not start" }
$TokenAuthorityHost = "http://127.0.0.1:$($sync['Port'])"
Write-Host "Mock token endpoint: $TokenAuthorityHost  (MOCK, not Entra)"
Write-Host "State dir: $BaseDir"

function Reset-State { if (Test-Path $CredentialStatePath) { Remove-Item $CredentialStatePath -Force } }
function New-ThrowawayCert([string]$subject = "CN=ABG-BayAgent attack", [int]$days = 30) {
    $c = New-SelfSignedCertificate -Type Custom -Subject $subject -CertStoreLocation "Cert:\CurrentUser\My" `
         -KeyAlgorithm RSA -KeyLength 2048 -HashAlgorithm sha256 -KeyExportPolicy NonExportable `
         -KeyUsage DigitalSignature -TextExtension @("2.5.29.37={text}1.3.6.1.5.5.7.3.2") `
         -Provider "Microsoft Software Key Storage Provider" -NotAfter (Get-Date).AddDays($days)
    [void]$script:MadeCerts.Add($c.Thumbprint); return $c
}

try {

# ================================================================ A1
Section "A1  retire secret=true on a bay whose only secret is the PLAINTEXT clientSecret"
Reset-State
$c1 = New-BayClientCertificate -Store "CurrentUser"; [void]$script:MadeCerts.Add($c1.Thumbprint)
Update-CredentialState @{ activeThumbprint = $c1.Thumbprint } | Out-Null
$script:Secret = "a-plaintext-secret-that-still-works"
$script:SecretPath = $null; $script:SecretPathCfg = $null
$script:HasSecretCredential = $true
$r1 = Invoke-CredentialRetire @{ secret = $true }
$stillWorks = $false
try { $null = Acquire-TokenWithSecret; $stillWorks = $true } catch {}
$okReported = [bool]$r1.ok
Attack "A1" "retire secret=true reports ok while the plaintext secret is untouched and still mints" `
  ($okReported -and $stillWorks) `
  ("result.ok={0}; secret.plaintextSecretStillInConfig={1}; note='{2}'; a token STILL minted with the secret afterwards={3}; HasSecretCredential still={4}" -f `
    $okReported, (Get-PropValue $r1.secret "plaintextSecretStillInConfig" $false), (Get-PropValue $r1.secret "note" ""), $stillWorks, $script:HasSecretCredential)

# ================================================================ A2
Section "A2  can any enroll payload field import caller-supplied key material?"
Reset-State
$script:Secret = $null; $script:HasSecretCredential = $false
$fakePfx = Join-Path $BaseDir "evil.pfx"
[IO.File]::WriteAllBytes($fakePfx, (New-Object byte[] 64))
$importNames = @("key","privateKey","pfx","pfxPath","pfxBase64","certificate","certificateBase64","cer","cerPath",
                 "path","filePath","file","url","uri","certUrl","import","importFrom","password","thumbprintFile",
                 "publicCertBase64","keyFile","pem","pemBase64","keyExportPolicy","exportable")
$payload = @{ action = "enroll"; force = $true }
foreach ($n in $importNames) { $payload[$n] = $fakePfx }
$payload["exportable"] = $true; $payload["keyExportPolicy"] = "Exportable"
$before = @(Get-ChildItem Cert:\CurrentUser\My | Select-Object -ExpandProperty Thumbprint)
$e2 = Invoke-CredentialEnroll $payload
[void]$script:MadeCerts.Add($e2.thumbprint)
$newCert = Get-ChildItem ("Cert:\CurrentUser\My\{0}" -f $e2.thumbprint)
$freshKey = ($newCert.Thumbprint -notin $before)
# Did any payload field influence what was created?
$subjectIsDefault = ($newCert.Subject -like "CN=ABG-BayAgent*")
Attack "A2" "an enroll payload stuffed with 25 import-shaped fields imports nothing; a fresh on-machine key is generated" `
  (-not ($freshKey -and $subjectIsDefault)) `
  ("thumbprint={0} freshlyGenerated={1} subject='{2}' - no payload field named a key, blob, path or URL that was honoured" -f $e2.thumbprint, $freshKey, $newCert.Subject)

# ================================================================ A3
Section "A3  can the private key be exported off the machine?"
$exportLanded = $false; $why = ""
try { $null = $newCert.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Pfx, "pw"); $exportLanded = $true; $why = "Export(Pfx) SUCCEEDED" }
catch { $why = "Export(Pfx) refused: " + $_.Exception.Message }
$rk = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($newCert)
$rawLanded = $false
try { $null = $rk.ExportParameters($true); $rawLanded = $true; $why += " ; ExportParameters(true) SUCCEEDED" }
catch { $why += " ; ExportParameters(true) refused: " + $_.Exception.Message }
# The public half must still be obtainable - that is the whole point of enroll.
$pubOk = ($e2.publicCertBase64 -and ([Convert]::FromBase64String($e2.publicCertBase64)).Length -gt 300)
Attack "A3" "the enrolled private key cannot be exported; only the public certificate is returned" `
  ($exportLanded -or $rawLanded) ("{0} ; publicCertBase64 present and parses as DER={1}" -f $why, $pubOk)

# ================================================================ A4
Section "A4  a second mint cannot silently overwrite the ACTIVE credential"
Reset-State
$act = New-BayClientCertificate -Store "CurrentUser"; [void]$script:MadeCerts.Add($act.Thumbprint)
Update-CredentialState @{ activeThumbprint = $act.Thumbprint } | Out-Null
$script:HasSecretCredential = $false
$eA = Invoke-CredentialEnroll @{ action="enroll" }; [void]$script:MadeCerts.Add($eA.thumbprint)
$activeAfter1 = Get-ActiveCertThumbprint
$eB = Invoke-CredentialEnroll @{ action="enroll"; force=$true }; [void]$script:MadeCerts.Add($eB.thumbprint)
$activeAfter2 = Get-ActiveCertThumbprint
$stAfter = Read-CredentialState
$pendingAfter = [string](Get-PropValue $stAfter "pendingThumbprint" "")
Attack "A4a" "two successive enrolls leave the ACTIVE thumbprint untouched" `
  (($activeAfter1 -ne $act.Thumbprint) -or ($activeAfter2 -ne $act.Thumbprint)) `
  ("active before={0} after enroll1={1} after forced enroll2={2}" -f $act.Thumbprint.Substring(0,12), $activeAfter1.Substring(0,12), $activeAfter2.Substring(0,12))
$orphan = ($eA.thumbprint -ne $eB.thumbprint) -and ($pendingAfter -eq $eB.thumbprint) -and (Find-ClientCertificate $eA.thumbprint)
$stJson = (Get-Content $CredentialStatePath -Raw)
$orphanRecorded = $stJson.Contains($eA.thumbprint)
Attack "A4b" "a forced re-enroll ORPHANS the previous pending key: it stays in the store but is no longer named in credential.json" `
  ([bool]($orphan -and -not $orphanRecorded)) `
  ("enroll1 tp={0} enroll2 tp={1} pendingThumbprint now={2}; enroll1 key still in CurrentUser\My={3}; enroll1 tp still named in credential.json={4}" -f `
    $eA.thumbprint.Substring(0,12), $eB.thumbprint.Substring(0,12), $pendingAfter.Substring(0,12), [bool](Find-ClientCertificate $eA.thumbprint), $orphanRecorded)

# ================================================================ A5
Section "A5  can any CredentialRotate action reset the durable fallbackCountTotal?"
Reset-State
$c5 = New-BayClientCertificate -Store "CurrentUser"; [void]$script:MadeCerts.Add($c5.Thumbprint)
Update-CredentialState @{ activeThumbprint = $c5.Thumbprint } | Out-Null
$script:Secret = "s"; $script:SecretPath = $null; $script:HasSecretCredential = $true
$Global:CredentialTelemetry.fallbackCount = 7; $Global:CredentialTelemetry.fallbackFlushed = 0
$Global:CredentialTelemetry.lastFallbackUtc = "2026-09-14T00:00:00Z"
$null = Sync-FallbackTelemetry
$base = [int](Get-PropValue (Read-CredentialState) "fallbackCountTotal" 0)
$attempts = @(
  @{ n="status";   p=@{ action="status" } }
  @{ n="enroll";   p=@{ action="enroll"; force=$true; fallbackCountTotal=0 } }
  @{ n="test";     p=@{ action="test"; fallbackCountTotal=0 } }
  @{ n="activate"; p=@{ action="activate"; thumbprint=$c5.Thumbprint; fallbackCountTotal=0 } }
  @{ n="retire";   p=@{ action="retire"; secret=$true; fallbackCountTotal=0 } }
)
$resetBy = @()
foreach ($a in $attempts) {
    try { $null = Invoke-CredentialRotate $a.p } catch {}
    $now = [int](Get-PropValue (Read-CredentialState) "fallbackCountTotal" 0)
    if ($now -lt $base) { $resetBy += ("{0} -> {1}" -f $a.n, $now) }
}
$final = [int](Get-PropValue (Read-CredentialState) "fallbackCountTotal" 0)
Attack "A5" "no CredentialRotate action (with a fallbackCountTotal field in its payload) can lower the durable total" `
  ($resetBy.Count -gt 0) ("total before={0} after status/enroll/test/activate/retire={1}; actions that lowered it: {2}" -f $base, $final, $(if ($resetBy.Count) { $resetBy -join ", " } else { "none" }))

# ================================================================ A6
Section "A6  a corrupt or truncated credential.json"
Reset-State
$c6 = New-BayClientCertificate -Store "CurrentUser"; [void]$script:MadeCerts.Add($c6.Thumbprint)
Update-CredentialState @{ activeThumbprint = $c6.Thumbprint; retiredThumbprints = @("AAAA") } | Out-Null
$Global:CredentialTelemetry.fallbackCount = 11; $Global:CredentialTelemetry.fallbackFlushed = 0
$null = Sync-FallbackTelemetry
$preTotal = [int](Get-PropValue (Read-CredentialState) "fallbackCountTotal" 0)
[IO.File]::WriteAllText($CredentialStatePath, '{"activeThumbprint":"' + $c6.Thumbprint + '", "fallbackCountTot')  # truncated
$corruptBytes = [IO.File]::ReadAllText($CredentialStatePath)
$readBack = Read-CredentialState
$activeLost = ($null -eq $readBack)
$script:LogLines.Clear()
$Global:CredentialTelemetry.fallbackCount = 12; $Global:CredentialTelemetry.fallbackFlushed = 11
$null = Sync-FallbackTelemetry
# ⚠️ THE ORIGINAL ORACLE HERE WAS `$activeLost -and $postTotal -lt $preTotal`, AND IT CANNOT BE SATISFIED
# BY ANY CORRECT IMPLEMENTATION. Both halves are true the moment the file stops parsing: a corrupt file
# reads as no-state, so the total read back from it is 0, whatever the agent does. It scored the damage
# the CORRUPTION did, not the damage the AGENT did -- and the only way to make it read "held" would be to
# silently repair or overwrite the file, which is precisely the behaviour being attacked. Rewritten to
# measure the actual claim: did the agent OVERWRITE the file, was it merely a WARN, and does the heartbeat
# still present a healthy-looking zero?
$fileOverwritten = ([IO.File]::ReadAllText($CredentialStatePath) -ne $corruptBytes)
$onlyAWarn = -not (@($script:LogLines | Where-Object { $_ -match "^\[ERROR\]" }).Count -ge 1)
$tel6 = Get-CredentialTelemetry
$reportsCleanZero = ($tel6.fallbackCountTotal -eq 0)
$hidesIt = -not ($tel6.stateFileCorrupt -eq $true)
$backupExists = (Test-Path "$CredentialStatePath.bak")
Attack "A6" "a truncated credential.json silently resets activeThumbprint, retiredThumbprints AND fallbackCountTotal to zero, with only a WARN" `
  ($fileOverwritten -or $onlyAWarn -or $reportsCleanZero -or $hidesIt -or (-not $backupExists)) `
  ("file overwritten={0}; only-a-WARN={1}; heartbeat reports a clean zero total={2} (value='{3}'); corruption hidden from heartbeat={4}; .bak present for recovery={5}" -f `
    $fileOverwritten, $onlyAWarn, $reportsCleanZero, "$($tel6.fallbackCountTotal)", $hidesIt, $backupExists)

# ================================================================ A7
Section "A7  cert CONFIGURED but not present / not activated - is it ever reported as 'certificate' minting?"
Reset-State
$script:CertThumbprintCfg = ("A" * 40)
$script:Secret = "s"; $script:SecretPath = $null; $script:HasSecretCredential = $true
$Global:CredentialTelemetry.lastMintMode = $null
$Global:AccessToken = $null; $Global:TokenExpiresUtc = [DateTime]::MinValue
$null = Acquire-Token
$tel = Get-CredentialTelemetry
$claimsCert = ($tel.lastMintMode -eq "certificate")
$foundFlag = $(if ($tel.activeCertificate) { [bool](Get-PropValue $tel.activeCertificate "found" $false) } else { "n/a" })
Attack "A7" "a configured-but-absent certificate never reports lastMintMode=certificate" `
  $claimsCert ("configuredMode='{0}' lastMintMode='{1}' activeCertificate.found={2} fallbackCount={3} lastCertError present={4}" -f `
    $tel.configuredMode, $tel.lastMintMode, $foundFlag, $tel.fallbackCount, [bool]$tel.lastCertError)
$script:CertThumbprintCfg = $null

# ================================================================ A8
Section "A8  after retire, can any command path re-enable the secret?"
Reset-State
$c8 = New-BayClientCertificate -Store "CurrentUser"; [void]$script:MadeCerts.Add($c8.Thumbprint)
Update-CredentialState @{ activeThumbprint = $c8.Thumbprint } | Out-Null
$dpapiFile = Join-Path $BaseDir "clientsecret.dpapi"
[IO.File]::WriteAllBytes($dpapiFile, [System.Security.Cryptography.ProtectedData]::Protect(
    [Text.Encoding]::UTF8.GetBytes("the-secret"), $null, [System.Security.Cryptography.DataProtectionScope]::LocalMachine))
$script:Secret = $null; $script:SecretPath = $dpapiFile; $script:SecretPathCfg = $dpapiFile; $script:HasSecretCredential = $true
$r8 = Invoke-CredentialRetire @{ secret = $true }
$fileGone = -not (Test-Path $dpapiFile)
# now try every action to get it back
$reEnabled = $false; $how = @()
foreach ($p in @(@{action="status"}, @{action="enroll";force=$true}, @{action="test";includeSecret=$true},
                 @{action="activate";thumbprint=$c8.Thumbprint}, @{action="retire";secret=$false;thumbprint=$c8.Thumbprint},
                 @{action="enroll";clientSecret="new"; clientSecretDpapiPath=$dpapiFile; secretPath=$dpapiFile})) {
    try { $null = Invoke-CredentialRotate $p } catch {}
    if ((Test-Path $dpapiFile) -or $script:SecretPath -or $script:Secret) { $reEnabled = $true; $how += $p.action }
}
Attack "A8" "after retire secret=true no command can restore the DPAPI file, SecretPath or plaintext secret" `
  $reEnabled ("dpapi file removed={0}; SecretPath now='{1}'; Secret now='{2}'; actions that restored it: {3}; agent-config.json is never written by the agent (only read at lines 51/97)" -f `
    $fileGone, $(if($script:SecretPath){"set"}else{"null"}), $(if($script:Secret){"set"}else{"null"}), $(if($how.Count){$how -join ","}else{"none"}))

# ================================================================ A9
Section "A9  subject collision - a certificate this agent did NOT create but whose subject starts CN=ABG-BayAgent"
Reset-State
$c9active = New-BayClientCertificate -Store "CurrentUser"; [void]$script:MadeCerts.Add($c9active.Thumbprint)
Update-CredentialState @{ activeThumbprint = $c9active.Thumbprint } | Out-Null
$victim = New-ThrowawayCert "CN=ABG-BayAgent Code Signing DO NOT DELETE" 400
$owned = Test-IsAgentOwnedCertificate -Thumbprint $victim.Thumbprint
$deleted = $false
try { $null = Invoke-CredentialRetire @{ thumbprint = $victim.Thumbprint }; $deleted = -not (Test-Path ("Cert:\CurrentUser\My\{0}" -f $victim.Thumbprint)) } catch {}
Attack "A9" "retire will destroy ANY certificate in the agent's stores whose subject merely STARTS WITH 'CN=ABG-BayAgent', even one the agent never created or recorded" `
  ($owned -and $deleted) ("Test-IsAgentOwnedCertificate('{0}')={1}; retire deleted it with its private key={2}; subject was '{3}'" -f `
    $victim.Thumbprint.Substring(0,12), $owned, $deleted, $victim.Subject)

# ================================================================ A10
Section "A10 retire ordering - the certificate deletion runs BEFORE the secret proof"
Reset-State
$cA = New-BayClientCertificate -Store "CurrentUser"; [void]$script:MadeCerts.Add($cA.Thumbprint)
$old = New-BayClientCertificate -Store "CurrentUser"; [void]$script:MadeCerts.Add($old.Thumbprint)
Update-CredentialState @{ activeThumbprint = $cA.Thumbprint; previousThumbprint = $old.Thumbprint } | Out-Null
$script:Secret = $null; $script:SecretPath = $null; $script:HasSecretCredential = $false
$sync["CertResponse"] = @{ status = 401; body = '{"error":"invalid_client","error_description":"AADSTS700027: no matching key"}' }
$threw = $false
try { $null = Invoke-CredentialRetire @{ thumbprint = $old.Thumbprint; secret = $true } } catch { $threw = $true }
$oldGone = -not (Find-ClientCertificate $old.Thumbprint)
$sync["CertResponse"] = @{ status = 200; body = '{"token_type":"Bearer","expires_in":3599,"access_token":"mock-cert-token"}' }
Attack "A10" "a combined retire {thumbprint + secret:true} deletes the named certificate FIRST and only then fails the live proof - the deletion is not rolled back" `
  ($threw -and $oldGone) ("the live proof threw={0}; the named certificate was already destroyed={1}; command is marked Failed although a key was irreversibly deleted" -f $threw, $oldGone)

# ================================================================ A11
Section "A11 the 2000-char result cap is a hardcoded mirror, never re-measured"
$hard = $ResultJsonMaxChars
$srcTxt = [IO.File]::ReadAllText($AgentScript)
# ⚠️ THE ORIGINAL ORACLE WAS A GREP FOR THE WORDS "MaxLength" / "EntityDefinitions" ANYWHERE IN THE FILE,
# INCLUDING COMMENTS -- so simply DOCUMENTING that the cap is a Dev measurement flipped this attack to
# "held" with no behaviour changed at all. That is a false pass, and it was observed happening
# (2026-09-14). Strip comments before grepping, and score the disposition that was actually chosen:
# the cap stays a constant, but it must be DOCUMENTED as Dev-measured and OVERRIDABLE per tenant, so a
# customer environment whose column differs can be corrected without a code change.
$codeOnly = ($srcTxt -split "`n" | Where-Object { $_ -notmatch '^\s*#' }) -join "`n"
$queriesColumn = ($codeOnly -match "EntityDefinitions")
$documented    = ($srcTxt -match "(?i)MEASURED against DEV" -and $srcTxt -match "(?i)resultJsonMaxChars")
$overridable   = ($codeOnly -match 'resultJsonMaxChars')
Attack "A11" "the 2000-char cap is an undocumented, unoverridable mirror of a Dev-only measurement" `
  (-not ($queriesColumn -or ($documented -and $overridable))) `
  ("ResultJsonMaxChars={0}; queries EntityDefinitions in CODE (comments stripped)={1}; documented as a Dev measurement={2}; overridable from agent-config.json={3}" -f $hard, $queriesColumn, $documented, $overridable)

} finally {
    $sync["Stop"] = $true
    try { $mock.PS.Stop() } catch {}
    try { $mock.RS.Close() } catch {}
    foreach ($tp in $script:MadeCerts) {
        try { if (Test-Path "Cert:\CurrentUser\My\$tp") { Remove-Item "Cert:\CurrentUser\My\$tp" -DeleteKey -Force -ErrorAction SilentlyContinue } } catch {}
    }
    Write-Host ""
    Write-Host "Cleaned up $($script:MadeCerts.Count) throwaway certificates from Cert:\CurrentUser\My"
    $leftovers = @($script:MadeCerts | Where-Object { Test-Path "Cert:\CurrentUser\My\$_" })
    Write-Host ("Leftovers: {0}" -f $(if ($leftovers.Count) { $leftovers -join "," } else { "none" }))
    try { Remove-Item -Recurse -Force $BaseDir -ErrorAction SilentlyContinue } catch {}
}

Write-Host ""
Write-Host "==== ATTACK RESULTS ===="
$script:Rows | Select-Object Id, Landed, Claim | Format-Table -AutoSize -Wrap | Out-String -Width 190 | Write-Host
Write-Host ("Attacks that LANDED: {0}   held: {1}" -f $script:Land, $script:Hold)
