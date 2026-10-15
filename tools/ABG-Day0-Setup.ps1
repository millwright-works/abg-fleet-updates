<# 
ABG-Day0-Setup.ps1
Day 0 bootstrap for a new bay PC (AllSigned-friendly) + optional Dataverse ConfigItem registration.

Run as Administrator.

Example:
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\ABG-Day0-Setup.ps1 `
  -FleetRawBaseUrl "https://raw.githubusercontent.com/millwright-works/abg-fleet-updates/main/src/BayAgent" `
  -BayKioskUser "BayKiosk" `
  -RegisterConfigItems `
  -EnvironmentUrl "https://builds-apps-dev.crm.dynamics.com" `
  -TenantId "<tenant-guid>" `
  -ClientId "<app-client-id>" `
  -ClientSecretDpapiPath "C:\AllBirdies\BayAgent\secrets\clientsecret.dpapi" `
  -BayId "<bay-guid>"

Notes:
- Uses client_credentials token scope: <EnvironmentUrl>/.default
- Creates ConfigItem records (upsert) for thumbprint + key unique name.
- Signs bootstrap/tools scripts (RFC 3161 timestamped) so signatures outlive the
  signing certificate's own expiry -- see -TimeStampServer below.
#>

[CmdletBinding()]
param(
  [string]$AllBirdiesRoot = "C:\AllBirdies",
  [string]$BayKioskUser = "BayKiosk",

  # Raw GitHub base for downloading scripts
  [Parameter(Mandatory=$true)]
  [string]$FleetRawBaseUrl,

  # Scheduled tasks
  [switch]$CreateAgentTask = $false,
  [string]$BayKioskPassword = "",
  [switch]$CreateWatchdogTask = $true,

  # Cert subject
  [string]$CertSubject = "CN=ABG Bay Code Signing",

  # Config template
  [switch]$WriteAgentConfigTemplate = $true,
  # Values for the agent-config.json template, and for nothing else. Kept apart from -EnvironmentUrl, -TenantId,
  # -ClientId and -BayId below (which drive -RegisterConfigItems) so that a caller's DEFAULT for those can never land
  # in a bay's configuration: Setup-BayPC.ps1 passes these four only for values its operator typed. Empty = the
  # template keeps its <placeholder>.
  [string]$ConfigEnvironmentUrl = "",
  [string]$ConfigTenantId = "",
  [string]$ConfigClientId = "",
  [string]$ConfigBayId = "",

  # Place bootstrap\ABG.SetClientSecretDpapi.ps1 on this PC. Only for a bay being set up for the legacy secret
  # credential; a certificate bay is given neither the shared secret nor the tool that seals one (A0.529).
  [switch]$PlaceSecretTool = $false,

  # ---- Dataverse ConfigItem registration ----
  [switch]$RegisterConfigItems = $false,
  [string]$EnvironmentUrl = "",
  [string]$TenantId = "",
  [string]$ClientId = "",
  [string]$ClientSecretDpapiPath = "",
  [string]$BayId = "",

  # Entity set + field logical names (defaults match your schema screenshots)
  [string]$ConfigItemEntitySet = "build_configitems",
  [string]$ConfigItemIdField = "build_configitemid",
  [string]$Cfg_KeyField = "build_key",
  [string]$Cfg_ValueField = "build_value",
  [string]$Cfg_EnabledField = "build_enabled",
  [string]$Cfg_ScopeField = "build_scope",
  [string]$Cfg_BayLookupField = "build_bay",      # lookup logical name
  [string]$BayEntitySet = "build_baies",

  # RFC 3161 timestamp server used when signing bootstrap/tools scripts on Day 0.
  # A timestamped Authenticode signature stays valid after the signing certificate
  # itself expires; an untimestamped one does not. Must be HTTP, not HTTPS --
  # Set-AuthenticodeSignature does not support HTTPS timestamp URLs. Override only
  # if DigiCert's responder endpoint moves or a different CA is used.
  [string]$TimeStampServer = "http://timestamp.digicert.com"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Ensure-Dir([string]$p) {
  if (-not (Test-Path -LiteralPath $p)) { New-Item -ItemType Directory -Path $p -Force | Out-Null }
}

function Write-Step($msg) { Write-Host ("`n=== {0} ===" -f $msg) }

function Download-File([string]$url, [string]$outPath) {
  [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
  Ensure-Dir (Split-Path -Parent $outPath)
  Write-Host "Downloading: $url"
  Invoke-WebRequest -Uri $url -OutFile $outPath -UseBasicParsing -MaximumRedirection 10
  if (-not (Test-Path -LiteralPath $outPath)) { throw "Download failed: $outPath" }
}

function Get-CodeSigningCertOrCreate() {
  $existing = @(Get-ChildItem Cert:\LocalMachine\My | Where-Object {
      $_.EnhancedKeyUsageList.FriendlyName -contains "Code Signing" -and
      $_.HasPrivateKey -and
      $_.Subject -like "*ABG*"
    } | Sort-Object NotAfter -Descending)

  if ($existing.Count -gt 0) {
    Write-Host "Found existing code signing cert: $($existing[0].Subject) Thumbprint=$($existing[0].Thumbprint)"
    return $existing[0]
  }

  Write-Host "Creating new code signing cert: $CertSubject"
  $cert = New-SelfSignedCertificate `
    -Type CodeSigningCert `
    -Subject $CertSubject `
    -CertStoreLocation "Cert:\LocalMachine\My" `
    -HashAlgorithm sha256 `
    -KeyLength 2048

  if (-not $cert.HasPrivateKey) { throw "Created cert but no private key present." }
  Write-Host "Created cert Thumbprint=$($cert.Thumbprint) NotAfter=$($cert.NotAfter)"

  # Trust it on this machine
  $tmpCer = Join-Path $env:TEMP "abg-bay-codesign.cer"
  Export-Certificate -Cert "Cert:\LocalMachine\My\$($cert.Thumbprint)" -FilePath $tmpCer | Out-Null
  Import-Certificate -FilePath $tmpCer -CertStoreLocation "Cert:\LocalMachine\TrustedPublisher" | Out-Null
  Import-Certificate -FilePath $tmpCer -CertStoreLocation "Cert:\LocalMachine\Root" | Out-Null

  Write-Host "TrustedPublisher + Root updated."
  return $cert
}

function Get-CertUniqueContainerName([string]$thumbprint) {
  $out = (certutil -store My $thumbprint) 2>&1 | Out-String
  $match = [regex]::Match($out, "Unique container name:\s*(.+)")
  if (-not $match.Success) { throw "Could not find 'Unique container name' in certutil output.`n$out" }
  return $match.Groups[1].Value.Trim()
}

function Grant-Kiosk-KeyAccess([string]$uniqueName, [string]$kioskAccount) {
  $keyPath = Join-Path $env:ProgramData ("Microsoft\Crypto\Keys\{0}" -f $uniqueName)
  if (-not (Test-Path -LiteralPath $keyPath)) { throw "Key file not found: $keyPath" }

  Write-Host "Granting $kioskAccount read access to key file:"
  Write-Host "  $keyPath"
  icacls "$keyPath" /grant "${kioskAccount}:(R)" | Out-Null

  Write-Host "Key ACL now:"
  icacls "$keyPath"
}

function Sign-File([string]$path, $cert, [string]$timeStampServer) {
  if (-not (Test-Path -LiteralPath $path)) { throw "Cannot sign missing file: $path" }
  Set-AuthenticodeSignature -FilePath $path -Certificate $cert -TimeStampServer $timeStampServer | Out-Null
  $sig = Get-AuthenticodeSignature $path
  if ($sig.Status -ne "Valid") { throw "Signature invalid for $path. Status=$($sig.Status) Message=$($sig.StatusMessage)" }
  if ($null -eq $sig.TimeStamperCertificate) {
    # Set-AuthenticodeSignature can silently sign WITHOUT a timestamp and still report
    # Status=Valid if the timestamp server was unreachable or rejected the request --
    # that untimestamped signature stops validating the moment the signing cert expires.
    # Hard-fail rather than provision a bay PC with that fault baked in from Day 0.
    throw "Signature for $path is Valid but UNTIMESTAMPED (server: $timeStampServer). Refusing to provision with an untimestamped signature."
  }
}

function Set-AgentConfigTemplateValues {
  # Put the values the installer already has into the template text, so nobody hand-edits JSON on a kiosk for values
  # that were typed on the command line. A value that is empty, or that is not what its field needs (a GUID for the
  # three ids, an https address for the org), is NOT written: its placeholder stays, visibly unfilled, instead of a
  # typo becoming the bay's configuration. Returns the text and the list of fields still holding a placeholder.
  param(
    [Parameter(Mandatory = $true)][string]$Template,
    [string]$EnvironmentUrl = "",
    [string]$TenantId = "",
    [string]$ClientId = "",
    [string]$BayId = ""
  )
  $text = $Template
  $g = [guid]::Empty
  if (-not [string]::IsNullOrWhiteSpace($EnvironmentUrl) -and $EnvironmentUrl.Trim() -match '^https://[A-Za-z0-9.-]+/?$') {
    $text = $text.Replace('https://<your-org>.crm.dynamics.com', $EnvironmentUrl.Trim().TrimEnd('/'))
  }
  foreach ($pair in @(@('<tenant-guid>', $TenantId), @('<app-client-id>', $ClientId), @('<bay-guid>', $BayId))) {
    $value = [string]$pair[1]
    if (-not [string]::IsNullOrWhiteSpace($value) -and [guid]::TryParse($value.Trim(), [ref]$g) -and $g -ne [guid]::Empty) {
      $text = $text.Replace([string]$pair[0], $g.ToString("D"))
    }
  }
  $left = @()
  foreach ($ph in @('<your-org>', '<tenant-guid>', '<app-client-id>', '<bay-guid>')) { if ($text.Contains($ph)) { $left += $ph } }
  return [ordered]@{ text = $text; unfilled = $left }
}

function Write-AgentConfigTemplateIfMissing([string]$path, [string]$envUrl = "", [string]$tenant = "", [string]$client = "", [string]$bay = "") {
  if (Test-Path -LiteralPath $path) { Write-Host "agent-config.json exists; not overwriting."; return }

  $template = @"
{
  "environmentUrl": "https://<your-org>.crm.dynamics.com",
  "tenantId": "<tenant-guid>",
  "clientId": "<app-client-id>",
  "clientSecretDpapiPath": "C:\\AllBirdies\\BayAgent\\secrets\\clientsecret.dpapi",
  "clientCertThumbprint": "",
  "bayId": "<bay-guid>",
  "pollSeconds": 3,
  "heartbeatSeconds": 60,
  "heartbeatEnabled": true,
  "postSessionThanksSeconds": 120,
  "postSessionThanksEnabled": true,
  "knownGoodSeconds": 60,
  "logLevel": "INFO",
  "sessionJsonPath": "C:\\AllBirdies\\SessionDisplay\\data\\session.json",
  "launcher": {
    "path": "C:\\Uneekor\\Launcher\\UneekorLauncher.exe",
    "args": "",
    "processName": "UneekorLauncher",
    "displayRole": "control",
    "startOnPrep": false,
    "startOnStart": true
  },
  "sessionDisplay": {
    "mode": "kiosk",
    "displayRole": "session",
    "url": "file:///C:/AllBirdies/SessionDisplay/current/index.html",
    "profileDir": "C:\\AllBirdies\\SessionDisplay\\edge-profile"
  }
}
"@
  Ensure-Dir (Split-Path -Parent $path)
  $filled = Set-AgentConfigTemplateValues -Template $template -EnvironmentUrl $envUrl -TenantId $tenant -ClientId $client -BayId $bay
  $filled.text | Set-Content -LiteralPath $path -Encoding UTF8
  Write-Host "Wrote agent-config.json template to: $path"
  if (@($filled.unfilled).Count -gt 0) {
    Write-Host ("  STILL TO FILL IN by hand before the agent can start: " + (@($filled.unfilled) -join ", "))
  } else {
    Write-Host "  environmentUrl, tenantId, clientId and bayId were filled from this command line."
  }
}

function Ensure-SessionDisplayPersistentFiles([string]$dataDir) {
  Ensure-Dir $dataDir

  # ensure promos assets folder exists (used by PromosPack /MIR installs)
  Ensure-Dir (Join-Path $dataDir "promos")

  $sessionJson = Join-Path $dataDir "session.json"
  $promosJson  = Join-Path $dataDir "promos.json"

  if (-not (Test-Path $sessionJson)) {
    '{"status":"idle","updatedUtc":""}' | Set-Content -LiteralPath $sessionJson -Encoding UTF8
  }

  # use the schema we expect: { "promos": [] }
  if (-not (Test-Path $promosJson))  {
    '{ "promos": [] }' | Set-Content -LiteralPath $promosJson -Encoding UTF8
  }
}

# Runs schtasks.exe and THROWS, with the text schtasks printed, when it exits non-zero. Both streams are kept (the
# error preference is lowered for the call because Windows PowerShell 5.1 turns merged native stderr into a
# terminating error under Stop), and the exit code is read on the very next line. A registration that failed used to
# print "Created/updated" anyway.
function Invoke-SchtasksChecked([string[]]$schtasksArgs, [string]$what) {
  $savedPref = $ErrorActionPreference
  $ErrorActionPreference = "Continue"
  $global:LASTEXITCODE = 0
  try {
    $out = schtasks @schtasksArgs 2>&1
    $rc = $LASTEXITCODE
  } finally {
    $ErrorActionPreference = $savedPref
  }
  if ($rc -ne 0) {
    $text = ((@($out) | ForEach-Object { if ($_ -is [System.Management.Automation.ErrorRecord]) { [string]$_.Exception.Message } else { [string]$_ } } | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }) -join " ").Trim()
    throw ("{0} failed: schtasks exit {1}: {2}" -f $what, $rc, $text)
  }
}

function Create-WatchdogTask([string]$watchdogPath) {
  $tn = "\ABG Host Watchdog"
  $tr = "powershell.exe -NoProfile -File `"$watchdogPath`""
  Invoke-SchtasksChecked -schtasksArgs @("/Create", "/F", "/TN", $tn, "/SC", "MINUTE", "/MO", "1", "/RU", "SYSTEM", "/RL", "HIGHEST", "/TR", $tr) -what "Registering $tn"
  Write-Host "Created/updated scheduled task: $tn (SYSTEM, every 1 minute)"
}

# The agent task is INTERACTIVE ONLY, with NO stored password (measured on Bay 1, 2026-10-15): the old registration
# (schtasks /RU /RP /IT, a stored BayKiosk password) could never be started (0x80070490, "Element not found") by the
# logon trigger, the watchdog or Start-ScheduledTask; this registration started at once. Same pattern as the Update
# Guard in Update-BayAgent.ps1. Task Scheduler's own start limit is turned OFF (zero): the host is a supervisor meant to
# run until the PC restarts, and the 72-hour default would end it (and maybe orphan the agent it supervises) while
# the watchdog is only a safety net that brings it back up to a minute later. The battery flags keep a UPS that reports
# itself as a battery from stopping it. $kioskPassword is accepted for older callers and ignored.
function Create-AgentTask([string]$agentHostPath, [string]$kioskAccount, [string]$kioskPassword) {
  $tn = "ABG Bay Agent"
  $psArgs = "-NoProfile -WindowStyle Minimized -File `"$agentHostPath`""
  $action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument $psArgs
  $trigger = New-ScheduledTaskTrigger -AtLogOn
  $principal = New-ScheduledTaskPrincipal -UserId $kioskAccount -LogonType Interactive -RunLevel Limited
  $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -MultipleInstances IgnoreNew -ExecutionTimeLimit (New-TimeSpan -Seconds 0)
  Register-ScheduledTask -TaskName $tn -TaskPath "\" -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Force -ErrorAction Stop | Out-Null
  Write-Host "Created/updated scheduled task: \$tn (at logon, Interactive as $kioskAccount, no stored password, no time limit)"
}

# ---------- Dataverse helpers ----------

function Get-ClientSecretFromDpapiFile([string]$path) {
  if (-not (Test-Path -LiteralPath $path)) { throw "DPAPI secret file not found: $path" }
  Add-Type -AssemblyName System.Security | Out-Null
  $bytes = [System.IO.File]::ReadAllBytes($path)
  $plain = [System.Security.Cryptography.ProtectedData]::Unprotect($bytes, $null, [System.Security.Cryptography.DataProtectionScope]::LocalMachine)
  return [System.Text.Encoding]::UTF8.GetString($plain)
}

function Get-DataverseToken([string]$envUrl, [string]$tenantId, [string]$clientId, [string]$clientSecret) {
  $tokenUrl = "https://login.microsoftonline.com/$tenantId/oauth2/v2.0/token"
  $body = @{
    client_id     = $clientId
    client_secret = $clientSecret
    grant_type    = "client_credentials"
    scope         = ($envUrl.TrimEnd("/") + "/.default")
  }
  $resp = Invoke-RestMethod -Method Post -Uri $tokenUrl -ContentType "application/x-www-form-urlencoded" -Body $body
  if (-not $resp.access_token) { throw "Token request did not return access_token." }
  return $resp.access_token
}

function Invoke-Dv([string]$method, [string]$envUrl, [string]$path, [string]$token, $body = $null) {
  $uri = $envUrl.TrimEnd("/") + "/api/data/v9.2/" + $path.TrimStart("/")
  $headers = @{
    Authorization      = "Bearer $token"
    "OData-MaxVersion" = "4.0"
    "OData-Version"    = "4.0"
    Accept             = "application/json"
  }
  if ($method -in @("POST","PATCH","PUT")) {
    $headers["Content-Type"] = "application/json; charset=utf-8"
  }
  if ($null -eq $body) {
    return Invoke-RestMethod -Method $method -Uri $uri -Headers $headers
  } else {
    $json = ($body | ConvertTo-Json -Depth 20)
    return Invoke-RestMethod -Method $method -Uri $uri -Headers $headers -Body $json
  }
}

function Get-ChoiceValueByLabel([string]$envUrl, [string]$token, [string]$entityLogical, [string]$attrLogical, [string]$labelToFind) {
  $metaPath = "EntityDefinitions(LogicalName='$entityLogical')/Attributes(LogicalName='$attrLogical')/Microsoft.Dynamics.CRM.PicklistAttributeMetadata?`$select=LogicalName&`$expand=OptionSet(`$select=Options)"
  $meta = Invoke-Dv -method "GET" -envUrl $envUrl -path $metaPath -token $token

  $options = $meta.OptionSet.Options
  foreach ($opt in $options) {
    foreach ($lbl in $opt.Label.LocalizedLabels) {
      if ($lbl.Label -eq $labelToFind) { return [int]$opt.Value }
    }
  }
  throw "Could not find option label '$labelToFind' for $entityLogical.$attrLogical"
}

function Upsert-ConfigItemForBay([string]$envUrl, [string]$token, [guid]$bayGuid, [int]$scopeValue, [string]$keyName, [string]$val) {
  $filter = "$Cfg_KeyField eq '$keyName' and _${Cfg_BayLookupField}_value eq $bayGuid"
  $qry = "$ConfigItemEntitySet?`$select=$ConfigItemIdField&`$filter=$filter"
  $res = Invoke-Dv -method "GET" -envUrl $envUrl -path $qry -token $token

  $payload = @{
    $Cfg_KeyField     = $keyName
    $Cfg_ValueField   = $val
    $Cfg_EnabledField = $true
    $Cfg_ScopeField   = $scopeValue
    ("$Cfg_BayLookupField@odata.bind") = "/$BayEntitySet($bayGuid)"
  }

  if ($res.value -and $res.value.Count -gt 0) {
    $id = $res.value[0].$ConfigItemIdField
    Invoke-Dv -method "PATCH" -envUrl $envUrl -path "$ConfigItemEntitySet($id)" -token $token -body $payload | Out-Null
    Write-Host "Updated ConfigItem: $keyName"
  } else {
    Invoke-Dv -method "POST" -envUrl $envUrl -path $ConfigItemEntitySet -token $token -body $payload | Out-Null
    Write-Host "Created ConfigItem: $keyName"
  }
}

# ---------------- MAIN ----------------

Write-Step "Folder structure"
$bayAgentDir   = Join-Path $AllBirdiesRoot "BayAgent"
$sessionDir    = Join-Path $AllBirdiesRoot "SessionDisplay"

@(
  $bayAgentDir,
  (Join-Path $bayAgentDir "bootstrap"),
  (Join-Path $bayAgentDir "tools"),
  (Join-Path $bayAgentDir "current"),
  (Join-Path $bayAgentDir "releases"),
  (Join-Path $bayAgentDir "staging"),
  (Join-Path $bayAgentDir "logs"),
  (Join-Path $bayAgentDir "state"),
  (Join-Path $bayAgentDir "control"),
  (Join-Path $bayAgentDir "secrets")
) | ForEach-Object { Ensure-Dir $_ }

@(
  $sessionDir,
  (Join-Path $sessionDir "current"),
  (Join-Path $sessionDir "releases"),
  (Join-Path $sessionDir "staging"),
  (Join-Path $sessionDir "data"),
  (Join-Path $sessionDir "data\promos"),
  (Join-Path $sessionDir "edge-profile")
) | ForEach-Object { Ensure-Dir $_ }

Ensure-SessionDisplayPersistentFiles -dataDir (Join-Path $sessionDir "data")

Write-Step "Download bootstrap/tools scripts"
$agentHostPath     = Join-Path $bayAgentDir "bootstrap\ABG.AgentHost.ps1"
$watchdogPath      = Join-Path $bayAgentDir "bootstrap\ABG.HostWatchdog.ps1"
$updateAgentPath   = Join-Path $bayAgentDir "tools\Update-BayAgent.ps1"
$updateDispPath    = Join-Path $bayAgentDir "tools\Update-SessionDisplay.ps1"

# NEW: Promos pack updater
$updatePromosPath  = Join-Path $bayAgentDir "tools\Update-PromosPack.ps1"

Download-File -url ($FleetRawBaseUrl.TrimEnd("/") + "/bootstrap/ABG.AgentHost.ps1")         -outPath $agentHostPath
Download-File -url ($FleetRawBaseUrl.TrimEnd("/") + "/bootstrap/ABG.HostWatchdog.ps1")     -outPath $watchdogPath
Download-File -url ($FleetRawBaseUrl.TrimEnd("/") + "/tools/Update-BayAgent.ps1")          -outPath $updateAgentPath
Download-File -url ($FleetRawBaseUrl.TrimEnd("/") + "/tools/Update-SessionDisplay.ps1")   -outPath $updateDispPath

# NEW: download promos pack updater
Download-File -url ($FleetRawBaseUrl.TrimEnd("/") + "/tools/Update-PromosPack.ps1")        -outPath $updatePromosPath

# The secret-credential tool, ONLY for a bay being set up for the legacy secret credential (-PlaceSecretTool, which
# Setup-BayPC.ps1 passes for -Credential Secret and for nothing else). Setup-BayPC.ps1 has always printed a command
# that runs it from bootstrap\, and nothing ever put it there: Day0 did not download it and the release package does
# not ship it (measured 2026-10-11). A certificate bay does not get it: such a bay never holds the shared secret, and
# a failed enrollment is fixed, not worked around (A0.529). It is DELIBERATELY NOT SIGNED (see the note at the top of
# that script): it is run by hand with -ExecutionPolicy Bypass, and it creates nothing until someone runs it.
# Last of the downloads, so a fork or a pinned commit without this file cannot stop the five the bay needs.
$setSecretPath = Join-Path $bayAgentDir "bootstrap\ABG.SetClientSecretDpapi.ps1"
if ($PlaceSecretTool) {
  Download-File -url ($FleetRawBaseUrl.TrimEnd("/") + "/bootstrap/ABG.SetClientSecretDpapi.ps1") -outPath $setSecretPath
}

Write-Step "Create/trust code-signing certificate"
$cert = Get-CodeSigningCertOrCreate

Write-Step "Grant BayKiosk access to private key file (Crypto\Keys)"
$kioskAccount = "$env:COMPUTERNAME\$BayKioskUser"
$uniqueName = Get-CertUniqueContainerName -thumbprint $cert.Thumbprint
Write-Host "Unique container name: $uniqueName"
Grant-Kiosk-KeyAccess -uniqueName $uniqueName -kioskAccount $kioskAccount

Write-Step "Sign bootstrap/tools scripts"
Sign-File -path $agentHostPath     -cert $cert -timeStampServer $TimeStampServer
Sign-File -path $watchdogPath      -cert $cert -timeStampServer $TimeStampServer
Sign-File -path $updateAgentPath   -cert $cert -timeStampServer $TimeStampServer
Sign-File -path $updateDispPath    -cert $cert -timeStampServer $TimeStampServer

# NEW: sign promos updater
Sign-File -path $updatePromosPath  -cert $cert -timeStampServer $TimeStampServer

Write-Host "All bootstrap/tools scripts signed and valid."

Write-Step "Write agent-config.json template (if missing)"
if ($WriteAgentConfigTemplate) {
  $cfgPath = Join-Path $bayAgentDir "agent-config.json"
  Write-AgentConfigTemplateIfMissing -path $cfgPath -envUrl $ConfigEnvironmentUrl -tenant $ConfigTenantId -client $ConfigClientId -bay $ConfigBayId
}

Write-Step "Scheduled tasks"
if ($CreateWatchdogTask) { Create-WatchdogTask -watchdogPath $watchdogPath }
if ($CreateAgentTask)    { Create-AgentTask -agentHostPath $agentHostPath -kioskAccount $kioskAccount -kioskPassword $BayKioskPassword }

# ---- Dataverse registration ----
if ($RegisterConfigItems) {
  Write-Step "Dataverse: Register per-bay ConfigItems (thumbprint + key unique name)"

  if ([string]::IsNullOrWhiteSpace($EnvironmentUrl) -or
      [string]::IsNullOrWhiteSpace($TenantId) -or
      [string]::IsNullOrWhiteSpace($ClientId) -or
      [string]::IsNullOrWhiteSpace($ClientSecretDpapiPath) -or
      [string]::IsNullOrWhiteSpace($BayId)) {
    throw "RegisterConfigItems set, but missing one of: EnvironmentUrl, TenantId, ClientId, ClientSecretDpapiPath, BayId"
  }

  $bayGuid = [guid]$BayId

  $secret = Get-ClientSecretFromDpapiFile -path $ClientSecretDpapiPath
  $token  = Get-DataverseToken -envUrl $EnvironmentUrl -tenantId $TenantId -clientId $ClientId -clientSecret $secret

  $scopeBayValue = Get-ChoiceValueByLabel -envUrl $EnvironmentUrl -token $token -entityLogical "build_configitem" -attrLogical $Cfg_ScopeField -labelToFind "Bay"
  Write-Host "Resolved ConfigItem scope 'Bay' option value: $scopeBayValue"

  Upsert-ConfigItemForBay -envUrl $EnvironmentUrl -token $token -bayGuid $bayGuid -scopeValue $scopeBayValue `
    -keyName "Agent.CodeSigningThumbprint" -val $cert.Thumbprint

  Upsert-ConfigItemForBay -envUrl $EnvironmentUrl -token $token -bayGuid $bayGuid -scopeValue $scopeBayValue `
    -keyName "Agent.CodeSigningKeyUniqueName" -val $uniqueName

  Write-Host "Dataverse ConfigItems registered successfully."
}

Write-Step "BayKiosk signing smoke test instructions"
Write-Host "Log in as $kioskAccount and run:"
Write-Host '  $tp = "' + $cert.Thumbprint + '"'
Write-Host '  $cert = Get-ChildItem "Cert:\LocalMachine\My\$tp"'
Write-Host '  $test = "C:\AllBirdies\BayAgent\state\sign-test.ps1"'
Write-Host '  "Write-Output ''sign test ok''" | Set-Content -Path $test -Encoding UTF8'
Write-Host '  Set-AuthenticodeSignature -FilePath $test -Certificate $cert -TimeStampServer http://timestamp.digicert.com | Out-Null'
Write-Host '  Get-AuthenticodeSignature $test | Format-List Status, StatusMessage'

Write-Step "DONE"
Write-Host "BayAgent root: $bayAgentDir"
Write-Host "SessionDisplay root: $sessionDir"
Write-Host "Code signing thumbprint: $($cert.Thumbprint)"
Write-Host "Key unique name: $uniqueName"
Write-Host "Kiosk key ACL granted to: $kioskAccount"
Write-Host "PromosPack updater installed at: $updatePromosPath"
