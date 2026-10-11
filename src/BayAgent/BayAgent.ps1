<#
ABG Bay Agent (Production Baseline v2 - includes periodic heartbeat)
- Step 1 foundation: Entra client-credentials auth, Dataverse polling, optimistic lock, execute, report
- Adds: automatic Bay heartbeat update every HeartbeatSeconds (default 60) even when no commands exist
- Extend by adding new command handlers in Execute-Command()
- Credential (2026-08-28): CERTIFICATE credential (client_assertion JWT signed by a key that never leaves the
  Windows key store) is preferred; the DPAPI client secret is the transitional fallback; CredentialRotate
  BayCommands enroll / test / activate / retire certificates without a visit to the machine.

Run examples:
  # One-time auth + poll iteration then exit:
  powershell.exe -NoProfile -File "C:\AllBirdies\BayAgent\BayAgent.ps1" -Once

  # Run continuously:
  powershell.exe -NoProfile -File "C:\AllBirdies\BayAgent\BayAgent.ps1"

Optional switches:
  -TokenOnly   Acquire token then exit (auth test; the log line names WHICH credential minted it)
  -Once        Run one poll iteration then exit
  -EnrollCert  Generate a NEW certificate credential for this bay: a non-exportable RSA key pair in the
               Windows certificate store, recorded in state\credential.json, with the PUBLIC certificate
               written to state\bay-cert-<thumbprint>.cer and printed as base64. Needs no working
               credential, so it is the Day-0 / hands-on enrollment path. If no credential is active
               yet the new certificate becomes active immediately; otherwise it is PENDING until a
               CredentialRotate action=activate proves it can mint a token.
               Optional: -EnrollValidityDays <int> (default 730), -EnrollStore CurrentUser|LocalMachine
#>

param(
    [switch]$Once,
    [switch]$TokenOnly,
    [switch]$EnrollCert,
    [int]$EnrollValidityDays = 730,
    [ValidateSet("", "CurrentUser", "LocalMachine")][string]$EnrollStore = "",
    # Minting a SECOND pending key pair is not what a repeated -EnrollCert usually means -- it is usually
    # someone re-running the command because they lost the console output. Default to reusing the pending
    # certificate and re-printing its public half; require an explicit -EnrollForce to mint a new one.
    [switch]$EnrollForce
)

Set-StrictMode -Version Latest
try { Add-Type -AssemblyName System.Security -ErrorAction SilentlyContinue } catch {}
$ErrorActionPreference = "Stop"

# Helps on some Windows PowerShell stacks; harmless on Win11
try { [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 } catch {}

# ---------------- Paths ----------------
$BaseDir = "C:\AllBirdies\BayAgent"
$CfgPath = Join-Path $BaseDir "agent-config.json"
$LogDir  = Join-Path $BaseDir "logs"

if (!(Test-Path $BaseDir)) { New-Item -ItemType Directory -Path $BaseDir | Out-Null }
if (!(Test-Path $LogDir))  { New-Item -ItemType Directory -Path $LogDir  | Out-Null }
if (!(Test-Path $CfgPath)) { throw "Config file not found: $CfgPath" }

# ---------------- Logging ----------------
# Levels: DEBUG, INFO, WARN, ERROR
$Global:LogLevel = "INFO"  # change to DEBUG when troubleshooting
$LogFile = Join-Path $LogDir ("BayAgent-{0}.log" -f (Get-Date).ToString("yyyyMMdd"))

function Get-LogLevelRank([string]$lvl) {
    switch ($lvl.ToUpperInvariant()) {
        "DEBUG" { 0 }
        "INFO"  { 1 }
        "WARN"  { 2 }
        "ERROR" { 3 }
        default { 1 }
    }
}

function Write-Log {
    param(
        [Parameter(Mandatory=$true)][string]$Message,
        [ValidateSet("DEBUG","INFO","WARN","ERROR")][string]$Level = "INFO"
    )
    if ((Get-LogLevelRank $Level) -lt (Get-LogLevelRank $Global:LogLevel)) { return }

    $ts = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
    $line = "$ts [$Level] $Message"
    try { Write-Host $line } catch {}
    try { Add-Content -Path $LogFile -Value $line } catch {}
}


# ---------------- Fatal error trap ----------------
# If something blows up outside the main loop (e.g., config parse, auth init), we still want a clear log line.
# NOTE: This trap only fires for UNHANDLED terminating errors.
#
# IT CALLS NO FUNCTION FROM THIS SCRIPT AND READS NO SCRIPT VARIABLE, AND THAT IS THE POINT.
# (Built-in cmdlets are always there; anything this file defines is not.)
# A trap is HOISTED: it is registered for the whole script block, so it fires for errors raised ABOVE the
# line it is written on. MEASURED on Windows PowerShell 5.1, 2026-09-21: a throw on line 3 is caught by a
# trap written on line 4, and a function defined on line 5 is NOT available inside it.
#
# This trap used to call Write-Log, which is defined further up but AFTER the three statements that create
# the log directory and check for agent-config.json -- the statements most likely to fail on a Day-0 or
# mis-provisioned bay. A missing agent-config.json therefore exited 1 having written NOTHING, because
# Write-Log did not exist yet and the try/catch around it swallowed that too. The handler of last resort
# cannot depend on initialization having succeeded, so it now writes the two lines itself, in exactly the
# format Write-Log produces.
#
trap {
    $abgErr = $_
    $abgMsg = $null
    try { $abgMsg = $abgErr.Exception.Message } catch { $abgMsg = [string]$abgErr }
    $abgTs = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")

    # $LogFile is assigned BELOW this trap, so it may or may not exist when the trap fires. Get-Variable
    # rather than $LogFile: reading an unset variable is a terminating error under Set-StrictMode, and the
    # handler of last resort must not fail in its own first line. It is written this way rather than
    # wrapped in try/catch so the "it might not be there" is stated, not hidden, and so the fallback is
    # visible on the next line. Hardcoding the path instead was measured wrong: a sandboxed test run wrote
    # its FATAL into the LIVE install's log directory.
    $abgPath = Get-Variable -Name LogFile -ValueOnly -ErrorAction SilentlyContinue
    if (-not $abgPath) {
        $abgPath = "C:\AllBirdies\BayAgent\logs\BayAgent-{0}.log" -f (Get-Date).ToString("yyyyMMdd")
    }

    $abgOut = @("$abgTs [ERROR] FATAL (pid=$PID): $abgMsg")
    try {
        if ($abgErr.ScriptStackTrace) { $abgOut += "$abgTs [ERROR] STACK: $($abgErr.ScriptStackTrace)" }
    } catch {}
    foreach ($abgLine in $abgOut) {
        try { Write-Host $abgLine } catch {}
        try { Add-Content -Path $abgPath -Value $abgLine } catch {}
    }
    exit 1
}

# ---------------- Config ----------------
$cfg = Get-Content $CfgPath -Raw | ConvertFrom-Json

function Require-Config([string]$name) {
    if (-not ($cfg.PSObject.Properties.Name -contains $name) -or [string]::IsNullOrWhiteSpace($cfg.$name)) {
        throw "Missing or empty config field '$name' in $CfgPath"
    }
}

# environmentUrl is preferred; dataverseUrl accepted as an alias
function Get-ConfigString([string[]]$names) {
    foreach ($n in $names) {
        try {
            if ($cfg.PSObject.Properties.Name -contains $n) {
                $v = $cfg.$n
                if ($null -ne $v) {
                    $s = ($v.ToString()).Trim()
                    if (-not [string]::IsNullOrWhiteSpace($s)) { return $s }
                }
            }
        } catch {}
    }
    return $null
}

$OrgUrlRaw = Get-ConfigString @("environmentUrl","dataverseUrl")
if ([string]::IsNullOrWhiteSpace($OrgUrlRaw)) {
    throw "Missing or empty config field 'environmentUrl' (or 'dataverseUrl') in $CfgPath"
}
$OrgUrl = $OrgUrlRaw.TrimEnd("/")

Require-Config "tenantId"
Require-Config "clientId"
Require-Config "bayId"
Require-Config "pollSeconds"

$TenantId = $cfg.tenantId.ToString()
$ClientId = $cfg.clientId.ToString()
# ---------------- Credential configuration ----------------
# Three credential sources, tried in this order at token time (see Acquire-Token):
#   1. clientCertThumbprint  - CERTIFICATE credential (preferred). The agent signs a client_assertion JWT with a
#                              private key that never leaves the Windows certificate store (CurrentUser\My of the
#                              agent account, or LocalMachine\My). Nothing to type, copy, or steal off disk.
#                              An active thumbprint recorded by CredentialRotate / -EnrollCert in
#                              state\credential.json OVERRIDES this value (that is how rotation lands without
#                              rewriting agent-config.json).
#   2. clientSecretDpapiPath - client SECRET, DPAPI(LocalMachine) protected. Kept as the transitional fallback so
#                              a bay keeps working while its certificate is enrolled and registered in Entra.
#   3. clientSecret          - DEPRECATED plaintext secret in agent-config.json. Still honoured so an existing bay
#                              does not go dark on upgrade, but it is flagged in the heartbeat capabilities JSON
#                              and logged at WARN on every start. Delete it once the bay reports
#                              credential.lastMintMode = "certificate".
# At least one source must be configured unless -EnrollCert is used (enrollment needs no credential).
$Secret            = $null
$SecretPath        = $null
$SecretPathCfg     = $null
$CertThumbprintCfg = $null
$CertStoreCfg      = $null

$CertThumbprintCfg = Get-ConfigString @("clientCertThumbprint")
if ($CertThumbprintCfg) {
    $CertThumbprintCfg = ($CertThumbprintCfg -replace "[^0-9A-Fa-f]", "").ToUpperInvariant()
    if ($CertThumbprintCfg.Length -ne 40) { throw "clientCertThumbprint must be a 40-hex-character SHA-1 thumbprint in $CfgPath" }
}
$CertStoreCfg = Get-ConfigString @("clientCertStore")   # optional: CurrentUser | LocalMachine (default: search both)
if ($CertStoreCfg -and $CertStoreCfg -notin @("CurrentUser", "LocalMachine")) { throw "clientCertStore must be CurrentUser or LocalMachine" }

# Token authority host. Default is public Entra; overridable for sovereign clouds and for tests (the credential
# test harness points it at a local mock token endpoint).
$TokenAuthorityHost = Get-ConfigString @("tokenAuthorityHost")
if ([string]::IsNullOrWhiteSpace($TokenAuthorityHost)) { $TokenAuthorityHost = "https://login.microsoftonline.com" }
$TokenAuthorityHost = $TokenAuthorityHost.TrimEnd("/")

# Assertion signing algorithm: RS256 (PKCS#1 v1.5 padding, accepted by Entra everywhere) or PS256 (PSS padding,
# what Microsoft's current guidance recommends). Both are RSA + SHA-256; only the padding differs.
$AssertionAlg = Get-ConfigString @("clientAssertionAlg")
if ([string]::IsNullOrWhiteSpace($AssertionAlg)) { $AssertionAlg = "RS256" }
$AssertionAlg = $AssertionAlg.ToUpperInvariant()
if ($AssertionAlg -notin @("RS256", "PS256")) { throw "clientAssertionAlg must be RS256 or PS256 (got '$AssertionAlg') in $CfgPath" }

$hasDpapiPath = ($cfg.PSObject.Properties.Name -contains "clientSecretDpapiPath") -and
                (-not [string]::IsNullOrWhiteSpace($cfg.clientSecretDpapiPath))

$hasPlaintext = ($cfg.PSObject.Properties.Name -contains "clientSecret") -and
                (-not [string]::IsNullOrWhiteSpace($cfg.clientSecret))

if ($hasDpapiPath) {
    $SecretPathCfg = $cfg.clientSecretDpapiPath.ToString().Trim()
    $SecretPath    = $SecretPathCfg
}
elseif ($hasPlaintext) {
    $Secret = $cfg.clientSecret.ToString().Trim()
}

# Finalised (file-existence checked, fallback semantics applied) in Write-CredentialStartupSummary below,
# once the certificate helpers are defined.
$HasSecretCredential = ($null -ne $SecretPath) -or ($null -ne $Secret)

if (-not $EnrollCert) {
    if (-not $CertThumbprintCfg -and -not $HasSecretCredential) {
        throw "Missing auth config: provide clientCertThumbprint (preferred), clientSecretDpapiPath, or clientSecret (deprecated) in $CfgPath"
    }
}

function Get-ClientSecret {
    if ($Secret) { 
        return $Secret.Trim()
    }

    if ([string]::IsNullOrWhiteSpace($SecretPath)) { 
        throw "SecretPath not configured" 
    }

    if (!(Test-Path $SecretPath)) { 
        throw "Secret file not found: $SecretPath" 
    }

    $enc = [IO.File]::ReadAllBytes($SecretPath)

    $bytes = [System.Security.Cryptography.ProtectedData]::Unprotect(
        $enc,
        $null,
        [System.Security.Cryptography.DataProtectionScope]::LocalMachine
    )

    $s = ([Text.Encoding]::UTF8.GetString($bytes)).Trim()
    Write-Log ("Loaded DPAPI secret from {0} (length={1})" -f $SecretPath, $s.Length) "DEBUG"
    return $s
}

$BayId    = ($cfg.bayId.ToString()).Trim("{}")
$PollSec  = [int]$cfg.pollSeconds

# Optional config
if ($cfg.PSObject.Properties.Name -contains "logLevel" -and -not [string]::IsNullOrWhiteSpace($cfg.logLevel)) {
    $Global:LogLevel = $cfg.logLevel.ToString().ToUpperInvariant()
}

# Heartbeat cadence (seconds). Defaults to 60.
$HeartbeatSec = 60
if ($cfg.PSObject.Properties.Name -contains "heartbeatSeconds" -and $cfg.heartbeatSeconds) {
    try { $HeartbeatSec = [int]$cfg.heartbeatSeconds } catch {}
    if ($script:HeartbeatSec -lt 15) { $script:HeartbeatSec = 15 } # floor to avoid accidental thrash
}

# Release version. THE CODE CARRIES ITS OWN VERSION (1.3.1).
# Through 1.3.0 the reported version was read from manifest.json next to this script. MEASURED on Bay 1,
# 2026-10-07: 1.3.0 installed, ran (its heartbeat carried emergencyStop, which only 1.3.0 writes) and reported
# "1.2.1" everywhere, because the updater's robocopy /MIR skipped manifest.json (same size, same fixed zip time).
# A label read from a side file is only as true as the copy that placed it. So the version is a constant in the
# file that runs, the build refuses a package whose manifest disagrees with it, and the manifest's own value is
# reported next to it (manifestVersion) so a stale copy is visible instead of believed.
$AgentCodeVersion = "1.5.0"
$AgentVersion = $AgentCodeVersion
$AgentManifestVersion = $null

try {
    $manifestPath = Join-Path $PSScriptRoot "manifest.json"
    if (Test-Path $manifestPath) {
        $m = Get-Content $manifestPath -Raw | ConvertFrom-Json
        if ($m -and $m.version) { $AgentManifestVersion = [string]$m.version }
    }
} catch {
    # An unreadable manifest is reported as null; the code version above still stands.
}

# The hash of the file this process is running, taken ONCE at startup (a later update rewrites the file under a
# running process). The rollback guard compares it with the hash it promoted: "the new code came back" is proven
# by the bytes that ran, never by a version label.
$AgentCodeSha256 = $null
$AgentScriptPath = $PSCommandPath
try {
    # .NET directly, not Get-FileHash: a missing hash means no alive record, and no alive record means the update guard
    # rolls back a healthy agent, so this must not depend on a module loading (MEASURED 2026-10-07: a 5.1 child started
    # from PowerShell 7 inherits a PSModulePath on which Get-FileHash does not resolve).
    if ($AgentScriptPath) {
        $shaAlg = [System.Security.Cryptography.SHA256]::Create()
        $shaFs = [System.IO.File]::OpenRead($AgentScriptPath)
        try { $AgentCodeSha256 = ([BitConverter]::ToString($shaAlg.ComputeHash($shaFs)) -replace "-", "").ToLowerInvariant() }
        finally { $shaFs.Dispose(); $shaAlg.Dispose() }
    }
} catch { }
$AgentProcessStartUtc = (Get-Date).ToUniversalTime()

Write-Log "BayAgent starting. pid=$PID. OrgUrl=$OrgUrl BayId=$BayId PollSec=$PollSec HeartbeatSec=$HeartbeatSec LogLevel=$Global:LogLevel Version=$AgentVersion ManifestVersion=$AgentManifestVersion TokenOnly=$TokenOnly Once=$Once" "INFO"

# ---------------- Dataverse schema (your verified names) ----------------
$BayCommandEntitySet = "build_baycommands"
$BayEntitySet        = "build_baies"


# ---------------- Step 8.2: Dynamic config entities (BayProfile + ConfigItem overlay) ----------------
$BayProfileEntitySet  = "build_bayprofiles"
$ConfigItemEntitySet  = "build_configitems"
$LocationEntitySet    = "build_locations"

# Bay lookup columns (Web API exposes these as _{lookup}_value)
$Lookup_Location      = "build_location"
$Lookup_LocationValue = "_{0}_value" -f $Lookup_Location

$Lookup_BayProfile      = "build_bayprofile"
$Lookup_BayProfileValue = "_{0}_value" -f $Lookup_BayProfile

# Bay operational status columns (Step 8)
$Col_AgentStatus       = "build_agentstatus"
$Col_AgentStatusUntil  = "build_agentstatusuntil"
$Col_AgentStatusReason = "build_agentstatusreason"
$Col_AgentCapsJson     = "build_agentcapabilitiesjson"

# Location columns
$Col_TimeZoneId = "build_timezoneid"

# BayProfile columns (logical names)
$Col_BP_LauncherPath       = "build_launcherpath"
$Col_BP_LauncherArgs       = "build_launcherargs"
$Col_BP_LauncherProcName   = "build_launcherprocessname"
$Col_BP_SessionMode        = "build_sessiondisplaymode"
$Col_BP_SessionJsonPath    = "build_sessionjsonpath"
$Col_BP_ProfileJson        = "build_profilejson"

# ConfigItem columns (logical names)
$Col_CI_Scope   = "build_scope"
$Col_CI_Key     = "build_key"
$Col_CI_Value   = "build_value"
$Col_CI_Enabled = "build_enabled"

# IMPORTANT: Update these to match your ConfigItem.Scope choice values in Dataverse if different
$SCOPE_GLOBAL   = 100000000
$SCOPE_LOCATION = 100000001
$SCOPE_BAY      = 100000002

# Dynamic config refresh cadence (seconds)
$ConfigRefreshSec = 300
# BayCommand columns (logical names)
$Col_CommandId    = "build_baycommandid"
$Col_Status       = "build_status"
$Col_CommandType  = "build_commandtype"
$Col_NotBefore    = "build_notbefore"
$Col_AttemptCount = "build_attemptcount"
$Col_StartedOn    = "build_startedon"
$Col_CompletedOn  = "build_completedon"
$Col_Payload      = "build_payload"
$Col_Result       = "build_resultjson"
$Col_Error        = "build_errordetails"

# MEASURED 2026-08-29 against Dev: build_resultjson is a Memo column with MaxLength 2000. A PATCH that
# exceeds it is REJECTED, and the reject lands in Process-Command's catch - so an oversized result does not
# merely get clipped, it marks an otherwise SUCCESSFUL command as Failed. That is a silent-failure trap for
# every command, and specifically it would turn a remote certificate enrollment (whose whole point is to
# return the public cert without a visit to the bay) into a drive to the machine. Limit-ResultJson below is
# the guard; keep this number in step with the column.
# MEASURED against DEV on 2026-08-29: build_resultjson is a Memo column with MaxLength 2000.
# THAT IS A DEV MEASUREMENT, AND IT IS NOT SELF-VERIFYING. Nothing here reads the column's real metadata,
# so a customer tenant whose build_resultjson was provisioned with a different MaxLength would have this
# agent trim to the wrong number -- too small silently loses detail, too large makes the result PATCH fail,
# and that failure lands in the catch that marks the command Failed (an enrollment that created a key and
# then reported that it had not). It is left as a constant rather than probed at startup because an
# EntityDefinitions call on the boot path is a new way for an agent to fail to start, for a number that has
# changed zero times. It is OVERRIDABLE so a tenant that differs can be corrected without a code change:
# set "resultJsonMaxChars" in agent-config.json. Re-measure it per tenant at onboarding.
$ResultJsonMaxChars = 2000
if ($cfg -and ($cfg.PSObject.Properties.Name -contains "resultJsonMaxChars")) {
    try {
        $rjm = [int]$cfg.resultJsonMaxChars
        if ($rjm -ge 256 -and $rjm -le 1048576) { $ResultJsonMaxChars = $rjm }
    } catch { }
}

# Lookup logical name for Bay lookup in BayCommand (Web API filter uses _{lookup}_value)
$Lookup_Bay      = "build_bay"
$Lookup_BayValue = "_{0}_value" -f $Lookup_Bay
# The bay session a command row is bound to (the platform binds a canceled booking's Reset to that booking's session,
# build_BaySession@odata.bind). In the core solution; measured on Dev 2026-10-09 as a lower-case GUID string.
$Lookup_BaySessionValue = "_build_baysession_value"

# Bay columns (logical names)
$Col_Heartbeat = "build_lastheartbeat"
$Col_Machine   = "build_agentmachinename"
$Col_Version   = "build_agentversion"

# Choice values
$STATUS_PENDING    = 100000000
$STATUS_INPROGRESS = 100000001
$STATUS_SUCCEEDED  = 100000002
$STATUS_FAILED     = 100000003
# Pending -> Skipped is the one close-out the guard plugin allows WITHOUT execution fields (no result, no error text).
$STATUS_SKIPPED    = 100000005


# Bay Agent status values (build_agentstatus)
# NOTE: These must match your Dataverse choice values for the Bay table column build_agentstatus.
$AGENTSTATUS_ONLINE      = 100000000
$AGENTSTATUS_DEGRADED    = 100000001
$AGENTSTATUS_OFFLINE     = 100000002
$AGENTSTATUS_MAINTENANCE = 100000003

# Command type values (Step 2 primitives included)
$CMD_HEALTHCHECK   = 100000000
$CMD_SHOWMESSAGE  = 100000001
$CMD_STARTPROCESS = 100000002
$CMD_STOPPROCESS  = 100000003
$CMD_QUERYPROCESS = 100000004
$CMD_UPDATESESSIONDISPLAY = 100000005
$CMD_STARTSESSION = 100000010
$CMD_ENDSESSION   = 100000011
$CMD_RESET        = 100000012



# Step 5 command types (add matching Choice values in Dataverse build_commandtype)
$CMD_DISPLAY_TOPOLOGY  = 100000020
$CMD_FACILITY_SETMODE  = 100000021
$CMD_FACILITY_POWERON  = 100000022
$CMD_FACILITY_POWEROFF = 100000023

# Step 5 discrete facility commands
$CMD_SETLIGHTS        = 100000024
$CMD_PROJECTOR_POWER  = 100000025
$CMD_AUDIO_VOLUME     = 100000026
$CMD_EMERGENCY_STOP   = 100000027

# Credential lifecycle (2026-08-28): payload.action = status | enroll | test | activate | retire
$CMD_CREDENTIAL_ROTATE = 100000030


# Tracks the process started for Session Display so EndSession/Reset can close the right window
$Global:SessionDisplayProcId = $null

# Emergency stop latch (cleared only by explicit command). It is also PERSISTED in the state file below, so a restart
# (crash relaunch, RestartBayAgent, Update-BayAgent, reboot, power loss) cannot release it: Restore-EmergencyStopLatch
# reads it at startup and treats a present-but-unreadable file as ENGAGED.
$Global:EmergencyStopStatePath = Join-Path $BaseDir "state\emergency-stop.json"
$Global:EmergencyStopPersistOk = $true
$Global:EmergencyStopEngaged = $false
$Global:EmergencyStopReason = $null



$Global:SessionDisplayUrl = $null
$Global:SessionDisplayStatePath = "C:\AllBirdies\SessionDisplay\data\session-display.state.json"

$Global:SessionDisplayProfileDir = "C:\AllBirdies\SessionDisplay\edge-profile"
$Global:SessionDisplayTag = "--user-data-dir=$Global:SessionDisplayProfileDir"
# ---------------- Token cache ----------------
$Global:AccessToken = $null
$Global:TokenExpiresUtc = [DateTime]::MinValue

function Read-WebExceptionBody {
    param([Parameter(Mandatory=$true)]$WebException)
    try {
        $resp = $WebException.Response
        if ($resp -ne $null) {
            $stream = $resp.GetResponseStream()
            if ($stream -ne $null) {
                $reader = New-Object System.IO.StreamReader($stream)
                $body = $reader.ReadToEnd()
                $reader.Close()
                return $body
            }
        }
    } catch {}
    return $null
}

# ---------------- Generic object helper ----------------
# MOVED UP FROM THE COMMAND-EXECUTION SECTION (it used to sit beside Try-ParseJson, around line 1563).
# It is read by Get-ActiveCertThumbprint, which Write-CredentialStartupSummary calls at script level long
# before the interpreter ever reached the old definition. PowerShell defines a function when it REACHES the
# definition, so BayAgent 1.2.0 died on every real bay inside a second:
#   FATAL: The term 'Get-PropValue' is not recognized ... at Get-ActiveCertThumbprint line 564
# It has no dependencies of its own, so the only thing keeping it where it was, was habit.
# tests\BayAgent.StartupOrder.Tests.ps1 now fails the build if anything is used above its definition again.
function Get-PropValue($obj, [string]$name, $default = $null) {
    if ($null -eq $obj) { return $default }

    # Hashtable / dictionary
    if ($obj -is [System.Collections.IDictionary]) {
        foreach ($k in $obj.Keys) { if ($k -ieq $name) { return $obj[$k] } }
        return $default
    }

    # PSCustomObject or other PSObject
    try {
        foreach ($p in $obj.PSObject.Properties) {
            if ($p.Name -ieq $name) { return $p.Value }
        }
    } catch {}
    return $default
}

# ---------------- Certificate credential (client_assertion) ----------------
# State written by CredentialRotate commands and -EnrollCert. Precedence for the ACTIVE thumbprint:
#   state\credential.json activeThumbprint  >  agent-config.json clientCertThumbprint
$CredentialStatePath = Join-Path $BaseDir "state\credential.json"

# Telemetry (never a secret, never a key). Surfaced in build_agentcapabilitiesjson via the heartbeat so an
# operator - and the credential-expiry monitor - can see WHICH credential is actually minting tokens.
$Global:CredentialTelemetry = @{
    lastMintMode      = $null     # "certificate" | "secret"
    lastMintUtc       = $null
    lastCertMintUtc   = $null
    lastSecretMintUtc = $null
    lastCertError     = $null
    lastSecretError   = $null
    fallbackCount     = 0     # THIS PROCESS only - see Sync-FallbackTelemetry for the durable total
    fallbackFlushed   = 0     # how much of fallbackCount has already been folded into credential.json
    lastFallbackUtc   = $null
    lastTest          = $null
}

function ConvertTo-Base64Url([byte[]]$bytes) {
    return [Convert]::ToBase64String($bytes).TrimEnd("=").Replace("+", "-").Replace("/", "_")
}

function ConvertFrom-Base64Url([string]$s) {
    $t = $s.Replace("-", "+").Replace("_", "/")
    switch ($t.Length % 4) { 2 { $t += "==" } 3 { $t += "=" } }
    return [Convert]::FromBase64String($t)
}

function Normalize-Thumbprint([string]$tp) {
    if ([string]::IsNullOrWhiteSpace($tp)) { return $null }
    $n = ($tp -replace "[^0-9A-Fa-f]", "").ToUpperInvariant()
    if ($n.Length -ne 40) { throw "Thumbprint must be 40 hex characters (got '$tp')" }
    return $n
}

# Set by Read-CredentialState whenever the file EXISTS but does not parse. Surfaced in the heartbeat, and
# consulted by Update-CredentialState, which must never write over a file it could not read.
$Global:CredentialStateCorrupt = $false

function Read-CredentialState {
    # ABSENCE AND CORRUPTION ARE NOT THE SAME EVENT, and treating them the same was a real defect. A truncated
    # credential.json -- a power cut mid-write on an unmanned kiosk is the obvious cause -- used to read as
    # "no state yet" at WARN, and the very next Update-CredentialState wrote a FRESH file containing only the
    # keys of that one update. activeThumbprint, retiredThumbprints and fallbackCountTotal were gone
    # permanently, and fallbackCountTotal is the number the irreversible retirement step is gated on. The bay
    # would then look healthy on a zeroed counter.
    #
    # So: a file that is absent is absent (returns $null, no noise -- that is Day 0). A file that is PRESENT
    # and unparseable is a fault. It is logged at ERROR, flagged for the heartbeat, and it still returns $null
    # so the agent can keep running on what it CAN prove (its certificate store, its config) -- but
    # Update-CredentialState refuses to write, so the corrupt bytes survive for a human to recover from the
    # .bak beside them. Fail closed on the write, degrade on the read.
    if (-not (Test-Path -LiteralPath $CredentialStatePath)) {
        $Global:CredentialStateCorrupt = $false
        return $null
    }
    $raw = $null
    try { $raw = Get-Content -LiteralPath $CredentialStatePath -Raw } catch {
        $Global:CredentialStateCorrupt = $true
        Write-Log ("credential.json is present but UNREADABLE ({0}); refusing to overwrite it. Recover from {1}.bak" -f $_.Exception.Message, $CredentialStatePath) "ERROR"
        return $null
    }
    # An empty file is the one ambiguous case; treat it as absence rather than corruption, because
    # Write-CredentialState's own temp-then-move never produces a zero-length target.
    if ([string]::IsNullOrWhiteSpace($raw)) {
        $Global:CredentialStateCorrupt = $false
        return $null
    }
    try {
        $parsed = $raw | ConvertFrom-Json
        $Global:CredentialStateCorrupt = $false
        return $parsed
    } catch {
        $Global:CredentialStateCorrupt = $true
        Write-Log ("credential.json is CORRUPT and will NOT be overwritten ({0}). The active thumbprint, the retired list and fallbackCountTotal cannot be trusted until it is repaired -- recover from {1}.bak by hand." -f $_.Exception.Message, $CredentialStatePath) "ERROR"
        return $null
    }
}

function Write-CredentialState($stateObj) {
    $dir = Split-Path -Parent $CredentialStatePath
    if (!(Test-Path $dir)) { New-Item -ItemType Directory -Force -Path $dir | Out-Null }
    $json = ($stateObj | ConvertTo-Json -Depth 6)
    # Keep the PREVIOUS good file beside the new one. It is the only recovery path from a corrupt state file,
    # and it costs a file copy on a write that happens a handful of times in a bay's life.
    if (Test-Path -LiteralPath $CredentialStatePath) {
        try { Copy-Item -LiteralPath $CredentialStatePath -Destination "$CredentialStatePath.bak" -Force } catch {
            Write-Log ("Could not write credential.json.bak ({0}); continuing" -f $_.Exception.Message) "WARN"
        }
    }
    $tmp = "$CredentialStatePath.tmp"
    [IO.File]::WriteAllText($tmp, $json, (New-Object Text.UTF8Encoding($false)))
    Move-Item -LiteralPath $tmp -Destination $CredentialStatePath -Force
}

function Update-CredentialState([hashtable]$changes) {
    $cur = Read-CredentialState
    # THE FAIL-CLOSED HALF. Read-CredentialState has already returned $null; writing now would replace the
    # corrupt file with a fresh one holding only $changes, which is exactly the silent data loss this guards.
    if ($Global:CredentialStateCorrupt) {
        throw "credential.json is corrupt; refusing to write over it. Recover from $CredentialStatePath.bak (or delete the file deliberately if the bay is being re-enrolled), then retry."
    }
    $st = [ordered]@{}
    if ($cur) { foreach ($p in $cur.PSObject.Properties) { $st[$p.Name] = $p.Value } }
    foreach ($k in $changes.Keys) { $st[$k] = $changes[$k] }
    $st["updatedUtc"] = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
    Write-CredentialState $st
    return $st
}

function Test-HasUsableSecret {
    # Does a secret credential ACTUALLY exist right now, as opposed to being named in the config?
    # $HasSecretCredential is a startup-time reading of what agent-config.json MENTIONS; this is a reading of
    # what is on disk. The two differ on exactly one bay: a Day-0 machine running the shipped config, whose
    # clientSecretDpapiPath points at a file nobody has created yet. See Invoke-CredentialEnroll.
    if ($null -ne $script:Secret) { return $true }
    if ($script:SecretPath -and (Test-Path -LiteralPath $script:SecretPath)) { return $true }
    return $false
}

function Read-LastUpdateResult {
    # The durable outcome of the most recent fleet update, written by Update-BayAgent.ps1 (success or failure).
    # It exists because a BayCommand StartProcess reports Succeeded the instant the process LAUNCHES -- it has
    # no idea whether the updater then died. Carried in the heartbeat so a command result can be reconciled
    # against what actually happened on the machine.
    param([string]$Base = $BaseDir)
    $p = Join-Path $Base "state\last-update-result.json"
    if (-not (Test-Path -LiteralPath $p)) { return $null }
    try { return (Get-Content -LiteralPath $p -Raw | ConvertFrom-Json) } catch { return $null }
}

function Get-ActiveCertThumbprint {
    $st = Read-CredentialState
    $fromState = Normalize-Thumbprint ([string](Get-PropValue $st "activeThumbprint" ""))
    if ($fromState) { return $fromState }
    return $CertThumbprintCfg
}

function Get-PendingCertThumbprint {
    $st = Read-CredentialState
    return (Normalize-Thumbprint ([string](Get-PropValue $st "pendingThumbprint" "")))
}

# ---------------- A0.458: the bay's OWN identity ----------------
# Kevin's prompt answer 2026-10-08 ("Each bay its own identity"): each bay signs in as ITS OWN Entra app with a
# certificate whose key never leaves this machine, so the cloud knows exactly which bay is asking. agent-config.json's
# clientId stays the SHARED bay-agent app (it is what the DPAPI secret belongs to); credential.json's activeClientId,
# when present, names the bay's own app and goes with activeThumbprint. A switch to it is proven against Dataverse and
# the command guard BEFORE it happens, held on probation, and undone by the agent itself when the new identity cannot
# work (Invoke-IdentityRevert), so a remote switch cannot strand the bay.

function ConvertTo-AgentGuid([string]$Text) {
    # A GUID in its canonical lower-case D form, or $null. Never throws.
    $g = [guid]::Empty
    if ([string]::IsNullOrWhiteSpace($Text)) { return $null }
    if (-not [guid]::TryParse($Text.Trim(), [ref]$g)) { return $null }
    if ($g -eq [guid]::Empty) { return $null }
    return $g.ToString("D")
}

function Get-ActiveClientId {
    # The app the ACTIVE certificate signs in as. A valid activeClientId in credential.json, else the configured
    # (shared) clientId. A corrupt state file names nothing, so this falls back to the configured app, which is what
    # the active certificate also falls back to (Get-ActiveCertThumbprint).
    $st = Read-CredentialState
    $own = ConvertTo-AgentGuid ([string](Get-PropValue $st "activeClientId" ""))
    if ($own) { return $own }
    return (ConvertTo-AgentGuid $ClientId)
}

function Test-OwnIdentityActive {
    # True when the active credential is a certificate on an app other than the configured shared one.
    $tp = Get-ActiveCertThumbprint
    if (-not $tp) { return $false }
    return ((Get-ActiveClientId) -ne (ConvertTo-AgentGuid $ClientId))
}

function Get-IdentityProbation {
    # The probation record written by an identity switch, or $null when none is open.
    $st = Read-CredentialState
    $p = Get-PropValue $st "identityProbation" $null
    if ($null -eq $p) { return $null }
    if (-not (ConvertTo-AgentGuid ([string](Get-PropValue $p "clientId" "")))) { return $null }
    return $p
}

# The body of the last refused Dataverse call (Invoke-DvSafe sets it); read by the identity probation. Set here, before
# anything can read it, because reading an unset variable is a terminating error under strict mode.
$Global:LastDvErrorBody = $null

function Get-CertStoreSearchOrder {
    $stores = @("Cert:\CurrentUser\My", "Cert:\LocalMachine\My")
    if ($CertStoreCfg) {
        $pref = "Cert:\$CertStoreCfg\My"
        $stores = @($pref) + @($stores | Where-Object { $_ -ne $pref })
    }
    return $stores
}

function Get-CertStoreName($cert) {
    try {
        $pp = [string]$cert.PSParentPath
        if ($pp -and $pp.Contains("::")) { return ($pp -split "::")[-1] }
    } catch {}
    return "?"
}

function Find-ClientCertificate([string]$thumbprint) {
    $tp = Normalize-Thumbprint $thumbprint
    if (-not $tp) { return $null }
    foreach ($store in (Get-CertStoreSearchOrder)) {
        try {
            $c = Get-ChildItem -LiteralPath "$store\$tp" -ErrorAction SilentlyContinue
            if ($c -and $c.HasPrivateKey) { return $c }
        } catch {}
    }
    return $null
}

function New-ClientAssertionJwt {
    # RFC 7523 / Entra "certificate credentials" assertion. Header carries BOTH thumbprint forms (x5t = SHA-1,
    # x5t#S256 = SHA-256) so either lookup Entra performs succeeds; claims are the documented set.
    param(
        [Parameter(Mandatory=$true)][System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate,
        [Parameter(Mandatory=$true)][string]$ClientId,
        [Parameter(Mandatory=$true)][string]$Audience,
        [string]$Alg = "RS256",
        [int]$LifetimeSeconds = 300
    )
    $der    = $Certificate.RawData
    $sha1   = [System.Security.Cryptography.SHA1]::Create().ComputeHash($der)
    $sha256 = [System.Security.Cryptography.SHA256]::Create().ComputeHash($der)

    $header = [ordered]@{
        alg        = $Alg
        typ        = "JWT"
        x5t        = (ConvertTo-Base64Url $sha1)
        "x5t#S256" = (ConvertTo-Base64Url $sha256)
    }

    # nbf is backdated 60 s to absorb clock skew between the bay PC and Entra; exp stays short (5 min default).
    $now = [DateTimeOffset]::UtcNow
    $claims = [ordered]@{
        aud = $Audience
        iss = $ClientId
        sub = $ClientId
        jti = ([guid]::NewGuid().ToString())
        nbf = $now.AddSeconds(-60).ToUnixTimeSeconds()
        iat = $now.ToUnixTimeSeconds()
        exp = $now.AddSeconds($LifetimeSeconds).ToUnixTimeSeconds()
    }

    $enc = [Text.Encoding]::UTF8
    $h64 = ConvertTo-Base64Url ($enc.GetBytes(($header | ConvertTo-Json -Compress)))
    $p64 = ConvertTo-Base64Url ($enc.GetBytes(($claims | ConvertTo-Json -Compress)))
    $signingInput = $enc.GetBytes("$h64.$p64")

    $rsa = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($Certificate)
    if ($null -eq $rsa) { throw "Certificate $($Certificate.Thumbprint) has no usable RSA private key for this account" }
    $padding = if ($Alg -eq "PS256") { [System.Security.Cryptography.RSASignaturePadding]::Pss } else { [System.Security.Cryptography.RSASignaturePadding]::Pkcs1 }
    $sig = $rsa.SignData($signingInput, [System.Security.Cryptography.HashAlgorithmName]::SHA256, $padding)

    return ("{0}.{1}.{2}" -f $h64, $p64, (ConvertTo-Base64Url $sig))
}

function Get-AadstsCode([string]$text) {
    if ([string]::IsNullOrWhiteSpace($text)) { return "" }
    $m = [regex]::Match($text, "AADSTS\d+")
    if ($m.Success) { return $m.Value }
    return ""
}

function Get-TokenUrl {
    return "$TokenAuthorityHost/$TenantId/oauth2/v2.0/token"
}

function Invoke-TokenEndpoint {
    # One POST to the v2.0 token endpoint. Returns the parsed JSON on 2xx; throws otherwise with the HTTP status
    # and AADSTS code in the message. The request body is never logged (it may carry the secret).
    param(
        [Parameter(Mandatory=$true)][string]$TokenUrl,
        [Parameter(Mandatory=$true)][string]$FormBody
    )
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($FormBody)

    $req = [System.Net.HttpWebRequest]::Create($TokenUrl)
    $req.Method = "POST"
    $req.ContentType = "application/x-www-form-urlencoded"
    $req.Accept = "application/json"
    $req.Timeout = 30000
    $req.ReadWriteTimeout = 30000
    try { $req.ServicePoint.Expect100Continue = $false } catch {}

    $reqStream = $req.GetRequestStream()
    $reqStream.Write($bytes, 0, $bytes.Length)
    $reqStream.Close()

    $resp = $null
    $statusCode = $null
    $respText = $null

    try {
        $resp = $req.GetResponse()
        $statusCode = [int]$resp.StatusCode
    }
    catch [System.Net.WebException] {
        $resp = $_.Exception.Response
        if ($resp -ne $null) {
            try { $statusCode = [int]$resp.StatusCode } catch {}
            $respText = Read-WebExceptionBody -WebException $_.Exception
        } else {
            throw "Token endpoint unreachable: $($_.Exception.Message)"
        }
    }

    if ($resp -ne $null -and -not $respText) {
        try {
            $reader = New-Object System.IO.StreamReader($resp.GetResponseStream())
            $respText = $reader.ReadToEnd()
            $reader.Close()
        } catch {}
    }

    if ($statusCode -lt 200 -or $statusCode -ge 300) {
        if ([string]::IsNullOrWhiteSpace($respText)) { $respText = "<empty>" }
        Write-Log "Token failed (HTTP $statusCode). Body: $respText" "ERROR"
        $code = Get-AadstsCode $respText
        throw ("Token request failed with HTTP {0}{1}" -f $statusCode, $(if ($code) { " ($code)" } else { "" }))
    }

    $json = $respText | ConvertFrom-Json
    if (-not $json.access_token) {
        Write-Log "Token success but missing access_token. Raw: $respText" "ERROR"
        throw "No access_token in token response."
    }
    return $json
}

function Acquire-TokenWithCertificate {
    # Mints with ONE named certificate and does NOT touch the token cache or telemetry - so it doubles as the
    # proof step for activate / test / retire.
    # A0.458: -ForClientId names the app the certificate signs in as (default: the active app when this is the active
    # certificate, else the configured shared app); -Scope names the resource (default: this bay's Dataverse).
    param(
        [Parameter(Mandatory=$true)][string]$Thumbprint,
        [string]$ForClientId = "",
        [string]$Scope = ""
    )
    $cert = Find-ClientCertificate $Thumbprint
    if ($null -eq $cert) { throw "Certificate $Thumbprint (with private key) not found in $((Get-CertStoreSearchOrder) -join ', ')" }
    if ($cert.NotAfter.ToUniversalTime() -lt (Get-Date).ToUniversalTime()) { throw "Certificate $Thumbprint expired $($cert.NotAfter.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ'))" }

    $clientForMint = ConvertTo-AgentGuid $ForClientId
    if (-not $clientForMint) {
        if ((Normalize-Thumbprint $Thumbprint) -eq (Get-ActiveCertThumbprint)) { $clientForMint = Get-ActiveClientId }
        else { $clientForMint = ConvertTo-AgentGuid $ClientId }
    }
    if (-not $clientForMint) { throw "No client id to sign in as (agent-config.json clientId is not a GUID)" }
    $scopeForMint = $Scope
    if ([string]::IsNullOrWhiteSpace($scopeForMint)) { $scopeForMint = "$OrgUrl/.default" }

    $tokenUrl  = Get-TokenUrl
    $assertion = New-ClientAssertionJwt -Certificate $cert -ClientId $clientForMint -Audience $tokenUrl -Alg $AssertionAlg
    $body = @(
        "client_id=$([uri]::EscapeDataString($clientForMint))"
        "client_assertion_type=$([uri]::EscapeDataString('urn:ietf:params:oauth:client-assertion-type:jwt-bearer'))"
        "client_assertion=$assertion"
        "grant_type=client_credentials"
        "scope=$([uri]::EscapeDataString($scopeForMint))"
    ) -join "&"
    return (Invoke-TokenEndpoint -TokenUrl $tokenUrl -FormBody $body)
}

function Acquire-TokenWithSecret {
    $clientSecret = Get-ClientSecret
    $body = @(
        "client_id=$([uri]::EscapeDataString($ClientId))"
        "client_secret=$([uri]::EscapeDataString($clientSecret))"
        "grant_type=client_credentials"
        "scope=$([uri]::EscapeDataString("$OrgUrl/.default"))"
    ) -join "&"
    return (Invoke-TokenEndpoint -TokenUrl (Get-TokenUrl) -FormBody $body)
}

function Acquire-Token {
    # Certificate first when one is active; the client secret is the transitional fallback. Every fallback is
    # logged and counted, so a silently-broken certificate path cannot hide behind a still-working secret.
    $json = $null
    $mode = $null
    $activeTp = Get-ActiveCertThumbprint
    $nowStr = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")

    if ($activeTp) {
        try {
            $json = Acquire-TokenWithCertificate -Thumbprint $activeTp
            $mode = "certificate"
            $Global:CredentialTelemetry.lastCertMintUtc = $nowStr
            $Global:CredentialTelemetry.lastCertError   = $null
        } catch {
            $Global:CredentialTelemetry.lastCertError = $_.Exception.Message
            # A0.458: on probation, a certificate that cannot sign in as the bay's own app counts toward going back.
            Register-IdentityProbationFailure ("mint: " + $_.Exception.Message)
            if ($HasSecretCredential) {
                $Global:CredentialTelemetry.fallbackCount++
                $Global:CredentialTelemetry.lastFallbackUtc = $nowStr
                Write-Log ("Certificate credential {0} failed ({1}); falling back to the client secret" -f $activeTp, $_.Exception.Message) "WARN"
            } else {
                throw
            }
        }
    }

    if ($null -eq $json) {
        try {
            $json = Acquire-TokenWithSecret
            $mode = "secret"
            $Global:CredentialTelemetry.lastSecretMintUtc = $nowStr
            $Global:CredentialTelemetry.lastSecretError   = $null
        } catch {
            $Global:CredentialTelemetry.lastSecretError = $_.Exception.Message
            throw
        }
    }

    # Cache expiry with a 5-minute safety buffer
    $expiresIn = 3600
    try { if ($json.expires_in) { $expiresIn = [int]$json.expires_in } } catch {}
    $Global:AccessToken = $json.access_token
    $Global:TokenExpiresUtc = (Get-Date).ToUniversalTime().AddSeconds($expiresIn - 300)
    $Global:CredentialTelemetry.lastMintMode = $mode
    $Global:CredentialTelemetry.lastMintUtc  = $nowStr

    Write-Log "Token acquired via $mode; expires approx $($Global:TokenExpiresUtc.ToString('yyyy-MM-ddTHH:mm:ssZ'))" "DEBUG"
    return $Global:AccessToken
}

function Sync-FallbackTelemetry {
    # A certificate that fails on EVERY loop while the secret quietly carries the bay is the exact silent state
    # this counter exists to expose - and an in-memory counter cannot expose it, because the Host Watchdog
    # restarts the agent routinely (restart.host markers, ONLOGON re-launch). Each restart would zero the count
    # and the bay would look healthy while running on a credential that is days from expiry.
    #
    # So the total is DURABLE: the session delta is folded into credential.json. Flushing happens here rather
    # than at the increment because this runs on the capabilities cadence (~10 min), not the 3-second poll -
    # a broken certificate would otherwise rewrite the state file every 3 seconds. The flush is idempotent:
    # only the not-yet-flushed delta is added, so calling it twice cannot double-count.
    $t = $Global:CredentialTelemetry
    $persisted = 0
    $st = Read-CredentialState
    # A CORRUPT STATE FILE MUST NOT REPORT A HEALTHY-LOOKING ZERO. The durable total lives in the file we
    # just failed to read, so the honest answer is "unknown", not 0 -- and the difference is the whole point of
    # the counter. KH-18 step 8 (deleting the estate's client secrets, the one irreversible act in the
    # rotation) is gated on an operator reading fallbackCountTotal and seeing zero. If corruption rendered as
    # zero, a bay that had been silently running on the secret for days would present exactly the reading that
    # unlocks the irreversible step. $null renders as absent/unknown in the heartbeat JSON and cannot be
    # mistaken for a clean zero; stateFileCorrupt says why.
    if ($Global:CredentialStateCorrupt) {
        Write-Log "fallbackCountTotal is UNKNOWN: credential.json is corrupt. Do not read this as zero, and do not treat the retirement gate as satisfied." "ERROR"
        return $null
    }
    try { $persisted = [int](Get-PropValue $st "fallbackCountTotal" 0) } catch { $persisted = 0 }

    $delta = [int]$t.fallbackCount - [int]$t.fallbackFlushed
    if ($delta -gt 0) {
        $persisted = $persisted + $delta
        try {
            $changes = @{ fallbackCountTotal = $persisted }
            if ($t.lastFallbackUtc) { $changes.lastFallbackUtc = $t.lastFallbackUtc }
            Update-CredentialState $changes | Out-Null
            $t.fallbackFlushed = $t.fallbackCount
        } catch {
            # Never let telemetry bookkeeping break a heartbeat. The delta stays unflushed and is retried.
            Write-Log ("Could not persist fallback telemetry: {0}" -f $_.Exception.Message) "WARN"
            $persisted = $persisted - $delta
        }
    }
    return $persisted
}

function Get-CredentialTelemetry {
    # Everything an operator or the expiry monitor needs, nothing an attacker wants.
    $activeTp = $null; $pendingTp = $null
    try { $activeTp  = Get-ActiveCertThumbprint } catch {}
    try { $pendingTp = Get-PendingCertThumbprint } catch {}

    $certInfo = $null
    if ($activeTp) {
        $c = Find-ClientCertificate $activeTp
        if ($c) {
            $certInfo = [ordered]@{
                found       = $true
                subject     = $c.Subject
                store       = (Get-CertStoreName $c)
                notBeforeUtc = $c.NotBefore.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
                notAfterUtc  = $c.NotAfter.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
                daysToExpiry = [int][Math]::Floor(($c.NotAfter.ToUniversalTime() - (Get-Date).ToUniversalTime()).TotalDays)
            }
        } else {
            $certInfo = [ordered]@{ found = $false }
        }
    }

    $secretMode = "none"
    if ($SecretPath) { $secretMode = "dpapi" } elseif ($Secret) { $secretMode = "plaintext" }

    # A0.458: which app the bay signs in as (public ids), and the state of an identity switch. The operator ladder's
    # activate reads activeClientId and activeThumbprint from here, next to the platform's own record of who wrote the row.
    $idState = $null
    try { $idState = Read-CredentialState } catch { }
    $probation = $null
    try { $probation = Get-IdentityProbation } catch { }
    $identity = [ordered]@{
        activeClientId       = $(try { Get-ActiveClientId } catch { $null })
        configuredClientId   = (ConvertTo-AgentGuid $ClientId)
        ownIdentity          = $(try { Test-OwnIdentityActive } catch { $false })
        probationSinceUtc    = $(if ($probation) { [string](Get-PropValue $probation "sinceUtc" "") } else { $null })
        probationFailures    = [int]$Global:IdentityProbationFailures
        confirmedUtc         = [string](Get-PropValue $idState "identityConfirmedUtc" "")
        reverted             = (Get-PropValue $idState "identityReverted" $null)
    }

    $t = $Global:CredentialTelemetry
    return [ordered]@{
        schema                 = 2
        activeClientId         = $identity.activeClientId
        identity               = $identity
        configuredMode         = $(if ($activeTp) { "certificate" } else { "secret" })
        # A corrupt state file is the one condition under which every OTHER number in this block is
        # untrustworthy -- including fallbackCountTotal, which gates the irreversible retirement. Say so.
        stateFileCorrupt       = [bool]$Global:CredentialStateCorrupt
        activeThumbprint       = $activeTp
        activeCertificate      = $certInfo
        pendingThumbprint      = $pendingTp
        secretConfigured       = $secretMode
        plaintextSecretPresent = ($null -ne $Secret)
        assertionAlg           = $AssertionAlg
        lastMintMode           = $t.lastMintMode
        lastMintUtc            = $t.lastMintUtc
        lastCertMintUtc        = $t.lastCertMintUtc
        lastSecretMintUtc      = $t.lastSecretMintUtc
        lastCertError          = $t.lastCertError
        lastSecretError        = $t.lastSecretError
        fallbackCount          = $t.fallbackCount        # this process
        fallbackCountTotal     = (Sync-FallbackTelemetry)  # durable across restarts - the one a monitor should read
        lastFallbackUtc        = $t.lastFallbackUtc
        lastTest               = $t.lastTest
    }
}

function Write-CredentialStartupSummary {
    # Finalises the fallback secret (file existence) and logs which credential the loop will run on.
    # Fail-fast rule: a configured-but-missing DPAPI file is FATAL only when the secret is the ONLY credential.
    # With a certificate active it is a WARN, so CredentialRotate action=retire secret=true cannot brick a
    # restart while clientSecretDpapiPath is still present in agent-config.json.
    $activeTp = Get-ActiveCertThumbprint
    $cert = $null
    if ($activeTp) { $cert = Find-ClientCertificate $activeTp }

    if ($SecretPathCfg -and -not (Test-Path -LiteralPath $SecretPathCfg)) {
        if ($cert) {
            Write-Log ("clientSecretDpapiPath is set but the file is missing ({0}); certificate-only, no secret fallback" -f $SecretPathCfg) "WARN"
            $script:SecretPath = $null
            $script:HasSecretCredential = ($null -ne $script:Secret)
        } else {
            throw "clientSecretDpapiPath is set but file not found: $SecretPathCfg"
        }
    }

    $fallbackLabel = "none"
    if ($script:SecretPath) { $fallbackLabel = "dpapi" } elseif ($script:Secret) { $fallbackLabel = "plaintext" }

    if ($activeTp) {
        if ($cert) {
            Write-Log ("Auth mode: CERTIFICATE thumbprint={0} store={1} notAfter={2} fallbackSecret={3}" -f $activeTp, (Get-CertStoreName $cert), $cert.NotAfter.ToUniversalTime().ToString("yyyy-MM-dd"), $fallbackLabel) "INFO"
        } elseif ($script:HasSecretCredential) {
            Write-Log ("Auth mode: CERTIFICATE thumbprint={0} is configured but NOT FOUND in {1}; running on the client secret ({2}) until it is" -f $activeTp, ((Get-CertStoreSearchOrder) -join ", "), $fallbackLabel) "WARN"
        } else {
            throw "Certificate $activeTp is configured but no certificate with a private key was found in $((Get-CertStoreSearchOrder) -join ', '), and no secret fallback is configured"
        }
    } else {
        if ($script:SecretPath) { Write-Log ("Auth mode: SECRET (DPAPI path={0}); no certificate enrolled yet - send CredentialRotate action=enroll" -f $script:SecretPath) "INFO" }
        elseif ($script:Secret) { Write-Log "Auth mode: SECRET (PLAINTEXT clientSecret in agent-config.json - DEPRECATED)" "WARN" }
    }
    if ($script:Secret) {
        Write-Log "DEPRECATED: agent-config.json carries a plaintext clientSecret. Enroll a certificate (CredentialRotate action=enroll) and delete the key; it is reported in the heartbeat as plaintextSecretPresent=true" "WARN"
    }
}

if (-not $EnrollCert) { Write-CredentialStartupSummary }

function Get-AccessToken {
    $now = (Get-Date).ToUniversalTime()
    if ($Global:AccessToken -and $now -lt $Global:TokenExpiresUtc) { return $Global:AccessToken }
    return (Acquire-Token)
}

# ---------------- Dataverse HTTP helpers ----------------
function New-DvHeaders {
    param(
        [Parameter(Mandatory=$true)][string]$token,
        [string]$ifMatch = $null
    )

    $h = @{
        Authorization      = "Bearer $token"
        Accept             = "application/json"
        "OData-MaxVersion" = "4.0"
        "OData-Version"    = "4.0"
        "User-Agent"       = "ABG-BayAgent/$AgentVersion"
        Prefer             = 'odata.include-annotations="*"'
    }
    if ($ifMatch) { $h["If-Match"] = $ifMatch }
    return $h
}

function Invoke-DvSafe {
    param(
        [Parameter(Mandatory=$true)][ValidateSet("GET","PATCH")][string]$Method,
        [Parameter(Mandatory=$true)][string]$Uri,
        [Parameter(Mandatory=$true)][hashtable]$Headers,
        [string]$BodyJson = $null
    )

    $Global:LastDvErrorBody = $null
    try {
        if ($Method -eq "PATCH") {
            Invoke-RestMethod -Method Patch -Uri $Uri -Headers $Headers -ContentType "application/json" -Body $BodyJson -ErrorAction Stop | Out-Null
            return $null
        } else {
            return Invoke-RestMethod -Method Get -Uri $Uri -Headers $Headers -ErrorAction Stop
        }
    }
    catch {
        # Capture the error record first: a nested try/catch below rebinds $_.
        $errRec = $_
        $ex = $errRec.Exception
        Write-Log "Dataverse call failed: $Method $Uri :: $($ex.Message)" "ERROR"

        # Best-effort: log the Dataverse error JSON body. On Windows PowerShell 5.1 Invoke-RestMethod has
        # already consumed the response stream, so the body lives in ErrorDetails.Message; read that first
        # and fall back to the stream only when it is empty.
        $body = $null
        try {
            if ($null -ne $errRec.ErrorDetails -and -not [string]::IsNullOrWhiteSpace([string]$errRec.ErrorDetails.Message)) {
                $body = [string]$errRec.ErrorDetails.Message
            }
        } catch {}
        if ([string]::IsNullOrWhiteSpace($body)) {
            try {
                $resp = $ex.Response
                if ($resp -ne $null) {
                    $reader = New-Object System.IO.StreamReader($resp.GetResponseStream())
                    $body = $reader.ReadToEnd()
                    $reader.Close()
                }
            } catch {}
        }
        if (-not [string]::IsNullOrWhiteSpace($body)) { Write-Log "Dataverse response body: $body" "ERROR" }
        # A0.458: the identity probation reads the platform's refusal text (a plugin's refusal arrives as a 400 whose
        # message is only in the body).
        $Global:LastDvErrorBody = $body

        throw
    }
}

function Dataverse-WhoAmI {
    param([Parameter(Mandatory=$true)][string]$token)
    $uri = "$OrgUrl/api/data/v9.2/WhoAmI()"
    $res = Invoke-DvSafe -Method GET -Uri $uri -Headers (New-DvHeaders $token)
    Write-Log ("WhoAmI OK: UserId={0} OrgId={1} BU={2}" -f $res.UserId, $res.OrganizationId, $res.BusinessUnitId) "INFO"
}

function Limit-ResultJson {
    # Serialise a command result so it ALWAYS fits build_resultjson. Bulky-but-optional keys are dropped in a
    # defined order (least useful first) before any hard truncation, so the load-bearing values - ok, action,
    # thumbprint, publicCertBase64 - survive. Anything dropped is named in the result, so a reader can never
    # mistake a trimmed result for a complete one.
    param(
        [Parameter(Mandatory=$true)]$ResultObj,
        [int]$MaxChars = 0
    )
    if ($MaxChars -le 0) { $MaxChars = $ResultJsonMaxChars }

    if ($ResultObj -is [string]) {
        if ($ResultObj.Length -le $MaxChars) { return $ResultObj }
        return ($ResultObj.Substring(0, [Math]::Max(0, $MaxChars - 15)) + "...[truncated]")
    }

    $json = ($ResultObj | ConvertTo-Json -Depth 10 -Compress)
    if ($json.Length -le $MaxChars) { return $json }

    # Rebuild as an ordered map we can prune. Drop order: prose and paths first, identity and key material last.
    $map = [ordered]@{}
    if ($ResultObj -is [System.Collections.IDictionary]) {
        foreach ($k in @($ResultObj.Keys)) { $map[$k] = $ResultObj[$k] }
    } else {
        foreach ($prop in $ResultObj.PSObject.Properties) { $map[$prop.Name] = $prop.Value }
    }
    $dropOrder = @("next", "publicCertPath", "subject", "notBeforeUtc", "store", "reused", "activatedDirectly", "state", "certificates")
    $dropped = @()
    foreach ($k in $dropOrder) {
        if (-not $map.Contains($k)) { continue }
        $map.Remove($k)
        $dropped += $k
        $map["resultTrimmed"] = $true
        $map["resultDroppedKeys"] = ($dropped -join ",")
        $json = ($map | ConvertTo-Json -Depth 10 -Compress)
        if ($json.Length -le $MaxChars) { return $json }
    }

    # Still too big: the key material itself cannot fit. Say so explicitly and point at the on-disk copy rather
    # than shipping a half base64 blob that looks like a certificate and is not one.
    if ($map.Contains("publicCertBase64")) {
        $map["publicCertBase64"] = $null
        $map["publicCertBase64Omitted"] = "too large for build_resultjson; read state\bay-cert-<thumbprint>.cer on the bay, or re-enroll with keyLength 2048"
        $map["resultTrimmed"] = $true
        $json = ($map | ConvertTo-Json -Depth 10 -Compress)
        if ($json.Length -le $MaxChars) { return $json }
    }

    return ($json.Substring(0, [Math]::Max(0, $MaxChars - 15)) + "...[truncated]")
}

function Patch-Row {
    param(
        [Parameter(Mandatory=$true)][string]$token,
        [Parameter(Mandatory=$true)][string]$entitySet,
        [Parameter(Mandatory=$true)][string]$id,
        [Parameter(Mandatory=$true)]$bodyObj,
        [Parameter(Mandatory=$true)][string]$ifMatch
    )

    $id = ($id.ToString()).Trim("{}")
    $uri = "$OrgUrl/api/data/v9.2/$entitySet($id)"
    $json = ($bodyObj | ConvertTo-Json -Depth 10)

    Invoke-DvSafe -Method PATCH -Uri $uri -Headers (New-DvHeaders $token $ifMatch) -BodyJson $json
}

# ---------------- A0.458: identity switch proof, probation and revert ----------------
# An identity switch is held on PROBATION until an operator confirms it (CredentialRotate action=confirm, which can
# only run if the new identity can claim a command). While on probation the agent goes back to its previous credential
# on its own when the new identity is REFUSED (an Entra code, a 401/403, the command guard) five times in a row, or
# when nobody confirms within 72 hours. A network outage is not a refusal and never triggers it.
$IdentityProbationMaxFailures = 5
$IdentityProbationMaxHours    = 72
$Global:IdentityProbationFailures = 0
$Global:CurrentCommandId = $null

function Test-IdentityRefusal([string]$Message) {
    # Refused BY the platform, as opposed to unreachable. Reads the last Dataverse error body too (a plugin refusal
    # is a 400 whose words are only in the body).
    $text = "$Message $([string]$Global:LastDvErrorBody)"
    if ($text -match "unreachable|timed out|could not be resolved|No such host|actively refused|Unable to connect") { return $false }
    return ($text -match "AADSTS\d+|\(401\)|\(403\)|\b401\b|\b403\b|Unauthorized|Forbidden|Only the BayAgent user|not found in Cert:|expired")
}

function Register-IdentityProbationFailure([string]$What) {
    # Never throws: it is called from the token path and the main loop's catch.
    try {
        if ($null -eq (Get-IdentityProbation)) { return }
        if (-not (Test-IdentityRefusal $What)) { return }
        $Global:IdentityProbationFailures = [int]$Global:IdentityProbationFailures + 1
        Write-Log ("[IDENTITY] the bay's own identity was refused ({0}/{1}): {2}" -f $Global:IdentityProbationFailures, $IdentityProbationMaxFailures, $What) "WARN"
        if ($Global:IdentityProbationFailures -ge $IdentityProbationMaxFailures) {
            [void](Invoke-IdentityRevert -Reason ("auto: refused {0} times in a row; last: {1}" -f $Global:IdentityProbationFailures, $What))
        }
    } catch {
        Write-Log ("[IDENTITY] could not record a probation failure: {0}" -f $_.Exception.Message) "ERROR"
    }
}

function Clear-IdentityProbationFailures {
    $Global:IdentityProbationFailures = 0
}

function Test-IdentityProbationExpiry {
    # Never throws. A switch nobody confirmed within the window is undone.
    param([DateTime]$Now = (Get-Date).ToUniversalTime())
    try {
        $p = Get-IdentityProbation
        if ($null -eq $p) { return }
        $since = [DateTime]::MinValue
        $raw = Get-PropValue $p "sinceUtc" $null
        if ($raw -is [DateTime]) { $since = $raw.ToUniversalTime() }
        elseif (-not [DateTime]::TryParse([string]$raw, [Globalization.CultureInfo]::InvariantCulture,
                [Globalization.DateTimeStyles]::AdjustToUniversal -bor [Globalization.DateTimeStyles]::AssumeUniversal, [ref]$since)) {
            # An unreadable start is treated as expired: a probation that cannot say when it began cannot be kept open.
            $since = [DateTime]::MinValue
        }
        if ($since.AddHours($IdentityProbationMaxHours) -lt $Now) {
            [void](Invoke-IdentityRevert -Reason ("auto: not confirmed within {0} hours" -f $IdentityProbationMaxHours))
        }
    } catch {
        Write-Log ("[IDENTITY] probation expiry check failed: {0}" -f $_.Exception.Message) "ERROR"
    }
}

function Invoke-IdentityRevert {
    # Go back to the credential in force before the switch. Returns $true when it did. A corrupt state file is never
    # rewritten (Update-CredentialState refuses), so a revert that cannot be recorded does not happen and says so.
    param([Parameter(Mandatory=$true)][string]$Reason)
    $p = Get-IdentityProbation
    if ($null -eq $p) { return $false }
    if ($Global:CredentialStateCorrupt) {
        Write-Log "[IDENTITY] cannot revert: credential.json is corrupt. Recover it from the .bak first." "ERROR"
        return $false
    }
    $fromTp = Get-ActiveCertThumbprint
    $fromClient = Get-ActiveClientId
    $prevTp = $null
    try { $prevTp = Normalize-Thumbprint ([string](Get-PropValue $p "previousThumbprint" "")) } catch { $prevTp = $null }
    $prevClient = ConvertTo-AgentGuid ([string](Get-PropValue $p "previousClientId" ""))
    $nowStr = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")

    # The certificate being left keeps a record, so its private key can still be retired later.
    $sup = @()
    $priorSup = Get-PropValue (Read-CredentialState) "superseded" $null
    if ($priorSup) { $sup = @($priorSup) }
    if ($fromTp -and ($sup -notcontains $fromTp) -and ($fromTp -ne $prevTp)) { $sup += $fromTp }

    Update-CredentialState @{
        activeThumbprint  = $prevTp
        activeClientId    = $prevClient
        identityProbation = $null
        superseded        = $sup
        identityReverted  = [ordered]@{ utc = $nowStr; reason = $Reason; fromClientId = $fromClient; fromThumbprint = $fromTp }
    } | Out-Null
    # Expiring the cached token is enough: Get-AccessToken re-mints when the expiry has passed (the e-stop latch writer
    # census pins every dynamic variable write, so no Set-Variable here).
    $Global:TokenExpiresUtc = [DateTime]::MinValue
    $Global:IdentityProbationFailures = 0
    Write-Log ("[IDENTITY] REVERTED from app {0} to {1}: {2}" -f $fromClient, $(if ($prevTp) { "certificate $prevTp" } else { "the configured credential" }), $Reason) "ERROR"
    return $true
}

function Test-IdentityCandidate {
    # PROVE a new identity before switching to it, against the things that would strand the bay if they refused it:
    # a token mint, Dataverse (WhoAmI), this bay's own row (read and the heartbeat write), and the COMMAND GUARD (an
    # execution-field write on the command being run, which the guard refuses to anyone but the bay agent user). Throws
    # a sentence naming the first refusal; nothing has been switched when it throws.
    param(
        [Parameter(Mandatory=$true)][string]$Thumbprint,
        [Parameter(Mandatory=$true)][string]$ForClientId
    )
    $cmdId = [string]$Global:CurrentCommandId
    if ([string]::IsNullOrWhiteSpace($cmdId)) { throw "activate: an identity switch runs only as a CredentialRotate command (the command it runs on is the command-guard probe)" }

    $j = $null
    try { $j = Acquire-TokenWithCertificate -Thumbprint $Thumbprint -ForClientId $ForClientId }
    catch { throw ("activate refused: certificate {0} cannot sign in as app {1}: {2}" -f $Thumbprint, $ForClientId, $_.Exception.Message) }
    $tok = [string]$j.access_token
    $h = New-DvHeaders $tok

    $who = $null
    try { $who = Invoke-DvSafe -Method GET -Uri "$OrgUrl/api/data/v9.2/WhoAmI()" -Headers $h }
    catch { throw ("activate refused: Dataverse refuses app {0} (is its application user missing or disabled?): {1}" -f $ForClientId, $_.Exception.Message) }

    try { [void](Invoke-DvSafe -Method GET -Uri "$OrgUrl/api/data/v9.2/$BayEntitySet($BayId)?`$select=build_bayid" -Headers $h) }
    catch { throw ("activate refused: app {0} cannot read this bay's row (its role?): {1}" -f $ForClientId, $_.Exception.Message) }

    $nowStr = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
    try { Patch-Row $tok $BayEntitySet $BayId @{ $Col_Heartbeat = $nowStr } "*" }
    catch { throw ("activate refused: app {0} cannot write this bay's heartbeat: {1}" -f $ForClientId, $_.Exception.Message) }

    try { Patch-Row $tok $BayCommandEntitySet $cmdId @{ $Col_Result = '{"stage":"identity-probe"}' } "*" }
    catch { throw ("activate refused: the command guard refuses app {0}, so this bay could not run its commands on it: {1}" -f $ForClientId, $_.Exception.Message) }

    return [ordered]@{ mintedWithCertificate = $true; userId = [string](Get-PropValue $who "UserId" ""); bayRead = $true; bayWrite = $true; commandGuard = $true }
}

# ---------------- A0.456: the bay's own short-lived wall pass ----------------
# The bay fetches the pass for ITS OWN wall with its own identity (POST /api/v1/bay/display-pass) and refreshes it; nothing
# long-lived is stored. WHERE it asks is fixed in this signed file, keyed by this bay's own Dataverse org: no platform row,
# config item or command can point the bay (or its token) at another host. "off" until a release turns it on.
$DisplayPassReleaseMode = "off"
$DisplayPassSites = @{
    "builds-apps-dev.crm.dynamics.com" = @{ site = "https://testclub.dev.aceofclubs.golf"; apiAppId = "e7e1a2d5-4612-4e3f-9c58-5618ec7e0454" }
}
$DisplayPassWallPath  = "/bay-display.html"
# The wall page's query parameter that carries the pass (web/src/pages/bay-display.ts reads it).
$DisplayPassQueryName = "token"
$DisplayPassRoute     = "/api/v1/bay/display-pass"
$DisplayPassStatePath = Join-Path $BaseDir "state\display-pass.json"
$Global:DisplayPassNextAttemptUtc = [DateTime]::MinValue
$Global:DisplayPassBackoffSec     = 60
$Global:DisplayPassLast           = [ordered]@{ attemptUtc = $null; result = $null; status = $null }

function Get-DisplayPassEndpoint {
    # The pinned site and API app for this bay's own org, or $null.
    $orgHost = $null
    try { $orgHost = ([uri]$OrgUrl).Host.ToLowerInvariant() } catch { return $null }
    if (-not $DisplayPassSites.ContainsKey($orgHost)) { return $null }
    $e = $DisplayPassSites[$orgHost]
    $site = [string]$e.site
    $api = ConvertTo-AgentGuid ([string]$e.apiAppId)
    if (-not $api) { return $null }
    $u = $null
    if (-not [uri]::TryCreate($site, [UriKind]::Absolute, [ref]$u)) { return $null }
    if ($u.AbsolutePath -ne "/" -or $u.Query -or $u.UserInfo) { return $null }
    if ($u.Scheme -ne "https" -and -not ($u.Scheme -eq "http" -and $u.IsLoopback)) { return $null }
    return [ordered]@{ site = $site.TrimEnd("/"); apiAppId = $api }
}

function ConvertTo-DisplayPassUtc($Value) {
    # A zoned instant as UTC, or $null. PowerShell 7 hands back DateTime for ISO text (Kind Utc when the text carried a
    # zone, Unspecified when it did not); 5.1 hands back text. A zone-less value is refused on both.
    if ($null -eq $Value) { return $null }
    if ($Value -is [DateTime]) {
        if ($Value.Kind -eq [DateTimeKind]::Unspecified) { return $null }
        return $Value.ToUniversalTime()
    }
    $s = [string]$Value
    if ($s -notmatch '(Z|[+-]\d\d:\d\d)$') { return $null }
    $d = [DateTimeOffset]::MinValue
    if (-not [DateTimeOffset]::TryParse($s, [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::None, [ref]$d)) { return $null }
    return $d.UtcDateTime
}

function Test-DisplayPassShape {
    # The pass as the bay keeps it. Every field checked; any failure is "no pass". Returns the normalized record or $null.
    param($Obj, [DateTime]$Now = (Get-Date).ToUniversalTime())
    if ($null -eq $Obj) { return $null }
    $bay = ConvertTo-AgentGuid ([string](Get-PropValue $Obj "bayId" ""))
    if ($bay -ne (ConvertTo-AgentGuid $BayId)) { return $null }
    $ref = [string](Get-PropValue $Obj "bayRef" "")
    if ($ref -notmatch '^[A-Za-z0-9._-]{1,64}$') { return $null }
    $pass = [string](Get-PropValue $Obj "pass" "")
    if ($pass.Length -gt 2048 -or $pass -notmatch '^BAYD1\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$') { return $null }
    if ([string](Get-PropValue $Obj "wallPath" "") -ne $DisplayPassWallPath) { return $null }
    $exp = ConvertTo-DisplayPassUtc (Get-PropValue $Obj "expiresUtc" $null)
    $refresh = ConvertTo-DisplayPassUtc (Get-PropValue $Obj "refreshAfterUtc" $null)
    if ($null -eq $exp -or $null -eq $refresh) { return $null }
    if ($exp -le $Now -or $exp -gt $Now.AddHours(25) -or $refresh -gt $exp) { return $null }
    return [ordered]@{
        bayId = $bay; bayRef = $ref; pass = $pass; wallPath = $DisplayPassWallPath
        expiresUtc = $exp.ToString("yyyy-MM-ddTHH:mm:ssZ"); refreshAfterUtc = $refresh.ToString("yyyy-MM-ddTHH:mm:ssZ")
    }
}

function Read-DisplayPassState {
    # Strict: absent, unreadable, unparseable or out of shape are all "no pass".
    param([DateTime]$Now = (Get-Date).ToUniversalTime())
    if (-not (Test-Path -LiteralPath $DisplayPassStatePath)) { return $null }
    try {
        $raw = [IO.File]::ReadAllText($DisplayPassStatePath)
        $obj = $raw | ConvertFrom-Json
        return (Test-DisplayPassShape -Obj $obj -Now $Now)
    } catch { return $null }
}

function Write-DisplayPassState($Record) {
    $dir = Split-Path -Parent $DisplayPassStatePath
    if (!(Test-Path $dir)) { New-Item -ItemType Directory -Force -Path $dir | Out-Null }
    $tmp = "$DisplayPassStatePath.tmp"
    [IO.File]::WriteAllText($tmp, ($Record | ConvertTo-Json -Depth 4 -Compress), (New-Object Text.UTF8Encoding($false)))
    Move-Item -LiteralPath $tmp -Destination $DisplayPassStatePath -Force
}

function Invoke-DisplayPassFetch {
    # One fetch. Returns a short result code; writes the pass only when its shape holds. Never logs the pass.
    param([DateTime]$Now = (Get-Date).ToUniversalTime())
    $ep = Get-DisplayPassEndpoint
    if ($null -eq $ep) { return "no_pinned_site" }
    if (-not (Test-OwnIdentityActive)) { return "not_own_identity" }
    $tp = Get-ActiveCertThumbprint
    $j = $null
    try { $j = Acquire-TokenWithCertificate -Thumbprint $tp -ForClientId (Get-ActiveClientId) -Scope ("{0}/.default" -f $ep.apiAppId) }
    catch {
        Register-IdentityProbationFailure ("pass mint: " + $_.Exception.Message)
        return ("mint_failed:" + (Get-AadstsCode $_.Exception.Message))
    }
    $headers = @{ "X-Bay-Identity-Authorization" = ("Bearer " + [string]$j.access_token); Accept = "application/json"; "User-Agent" = "ABG-BayAgent/$AgentVersion" }
    $body = (@{ bayId = (ConvertTo-AgentGuid $BayId) } | ConvertTo-Json -Compress)
    $resp = $null
    try {
        $resp = Invoke-RestMethod -Method Post -Uri ($ep.site + $DisplayPassRoute) -Headers $headers -ContentType "application/json" -Body $body -TimeoutSec 20 -ErrorAction Stop
    } catch {
        $errRec = $_
        $code = $null
        try { $code = ([string]$errRec.ErrorDetails.Message | ConvertFrom-Json).error.code } catch { }
        $status = $null
        try { $status = [int]$errRec.Exception.Response.StatusCode } catch { }
        $Global:DisplayPassLast.status = $status
        return ("refused:" + $(if ($code) { $code } elseif ($status) { "http_$status" } else { "unreachable" }))
    }
    $record = Test-DisplayPassShape -Obj $resp -Now $Now
    if ($null -eq $record) { return "bad_shape" }
    Write-DisplayPassState $record
    $back = Read-DisplayPassState -Now $Now
    if ($null -eq $back -or $back.pass -ne $record.pass) { return "write_not_read_back" }
    return "ok"
}

function Update-DisplayPassIfDue {
    # Called every main-loop pass; does nothing until the pass is due or missing. Never throws.
    param([DateTime]$Now = (Get-Date).ToUniversalTime())
    try {
        if ($DisplayPassReleaseMode -ne "on") { return }
        if ($Now -lt $Global:DisplayPassNextAttemptUtc) { return }
        $have = Read-DisplayPassState -Now $Now
        if ($null -ne $have) {
            $refresh = ConvertTo-DisplayPassUtc $have.refreshAfterUtc
            if ($null -ne $refresh -and $Now -lt $refresh) { return }
        }
        $Global:DisplayPassLast.attemptUtc = $Now.ToString("yyyy-MM-ddTHH:mm:ssZ")
        $result = Invoke-DisplayPassFetch -Now $Now
        $Global:DisplayPassLast.result = $result
        if ($result -eq "ok") {
            $Global:DisplayPassBackoffSec = 60
            $Global:DisplayPassNextAttemptUtc = $Now.AddSeconds(60)
            Write-Log "[DISPLAY-PASS] fetched a new wall pass" "INFO"
        } else {
            $Global:DisplayPassNextAttemptUtc = $Now.AddSeconds($Global:DisplayPassBackoffSec)
            $Global:DisplayPassBackoffSec = [Math]::Min(1800, [int]$Global:DisplayPassBackoffSec * 2)
            Write-Log ("[DISPLAY-PASS] no new pass: {0}" -f $result) "WARN"
        }
    } catch {
        $Global:DisplayPassLast.result = "error:" + $_.Exception.GetType().Name
        Write-Log ("[DISPLAY-PASS] refresh failed: {0}" -f $_.Exception.Message) "WARN"
    }
}

function Get-DisplayPassWallUrl {
    # THE SEAM for whatever opens the wall (Start-SessionDisplay / the kiosk shell): the wall address for this bay's own
    # pinned site with a valid pass, or $null (then the caller keeps its existing display). The pass must outlive the
    # next two minutes.
    param([DateTime]$Now = (Get-Date).ToUniversalTime())
    if ($DisplayPassReleaseMode -ne "on") { return $null }
    $ep = Get-DisplayPassEndpoint
    if ($null -eq $ep) { return $null }
    $p = Read-DisplayPassState -Now $Now.AddMinutes(2)
    if ($null -eq $p) { return $null }
    return ("{0}{1}?bay={2}&{3}={4}" -f $ep.site, $p.wallPath, [uri]::EscapeDataString($p.bayRef), $DisplayPassQueryName, [uri]::EscapeDataString($p.pass))
}

function Get-DisplayPassTelemetry {
    # Never the pass.
    $ep = Get-DisplayPassEndpoint
    $p = Read-DisplayPassState
    return [ordered]@{
        mode            = $DisplayPassReleaseMode
        sitePinned      = ($null -ne $ep)
        site            = $(if ($ep) { $ep.site } else { $null })
        ownIdentity     = (Test-OwnIdentityActive)
        hasValidPass    = ($null -ne $p)
        bayRef          = $(if ($p) { $p.bayRef } else { $null })
        expiresUtc      = $(if ($p) { $p.expiresUtc } else { $null })
        refreshAfterUtc = $(if ($p) { $p.refreshAfterUtc } else { $null })
        lastAttemptUtc  = $Global:DisplayPassLast.attemptUtc
        lastResult      = $Global:DisplayPassLast.result
    }
}


# ---------------- Step 8.2: Dynamic config pull + overlay + caching ----------------
$Global:NextConfigRefreshUtc = [DateTime]::MinValue
$Global:EffectiveConfig = $null

# Capabilities write-back cadence (seconds)
$Global:CapabilitiesEverySeconds = 600   # 10 minutes
$Global:NextCapabilitiesUtc = (Get-Date).ToUniversalTime()  # write on first heartbeat

function Dv-Get {
    param(
        [Parameter(Mandatory=$true)][string]$token,
        [Parameter(Mandatory=$true)][string]$pathAndQuery
    )
    $uri = "$OrgUrl/api/data/v9.2/$pathAndQuery"
    return Invoke-DvSafe -Method GET -Uri $uri -Headers (New-DvHeaders $token)
}

function Set-PSObjectProp {
    param(
        [Parameter(Mandatory=$true)]$obj,
        [Parameter(Mandatory=$true)][string]$name,
        $value
    )
    if ($null -eq $obj) { return }
    if ($obj.PSObject.Properties.Name -contains $name) {
        $obj.$name = $value
    } else {
        $obj | Add-Member -NotePropertyName $name -NotePropertyValue $value -Force
    }
}

function Get-EffectiveConfigValue {
    param(
        [hashtable]$cfg,
        [string]$key,
        $defaultValue = $null
    )
    if ($null -ne $cfg -and $cfg.ContainsKey($key)) {
        $v = $cfg[$key]
        if ($null -ne $v -and (-not [string]::IsNullOrWhiteSpace([string]$v))) { return $v }
    }
    return $defaultValue
}

function Get-BayContextForConfig {
    param([Parameter(Mandatory=$true)][string]$token)

    $selectBay = @(
        $Lookup_LocationValue,
        $Lookup_BayProfileValue,
        $Col_AgentStatus,
        $Col_AgentStatusUntil,
        $Col_AgentStatusReason
    ) -join ","

    $bay = Dv-Get $token "${BayEntitySet}($BayId)?`$select=$selectBay"

    $locId = $null
    $bpId  = $null
    try { $locId = $bay.$Lookup_LocationValue } catch {}
    try { $bpId  = $bay.$Lookup_BayProfileValue } catch {}

    $tzId = $null
    if ($locId) {
        $loc = Dv-Get $token "${LocationEntitySet}($locId)?`$select=$Col_TimeZoneId"
        try { $tzId = $loc.$Col_TimeZoneId } catch {}
    }

    $bp = $null
    if ($bpId) {
        $selectBp = @(
            $Col_BP_LauncherPath,
            $Col_BP_LauncherArgs,
            $Col_BP_LauncherProcName,
            $Col_BP_SessionMode,
            $Col_BP_SessionJsonPath,
            $Col_BP_ProfileJson
        ) -join ","
        $bp = Dv-Get $token "${BayProfileEntitySet}($bpId)?`$select=$selectBp"
    }

    return [pscustomobject]@{
        Bay = $bay
        LocationId = $locId
        TimeZoneId = $tzId
        BayProfileId = $bpId
        BayProfile = $bp
    }
}

function Get-ConfigOverlay {
    param(
        [Parameter(Mandatory=$true)][string]$token,
        [Parameter(Mandatory=$true)][Guid]$bayGuid,
        [Guid]$locationGuid = $null
    )

    # enabled AND (global OR location-match OR bay-match)
    $filter = "$Col_CI_Enabled eq true and ( $Col_CI_Scope eq $SCOPE_GLOBAL"
    if ($locationGuid) { $filter += " or ($Col_CI_Scope eq $SCOPE_LOCATION and _build_location_value eq $locationGuid)" }
    $filter += " or ($Col_CI_Scope eq $SCOPE_BAY and _build_bay_value eq $bayGuid) )"

    $select = "$Col_CI_Scope,$Col_CI_Key,$Col_CI_Value"
    $uri = "${ConfigItemEntitySet}?`$select=$select&`$filter=$([uri]::EscapeDataString($filter))&`$top=5000"

    $res = Dv-Get $token $uri
    $items = @()
    if ($res.value) { $items = @($res.value) }

    # order by precedence: Global -> Location -> Bay
    $ordered = @()
    $ordered += $items | Where-Object { $_.$Col_CI_Scope -eq $SCOPE_GLOBAL }
    $ordered += $items | Where-Object { $_.$Col_CI_Scope -eq $SCOPE_LOCATION }
    $ordered += $items | Where-Object { $_.$Col_CI_Scope -eq $SCOPE_BAY }

    $cfg = @{}
    foreach ($it in $ordered) {
        $k = $it.$Col_CI_Key
        if ([string]::IsNullOrWhiteSpace([string]$k)) { continue }
        $cfg[$k.Trim()] = $it.$Col_CI_Value
    }
    return $cfg
}

function Build-EffectiveConfig {
    param(
        [Parameter(Mandatory=$true)]$ctx,
        [Parameter(Mandatory=$true)][hashtable]$overlay
    )

    $eff = @{}

    if (-not [string]::IsNullOrWhiteSpace([string]$ctx.TimeZoneId)) {
        $eff["Location.TimeZoneId"] = $ctx.TimeZoneId
    }

    if ($ctx.BayProfile) {
        $bp = $ctx.BayProfile
        $eff["BayProfile.Id"] = $ctx.BayProfileId

        $eff["Bay.Launcher.Path"]        = $bp.$Col_BP_LauncherPath
        $eff["Bay.Launcher.Args"]        = $bp.$Col_BP_LauncherArgs
        $eff["Bay.Launcher.ProcessName"] = $bp.$Col_BP_LauncherProcName

        $eff["Bay.SessionDisplay.Mode"] = $bp.$Col_BP_SessionMode
        $eff["Bay.SessionDisplay.SessionJsonPath"] = $bp.$Col_BP_SessionJsonPath

        try {
            if ($bp.PSObject.Properties.Name -contains $Col_BP_ProfileJson) {
                $eff["BayProfile.ProfileJson"] = $bp.$Col_BP_ProfileJson
            }
        } catch {}
    }

    # overlay (Global -> Location -> Bay)
    foreach ($k in $overlay.Keys) { $eff[$k] = $overlay[$k] }

    # include operational status (read-only reference for Step 8.3)
    try { $eff["Bay.AgentStatus"] = $ctx.Bay.$Col_AgentStatus } catch {}
    try { $eff["Bay.AgentStatusUntil"] = $ctx.Bay.$Col_AgentStatusUntil } catch {}
    try { $eff["Bay.AgentStatusReason"] = $ctx.Bay.$Col_AgentStatusReason } catch {}

    return $eff
}

function Apply-EffectiveConfigToRuntime {
    param([Parameter(Mandatory=$true)][hashtable]$eff)

    # Poll / heartbeat / log level
    $newPoll = Get-EffectiveConfigValue $eff "Bay.PollSeconds" $script:PollSec
    $newHb   = Get-EffectiveConfigValue $eff "Bay.HeartbeatSeconds" $script:HeartbeatSec
    $newLvl  = Get-EffectiveConfigValue $eff "Bay.LogLevel" $Global:LogLevel

    try { $script:PollSec = [int]$newPoll } catch {}
    try { $script:HeartbeatSec = [int]$newHb } catch {}
    if ($script:HeartbeatSec -lt 15) { $script:HeartbeatSec = 15 }

    if (-not [string]::IsNullOrWhiteSpace([string]$newLvl)) {
        $Global:LogLevel = $newLvl.ToString().ToUpperInvariant()
    }

    # Launcher defaults (update $cfg so existing code paths keep working unchanged)
    if ($null -eq $cfg.launcher) { Set-PSObjectProp $cfg "launcher" ([pscustomobject]@{}) }
    $lp = Get-EffectiveConfigValue $eff "Bay.Launcher.Path" $null
    $la = Get-EffectiveConfigValue $eff "Bay.Launcher.Args" $null
    $ln = Get-EffectiveConfigValue $eff "Bay.Launcher.ProcessName" $null
    if ($lp) { Set-PSObjectProp $cfg.launcher "path" $lp }
    if ($la -ne $null) { Set-PSObjectProp $cfg.launcher "args" $la }
    if ($ln) { Set-PSObjectProp $cfg.launcher "processName" $ln }

    # Session display defaults (update $cfg so UpdateSessionDisplay / Start/End session uses it)
    $sj = Get-EffectiveConfigValue $eff "Bay.SessionDisplay.SessionJsonPath" $null
    if ($sj) { Set-PSObjectProp $cfg "sessionJsonPath" $sj }

    if ($null -eq $cfg.sessionDisplay) { Set-PSObjectProp $cfg "sessionDisplay" ([pscustomobject]@{}) }
    $sm = Get-EffectiveConfigValue $eff "Bay.SessionDisplay.Mode" $null
    if ($sm) {
        # Normalize SessionDisplay.Mode:
        # - BayProfile choice values come through as integers (e.g., 100000000)
        # - ConfigItem overrides may come through as "kiosk"/"normal"
        $smNorm = "$sm".ToLowerInvariant()
        switch ($smNorm) {
            "100000000" { $smNorm = "kiosk" }
            "100000001" { $smNorm = "normal" }
            "kiosk"     { $smNorm = "kiosk" }
            "normal"    { $smNorm = "normal" }
            default     { }
        }
        Set-PSObjectProp $cfg.sessionDisplay "mode" $smNorm
        # Also normalize the effective config value so later reads/logs see the label
        $eff["Bay.SessionDisplay.Mode"] = $smNorm
    }
    # Optional: log a one-line summary when config applies (DEBUG)
    if ($Global:LogLevel -eq "DEBUG") {
        $tz = Get-EffectiveConfigValue $eff "Location.TimeZoneId" "<null>"
        Write-Log ("[CFG] tz={0} poll={1}s hb={2}s launcher={3} sessionJson={4} mode={5}" -f $tz, $script:PollSec, $script:HeartbeatSec,
            (Get-EffectiveConfigValue $eff "Bay.Launcher.Path" "<null>"),
            (Get-EffectiveConfigValue $eff "Bay.SessionDisplay.SessionJsonPath" "<null>"),
            (Get-EffectiveConfigValue $eff "Bay.SessionDisplay.Mode" "<null>")
        ) "DEBUG"
    }
}

function Refresh-EffectiveConfigIfDue {
    param([Parameter(Mandatory=$true)][string]$token)

    $now = (Get-Date).ToUniversalTime()
    if ($now -lt $Global:NextConfigRefreshUtc -and $Global:EffectiveConfig) { return }

    try {
        $ctx = Get-BayContextForConfig $token

        $bayGuid = [Guid]$BayId
        $locGuid = $null
        if ($ctx.LocationId) { $locGuid = [Guid]$ctx.LocationId }

        $overlay = Get-ConfigOverlay -token $token -bayGuid $bayGuid -locationGuid $locGuid
        $eff = Build-EffectiveConfig -ctx $ctx -overlay $overlay

        $Global:EffectiveConfig = $eff
        Apply-EffectiveConfigToRuntime $eff

        $Global:NextConfigRefreshUtc = $now.AddSeconds($ConfigRefreshSec)
    }
    catch {
        # Don't crash on config failures; keep last-known-good config and retry soon
        Write-Log ("Dynamic config refresh failed: {0}" -f $_.Exception.Message) "WARN"
        $Global:NextConfigRefreshUtc = $now.AddSeconds([Math]::Min($ConfigRefreshSec, 30))
    }
}

function Get-EmergencyStopCapability {
    return @{
        engaged   = [bool]$Global:EmergencyStopEngaged
        reason    = $Global:EmergencyStopReason
        persisted = [bool]$Global:EmergencyStopPersistOk
    }
}

# ---------------- Remote state report (1.3.1, A0.437) ----------------
# Kevin, 2026-10-07: "I don't like that you need me to be at the Bay PC in order to update the BayAgent." The 1.3.0
# remote install could only INFER three things: where windows landed, whether self-heal was off (the local config
# cannot be read remotely) and which code was running (the version label lied, F1). These functions put those facts
# where the platform already reads: build_agentcapabilitiesjson on the bay row (30000 chars), refreshed on demand by
# a DisplayTopology command or a HealthCheck with payload {"report":true}.

function Invoke-ReportPart([scriptblock]$Part) {
    # One failing part of the report must not take the rest down (a failed capabilities build falls back to the
    # small partial document and loses everything else).
    try { return (& $Part) } catch { return [ordered]@{ error = $_.Exception.Message } }
}

function Get-StateJsonSummary([string]$Name, [int]$MaxChars = 1500) {
    # A small state file under state\, returned parsed; $null when absent, a marker when unreadable or too large.
    $p = Join-Path $BaseDir ("state\" + $Name)
    if (-not (Test-Path -LiteralPath $p)) { return $null }
    try {
        $t = [IO.File]::ReadAllText($p)
        if ($t.Length -gt $MaxChars) { return [ordered]@{ unreadable = "larger than $MaxChars chars" } }
        return ($t | ConvertFrom-Json)
    } catch { return [ordered]@{ unreadable = $_.Exception.Message } }
}

function Get-AgentInstallFacts {
    # Which code is running, and the shape of the install the next update and the rollback guard will act on.
    $i = [ordered]@{
        codeVersion         = $AgentCodeVersion
        manifestVersion     = $AgentManifestVersion
        manifestMatchesCode = ([string]$AgentManifestVersion -eq [string]$AgentCodeVersion)
        codeSha256          = $AgentCodeSha256
        scriptPath          = $AgentScriptPath
        pid                 = $PID
        processStartUtc     = $AgentProcessStartUtc.ToString("yyyy-MM-ddTHH:mm:ssZ")
    }
    try {
        $cur = Join-Path $BaseDir "current"
        $it = Get-Item -LiteralPath $cur -Force -ErrorAction Stop
        $isLink = (($it.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0)
        $i["currentIsLink"] = $isLink
        if ($isLink) { try { $i["currentLinkTarget"] = (@($it.Target) -join ";") } catch { $i["currentLinkTarget"] = "unreadable" } }
    } catch { $i["currentError"] = $_.Exception.Message }
    try {
        $rel = Join-Path $BaseDir "releases"
        if (Test-Path -LiteralPath $rel) { $i["releases"] = @(Get-ChildItem -LiteralPath $rel -Directory -ErrorAction Stop | Sort-Object Name | Select-Object -Last 12 | ForEach-Object { $_.Name }) }
    } catch { }
    try {
        $snapPath = Join-Path $BaseDir "rollback\snapshot.json"
        if (Test-Path -LiteralPath $snapPath) {
            $snap = [IO.File]::ReadAllText($snapPath) | ConvertFrom-Json
            $i["rollbackSnapshot"] = [ordered]@{
                takenUtc        = $snap.takenUtc
                agentSha256     = $snap.agentSha256
                manifestVersion = $snap.manifestVersion
                forInstall      = $snap.forVersion
            }
        } else { $i["rollbackSnapshot"] = $null }
    } catch { $i["rollbackSnapshot"] = [ordered]@{ unreadable = $_.Exception.Message } }
    $i["updateGuard"] = (Get-StateJsonSummary "update-guard.json")
    return $i
}

function Get-LocalConfigFacts {
    # The effective settings this process runs with, as an ALLOWLIST (no credential, id, secret or path to one).
    # $cfg is what this process loaded at start, after the platform overlay (Apply-EffectiveConfigToRuntime);
    # selfHeal is read from the LOCAL file only, exactly as Read-SelfHealSettings decides it.
    $f = [ordered]@{ source = "effective: agent-config.json read at start plus the platform overlay; selfHeal from the local file" }
    try {
        $fi = Get-Item -LiteralPath $CfgPath -ErrorAction Stop
        $f["fileUtc"] = $fi.LastWriteTimeUtc.ToString("yyyy-MM-ddTHH:mm:ssZ")
        $f["fileBytes"] = [int64]$fi.Length
        $f["fileChangedSinceStart"] = ($fi.LastWriteTimeUtc -gt $AgentProcessStartUtc)
    } catch { $f["fileError"] = $_.Exception.Message }

    $sh = [ordered]@{}
    try {
        $run = Get-Variable -Name SelfHealSettings -Scope Script -ValueOnly -ErrorAction SilentlyContinue
        if ($null -ne $run) { $sh["running"] = [ordered]@{ enabled = [bool]$run.Enabled; watchdog = [bool]$run.WatchdogEnabled; health = [bool]$run.HealthEnabled } }
        else { $sh["running"] = $null }
    } catch { $sh["runningError"] = $_.Exception.Message }
    try {
        $now = Read-SelfHealSettings -Path $CfgPath
        $sh["file"] = [ordered]@{ enabled = [bool]$now.Enabled; watchdog = [bool]$now.WatchdogEnabled; health = [bool]$now.HealthEnabled; configErrors = @($now.Errors).Count }
    } catch { $sh["fileError"] = $_.Exception.Message }
    $f["selfHeal"] = $sh

    try {
        $dr = Get-DisplayRoutingConfigFromPayloadOrConfig $null
        $en = $true
        $ev = Get-PropValue $dr "enabled" $null
        if ($null -ne $ev) { $en = [bool]$ev }
        $roleSel = [ordered]@{}
        $rolesObj = Get-PropValue $dr "roles" $null
        foreach ($rn in @("play", "control", "session")) {
            $ro = Get-PropValue $rolesObj $rn $null
            $sel = Get-PropValue $ro "selector" $null
            if ($null -eq $sel) { $sel = Get-PropValue $ro "deviceName" $null }
            if ($null -eq $sel) { $sel = Get-PropValue $ro "index" $null }
            $roleSel[$rn] = $(if ($null -ne $sel) { [string]$sel } else { $null })
        }
        $f["displayRouting"] = [ordered]@{ configured = ($null -ne $dr); enabled = $en; roleSelectors = $roleSel }
    } catch { $f["displayRouting"] = [ordered]@{ error = $_.Exception.Message } }

    try {
        $lc = Get-LauncherConfigFromPayloadOrConfig $null
        $lp = [string](Get-PropValue $lc "path" "")
        $cl = $null; try { $cl = $cfg.launcher } catch { }
        $f["launcher"] = [ordered]@{
            path                 = $lp
            pathExists           = ((-not [string]::IsNullOrWhiteSpace($lp)) -and (Test-Path -LiteralPath $lp))
            processName          = (Get-PropValue $lc "processName" $null)
            configuredDisplayRole = (Get-PropValue $cl "displayRole" $null)
            startOnPrep          = (Get-PropValue $lc "startOnPrep" $null)
            startOnStart         = (Get-PropValue $lc "startOnStart" $null)
        }
    } catch { $f["launcher"] = [ordered]@{ error = $_.Exception.Message } }

    try {
        $sd = $null; try { if ($cfg.PSObject.Properties.Name -contains "sessionDisplay") { $sd = $cfg.sessionDisplay } } catch { }
        $f["sessionDisplay"] = [ordered]@{
            enabled     = (Get-PropValue $sd "enabled" $true)
            mode        = (Get-PropValue $sd "mode" $null)
            displayRole = (Get-PropValue $sd "displayRole" $null)
            url         = (Get-PropValue $sd "url" $null)
        }
    } catch { $f["sessionDisplay"] = [ordered]@{ error = $_.Exception.Message } }

    try {
        $fac = $null; try { $fac = $cfg.facility } catch { }
        $f["facility"] = [ordered]@{ enabled = (Get-PropValue $fac "enabled" $null); simulated = (Get-PropValue $fac "simulated" $null) }
    } catch { }

    $f["pollSeconds"] = $PollSec
    $f["heartbeatSeconds"] = $HeartbeatSec
    $f["logLevel"] = $Global:LogLevel
    $f["resultJsonMaxChars"] = $ResultJsonMaxChars
    return $f
}

function Get-HealthCheckFacts {
    # Small enough for build_resultjson (2000 chars) next to the original HealthCheck fields.
    $h = [ordered]@{
        manifestVersion = $AgentManifestVersion
        codeSha256      = $AgentCodeSha256
    }
    try {
        $run = Get-Variable -Name SelfHealSettings -Scope Script -ValueOnly -ErrorAction SilentlyContinue
        $h["selfHealRunning"] = $(if ($null -ne $run) { [bool]$run.Enabled } else { $null })
    } catch { $h["selfHealRunning"] = $null }
    try {
        $it = Get-Item -LiteralPath (Join-Path $BaseDir "current") -Force -ErrorAction Stop
        $h["currentIsLink"] = (($it.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0)
    } catch { $h["currentIsLink"] = $null }
    try {
        $g = Get-StateJsonSummary "update-guard.json" 1500
        if ($null -ne $g) { $h["updateGuard"] = [ordered]@{ state = (Get-PropValue $g "state" $null); version = (Get-PropValue $g "version" $null); utc = (Get-PropValue $g "utc" $null) } }
    } catch { }
    try {
        $u = Read-LastUpdateResult
        if ($null -ne $u) { $h["lastUpdate"] = [ordered]@{ ok = (Get-PropValue $u "ok" $null); version = (Get-PropValue $u "version" $null); stage = (Get-PropValue $u "stage" $null); utc = (Get-PropValue $u "utc" $null) } }
    } catch { }
    return $h
}

function Get-CompactWindowSummary {
    # One line per managed window for a command result: device it is on, whether that is the expected one.
    $out = @()
    foreach ($w in @(Get-ManagedWindowReport)) {
        $first = $null
        if ($w.Contains("windows") -and @($w["windows"]).Count -gt 0) { $first = @($w["windows"])[0] }
        $out += [ordered]@{
            name       = $w["name"]
            running    = $(if ($w.Contains("running")) { $w["running"] } else { $null })
            expected   = $(if ($w.Contains("expectedDevice")) { $w["expectedDevice"] } else { $null })
            device     = $(if ($null -ne $first) { $first["device"] } else { $null })
            onExpected = $(if ($w.Contains("onExpected")) { $w["onExpected"] } else { $null })
            maximized  = $(if ($null -ne $first) { $first["maximized"] } else { $null })
            covers     = $(if ($null -ne $first) { $first["coversMonitor"] } else { $null })
            error      = $(if ($w.Contains("error")) { $w["error"] } else { $null })
        }
    }
    return $out
}

function Request-CapabilitiesRefresh {
    # Make the next main-loop pass send the full capabilities document (seconds, not the 10-minute cadence).
    # Rate-limited so a burst of commands cannot turn into a burst of 30 KB PATCHes.
    $now = (Get-Date).ToUniversalTime()
    $last = Get-Variable -Name CapabilitiesRefreshRequestedUtc -Scope Global -ValueOnly -ErrorAction SilentlyContinue
    if ($last -is [DateTime] -and ($now - $last).TotalSeconds -lt 30) { return $false }
    $Global:CapabilitiesRefreshRequestedUtc = $now
    $Global:NextCapabilitiesUtc = $now
    $Global:NextHeartbeatUtc = [DateTime]::MinValue
    return $true
}

# ---------------- Alive record for the update rollback guard (1.3.1, A0.437) ----------------
# tools\Watch-BayAgentUpdate.ps1 decides whether a newly installed agent "came back" from this file alone: the SHA256
# of the script this process runs, and the first and last time in this process that BOTH a heartbeat PATCH and a
# command poll succeeded. Both, because a bay that polls but cannot heartbeat looks offline to every operator, and a
# heartbeat alone does not prove commands can run. Written at most every 30 s; never throws.
$Global:AliveHeartbeatOk = $false
$Global:AliveRecord = $null
$Global:AliveLastWriteUtc = [DateTime]::MinValue
$Global:AliveWriteWarned = $false

function Update-AgentAliveRecord {
    param([Parameter(Mandatory=$true)][DateTime]$Now)
    try {
        if (-not $Global:AliveHeartbeatOk) { return }
        if ([string]::IsNullOrWhiteSpace([string]$AgentCodeSha256)) { return }
        $nowStr = $Now.ToString("yyyy-MM-ddTHH:mm:ssZ")
        if ($null -eq $Global:AliveRecord) {
            $Global:AliveRecord = [ordered]@{
                codeSha256      = $AgentCodeSha256
                codeVersion     = $AgentCodeVersion
                pid             = $PID
                processStartUtc = $AgentProcessStartUtc.ToString("yyyy-MM-ddTHH:mm:ssZ")
                firstOkUtc      = $nowStr
                lastOkUtc       = $nowStr
                writes          = 0
            }
        } else {
            if (($Now - $Global:AliveLastWriteUtc).TotalSeconds -lt 30) { return }
            $Global:AliveRecord["lastOkUtc"] = $nowStr
        }
        $Global:AliveRecord["writes"] = [int]$Global:AliveRecord["writes"] + 1
        $dir = Join-Path $BaseDir "state"
        if (-not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Force -Path $dir | Out-Null }
        Write-JsonAtomic -path (Join-Path $dir "agent-alive.json") -obj $Global:AliveRecord
        $Global:AliveLastWriteUtc = $Now
    } catch {
        if (-not $Global:AliveWriteWarned) {
            $Global:AliveWriteWarned = $true
            try { Write-Log ("Alive record could not be written (an update guard cannot confirm this agent): {0}" -f $_.Exception.Message) "WARN" } catch { }
        }
    }
}

function Build-AgentCapabilitiesJson {
    param(
        [Parameter(Mandatory=$true)][hashtable]$eff
    )

    # NOTE: Do NOT rely on $script:* vars here. This agent keeps runtime config in $cfg (agent-config.json),
    # and Step 8.2 overlays also populate $eff (BayProfile + ConfigItems). Use both safely.

    # Launcher
    $launcherPath = Get-EffectiveConfigValue $eff "Bay.Launcher.Path" $null
    if (-not $launcherPath -and $cfg -and $cfg.launcher) { $launcherPath = $cfg.launcher.path }

    $launcherProc = Get-EffectiveConfigValue $eff "Bay.Launcher.ProcessName" $null
    if (-not $launcherProc -and $cfg -and $cfg.launcher) { $launcherProc = $cfg.launcher.processName }

    # Session display
    $sessionJson = Get-EffectiveConfigValue $eff "Bay.SessionDisplay.SessionJsonPath" $null
    if (-not $sessionJson -and $cfg) { $sessionJson = $cfg.sessionJsonPath }

    $mode = Get-EffectiveConfigValue $eff "Bay.SessionDisplay.Mode" $null
    if (-not $mode -and $cfg -and $cfg.sessionDisplay) { $mode = $cfg.sessionDisplay.mode }

    $cap = [ordered]@{
        agentVersion    = $AgentVersion
        machineName     = $env:COMPUTERNAME
        lastUpdatedUtc  = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")

        launcher = @{
            path        = $launcherPath
            processName = $launcherProc
            pathExists  = ([string]::IsNullOrWhiteSpace([string]$launcherPath) -eq $false -and (Test-Path -LiteralPath $launcherPath))
        }

        sessionDisplay = @{
            mode            = $mode
            sessionJsonPath = $sessionJson
            jsonPathExists  = ([string]::IsNullOrWhiteSpace([string]$sessionJson) -eq $false -and (Test-Path -LiteralPath $sessionJson))
        }

        # Credential health (no secrets, no keys): which credential is configured, which one actually minted
        # the last token, when the active certificate expires. Read by operators and the expiry monitor.
        credential = (Get-CredentialTelemetry)

        # The emergency-stop latch, so the platform can see an engaged stop (and one restored after a restart).
        # persisted=false means the last save did not read back; the latch itself is still held in memory.
        emergencyStop = (Get-EmergencyStopCapability)

        # The durable outcome of the last fleet update. StartProcess reports Succeeded when the updater
        # LAUNCHES, so this is the only signal that says whether it then installed anything.
        lastUpdateResult = (Read-LastUpdateResult)

        # Keep this conservative; expand as you add commands.
        supportedCommandTypes = @(
            "HealthCheck",
            "StartSession",
            "EndSession",
            "CredentialRotate"
        )

        # 1.3.1 (A0.437): the facts a remote operator needs to install and prove an update with nobody on site.
        # manifestVersion next to agentVersion (the code's own constant) makes a stale manifest copy visible.
        manifestVersion = $AgentManifestVersion
        install         = (Invoke-ReportPart { Get-AgentInstallFacts })
        localConfig     = (Invoke-ReportPart { Get-LocalConfigFacts })
        display         = (Invoke-ReportPart { Get-DisplayReport })

        # 1.4.0 (A0.363): the kiosk shell's mode, file, liveness and intent, and BayKiosk's Winlogon Shell (read only).
        kiosk           = (Invoke-ReportPart { Get-KioskCapability })
        # A0.456: the wall pass's state (its expiry and the last fetch's result; never the pass itself).
        displayPass     = (Invoke-ReportPart { Get-DisplayPassTelemetry })
    }

    # The column holds 30000 characters (measured in Dev, 2026-10-07). Drop the bulkiest optional parts first, and
    # say so, rather than let the whole heartbeat PATCH fail.
    $json = ($cap | ConvertTo-Json -Depth 12 -Compress)
    $limit = 29000
    if ($json.Length -gt $limit) {
        $d = $cap["display"]
        $cap["display"] = [ordered]@{ trimmed = "display report too large for the column"; roles = $(if ($d -is [System.Collections.IDictionary] -and $d.Contains("roles")) { $d["roles"] } else { $null }) }
        $json = ($cap | ConvertTo-Json -Depth 12 -Compress)
    }
    if ($json.Length -gt $limit) {
        $cap["localConfig"] = [ordered]@{ trimmed = "too large for the column" }
        $cap["install"] = [ordered]@{ trimmed = "too large for the column"; codeVersion = $AgentCodeVersion; codeSha256 = $AgentCodeSha256 }
        $json = ($cap | ConvertTo-Json -Depth 12 -Compress)
    }
    return $json
}

# ---------------- Heartbeat (periodic) ----------------
$Global:NextHeartbeatUtc = [DateTime]::MinValue

function Send-HeartbeatIfDue {
    param(
        [Parameter(Mandatory=$true)][string]$token
    )

    $now = (Get-Date).ToUniversalTime()
    if ($now -lt $Global:NextHeartbeatUtc) { return }

    $nowUtcStr = $now.ToString("yyyy-MM-ddTHH:mm:ssZ")

    try {
        $patch = @{
            $Col_Heartbeat = $nowUtcStr
            $Col_Machine   = $env:COMPUTERNAME
            $Col_Version   = $AgentVersion
        }

        # Capabilities write-back (every N seconds)
        if ($now -ge $Global:NextCapabilitiesUtc) {
            try {
                $capJson = Build-AgentCapabilitiesJson -eff $(if ($Global:EffectiveConfig) { $Global:EffectiveConfig } else { @{} })
                $patch["build_agentcapabilitiesjson"] = $capJson

                # schedule next capabilities write
                $Global:NextCapabilitiesUtc = $now.AddSeconds($Global:CapabilitiesEverySeconds)

                if ($Global:LogLevel -eq "DEBUG") {
                    Write-Log ("Capabilities updated (next in {0}s)" -f $Global:CapabilitiesEverySeconds) "DEBUG"
                }
            }
            catch {
                # Never let capabilities block heartbeat; just retry soon
                Write-Log ("Capabilities update failed: {0}" -f $_.Exception.Message) "WARN"
                $Global:NextCapabilitiesUtc = $now.AddSeconds(30)
                # The emergency-stop state must still reach the platform when the full capabilities cannot be built
                # (a missing config section is enough): send the small document that carries it.
                try {
                    $patch["build_agentcapabilitiesjson"] = (ConvertTo-Json -Compress -Depth 4 -InputObject ([ordered]@{
                        agentVersion = $AgentVersion; lastUpdatedUtc = $nowUtcStr; partial = $true; emergencyStop = (Get-EmergencyStopCapability)
                        manifestVersion = $AgentManifestVersion; codeSha256 = $AgentCodeSha256; lastUpdateResult = (Read-LastUpdateResult) }))
                } catch { }
            }
        }

        Patch-Row $token "${BayEntitySet}" $BayId $patch "*"
        # A heartbeat the platform accepted: one half of what the update rollback guard needs (Update-AgentAliveRecord).
        $Global:AliveHeartbeatOk = $true

        $Global:NextHeartbeatUtc = $now.AddSeconds($HeartbeatSec)
        Write-Log "Heartbeat updated ($nowUtcStr)" "DEBUG"
    }
    catch {
        # Don't crash the agent for heartbeat failures; just retry soon
        Write-Log "Heartbeat update failed: $($_.Exception.Message)" "WARN"
        $Global:NextHeartbeatUtc = $now.AddSeconds([Math]::Min($HeartbeatSec, 30))
    }
}


# ---------------- Step 8.3: Mode enforcement (Offline / Maintenance) ----------------
function Get-AgentOperationalState {
    param([Parameter(Mandatory=$true)][hashtable]$eff)

    $status = $AGENTSTATUS_ONLINE
    try { $status = [int](Get-EffectiveConfigValue $eff "Bay.AgentStatus" $AGENTSTATUS_ONLINE) } catch {}

    $reason = ""
    try { $reason = [string](Get-EffectiveConfigValue $eff "Bay.AgentStatusReason" "") } catch {}

    $untilRaw = $null
    try { $untilRaw = Get-EffectiveConfigValue $eff "Bay.AgentStatusUntil" $null } catch {}

    $untilUtc = $null
    if (-not [string]::IsNullOrWhiteSpace([string]$untilRaw)) {
        try { $untilUtc = [DateTime]::Parse([string]$untilRaw).ToUniversalTime() } catch {}
    }

    $now = (Get-Date).ToUniversalTime()
    $expired = ($untilUtc -ne $null -and $untilUtc -le $now)

    $modeLabel = switch ($status) {
        $AGENTSTATUS_OFFLINE     { "Offline" }
        $AGENTSTATUS_MAINTENANCE { "Maintenance" }
        $AGENTSTATUS_DEGRADED    { "Degraded" }
        default                  { "Online" }
    }

    $blocked = ($status -eq $AGENTSTATUS_OFFLINE -or $status -eq $AGENTSTATUS_MAINTENANCE)

    # If a temporary block has expired, treat as unblocked (and we'll auto-clear the fields below)
    if ($blocked -and $expired) { $blocked = $false }

    $blockReason = ""
    if ($status -eq $AGENTSTATUS_OFFLINE -or $status -eq $AGENTSTATUS_MAINTENANCE) {
        $blockReason = ("Bay is in {0} mode{1}" -f $modeLabel, ($(if (-not [string]::IsNullOrWhiteSpace($reason)) { ": $reason" } else { "" })))
        if ($untilUtc -ne $null) { $blockReason += (" (until {0}Z)" -f $untilUtc.ToString("yyyy-MM-ddTHH:mm:ss")) }
    }

    return [pscustomobject]@{
        Status      = $status
        ModeLabel   = $modeLabel
        Blocked     = $blocked
        Expired     = $expired
        UntilUtc    = $untilUtc
        Reason      = $reason
        BlockReason = $blockReason
    }
}

function Is-CommandAllowedInMode {
    param(
        [Parameter(Mandatory=$true)][int]$CommandType,
        [Parameter(Mandatory=$true)]$OpState
    )

    if (-not $OpState -or -not $OpState.Blocked) { return $true }

    # OFFLINE: allow only safe "read-only / diagnostics" style commands
    if ($OpState.Status -eq $AGENTSTATUS_OFFLINE) {
        return (
            $CommandType -eq $CMD_HEALTHCHECK -or
            $CommandType -eq $CMD_SHOWMESSAGE -or
            $CommandType -eq $CMD_QUERYPROCESS -or
            $CommandType -eq $CMD_DISPLAY_TOPOLOGY -or
            $CommandType -eq $CMD_CREDENTIAL_ROTATE
        )
    }

    # MAINTENANCE: allow operator controls, but block customer session starts
    if ($OpState.Status -eq $AGENTSTATUS_MAINTENANCE) {
        return ($CommandType -ne $CMD_STARTSESSION)
    }

    return $true
}

function AutoClear-ExpiredAgentStatusIfDue {
    param([Parameter(Mandatory=$true)][string]$token)

    if (-not $Global:EffectiveConfig) { return }

    $op = Get-AgentOperationalState -eff $Global:EffectiveConfig
    if (-not $op.Expired) { return }

    # Only auto-clear if we were in a blocking mode and the Until has elapsed
    if ($op.Status -ne $AGENTSTATUS_OFFLINE -and $op.Status -ne $AGENTSTATUS_MAINTENANCE) { return }

    try {
        Patch-Row $token "${BayEntitySet}" $BayId @{
            $Col_AgentStatus       = $AGENTSTATUS_ONLINE
            $Col_AgentStatusUntil  = $null
            $Col_AgentStatusReason = $null
        } "*"

        Write-Log ("AgentStatusUntil expired; auto-cleared {0} -> Online" -f $op.ModeLabel) "INFO"

        # Force a config refresh next loop so EffectiveConfig reflects the cleared status
        $Global:NextConfigRefreshUtc = (Get-Date).ToUniversalTime()
    }
    catch {
        Write-Log ("Failed to auto-clear expired AgentStatus: {0}" -f $_.Exception.Message) "WARN"
    }
}

# ---------------- Command polling ----------------
function Get-NextPendingCommand {
    param([Parameter(Mandatory=$true)][string]$token)

    $nowUtc = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
    $selectClause = "$Col_CommandId,$Col_Status,$Col_CommandType,$Col_Payload,$Col_AttemptCount,$Col_NotBefore,createdon,$Lookup_BayValue,$Lookup_BaySessionValue"

    $filterClause = "$Lookup_BayValue eq $BayId and $Col_Status eq $STATUS_PENDING and ($Col_NotBefore eq null or $Col_NotBefore le $nowUtc)"

    $uri = "$OrgUrl/api/data/v9.2/${BayCommandEntitySet}?`$select=$selectClause&`$filter=$([uri]::EscapeDataString($filterClause))&`$orderby=createdon asc&`$top=1"
    $res = Invoke-DvSafe -Method GET -Uri $uri -Headers (New-DvHeaders $token)
    if ($res.value -and $res.value.Count -gt 0) { return $res.value[0] }
    return $null
}

# ---------------- Command execution ----------------
function Try-ParseJson([string]$jsonText) {
    if ([string]::IsNullOrWhiteSpace($jsonText)) { return $null }
    try { return ($jsonText | ConvertFrom-Json) } catch { return $null }
}

# Get-PropValue used to be defined here. It is now defined with the other generic helpers, above the
# credential section, because script-level startup code reaches it. See the comment at its definition.

function Set-PropValue {
    param(
        [Parameter(Mandatory=$true)]$obj,
        [Parameter(Mandatory=$true)][string]$name,
        $value,
        [switch]$OnlyIfMissing
    )
    if ($null -eq $obj) { return }

    $existing = Get-PropValue $obj $name $null
    if ($OnlyIfMissing -and $null -ne $existing -and -not [string]::IsNullOrWhiteSpace([string]$existing)) { return }

    if ($obj -is [System.Collections.IDictionary]) {
        # Hashtable/dictionary
        $obj[$name] = $value
        return
    }

    # PSObject: update if exists, else add
    try {
        foreach ($p in $obj.PSObject.Properties) {
            if ($p.Name -ieq $name) {
                $p.Value = $value
                return
            }
        }
        $obj | Add-Member -NotePropertyName $name -NotePropertyValue $value -Force
    } catch {
        # no-op
    }
}

function Get-BayLabelFromCommandRow {
    param([Parameter(Mandatory=$true)]$cmdRow)

    # Dataverse lookup formatted value is typically:
    #   _build_bay_value@OData.Community.Display.V1.FormattedValue : "Bay_1"
    $fmtProp = "$Lookup_BayValue@OData.Community.Display.V1.FormattedValue"
    $label = Get-PropValue $cmdRow $fmtProp $null

    if ([string]::IsNullOrWhiteSpace([string]$label)) {
        # Sometimes clients use build_bay@... formatted value (less common for lookups)
        $altProp = "$Lookup_Bay@OData.Community.Display.V1.FormattedValue"
        $label = Get-PropValue $cmdRow $altProp $null
    }

    if ([string]::IsNullOrWhiteSpace([string]$label)) {
        # Fallback to config-defined label (if any) or "Bay"
        return (Get-BayLabel)
    }
    return $label.ToString()
}


function Get-DefaultEdgePath {
    $candidates = @(
        "C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
        "C:\Program Files\Microsoft\Edge\Application\msedge.exe"
    )
    foreach ($p in $candidates) { if (Test-Path $p) { return $p } }
    return "msedge.exe"
}

function Get-SessionJsonPath {
    $p = $null
    try {
        if ($cfg.PSObject.Properties.Name -contains "sessionJsonPath") { $p = $cfg.sessionJsonPath }
    } catch {}
    if ([string]::IsNullOrWhiteSpace([string]$p)) { $p = "C:\AllBirdies\SessionDisplay\data\session.json" }
    return $p
}


function Write-TextAtomic([string]$path, [string]$text) {
    $dir = Split-Path -Parent $path
    if (!(Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }

    $tmp = "$path.tmp"
    Set-Content -Path $tmp -Value $text -Encoding UTF8

    try {
        if (Test-Path $path) {
            # Atomic replace when the destination exists. [NullString]::Value, not $null (1.3.1): $null reaches File.Replace
            # as "" and it threw on every call, so this always took the non-atomic fallback below.
            [System.IO.File]::Replace($tmp, $path, [NullString]::Value, $true)
        } else {
            Move-Item -Path $tmp -Destination $path -Force
        }
    } catch {
        # Fallback: best-effort overwrite
        if (Test-Path $path) { Remove-Item $path -Force }
        Move-Item -Path $tmp -Destination $path -Force
    }
}

function Write-JsonAtomic([string]$path, $obj) {
    $json = ($obj | ConvertTo-Json -Depth 10)
    Write-TextAtomic -path $path -text $json
}

function Get-SessionJsPath {
    $jsonPath = Get-SessionJsonPath
    # Same folder, different extension
    return ([System.IO.Path]::ChangeExtension($jsonPath, "js"))
}

function Set-EmergencyStopBanner($modelObj) {
    # While the emergency stop is engaged the display must keep saying so. Every writer of the session files
    # (UpdateSessionDisplay, EndSession, Reset, ...) goes through Write-SessionFiles, so the banner is forced here,
    # at the one place nothing can bypass, and never anywhere that could clear the latch.
    if (-not $Global:EmergencyStopEngaged) { return $modelObj }
    $ht = To-Hashtable $modelObj
    $out = @{}
    foreach ($k in @($ht.Keys)) { $out[$k] = $ht[$k] }
    $out.bannerText = "EMERGENCY STOP"
    $out.statusDetail = [string]$Global:EmergencyStopReason
    $out.status = "STOP"
    return $out
}

function Set-AgentRunningStamp($modelObj) {
    # Kiosk round 2 (F1-R1, RV2): every wall write carries WHO THIS AGENT SAYS IS PLAYING (its in-memory running-session
    # record, the authority) in the same atomic write as the wall's status, so the two can never disagree on disk. The
    # stamp echoes the status and session id it was written with: a later writer that merges the old model forward (an
    # older agent after a rollback) leaves a stamp that no longer matches, and the shell then reads "cannot tell". The
    # shell closes a relaunched launcher on READY or PREP only when this stamp says, for that very write, that nobody
    # plays; the agent reads it back at start (the newer of it and state\running-session.json wins). Never throws: on any
    # failure the stamp is dropped (the shell holds, the start-up read falls back).
    $ht = To-Hashtable $modelObj
    $out = @{}
    foreach ($k in @($ht.Keys)) { if ($k -ne "agentRunning") { $out[$k] = $ht[$k] } }
    try {
        $r = $Global:RunningSession
        $st = Get-PropValue $out "status" ""
        $fs = Get-PropValue $out "baySessionId" ""
        $out.agentRunning = [ordered]@{
            schema       = 1
            running      = ($null -ne $r)
            baySessionId = $(if ($null -ne $r) { [string](Get-KioskProp $r "baySessionId" "") } else { "" })
            endUtc       = $(if ($null -ne $r) { Get-KioskProp $r "endUtc" $null } else { $null })
            since        = $(if ($null -ne $r) { Get-KioskProp $r "since" $null } else { $null })
            cancelEndUtc = $(if ($null -ne $r) { Get-KioskProp $r "cancelEndUtc" $null } else { $null })
            status       = $(if ($null -ne $st) { [string]$st } else { "" })
            forSessionId = $(if ($null -ne $fs) { [string]$fs } else { "" })
            writtenUtc   = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
        }
    } catch { $out.Remove("agentRunning") }
    return $out
}

function Write-SessionFiles($modelObj) {
    $modelObj = Set-EmergencyStopBanner $modelObj
    $modelObj = Set-AgentRunningStamp $modelObj
    $jsonPath = Get-SessionJsonPath
    $jsPath   = Get-SessionJsPath

    # 1) Write JSON (for debugging / inspection)
    Write-JsonAtomic -path $jsonPath -obj $modelObj

    # 2) Write JS (avoids file:// fetch restrictions in some Edge/Chromium modes)
    $jsonCompact = ($modelObj | ConvertTo-Json -Depth 10 -Compress)
    $js = "window.ABG_SESSION = $jsonCompact;"
    Write-TextAtomic -path $jsPath -text $js

    return @{ sessionJsonPath = $jsonPath; sessionJsPath = $jsPath }
}


# ---------------- Session lifecycle helpers (Step 3) ----------------
function Get-BayLabel {
    try {
        if ($cfg.PSObject.Properties.Name -contains "bayLabel" -and -not [string]::IsNullOrWhiteSpace([string]$cfg.bayLabel)) {
            return $cfg.bayLabel.ToString()
        }
    } catch {}
    return "Bay"
}

function Get-HelpText {
    try {
        if ($cfg.PSObject.Properties.Name -contains "helpText" -and -not [string]::IsNullOrWhiteSpace([string]$cfg.helpText)) {
            return $cfg.helpText.ToString()
        }
    } catch {}
    return "Need help? Text us."
}

function Read-SessionModelFromDisk {
    # Reads the last written session model from session.json (preferred).
    $jsonPath = Get-SessionJsonPath
    if (Test-Path $jsonPath) {
        try {
            $raw = Get-Content -Path $jsonPath -Raw -Encoding UTF8
            if (-not [string]::IsNullOrWhiteSpace($raw)) {
                return ($raw | ConvertFrom-Json)
            }
        } catch {}
    }
    return $null
}

function To-Hashtable($obj) {
    if ($null -eq $obj) { return @{} }
    if ($obj -is [hashtable]) { return $obj }

    $ht = @{}
    try {
        foreach ($p in $obj.PSObject.Properties) {
            $ht[$p.Name] = $p.Value
        }
    } catch {}
    return $ht
}

function Merge-Hashtables([hashtable]$base, [hashtable]$patch) {
    $out = @{}
    foreach ($k in $base.Keys) { $out[$k] = $base[$k] }
    foreach ($k in $patch.Keys) { $out[$k] = $patch[$k] }
    return $out
}


function Normalize-SessionModel([hashtable]$model) {
    # Normalizes common fields so the Session Display and promo targeting are consistent:
    # - Keeps displayName/customerDisplayName/customer.displayName aligned
    # - Prefers bayLabel for display, falling back to locationLabel/config
    # - Ensures timing.startUtc/timing.endUtc matches sessionStartUtc/sessionEndUtc
    if ($null -eq $model) { return $model }

    # Bay label normalization
    $bayLabel = Get-PropValue $model "bayLabel" $null
    $locLabel = Get-PropValue $model "locationLabel" $null
    if (-not [string]::IsNullOrWhiteSpace([string]$bayLabel)) {
        if ([string]::IsNullOrWhiteSpace([string]$locLabel) -or $locLabel -eq "Bay") {
            $model.locationLabel = $bayLabel
        }
    }

    # Name normalization (prefer customerDisplayName, then displayName, then customer.displayName)
    $custObj = Get-PropValue $model "customer" $null
    $custHt = $null
    if ($null -ne $custObj) {
        try { $custHt = To-Hashtable $custObj } catch { $custHt = $null }
    }

    $name = Get-PropValue $model "customerDisplayName" $null
    if ([string]::IsNullOrWhiteSpace([string]$name)) { $name = Get-PropValue $model "displayName" $null }
    if ([string]::IsNullOrWhiteSpace([string]$name) -and $null -ne $custHt) { $name = Get-PropValue $custHt "displayName" $null }
    if ([string]::IsNullOrWhiteSpace([string]$name)) { $name = "Guest" }
    $model.displayName = $name
    $model.customerDisplayName = $name

    if ($null -eq $custHt) { $custHt = @{} }
    # Keep customer.displayName aligned with displayName/customerDisplayName (display UI prefers this field).
    $custHt.displayName = $name
    $model.customer = $custHt

    # Timing normalization
    $s = Get-PropValue $model "sessionStartUtc" $null
    if ([string]::IsNullOrWhiteSpace([string]$s)) { $s = Get-PropValue $model "startUtc" $null }
    $e = Get-PropValue $model "sessionEndUtc" $null
    # Prefer playEndUtc (customer-visible play end) when present
    if ([string]::IsNullOrWhiteSpace([string]$e)) { $e = Get-PropValue $model "playEndUtc" $null }
    if ([string]::IsNullOrWhiteSpace([string]$e)) { $e = Get-PropValue $model "endUtc" $null }

    $timingObj = Get-PropValue $model "timing" $null
    $timingHt = $null
    if ($null -ne $timingObj) {
        try { $timingHt = To-Hashtable $timingObj } catch { $timingHt = $null }
    }
    if ($null -eq $timingHt) { $timingHt = @{} }
    if (-not [string]::IsNullOrWhiteSpace([string]$s)) { $timingHt.startUtc = $s.ToString() }
    if (-not [string]::IsNullOrWhiteSpace([string]$e)) { $timingHt.endUtc = $e.ToString() }
    $model.timing = $timingHt

    # Schema + updatedUtc
    if ([string]::IsNullOrWhiteSpace([string](Get-PropValue $model "schema" $null))) { $model.schema = "abg.session.v1" }
    if ([string]::IsNullOrWhiteSpace([string](Get-PropValue $model "updatedUtc" $null))) { $model.updatedUtc = (UtcNow-Z) }

    return $model
}

function UtcNow-Z {
    return (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
}

function Build-SessionDisplayPatchFromPayload($payloadObj) {
    # Accepts either:
    #  1) A "mode-based" session payload (Prep/Start/Warn5/End) from Power Automate
    #  2) A full display model (status/sessionEndUtc/etc.)
    #
    # Returns a hashtable patch that can be merged with the previous model.
    $p = $payloadObj

    $mode = Get-PropValue $p "mode" $null
    if (-not [string]::IsNullOrWhiteSpace([string]$mode)) { $mode = $mode.ToString() }

    $status = Get-PropValue $p "status" $null
    if ([string]::IsNullOrWhiteSpace([string]$status) -and -not [string]::IsNullOrWhiteSpace([string]$mode)) {
        switch ($mode.ToLowerInvariant()) {
            "prep"  { $status = "PREP" }
            "start" { $status = "ACTIVE" }
            "warn5" { $status = "ENDING" }
            "end"   { $status = "ENDED" }
            default { $status = $null }
        }
    }

    # Primary fields (support both naming conventions)
    $displayName = Get-PropValue $p "displayName" $null
    if ([string]::IsNullOrWhiteSpace([string]$displayName)) { $displayName = Get-PropValue $p "customerDisplayName" $null }
    if ([string]::IsNullOrWhiteSpace([string]$displayName)) { $displayName = "Guest" }

$locationLabel = Get-PropValue $p "locationLabel" $null
if ([string]::IsNullOrWhiteSpace([string]$locationLabel)) { $locationLabel = Get-PropValue $p "bayLabel" $null }
if ([string]::IsNullOrWhiteSpace([string]$locationLabel)) { $locationLabel = Get-BayLabel }

$bayLabel = Get-PropValue $p "bayLabel" $null
$bayId = Get-PropValue $p "bayId" $null

    $helpText = Get-PropValue $p "helpText" $null
    if ([string]::IsNullOrWhiteSpace([string]$helpText)) { $helpText = Get-HelpText }

    # Times: allow either sessionStartUtc/sessionEndUtc OR startUtc/endUtc
    $startUtc = Get-PropValue $p "sessionStartUtc" $null
    if ([string]::IsNullOrWhiteSpace([string]$startUtc)) { $startUtc = Get-PropValue $p "startUtc" $null }

    $endUtc = Get-PropValue $p "sessionEndUtc" $null
    # Prefer playEndUtc (customer-visible play end) when present
    if ([string]::IsNullOrWhiteSpace([string]$endUtc)) { $endUtc = Get-PropValue $p "playEndUtc" $null }
    if ([string]::IsNullOrWhiteSpace([string]$endUtc)) { $endUtc = Get-PropValue $p "endUtc" $null }

    # Banner/message
    $bannerText = Get-PropValue $p "bannerText" $null
    if ([string]::IsNullOrWhiteSpace([string]$bannerText)) { $bannerText = Get-PropValue $p "message" $null }

    if ([string]::IsNullOrWhiteSpace([string]$bannerText) -and -not [string]::IsNullOrWhiteSpace([string]$mode)) {
        switch ($mode.ToLowerInvariant()) {
            "prep"  { $bannerText = "" }
            "start" { $bannerText = "" }
            "warn5" { $bannerText = "5 minutes remaining" }
            "end"   { $bannerText = "Session ended" }
        }
    }

    $patch = @{}
    if (-not [string]::IsNullOrWhiteSpace([string]$status)) { $patch.status = $status.ToString().ToUpperInvariant() }
    if (-not [string]::IsNullOrWhiteSpace([string]$locationLabel)) { $patch.locationLabel = $locationLabel }
    if (-not [string]::IsNullOrWhiteSpace([string]$bayLabel)) { $patch.bayLabel = $bayLabel }
    if (-not [string]::IsNullOrWhiteSpace([string]$bayId)) { $patch.bayId = $bayId }
    if (-not [string]::IsNullOrWhiteSpace([string]$displayName)) { $patch.displayName = $displayName }
    if ($null -ne $startUtc -and -not [string]::IsNullOrWhiteSpace([string]$startUtc)) { $patch.sessionStartUtc = $startUtc.ToString() }
    if ($null -ne $endUtc -and -not [string]::IsNullOrWhiteSpace([string]$endUtc)) { $patch.sessionEndUtc = $endUtc.ToString() }
    if ($null -ne $bannerText) { $patch.bannerText = $bannerText.ToString() }
    if (-not [string]::IsNullOrWhiteSpace([string]$helpText)) { $patch.helpText = $helpText }

    # Copy identifiers for debugging (optional)
    $baySessionId = Get-PropValue $p "baySessionId" $null
    if (-not [string]::IsNullOrWhiteSpace([string]$baySessionId)) { $patch.baySessionId = $baySessionId.ToString() }

    $bookingId = Get-PropValue $p "bookingId" $null
    if (-not [string]::IsNullOrWhiteSpace([string]$bookingId)) { $patch.bookingId = $bookingId.ToString() }

    $patch.updatedUtc = (UtcNow-Z)
    return $patch
}

function Get-LauncherConfigFromPayloadOrConfig($payloadObj) {
    # Payload override: payload.launcher.path/args/processName
    $pl = Get-PropValue $payloadObj "launcher" $null
    $path = Get-PropValue $pl "path" $null
    $args = Get-PropValue $pl "args" $null
    $procName = Get-PropValue $pl "processName" $null
    $startOnPrep = Get-PropValue $pl "startOnPrep" $null
    $startOnStart = Get-PropValue $pl "startOnStart" $null

    # Fallback to config.launcher.*
    if ([string]::IsNullOrWhiteSpace([string]$path)) {
        $cl = $null
        try { $cl = $cfg.launcher } catch { $cl = $null }
        $path = Get-PropValue $cl "path" $path
        $args = Get-PropValue $cl "args" $args
        $procName = Get-PropValue $cl "processName" $procName
        if ($null -eq $startOnPrep) { $startOnPrep = Get-PropValue $cl "startOnPrep" $null }
        if ($null -eq $startOnStart) { $startOnStart = Get-PropValue $cl "startOnStart" $null }
    }

    return @{
        path = $path
        args = $args
        processName = $procName
        startOnPrep = $startOnPrep
        startOnStart = $startOnStart
    }
}

function Start-LauncherIfNeeded([string]$context, $launcherCfg) {
    $path = $launcherCfg.path
    $args = $launcherCfg.args
    $processName = $launcherCfg.processName

    if ([string]::IsNullOrWhiteSpace([string]$path)) {
        return @{ started = $false; reason = "no_launcher_path_configured"; context = $context }
    }
    if (!(Test-Path $path)) {
        return @{ started = $false; reason = "launcher_path_not_found"; path = $path; context = $context }
    }

    # If processName is provided, don't start if already running
    if (-not [string]::IsNullOrWhiteSpace([string]$processName)) {
        $base = [System.IO.Path]::GetFileNameWithoutExtension([string]$processName)
        $running = Get-Process -Name $base -ErrorAction SilentlyContinue
        if ($running) {
            $pids = @($running | Select-Object -ExpandProperty Id)
            # Step 5: best-effort route already-running Launcher to the Control display
            try {
                $role = Get-PropValue $launcherCfg "displayRole" $null
                if ([string]::IsNullOrWhiteSpace([string]$role)) { $role = "control" }
                foreach ($id in $pids) { $null = Safe-RouteProcessWindow -context $context -ProcessId ([int]$id) -role $role -payloadObj $null -Maximize }
            } catch {}
            return @{ started = $false; reason = "already_running"; processName = $base; pids = $pids; context = $context }
        }
    }

    $proc = $null
    if ([string]::IsNullOrWhiteSpace([string]$args)) {
        $proc = Start-Process -FilePath $path -PassThru
    } else {
        $proc = Start-Process -FilePath $path -ArgumentList $args -PassThru
    }
    # Step 5: route Launcher window to Control display (best effort)
    try {
        $role = Get-PropValue $launcherCfg "displayRole" $null
        if ([string]::IsNullOrWhiteSpace([string]$role)) { $role = "control" }
        $null = Safe-RouteProcessWindow -context $context -ProcessId ([int]$proc.Id) -role $role -payloadObj $null -Maximize
    } catch {}

    return @{ started = $true; pid = $proc.Id; path = $path; args = $args; context = $context }
}

function Stop-AppsIfRequested($payloadObj) {
    $closeApps = [bool](Get-PropValue $payloadObj "closeApps" $false)
    if (-not $closeApps) { return @{ stopped = $false; reason = "closeApps_false" } }

    $apps = Get-PropValue $payloadObj "appsToClose" $null
    if ($null -eq $apps) { return @{ stopped = $true; reason = "no_apps_list"; closed = @() } }

    $closed = @()
    foreach ($a in $apps) {
        if ($null -eq $a) { continue }
        $name = $a.ToString()
        if ([string]::IsNullOrWhiteSpace($name)) { continue }
        $base = [System.IO.Path]::GetFileNameWithoutExtension($name)
        try {
            $procs = Get-Process -Name $base -ErrorAction SilentlyContinue
            if ($procs) {
                $pids = @($procs | Select-Object -ExpandProperty Id)
                $procs | Stop-Process -Force -ErrorAction SilentlyContinue
                $closed += @{ processName = $base; pids = $pids }
            }
        } catch {}
    }
    return @{ stopped = $true; closed = $closed }
}


# ---------------- Step 5: Display routing + facility controls ----------------
# This section is designed to be "hardware tolerant":
# - If a target display (projector/touch/TV) isn't present yet, routing gracefully falls back.
# - Facility device power control defaults to Simulated unless explicitly enabled/configured.

# Load WinForms for Screen enumeration (safe no-op if not available)
try { Add-Type -AssemblyName System.Windows.Forms } catch {}
try { Add-Type -AssemblyName System.Drawing } catch {}

# Win32 window helpers (EnumWindows, move/resize, etc.)
if (-not ("ABGWin32" -as [type])) {
Add-Type @"
using System;
using System.Text;
using System.Runtime.InteropServices;

public static class ABGWin32 {
    public delegate bool EnumWindowsProc(IntPtr hWnd, IntPtr lParam);

    [DllImport("user32.dll")] public static extern bool EnumWindows(EnumWindowsProc lpEnumFunc, IntPtr lParam);
    [DllImport("user32.dll")] public static extern uint GetWindowThreadProcessId(IntPtr hWnd, out uint lpdwProcessId);
    [DllImport("user32.dll")] public static extern bool IsWindowVisible(IntPtr hWnd);
    [DllImport("user32.dll")] public static extern bool GetWindowRect(IntPtr hWnd, out RECT rect);
    [DllImport("user32.dll")] public static extern bool SetWindowPos(IntPtr hWnd, IntPtr hWndInsertAfter, int X, int Y, int cx, int cy, uint uFlags);
    [DllImport("user32.dll")] public static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);
    [DllImport("user32.dll")] public static extern bool SetForegroundWindow(IntPtr hWnd);

    // Display device info
    [StructLayout(LayoutKind.Sequential, CharSet=CharSet.Unicode)]
    public struct DISPLAY_DEVICE {
        public int cb;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst=32)]
        public string DeviceName;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst=128)]
        public string DeviceString;
        public int StateFlags;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst=128)]
        public string DeviceID;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst=128)]
        public string DeviceKey;
    }

    [DllImport("user32.dll", CharSet=CharSet.Unicode)]
    public static extern bool EnumDisplayDevices(string lpDevice, uint iDevNum, ref DISPLAY_DEVICE lpDisplayDevice, uint dwFlags);

    public const int SW_RESTORE  = 9;
    public const int SW_MAXIMIZE = 3;

    public const uint SWP_NOZORDER   = 0x0004;
    public const uint SWP_NOACTIVATE = 0x0010;
    public const uint SWP_SHOWWINDOW = 0x0040;

    [StructLayout(LayoutKind.Sequential)]
    public struct RECT { public int Left; public int Top; public int Right; public int Bottom; }
}
"@
}

function Get-DisplayDeviceString([string]$deviceName) {
    # deviceName is typically like "\\.\DISPLAY1"
    try {
        $dd = New-Object ABGWin32+DISPLAY_DEVICE
        $dd.cb = [System.Runtime.InteropServices.Marshal]::SizeOf($dd)
        # iDevNum=0 enumerates the first display attached to that name
        $ok = [ABGWin32]::EnumDisplayDevices($deviceName, 0, [ref]$dd, 0)
        if ($ok -and -not [string]::IsNullOrWhiteSpace([string]$dd.DeviceString)) {
            return $dd.DeviceString
        }
    } catch {}
    return $null
}

# Fresh monitor enumeration and window placement (1.3.1, A0.437).
# WHY: [System.Windows.Forms.Screen]::AllScreens is CACHED per process and is refreshed only by a display-change
# event that a process with no message pump may never receive. MEASURED on Bay 1, 2026-10-07: the 1.2.1 process
# reported two screens and the 1.3.0 process, started later, reported one, and nothing remote could say which was
# true. Routing chose its target from that cache too. Everything below asks Windows afresh on every call
# (EnumDisplayMonitors, GetMonitorInfo, MonitorFromWindow), and the window report says which monitor each managed
# window is actually on, so an operator can see placement instead of inferring it.
if (-not ("ABGDisplayInfo" -as [type])) {
Add-Type @"
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;

public static class ABGDisplayInfo {
    [StructLayout(LayoutKind.Sequential)]
    public struct RECT { public int Left; public int Top; public int Right; public int Bottom; }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct MONITORINFOEX {
        public int cbSize;
        public RECT rcMonitor;
        public RECT rcWork;
        public uint dwFlags;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 32)]
        public string szDevice;
    }

    public delegate bool MonitorEnumProc(IntPtr hMonitor, IntPtr hdc, IntPtr lprcMonitor, IntPtr dwData);

    [DllImport("user32.dll")] public static extern bool EnumDisplayMonitors(IntPtr hdc, IntPtr lprcClip, MonitorEnumProc lpfnEnum, IntPtr dwData);
    [DllImport("user32.dll", CharSet = CharSet.Unicode)] public static extern bool GetMonitorInfo(IntPtr hMonitor, ref MONITORINFOEX lpmi);
    [DllImport("user32.dll")] public static extern IntPtr MonitorFromWindow(IntPtr hwnd, uint dwFlags);
    [DllImport("user32.dll")] public static extern bool GetWindowRect(IntPtr hWnd, out RECT rect);
    [DllImport("user32.dll")] public static extern bool IsZoomed(IntPtr hWnd);
    [DllImport("user32.dll")] public static extern bool IsIconic(IntPtr hWnd);
    [DllImport("user32.dll")] public static extern int GetSystemMetrics(int nIndex);

    public sealed class MonitorRow {
        public string DeviceName;
        public bool Primary;
        public int Left; public int Top; public int Width; public int Height;
    }

    public static MonitorRow Describe(IntPtr hMonitor) {
        MONITORINFOEX mi = new MONITORINFOEX();
        mi.cbSize = Marshal.SizeOf(typeof(MONITORINFOEX));
        if (!GetMonitorInfo(hMonitor, ref mi)) { return null; }
        MonitorRow r = new MonitorRow();
        r.DeviceName = mi.szDevice;
        r.Primary = (mi.dwFlags & 1) != 0;
        r.Left = mi.rcMonitor.Left;
        r.Top = mi.rcMonitor.Top;
        r.Width = mi.rcMonitor.Right - mi.rcMonitor.Left;
        r.Height = mi.rcMonitor.Bottom - mi.rcMonitor.Top;
        return r;
    }

    public static List<MonitorRow> GetMonitors() {
        List<MonitorRow> list = new List<MonitorRow>();
        MonitorEnumProc cb = delegate (IntPtr h, IntPtr hdc, IntPtr rc, IntPtr data) {
            MonitorRow row = Describe(h);
            if (row != null) { list.Add(row); }
            return true;
        };
        EnumDisplayMonitors(IntPtr.Zero, IntPtr.Zero, cb, IntPtr.Zero);
        GC.KeepAlive(cb);
        return list;
    }

    public static MonitorRow MonitorForWindow(IntPtr hwnd) {
        IntPtr h = MonitorFromWindow(hwnd, 2);
        if (h == IntPtr.Zero) { return null; }
        return Describe(h);
    }
}
"@
}

function Get-CurrentScreens {
    # The screens as Windows reports them NOW, shaped like System.Windows.Forms.Screen (DeviceName, Primary, Bounds)
    # so the routing code reads them unchanged. Same enumeration order as Screen.AllScreens (both are
    # EnumDisplayMonitors), so a numeric role selector keeps its meaning. Falls back to the cached WinForms list only
    # when the fresh enumeration fails or returns nothing.
    $out = @()
    try {
        foreach ($m in @([ABGDisplayInfo]::GetMonitors())) {
            $out += [pscustomobject]@{
                DeviceName = [string]$m.DeviceName
                Primary    = [bool]$m.Primary
                Bounds     = (New-Object System.Drawing.Rectangle([int]$m.Left, [int]$m.Top, [int]$m.Width, [int]$m.Height))
                Fresh      = $true
            }
        }
    } catch { $out = @() }
    if ($out.Count -gt 0) { return $out }
    try { return @([System.Windows.Forms.Screen]::AllScreens) } catch { return @() }
}

function Get-CachedScreensSummary {
    # What THIS process's WinForms cache says, reported next to the fresh view so a stale cache is visible.
    try {
        return @(@([System.Windows.Forms.Screen]::AllScreens) | ForEach-Object {
            "{0}{1} {2},{3} {4}x{5}" -f $_.DeviceName, $(if ($_.Primary) { "*" } else { "" }), $_.Bounds.Left, $_.Bounds.Top, $_.Bounds.Width, $_.Bounds.Height })
    } catch { return @("error: " + $_.Exception.Message) }
}

function Get-DisplayAdapterReport {
    # Every display adapter and the monitors Windows knows on each, with their state flags: a TV that is cabled but
    # off, or attached but not part of the desktop, shows here (active=false) while the monitor list above omits it.
    $rows = @()
    try {
        for ($i = 0; $i -lt 16; $i++) {
            $ad = New-Object ABGWin32+DISPLAY_DEVICE
            $ad.cb = [System.Runtime.InteropServices.Marshal]::SizeOf($ad)
            # [NullString]::Value, not $null: PowerShell passes $null to a .NET string parameter as "", and
            # EnumDisplayDevices("") enumerates nothing (MEASURED 2026-10-07: every call returned false).
            if (-not [ABGWin32]::EnumDisplayDevices([NullString]::Value, [uint32]$i, [ref]$ad, 0)) { break }
            $mons = @()
            for ($j = 0; $j -lt 8; $j++) {
                $md = New-Object ABGWin32+DISPLAY_DEVICE
                $md.cb = [System.Runtime.InteropServices.Marshal]::SizeOf($md)
                if (-not [ABGWin32]::EnumDisplayDevices([string]$ad.DeviceName, [uint32]$j, [ref]$md, 0)) { break }
                $mons += [ordered]@{
                    desc     = [string]$md.DeviceString
                    active   = (([int]$md.StateFlags -band 1) -ne 0)
                    attached = (([int]$md.StateFlags -band 2) -ne 0)
                }
            }
            # Skip adapters with no desktop and no monitors (virtual and mirror drivers) to keep the report small.
            $onDesktop = (([int]$ad.StateFlags -band 1) -ne 0)
            if (-not $onDesktop -and $mons.Count -eq 0) { continue }
            $rows += [ordered]@{
                deviceName = [string]$ad.DeviceName
                desc       = [string]$ad.DeviceString
                onDesktop  = $onDesktop
                primary    = (([int]$ad.StateFlags -band 4) -ne 0)
                monitors   = @($mons)
            }
        }
    } catch { $rows += [ordered]@{ error = $_.Exception.Message } }
    return $rows
}

function Get-WindowPlacement([IntPtr]$hWnd) {
    # Where one window actually is: its rectangle, the monitor Windows says it is on, and its state.
    $r = New-Object ABGDisplayInfo+RECT
    $okRect = [ABGDisplayInfo]::GetWindowRect($hWnd, [ref]$r)
    $mon = [ABGDisplayInfo]::MonitorForWindow($hWnd)
    $w = $r.Right - $r.Left; $h = $r.Bottom - $r.Top
    $covers = $false
    if ($okRect -and $null -ne $mon) {
        $covers = ($r.Left -le $mon.Left -and $r.Top -le $mon.Top -and $r.Right -ge ($mon.Left + $mon.Width) -and $r.Bottom -ge ($mon.Top + $mon.Height))
    }
    return [ordered]@{
        device        = $(if ($null -ne $mon) { [string]$mon.DeviceName } else { $null })
        left          = $r.Left; top = $r.Top; width = $w; height = $h
        maximized     = [bool][ABGDisplayInfo]::IsZoomed($hWnd)
        minimized     = [bool][ABGDisplayInfo]::IsIconic($hWnd)
        coversMonitor = [bool]$covers
    }
}

function Get-SessionDisplayEdgePids([string]$pdir) {
    # Top-level twin of Start-SessionDisplay's own profile-dir match (read-only use: the placement report).
    $ids = @()
    if ([string]::IsNullOrWhiteSpace($pdir)) { return @() }
    try {
        $edgeCim = Get-CimInstance Win32_Process -Filter "Name='msedge.exe'" -OperationTimeoutSec 2 -ErrorAction SilentlyContinue
        foreach ($p in @($edgeCim)) {
            $cmd = $p.CommandLine
            if ($null -ne $cmd -and $cmd -like "*$pdir*") { $ids += [int]$p.ProcessId }
        }
    } catch {}
    return $ids
}

function Get-ManagedWindowEntry([string]$name, [string]$role, [int[]]$pids, [string]$processLabel) {
    $expected = $null
    try { $sc = Get-ScreenForRole $role $null; if ($null -ne $sc) { $expected = [string]$sc.DeviceName } } catch { }
    $wins = @()
    foreach ($id in @($pids | Select-Object -First 12)) {
        try {
            $hw = Get-FirstVisibleWindowHandleForPid ([int]$id)
            if ($hw -eq [IntPtr]::Zero) { continue }
            $pl = Get-WindowPlacement $hw
            $pl["pid"] = [int]$id
            $wins += $pl
        } catch { }
        if ($wins.Count -ge 4) { break }
    }
    $onExpected = $null
    if ($wins.Count -gt 0 -and $null -ne $expected) { $onExpected = (@($wins | Where-Object { $_.device -ine $expected }).Count -eq 0) }
    return [ordered]@{
        name           = $name
        process        = $processLabel
        role           = $role
        expectedDevice = $expected
        running        = (@($pids).Count -gt 0)
        windows        = @($wins)
        onExpected     = $onExpected
    }
}

function Get-ManagedWindowReport {
    # The two windows this agent places: the launcher (role as Start-LauncherIfNeeded computes it) and the wall
    # display (Edge with the session-display profile).
    $out = @()
    try {
        $lc = Get-LauncherConfigFromPayloadOrConfig $null
        $lrole = Get-PropValue $lc "displayRole" $null
        if ([string]::IsNullOrWhiteSpace([string]$lrole)) { $lrole = "control" }
        $lname = [string](Get-PropValue $lc "processName" "")
        $lpids = @()
        if (-not [string]::IsNullOrWhiteSpace($lname)) {
            $base = [System.IO.Path]::GetFileNameWithoutExtension($lname)
            $lpids = @(Get-Process -Name $base -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Id)
        }
        $out += (Get-ManagedWindowEntry "launcher" ([string]$lrole) ([int[]]@($lpids)) $lname)
    } catch { $out += [ordered]@{ name = "launcher"; error = $_.Exception.Message } }
    try {
        $sdCfg = $null
        try { if ($cfg.PSObject.Properties.Name -contains "sessionDisplay") { $sdCfg = $cfg.sessionDisplay } } catch {}
        $srole = Get-PropValue $sdCfg "displayRole" $null
        if ([string]::IsNullOrWhiteSpace([string]$srole)) { $srole = "session" }
        $pdir = Get-PropValue $sdCfg "profileDir" $Global:SessionDisplayProfileDir
        if ([string]::IsNullOrWhiteSpace([string]$pdir)) { $pdir = "C:\AllBirdies\SessionDisplay\edge-profile" }
        $spids = @(Get-SessionDisplayEdgePids ([string]$pdir))
        $out += (Get-ManagedWindowEntry "sessionDisplay" ([string]$srole) ([int[]]@($spids)) "msedge")
    } catch { $out += [ordered]@{ name = "sessionDisplay"; error = $_.Exception.Message } }
    return $out
}

function Get-DisplayReport {
    # The remote operator's view of the screens: fresh monitors, adapters, the screen each role resolves to now,
    # where each managed window is, and the last routing attempt per role. Every part is isolated: one failing part
    # reports its error and the rest still arrive.
    $rep = [ordered]@{ utc = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ") }
    try { $rep["monitorCountSystem"] = [ABGDisplayInfo]::GetSystemMetrics(80) } catch { $rep["monitorCountSystem"] = $null }
    try { $rep["monitors"] = @(Get-DisplayTopology) } catch { $rep["monitors"] = @([ordered]@{ error = $_.Exception.Message }) }
    try { $rep["screensCachedByProcess"] = @(Get-CachedScreensSummary) } catch { }
    try { $rep["adapters"] = @(Get-DisplayAdapterReport) } catch { $rep["adapters"] = @([ordered]@{ error = $_.Exception.Message }) }
    $roles = [ordered]@{}
    foreach ($rn in @("play", "control", "session")) {
        try { $sc = Get-ScreenForRole $rn $null; $roles[$rn] = $(if ($null -ne $sc) { [string]$sc.DeviceName } else { $null }) }
        catch { $roles[$rn] = "error: " + $_.Exception.Message }
    }
    $rep["roles"] = $roles
    try { $rep["windows"] = @(Get-ManagedWindowReport) } catch { $rep["windows"] = @([ordered]@{ error = $_.Exception.Message }) }
    try {
        $lr = [ordered]@{}
        $store = Get-Variable -Name LastDisplayRouting -Scope Global -ValueOnly -ErrorAction SilentlyContinue
        if ($store -is [hashtable]) { foreach ($k in @($store.Keys | Sort-Object)) { $lr[$k] = $store[$k] } }
        $rep["lastRouting"] = $lr
    } catch { }
    return $rep
}

function Get-DisplayTopology {
    # Returns a view of monitors for config + troubleshooting, enumerated fresh on every call (see Get-CurrentScreens).
    $out = @()
    try {
        $screens = @(Get-CurrentScreens)
        for ($i=0; $i -lt $screens.Count; $i++) {
            $s = $screens[$i]
            $b = $s.Bounds
            $ds = Get-DisplayDeviceString $s.DeviceName
            $out += [ordered]@{
                index      = $i
                deviceName = $s.DeviceName
                deviceDesc = $ds
                primary    = [bool]$s.Primary
                left       = $b.Left
                top        = $b.Top
                width      = $b.Width
                height     = $b.Height
            }
        }
    } catch {
        $out += [ordered]@{ error = $_.Exception.Message }
    }
    return $out
}

function Get-DisplayRoutingConfigFromPayloadOrConfig($payloadObj) {
    # Prefer payload.displayRouting, then cfg.displayRouting, then cfg.facility.displayRouting
    $dr = Get-PropValue $payloadObj "displayRouting" $null
    if ($null -ne $dr) { return $dr }

    try {
        if ($cfg.PSObject.Properties.Name -contains "displayRouting") { return $cfg.displayRouting }
    } catch {}

    try {
        $fac = $cfg.facility
        if ($null -ne $fac) { return $fac.displayRouting }
    } catch {}

    return $null
}

function Resolve-RoleSelectorToScreen($selector, $screens) {
    if ($null -eq $screens) { $screens = @(Get-CurrentScreens) }
    if ($null -eq $selector) { return $null }

    # Numeric index
    try {
        if ($selector -is [int] -or $selector -is [long] -or ($selector -is [double])) {
            $idx = [int]$selector
            if ($idx -ge 0 -and $idx -lt $screens.Count) { return $screens[$idx] }
        }
    } catch {}

    $sel = $selector.ToString()
    if ([string]::IsNullOrWhiteSpace($sel)) { return $null }
    $sel = $sel.Trim()

    # DeviceName direct match
    foreach ($s in $screens) {
        if ($s.DeviceName -ieq $sel) { return $s }
    }

    # Allow shorthand like "DISPLAY2"
    if ($sel -match '^DISPLAY\d+$') {
        $full = "\\.\$sel"
        foreach ($s in $screens) {
            if ($s.DeviceName -ieq $full) { return $s }
        }
    }

    # Substring match on DeviceString (friendly-ish)
    foreach ($s in $screens) {
        $ds = Get-DisplayDeviceString $s.DeviceName
        if (-not [string]::IsNullOrWhiteSpace([string]$ds) -and $ds.ToLowerInvariant().Contains($sel.ToLowerInvariant())) {
            return $s
        }
    }

    return $null
}

function Get-ScreenForRole([string]$role, $payloadObj) {
    # Roles: play, control, session
    $screens = $null
    try { $screens = @(Get-CurrentScreens) } catch { return $null }
    if ($null -eq $screens -or @($screens).Count -eq 0) { return $null }

    $dr = Get-DisplayRoutingConfigFromPayloadOrConfig $payloadObj
    $enabled = $true
    try {
        $enabledVal = Get-PropValue $dr "enabled" $null
        if ($null -ne $enabledVal) { $enabled = [bool]$enabledVal }
    } catch {}
    if (-not $enabled) { return $null }

    # role selector from config/payload
    $roles = Get-PropValue $dr "roles" $null
    $roleObj = Get-PropValue $roles $role $null
    $selector = $null
    $selector = Get-PropValue $roleObj "selector" $null
    if ($null -eq $selector) { $selector = Get-PropValue $roleObj "deviceName" $null }
    if ($null -eq $selector) { $selector = Get-PropValue $roleObj "index" $null }

    $screen = $null
    if ($null -ne $selector) {
        $screen = Resolve-RoleSelectorToScreen $selector $screens
    }

    if ($null -ne $screen) { return $screen }

    # Safe fallbacks if not configured:
    # - play: primary
    # - control: first non-primary
    # - session: last non-primary (if 2+ monitors)
    if ($role -ieq "play") {
        foreach ($s in $screens) { if ($s.Primary) { return $s } }
        return $screens[0]
    }

    $nonPrimary = @($screens | Where-Object { -not $_.Primary })
    if ($nonPrimary.Count -eq 0) { return $null }

    if ($role -ieq "control") { return $nonPrimary[0] }
    if ($role -ieq "session") { return $nonPrimary[$nonPrimary.Count - 1] }

    return $null
}

function Get-FirstVisibleWindowHandleForPid([int]$ProcessId) {
    # Returns the first visible top-level window for a PID, or IntPtr::Zero.
    $script:__abgFoundHwnd = [IntPtr]::Zero
    try {
        $cb = [ABGWin32+EnumWindowsProc]{
            param([IntPtr]$hWnd, [IntPtr]$lParam)
            try {
                if (-not [ABGWin32]::IsWindowVisible($hWnd)) { return $true }
                $outPid = 0
                [void][ABGWin32]::GetWindowThreadProcessId($hWnd, [ref]$outPid)
                if ([int]$outPid -eq $ProcessId) {
                    $script:__abgFoundHwnd = $hWnd
                    return $false
                }
            } catch {}
            return $true
        }
        [void][ABGWin32]::EnumWindows($cb, [IntPtr]::Zero)
    } catch {}
    return $script:__abgFoundHwnd
}

function Move-ProcessWindowToRole {
    param(
        [Parameter(Mandatory=$true)][int]$ProcessId,
        [Parameter(Mandatory=$true)][ValidateSet("play","control","session")][string]$role,
        $payloadObj,
        [int]$timeoutSec = 8,
        [int]$windowGraceSec = 10,
        [switch]$Maximize
    )

    $screen = Get-ScreenForRole $role $payloadObj
    if ($null -eq $screen) { return @{ moved = $false; reason = "no_target_screen"; role = $role; pid = $ProcessId } }

    # Bound the wait (R2). Waiting for a window only makes sense for a process that is still opening one: a process
    # older than windowGraceSec that shows no window now is not going to, so it costs one check, not timeoutSec.
    # A process that is gone costs one check too. If the age cannot be read, keep the full wait (never skip a move).
    $waitSec = $timeoutSec
    $procGone = $false
    try {
        $rp = Get-Process -Id $ProcessId -ErrorAction Stop
        if ($rp.HasExited) { $procGone = $true }
        else {
            try {
                $ageSec = ((Get-Date) - $rp.StartTime).TotalSeconds
                $waitSec = [Math]::Min([double]$timeoutSec, [Math]::Max(0.0, [double]$windowGraceSec - $ageSec))
            } catch { }
        }
    } catch { $procGone = $true }
    if ($procGone) { return @{ moved = $false; reason = "no_process"; role = $role; pid = $ProcessId } }

    $deadline = (Get-Date).AddSeconds($waitSec)
    $hWnd = [IntPtr]::Zero
    do {
        $hWnd = Get-FirstVisibleWindowHandleForPid $ProcessId
        if ($hWnd -ne [IntPtr]::Zero) { break }
        Start-Sleep -Milliseconds 250
    } while ((Get-Date) -lt $deadline)

    if ($hWnd -eq [IntPtr]::Zero) {
        return @{ moved = $false; reason = "no_window_handle"; role = $role; pid = $ProcessId }
    }

    $b = $screen.Bounds
    try {
        # Restore then move/resize then optionally maximize
        [void][ABGWin32]::ShowWindow($hWnd, [ABGWin32]::SW_RESTORE)
        [void][ABGWin32]::SetWindowPos($hWnd, [IntPtr]::Zero, $b.Left, $b.Top, $b.Width, $b.Height,
            [ABGWin32]::SWP_NOZORDER -bor [ABGWin32]::SWP_NOACTIVATE -bor [ABGWin32]::SWP_SHOWWINDOW)
        if ($Maximize) { [void][ABGWin32]::ShowWindow($hWnd, [ABGWin32]::SW_MAXIMIZE) }
        return @{
            moved = $true
            role = $role
            pid = $ProcessId
            deviceName = $screen.DeviceName
            deviceDesc = (Get-DisplayDeviceString $screen.DeviceName)
            bounds = @{ left=$b.Left; top=$b.Top; width=$b.Width; height=$b.Height }
        }
    } catch {
        return @{ moved = $false; role = $role; pid = $ProcessId; error = $_.Exception.Message }
    }
}

function Safe-RouteProcessWindow {
    param(
        [string]$context,
        [int]$ProcessId,
        [string]$role,
        $payloadObj,
        [switch]$Maximize
    )
    try {
        $res = Move-ProcessWindowToRole -ProcessId $ProcessId -role $role -payloadObj $payloadObj -Maximize:$Maximize
        if ($res.moved) {
            Write-Log "DisplayRouting: moved pid=$ProcessId to role=$role ($($res.deviceName) / $($res.deviceDesc)) context=$context" "INFO"
        } else {
            Write-Log "DisplayRouting: no move pid=$ProcessId role=$role reason=$($res.reason) context=$context" "DEBUG"
        }
        Save-LastDisplayRouting -role $role -context $context -res $res
        return $res
    } catch {
        Write-Log "DisplayRouting: exception context=$context pid=$ProcessId role=$role :: $($_.Exception.Message)" "WARN"
        $err = @{ moved = $false; role = $role; pid = $ProcessId; error = $_.Exception.Message }
        Save-LastDisplayRouting -role $role -context $context -res $err
        return $err
    }
}

function Save-LastDisplayRouting {
    # Through 1.3.0 every routing result was discarded at its call site ($null = Safe-RouteProcessWindow ...), so no
    # remote reader could learn where a window was sent. Keep the last attempt per role for the display report.
    # Never throws: recording a result must not turn a routing success into a failure.
    param([string]$role, [string]$context, $res)
    try {
        $store = Get-Variable -Name LastDisplayRouting -Scope Global -ValueOnly -ErrorAction SilentlyContinue
        if ($null -eq $store -or -not ($store -is [hashtable])) { $store = @{}; $Global:LastDisplayRouting = $store }
        $store[[string]$role] = [ordered]@{
            utc     = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
            context = $context
            pid     = $(if ($null -ne $res) { $res.pid } else { $null })
            moved   = $(if ($null -ne $res) { [bool]$res.moved } else { $false })
            device  = $(if ($null -ne $res -and $res.ContainsKey("deviceName")) { $res.deviceName } else { $null })
            reason  = $(if ($null -ne $res -and $res.ContainsKey("reason")) { $res.reason } elseif ($null -ne $res -and $res.ContainsKey("error")) { $res.error } else { $null })
        }
    } catch { }
}

function Get-FacilityConfigFromPayloadOrConfig($payloadObj) {
    $f = Get-PropValue $payloadObj "facility" $null
    if ($null -ne $f) { return $f }
    try { return $cfg.facility } catch { return $null }
}

function Facility-IsEnabled($payloadObj) {
    $f = Get-FacilityConfigFromPayloadOrConfig $payloadObj
    $enabled = $false
    try {
        $v = Get-PropValue $f "enabled" $null
        if ($null -ne $v) { $enabled = [bool]$v }
    } catch {}
    return $enabled
}


function Normalize-FacilityScene([string]$scene) {
    if ([string]::IsNullOrWhiteSpace($scene)) { return "Idle" }
    $s = $scene.Trim()

    switch ($s.ToLowerInvariant()) {
        # Preferred scene names (per Step 5 spec)
        "ready"   { return "Ready" }
        "active"  { return "Active" }
        "warning" { return "Warning" }
        "cleanup" { return "Cleanup" }
        "idle"    { return "Idle" }

        # Back-compat aliases
        "warmup"    { return "Ready" }
        "insession" { return "Active" }
        "session"   { return "Active" }
        "warn5"     { return "Warning" }
        "end"       { return "Cleanup" }
        "closed"    { return "Idle" }
        default     { return "Idle" }
    }
}

function Facility-CheckEmergencyStop {
    if ($Global:EmergencyStopEngaged) {
        throw ("EmergencyStop is engaged" + ($(if ($Global:EmergencyStopReason) { ": $Global:EmergencyStopReason" } else { "" })))
    }
}

function Invoke-LightsScene {
    param([Parameter(Mandatory=$true)][string]$Scene, $payloadObj)
    # Placeholder driver. Later: Shelly/Kasa/Lutron/relays/DMX/etc.
    return @{
        device="lights"
        action="SetLights"
        scene=$Scene
        ok=$true
        simulated=$true
        note="placeholder"
    }
}

function Invoke-ProjectorPower {
    param([Parameter(Mandatory=$true)][bool]$On, $payloadObj)
    # Placeholder driver. Later: RS-232 (BenQ), PJLink, etc.
    return @{
        device="projector"
        action="ProjectorPower"
        on=$On
        ok=$true
        simulated=$true
        note="placeholder"
    }
}

function Invoke-AudioVolume {
    param([Parameter(Mandatory=$true)]$Level, $payloadObj)
    # Placeholder driver. Later options:
    # - Windows system volume via a helper tool (nircmd) or an audio endpoint API wrapper
    # - AV receiver / amp via IP/RS-232
    return @{
        device="audio"
        action="AudioVolume"
        level=$Level
        ok=$true
        simulated=$true
        note="placeholder"
    }
}

# ---- persisted emergency-stop latch: a restart must not release it ----
function ConvertFrom-EmergencyStopStateText {
    # STRICT, same pattern as ConvertFrom-SelfHealStateText. The file is valid only as an OBJECT with exactly one
    # boolean "engaged" and exactly one "reason" that is a string (engaged) or null (cleared). Anything else is
    # UNREADABLE, never "not engaged": 0 bytes, whitespace, a BOM only, NUL bytes (power loss), null, {}, [], a
    # missing key, a wrong type, or one bad field. The caller reads UNREADABLE as ENGAGED.
    param([string]$Text)
    $fail = @{ Ok = $false; Engaged = $false; Reason = $null; Why = "" }
    if ($null -ne $Text) { $Text = $Text.TrimStart([char]0xFEFF) }
    if ([string]::IsNullOrWhiteSpace($Text)) { $fail.Why = "empty"; return $fail }
    if ($Text.IndexOf([char]0) -ge 0) { $fail.Why = "NUL bytes"; return $fail }
    $o = $null
    try { $o = ConvertFrom-Json -InputObject $Text -ErrorAction Stop } catch { $fail.Why = "not JSON"; return $fail }
    if ($null -eq $o -or -not ($o -is [System.Management.Automation.PSCustomObject])) { $fail.Why = "not an object"; return $fail }
    $pe = @($o.PSObject.Properties | Where-Object { $_.Name -ceq "engaged" })
    $pr = @($o.PSObject.Properties | Where-Object { $_.Name -ceq "reason" })
    if ($pe.Count -ne 1) { $fail.Why = "no engaged"; return $fail }
    if ($pr.Count -ne 1) { $fail.Why = "no reason"; return $fail }
    $engaged = $pe[0].Value
    $reason = $pr[0].Value
    if ($null -eq $engaged -or -not ($engaged -is [bool])) { $fail.Why = "engaged is not a boolean"; return $fail }
    if ($engaged) {
        if (-not ($reason -is [string]) -or [string]::IsNullOrWhiteSpace($reason)) { $fail.Why = "reason is not a non-empty string"; return $fail }
    } else {
        if ($null -ne $reason) { $fail.Why = "a cleared state carries a reason"; return $fail }
    }
    return @{ Ok = $true; Engaged = [bool]$engaged; Reason = $(if ($engaged) { [string]$reason } else { $null }); Why = "" }
}

function Save-EmergencyStopState {
    # Writes the latch to disk and reads it back through the strict reader. Returns @{ Ok; Detail }. Never throws.
    # The file is never deleted (a missing file reads as "first install, not engaged"): the replace path overwrites.
    param([bool]$Engaged, [string]$Reason)
    $ok = $false; $detail = ""
    try {
        $path = $Global:EmergencyStopStatePath
        $dir = Split-Path -Parent $path
        if (-not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
        $o = [ordered]@{ engaged = $Engaged; reason = $(if ($Engaged) { $Reason } else { $null }) }
        $text = ConvertTo-Json -InputObject $o -Depth 3
        $tmp = "$path.tmp"
        [IO.File]::WriteAllText($tmp, $text, (New-Object System.Text.UTF8Encoding($false)))
        try {
            if (Test-Path -LiteralPath $path) { [IO.File]::Replace($tmp, $path, [NullString]::Value, $true) }
            else { [IO.File]::Move($tmp, $path) }
        } catch {
            # Overwrite in place; never remove the file, so a crash here still leaves a file (zero bytes reads ENGAGED).
            [IO.File]::WriteAllText($path, $text, (New-Object System.Text.UTF8Encoding($false)))
        }
        $back = ConvertFrom-EmergencyStopStateText -Text ([IO.File]::ReadAllText($path))
        if (-not $back.Ok) { $detail = "read back unreadable ($($back.Why))" }
        elseif ($back.Engaged -ne $Engaged) { $detail = "read back engaged=$($back.Engaged), wrote engaged=$Engaged" }
        elseif ($Engaged -and $back.Reason -ne $Reason) { $detail = "read back a different reason" }
        else { $ok = $true }
    } catch {
        $detail = $_.Exception.Message
    }
    $Global:EmergencyStopPersistOk = $ok
    if (-not $ok) {
        try { Write-Log ("[ESTOP] the emergency-stop state was not saved ({0}); the latch stays as it is in memory" -f $detail) "ERROR" } catch {}
    }
    return @{ Ok = $ok; Detail = $detail }
}

function Restore-EmergencyStopLatch {
    # Startup. A missing file is a first install (not engaged). A present file that cannot be read back exactly is
    # ENGAGED: an unreadable latch is never a released one.
    $path = $Global:EmergencyStopStatePath
    $engaged = $false; $reason = $null
    if (Test-Path -LiteralPath $path) {
        $parsed = @{ Ok = $false; Engaged = $false; Reason = $null; Why = "unreadable" }
        try { $parsed = ConvertFrom-EmergencyStopStateText -Text ([IO.File]::ReadAllText($path)) }
        catch { $parsed = @{ Ok = $false; Engaged = $false; Reason = $null; Why = $_.Exception.Message } }
        if ($parsed.Ok) {
            $engaged = $parsed.Engaged; $reason = $parsed.Reason
        } else {
            $engaged = $true
            $reason = "Emergency-stop state file unreadable ($($parsed.Why)); the stop is held until an explicit clear"
            try { Write-Log ("[ESTOP] {0}" -f $reason) "ERROR" } catch {}
        }
        if ($engaged) { try { Write-Log ("[ESTOP] restored ENGAGED after a restart: {0}" -f $reason) "WARN" } catch {} }
    }
    $Global:EmergencyStopEngaged = $engaged
    $Global:EmergencyStopReason = $reason
    $Global:NextCapabilitiesUtc = [DateTime]::MinValue
}

function Invoke-EmergencyStopInternal {
    param($payloadObj)

    $reason = $null
    try { $reason = (Get-PropValue $payloadObj "reason" $null) } catch {}
    if ([string]::IsNullOrWhiteSpace([string]$reason)) { $reason = "Emergency stop requested" }

    # Engage in memory first (the safe direction), then persist and confirm. A failed save is logged and reported
    # but never un-engages the stop.
    $Global:EmergencyStopEngaged = $true
    $Global:EmergencyStopReason = $reason
    $persist = Save-EmergencyStopState -Engaged $true -Reason ([string]$reason)
    $Global:NextCapabilitiesUtc = [DateTime]::MinValue

    # Put the bay into a safe scene and show a clear message.
    $facility = Invoke-FacilitySetMode -Mode "Cleanup" -payloadObj $payloadObj

    # Update display model (best-effort)
    try {
        $existing = Read-SessionModelFromDisk
        $ht = To-Hashtable $existing
        $ht.bannerText = "EMERGENCY STOP"
        $ht.statusDetail = $reason
        $ht.status = "STOP"
        $ht = Normalize-SessionModel $ht
        Write-SessionFiles $ht | Out-Null
        Start-SessionDisplay $payloadObj | Out-Null
    } catch {}

    return @{
        ok = $true
        engaged = $true
        reason = $reason
        persisted = [bool]$persist.Ok
        facility = $facility
    }
}

function Clear-EmergencyStopInternal {
    # Persist the release FIRST and confirm it by reading it back. A clear that cannot be made durable is refused:
    # acting as cleared now would let the next restart read the old ENGAGED file (harmless) or, worse, leave the
    # platform believing the bay is released while the file says otherwise.
    $persist = Save-EmergencyStopState -Engaged $false -Reason $null
    if (-not $persist.Ok) {
        return @{ ok=$false; engaged=$true; note="emergency_stop_clear_not_persisted"; detail=$persist.Detail; reason=$Global:EmergencyStopReason }
    }
    $Global:EmergencyStopEngaged = $false
    $Global:EmergencyStopReason = $null
    $Global:NextCapabilitiesUtc = [DateTime]::MinValue
    return @{ ok=$true; engaged=$false }
}

function Invoke-FacilitySetMode {
    param(
        [Parameter(Mandatory=$true)][string]$Mode,
        $payloadObj
    )

    # Facility scenes per Step 5 spec:
    #   Ready / Active / Warning / Cleanup / Idle
    #
    # Back-compat:
    #   Warmup -> Ready
    #   InSession -> Active
    #   Closed -> Idle
    $scene = Normalize-FacilityScene $Mode

    # If EmergencyStop is latched, do not allow scene changes (except Cleanup/Idle via Reset/Clear).
    if ($Global:EmergencyStopEngaged -and ($scene -ne "Cleanup") -and ($scene -ne "Idle")) {
        return @{
            ok = $false
            enabled = (Facility-IsEnabled $payloadObj)
            scene = $scene
            emergencyStop = @{ engaged = $true; reason = $Global:EmergencyStopReason }
            note = "emergency_stop_engaged"
        }
    }

    # Build a plan (device/action pairs). Even when facility is disabled, returning the plan helps validate Step 5.
    $actions = @()
    switch ($scene) {
        "Idle" {
            $actions += @{ device="projector"; action=@{ type="ProjectorPower"; on=$false } }
            $actions += @{ device="lights"; action=@{ type="SetLights"; scene="Idle" } }
            $actions += @{ device="audio"; action=@{ type="AudioVolume"; level="mute" } }
        }
        "Ready" {
            $actions += @{ device="projector"; action=@{ type="ProjectorPower"; on=$true } }
            $actions += @{ device="lights"; action=@{ type="SetLights"; scene="Ready" } }
            $actions += @{ device="audio"; action=@{ type="AudioVolume"; level=20 } }
        }
        "Active" {
            $actions += @{ device="projector"; action=@{ type="ProjectorPower"; on=$true } }
            $actions += @{ device="lights"; action=@{ type="SetLights"; scene="Active" } }
            $actions += @{ device="audio"; action=@{ type="AudioVolume"; level=35 } }
        }
        "Warning" {
            $actions += @{ device="lights"; action=@{ type="SetLights"; scene="Warning" } }
            $actions += @{ device="audio"; action=@{ type="AudioVolume"; level=35 } }
        }
        "Cleanup" {
            $actions += @{ device="projector"; action=@{ type="ProjectorPower"; on=$false } }
            $actions += @{ device="lights"; action=@{ type="SetLights"; scene="Cleanup" } }
            $actions += @{ device="audio"; action=@{ type="AudioVolume"; level="mute" } }
        }
        default {
            $actions += @{ device="projector"; action=@{ type="ProjectorPower"; on=$false } }
            $actions += @{ device="lights"; action=@{ type="SetLights"; scene="Idle" } }
            $actions += @{ device="audio"; action=@{ type="AudioVolume"; level="mute" } }
        }
    }

    # Execute the plan via driver stubs. Later we will route each device to real drivers (Shelly/Kasa/Lutron/RS-232/PJLink/etc.).
    $results = @()
    foreach ($a in $actions) {
        $dev = $a.device
        $act = $a.action

        switch ($act.type) {
            "SetLights" {
                $results += Invoke-LightsScene -Scene $act.scene -payloadObj $payloadObj
            }
            "ProjectorPower" {
                $results += Invoke-ProjectorPower -On ([bool]$act.on) -payloadObj $payloadObj
            }
            "AudioVolume" {
                $results += Invoke-AudioVolume -Level $act.level -payloadObj $payloadObj
            }
            default {
                $results += @{
                    device = $dev
                    action = $act.type
                    ok = $true
                    simulated = $true
                    note = "unknown_action_type_placeholder"
                }
            }
        }
    }

    return @{
        ok = $true
        scene = $scene
        enabled = (Facility-IsEnabled $payloadObj)
        simulated = $true
        plan = $actions
        results = $results
    }
}


function Start-SessionDisplay($payloadObj) {
    # Session Display settings can come from the command payload OR agent-config.json.
    # Payload wins, config provides stable defaults so you don't have to modify flows.
    $sdPayload = Get-PropValue $payloadObj "sessionDisplay" $null
    $sdCfg = $null
    try { if ($cfg.PSObject.Properties.Name -contains "sessionDisplay") { $sdCfg = $cfg.sessionDisplay } } catch {}

    $enabled = Get-PropValue $sdPayload "enabled" (Get-PropValue $sdCfg "enabled" $true)
    if ($enabled -eq $false) { return @{ started = $false; reason = "disabled" } }

    # A0.363 (I5, one owner): while a live kiosk shell supervises, IT starts and places the wall window (and moves it
    # aside when one screen must serve the launcher). The agent still writes the session files the wall shows.
    $kioskWall = Get-KioskWallDeferral -NowUtc ((Get-Date).ToUniversalTime())
    if ($kioskWall.Defer) { return @{ started = $false; reason = "kiosk_shell_owns_wall" } }

    $mode = (Get-PropValue $sdPayload "mode" (Get-PropValue $sdCfg "mode" "kiosk")).ToString().ToLowerInvariant()

    $edgePath = Get-PropValue $sdPayload "edgePath" (Get-PropValue $sdCfg "edgePath" $null)
    if ([string]::IsNullOrWhiteSpace([string]$edgePath)) { $edgePath = Get-DefaultEdgePath }

    $url = Get-PropValue $sdPayload "url" (Get-PropValue $sdCfg "url" $null)
    if ([string]::IsNullOrWhiteSpace([string]$url)) { $url = "file:///C:/AllBirdies/SessionDisplay/index.html" }

    $profileDir = Get-PropValue $sdPayload "profileDir" (Get-PropValue $sdCfg "profileDir" $Global:SessionDisplayProfileDir)
    if ([string]::IsNullOrWhiteSpace([string]$profileDir)) { $profileDir = "C:\AllBirdies\SessionDisplay\edge-profile" }

    # Desired display role for signage
    $role = Get-PropValue $sdPayload "displayRole" (Get-PropValue $sdCfg "displayRole" $null)
    if ([string]::IsNullOrWhiteSpace([string]$role)) { $role = "session" }

    # Compute target bounds up-front so we can spawn the window on the correct monitor
    $targetBounds = $null
    try {
        $screen = Get-ScreenForRole $role $payloadObj
        if ($null -ne $screen) { $targetBounds = $screen.Bounds }
    } catch {}

    # Find ALL Edge processes using our dedicated profile dir (browser + renderer processes)
    function Get-EdgePidsForProfile([string]$pdir) {
        $ids = @()
        try {
            $edgeCim = Get-CimInstance Win32_Process -Filter "Name='msedge.exe'" -OperationTimeoutSec 2 -ErrorAction SilentlyContinue
            foreach ($p in $edgeCim) {
                $cmd = $p.CommandLine
                if ($null -ne $cmd -and $cmd -like "*$pdir*") { $ids += [int]$p.ProcessId }
            }
        } catch {}
        return $ids
    }

    function Pick-EdgePidWithWindow([int[]]$pids) {
        foreach ($id in $pids) {
            try {
                $h = Get-FirstVisibleWindowHandleForPid $id
                if ($h -ne [IntPtr]::Zero) { return $id }
            } catch {}
        }
        if ($pids.Count -gt 0) { return $pids[0] }
        return $null
    }

    $existingPids = @(Get-EdgePidsForProfile $profileDir)

    if ($existingPids.Count -gt 0) {
        # IMPORTANT: pick the PID that actually owns the visible window (Edge spawns many processes)
        $pidToUse = Pick-EdgePidWithWindow $existingPids
        if ($null -eq $pidToUse) { $pidToUse = $existingPids[0] }

        $Global:SessionDisplayProcId = $pidToUse
        $Global:SessionDisplayUrl = $url

        # Best-effort route to the Session screen and maximize
        try { $null = Safe-RouteProcessWindow -context "SessionDisplay:already_running" -ProcessId ([int]$pidToUse) -role $role -payloadObj $payloadObj -Maximize } catch {}

        return @{ started = $false; reason = "already_running"; mode = $mode; url = $url; pid = $pidToUse; procId = $pidToUse; profileDir = $profileDir }
    }

    # Tag the Session Display Edge instance with a dedicated profile directory.
    # This makes EndSession/Reset reliable even if other Edge windows are open.
    $args = "--allow-file-access-from-files --user-data-dir=$profileDir --no-first-run --no-default-browser-check "

    # Spawn on the correct monitor (best effort). Works well for multi-monitor layouts.
    if ($null -ne $targetBounds) {
        $args += "--window-position=$($targetBounds.Left),$($targetBounds.Top) --window-size=$($targetBounds.Width),$($targetBounds.Height) "
    }

    if ($mode -eq "kiosk") {
        # Fullscreen signage mode (no borders, no taskbar)
        $args += "--kiosk ""$url"" --edge-kiosk-type=fullscreen --kiosk-idle-timeout-minutes=0"
    } else {
        # App mode (borderless-ish); start fullscreen improves reliability
        $args += "--app=""$url"" --start-fullscreen"
    }

    $proc = Start-Process -FilePath $edgePath -ArgumentList $args -PassThru

    # Edge may spawn multiple processes; route the PID that actually owns the visible window.
    $pidToRoute = $proc.Id
    $deadline = (Get-Date).AddSeconds(10)
    do {
        try {
            $h = Get-FirstVisibleWindowHandleForPid $pidToRoute
            if ($h -ne [IntPtr]::Zero) { break }
        } catch {}

        # Rescan and pick a PID with a window for our profile dir
        $pids = @(Get-EdgePidsForProfile $profileDir)
        $pick = Pick-EdgePidWithWindow $pids
        if ($null -ne $pick) { $pidToRoute = $pick; break }

        Start-Sleep -Milliseconds 250
    } while ((Get-Date) -lt $deadline)

    $Global:SessionDisplayProcId = $pidToRoute
    $Global:SessionDisplayUrl = $url

    # Persist a tiny bit of state so EndSession works even if the agent is restarted
    try {
        $state = @{
            pid        = $pidToRoute
            procId     = $pidToRoute
            url        = $url
            profileDir = $profileDir
            startedUtc = (Get-Date).ToUniversalTime().ToString("o")
        }
        Write-JsonAtomic -path $Global:SessionDisplayStatePath -obj $state
    } catch { }

    # Route to Session screen and maximize (best effort)
    try { $null = Safe-RouteProcessWindow -context "SessionDisplay:started" -ProcessId ([int]$pidToRoute) -role $role -payloadObj $payloadObj -Maximize } catch {}

    return @{ started = $true; mode = $mode; edgePath = $edgePath; url = $url; pid = $pidToRoute; procId = $pidToRoute; profileDir = $profileDir }
}



function Start-GenericProcess($payloadObj) {
    if ($null -eq $payloadObj) { throw "StartProcess payload must be valid JSON." }

    $path = Get-PropValue $payloadObj "path" $null
    $args = Get-PropValue $payloadObj "args" $null

    # Step 7 hardening: prevent StartProcess from bypassing execution policy or running inline PowerShell.
    # (All scripts must run under LocalMachine=AllSigned; do NOT allow -ExecutionPolicy Bypass / -EncodedCommand.)
    $argsText = [string]$args
    if (-not [string]::IsNullOrWhiteSpace($argsText)) {
        $al = $argsText.ToLowerInvariant()

        $badTokens = @(
            "-executionpolicy bypass",
            "-ep bypass",
            "-executionpolicy unrestricted",
            "-encodedcommand",
            "-enc "
        )

        foreach ($t in $badTokens) {
            if ($al.Contains($t)) {
                throw "StartProcess args contains disallowed token '$t'. Remove it and rely on AllSigned."
            }
        }

        # If launching PowerShell, require -File <script> under C:\AllBirdies\BayAgent and block -Command.
        $leaf = ([IO.Path]::GetFileName([string]$path)).ToLowerInvariant()
        if ($leaf -in @("powershell.exe","pwsh.exe")) {
            if ($al -match "\s-(command|c)\s+") { throw "StartProcess launching PowerShell cannot use -Command/-c. Use -File <script>." }

            $m = [regex]::Match($argsText, '(?i)\s-file\s+("([^"]+)"|(\S+))')
            if (-not $m.Success) { throw "StartProcess launching PowerShell must use -File <script> (no inline commands)." }

            $scriptPath = $m.Groups[2].Value
            if ([string]::IsNullOrWhiteSpace($scriptPath)) { $scriptPath = $m.Groups[3].Value }
            $scriptPath = $scriptPath.Trim()

            if ([string]::IsNullOrWhiteSpace($scriptPath)) { throw "StartProcess PowerShell args must include a script path after -File." }

            $allowedBase = $BaseDir
            if (-not ($scriptPath.ToLowerInvariant().StartsWith($allowedBase.ToLowerInvariant()))) {
                throw "StartProcess PowerShell scripts must be under $allowedBase. Got: $scriptPath"
            }
        }
    }

    if ([string]::IsNullOrWhiteSpace([string]$path)) { throw "StartProcess requires payload.path" }

    if (!(Test-Path $path)) { throw "Executable not found: $path" }

    # Write the agent's Dataverse token to a temp file so child scripts (e.g. Update-BayAgent.ps1)
    # can authenticate to Dataverse file downloads without exposing the token in process arguments.
    $leaf = ([IO.Path]::GetFileName([string]$path)).ToLowerInvariant()
    if ($leaf -in @("powershell.exe","pwsh.exe")) {
        try {
            $dvTok = Get-AccessToken
            if (-not [string]::IsNullOrWhiteSpace($dvTok)) {
                $tokFile = Join-Path $BaseDir "control\dvtoken.tmp"
                [IO.File]::WriteAllText($tokFile, $dvTok)
            }
        } catch {
            Write-Log "WARNING: Could not write dvtoken.tmp for child process: $($_.Exception.Message)"
        }
    }

    # started=true MEANS "THE PROCESS LAUNCHED", NOT "THE WORK SUCCEEDED", and the difference is the whole
    # bench-day failure mode. This is how a fleet update is triggered: the BayCommand result is written from
    # this return value, so a StartProcess that hands off to Update-BayAgent.ps1 reports Succeeded the instant
    # powershell.exe exists -- even when the updater dies a second later having installed nothing. The real
    # case is a bay PC with no code-signing certificate: Get-CodeSigningCert throws, and before this round it
    # threw into silence. The updater now writes a durable result marker that the heartbeat carries
    # (lastUpdateResult), so the command result can be reconciled against what actually happened.
    #
    # What is fixed HERE is narrower and still worth having: a launch that THROWS must not be reported as a
    # launch that worked.
    try {
        if ([string]::IsNullOrWhiteSpace([string]$args)) {
            $p = Start-Process -FilePath $path -PassThru
        } else {
            $p = Start-Process -FilePath $path -ArgumentList $args -PassThru
        }
    } catch {
        Write-Log ("StartProcess FAILED to launch '{0}': {1}" -f $path, $_.Exception.Message) "ERROR"
        return @{
            started = $false
            path = $path
            args = $args
            error = $_.Exception.Message
            note = "the process did not launch; nothing ran"
        }
    }

    return @{
        started = $true
        launchedOnly = $true   # says what started=true does and does not claim; see lastUpdateResult
        path = $path
        args = $args
        pid = $p.Id
    }
}

function Stop-GenericProcess($payloadObj) {
    if ($null -eq $payloadObj) { throw "StopProcess payload must be valid JSON." }

    $force = [bool](Get-PropValue $payloadObj "force" $false)

    $procId = Get-PropValue $payloadObj "pid" $null
    if ($null -eq $procId) { $procId = Get-PropValue $payloadObj "procId" $null }

    if ($null -ne $procId) {
        Stop-Process -Id ([int]$procId) -Force:$force -ErrorAction Stop
        return @{ stopped = $true; mode = "pid"; pid = [int]$procId; force = $force }
    }

    $processName = Get-PropValue $payloadObj "processName" $null
    if (-not [string]::IsNullOrWhiteSpace([string]$processName)) {
        $base = [System.IO.Path]::GetFileNameWithoutExtension([string]$processName)
        $procs = Get-Process -Name $base -ErrorAction SilentlyContinue
        if (-not $procs) { return @{ stopped = $false; mode = "name"; processName = $processName; reason = "not_running" } }
        $ids = @($procs | Select-Object -ExpandProperty Id)
        $procs | Stop-Process -Force:$force -ErrorAction Stop
        return @{ stopped = $true; mode = "name"; processName = $processName; pids = $ids; force = $force }
    }

    throw "StopProcess requires payload.pid (or procId) or payload.processName"
}

function Query-GenericProcess($payloadObj) {
    if ($null -eq $payloadObj) { throw "QueryProcess payload must be valid JSON." }

    $procId = Get-PropValue $payloadObj "pid" $null
    if ($null -eq $procId) { $procId = Get-PropValue $payloadObj "procId" $null }

    if ($null -ne $procId) {
        $p = Get-Process -Id ([int]$procId) -ErrorAction SilentlyContinue
        return @{ mode = "pid"; pid = [int]$procId; running = ($null -ne $p) }
    }

    $processName = Get-PropValue $payloadObj "processName" $null
    if (-not [string]::IsNullOrWhiteSpace([string]$processName)) {
        $base = [System.IO.Path]::GetFileNameWithoutExtension([string]$processName)
        $procs = Get-Process -Name $base -ErrorAction SilentlyContinue
        return @{ mode = "name"; processName = $processName; running = [bool]$procs; count = ($procs | Measure-Object).Count; pids = @($procs | Select-Object -ExpandProperty Id) }
    }

    throw "QueryProcess requires payload.pid (or procId) or payload.processName"
}


function Stop-SessionDisplay {
    # Close the visible Session Display window reliably.
    # We strongly prefer killing Edge processes that are using our dedicated profile directory.
    $url = $Global:SessionDisplayUrl
    $profileDir = $Global:SessionDisplayProfileDir
    $rootPid = $Global:SessionDisplayProcId

    # Recover state if needed (e.g., agent restarted)
    try {
        if (Test-Path $Global:SessionDisplayStatePath) {
            $st = (Get-Content $Global:SessionDisplayStatePath -Raw -Encoding UTF8) | ConvertFrom-Json
            if ([string]::IsNullOrWhiteSpace([string]$url)) { $url = Get-PropValue $st "url" $url }
            if ([string]::IsNullOrWhiteSpace([string]$profileDir)) { $profileDir = Get-PropValue $st "profileDir" $profileDir }
            if ($null -eq $rootPid) { $rootPid = Get-PropValue $st "procId" $rootPid }
            if ($null -eq $rootPid) { $rootPid = Get-PropValue $st "pid" $rootPid }
        }
    } catch { }

    if ([string]::IsNullOrWhiteSpace([string]$url)) { $url = "file:///C:/AllBirdies/SessionDisplay/index.html" }
    if ([string]::IsNullOrWhiteSpace([string]$profileDir)) { $profileDir = "C:\AllBirdies\SessionDisplay\edge-profile" }

    $pids = New-Object System.Collections.Generic.HashSet[int]

    function Add-Pid([int]$procId) {
        if ($procId -gt 0) { [void]$pids.Add($procId) }
    }

    function Add-Children([int[]]$parents) {
        foreach ($pp in $parents) {
            try {
                $kids = Get-CimInstance Win32_Process -Filter "ParentProcessId=$pp" -OperationTimeoutSec 2 -ErrorAction SilentlyContinue |
                        Select-Object -ExpandProperty ProcessId
                foreach ($k in $kids) { Add-Pid ([int]$k) }
            } catch { }
        }
    }

    # 1) Strongest match: Edge processes that include our profile directory in the command line.
    try {
        $edgeCim = Get-CimInstance Win32_Process -Filter "Name='msedge.exe'" -OperationTimeoutSec 2 -ErrorAction SilentlyContinue
        foreach ($p in $edgeCim) {
            $cmd = $p.CommandLine
            if ($null -ne $cmd -and $cmd -like "*$profileDir*") {
                Add-Pid ([int]$p.ProcessId)
            }
        }
    } catch { }

    # Add children of those matches (helps close the actual window)
    try { Add-Children @($pids) } catch { }

    # 2) Window-title match (fallback)
    try {
        $edge = Get-Process -Name msedge -ErrorAction SilentlyContinue
        foreach ($p in $edge) {
            $t = $p.MainWindowTitle
            if (-not [string]::IsNullOrWhiteSpace($t) -and $t -like "*ABG Session Display*") {
                Add-Pid ([int]$p.Id)
            }
        }
    } catch { }

    # 3) URL match (last resort)
    try {
        $edgeCim2 = Get-CimInstance Win32_Process -Filter "Name='msedge.exe'" -OperationTimeoutSec 2 -ErrorAction SilentlyContinue
        foreach ($p in $edgeCim2) {
            $cmd = $p.CommandLine
            if ($null -ne $cmd -and $cmd -like "*$url*") {
                Add-Pid ([int]$p.ProcessId)
            }
        }
    } catch { }

    # 4) Fallback: root pid (if we have it)
    if ($null -ne $rootPid) { Add-Pid ([int]$rootPid) }

    $killList = @($pids | Sort-Object -Descending)
    if ($killList.Count -eq 0) {
        return @{ stopped = $false; reason = "not_found"; url = $url; profileDir = $profileDir }
    }

    foreach ($id in $killList) {
        try { Stop-Process -Id $id -Force -ErrorAction SilentlyContinue } catch { }
    }

    # Clear state
    $Global:SessionDisplayProcId = $null
    # NOTE: this function must never touch the emergency-stop latch. It is cleared only by the explicit
    # EmergencyStop command with action=clear (Clear-EmergencyStopInternal).
    $Global:SessionDisplayUrl = $null
    try { if (Test-Path $Global:SessionDisplayStatePath) { Remove-Item $Global:SessionDisplayStatePath -Force -ErrorAction SilentlyContinue } } catch { }

    return @{ stopped = $true; url = $url; profileDir = $profileDir; killedPids = $killList }
}

# ---------------- Credential lifecycle (CredentialRotate command, -EnrollCert) ----------------
# The rotation contract, in order:
#   enroll   - mint a NEW non-exportable key pair on this machine; publish the PUBLIC cert (result JSON +
#              state\bay-cert-<tp>.cer); record it as PENDING. The old credential keeps working.
#   (Entra)  - the operator registers the public cert on the app (keyCredential). Nothing on the bay changes.
#   test     - prove a named / pending certificate mints a real token. Changes nothing.
#   activate - prove the candidate mints a token, THEN switch the active thumbprint and drop the cached token.
#              A failed proof leaves the active credential untouched (the command is marked Failed).
#   (Entra)  - once the heartbeat shows credential.lastMintMode = "certificate", the operator deletes the old
#              secret / old certificate on the app.
#   retire   - remove an old certificate from the store, and/or the DPAPI secret file (only after a live proof
#              that the active certificate mints). The active credential can never be retired.
function New-BayClientCertificate {
    param(
        [string]$Subject = "",
        [int]$ValidityDays = 730,
        [string]$Store = "CurrentUser",
        [string]$KeyProvider = "",
        [int]$KeyLength = 2048
    )
    if ([string]::IsNullOrWhiteSpace($Subject)) { $Subject = "CN=ABG-BayAgent $BayId" }
    if ($Store -notin @("CurrentUser", "LocalMachine")) { throw "store must be CurrentUser or LocalMachine" }
    if ($ValidityDays -lt 30 -or $ValidityDays -gt 1825) { throw "validityDays must be between 30 and 1825" }
    # 4096 is deliberately NOT offered over the BayCommand path. MEASURED 2026-08-29: an RSA-4096 public cert is
    # 1808 base64 chars, and the enroll result carrying it is 2324 - over build_resultjson's 2000-char cap even
    # after Limit-ResultJson has dropped every optional field. The cert would then be reachable only by reading
    # state\bay-cert-<tp>.cer ON the machine, which defeats the entire point of remote enrollment. 2048 is the
    # Entra default for certificate credentials and is not the weak link in a 2-year bay credential.
    if ($KeyLength -notin @(2048, 3072)) { throw "keyLength must be 2048 or 3072 (4096 does not fit build_resultjson's 2000-char cap, so its public cert could not be returned remotely)" }
    if ($Subject.Length -gt 120) { throw "subject must be 120 characters or fewer (it shares build_resultjson's 2000-char budget with the public certificate)" }
    # Closed set, not free text: keyProvider reaches New-SelfSignedCertificate -Provider from a caller-supplied
    # payload, and an allow-list is cheaper than reasoning about what an arbitrary provider name can do.
    if ([string]::IsNullOrWhiteSpace($KeyProvider)) { $KeyProvider = "Microsoft Software Key Storage Provider" }
    elseif ($KeyProvider -ieq "tpm") { $KeyProvider = "Microsoft Platform Crypto Provider" }
    elseif ($KeyProvider -ieq "software") { $KeyProvider = "Microsoft Software Key Storage Provider" }
    else { throw "keyProvider must be 'software' or 'tpm' (got '$KeyProvider')" }

    # Non-exportable: the private key can be USED by this account but never copied off the machine. The client
    # authentication EKU is cosmetic for Entra (it keys on the thumbprint) but documents the intent.
    $cert = New-SelfSignedCertificate `
        -Type Custom `
        -Subject $Subject `
        -CertStoreLocation "Cert:\$Store\My" `
        -KeyAlgorithm RSA -KeyLength $KeyLength -HashAlgorithm sha256 `
        -KeyExportPolicy NonExportable `
        -KeyUsage DigitalSignature `
        -TextExtension @("2.5.29.37={text}1.3.6.1.5.5.7.3.2") `
        -Provider $KeyProvider `
        -NotAfter (Get-Date).AddDays($ValidityDays) `
        -FriendlyName ("ABG BayAgent credential " + (Get-Date).ToUniversalTime().ToString("yyyy-MM-dd"))
    if (-not $cert.HasPrivateKey) { throw "Certificate created but no private key present" }

    # Re-read through the provider so the object carries its store path (PSParentPath).
    $stored = Get-ChildItem -LiteralPath ("Cert:\{0}\My\{1}" -f $Store, $cert.Thumbprint) -ErrorAction SilentlyContinue
    if ($stored) { return $stored }
    return $cert
}

function Export-PublicCertificate($cert) {
    $dir = Join-Path $BaseDir "state"
    if (!(Test-Path $dir)) { New-Item -ItemType Directory -Force -Path $dir | Out-Null }
    $path = Join-Path $dir ("bay-cert-{0}.cer" -f $cert.Thumbprint)
    [IO.File]::WriteAllBytes($path, $cert.RawData)     # DER, public half only
    return $path
}

function Build-CredentialEnrollResult($cert, [string]$cerPath, [bool]$reused, [bool]$activatedDirectly) {
    return [ordered]@{
        ok                = $true
        action            = "enroll"
        reused            = $reused
        activatedDirectly = $activatedDirectly
        thumbprint        = $cert.Thumbprint
        subject           = $cert.Subject
        store             = (Get-CertStoreName $cert)
        notBeforeUtc      = $cert.NotBefore.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
        notAfterUtc       = $cert.NotAfter.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
        publicCertBase64  = [Convert]::ToBase64String($cert.RawData)   # DER; register this as the app's certificate credential
        publicCertPath    = $cerPath
        next              = $(if ($activatedDirectly) { "Register publicCertBase64 on the Entra app, then run BayAgent.ps1 -TokenOnly (or send CredentialRotate action=test) to prove the mint" } else { "Register publicCertBase64 on the Entra app, then send CredentialRotate action=activate" })
    }
}

function Invoke-CredentialEnroll($payloadObj) {
    if ($null -eq $payloadObj) { $payloadObj = @{} }
    $force = [bool](Get-PropValue $payloadObj "force" $false)

    $pending = Get-PendingCertThumbprint
    if ($pending -and -not $force) {
        $existing = Find-ClientCertificate $pending
        if ($existing) {
            # Idempotent: a retried enroll returns the pending certificate instead of minting another key pair.
            return (Build-CredentialEnrollResult -cert $existing -cerPath (Export-PublicCertificate $existing) -reused $true -activatedDirectly $false)
        }
    }

    $cert = New-BayClientCertificate `
        -Subject      ([string](Get-PropValue $payloadObj "subject" "")) `
        -ValidityDays ([int](Get-PropValue $payloadObj "validityDays" 730)) `
        -Store        ([string](Get-PropValue $payloadObj "store" "CurrentUser")) `
        -KeyProvider  ([string](Get-PropValue $payloadObj "keyProvider" "")) `
        -KeyLength    ([int](Get-PropValue $payloadObj "keyLength" 2048))
    $cerPath = Export-PublicCertificate $cert
    $nowStr = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")

    # A bay with NO credential at all (fresh Day-0) has nothing to protect and nothing to prove against: the new
    # certificate becomes active at once. Any bay that already has a credential gets a PENDING certificate.
    #
    # THIS ASKS WHETHER A SECRET ACTUALLY WORKS, NOT WHETHER THE CONFIG MENTIONS ONE. $HasSecretCredential
    # is computed at startup from the mere PRESENCE of clientSecretDpapiPath in agent-config.json, before
    # anything checks that the file exists. The shipped agent-config.json names that path, so a fresh Day-0 bay
    # that had not yet run the DPAPI setup looked to this line like a bay with a working secret: the new
    # certificate went PENDING instead of ACTIVE, nothing could activate it (no credential to mint with), and
    # the next startup threw on the missing DPAPI file. A bay with no credential could not enroll its way to
    # one. Found by independent attack, 2026-09-14.
    $activeTp = Get-ActiveCertThumbprint
    $activateNow = (-not $activeTp) -and (-not (Test-HasUsableSecret))
    if ($activateNow) {
        Update-CredentialState @{ activeThumbprint = $cert.Thumbprint; pendingThumbprint = $null; activatedUtc = $nowStr; enrolledUtc = $nowStr } | Out-Null
        Write-Log ("Credential enrolled AND activated (no prior credential): certificate {0} notAfter={1}; public cert at {2}" -f $cert.Thumbprint, $cert.NotAfter.ToUniversalTime().ToString("yyyy-MM-dd"), $cerPath) "INFO"
    } else {
        # A pending certificate being REPLACED leaves a non-exportable private key on the machine. If its
        # thumbprint is not written down, nothing points at it any more: it cannot be found by the ownership
        # guard, so it cannot be retired, and it sits there for the life of the box. Record it.
        $changes = @{ pendingThumbprint = $cert.Thumbprint; enrolledUtc = $nowStr }
        $displaced = Get-PendingCertThumbprint
        if ($displaced -and $displaced -ne $cert.Thumbprint) {
            $sup = @()
            $priorSup = Get-PropValue (Read-CredentialState) "superseded" $null
            if ($priorSup) { $sup = @($priorSup) }
            if ($sup -notcontains $displaced) { $sup += $displaced }
            $changes.superseded = $sup
            Write-Log ("Credential enroll SUPERSEDED pending certificate {0}; recorded so its orphaned private key can still be retired" -f $displaced) "WARN"
        }
        Update-CredentialState $changes | Out-Null
        Write-Log ("Credential enrolled as PENDING: certificate {0} notAfter={1}; public cert at {2}. Register it in Entra, then activate." -f $cert.Thumbprint, $cert.NotAfter.ToUniversalTime().ToString("yyyy-MM-dd"), $cerPath) "INFO"
    }
    return (Build-CredentialEnrollResult -cert $cert -cerPath $cerPath -reused $false -activatedDirectly $activateNow)
}

function Invoke-CredentialTest($payloadObj) {
    if ($null -eq $payloadObj) { $payloadObj = @{} }
    $tp = Normalize-Thumbprint ([string](Get-PropValue $payloadObj "thumbprint" ""))
    if (-not $tp) { $tp = Get-PendingCertThumbprint }
    if (-not $tp) { $tp = Get-ActiveCertThumbprint }
    $nowStr = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")

    $res = [ordered]@{ ok = $false; action = "test"; certificate = $null; secret = $null }
    # A0.458: clientId tests the certificate against the bay's own app (a GUID, or nothing).
    $testClient = ConvertTo-AgentGuid ([string](Get-PropValue $payloadObj "clientId" ""))
    if ($tp) {
        try {
            $j = Acquire-TokenWithCertificate -Thumbprint $tp -ForClientId $(if ($testClient) { $testClient } else { "" })
            $res.certificate = [ordered]@{ ok = $true; thumbprint = $tp; expiresIn = $j.expires_in }
        } catch {
            $res.certificate = [ordered]@{ ok = $false; thumbprint = $tp; error = $_.Exception.Message }
        }
        $Global:CredentialTelemetry.lastTest = [ordered]@{ utc = $nowStr; thumbprint = $tp; ok = $res.certificate.ok }
    } else {
        $res.certificate = [ordered]@{ ok = $false; error = "no certificate thumbprint given, pending, or active" }
    }

    if ([bool](Get-PropValue $payloadObj "includeSecret" $false)) {
        if ($HasSecretCredential) {
            try {
                $j2 = Acquire-TokenWithSecret
                $res.secret = [ordered]@{ ok = $true; expiresIn = $j2.expires_in; source = $(if ($SecretPath) { "dpapi" } else { "plaintext" }) }
            } catch {
                $res.secret = [ordered]@{ ok = $false; error = $_.Exception.Message }
            }
        } else {
            $res.secret = [ordered]@{ ok = $false; configured = $false }
        }
    }

    $res.ok = ($res.certificate.ok -eq $true)
    return $res
}

function Invoke-CredentialActivate($payloadObj) {
    if ($null -eq $payloadObj) { $payloadObj = @{} }
    $tp = Normalize-Thumbprint ([string](Get-PropValue $payloadObj "thumbprint" ""))
    if (-not $tp) { $tp = Get-PendingCertThumbprint }
    if (-not $tp) { throw "activate: no thumbprint given and no pending certificate enrolled" }

    # A0.458: clientId names the bay's OWN app the certificate signs in as. Absent = the app already in force.
    $rawClient = [string](Get-PropValue $payloadObj "clientId" "")
    $newClient = $null
    if (-not [string]::IsNullOrWhiteSpace($rawClient)) {
        $newClient = ConvertTo-AgentGuid $rawClient
        if (-not $newClient) { throw "activate: clientId must be a GUID (got '$rawClient')" }
    }
    $prevClient = Get-ActiveClientId
    $switching = ($null -ne $newClient) -and ($newClient -ne $prevClient)
    $mintClient = $(if ($newClient) { $newClient } else { $prevClient })

    $cert = Find-ClientCertificate $tp
    if (-not $cert) { throw "activate: certificate $tp with a private key not found in $((Get-CertStoreSearchOrder) -join ', ')" }

    # PROVE before switching. A real token mint with the candidate; if this throws nothing below runs and the
    # active credential is untouched (Process-Command marks the command Failed with the AADSTS code).
    # An identity SWITCH is proven further: Dataverse, this bay's row and the command guard must all accept it, or the bay
    # would be left on an identity that cannot run its commands (Test-IdentityCandidate).
    $proofDetail = $null
    if ($switching) {
        if ($Global:CredentialStateCorrupt) { throw "activate: credential.json is corrupt; an identity switch is never recorded over it" }
        if ($null -ne (Get-IdentityProbation)) { throw "activate: an identity switch is already on probation; confirm or revert it first" }
        $proofDetail = Test-IdentityCandidate -Thumbprint $tp -ForClientId $newClient
        $j = [pscustomobject]@{ expires_in = $null }
    } else {
        $j = Acquire-TokenWithCertificate -Thumbprint $tp -ForClientId $mintClient
    }

    $prevActive = Get-ActiveCertThumbprint
    $nowStr = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
    $changes = @{ activeThumbprint = $tp; activatedUtc = $nowStr }
    if ((Get-PendingCertThumbprint) -eq $tp) { $changes.pendingThumbprint = $null }
    if ($prevActive -and $prevActive -ne $tp) { $changes.previousThumbprint = $prevActive }
    if ($switching) {
        $changes.activeClientId = $newClient
        $changes.identityProbation = [ordered]@{
            clientId           = $newClient
            sinceUtc           = $nowStr
            previousThumbprint = $prevActive
            previousClientId   = $(if ($prevClient -ne (ConvertTo-AgentGuid $ClientId)) { $prevClient } else { $null })
        }
        $changes.identityReverted = $null
    }
    Update-CredentialState $changes | Out-Null
    $Global:IdentityProbationFailures = 0

    # Drop the cached token so the very next loop iteration mints with the new certificate.
    $Global:AccessToken = $null
    $Global:TokenExpiresUtc = [DateTime]::MinValue

    Write-Log ("Credential activated: certificate {0} is now the active credential (previous: {1}){2}" -f $tp, $(if ($prevActive) { $prevActive } else { "secret" }), $(if ($switching) { " signing in as the bay's own app $newClient, ON PROBATION" } else { "" })) "INFO"
    return [ordered]@{
        ok                 = $true
        action             = "activate"
        activeThumbprint   = $tp
        activeClientId     = (Get-ActiveClientId)
        identitySwitched   = $switching
        previousThumbprint = $prevActive
        notAfterUtc        = $cert.NotAfter.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
        proof              = $(if ($switching) { $proofDetail } else { [ordered]@{ mintedWithCertificate = $true; expiresIn = $j.expires_in } })
        next               = $(if ($switching) { "On probation: the agent goes back on its own if this identity is refused, or if nobody confirms within $IdentityProbationMaxHours h. After the next heartbeat run the operator ladder's activate; after a day of normal running send action=confirm." } else { "Wait for a heartbeat showing credential.lastMintMode = certificate, THEN delete the old secret/certificate on the Entra app, THEN send action=retire" })
    }
}

function Invoke-CredentialConfirm {
    # A0.458: end the probation of an identity switch. Running at all proves the new identity can claim a command (the
    # claim is the command guard's agent-only write); a live mint is proven again here.
    $p = Get-IdentityProbation
    if ($null -eq $p) { throw "confirm: no identity switch is on probation" }
    if (-not (Test-OwnIdentityActive)) { throw "confirm: the active credential is not the bay's own identity" }
    $tp = Get-ActiveCertThumbprint
    $client = Get-ActiveClientId
    $null = Acquire-TokenWithCertificate -Thumbprint $tp -ForClientId $client
    $nowStr = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
    Update-CredentialState @{ identityProbation = $null; identityConfirmedUtc = $nowStr; identityConfirmedClientId = $client } | Out-Null
    $Global:IdentityProbationFailures = 0
    Write-Log ("[IDENTITY] confirmed: app {0} with certificate {1}" -f $client, $tp) "INFO"
    return [ordered]@{
        ok = $true; action = "confirm"; activeClientId = $client; activeThumbprint = $tp
        next = "The switch is final. Retire the shared secret on this bay (action=retire with the secret flag) once the operator is ready; revoking this bay is then complete without touching the shared app."
    }
}

function Invoke-CredentialRevert {
    # A0.458: undo an identity switch still on probation, on an operator's word.
    if ($null -eq (Get-IdentityProbation)) { throw "revert: no identity switch is on probation (a confirmed identity changes only by a new activate)" }
    if (-not (Invoke-IdentityRevert -Reason "operator: CredentialRotate action=revert")) { throw "revert: the switch could not be undone (see the agent log)" }
    return [ordered]@{ ok = $true; action = "revert"; activeClientId = (Get-ActiveClientId); activeThumbprint = (Get-ActiveCertThumbprint) }
}

function Test-IsAgentOwnedCertificate {
    # SECURITY BOUNDARY. retire is the only action that DESTROYS something, and its thumbprint comes
    # straight from a caller-supplied BayCommand payload. Without this predicate the payload is a
    # delete-any-certificate-with-its-private-key primitive against both of the agent account's stores -
    # which has nothing to do with credential rotation and is not a capability this command should carry.
    # A certificate is retirable ONLY if this agent RECORDED it in credential.json.
    #
    # THIS USED TO ALSO ACCEPT A SUBJECT PREFIX ("CN=ABG-BayAgent*"), AND THAT WAS A HOLE. A subject is
    # not a fact about provenance -- it is a string the creator chooses. Anyone who can run
    # New-SelfSignedCertificate on the box can name a certificate "CN=ABG-BayAgent anything" and have retire
    # destroy it, private key and all. The prefix branch re-opened, in weaker form, the delete-any-certificate
    # primitive the record branch was added to close. Found by independent attack, 2026-09-14.
    #
    # Every certificate this agent legitimately creates is recorded the moment it is created:
    # Invoke-CredentialEnroll writes activeThumbprint or pendingThumbprint before it returns, a superseded
    # pending certificate is pushed onto `superseded`, and retire pushes onto `retiredThumbprints`. So the
    # record branch alone covers the whole legitimate set, and nothing else on the machine is in scope.
    param([Parameter(Mandatory=$true)][string]$Thumbprint)
    $tp = Normalize-Thumbprint $Thumbprint
    if (-not $tp) { return $false }

    $st = Read-CredentialState
    foreach ($k in @("pendingThumbprint", "previousThumbprint", "activeThumbprint")) {
        $v = $null
        try { $v = Normalize-Thumbprint ([string](Get-PropValue $st $k "")) } catch {}
        if ($v -eq $tp) { return $true }
    }
    foreach ($listKey in @("retiredThumbprints", "superseded")) {
        $prior = Get-PropValue $st $listKey $null
        if ($prior) { foreach ($r in @($prior)) { if (("$r").ToUpperInvariant() -eq $tp) { return $true } } }
    }

    return $false
}

function Invoke-CredentialRetire($payloadObj) {
    if ($null -eq $payloadObj) { $payloadObj = @{} }
    $tp = Normalize-Thumbprint ([string](Get-PropValue $payloadObj "thumbprint" ""))
    $retireSecret = [bool](Get-PropValue $payloadObj "secret" $false)
    if (-not $tp -and -not $retireSecret) { throw "retire: give thumbprint and/or secret=true" }

    $active = Get-ActiveCertThumbprint

    # A CORRUPT STATE FILE DISQUALIFIES THE ONLY ACTION THAT DESTROYS SOMETHING.
    # Get-ActiveCertThumbprint falls back to agent-config.json's clientCertThumbprint whenever state names
    # none -- and a corrupt state file names none, because Read-CredentialState returns $null on corruption.
    # So without this, a corrupt state file silently promotes the CONFIG value to "active", and
    # retire secret=true (which needs only a non-null $active that mints) would delete the DPAPI file on the
    # strength of a credential the agent inferred while declaring its own records untrustworthy. The mint
    # proof is live, so the bay would keep working -- which is exactly what makes it the wrong kind of
    # failure: nothing looks broken. Found by independent verification, 2026-09-14.
    if ($Global:CredentialStateCorrupt) {
        throw "retire: credential.json is corrupt, so which certificate is active cannot be established. Recover it from $CredentialStatePath.bak first. Refusing to destroy anything on an inferred credential."
    }

    $result = [ordered]@{ ok = $true; action = "retire" }

    # ---- PHASE 1: every check, and the live proof, BEFORE anything is destroyed. ----
    #
    # THE ORDER IS THE CONTROL. This used to delete the named certificate first and only then perform the
    # live mint proof for secret=true. A combined {thumbprint, secret:true} payload whose proof failed had
    # already destroyed a private key by the time it threw, and there is no rollback for a destroyed private
    # key -- the whole point of a non-exportable key is that no copy exists. Found by independent attack,
    # 2026-09-14. Prove first. Delete after. Nothing between the two can fail.
    if ($tp) {
        # The credential the loop is living on is never removed.
        if ($tp -eq $active) { throw "retire: $tp is the ACTIVE credential; activate another certificate first" }
        # ...and nothing this agent recorded is removable at all.
        if (-not (Test-IsAgentOwnedCertificate -Thumbprint $tp)) { throw "retire: $tp is not an agent-owned certificate (its thumbprint must be recorded in credential.json as active, pending, previous, superseded or already retired); refusing to delete it" }
    }

    $secretProofTp = $null
    if ($retireSecret) {
        if (-not $active) { throw "retire secret: no active certificate; refusing to remove the only credential" }
        # Live proof RIGHT NOW that the active certificate mints - not a cached token, not a remembered success.
        $null = Acquire-TokenWithCertificate -Thumbprint $active
        $secretProofTp = $active
    }

    # ---- PHASE 2: destroy. Every precondition above has passed. ----
    if ($tp) {
        $removedFrom = @()
        foreach ($store in (Get-CertStoreSearchOrder)) {
            $p = "$store\$tp"
            if (Test-Path -LiteralPath $p) {
                Remove-Item -LiteralPath $p -DeleteKey -Force
                $removedFrom += $store
            }
        }
        $changes = @{}
        if ((Get-PendingCertThumbprint) -eq $tp) { $changes.pendingThumbprint = $null }
        $st = Read-CredentialState
        if ([string](Get-PropValue $st "previousThumbprint" "") -eq $tp) { $changes.previousThumbprint = $null }
        $retired = @()
        $prior = Get-PropValue $st "retiredThumbprints" $null
        if ($prior) { $retired = @($prior) }
        $retired += $tp
        $changes.retiredThumbprints = $retired
        Update-CredentialState $changes | Out-Null
        $result.certificate = [ordered]@{ thumbprint = $tp; removedFrom = $removedFrom; wasInStore = ($removedFrom.Count -gt 0) }
        Write-Log ("Credential retired: certificate {0} removed from {1}" -f $tp, $(if ($removedFrom.Count) { $removedFrom -join ", " } else { "(not present)" })) "INFO"
    }

    if ($retireSecret) {
        # The proof already ran in phase 1; $secretProofTp names the certificate that carried it.
        # BOTH outcome fields are always stated, never implied by the presence or absence of a note: a reader
        # (and the bench-day sheet) has to be able to answer "is the secret gone?" from the result alone.
        $secretRes = [ordered]@{
            proofMintedWithCertificate = $secretProofTp
            dpapiFileRemoved           = $false
            plaintextSecretStillInConfig = $false
        }
        if ($script:SecretPath) {
            try {
                Remove-Item -LiteralPath $script:SecretPath -Force
                $secretRes.dpapiFileRemoved = $true
                $script:SecretPath = $null
                $script:HasSecretCredential = ($null -ne $script:Secret)
                Write-Log "Credential retired: DPAPI secret file removed; certificate-only from now on" "INFO"
            } catch {
                $secretRes.error = $_.Exception.Message
                $secretRes.reason = "ABG_CRED_DPAPI_REMOVE_FAILED"
                $result.ok = $false
            }
        } else {
            $secretRes.note = "no DPAPI secret file configured"
        }

        # THE PLAINTEXT BRANCH USED TO REPORT SUCCESS. On a bay whose secret is the DEPRECATED plaintext
        # `clientSecret` in agent-config.json, there is no DPAPI file to delete, so this fell through the else
        # branch above, set a note, and returned ok=true -- while the secret sat in the config and went on
        # minting tokens. The operator's next act, on the strength of that ok, is KH-18 step 8: deleting the
        # app's client secrets in Entra. The bay would then be running on a credential the operator believes
        # is retired, and the one irreversible step in the whole rotation would have been taken on a false
        # report. Found by independent attack, 2026-09-14.
        #
        # The agent deliberately does not rewrite its own config (see Invoke-CredentialActivate), so it cannot
        # fix this itself. What it CAN do is refuse to call it done.
        if ($script:Secret) {
            $secretRes.plaintextSecretStillInConfig = $true
            $secretRes.reason = "ABG_CRED_PLAINTEXT_SECRET_REMAINS"
            $secretRes.note = "agent-config.json still carries a plaintext clientSecret and it still mints tokens. The agent never rewrites its own config: delete the clientSecret key by hand and restart, THEN re-run retire. Do not delete the app's secrets in Entra until this reports ok."
            $result.ok = $false
            Write-Log "retire secret: a plaintext clientSecret is STILL in agent-config.json; the secret is NOT retired. Reporting failure so the Entra deletion is not taken on a false success." "ERROR"
        }
        $result.secret = $secretRes
    }

    return $result
}

function Invoke-CredentialStatus {
    $certs = @()
    foreach ($store in @("Cert:\CurrentUser\My", "Cert:\LocalMachine\My")) {
        try {
            foreach ($c in @(Get-ChildItem -LiteralPath $store -ErrorAction SilentlyContinue | Where-Object { $_.Subject -like "CN=ABG-BayAgent*" })) {
                $certs += [ordered]@{
                    thumbprint    = $c.Thumbprint
                    subject       = $c.Subject
                    store         = ($store -replace "^Cert:\\", "")
                    hasPrivateKey = $c.HasPrivateKey
                    notAfterUtc   = $c.NotAfter.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
                }
            }
        } catch {}
    }
    return [ordered]@{
        ok           = $true
        action       = "status"
        credential   = (Get-CredentialTelemetry)
        state        = (Read-CredentialState)
        certificates = $certs
    }
}

function New-EnrollCertPayload {
    # The payload the -EnrollCert CONSOLE path hands to Invoke-CredentialEnroll.
    #
    # This is a function purely so it can be TESTED. It used to be three lines of top-level code inside
    # `if ($EnrollCert) { ... }`, and the suite lifts functions out of this script by AST -- so top-level
    # code and the param() block are both invisible to it. An independent verifier proved the consequence
    # on 2026-09-14: flipping `[switch]$EnrollForce` to default $true restores the original F5 defect (every
    # Day-0 re-run mints and abandons another non-exportable private key) and all 181 assertions stay green.
    # The payload half was pinned; the half the bench day actually runs was not covered at all.
    param(
        [int]$ValidityDays = 730,
        [string]$Store = "",
        [switch]$Force
    )
    $p = @{ validityDays = $ValidityDays; force = [bool]$Force }
    if ($Store) { $p.store = $Store }
    return $p
}

function Invoke-CredentialRotate($payloadObj) {
    if ($null -eq $payloadObj) { $payloadObj = @{} }
    $action = ([string](Get-PropValue $payloadObj "action" "status")).ToLowerInvariant()
    switch ($action) {
        "status"   { return (Invoke-CredentialStatus) }
        "enroll"   { return (Invoke-CredentialEnroll $payloadObj) }
        "test"     { return (Invoke-CredentialTest $payloadObj) }
        "activate" { return (Invoke-CredentialActivate $payloadObj) }
        "retire"   { return (Invoke-CredentialRetire $payloadObj) }
        "confirm"  { return (Invoke-CredentialConfirm) }
        "revert"   { return (Invoke-CredentialRevert) }
        default    { throw "CredentialRotate: unknown action '$action' (status | enroll | test | activate | retire | confirm | revert)" }
    }
}

function Execute-Command {
    param(
        [Parameter(Mandatory=$true)][int]$CommandType,
        [string]$PayloadJson,
        [string]$BayLabel,
        # The session the command ROW is bound to ($Lookup_BaySessionValue); "" when it names none.
        [string]$BoundSessionId = ""
    )
    $payloadObj = Try-ParseJson $PayloadJson


# Inject bay label into payload so Session Display can show it dynamically across multiple bays.
$effectiveBayLabel = $BayLabel
if ([string]::IsNullOrWhiteSpace([string]$effectiveBayLabel)) { $effectiveBayLabel = (Get-BayLabel) }

if ($null -ne $payloadObj) {
    Set-PropValue -obj $payloadObj -name "bayLabel" -value $effectiveBayLabel -OnlyIfMissing
    Set-PropValue -obj $payloadObj -name "locationLabel" -value $effectiveBayLabel -OnlyIfMissing
    Set-PropValue -obj $payloadObj -name "bayId" -value $BayId -OnlyIfMissing
}
    switch ($CommandType) {
        $CMD_HEALTHCHECK {
            $nowHb = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
            $hc = [ordered]@{
                ok = $true
                agentVersion = $AgentVersion
                machine = $env:COMPUTERNAME
                bayId = $BayId
                utc = $nowHb
            }
            # 1.3.1: cheap facts always (which code runs, whether self-heal runs, the update guard's last word); the
            # display placement only on request ({"report":true}), which also sends the full report to
            # build_agentcapabilitiesjson within one poll.
            foreach ($kv in (Get-HealthCheckFacts).GetEnumerator()) { $hc[$kv.Key] = $kv.Value }
            try { $hc["kiosk"] = (Get-KioskHealthSummary) } catch { }
            if ([bool](Get-PropValue $payloadObj "report" $false)) {
                $hc["windows"] = @(Invoke-ReportPart { Get-CompactWindowSummary })
                $hc["fullReportRequested"] = (Request-CapabilitiesRefresh)
                $hc["fullReportIn"] = "build_agentcapabilitiesjson"
            }
            return $hc
        }


$CMD_DISPLAY_TOPOLOGY {
    # 1.3.1: fresh monitors (not this process's cached view), where each managed window is, and the full report sent
    # to build_agentcapabilitiesjson within one poll (the result column holds only 2000 characters).
    $dt = [ordered]@{
        ok = $true
        topology = @((Get-DisplayTopology))
    }
    try { $dt["monitorCountSystem"] = [ABGDisplayInfo]::GetSystemMetrics(80) } catch { }
    $dt["windows"] = @(Invoke-ReportPart { Get-CompactWindowSummary })
    $dt["fullReportRequested"] = (Request-CapabilitiesRefresh)
    $dt["fullReportIn"] = "build_agentcapabilitiesjson"
    return $dt
}

$CMD_FACILITY_SETMODE {
    if ($null -eq $payloadObj) { $payloadObj = @{} }
    $mode = (Get-PropValue $payloadObj "mode" "Idle").ToString()

    $res = Invoke-FacilitySetMode -Mode $mode -payloadObj $payloadObj
    $res.requestedMode = $mode
    if (-not (Facility-IsEnabled $payloadObj)) {
        $res.note = "facility.disabled"
        $res.topology = @((Get-DisplayTopology))
    }
    return $res
}

$CMD_FACILITY_POWERON {
    if ($null -eq $payloadObj) { $payloadObj = @{} }
    if (-not (Facility-IsEnabled $payloadObj)) {
        return @{ ok = $true; enabled = $false; note = "facility.disabled"; requestedMode = "Ready" }
    }
    return (Invoke-FacilitySetMode -Mode "Ready" -payloadObj $payloadObj)
}

$CMD_FACILITY_POWEROFF {
    if ($null -eq $payloadObj) { $payloadObj = @{} }
    if (-not (Facility-IsEnabled $payloadObj)) {
        return @{ ok = $true; enabled = $false; note = "facility.disabled"; requestedMode = "Idle" }
    }
    return (Invoke-FacilitySetMode -Mode "Idle" -payloadObj $payloadObj)
}


$CMD_SETLIGHTS {
    if ($null -eq $payloadObj) { $payloadObj = @{} }
    if ($Global:EmergencyStopEngaged) {
        return @{ ok=$false; note="emergency_stop_engaged"; emergencyStop=@{ engaged=$true; reason=$Global:EmergencyStopReason } }
    }
    $scene = (Get-PropValue $payloadObj "scene" "Idle").ToString()
    return @{
        ok = $true
        result = (Invoke-LightsScene -Scene (Normalize-FacilityScene $scene) -payloadObj $payloadObj)
    }
}

$CMD_PROJECTOR_POWER {
    if ($null -eq $payloadObj) { $payloadObj = @{} }
    if ($Global:EmergencyStopEngaged) {
        return @{ ok=$false; note="emergency_stop_engaged"; emergencyStop=@{ engaged=$true; reason=$Global:EmergencyStopReason } }
    }
    $onVal = Get-PropValue $payloadObj "on" $false
    $on = [bool]$onVal
    return @{
        ok = $true
        result = (Invoke-ProjectorPower -On $on -payloadObj $payloadObj)
    }
}

$CMD_AUDIO_VOLUME {
    if ($null -eq $payloadObj) { $payloadObj = @{} }
    if ($Global:EmergencyStopEngaged) {
        return @{ ok=$false; note="emergency_stop_engaged"; emergencyStop=@{ engaged=$true; reason=$Global:EmergencyStopReason } }
    }
    $level = Get-PropValue $payloadObj "level" 30
    return @{
        ok = $true
        result = (Invoke-AudioVolume -Level $level -payloadObj $payloadObj)
    }
}

$CMD_EMERGENCY_STOP {
    if ($null -eq $payloadObj) { $payloadObj = @{} }
    $action = (Get-PropValue $payloadObj "action" "engage").ToString()
    if ($action.ToLowerInvariant() -eq "clear") {
        return (Clear-EmergencyStopInternal)
    }
    # A0.363: the launcher is no longer wanted (only STOPS the kiosk shell from restarting it; closes nothing).
    $null = Set-KioskIntentForCommand -CommandType $CMD_EMERGENCY_STOP -Mode "" -Payload $payloadObj
    return (Invoke-EmergencyStopInternal -payloadObj $payloadObj)
}


        $CMD_CREDENTIAL_ROTATE {
            return (Invoke-CredentialRotate $payloadObj)
        }

        $CMD_SHOWMESSAGE {
            $title = Get-PropValue $payloadObj "title" "All Birdies"
            $message = Get-PropValue $payloadObj "message" "Hello from Bay Agent"
            $timeoutSec = [int](Get-PropValue $payloadObj "timeoutSec" 8)

            try {
                $ws = New-Object -ComObject WScript.Shell
                $code = $ws.Popup([string]$message, $timeoutSec, [string]$title, 0)
                return @{ shown = $true; timeoutSec = $timeoutSec; resultCode = $code }
            } catch {
                return @{ shown = $false; error = $_.Exception.Message }
            }
        }
        $CMD_STARTPROCESS {
            return (Start-GenericProcess $payloadObj)
        }

        $CMD_STOPPROCESS {
            return (Stop-GenericProcess $payloadObj)
        }

        $CMD_QUERYPROCESS {
            return (Query-GenericProcess $payloadObj)
        }



        $CMD_UPDATESESSIONDISPLAY {
            if ($null -eq $payloadObj) { throw "UpdateSessionDisplay payload must be valid JSON." }

            # RV1 (kiosk round 2): a display update (Warn5, an extension) for a session this bay already ended is a replay:
            # it would put that session's countdown and Warning scene over whoever plays now. Nothing is touched.
            # A0.489: the same refusal for a canceled booking in its warning (an extension must not restore its countdown).
            $updRef = Get-CommandRefusal -CommandType $CMD_UPDATESESSIONDISPLAY -Payload $payloadObj -Running $Global:RunningSession -Finished $Global:RunningSessionFinished -Pending $Global:RunningSessionEndPending
            if ($null -ne $updRef) {
                return @{ updated = $false; skipped = $true; refusal = $updRef.Kind; reason = $updRef.Why }
            }

            # A0.363: a later end for the SAME running session extends the launcher intent (never creates one).
            $null = Set-KioskIntentForCommand -CommandType $CMD_UPDATESESSIONDISPLAY -Mode ([string](Get-PropValue $payloadObj "mode" "")) -Payload $payloadObj

            # Merge with last known model so partial updates (like Warn5) don't wipe start/end/name.
            $existing = Read-SessionModelFromDisk
            $baseHt = To-Hashtable $existing
            $payloadHt = To-Hashtable $payloadObj
            $patch = Build-SessionDisplayPatchFromPayload $payloadObj

            $tmp = Merge-Hashtables $baseHt $payloadHt
            $model = Merge-Hashtables $tmp $patch

            # Ensure a few safe defaults
            if ([string]::IsNullOrWhiteSpace([string](Get-PropValue $model "locationLabel" $null))) { $model.locationLabel = $effectiveBayLabel }
            if ([string]::IsNullOrWhiteSpace([string](Get-PropValue $model "displayName" $null))) { $model.displayName = "Guest" }
            if ([string]::IsNullOrWhiteSpace([string](Get-PropValue $model "helpText" $null))) { $model.helpText = (Get-HelpText) }

            $model = Normalize-SessionModel $model
            # RF-K1: a later end for the running session also moves the running-session record's end (before the wall is
            # written, so its stamp carries it).
            $null = Set-RunningSessionForCommand -CommandType $CMD_UPDATESESSIONDISPLAY -Mode ([string](Get-PropValue $payloadObj "mode" "")) -Payload $payloadObj
            $paths = Write-SessionFiles $model

            # Make sure the display is up (no duplicates).
            $display = Start-SessionDisplay $payloadObj

            $facility = $null
            try {
                $mode2 = Get-PropValue $payloadObj "mode" $null
                $scene2 = Get-PropValue $payloadObj "scene" $null
                if (-not [string]::IsNullOrWhiteSpace([string]$scene2)) {
                    $facility = Invoke-FacilitySetMode -Mode $scene2 -payloadObj $payloadObj
                } elseif (-not [string]::IsNullOrWhiteSpace([string]$mode2) -and $mode2.ToString().ToLowerInvariant() -eq "warn5") {
                    $facility = Invoke-FacilitySetMode -Mode "Warning" -payloadObj $payloadObj
                }
            } catch {
                $facility = @{ ok = $false; error = $_.Exception.Message }
            }

            return @{
                updated = $true
                sessionJsonPath = $paths.sessionJsonPath
                sessionJsPath = $paths.sessionJsPath
                display = $display
                facility = $facility
            }
        }

        $CMD_STARTSESSION {
            if ($null -eq $payloadObj) { throw "StartSession payload must be valid JSON." }

            $existing = Read-SessionModelFromDisk
            $baseHt = To-Hashtable $existing
            $payloadHt = To-Hashtable $payloadObj

            # Session boundary rules:
            # - Prep should NOT launch Uneekor Launcher (prevents early play)
            # - Start SHOULD launch Uneekor Launcher
            $mode = (Get-PropValue $payloadObj "mode" "").ToString()
            $modeLower = $mode.ToLowerInvariant()

            # RV1 (kiosk round 2): a session this bay already ended is never prepped or started again. A re-run of the
            # platform's command upsert replays a finished booking's Prep and Start with notBefore = now, and a replayed
            # Start would take the bay from whoever plays now. Nothing is touched.
            # A0.489 (Kevin, 2026-10-10): the same for a canceled booking in its 5-minute warning. A Prep or Start for it is
            # refused, the warning stays on the wall and the game ends at the warning's mark. Nothing is touched.
            $startSid = [string](Get-PropValue $payloadObj "baySessionId" "")
            $startRef = Get-CommandRefusal -CommandType $CMD_STARTSESSION -Payload $payloadObj -Running $Global:RunningSession -Finished $Global:RunningSessionFinished -Pending $Global:RunningSessionEndPending
            if ($null -ne $startRef) {
                return @{ ok = $true; skipped = $true; mode = $mode; refusal = $startRef.Kind; reason = $startRef.Why }
            }

            # Facility scene tied to the session (Step 5).
            $facility = $null

            # If EmergencyStop is latched, block session starts and force a safe scene.
            if ($Global:EmergencyStopEngaged) {
                try {
                    $facility = Invoke-FacilitySetMode -Mode "Cleanup" -payloadObj $payloadObj
                } catch {
                    $facility = @{ ok = $false; error = $_.Exception.Message }
                }
                # RV3 (kiosk round 2): the stop refuses the launcher, but the booking is still the bay's running booking:
                # it is recorded, so after the clear another booking's Reset cannot reset its wall, and its own End ends it.
                # Only a Start that names its session (every platform Start does): an unnamed refused Start has no booking
                # to protect and would hold every unbound Reset.
                if (-not [string]::IsNullOrWhiteSpace($startSid)) { $null = Set-RunningSessionForCommand -CommandType $CMD_STARTSESSION -Mode $mode -Payload $payloadObj }
                # A0.363: not wanted while the stop is engaged (Get-KioskIntentForCommand reads the latch).
                $null = Set-KioskIntentForCommand -CommandType $CMD_STARTSESSION -Mode $mode -Payload $payloadObj

                return @{
                    ok = $false
                    note = "emergency_stop_engaged"
                    emergencyStop = @{ engaged = $true; reason = $Global:EmergencyStopReason }
                    facility = $facility
                }
            }

            # Otherwise, apply the appropriate facility scene for the session phase.
            try {
                $scene = if ($modeLower -eq "start") { "Active" } elseif ($modeLower -eq "prep") { "Ready" } else { "Idle" }
                $facility = Invoke-FacilitySetMode -Mode $scene -payloadObj $payloadObj
            } catch {
                $facility = @{ ok = $false; error = $_.Exception.Message }
            }

            # Prevent stale/previous-session statusDetail (e.g., "Thanks for choosing All Birdies.") from carrying into Prep/Start
            if ($modeLower -eq "prep") {
                $payloadHt.status = "PREP"
                $payloadHt.statusDetail = ""   # allow display.js to show "Starts in"
                $payloadHt.bannerText = ""
            } elseif ($modeLower -eq "start") {
                $payloadHt.status = "ACTIVE"
                if ([string]::IsNullOrWhiteSpace([string](Get-PropValue $payloadHt "statusDetail" $null)) -and
                    [string]::IsNullOrWhiteSpace([string](Get-PropValue $payloadHt "bannerText" $null))) {
                    $payloadHt.statusDetail = "In progress."
                }
                $payloadHt.bannerText = ""
            }

            $patch = Build-SessionDisplayPatchFromPayload $payloadHt

            $tmp = Merge-Hashtables $baseHt $payloadHt
            $model = Merge-Hashtables $tmp $patch

            if ([string]::IsNullOrWhiteSpace([string](Get-PropValue $model "locationLabel" $null))) { $model.locationLabel = $effectiveBayLabel }
            if ([string]::IsNullOrWhiteSpace([string](Get-PropValue $model "displayName" $null))) { $model.displayName = "Guest" }
            if ([string]::IsNullOrWhiteSpace([string](Get-PropValue $model "helpText" $null))) { $model.helpText = (Get-HelpText) }

            $model = Normalize-SessionModel $model
            # RF-K1: Start makes this session the running-session record (Prep changes nothing). Recorded BEFORE the wall is
            # written, so the wall's stamp (agentRunning) names the session that now plays.
            $null = Set-RunningSessionForCommand -CommandType $CMD_STARTSESSION -Mode $mode -Payload $payloadObj
            $paths = Write-SessionFiles $model

            # Ensure the Session Display is running (no duplicates).
            $display = Start-SessionDisplay $payloadObj

            # Launcher should start ONLY at "Start"
            $launcherCfg = Get-LauncherConfigFromPayloadOrConfig $payloadObj
            if ([string]::IsNullOrWhiteSpace([string]$launcherCfg.path)) { $launcherCfg.path = "C:\Uneekor\Launcher\UneekorLauncher.exe" }

            # A0.363: the launcher intent the kiosk shell reads, written BEFORE anything starts the launcher. A Start whose
            # launcher config says startOnStart=false is written as a Prep (not wanted), so the shell cannot start what
            # the agent would not.
            $startOnStartCfg = $launcherCfg.startOnStart
            if ($null -eq $startOnStartCfg) { $startOnStartCfg = $true }
            $kioskMode = $(if ($modeLower -eq "start" -and -not [bool]$startOnStartCfg) { "start-disabled" } else { $mode })
            $kioskIntent = Set-KioskIntentForCommand -CommandType $CMD_STARTSESSION -Mode $kioskMode -Payload $payloadObj

            $launcher = $null
            if ($modeLower -eq "start") {
                $startOnStart = $launcherCfg.startOnStart
                if ($null -eq $startOnStart) { $startOnStart = $true }
                if ([bool]$startOnStart) {
                    # One starter at a time (I5): while a live kiosk shell supervises, it starts and places the launcher.
                    $kioskDefer = Get-KioskLauncherDeferral -NowUtc ((Get-Date).ToUniversalTime())
                    if ($kioskDefer.Defer) {
                        $launcher = @{ started = $false; reason = "kiosk_shell_owns_launcher"; shell = (Wait-KioskShellLauncher -TimeoutSeconds $KioskDeferWaitSeconds) }
                    } else {
                        $launcher = Start-LauncherIfNeeded "StartSession:Start" $launcherCfg
                    }
                } else {
                    $launcher = @{ started = $false; reason = "startOnStart_false" }
                }
            } else {
                $launcher = @{ started = $false; reason = "prep_or_unknown_mode" }
            }

            return @{
                ok = $true
                mode = $mode
                sessionJsonPath = $paths.sessionJsonPath
                sessionJsPath = $paths.sessionJsPath
                display = $display
                launcher = $launcher
                facility = $facility
                kiosk = $kioskIntent
            }
        }


        $CMD_ENDSESSION {
            # End of session:
            #  - Close Uneekor Launcher by default (prevents overtime)
            #  - Keep Session Display open by default and show a thank-you message
            if ($null -eq $payloadObj) { $payloadObj = @{} }

            # Kiosk round 2 (F1-R2/X3b, F1-R3, RV1): an End acts only on the session it names, judged against the
            # running-session record (Get-EndSessionScope), never session.json's id, which the next booking's Prep moves
            # while a member still plays. A replayed or duplicate End of a session this bay already ended touches nothing;
            # a late End of an older booking while another plays leaves that member's wall, facility, launcher and intent
            # alone (and still writes the booking back as complete).
            $endSid = [string](Get-PropValue $payloadObj "baySessionId" "")
            # A0.489: a platform End of a canceled booking in its warning is refused too (the agent's own End, at the
            # warning's mark, is not: -OwnEnd). A replayed End of an ended session is refused (RV1) unless it is the retry
            # of an End whose launcher close did not finish (R2: scope "retry" below).
            $endRef = Get-CommandRefusal -CommandType $CMD_ENDSESSION -Payload $payloadObj -Running $Global:RunningSession -Finished $Global:RunningSessionFinished -Pending $Global:RunningSessionEndPending -OwnEnd ([bool]$Global:RunningSessionOwnEnd)
            if ($null -ne $endRef) {
                return @{ ok = $true; skipped = $true; scope = $(if ($endRef.Kind -eq "cancel-warning") { "held" } else { "finished" }); refusal = $endRef.Kind; reason = $endRef.Why; kiosk = $null; launcherStopped = @{ stopped = $false; reason = $(if ($endRef.Kind -eq "cancel-warning") { "cancel_warning_holds" } else { "session_already_ended" }) } }
            }
            $endScope = Get-EndSessionScope -Running $Global:RunningSession -SessionId $endSid -Finished $Global:RunningSessionFinished -Pending $Global:RunningSessionEndPending
            if ($endScope.Scope -eq "finished") {
                return @{ ok = $true; skipped = $true; scope = "finished"; reason = $endScope.Why; kiosk = $null; launcherStopped = @{ stopped = $false; reason = "session_already_ended" } }
            }
            if ($endScope.Scope -eq "other") {
                Add-FinishedSession -SessionId $endSid -Why "a late End while another session plays"
                return @{ ok = $true; leftAlone = $true; scope = "other"; reason = $endScope.Why; runningSessionId = [string](Get-KioskProp $Global:RunningSession "baySessionId" ""); kiosk = $null; launcherStopped = @{ stopped = $false; reason = "late_old_session_skip" } }
            }

            # F3: the End is marked pending, in the record file, BEFORE it touches anything. From here a stop, a crash or a
            # restart ends with the launcher closed on the next pass (the main loop retries it) or by the next End of it.
            # F4: whether this End owns the launcher is decided ONCE, here, from the state it found, and stored with the
            # mark: the recorded session's own End owns it whatever session.json says (F1-R3); with nobody recorded, a late
            # End of an older booking (session.json names another) does not. A retry reads the stored decision.
            $endOwns = $true
            if ($endScope.Scope -eq "retry") {
                $endOwns = ([string](Get-KioskProp (Get-EndPendingEntry $endSid $Global:RunningSessionEndPending) "scope" "") -ne "leaves")
            } else {
                $wallSidEarly = [string](Get-PropValue (Read-SessionModelFromDisk) "baySessionId" "")
                if ($endScope.Scope -ne "running" -and -not [string]::IsNullOrWhiteSpace($endSid) -and -not [string]::IsNullOrWhiteSpace($wallSidEarly) -and ($endSid -ne $wallSidEarly)) { $endOwns = $false }
                Add-EndPending -SessionId $endSid -Payload $payloadObj -Scope $(if ($endOwns) { "owns" } else { "leaves" })
            }

            # Facility: EndSession always moves the bay to the Cleanup scene (Step 5). Not on a retry (R2): the first run did it.
            $facility = $null
            if ($endScope.Scope -ne "retry") {
                try {
                    $facility = Invoke-FacilitySetMode -Mode "Cleanup" -payloadObj $payloadObj
                } catch {
                    $facility = @{ ok = $false; error = $_.Exception.Message }
                }
            }

            function Get-ProcessesByExePathOrName([string]$exePath) {
                $list = @()
                if ([string]::IsNullOrWhiteSpace($exePath)) { return @() }

                $exeLeaf = [System.IO.Path]::GetFileName($exePath)
                $baseName = [System.IO.Path]::GetFileNameWithoutExtension($exePath)

                # 1) Try Get-Process Path match (may fail for some processes due to permissions)
                try {
                    $list += @(Get-Process -ErrorAction SilentlyContinue | Where-Object { $_.Path -and $_.Path -ieq $exePath })
                } catch {}

                # 2) Try CIM ExecutablePath match (more reliable on some systems)
                if (-not $list -or @($list).Count -eq 0) {
                    try {
                        $cim = @(Get-CimInstance Win32_Process -Filter "Name='$exeLeaf'" -ErrorAction SilentlyContinue)
                        foreach ($c in $cim) {
                            try {
                                if ($c.ExecutablePath -and $c.ExecutablePath -ieq $exePath) {
                                    $p = Get-Process -Id $c.ProcessId -ErrorAction SilentlyContinue
                                    if ($p) { $list += $p }
                                }
                            } catch {}
                        }
                    } catch {}
                }

                # 3) Directory scan fallback (handles cases where Process.Path is unavailable or exe name differs)
                if (-not $list -or @($list).Count -eq 0) {
                    try {
                        $dir = [System.IO.Path]::GetDirectoryName($exePath)
                        if (-not [string]::IsNullOrWhiteSpace($dir)) {
                            $cimAll = @(Get-CimInstance Win32_Process -ErrorAction SilentlyContinue | Where-Object {
                                $_.ExecutablePath -and ($_.ExecutablePath -like ($dir + "\*"))
                            })
                            foreach ($c in $cimAll) {
                                try {
                                    $p = Get-Process -Id $c.ProcessId -ErrorAction SilentlyContinue
                                    if ($p) { $list += $p }
                                } catch {}
                            }
                        }
                    } catch {}
                }

                # 4) Fallback to process name (last resort)
                if (-not $list -or @($list).Count -eq 0) {
                    try { $list += @(Get-Process -Name $baseName -ErrorAction SilentlyContinue) } catch {}
                }

                return @($list | Sort-Object Id -Unique)
            }

            function Stop-ProcessesGracefully([object[]]$procs, [int]$waitSec = 8) {
                $procs = @($procs)
                if (-not $procs -or $procs.Count -eq 0) { return @{ stopped = $false; reason = "not_running" } }

                foreach ($p in $procs) {
                    try {
                        if ($p.MainWindowHandle -ne 0) { $null = $p.CloseMainWindow() }
                    } catch {}
                }

                $deadline = (Get-Date).AddSeconds($waitSec)
                do {
                    Start-Sleep -Milliseconds 250
                    $still = @()
                    foreach ($p in $procs) {
                        try {
                            $cur = Get-Process -Id $p.Id -ErrorAction SilentlyContinue
                            if ($cur) { $still += $cur }
                        } catch {}
                    }
                } while ($still.Count -gt 0 -and (Get-Date) -lt $deadline)

                if ($still.Count -gt 0) {
                    foreach ($p in $still) {
                        try { Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue } catch {}
                    }
                    return @{ stopped = $true; method = "kill_after_timeout"; waitSec = $waitSec; count = $still.Count }
                }

                return @{ stopped = $true; method = "closemainwindow"; waitSec = $waitSec; count = $procs.Count }
            }

            $existing = Read-SessionModelFromDisk
            $baseHt = To-Hashtable $existing
            $payloadHt = To-Hashtable $payloadObj

            # Force End mode unless caller already set a specific status/mode.
            if ([string]::IsNullOrWhiteSpace([string](Get-PropValue $payloadHt "mode" $null)) -and
                [string]::IsNullOrWhiteSpace([string](Get-PropValue $payloadObj "status" $null))) {
                $payloadHt.mode = "End"
            }

            # Ensure explicit ENDED status
            if ([string]::IsNullOrWhiteSpace([string](Get-PropValue $payloadHt "status" $null))) { $payloadHt.status = "ENDED" }

            # Default thank-you message unless caller provided one.
            if ([string]::IsNullOrWhiteSpace([string](Get-PropValue $payloadHt "statusDetail" $null)) -and
                [string]::IsNullOrWhiteSpace([string](Get-PropValue $payloadHt "bannerText" $null))) {
                $payloadHt.statusDetail = "Thanks for choosing All Birdies."
            }

            $patch = Build-SessionDisplayPatchFromPayload $payloadHt
            $tmp = Merge-Hashtables $baseHt $payloadHt
            $model = Merge-Hashtables $tmp $patch

            if ([string]::IsNullOrWhiteSpace([string](Get-PropValue $model "locationLabel" $null))) { $model.locationLabel = $effectiveBayLabel }
            if ([string]::IsNullOrWhiteSpace([string](Get-PropValue $model "displayName" $null))) { $model.displayName = "Guest" }
            if ([string]::IsNullOrWhiteSpace([string](Get-PropValue $model "helpText" $null))) { $model.helpText = (Get-HelpText) }

            $model = Normalize-SessionModel $model
            # RF-K1: only the End of the running session clears the record (a late End of an older booking returned above).
            # Cleared BEFORE the wall is written, so the wall's stamp (agentRunning) says nobody plays; the session is
            # listed as ended here (RV1).
            # R2 (2026-10-10): the session is also marked "End pending" here, and the mark is dropped only after the intent is
            # written and the launcher closed (below). The ended list alone refuses a repeated End, so without the mark a
            # failure between the list and the launcher close left the launcher open for good. A retry (scope "retry",
            # run by the main loop) skips the wall, the record and the list: the first run did them.
            $wallError = $null
            $paths = @{ sessionJsonPath = $null; sessionJsPath = $null }
            if ($endScope.Scope -ne "retry") {
                Add-FinishedSession -SessionId $endSid -Why "EndSession"
                if ($endScope.Scope -eq "running") { $null = Set-RunningSessionForCommand -CommandType $CMD_ENDSESSION -Mode "End" -Payload $payloadObj }
                # A wall that cannot be written must not leave the launcher open (A0.360; a canceled booking never becomes free
                # play, A0.467): the End goes on to the intent and the launcher, and the result says the wall failed.
                try { $paths = Write-SessionFiles $model }
                catch { $wallError = $_.Exception.Message; try { Write-Log ("[SESSION] EndSession {0}: the wall could not be written ({1}); the launcher is still closed" -f $endSid, $wallError) "WARN" } catch { } }
            }

            # Stopping the apps the payload asks for is optional work; a failure there must not stop the protective act below.
            $apps = $null
            try { $apps = Stop-AppsIfRequested $payloadObj }
            catch { $apps = @{ ok = $false; error = $_.Exception.Message }; try { Write-Log ("[SESSION] EndSession {0}: stopping apps failed ({1}); the launcher is still closed" -f $endSid, $_.Exception.Message) "WARN" } catch { } }

            # Guard against late/out-of-order EndSession for an older session (e.g., back-to-back bookings). With a
            # running-session record the scope above decided it; with none, judged from session.json as before.
            $payloadSessionId = $endSid
            $currentSessionId = [string](Get-PropValue $existing "baySessionId" "")
            # F4: decided once, up front ($endOwns, stored with the pending mark), so a retry applies the guard its first run
            # applied even though the first run has since rewritten session.json.
            $sameSession = $endOwns

            # A0.363: not wanted, written BEFORE the launcher is closed, so a kiosk shell cannot reopen it in between. A late
            # EndSession for an older session leaves the current session's intent alone.
            $kioskIntent = Set-KioskIntentForCommand -CommandType $CMD_ENDSESSION -Mode "End" -Payload $payloadObj -SameSession $sameSession

            # Close the Uneekor Launcher by default (prevents playing past end time).
            $launcherCfg = Get-LauncherConfigFromPayloadOrConfig $payloadObj
            if ([string]::IsNullOrWhiteSpace([string]$launcherCfg.path)) { $launcherCfg.path = "C:\Uneekor\Launcher\UneekorLauncher.exe" }

            $closeLauncher = [bool](Get-PropValue $payloadObj "closeLauncher" $true)
            if (-not $sameSession) { $closeLauncher = $false }

            $launcherStopped = $null
            if ($closeLauncher) {
                $procs = Get-ProcessesByExePathOrName $launcherCfg.path
                $launcherStopped = Stop-ProcessesGracefully $procs 8
                if (-not $launcherStopped.stopped -and $launcherStopped.reason -eq "not_running") {
                    $launcherStopped = @{ stopped = $false; reason = "not_running"; path = $launcherCfg.path; found = 0 }
                }
            } else {
                if ($sameSession) {
                $launcherStopped = @{ stopped = $false; reason = "closeLauncher_false" }
            } else {
                $launcherStopped = @{ stopped = $false; reason = "late_old_session_skip" }
            }
            }
            # The protective act (the intent, then the launcher) is done: the End no longer needs a retry (R2).
            if (-not [string]::IsNullOrWhiteSpace($endSid)) { Clear-EndPending $endSid }

            # Keep Session Display open by default, showing the thank-you state.
            $closeDisplay = [bool](Get-PropValue $payloadObj "closeDisplay" $false)
            $display = $null
            $displayStopped = $null
            if ($closeDisplay) {
                $displayStopped = Stop-SessionDisplay
            } else {
                $display = Start-SessionDisplay $payloadObj
            }

            return @{
                ok = $true
                scope = $endScope.Scope
                wallError = $wallError
                sessionJsonPath = $paths.sessionJsonPath
                sessionJsPath = $paths.sessionJsPath
                facility = $facility
                apps = $apps
                launcherStopped = $launcherStopped
                closeDisplay = $closeDisplay
                display = $display
                displayStopped = $displayStopped
                kiosk = $kioskIntent
            }
        }

        $CMD_RESET {
            # Reset to a known-good "READY" state.
            # Default behavior: keep the Session Display running (or restart it) so the bay never sits on a blank screen.
            if ($null -eq $payloadObj) { $payloadObj = @{} }
            # R7 / RR1 (attacks 2026-10-08 and 2026-10-09): the platform sends a full Reset AT ONCE for every canceled
            # booking, bound to that booking's session on the row, whoever is playing on that bay. A Reset may not rewrite
            # the wall, restart the display or move the facility while a DIFFERENT session is running. "Running" is the
            # running-session record (RF-K1), which only Start, that session's own End and a Reset for that session move;
            # never session.json's status, which Prep, an emergency stop and a late End all rewrite while a member plays.
            $resetGate = Get-ResetGate -Running $Global:RunningSession -BoundSessionId $BoundSessionId -Payload $payloadObj -NowUtc ((Get-Date).ToUniversalTime())
            if (-not $resetGate.Proceed) {
                return @{
                    reset = $false
                    skipped = $true
                    reason = $resetGate.Why
                    runningSessionId = $resetGate.RunningSessionId
                    namedSessionId = $resetGate.NamedSessionId
                    force = $resetGate.Force
                }
            }
            # The running booking itself was canceled mid-play (the platform cancels its Warn5 and End): A0.467, the game
            # keeps running through a 5-minute warning on the wall and the control screen, then ends like a normal End
            # (Start-CancelWarning, Invoke-CancelEndIfDue). Nothing is reset now.
            if ($resetGate.NamesRunning) {
                $cw = Start-CancelWarning -PayloadObj $payloadObj -NowUtc ((Get-Date).ToUniversalTime())
                $cw["gate"] = $resetGate.Why
                return $cw
            }
            # A0.363: the launcher is not wanted after a reset.
            $null = Set-KioskIntentForCommand -CommandType $CMD_RESET -Mode "" -Payload $payloadObj

            $closeDisplay   = [bool](Get-PropValue $payloadObj "closeDisplay" $false)
            $restartDisplay = [bool](Get-PropValue $payloadObj "restartDisplay" $true)

            $stop = $null
            if ($closeDisplay -or $restartDisplay) {
                $stop = Stop-SessionDisplay
            }

            $default = @{
                locationLabel = $effectiveBayLabel
                displayName = "Guest"
                status = "READY"
                qrUrl = ""
                helpText = "Scan the QR code for help."
            }

            # No session is running, so carry NO session times. Writing
            # sessionStartUtc = sessionEndUtc = now made the idle screen print
            # START and END as the same minute, and left a stale zero-length
            # window for the next partial UpdateSessionDisplay to merge over.
            # Normalize-SessionModel also stamps schema + updatedUtc, which a
            # bare Write-SessionFiles did not - so an idle bay could not be
            # checked for staleness and the display printed "Updated: --".
            $default = Normalize-SessionModel $default

            $paths = Write-SessionFiles $default

            $display = $null
            if (-not $closeDisplay) {
                # Ensure the display is up again (no duplicates).
                $display = Start-SessionDisplay $payloadObj
            }

            $facility = $null
            try {
                $facility = Invoke-FacilitySetMode -Mode "Idle" -payloadObj $payloadObj
            } catch {
                $facility = @{ ok = $false; error = $_.Exception.Message }
            }

            return @{
                reset = $true
                gate = $resetGate.Why
                force = $resetGate.Force
                closeDisplay = $closeDisplay
                restartDisplay = $restartDisplay
                stopped = $stop
                display = $display
                sessionJsonPath = $paths.sessionJsonPath
                sessionJsPath = $paths.sessionJsPath
                facility = $facility
            }
        }


        default {
            throw "Unknown command type: $CommandType"
        }
    }
}

function Process-Command {
    param(
        [Parameter(Mandatory=$true)][string]$token,
        [Parameter(Mandatory=$true)]$cmd
    )

    $cmdId   = ($cmd.$Col_CommandId.ToString()).Trim("{}")
    $etag    = $cmd.'@odata.etag'
    $type    = [int]$cmd.$Col_CommandType
    $attempt = 0
    try { $attempt = [int]($cmd.$Col_AttemptCount) } catch {}

    if ([string]::IsNullOrWhiteSpace($etag)) {
        Write-Log "Command $cmdId missing @odata.etag; cannot lock safely. Skipping." "ERROR"
        return
    }

    Write-Log "Processing command $cmdId (type=$type attempt=$attempt)" "INFO"
    $boundSessionId = [string](Get-PropValue $cmd $Lookup_BaySessionValue "")

    # 0) A Reset the gate refuses is closed out as Skipped while it is still Pending (the guard plugin allows Pending ->
    # Skipped with no execution fields, and refuses InProgress -> Skipped). If that write fails for any reason, the
    # command takes the normal path below, where Execute-Command's own gate skips it and the result says so: a Reset
    # left Pending would be fetched first on every poll and block every later command.
    if ($type -eq $CMD_RESET) {
        $preGate = $null
        try { $preGate = Get-ResetGate -Running $Global:RunningSession -BoundSessionId $boundSessionId -Payload (Try-ParseJson ([string]$cmd.$Col_Payload)) -NowUtc ((Get-Date).ToUniversalTime()) } catch { $preGate = $null }
        if ($null -ne $preGate -and -not $preGate.Proceed) {
            $skippedOk = $false
            try { Patch-Row $token $BayCommandEntitySet $cmdId @{ $Col_Status = $STATUS_SKIPPED } $etag; $skippedOk = $true }
            catch { Write-Log ("Reset {0}: could not mark it Skipped ({1}); it runs, and its gate skips it" -f $cmdId, $_.Exception.Message) "WARN" }
            if ($skippedOk) {
                Write-Log ("Reset {0} Skipped: {1}" -f $cmdId, $preGate.Why) "INFO"
                return
            }
        }
    }

    # 0b) A Start, Prep, display update or End the bay refuses outright (a session it already ended, or a canceled booking in
    # its 5-minute warning: A0.489) is closed out as Skipped the same way, so the row says Skipped instead of Succeeded with
    # "skipped" buried in its result text. Same limits as above: Pending -> Skipped carries no execution fields (so the reason
    # is in the agent log, not on the row), and if the write fails the command runs and its handler refuses it.
    if ($type -eq $CMD_STARTSESSION -or $type -eq $CMD_UPDATESESSIONDISPLAY -or $type -eq $CMD_ENDSESSION) {
        $preRef = $null
        try { $preRef = Get-CommandRefusal -CommandType $type -Payload (Try-ParseJson ([string]$cmd.$Col_Payload)) -Running $Global:RunningSession -Finished $Global:RunningSessionFinished -Pending $Global:RunningSessionEndPending } catch { $preRef = $null }
        if ($null -ne $preRef) {
            $refSkippedOk = $false
            try { Patch-Row $token $BayCommandEntitySet $cmdId @{ $Col_Status = $STATUS_SKIPPED } $etag; $refSkippedOk = $true }
            catch { Write-Log ("Command {0}: could not mark it Skipped ({1}); it runs, and its handler refuses it" -f $cmdId, $_.Exception.Message) "WARN" }
            if ($refSkippedOk) {
                Write-Log ("Command {0} (type {1}) Skipped: {2}" -f $cmdId, $type, $preRef.Why) "INFO"
                return
            }
        }
    }

    # 1) LOCK (Pending -> InProgress) using ETag
    $now1 = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
    try {
        Patch-Row $token $BayCommandEntitySet $cmdId @{
            $Col_Status       = $STATUS_INPROGRESS
            $Col_StartedOn    = $now1
            $Col_AttemptCount = ($attempt + 1)
        } $etag
    }
    catch {
        Write-Log "Failed to lock command $cmdId (likely already taken). Skipping." "WARN"
        # A0.458: on probation, the command guard refusing the bay's own identity is a refusal, not a lost race.
        Register-IdentityProbationFailure ("command lock: " + $_.Exception.Message)
        return
    }


# Step 8.3: enforce bay mode (Offline / Maintenance)
$effNow = $(if ($Global:EffectiveConfig) { $Global:EffectiveConfig } else { @{} })
$op = Get-AgentOperationalState -eff $effNow
if ($op.Blocked -and -not (Is-CommandAllowedInMode -CommandType $type -OpState $op)) {
    $nowBlock = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
    $msg = $op.BlockReason
    try {
        Patch-Row $token $BayCommandEntitySet $cmdId @{
            $Col_Status      = $STATUS_FAILED
            $Col_CompletedOn = $nowBlock
            $Col_Error       = $msg
        } "*"
    } catch {
        Write-Log "Secondary failure: could not mark blocked command $cmdId Failed." "ERROR"
    }
    Write-Log "Command $cmdId blocked: $msg" "WARN"
    return
}

    # 2) EXECUTE + REPORT
    try {
        $payload = $null
        try { $payload = $cmd.$Col_Payload } catch {}

        
$bayLabelFromCmd = Get-BayLabelFromCommandRow $cmd
# A0.458: an identity switch probes the command guard on the command it runs on (Test-IdentityCandidate).
$Global:CurrentCommandId = $cmdId
try {
    $resultObj = Execute-Command -CommandType $type -PayloadJson $payload -BayLabel $bayLabelFromCmd -BoundSessionId $boundSessionId
} finally {
    $Global:CurrentCommandId = $null
}
        # Dataverse text columns (e.g., build_resultjson) require a STRING.
        # The baseline Step 1 agent returned JSON strings; we preserve that behavior here.
        # Limit-ResultJson, not a bare ConvertTo-Json: build_resultjson is capped at 2000 chars and an
        # over-length PATCH would fail the command in the catch below even though the work succeeded.
        $resultJson = Limit-ResultJson -ResultObj $resultObj

        $now2 = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
        Patch-Row $token $BayCommandEntitySet $cmdId @{
            $Col_Status      = $STATUS_SUCCEEDED
            $Col_CompletedOn = $now2
            $Col_Result      = $resultJson
        } "*"

        Write-Log "Command $cmdId succeeded." "INFO"

        # Booking status write-back (non-fatal): update booking when session starts or ends. Not for a command the agent
        # refused as a replay of a session it already ended (RV1): that would move a completed booking back to in-process.
        $refusedReplay = ($resultObj -is [System.Collections.IDictionary] -and $resultObj.Contains("skipped") -and $resultObj["skipped"] -eq $true)
        if (-not $refusedReplay) { try {
            $payloadForBooking = $null
            try { $payloadForBooking = Try-ParseJson $payload } catch {}
            $bkId = if ($payloadForBooking) { Get-PropValue $payloadForBooking "bookingId" $null } else { $null }
            if (-not [string]::IsNullOrWhiteSpace([string]$bkId)) {
                $bkPatchBody = $null
                if ($type -eq $CMD_STARTSESSION) {
                    $bkMode = if ($payloadForBooking) { (Get-PropValue $payloadForBooking "mode" "").ToString().ToLowerInvariant() } else { "" }
                    if ($bkMode -eq "start") { $bkPatchBody = @{ statecode = 0; statuscode = 271980001 } }  # Active / In-process
                }
                elseif ($type -eq $CMD_ENDSESSION) {
                    $bkPatchBody = @{ statecode = 1; statuscode = 271980002 }  # Inactive / Complete
                }
                if ($null -ne $bkPatchBody) {
                    Patch-Row $token "build_bookings" $bkId $bkPatchBody "*"
                    Write-Log "Booking $bkId status updated to $($bkPatchBody.statuscode) (statecode=$($bkPatchBody.statecode))" "INFO"
                }
            }
        } catch {
            Write-Log "Booking status write-back failed (non-fatal): $($_.Exception.Message)" "WARN"
        } }
    }
    catch {
        $nowErr = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
        $msg = $_.Exception.Message

        try {
            Patch-Row $token $BayCommandEntitySet $cmdId @{
                $Col_Status      = $STATUS_FAILED
                $Col_CompletedOn = $nowErr
                $Col_Error       = $msg
            } "*"
        } catch {
            Write-Log "Secondary failure: could not mark command $cmdId Failed." "ERROR"
        }

        Write-Log "Command $cmdId failed: $msg" "ERROR"
    }
}

# ---------------- A0.363: the bay kiosk shell, companion stage (SHIPPED DORMANT in 1.4.0) ----------------
# Design: C:\aoc-wt\reports\kiosk-shell-design-2026-10-06.md. The shell itself is kiosk\ABG.KioskShell.ps1 in the package.
#
# WHAT THIS SECTION DOES IN EVERY MODE (dormant included)
#   1. Writes state\kiosk-intent.json, the launcher signal the shell reads, one of three values:
#        wanted     StartSession Start, until the play end plus 2 minutes (extended by a later end for the same session)
#        closed     ONLY the EndSession of the running session (it names a session, the running-session record holds it,
#                   and the intent names no other), written BEFORE the launcher is closed: no session may play, so the shell
#                   closes a launcher a member reopens (Part B Test 11). A Reset never changes the intent (attack RF1).
#      A failed write keeps the DESIRED intent as the baseline and re-applies it every pass until it lands (RF2).
#        unmanaged  a Start with no readable end or startOnStart=false, an emergency stop, Maintenance/Offline: hands off
#      Prep changes nothing (it can run while the previous booking still plays). A readable intent outlives an agent
#      restart; an absent one is derived from session.json (running session: wanted; otherwise unmanaged).
#   2. Reports a `kiosk` block in build_agentcapabilitiesjson: the policy, the kill switch, the shell file's signature
#      facts, the shell's own heartbeat, the intent, and BayKiosk's Winlogon Shell values READ (never written) from HKCU
#      and HKLM, so the open bench question "which shell does BayKiosk actually have" is answered remotely.
# WHAT IT DOES ONLY WHEN current\kiosk\kiosk-policy.json SAYS "companion" (no shipped release says so yet)
#   3. Verifies releases\<this version>\kiosk\ABG.KioskShell.ps1 (inside this version's release folder, at least the
#      policy's minimum size, parses, Authenticode Valid AND timestamped AND signed by the same certificate as this
#      agent's own script) and starts it beside Explorer when it is not alive; at most 6 starts an hour.
#   4. Stops a HUNG shell (heartbeat older than 3 minutes) by the process id in its heartbeat, only after that process's
#      command line names a kiosk shell file under this install. It stops nothing else.
#   5. At StartSession Start, while a live shell supervises, it leaves starting and placing the launcher to the shell
#      (one starter at a time) and reports what the shell did; otherwise it starts the launcher itself, as before.
#      Start-SessionDisplay likewise leaves the wall window to a live supervising shell (it still writes the session
#      files the wall shows).
# WHAT IT NEVER DOES: write the registry, or take a mode from the platform (the mode is the package's policy file and
# the on-site kill switch control\kiosk.off only).

$KioskShellRelPath          = "kiosk\ABG.KioskShell.ps1"
$KioskPolicyPath            = Join-Path $BaseDir "current\kiosk\kiosk-policy.json"
$KioskKillSwitchPath        = Join-Path $BaseDir "control\kiosk.off"
$KioskIntentPath            = Join-Path $BaseDir "state\kiosk-intent.json"
$KioskHeartbeatPath         = Join-Path $BaseDir "state\kiosk-shell.json"
$KioskReconcilePath         = Join-Path $BaseDir "state\kiosk-reconcile.json"
$KioskIntentGraceSeconds    = 120
# RF-K1 (attack 2026-10-09): who is playing, as a fact only that session's own commands move (Get-ResetGate). In every
# mode, dormant included: it protects the wall, the display and the facility from another booking's Reset.
$RunningSessionPath            = Join-Path $BaseDir "state\running-session.json"
$Global:RunningSession         = $null
$Global:RunningSessionPending  = $false
# Kiosk round 2 (RV1): the sessions this bay has already ENDED, newest last, kept in the same file. A replayed Prep,
# Start, display update or End for one of them is refused (the platform's "replace by key" upsert can re-run a finished
# booking's commands with notBefore = now). At most this many are kept.
$Global:RunningSessionFinished = @()
$RunningSessionFinishedMax     = 50
# Kiosk round 2 fix (R2, 2026-10-10): an End whose protective act (the intent write and the launcher close) did not finish
# stays "pending" here, in memory, and the main loop retries it; at most this many tries per End, then it is dropped with a WARN.
$Global:RunningSessionEndPending = @()
$RunningSessionEndRetryMax     = 5
# A0.489 (Kevin, 2026-10-10): true only while the agent runs the End that ends a canceled booking after its warning, so
# that End is not refused by the very hold that keeps every other command for that booking out (Get-CommandRefusal).
$Global:RunningSessionOwnEnd   = $false
# A0.467 (Kevin, 2026-10-09): a booking canceled while its member plays ends after this warning, never past its own end.
$RunningSessionCancelWarningSeconds = 300
$KioskReconcileEverySeconds = 60
$KioskShellAliveSeconds     = 60
$KioskShellHungSeconds      = 180
$KioskShellMaxStartsPerHour = 6
$KioskDeferWaitSeconds      = 10

# THE AUTHORITY FOR THE KIOSK MODE IS THIS LINE OF SIGNED CODE, not the policy file (security review, 2026-10-08).
# Everything under C:\AllBirdies\BayAgent is writable by the bay account, and in companion mode a member at the desktop
# can reach it too. So the policy file may only turn the kiosk OFF (toward today's desktop, like the kill switch); it can
# never turn it on. "On" needs this constant, which ships in the signed, hash-pinned package (the bay signs it on arrival
# and an edit breaks the signature under AllSigned), AND the policy file to agree. The build refuses a package in which
# this constant, the shell's twin ($KioskShellReleaseMode) and kiosk-policy.json disagree.
$KioskReleaseMode           = "explorer"

# Shared with kiosk\ABG.KioskShell.ps1, byte for byte (tests\BayAgent.Kiosk.Tests.ps1 K-PARITY pins it): the agent
# and the shell must decide the mode and the intent the same way.
function Get-KioskProp($obj, [string]$name, $default = $null) {
    # An array value is returned AS an array (the comma): PowerShell unrolls a one-element array on return, which made
    # a policy mode of ["companion"] read as the text "companion". Every strict check downstream must see the shape.
    if ($null -eq $obj) { return $default }
    try {
        $v = $null; $found = $false
        if ($obj -is [System.Collections.IDictionary]) {
            if ($obj.Contains($name)) { $v = $obj[$name]; $found = $true }
        } else {
            $p = $obj.PSObject.Properties[$name]
            if ($null -ne $p) { $v = $p.Value; $found = $true }
        }
        if (-not $found) { return $default }
        if ($v -is [Array]) { return ,$v }
        return $v
    } catch { }
    return $default
}

function Read-KioskJsonFile([string]$Path, [int]$MaxBytes = 65536) {
    # Strict reader. @{ Ok; Obj; Why }. Absent, empty, whitespace, BOM only, NULs, too large, not JSON, or JSON that
    # is not an object (null, [], a number, a string) are all Ok=false with a reason. Never throws.
    $r = @{ Ok = $false; Obj = $null; Why = "" }
    try {
        if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { $r.Why = "absent"; return $r }
        # Opened with every share flag, so a reader never makes the writer's atomic replace fail (attack RF2, 2026-10-08).
        $fsR = New-Object IO.FileStream($Path, [IO.FileMode]::Open, [IO.FileAccess]::Read, ([IO.FileShare]::ReadWrite -bor [IO.FileShare]::Delete))
        $bytes = $null
        try {
            if ($fsR.Length -gt $MaxBytes) { $r.Why = "larger than $MaxBytes bytes"; return $r }
            $bytes = New-Object byte[] ([int]$fsR.Length)
            $got = 0
            while ($got -lt $bytes.Length) { $n = $fsR.Read($bytes, $got, $bytes.Length - $got); if ($n -le 0) { break }; $got += $n }
            if ($got -ne $bytes.Length) { $r.Why = "short read"; return $r }
        } finally { $fsR.Dispose() }
        $start = 0
        if ($bytes.Length -ge 3 -and $bytes[0] -eq 0xEF -and $bytes[1] -eq 0xBB -and $bytes[2] -eq 0xBF) { $start = 3 }
        for ($i = $start; $i -lt $bytes.Length; $i++) { if ($bytes[$i] -eq 0) { $r.Why = "contains NUL bytes"; return $r } }
        $text = [Text.Encoding]::UTF8.GetString($bytes, $start, $bytes.Length - $start)
        if ([string]::IsNullOrWhiteSpace($text)) { $r.Why = "empty"; return $r }
        $t = $text.Trim()
        if (-not $t.StartsWith("{")) { $r.Why = "not a JSON object"; return $r }
        $o = $null
        try { $o = ConvertFrom-Json -InputObject $t } catch { $r.Why = "not valid JSON"; return $r }
        if ($null -eq $o -or $o -is [Array] -or $o -is [string] -or $o -is [ValueType]) { $r.Why = "not a JSON object"; return $r }
        $r.Ok = $true; $r.Obj = $o
    } catch { $r.Why = "unreadable: " + $_.Exception.Message }
    return $r
}

function ConvertTo-KioskUtc($value) {
    # ISO text (Windows PowerShell 5.1 leaves it a string) or a DateTime (PowerShell 7 converts it). Text must carry
    # its zone (Z or an offset); anything else is $null. Never throws. PowerShell 7 turns zoned text into a Utc or
    # Local DateTime and zone-less text into an Unspecified one, so Unspecified is refused like zone-less text.
    if ($null -eq $value) { return $null }
    try {
        if ($value -is [DateTime]) {
            if ($value.Kind -eq [DateTimeKind]::Local) { return $value.ToUniversalTime() }
            if ($value.Kind -eq [DateTimeKind]::Utc) { return $value }
            return $null
        }
        if ($value -isnot [string]) { return $null }
        $s = $value.Trim()
        if ($s -notmatch '^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}(:\d{2}(\.\d{1,7})?)?(Z|[+-]\d{2}:\d{2})$') { return $null }
        $dto = [DateTimeOffset]::MinValue
        if ([DateTimeOffset]::TryParse($s, [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::None, [ref]$dto)) {
            return $dto.UtcDateTime
        }
    } catch { }
    return $null
}

function Get-KioskPolicyDecision($PolicyRead, [bool]$KillSwitchPresent, [string[]]$SupportedModes = @("explorer", "companion")) {
    # The ONLY place the kiosk mode is decided. Fails toward "explorer" (today's Windows desktop) for every shape that
    # is not exactly a known schema-1 policy naming a mode this code implements.
    $d = @{ Mode = "explorer"; Requested = $null; Reason = ""; MinShellBytes = 4096 }
    if ($KillSwitchPresent) { $d.Reason = "kill switch present (control\kiosk.off)"; return $d }
    if ($null -eq $PolicyRead -or -not $PolicyRead.Ok) {
        $why = $(if ($null -ne $PolicyRead) { [string]$PolicyRead.Why } else { "no read" })
        $d.Reason = "policy unreadable ($why)"; return $d
    }
    $o = $PolicyRead.Obj
    $schema = Get-KioskProp $o "schema" $null
    if (-not ($schema -is [int] -or $schema -is [long]) -or [int64]$schema -lt 1) { $d.Reason = "policy schema missing or not a positive integer"; return $d }
    $mode = Get-KioskProp $o "mode" $null
    if ($mode -isnot [string]) { $d.Reason = "policy mode missing or not text"; return $d }
    $d.Requested = $mode
    if ($mode -cnotin @("explorer", "companion", "shell")) { $d.Reason = "policy mode '$mode' is unknown"; return $d }
    $min = Get-KioskProp $o "minShellBytes" 4096
    if (-not ($min -is [int] -or $min -is [long]) -or [int64]$min -lt 1024 -or [int64]$min -gt 1048576) { $d.Reason = "policy minShellBytes missing or outside 1024..1048576"; return $d }
    $d.MinShellBytes = [int]$min
    if ($mode -cnotin $SupportedModes) { $d.Reason = "policy mode '$mode' is not implemented by this release"; return $d }
    $d.Mode = $mode
    $d.Reason = "policy"
    return $d
}

function Get-KioskLauncherWanted($IntentRead, [DateTime]$NowUtc) {
    # Three answers, read strictly:
    #   Wanted   only for an exact "wanted" whose untilUtc (with its zone) is in the future: the shell restarts it.
    #   Closed   only for an exact "closed" with a readable writtenUtc: no session may play (written by EndSession of the
    #            running session only); the shell closes a launcher that appears (A0.360), if session.json agrees.
    #   neither  ("unmanaged", "not_wanted", expired, unreadable, unknown): hands off, never restart, never close.
    # A failure to read is never a reason to close anything. Newer schemas are read by field name.
    $w = @{ Wanted = $false; Closed = $false; ClosedSinceUtc = $null; Reason = ""; UntilUtc = $null; SessionId = $null }
    if ($null -eq $IntentRead -or -not $IntentRead.Ok) {
        $why = $(if ($null -ne $IntentRead) { [string]$IntentRead.Why } else { "no read" })
        $w.Reason = "intent unreadable ($why)"; return $w
    }
    $o = $IntentRead.Obj
    $schema = Get-KioskProp $o "schema" $null
    if (-not ($schema -is [int] -or $schema -is [long]) -or [int64]$schema -lt 1) { $w.Reason = "intent schema missing or not a positive integer"; return $w }
    $sid = Get-KioskProp $o "baySessionId" $null
    if ($sid -is [string]) { $w.SessionId = $sid }
    $l = Get-KioskProp $o "launcher" $null
    if ($l -is [string] -and $l -ceq "closed") {
        $since = ConvertTo-KioskUtc (Get-KioskProp $o "writtenUtc" $null)
        if ($null -eq $since) { $w.Reason = "intent closed without a readable writtenUtc (left alone)"; return $w }
        $w.Closed = $true
        $w.ClosedSinceUtc = $since
        $w.Reason = "intent closed (no session)"
        return $w
    }
    if ($l -isnot [string] -or $l -cne "wanted") { $w.Reason = "intent says not wanted"; return $w }
    $until = ConvertTo-KioskUtc (Get-KioskProp $o "untilUtc" $null)
    if ($null -eq $until) { $w.Reason = "intent untilUtc missing or without a zone"; return $w }
    $w.UntilUtc = $until
    if ($NowUtc -ge $until) { $w.Reason = "intent expired"; return $w }
    $w.Wanted = $true
    $w.Reason = "intent wanted"
    return $w
}

function Get-KioskReleasePolicy {
    # The mode this agent acts on: "companion" only when BOTH the signed release constant ($KioskReleaseMode) AND the
    # policy file say so and no kill switch is present. A policy file that disagrees with the release is reported
    # (MatchesRelease = false) and never grants anything. Never throws.
    $allowed = @("explorer")
    if ($KioskReleaseMode -ceq "companion") { $allowed += "companion" }
    $d = Get-KioskPolicyDecision -PolicyRead (Read-KioskJsonFile -Path $KioskPolicyPath -MaxBytes 4096) -KillSwitchPresent (Test-Path -LiteralPath $KioskKillSwitchPath) -SupportedModes $allowed
    $d["ReleaseMode"] = $KioskReleaseMode
    $d["MatchesRelease"] = ([string]$d.Requested -ceq [string]$KioskReleaseMode)
    if (-not $d.MatchesRelease -and $d.Reason -notmatch "^kill switch") {
        $d.Reason = ("the policy file says '{0}' but this release was built '{1}' (changed outside a release?): {2}" -f $d.Requested, $KioskReleaseMode, $d.Reason)
    }
    return $d
}

function Get-KioskShellPath {
    # Version-pinned (I8): the release folder of the code that runs, which later updates do not delete.
    return (Join-Path $BaseDir ("releases\{0}\{1}" -f $AgentCodeVersion, $KioskShellRelPath))
}

function Get-KioskPowerShellExe {
    return (Join-Path $env:WINDIR "System32\WindowsPowerShell\v1.0\powershell.exe")
}

function Get-KioskShellArgumentList([string]$ShellPath) {
    # The ONE place the shell's command line is built. AllSigned applies: no -ExecutionPolicy, -File only. The launch
    # test starts the shell with exactly this text, so the test cannot drift from what a bay runs.
    return ('-NoProfile -NonInteractive -WindowStyle Hidden -File "{0}" -Companion' -f $ShellPath)
}

function Test-KioskShellCommandLine([string]$CommandLine) {
    # A process is a kiosk shell of THIS install when its command line names a kiosk shell file in one of this install's
    # release folders (any version: after an update the old shell keeps running until it is replaced).
    if ([string]::IsNullOrWhiteSpace($CommandLine)) { return $false }
    $root = [regex]::Escape((Join-Path $BaseDir "releases").TrimEnd('\') + '\')
    return ($CommandLine -match ('(?i)' + $root + '[^\\"]+\\kiosk\\ABG\.KioskShell\.ps1'))
}

function Get-KioskProcessCommandLine([int]$ProcessId) {
    # $null when the process is gone or cannot be read.
    try {
        $p = Get-CimInstance Win32_Process -Filter ("ProcessId={0}" -f $ProcessId) -OperationTimeoutSec 3 -ErrorAction Stop
        if ($null -eq $p) { return $null }
        return [string]$p.CommandLine
    } catch { return $null }
}

function Get-KioskAuthenticode([string]$Path) {
    # The signature facts the activation verifier needs. Never throws.
    $r = @{ Status = "Unknown"; Timestamped = $false; Thumbprint = $null; Error = $null }
    try {
        $sig = Get-AuthenticodeSignature -LiteralPath $Path -ErrorAction Stop
        $r.Status = [string]$sig.Status
        $r.Timestamped = ($null -ne $sig.TimeStamperCertificate)
        if ($null -ne $sig.SignerCertificate) { $r.Thumbprint = [string]$sig.SignerCertificate.Thumbprint }
    } catch { $r.Error = $_.Exception.Message }
    return $r
}

function Test-KioskShellFile([string]$Path, [int]$MinBytes, [string]$ExpectedSignerThumbprint, [string]$ExpectedFolder) {
    # The activation verifier (I2). Decide first, act second: nothing starts a shell file that did not just pass every
    # check here, in this order. @{ Ok; Why; Bytes; Sha256; Signature; Timestamped; SignerMatches }.
    $v = [ordered]@{ Ok = $false; Why = ""; Path = $Path; Bytes = $null; Sha256 = $null; Signature = $null; Timestamped = $null; SignerMatches = $null }
    try {
        $full = [IO.Path]::GetFullPath($Path)
        $folder = [IO.Path]::GetFullPath($ExpectedFolder).TrimEnd('\') + '\'
        if (-not $full.StartsWith($folder, [StringComparison]::OrdinalIgnoreCase)) { $v.Why = "not inside $folder"; return $v }
        if (-not (Test-Path -LiteralPath $full -PathType Leaf)) { $v.Why = "missing"; return $v }
        $fi = Get-Item -LiteralPath $full -ErrorAction Stop
        $v.Bytes = [int64]$fi.Length
        if ($fi.Length -lt $MinBytes) { $v.Why = ("{0} bytes, under the policy minimum {1}" -f $fi.Length, $MinBytes); return $v }
        $alg = [System.Security.Cryptography.SHA256]::Create()
        $fs = [IO.File]::OpenRead($full)
        try { $v.Sha256 = ([BitConverter]::ToString($alg.ComputeHash($fs)) -replace "-", "").ToLowerInvariant() } finally { $fs.Dispose(); $alg.Dispose() }
        $tok = $null; $perr = $null
        [void][System.Management.Automation.Language.Parser]::ParseFile($full, [ref]$tok, [ref]$perr)
        if (@($perr).Count -gt 0) { $v.Why = ("{0} parse error(s)" -f @($perr).Count); return $v }
        $sig = Get-KioskAuthenticode $full
        $v.Signature = $sig.Status
        $v.Timestamped = [bool]$sig.Timestamped
        if ($sig.Status -ne "Valid") { $v.Why = ("signature {0}" -f $sig.Status); return $v }
        if (-not $sig.Timestamped) { $v.Why = "signature is not timestamped"; return $v }
        $v.SignerMatches = (-not [string]::IsNullOrWhiteSpace($ExpectedSignerThumbprint) -and [string]$sig.Thumbprint -ieq $ExpectedSignerThumbprint)
        if (-not $v.SignerMatches) { $v.Why = "signed by a certificate other than the one that signed this agent"; return $v }
        $v.Ok = $true
        $v.Why = "verified"
    } catch { $v.Why = "verification failed: " + $_.Exception.Message }
    return $v
}

function Get-KioskShellLiveness($HeartbeatRead, [DateTime]$NowUtc, [scriptblock]$CommandLineOf) {
    # absent: no heartbeat or its process is gone. foreign: the heartbeat's process id now belongs to something that is
    # not a kiosk shell of this install (never stopped, never counted). alive: heartbeat within 60 s. stale: 60 to 180 s
    # (wait). hung: older than 180 s with the shell process still there.
    $l = [ordered]@{ State = "absent"; Pid = $null; Why = ""; AgeSeconds = $null; Supervising = $false; Degraded = $false; Version = $null; LauncherRunning = $false; LauncherPid = $null }
    if ($null -eq $HeartbeatRead -or -not $HeartbeatRead.Ok) { $l.Why = $(if ($null -ne $HeartbeatRead) { "no heartbeat (" + [string]$HeartbeatRead.Why + ")" } else { "no heartbeat" }); return $l }
    $o = $HeartbeatRead.Obj
    $hbPid = Get-KioskProp $o "pid" $null
    if (-not ($hbPid -is [int] -or $hbPid -is [long]) -or [int64]$hbPid -le 0) { $l.Why = "heartbeat has no process id"; return $l }
    $l.Pid = [int]$hbPid
    $l.Version = Get-KioskProp $o "version" $null
    $cl = & $CommandLineOf ([int]$hbPid)
    if ($null -eq $cl) { $l.Why = "the heartbeat's process is gone"; return $l }
    if (-not (Test-KioskShellCommandLine $cl)) { $l.State = "foreign"; $l.Why = "the heartbeat's process id belongs to another program"; return $l }
    $last = ConvertTo-KioskUtc (Get-KioskProp $o "lastLoopUtc" $null)
    if ($null -eq $last) { $l.State = "hung"; $l.Why = "heartbeat has no readable lastLoopUtc"; return $l }
    $age = ($NowUtc - $last).TotalSeconds
    $l.AgeSeconds = [int]$age
    $l.Supervising = ((Get-KioskProp $o "supervising" $false) -eq $true)
    $l.Degraded = ((Get-KioskProp $o "degraded" $false) -eq $true)
    $lo = Get-KioskProp $o "launcher" $null
    $l.LauncherRunning = ((Get-KioskProp $lo "running" $false) -eq $true)
    $l.LauncherPid = Get-KioskProp $lo "pid" $null
    if ($age -le $KioskShellAliveSeconds) { $l.State = "alive"; $l.Why = "heartbeat fresh"; return $l }
    if ($age -gt $KioskShellHungSeconds) { $l.State = "hung"; $l.Why = ("heartbeat {0} s old" -f [int]$age); return $l }
    $l.State = "stale"; $l.Why = ("heartbeat {0} s old" -f [int]$age)
    return $l
}

function Test-BaySessionIdMatch([string]$A, [string]$B) {
    # Pure. Two bay session ids name the same session: both present, compared as GUID text (spaces and braces trimmed,
    # case ignored: the row lookup is lower case, a payload may not be). An empty id never matches anything.
    $x = $(if ($null -ne $A) { $A.Trim().Trim('{', '}').Trim() } else { "" })
    $y = $(if ($null -ne $B) { $B.Trim().Trim('{', '}').Trim() } else { "" })
    if ($x.Length -eq 0 -or $y.Length -eq 0) { return $false }
    return [string]::Equals($x, $y, [StringComparison]::OrdinalIgnoreCase)
}

function Get-ResetGate {
    # Pure. May a Reset touch the wall, display and facility right now? (R7, RR1; RF-K1 of the 2026-10-09 attack.)
    # "A member is playing" is the RUNNING-SESSION RECORD ($Global:RunningSession), never session.json's status: Prep of
    # the next booking, an emergency stop that was cleared, a late End of the previous booking and the passage of time
    # all move session.json off ACTIVE while a member still plays, and none of them moves the record (only Start, that
    # session's own End, and a Reset for that session do). The session a Reset is FOR is the row's bound session
    # (BoundSessionId), else a payload baySessionId. Proceeds when: no record; the Reset is for the running session (it
    # was canceled mid-play: NamesRunning, the caller starts its 5-minute warning, A0.467); force is the JSON literal true (an operator;
    # "true", 1, "false" or {} are not force); the record's end is more than LapseHours past (an End that never came must
    # not pin the bay for good). Otherwise holds. @{ Proceed; Why; RunningSessionId; NamedSessionId; NamesRunning; Force }
    param($Running, [string]$BoundSessionId, $Payload, [DateTime]$NowUtc, [int]$LapseHours = 6)
    # Get-KioskProp keeps an array an array (Get-PropValue would unroll [true] to true).
    $f = Get-KioskProp $Payload "force" $null
    $force = ($f -is [bool] -and $f -eq $true)
    $named = $(if (-not [string]::IsNullOrWhiteSpace($BoundSessionId)) { $BoundSessionId.Trim() } else { [string](Get-PropValue $Payload "baySessionId" "") })
    $runSid = $(if ($null -ne $Running) { [string](Get-KioskProp $Running "baySessionId" "") } else { "" })
    $g = @{ Proceed = $false; Why = ""; RunningSessionId = $runSid; NamedSessionId = $named; NamesRunning = $false; Force = $force }
    if ($null -eq $Running) { $g.Proceed = $true; $g.Why = "nobody is playing (no running-session record)"; return $g }
    if (Test-BaySessionIdMatch $named $runSid) { $g.Proceed = $true; $g.NamesRunning = $true; $g.Why = "the Reset is for the running session $runSid"; return $g }
    if ($force) { $g.Proceed = $true; $g.Why = "force"; return $g }
    $end = ConvertTo-KioskUtc (Get-KioskProp $Running "endUtc" $null)
    if ($null -ne $end -and $NowUtc -gt $end.AddHours($LapseHours)) { $g.Proceed = $true; $g.Why = "the running-session record for $runSid lapsed ($LapseHours h past its end, no End came)"; return $g }
    $g.Why = "session '$runSid' is playing and this Reset is for '$named': the wall, display and facility are left alone"
    return $g
}

function Get-RunningSessionForCommand {
    # Pure. What a command does to the running-session record. @{ Change; Record; Reason }; Record $null = nobody plays.
    #   StartSession Start  this session plays (replaces any older record: the bay moved on). Prep changes nothing.
    #   EndSession          clears the record only when it names the recorded session (a late End of an older one does not).
    #   UpdateSessionDisplay moves the recorded session's end LATER only (an extension), never earlier, never another session.
    #   An End that names no session clears only a record that names none either (RV4: a Start sent with no session id).
    #   A canceled booking's warning end (cancelEndUtc, A0.467) survives a Start or an extension of the SAME session: a
    #   replayed Start of a canceled booking must not turn its warning back into play until the next booking.
    # The caller runs Start even when an emergency stop refused it (RV3: the booking is still the bay's running booking);
    # the Reset of a booking canceled mid-play starts its warning instead (Get-ResetGate's NamesRunning, Start-CancelWarning).
    param([int]$CommandType, [string]$Mode, $Payload, $Current, [DateTime]$NowUtc)
    $none = @{ Change = $false; Record = $Current; Reason = "" }
    $m = $(if ($null -ne $Mode) { $Mode.ToLowerInvariant() } else { "" })
    $sid = [string](Get-KioskProp $Payload "baySessionId" "")
    $curSid = $(if ($null -ne $Current) { [string](Get-KioskProp $Current "baySessionId" "") } else { "" })
    $curCancel = $(if ($null -ne $Current) { Get-KioskProp $Current "cancelEndUtc" $null } else { $null })
    $end = ConvertTo-KioskUtc (Get-KioskProp $Payload "playEndUtc" $null)
    if ($null -eq $end) { $end = ConvertTo-KioskUtc (Get-KioskProp $Payload "sessionEndUtc" $null) }
    if ($CommandType -eq $CMD_STARTSESSION) {
        if ($m -ne "start") { return $none }
        if ($null -eq $end) { $end = ConvertTo-KioskUtc (Get-KioskProp $Payload "endUtc" $null) }
        $rec = [ordered]@{ baySessionId = $sid; endUtc = $(if ($null -ne $end) { $end.ToString("yyyy-MM-ddTHH:mm:ssZ") } else { $null }); since = $NowUtc.ToString("yyyy-MM-ddTHH:mm:ssZ") }
        if ($null -ne $curCancel -and (Test-BaySessionIdMatch $sid $curSid)) { $rec["cancelEndUtc"] = $curCancel }
        return @{ Change = $true; Record = $rec; Reason = "StartSession Start $sid" }
    }
    if ($CommandType -eq $CMD_ENDSESSION -and $null -ne $Current -and [string]::IsNullOrWhiteSpace($sid) -and [string]::IsNullOrWhiteSpace($curSid)) {
        return @{ Change = $true; Record = $null; Reason = "EndSession naming no session, for the record naming none" }
    }
    if ($null -eq $Current -or -not (Test-BaySessionIdMatch $sid $curSid)) { return $none }
    if ($CommandType -eq $CMD_ENDSESSION) { return @{ Change = $true; Record = $null; Reason = "EndSession $sid" } }
    if ($CommandType -eq $CMD_UPDATESESSIONDISPLAY) {
        if ($null -eq $end) { return $none }
        $curEnd = ConvertTo-KioskUtc (Get-KioskProp $Current "endUtc" $null)
        if ($null -ne $curEnd -and $end -le $curEnd) { return $none }
        $rec = [ordered]@{ baySessionId = $curSid; endUtc = $end.ToString("yyyy-MM-ddTHH:mm:ssZ"); since = [string](Get-KioskProp $Current "since" "") }
        if ($null -ne $curCancel) { $rec["cancelEndUtc"] = $curCancel }
        return @{ Change = $true; Record = $rec; Reason = "UpdateSessionDisplay extended $curSid" }
    }
    return $none
}

function Write-RunningSessionFile {
    # Lays the in-memory record down atomically and reads it back. Throws on failure (callers catch).
    $r = $Global:RunningSession
    $o = [ordered]@{
        schema       = 1
        running      = ($null -ne $r)
        baySessionId = $(if ($null -ne $r) { [string](Get-KioskProp $r "baySessionId" "") } else { $null })
        endUtc       = $(if ($null -ne $r) { Get-KioskProp $r "endUtc" $null } else { $null })
        since        = $(if ($null -ne $r) { Get-KioskProp $r "since" $null } else { $null })
        cancelEndUtc = $(if ($null -ne $r) { Get-KioskProp $r "cancelEndUtc" $null } else { $null })
        finished     = @(@($Global:RunningSessionFinished) | ForEach-Object { [ordered]@{ id = [string](Get-KioskProp $_ "id" ""); utc = [string](Get-KioskProp $_ "utc" "") } })
        endPending   = @(@($Global:RunningSessionEndPending) | Where-Object { $null -ne $_ } | ForEach-Object { [ordered]@{ id = [string](Get-KioskProp $_ "id" ""); payload = [string](Get-KioskProp $_ "payload" ""); tries = [int](Get-KioskProp $_ "tries" 0); scope = [string](Get-KioskProp $_ "scope" "") } })
        writtenUtc   = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
    }
    $text = ConvertTo-Json -InputObject $o -Depth 4
    $dir = Split-Path -Parent $RunningSessionPath
    if (-not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Force -Path $dir | Out-Null }
    $tmp = "$RunningSessionPath.tmp"
    [IO.File]::WriteAllText($tmp, $text, (New-Object Text.UTF8Encoding($false)))
    try {
        if (Test-Path -LiteralPath $RunningSessionPath) { [IO.File]::Replace($tmp, $RunningSessionPath, [NullString]::Value, $true) }
        else { [IO.File]::Move($tmp, $RunningSessionPath) }
    } catch { [IO.File]::Copy($tmp, $RunningSessionPath, $true); try { [IO.File]::Delete($tmp) } catch { } }
    $fsR = New-Object IO.FileStream($RunningSessionPath, [IO.FileMode]::Open, [IO.FileAccess]::Read, ([IO.FileShare]::ReadWrite -bor [IO.FileShare]::Delete))
    try { $sr = New-Object IO.StreamReader($fsR, (New-Object Text.UTF8Encoding($false))); $back = $sr.ReadToEnd() } finally { $fsR.Dispose() }
    if ($back -cne $text) { throw "the running-session file does not read back as written" }
}

function Set-RunningSession($Record, [string]$Reason) {
    # The in-memory record is the authority for this process (the gate reads it); the file only carries it across a
    # restart. A failed write is retried every main-loop pass (Sync-RunningSessionFile). Never throws.
    $Global:RunningSession = $Record
    $Global:RunningSessionPending = $true
    try {
        Write-RunningSessionFile
        $Global:RunningSessionPending = $false
        try { Write-Log ("[SESSION] running-session record: {0} ({1})" -f $(if ($null -ne $Record) { [string](Get-KioskProp $Record "baySessionId" "") } else { "none" }), $Reason) "INFO" } catch { }
        return $true
    } catch {
        try { Write-Log ("[SESSION] running-session record could not be written (kept in memory, retried every pass): {0}" -f $_.Exception.Message) "WARN" } catch { }
        return $false
    }
}

function Sync-RunningSessionFile {
    # Every main-loop pass: lands a pending write. Never throws.
    if (-not $Global:RunningSessionPending) { return $false }
    try { Write-RunningSessionFile; $Global:RunningSessionPending = $false; return $true } catch { return $false }
}

function Set-RunningSessionForCommand {
    # Execute-Command's call per Start, End and UpdateSessionDisplay. Never throws; returns the change, or $null.
    param([int]$CommandType, [string]$Mode, $Payload)
    try {
        $c = Get-RunningSessionForCommand -CommandType $CommandType -Mode $Mode -Payload $Payload -Current $Global:RunningSession -NowUtc ((Get-Date).ToUniversalTime())
        if (-not $c.Change) { return $null }
        $ok = Set-RunningSession -Record $c.Record -Reason $c.Reason
        return [ordered]@{ running = ($null -ne $c.Record); reason = $c.Reason; written = $ok }
    } catch {
        try { Write-Log ("[SESSION] running-session record for command {0} failed: {1}" -f $CommandType, $_.Exception.Message) "WARN" } catch { }
        return $null
    }
}

function ConvertTo-RunningSnapshot($Obj) {
    # Pure. One snapshot of "who plays" (the record file, or the agentRunning stamp a wall write carries), read strictly:
    # @{ Ok; Record; At }. Ok needs a positive integer schema and a boolean running; a running snapshot needs a text
    # session id. Record $null = nobody plays. At = its writtenUtc ($null when unreadable).
    $x = @{ Ok = $false; Record = $null; At = $null }
    if ($null -eq $Obj) { return $x }
    $schema = Get-KioskProp $Obj "schema" $null
    $running = Get-KioskProp $Obj "running" $null
    if (-not (($schema -is [int] -or $schema -is [long]) -and [int64]$schema -ge 1 -and $running -is [bool])) { return $x }
    $x.At = ConvertTo-KioskUtc (Get-KioskProp $Obj "writtenUtc" $null)
    if (-not $running) { $x.Ok = $true; return $x }
    $sid = Get-KioskProp $Obj "baySessionId" $null
    if ($sid -isnot [string]) { return $x }
    $e = ConvertTo-KioskUtc (Get-KioskProp $Obj "endUtc" $null)
    $rec = [ordered]@{ baySessionId = $sid; endUtc = $(if ($null -ne $e) { $e.ToString("yyyy-MM-ddTHH:mm:ssZ") } else { $null }); since = [string](Get-KioskProp $Obj "since" "") }
    $ce = ConvertTo-KioskUtc (Get-KioskProp $Obj "cancelEndUtc" $null)
    if ($null -ne $ce) { $rec["cancelEndUtc"] = $ce.ToString("yyyy-MM-ddTHH:mm:ssZ") }
    $x.Ok = $true
    $x.Record = $rec
    return $x
}

function Initialize-RunningSession([DateTime]$NowUtc) {
    # Agent start. Two snapshots of what this agent last knew can survive a restart: the record file, and the stamp the
    # last wall write carried (agentRunning in session.json). The NEWER readable one wins (RV2, 2026-10-09: with the
    # record file's write failing from a Start until a restart, the file alone said "nobody plays" and lost the member);
    # on equal times a stamp saying someone plays wins. Neither readable (the first start of a release that has them, or
    # damaged files): derived ONCE from session.json's status, a session ACTIVE or ENDING, or STOP (an emergency stop over
    # a session) whose end is still ahead. A snapshot naming a session this bay already ENDED is "nobody". The list of
    # ended sessions is read from the record file only. Never throws.
    try {
        $rd = Read-KioskJsonFile -Path $RunningSessionPath -MaxBytes 65536
        $file = $(if ($rd.Ok) { ConvertTo-RunningSnapshot $rd.Obj } else { @{ Ok = $false; Record = $null; At = $null } })
        $fin = @()
        if ($rd.Ok) {
            $fl = Get-KioskProp $rd.Obj "finished" $null
            foreach ($fe in @($fl)) {
                $fid = Get-KioskProp $fe "id" $null
                if ($fid -is [string] -and -not [string]::IsNullOrWhiteSpace($fid)) { $fin += [ordered]@{ id = $fid; utc = [string](Get-KioskProp $fe "utc" "") } }
            }
        }
        # F3: an End that was received but did not finish closing the launcher (the pending list, written with the ended
        # list). Its session counts as ended (so a snapshot that still says it plays is "nobody") and the main loop retries
        # the End. A damaged file loses it, like the ended list itself (F9).
        $pend = @()
        if ($rd.Ok) {
            $pl2 = Get-KioskProp $rd.Obj "endPending" $null
            foreach ($pe in @($pl2)) {
                $pid2 = Get-KioskProp $pe "id" $null
                if ($pid2 -is [string] -and -not [string]::IsNullOrWhiteSpace($pid2)) {
                    $pt = Get-KioskProp $pe "tries" 0
                    $pend += [ordered]@{ id = $pid2; payload = [string](Get-KioskProp $pe "payload" ""); tries = $(if ($pt -is [int] -or $pt -is [long]) { [int]$pt } else { 0 }); scope = [string](Get-KioskProp $pe "scope" "") }
                    $fin = @(Add-FinishedSessionToList -Finished $fin -SessionId $pid2 -NowUtc $NowUtc -Max $RunningSessionFinishedMax)
                }
            }
        }
        $Global:RunningSessionEndPending = @($pend)
        $Global:RunningSessionFinished = @($fin)
        $model = Read-SessionModelFromDisk
        $stamp = ConvertTo-RunningSnapshot (Get-KioskProp $model "agentRunning" $null)
        $pick = $null; $src = ""
        if ($file.Ok -and $stamp.Ok) {
            $stampNewer = ($null -ne $stamp.At -and ($null -eq $file.At -or $stamp.At -gt $file.At -or ($stamp.At -eq $file.At -and $null -ne $stamp.Record)))
            if ($stampNewer) { $pick = $stamp; $src = "the session.json stamp (newer than the record file)" } else { $pick = $file; $src = "record file" }
        } elseif ($file.Ok) { $pick = $file; $src = "record file" }
        elseif ($stamp.Ok) { $pick = $stamp; $src = "the session.json stamp (record file " + $rd.Why + ")" }
        if ($null -ne $pick) {
            $rec = $pick.Record
            $finishedNote = ""
            if ($null -ne $rec -and (Test-SessionFinished ([string](Get-KioskProp $rec "baySessionId" "")) $Global:RunningSessionFinished)) { $rec = $null; $finishedNote = "; its session already ended here" }
            if ($src -eq "record file" -and $finishedNote -eq "") { $Global:RunningSession = $rec; return }
            $null = Set-RunningSession -Record $rec -Reason ("agent start: from " + $src + $finishedNote)
            return
        }
        $status = [string](Get-KioskProp $model "status" "")
        $msid = [string](Get-KioskProp $model "baySessionId" "")
        $mend = ConvertTo-KioskUtc (Get-KioskProp $model "sessionEndUtc" $null)
        $rec = $null
        $plays = ($status -cin @("ACTIVE", "ENDING")) -or ($status -ceq "STOP" -and $null -ne $mend -and $NowUtc -lt $mend)
        if ($plays -and -not [string]::IsNullOrWhiteSpace($msid) -and -not (Test-SessionFinished $msid $Global:RunningSessionFinished)) {
            $rec = [ordered]@{ baySessionId = $msid; endUtc = $(if ($null -ne $mend) { $mend.ToString("yyyy-MM-ddTHH:mm:ssZ") } else { $null }); since = $NowUtc.ToString("yyyy-MM-ddTHH:mm:ssZ") }
        }
        $null = Set-RunningSession -Record $rec -Reason ("agent start: derived from session.json (status '{0}', record file {1})" -f $status, $rd.Why)
    } catch { try { Write-Log ("[SESSION] running-session record could not be initialized: {0}" -f $_.Exception.Message) "WARN" } catch { } }
}

function Test-SessionFinished([string]$SessionId, $Finished) {
    # Pure. True when this bay already ENDED that session (RV1). An empty id is never finished.
    if ([string]::IsNullOrWhiteSpace($SessionId)) { return $false }
    foreach ($f in @($Finished)) { if (Test-BaySessionIdMatch $SessionId ([string](Get-KioskProp $f "id" ""))) { return $true } }
    return $false
}

function Test-EndPendingFor([string]$SessionId, $Pending) {
    # Pure. True when an End of that session was started here and its protective act (the intent write and the launcher
    # close) has not finished. An empty id is never pending (nothing to retry against).
    if ([string]::IsNullOrWhiteSpace($SessionId)) { return $false }
    foreach ($p in @($Pending)) { if ($null -ne $p -and (Test-BaySessionIdMatch $SessionId ([string](Get-KioskProp $p "id" "")))) { return $true } }
    return $false
}

function Get-CommandRefusal {
    # Pure. Whether the bay refuses a Start, Prep, display update or End outright, and why (kiosk round 2, RV1 + A0.489):
    #   cancel-warning  A0.489 (Kevin, 2026-10-10): "a cancel is final on that bay". The session in the running-session
    #                   record was canceled and is in its warning: nothing for that session is accepted (no Prep, Start,
    #                   display update, or platform End). The warning stays on the wall and the agent's own End runs at the
    #                   mark (-OwnEnd). Another booking's Start is not named here: it takes the bay as before.
    #   ended-replay    this bay already ended that session (a replay of a finished booking's command, or a booking
    #                   reinstated after the bay ended it). An End whose protective act is still pending is NOT refused
    #                   while nobody plays: it is the retry (R2).
    # @{ Kind; Why } or $null.
    param([int]$CommandType, $Payload, $Running, $Finished, $Pending, [bool]$OwnEnd = $false)
    if ($CommandType -ne $CMD_STARTSESSION -and $CommandType -ne $CMD_UPDATESESSIONDISPLAY -and $CommandType -ne $CMD_ENDSESSION) { return $null }
    $sid = [string](Get-KioskProp $Payload "baySessionId" "")
    if ([string]::IsNullOrWhiteSpace($sid)) { return $null }
    if (-not $OwnEnd -and $null -ne $Running) {
        $runSid = [string](Get-KioskProp $Running "baySessionId" "")
        $ce = ConvertTo-KioskUtc (Get-KioskProp $Running "cancelEndUtc" $null)
        if ($null -ne $ce -and (Test-BaySessionIdMatch $sid $runSid)) {
            return @{ Kind = "cancel-warning"; Why = "session '$sid' was canceled and is in its 5-minute warning: this command is refused, the warning stays on the wall and the game ends at its mark (A0.489)" }
        }
    }
    if (Test-SessionFinished $sid $Finished) {
        if ($CommandType -eq $CMD_ENDSESSION -and $null -eq $Running -and (Test-EndPendingFor $sid $Pending)) { return $null }
        return @{ Kind = "ended-replay"; Why = "session '$sid' already ended on this bay: a replayed command is not run" }
    }
    return $null
}

function Get-EndRetryPayloadJson($Payload, [string]$SessionId) {
    # Pure. The part of an End's payload a retry needs (never the customer block): mode, session, and what decides the
    # launcher close (closeLauncher, a launcher override, the reason). Small enough to live in the record file.
    $o = [ordered]@{ mode = "End"; baySessionId = $SessionId }
    foreach ($k in @("closeLauncher", "launcher", "reason")) {
        $v = Get-KioskProp $Payload $k $null
        if ($null -ne $v) { $o[$k] = $v }
    }
    $t = $null
    try { $t = ConvertTo-Json -Compress -Depth 4 -InputObject $o } catch { $t = $null }
    if ([string]::IsNullOrWhiteSpace($t) -or $t.Length -gt 1500) { $t = ConvertTo-Json -Compress -InputObject ([ordered]@{ mode = "End"; baySessionId = $SessionId }) }
    return $t
}

function Get-EndPendingEntry([string]$SessionId, $Pending) {
    # Pure. The pending entry for that session, or $null.
    if ([string]::IsNullOrWhiteSpace($SessionId)) { return $null }
    foreach ($p in @($Pending)) { if ($null -ne $p -and (Test-BaySessionIdMatch $SessionId ([string](Get-KioskProp $p "id" "")))) { return $p } }
    return $null
}

function Save-EndPendingState {
    # F3 (2026-10-10): the pending list lives in the record file, in the same atomic write as the ended list and the record,
    # so an agent that stops, crashes or restarts at any point after an End was received still knows the launcher may be
    # open (Initialize-RunningSession reads it back). Memory stays the authority; a failed write is retried every pass.
    $Global:RunningSessionPending = $true
    try { Write-RunningSessionFile; $Global:RunningSessionPending = $false }
    catch { try { Write-Log ("[SESSION] the pending-End mark could not be written (kept in memory, retried every pass): {0}" -f $_.Exception.Message) "WARN" } catch { } }
}

function Add-EndPending([string]$SessionId, $Payload, [string]$Scope) {
    # An End of that session was received and has not yet done its protective act (R2, F3, F4, 2026-10-10). Called FIRST,
    # before the End touches anything, and written to the record file at once. The main loop retries it
    # (Invoke-PendingEndRetry); an agent restart reads it back. Scope is how the first run judged the End ("running" or
    # "none"), so the retry applies the same session guard. Never throws.
    try {
        if ([string]::IsNullOrWhiteSpace($SessionId)) { return }
        $keep = @(@($Global:RunningSessionEndPending) | Where-Object { $null -ne $_ -and -not (Test-BaySessionIdMatch $SessionId ([string](Get-KioskProp $_ "id" ""))) })
        $keep += [ordered]@{ id = $SessionId.Trim(); payload = (Get-EndRetryPayloadJson $Payload $SessionId.Trim()); tries = 0; scope = $Scope }
        $Global:RunningSessionEndPending = @($keep)
        Save-EndPendingState
    } catch { }
}

function Clear-EndPending([string]$SessionId) {
    # The protective act is done (or moot): drop the mark, in memory and in the file. An empty id drops every mark.
    # Never throws.
    try {
        if ([string]::IsNullOrWhiteSpace($SessionId)) { $Global:RunningSessionEndPending = @() }
        else { $Global:RunningSessionEndPending = @(@($Global:RunningSessionEndPending) | Where-Object { $null -ne $_ -and -not (Test-BaySessionIdMatch $SessionId ([string](Get-KioskProp $_ "id" ""))) }) }
        Save-EndPendingState
    } catch { }
}

function Invoke-PendingEndRetry {
    # R2: re-runs the End whose protective act did not finish, once per main-loop pass, while nobody is recorded as
    # playing. The End handler recognizes it ("retry" scope), leaves the wall and facility alone, and does the intent and
    # the launcher. At most $RunningSessionEndRetryMax tries; a session that plays now drops the mark (the launcher
    # belongs to that session). Returns the End's result or $null. Never throws.
    try {
        $p = @($Global:RunningSessionEndPending)
        if ($p.Count -eq 0) { return $null }
        if ($null -ne $Global:RunningSession) {
            Clear-EndPending ""
            try { Write-Log "[SESSION] a pending End was dropped: another session is recorded as playing now" "INFO" } catch { }
            return $null
        }
        $e = $p[0]
        $sid = [string](Get-KioskProp $e "id" "")
        $tries = [int](Get-KioskProp $e "tries" 0)
        if ($tries -ge $RunningSessionEndRetryMax) {
            Clear-EndPending $sid
            try { Write-Log ("[SESSION] the End of session {0} could not finish its protective act after {1} tries; dropped (a StopProcess command closes the launcher)" -f $sid, $tries) "WARN" } catch { }
            return $null
        }
        $e["tries"] = $tries + 1
        $payload = [string](Get-KioskProp $e "payload" "")
        if ([string]::IsNullOrWhiteSpace($payload)) { $payload = ConvertTo-Json -Compress -InputObject ([ordered]@{ mode = "End"; baySessionId = $sid; reason = "EndRetry" }) }
        $res = Execute-Command -CommandType $CMD_ENDSESSION -PayloadJson $payload -BayLabel ""
        try { Write-Log ("[SESSION] retried the End of session {0} (try {1})" -f $sid, ($tries + 1)) "INFO" } catch { }
        return $res
    } catch {
        try { Write-Log ("[SESSION] the retry of a pending End failed: {0}" -f $_.Exception.Message) "WARN" } catch { }
        return $null
    }
}

function Add-FinishedSessionToList($Finished, [string]$SessionId, [DateTime]$NowUtc, [int]$Max) {
    # Pure. The list with this session as its newest entry (moved there if present); the oldest dropped past Max.
    $keep = @(@($Finished) | Where-Object { $null -ne $_ -and -not (Test-BaySessionIdMatch $SessionId ([string](Get-KioskProp $_ "id" ""))) })
    if (-not [string]::IsNullOrWhiteSpace($SessionId)) { $keep += [ordered]@{ id = $SessionId.Trim(); utc = $NowUtc.ToString("yyyy-MM-ddTHH:mm:ssZ") } }
    if ($Max -ge 1 -and $keep.Count -gt $Max) { $keep = @($keep[($keep.Count - $Max)..($keep.Count - 1)]) }
    return $keep
}

function Add-FinishedSession([string]$SessionId, [string]$Why) {
    # This bay ended that session (RV1): memory first (the authority), then the record file (retried every pass on a
    # failure, like the record itself). Never throws.
    try {
        if ([string]::IsNullOrWhiteSpace($SessionId)) { return }
        $l = Add-FinishedSessionToList -Finished $Global:RunningSessionFinished -SessionId $SessionId -NowUtc ((Get-Date).ToUniversalTime()) -Max $RunningSessionFinishedMax
        $Global:RunningSessionFinished = @($l)
        $Global:RunningSessionPending = $true
        try { Write-RunningSessionFile; $Global:RunningSessionPending = $false }
        catch { try { Write-Log ("[SESSION] the ended-session list could not be written (kept in memory, retried every pass): {0}" -f $_.Exception.Message) "WARN" } catch { } }
        try { Write-Log ("[SESSION] session {0} ended here ({1})" -f $SessionId, $Why) "INFO" } catch { }
    } catch { }
}

function Get-EndSessionScope {
    # Pure. Which session an EndSession may act on (kiosk round 2: F1-R2/X3b, F1-R3, RV1, RV4), judged against the
    # running-session record, never session.json's id (the next booking's Prep moves that while a member still plays):
    #   finished  this bay already ended that session: a replay or a duplicate. Touch nothing.
    #   other     another session is playing: a late or duplicate End of an older booking. Leave the wall, the facility,
    #             the launcher and the intent alone (a second End of an ended session used to rewrite the wall ENDED for
    #             it, and with a stale "closed" on disk the shell then ended the paying member's game: X3b).
    #   running   the End names the recorded session (or both name none: RV4). End it, whatever session.json says.
    #   none      nobody is recorded as playing: judged from session.json as before.
    # @{ Scope; Why }
    #   retry     (R2) this bay began that End and its protective act did not finish (the session is listed as ended, nobody
    #             plays): do the intent and the launcher again, nothing else.
    param($Running, [string]$SessionId, $Finished, $Pending = @())
    if (Test-SessionFinished $SessionId $Finished) {
        if ($null -eq $Running -and (Test-EndPendingFor $SessionId $Pending)) { return @{ Scope = "retry"; Why = "the End of session '$SessionId' began here and did not finish closing the launcher: retried" } }
        return @{ Scope = "finished"; Why = "session '$SessionId' already ended on this bay: a replayed or duplicate End is not run" }
    }
    if ($null -eq $Running) { return @{ Scope = "none"; Why = "nobody is recorded as playing" } }
    $runSid = [string](Get-KioskProp $Running "baySessionId" "")
    if (Test-BaySessionIdMatch $SessionId $runSid) { return @{ Scope = "running"; Why = "the End of the running session $runSid" } }
    if ([string]::IsNullOrWhiteSpace($SessionId) -and [string]::IsNullOrWhiteSpace($runSid)) { return @{ Scope = "running"; Why = "an End naming no session, for the running record naming none" } }
    return @{ Scope = "other"; Why = "session '$runSid' is playing and this End is for '$SessionId': the wall, facility, launcher and intent are left alone" }
}

function Get-CancelEndUtc {
    # Pure. A0.467: when a booking canceled mid-play ends. The warning's length from now, never later than the booking's
    # own recorded end (a canceled booking never plays longer than it would have), never earlier than now.
    param([DateTime]$NowUtc, $RecordEndUtc, [int]$WarningSeconds)
    $d = $NowUtc.AddSeconds($WarningSeconds)
    if ($null -ne $RecordEndUtc -and $RecordEndUtc -lt $d) { $d = $RecordEndUtc }
    if ($d -lt $NowUtc) { $d = $NowUtc }
    return $d
}

function Get-CancelWarningText([DateTime]$EndsUtc, [DateTime]$NowUtc) {
    # Pure. The control-screen text (ASCII, no quotes: it is placed on msg.exe's command line).
    $mins = [int][Math]::Ceiling(($EndsUtc - $NowUtc).TotalMinutes)
    if ($mins -lt 1) { $mins = 1 }
    $unit = $(if ($mins -eq 1) { "minute" } else { "minutes" })
    $at = $EndsUtc.ToLocalTime().ToString("h:mm tt", [Globalization.CultureInfo]::InvariantCulture)
    return ("This booking was canceled. Play ends in {0} {1}, at {2}." -f $mins, $unit, $at)
}

function Start-ControlScreenSender {
    # Runs the sender (msg.exe) hidden, waits up to $WaitMs for it to exit, and returns @{ pid; exitCode }; exitCode is $null
    # when it did not exit in time. msg.exe returns as soon as Windows has taken the message, so the wait is short.
    param([string]$Exe, [string]$ArgLine, [int]$WaitMs = 8000)
    $p = Start-Process -FilePath $Exe -ArgumentList $ArgLine -WindowStyle Hidden -PassThru
    $null = $p.Handle
    $done = $p.WaitForExit($WaitMs)
    return @{ pid = $p.Id; exitCode = $(if ($done) { $p.ExitCode } else { $null }) }
}

function Send-ControlScreenWarning {
    # A0.467: the warning on the control screen (the touchscreen the golf launcher runs on), on top of whatever is there,
    # without blocking this agent: Windows' own msg.exe to this desktop session, dismissed on its own when the warning
    # ends. Only this agent's fixed text reaches the command line (anything but letters, digits and . , : and spaces is
    # dropped). @{ shown; via; why; pid }. Never throws.
    # "shown" is true ONLY when msg.exe ran and exited 0 (the 2026-10-10 fix: it used to read true once the process was
    # started, so a box that never appeared read as shown). The starter returns @{ pid; exitCode }; a starter that reports
    # no exit code (or none within the wait) leaves shown false. Exit 0 means Windows accepted the message for that
    # desktop session; that it is visible on the bay's touchscreen is not something the exit code can say.
    param([string]$Text, [int]$Seconds, [scriptblock]$Starter = $null)
    $r = [ordered]@{ shown = $false; via = "msg.exe"; why = ""; pid = $null; exitCode = $null }
    try {
        $exe = Join-Path $env:WINDIR "System32\msg.exe"
        if ($null -eq $Starter) {
            if (-not (Test-Path -LiteralPath $exe -PathType Leaf)) { $r["why"] = "msg.exe not found"; return $r }
            $Starter = { param($f, $a) Start-ControlScreenSender -Exe $f -ArgLine $a }
        }
        $sess = [System.Diagnostics.Process]::GetCurrentProcess().SessionId
        $safe = ([string]$Text -replace '[^A-Za-z0-9 .,:]', '')
        $secs = [Math]::Max(1, $Seconds)
        $argLine = ('{0} /TIME:{1} "{2}"' -f $sess, $secs, $safe)
        $out = & $Starter $exe $argLine
        $r["pid"] = Get-KioskProp $out "pid" $null
        $code = Get-KioskProp $out "exitCode" $null
        $r["exitCode"] = $code
        if ($null -eq $code) { $r["why"] = "msg.exe reported no exit code: not confirmed shown" }
        elseif ([int]$code -eq 0) { $r["shown"] = $true; $r["why"] = "msg.exe exited 0: accepted for desktop session $sess for $secs s" }
        else { $r["why"] = "msg.exe exited with code $([int]$code): not shown" }
    } catch { $r["why"] = "could not be shown: " + $_.Exception.Message }
    return $r
}

function Start-CancelWarning {
    # A0.467 (Kevin, 2026-10-09): "a booking canceled while its member is playing ends the game after a 5-minute warning.
    # The wall and the launcher show the warning, then the session ends like a normal end. A canceled (refunded) booking
    # never becomes free play." The platform tells the bay with a Reset bound to the running session (it cancels that
    # session's Warn5 and End). This keeps the game running and: records when it ends (cancelEndUtc in the running-session
    # record, persisted, so a restart keeps it); cuts the launcher intent to that end; shows the warning on the wall (ENDING,
    # its countdown now to that end, a "Booking canceled" banner) and on the control screen; moves the facility to its
    # Warning scene. Invoke-CancelEndIfDue then runs the NORMAL End at that time, network or not. A second Reset for the
    # same booking keeps the first end. With no time left (the booking's own end already passed) it ends now.
    param($PayloadObj, [DateTime]$NowUtc)
    $rec = $Global:RunningSession
    $sid = [string](Get-KioskProp $rec "baySessionId" "")
    $prior = ConvertTo-KioskUtc (Get-KioskProp $rec "cancelEndUtc" $null)
    if ($null -ne $prior) {
        return @{ reset = $false; cancelWarning = [ordered]@{ sessionId = $sid; endsUtc = $prior.ToString("yyyy-MM-ddTHH:mm:ssZ"); duplicate = $true } }
    }
    $recEnd = ConvertTo-KioskUtc (Get-KioskProp $rec "endUtc" $null)
    $endsUtc = Get-CancelEndUtc -NowUtc $NowUtc -RecordEndUtc $recEnd -WarningSeconds $RunningSessionCancelWarningSeconds
    $endsText = $endsUtc.ToString("yyyy-MM-ddTHH:mm:ssZ")
    $newRec = [ordered]@{ baySessionId = $sid; endUtc = (Get-KioskProp $rec "endUtc" $null); since = (Get-KioskProp $rec "since" $null); cancelEndUtc = $endsText }
    $written = Set-RunningSession -Record $newRec -Reason ("booking canceled mid-play: it ends at {0} (A0.467)" -f $endsText)
    $out = [ordered]@{ sessionId = $sid; endsUtc = $endsText; warningSeconds = [int][Math]::Max(0, [Math]::Ceiling(($endsUtc - $NowUtc).TotalSeconds)); recordWritten = $written }
    if ($endsUtc -le $NowUtc) {
        $out["endedNow"] = $true
        $out["end"] = Invoke-CancelEndIfDue -NowUtc $NowUtc
        return @{ reset = $false; cancelWarning = $out }
    }
    # The launcher stays wanted only until the warning ends (never extended, never another session, never closed here).
    $out["kiosk"] = Set-KioskIntentForCommand -CommandType $CMD_RESET -Mode "cancel-warning" -Payload ([pscustomobject]@{ baySessionId = $sid; playEndUtc = $endsText })
    try {
        $base = To-Hashtable (Read-SessionModelFromDisk)
        # The next booking's Prep may already have rewritten the wall: show THIS booking's warning, not that one's.
        if (-not (Test-BaySessionIdMatch ([string](Get-PropValue $base "baySessionId" "")) $sid)) { $base = @{ baySessionId = $sid } }
        $base.status = "ENDING"
        $base.playEndUtc = $endsText
        $base.sessionEndUtc = $endsText
        $base.endUtc = $endsText
        $base.bannerText = "Booking canceled"
        $base.statusDetail = "This booking was canceled."
        $base.updatedUtc = (UtcNow-Z)
        if ([string]::IsNullOrWhiteSpace([string](Get-PropValue $base "locationLabel" $null))) { $base.locationLabel = (Get-BayLabel) }
        if ([string]::IsNullOrWhiteSpace([string](Get-PropValue $base "displayName" $null))) { $base.displayName = "Guest" }
        if ([string]::IsNullOrWhiteSpace([string](Get-PropValue $base "helpText" $null))) { $base.helpText = (Get-HelpText) }
        $model = Normalize-SessionModel $base
        [void](Write-SessionFiles $model)
        $out["wall"] = "ENDING until $endsText"
        $out["display"] = Start-SessionDisplay $PayloadObj
    } catch { $out["wall"] = "could not be written: " + $_.Exception.Message }
    try { $out["facility"] = Invoke-FacilitySetMode -Mode "Warning" -payloadObj $PayloadObj } catch { $out["facility"] = @{ ok = $false; error = $_.Exception.Message } }
    $out["control"] = Send-ControlScreenWarning -Text (Get-CancelWarningText -EndsUtc $endsUtc -NowUtc $NowUtc) -Seconds ([int][Math]::Ceiling(($endsUtc - $NowUtc).TotalSeconds))
    try { Write-Log ("[SESSION] booking canceled mid-play: session {0} ends at {1}; wall {2}; control screen {3}" -f $sid, $endsText, $out["wall"], $out["control"]["why"]) "INFO" } catch { }
    return @{ reset = $false; cancelWarning = $out }
}

function Invoke-CancelEndIfDue([DateTime]$NowUtc) {
    # A0.467: the NORMAL End of a booking canceled mid-play, once its warning is over. Every main-loop pass, before the
    # token (no network needed). Only the recorded session, only once its cancelEndUtc has passed. The End is the same
    # handler the platform's End runs (wall ENDED, intent closed, launcher closed, facility Cleanup, record cleared, the
    # session listed as ended), with no booking write-back (the booking is already Canceled). Returns the End's result,
    # or $null when nothing is due. Never throws.
    try {
        $r = $Global:RunningSession
        # R2: nobody is recorded as playing, but an End (this one, or a platform End) began and did not finish closing the
        # launcher: try that again first. It is a no-op when no End is pending.
        if ($null -eq $r) { return (Invoke-PendingEndRetry) }
        if (@($Global:RunningSessionEndPending).Count -gt 0) { Clear-EndPending "" }
        $ce = ConvertTo-KioskUtc (Get-KioskProp $r "cancelEndUtc" $null)
        if ($null -eq $ce -or $NowUtc -lt $ce) { return $null }
        $sid = [string](Get-KioskProp $r "baySessionId" "")
        $payload = ConvertTo-Json -Compress -InputObject ([ordered]@{ mode = "End"; baySessionId = $sid; reason = "BookingCanceled" })
        # A0.489: this End is the agent's own and is not refused by the cancel hold that keeps every other command out.
        $Global:RunningSessionOwnEnd = $true
        try { $res = Execute-Command -CommandType $CMD_ENDSESSION -PayloadJson $payload -BayLabel "" }
        finally { $Global:RunningSessionOwnEnd = $false }
        try { Write-Log ("[SESSION] booking canceled mid-play: session {0} ended after its warning (A0.467)" -f $sid) "INFO" } catch { }
        return $res
    } catch {
        try { Write-Log ("[SESSION] the End of a canceled booking failed: {0}" -f $_.Exception.Message) "WARN" } catch { }
        return $null
    }
}
function Get-KioskIntentForCommand {
    # Pure: what a command does to the launcher intent. $null = leave it as it is.
    param(
        [int]$CommandType,
        [string]$Mode,
        $Payload,
        $CurrentIntentRead,
        [bool]$SameSession,
        [bool]$EmergencyStopEngaged,
        [DateTime]$NowUtc
    )
    # Three values (Get-KioskLauncherWanted): "wanted" (the shell restarts it), "closed" (no session may play: the
    # shell closes a launcher that appears), "unmanaged" (hands off). "closed" is written ONLY by the EndSession of the
    # running session: it must name a session, be the session the running-session record holds (Get-EndSessionScope;
    # session.json when nobody is recorded), and not contradict the session the intent names. Never from a guess, never
    # from a Reset: a wrong "closed" ends a paying member's game (attack RF1).
    $m = $(if ($null -ne $Mode) { $Mode.ToLowerInvariant() } else { "" })
    $sid = [string](Get-KioskProp $Payload "baySessionId" "")
    $cur = Get-KioskLauncherWanted -IntentRead $CurrentIntentRead -NowUtc $NowUtc
    $curSid = [string]$cur.SessionId
    if ($CommandType -eq $CMD_STARTSESSION) {
        if ($EmergencyStopEngaged) { return @{ Launcher = "unmanaged"; UntilUtc = $null; SessionId = $sid; Reason = "emergency stop engaged" } }
        if ($m -eq "start") {
            $end = ConvertTo-KioskUtc (Get-KioskProp $Payload "playEndUtc" $null)
            if ($null -eq $end) { $end = ConvertTo-KioskUtc (Get-KioskProp $Payload "sessionEndUtc" $null) }
            if ($null -eq $end) { $end = ConvertTo-KioskUtc (Get-KioskProp $Payload "endUtc" $null) }
            if ($null -eq $end) { return @{ Launcher = "unmanaged"; UntilUtc = $null; SessionId = $sid; Reason = "Start without a readable end time" } }
            return @{ Launcher = "wanted"; UntilUtc = $end.AddSeconds($KioskIntentGraceSeconds); SessionId = $sid; Reason = "StartSession Start" }
        }
        if ($m -eq "start-disabled") { return @{ Launcher = "unmanaged"; UntilUtc = $null; SessionId = $sid; Reason = "StartSession Start with launcher.startOnStart=false" } }
        # Prep (start minus 15 minutes) may run while the PREVIOUS booking is still playing: it changes nothing.
        return $null
    }
    if ($CommandType -eq $CMD_ENDSESSION) {
        if (-not $SameSession) { return $null }
        # An End that names no session cannot prove it ends the running one (attack E6).
        if ([string]::IsNullOrWhiteSpace($sid)) { return $null }
        # The intent names another session (a later booking already started): not this End's to close.
        if (-not [string]::IsNullOrWhiteSpace($curSid) -and $curSid -cne $sid) { return $null }
        return @{ Launcher = "closed"; UntilUtc = $null; SessionId = $sid; Reason = "EndSession" }
    }
    if ($CommandType -eq $CMD_RESET) {
        # The platform sends a full Reset AT ONCE for every canceled booking, whoever is playing (attack RF1): it never
        # writes "closed" and never creates "wanted". Only the running session's EndSession writes "closed".
        # A0.467: the Reset of the RUNNING booking (canceled mid-play) starts its warning ("cancel-warning"): a wanted
        # intent of that same session is cut to the warning's end. Never extended, never another session.
        if ($m -ne "cancel-warning") { return $null }
        if (-not $cur.Wanted -or [string]::IsNullOrWhiteSpace($sid) -or [string]$cur.SessionId -cne $sid) { return $null }
        $cEnd = ConvertTo-KioskUtc (Get-KioskProp $Payload "playEndUtc" $null)
        if ($null -eq $cEnd) { return $null }
        $cUntil = $cEnd.AddSeconds($KioskIntentGraceSeconds)
        if ($cUntil -ge $cur.UntilUtc) { return $null }
        return @{ Launcher = "wanted"; UntilUtc = $cUntil; SessionId = $sid; Reason = "booking canceled mid-play: wanted until its warning ends (A0.467)" }
    }
    if ($CommandType -eq $CMD_EMERGENCY_STOP) {
        $a = [string](Get-KioskProp $Payload "action" "engage")
        if ($a.ToLowerInvariant() -eq "clear") { return $null }
        # Stops restarts; closes nothing (A0.457, Kevin 2026-10-08: an emergency stop does not close the golf program).
        if (-not $cur.Wanted) { return $null }
        return @{ Launcher = "unmanaged"; UntilUtc = $null; SessionId = $(if ($sid) { $sid } else { $curSid }); Reason = "emergency stop engaged" }
    }
    if ($CommandType -eq $CMD_UPDATESESSIONDISPLAY) {
        # Only EXTENDS a wanted intent of the SAME session to a later end (an extension); never creates one.
        if (-not $cur.Wanted -or [string]::IsNullOrWhiteSpace($sid) -or [string]$cur.SessionId -cne $sid) { return $null }
        $end = ConvertTo-KioskUtc (Get-KioskProp $Payload "playEndUtc" $null)
        if ($null -eq $end) { $end = ConvertTo-KioskUtc (Get-KioskProp $Payload "sessionEndUtc" $null) }
        if ($null -eq $end) { return $null }
        $newUntil = $end.AddSeconds($KioskIntentGraceSeconds)
        if ($newUntil -le $cur.UntilUtc) { return $null }
        return @{ Launcher = "wanted"; UntilUtc = $newUntil; SessionId = $sid; Reason = "UpdateSessionDisplay extended the end" }
    }
    return $null
}

function Write-KioskIntentText([string]$Text) {
    # Lays $Text down atomically and reads it back byte for byte (through a reader that blocks no writer). $true only
    # when the file now holds exactly $Text. Throws on failure (callers catch).
    $dir = Split-Path -Parent $KioskIntentPath
    if (-not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Force -Path $dir | Out-Null }
    $tmp = "$KioskIntentPath.tmp"
    [IO.File]::WriteAllText($tmp, $Text, (New-Object Text.UTF8Encoding($false)))
    try {
        if (Test-Path -LiteralPath $KioskIntentPath) { [IO.File]::Replace($tmp, $KioskIntentPath, [NullString]::Value, $true) }
        else { [IO.File]::Move($tmp, $KioskIntentPath) }
    } catch { [IO.File]::Copy($tmp, $KioskIntentPath, $true); try { [IO.File]::Delete($tmp) } catch { } }
    $fsB = New-Object IO.FileStream($KioskIntentPath, [IO.FileMode]::Open, [IO.FileAccess]::Read, ([IO.FileShare]::ReadWrite -bor [IO.FileShare]::Delete))
    try { $sr = New-Object IO.StreamReader($fsB, (New-Object Text.UTF8Encoding($false))); $back = $sr.ReadToEnd() } finally { $fsB.Dispose() }
    if ($back -cne $Text) { throw "the intent file does not read back as written" }
    return $true
}

function Write-KioskIntent([string]$Launcher, $UntilUtc, [string]$SessionId, [string]$Reason) {
    # The DESIRED intent becomes the agent's baseline BEFORE the write (attack RF2): if the write fails (the file held
    # open, a disk error), the older intent on disk is not authoritative; Test-KioskIntentIntegrity re-applies the
    # desired one on every main-loop pass until it lands, and the report says it is pending. Returns $true only when the
    # file now says exactly this. Never throws.
    $o = [ordered]@{
        schema       = 1
        launcher     = $Launcher
        untilUtc     = $(if ($null -ne $UntilUtc) { ([DateTime]$UntilUtc).ToString("yyyy-MM-ddTHH:mm:ssZ") } else { $null })
        baySessionId = $SessionId
        reason       = $Reason
        writtenUtc   = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
        agentPid     = $PID
    }
    $text = ConvertTo-Json -InputObject $o -Depth 3
    $Global:KioskIntentExpectedText = $text
    $Global:KioskIntentPending = $true
    try {
        [void](Write-KioskIntentText -Text $text)
        $Global:KioskIntentPending = $false
        $Global:KioskIntentLast = [ordered]@{ launcher = $Launcher; untilUtc = $o.untilUtc; reason = $Reason; utc = $o.writtenUtc; ok = $true }
        return $true
    } catch {
        $Global:KioskIntentLast = [ordered]@{ launcher = $Launcher; reason = $Reason; ok = $false; pending = $true; error = $_.Exception.Message }
        $Global:NextCapabilitiesUtc = [DateTime]::MinValue
        try { Write-Log ("[KIOSK] intent '{0}' could not be written (retried every pass until it lands): {1}" -f $Launcher, $_.Exception.Message) "WARN" } catch { }
        return $false
    }
}

function Test-KioskIntentIntegrity {
    # The intent file is state the shell ACTS on (restart, or end a relaunched launcher), and the bay account (or a member
    # at the companion desktop) can write it. This agent is its only author: content that differs from what this agent
    # last DECIDED (written, kept at start, or still pending after a failed write) is put back. A pending write that now
    # lands is reported as landed; a change made outside the agent is counted (security review and attack RF2,
    # 2026-10-08). Before this process has decided an intent there is nothing to compare. Returns $true when it wrote.
    # Never throws.
    try {
        $exp = $Global:KioskIntentExpectedText
        if ($null -eq $exp) { return $false }
        $onDisk = $null
        try {
            $fsI = New-Object IO.FileStream($KioskIntentPath, [IO.FileMode]::Open, [IO.FileAccess]::Read, ([IO.FileShare]::ReadWrite -bor [IO.FileShare]::Delete))
            try { $srI = New-Object IO.StreamReader($fsI, (New-Object Text.UTF8Encoding($false))); $onDisk = $srI.ReadToEnd() } finally { $fsI.Dispose() }
        } catch { $onDisk = $null }
        if ($null -ne $onDisk -and $onDisk -ceq $exp) { $Global:KioskIntentPending = $false; return $false }
        $wasPending = [bool]$Global:KioskIntentPending
        [void](Write-KioskIntentText -Text $exp)
        $Global:KioskIntentPending = $false
        if ($wasPending) {
            try { Write-Log "[KIOSK] the pending intent landed" "INFO" } catch { }
            if ($null -ne $Global:KioskIntentLast) { $Global:KioskIntentLast["ok"] = $true; $Global:KioskIntentLast["pending"] = $false }
        } else {
            $prev = $Global:KioskIntentTamper
            $n = $(if ($null -ne $prev) { [int]$prev["count"] + 1 } else { 1 })
            $Global:KioskIntentTamper = [ordered]@{ count = $n; lastUtc = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ"); found = $(if ($null -eq $onDisk) { "missing" } else { "changed" }) }
            try { Write-Log ("[KIOSK] the intent file was {0} outside the agent; restored ({1} so far)" -f $Global:KioskIntentTamper.found, $n) "WARN" } catch { }
        }
        $Global:NextCapabilitiesUtc = [DateTime]::MinValue
        return $true
    } catch { return $false }
}

function Set-KioskIntentForCommand {
    # Execute-Command's one call per command. Never throws; returns a small summary for the command result, or $null.
    param([int]$CommandType, [string]$Mode, $Payload, [bool]$SameSession = $true)
    # Decide from the intent this agent wrote, never from one edited behind its back.
    [void](Test-KioskIntentIntegrity)
    try {
        $now = (Get-Date).ToUniversalTime()
        # Decide from what this agent last DECIDED (which is what the file says once any pending write lands), never
        # from an older value a failed write left on disk (attack RF2).
        $cur = $null
        if ($null -ne $Global:KioskIntentExpectedText) {
            try { $cur = @{ Ok = $true; Obj = (ConvertFrom-Json -InputObject $Global:KioskIntentExpectedText); Why = "" } } catch { $cur = $null }
        }
        if ($null -eq $cur) { $cur = Read-KioskJsonFile -Path $KioskIntentPath -MaxBytes 8192 }
        $next = Get-KioskIntentForCommand -CommandType $CommandType -Mode $Mode -Payload $Payload -CurrentIntentRead $cur `
            -SameSession $SameSession -EmergencyStopEngaged ([bool]$Global:EmergencyStopEngaged) -NowUtc $now
        if ($null -eq $next) { return $null }
        $ok = Write-KioskIntent -Launcher $next.Launcher -UntilUtc $next.UntilUtc -SessionId $next.SessionId -Reason $next.Reason
        return [ordered]@{ launcher = $next.Launcher; untilUtc = $(if ($null -ne $next.UntilUtc) { $next.UntilUtc.ToString("yyyy-MM-ddTHH:mm:ssZ") } else { $null }); written = $ok }
    } catch {
        try { Write-Log ("[KIOSK] intent for command {0} failed: {1}" -f $CommandType, $_.Exception.Message) "WARN" } catch { }
        return $null
    }
}

function Initialize-KioskIntent([DateTime]$NowUtc) {
    # Agent start. The intent file outlives a restart and is the better record: a readable one is KEPT (session.json can
    # be rewritten by a late EndSession of an older session, measured 2026-10-08). Only an absent or unreadable intent
    # is derived from session.json: wanted for a running session (an agent restart mid-session keeps the member
    # playing), otherwise "unmanaged". "closed" is never derived from a guess. An engaged emergency stop turns a wanted
    # intent into "unmanaged". Never throws.
    try {
        $curRead = Read-KioskJsonFile -Path $KioskIntentPath -MaxBytes 8192
        $cur = Get-KioskLauncherWanted -IntentRead $curRead -NowUtc $NowUtc
        $diskText = $null
        if ($curRead.Ok) {
            try {
                $fsS = New-Object IO.FileStream($KioskIntentPath, [IO.FileMode]::Open, [IO.FileAccess]::Read, ([IO.FileShare]::ReadWrite -bor [IO.FileShare]::Delete))
                try { $srS = New-Object IO.StreamReader($fsS, (New-Object Text.UTF8Encoding($false))); $diskText = $srS.ReadToEnd() } finally { $fsS.Dispose() }
            } catch { $diskText = $null }
        }
        if ($Global:EmergencyStopEngaged) {
            if ($cur.Wanted) { [void](Write-KioskIntent -Launcher "unmanaged" -UntilUtc $null -SessionId ([string]$cur.SessionId) -Reason "agent start: emergency stop engaged") }
            elseif (-not $curRead.Ok -or $null -eq $diskText) { [void](Write-KioskIntent -Launcher "unmanaged" -UntilUtc $null -SessionId "" -Reason "agent start: emergency stop engaged") }
            else { $Global:KioskIntentExpectedText = $diskText }
            return
        }
        $model = Read-SessionModelFromDisk
        $status = [string](Get-KioskProp $model "status" "")
        $end = ConvertTo-KioskUtc (Get-KioskProp $model "sessionEndUtc" $null)
        $sid = [string](Get-KioskProp $model "baySessionId" "")
        $l = $(if ($curRead.Ok) { Get-KioskProp $curRead.Obj "launcher" $null } else { $null })
        if ($null -ne $diskText -and $l -is [string] -and $l -cin @("closed", "unmanaged")) { $Global:KioskIntentExpectedText = $diskText; return }
        if ($null -ne $diskText -and $l -is [string] -and $l -ceq "wanted") {
            # Adopted only when session.json backs it: the same session running, and no later end than that session's
            # own end plus the grace (attack residual R1: a "wanted until 2099" written while the agent was down).
            $backed = ($status -in @("ACTIVE", "ENDING") -and -not [string]::IsNullOrWhiteSpace($sid) -and [string]$cur.SessionId -ceq $sid -and
                       $null -ne $end -and $null -ne $cur.UntilUtc -and $cur.UntilUtc -le $end.AddSeconds($KioskIntentGraceSeconds))
            $expiredWanted = ($null -ne (ConvertTo-KioskUtc (Get-KioskProp $curRead.Obj "untilUtc" $null)) -and -not $cur.Wanted)
            if ($backed -or $expiredWanted) { $Global:KioskIntentExpectedText = $diskText; return }
            [void](Write-KioskIntent -Launcher "unmanaged" -UntilUtc $null -SessionId ([string]$cur.SessionId) -Reason "agent start: a wanted intent that session.json does not back")
            return
        }
        if ($status -in @("ACTIVE", "ENDING") -and $null -ne $end -and $NowUtc -lt $end.AddSeconds($KioskIntentGraceSeconds)) {
            [void](Write-KioskIntent -Launcher "wanted" -UntilUtc ($end.AddSeconds($KioskIntentGraceSeconds)) -SessionId $sid -Reason "agent start: session.json says $status")
        } else {
            [void](Write-KioskIntent -Launcher "unmanaged" -UntilUtc $null -SessionId $sid -Reason ("agent start: no running session (status '{0}')" -f $status))
        }
    } catch { try { Write-Log ("[KIOSK] intent could not be derived at start: {0}" -f $_.Exception.Message) "WARN" } catch { } }
}

function Get-KioskWinlogonFacts {
    # READ ONLY. This agent runs as BayKiosk, so HKCU here is BayKiosk's own hive (bench Part B question 12).
    $w = [ordered]@{ user = ("{0}\{1}" -f $env:USERDOMAIN, $env:USERNAME); hkcuShell = $null; hklmShell = $null }
    try { $w.hkcuShell = [string](Get-ItemProperty -LiteralPath "HKCU:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name Shell -ErrorAction Stop).Shell } catch { $w.hkcuShell = "(not set)" }
    try { $w.hklmShell = [string](Get-ItemProperty -LiteralPath "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name Shell -ErrorAction Stop).Shell } catch { $w.hklmShell = "(unreadable)" }
    return $w
}

function Read-KioskReconcileStarts([DateTime]$NowUtc) {
    # Shell start times, persisted so an agent restart does not reset the hourly cap. Present but unreadable: assume
    # the cap is spent for the next hour (fail toward not starting; the desktop stays as it is).
    $r = Read-KioskJsonFile -Path $KioskReconcilePath -MaxBytes 65536
    if (-not $r.Ok) {
        if ($r.Why -eq "absent") { return [DateTime[]]@() }
        $seed = @(); for ($i = 0; $i -lt $KioskShellMaxStartsPerHour; $i++) { $seed += $NowUtc }
        return [DateTime[]]$seed
    }
    $out = @()
    # Assigned first, then wrapped: Get-KioskProp returns an array as ONE object, and @(<call>) would nest it.
    $starts = Get-KioskProp $r.Obj "shellStarts" $null
    foreach ($t in @($starts)) { $u = ConvertTo-KioskUtc $t; if ($null -ne $u) { $out += $u } }
    return [DateTime[]]$out
}

$Global:KioskSignerThumbprint = $null
$Global:KioskVerifyCache = $null
$Global:KioskReport = $null
$Global:KioskIntentLast = $null
$Global:KioskIntentExpectedText = $null
$Global:KioskIntentTamper = $null
$Global:KioskIntentPending = $false
$Global:KioskStarts = [DateTime[]]@()
$Global:KioskNextReconcileUtc = [DateTime]::MinValue

function Initialize-Kiosk([DateTime]$NowUtc) {
    # The certificate that signed THIS script (the bay signs every release on arrival with its own certificate); a
    # shell file must carry the same signer. An unsigned or invalid agent has no signer to match: no shell is started.
    try {
        $a = Get-KioskAuthenticode $AgentScriptPath
        if ($a.Status -eq "Valid" -and -not [string]::IsNullOrWhiteSpace([string]$a.Thumbprint)) { $Global:KioskSignerThumbprint = [string]$a.Thumbprint }
    } catch { }
    $Global:KioskStarts = Read-KioskReconcileStarts -NowUtc $NowUtc
    Initialize-KioskIntent -NowUtc $NowUtc
}

function Invoke-KioskReconcileTick {
    # Once a minute and at start, before the token (it needs no network). Never throws.
    param([DateTime]$NowUtc, [scriptblock]$CommandLineOf = $null, [scriptblock]$StartShell = $null, [scriptblock]$StopProcess = $null, [scriptblock]$ExplorerProbe = $null)
    if ($null -eq $CommandLineOf) { $CommandLineOf = { param($procId) Get-KioskProcessCommandLine $procId } }
    if ($null -eq $ExplorerProbe) { $ExplorerProbe = { @(Get-Process -Name "explorer" -ErrorAction SilentlyContinue | Where-Object { $_.SessionId -eq [System.Diagnostics.Process]::GetCurrentProcess().SessionId }).Count -gt 0 } }
    if ($null -eq $StartShell) { $StartShell = { param($exe, $argLine) (Start-Process -FilePath $exe -ArgumentList $argLine -WindowStyle Hidden -PassThru).Id } }
    if ($null -eq $StopProcess) { $StopProcess = { param($procId) Stop-Process -Id $procId -Force -ErrorAction Stop } }
    $rep = [ordered]@{ utc = $NowUtc.ToString("yyyy-MM-ddTHH:mm:ssZ") }
    try {
        $policy = Get-KioskReleasePolicy
        $rep["target"] = $policy.Mode
        $rep["requested"] = $policy.Requested
        $rep["reason"] = $policy.Reason
        $rep["killSwitch"] = (Test-Path -LiteralPath $KioskKillSwitchPath)
        $rep["releaseMode"] = $policy.ReleaseMode
        $rep["policyMatchesRelease"] = [bool]$policy.MatchesRelease

        # Maintenance / Offline: hands off. Stops restarts, and lifts "closed" so staff working on the bay can run the
        # launcher; the next EndSession closes it again.
        try {
            if ($Global:EffectiveConfig) {
                $op = Get-AgentOperationalState -eff $Global:EffectiveConfig
                if ($op.Blocked) {
                    $cur = Get-KioskLauncherWanted -IntentRead (Read-KioskJsonFile -Path $KioskIntentPath -MaxBytes 8192) -NowUtc $NowUtc
                    if ($cur.Wanted -or $cur.Closed) { [void](Write-KioskIntent -Launcher "unmanaged" -UntilUtc $null -SessionId ([string]$cur.SessionId) -Reason ("bay in {0} mode" -f $op.ModeLabel)) }
                }
            }
        } catch { }

        $shellPath = Get-KioskShellPath
        $verify = $null
        # The cached verdict is keyed on the file's CONTENT (SHA256, taken every tick), never on its size and write time:
        # a file replaced with the same size and time (robocopy treats that as "same") must be verified again, or a stale
        # "verified" would keep authorizing whatever now sits at that path (security review, 2026-10-08).
        $shellSha = $null
        try {
            if (Test-Path -LiteralPath $shellPath -PathType Leaf) {
                $hAlg = [System.Security.Cryptography.SHA256]::Create()
                $hFs = [IO.File]::OpenRead($shellPath)
                try { $shellSha = ([BitConverter]::ToString($hAlg.ComputeHash($hFs)) -replace "-", "").ToLowerInvariant() } finally { $hFs.Dispose(); $hAlg.Dispose() }
            }
        } catch { $shellSha = $null }
        $key = $(if ($null -ne $shellSha) { "{0}|{1}|{2}|{3}" -f $shellPath, $shellSha, $policy.MinShellBytes, $Global:KioskSignerThumbprint } else { "nohash|" + [guid]::NewGuid().ToString("N") })
        if ($null -ne $Global:KioskVerifyCache -and $Global:KioskVerifyCache.Key -eq $key) { $verify = $Global:KioskVerifyCache.Result }
        else {
            $verify = Test-KioskShellFile -Path $shellPath -MinBytes $policy.MinShellBytes -ExpectedSignerThumbprint ([string]$Global:KioskSignerThumbprint) `
                -ExpectedFolder (Join-Path $BaseDir ("releases\{0}\kiosk" -f $AgentCodeVersion))
            $Global:KioskVerifyCache = @{ Key = $key; Result = $verify }
        }
        $rep["shellFile"] = [ordered]@{ path = $shellPath; ok = $verify.Ok; why = $verify.Why; bytes = $verify.Bytes; sha256 = $verify.Sha256; signature = $verify.Signature; timestamped = $verify.Timestamped; signerMatchesAgent = $verify.SignerMatches }

        $live = Get-KioskShellLiveness -HeartbeatRead (Read-KioskJsonFile -Path $KioskHeartbeatPath -MaxBytes 65536) -NowUtc $NowUtc -CommandLineOf $CommandLineOf
        $rep["shell"] = $live
        $action = "none"

        if ($live.State -eq "hung") {
            # Only a process whose command line names a kiosk shell of this install (Get-KioskShellLiveness checked it).
            try { & $StopProcess ([int]$live.Pid); $action = ("stopped hung shell pid {0}" -f $live.Pid); Write-Log ("[KIOSK] {0} ({1})" -f $action, $live.Why) "WARN" }
            catch { $action = ("could not stop hung shell pid {0}: {1}" -f $live.Pid, $_.Exception.Message) }
            $live.State = "absent"
        }

        if ($policy.Mode -eq "companion" -and $live.State -in @("absent", "foreign")) {
            $explorer = [bool](& $ExplorerProbe)
            $cut = $NowUtc.AddHours(-1)
            $Global:KioskStarts = [DateTime[]]@(@($Global:KioskStarts) | Where-Object { $_ -gt $cut })
            if (-not $verify.Ok) { $action = "not started: shell file " + $verify.Why }
            elseif (-not $explorer) { $action = "not started: no Explorer in this session (companion needs the Windows desktop)" }
            elseif (@($Global:KioskStarts).Count -ge $KioskShellMaxStartsPerHour) { $action = ("not started: {0} starts in the last hour" -f $KioskShellMaxStartsPerHour) }
            else {
                $Global:KioskStarts = [DateTime[]]@(@($Global:KioskStarts) + $NowUtc)
                try {
                    $newPid = & $StartShell (Get-KioskPowerShellExe) (Get-KioskShellArgumentList $shellPath)
                    $action = ("started shell pid {0}" -f $newPid)
                    Write-Log ("[KIOSK] {0} ({1})" -f $action, $shellPath) "INFO"
                } catch { $action = "start failed: " + $_.Exception.Message; Write-Log ("[KIOSK] {0}" -f $action) "ERROR" }
            }
        }
        $rep["action"] = $action
        $rep["shellStartsLastHour"] = @($Global:KioskStarts).Count
        try {
            Write-JsonAtomic -path $KioskReconcilePath -obj ([ordered]@{
                schema = 1; utc = $rep.utc; target = $policy.Mode; reason = $policy.Reason; shellState = $live.State; action = $action
                shellStarts = @(@($Global:KioskStarts) | ForEach-Object { $_.ToString("yyyy-MM-ddTHH:mm:ssZ") })
            })
        } catch { }
        if ($action -ne "none" -and $action -ne $(if ($null -ne $Global:KioskReport) { $Global:KioskReport["action"] } else { $null })) { $Global:NextCapabilitiesUtc = [DateTime]::MinValue }
    } catch {
        $rep["error"] = $_.Exception.Message
        try { Write-Log ("[KIOSK] reconcile failed: {0}" -f $_.Exception.Message) "WARN" } catch { }
    }
    try { $rep["winlogon"] = (Get-KioskWinlogonFacts) } catch { }
    $Global:KioskReport = $rep
}

function Invoke-KioskReconcileTickIfDue([DateTime]$NowUtc) {
    # Every main-loop pass (a few seconds): an edited intent file is put back before it can steer the shell for long.
    try { [void](Test-KioskIntentIntegrity) } catch { }
    try { [void](Sync-RunningSessionFile) } catch { }
    if ($NowUtc -lt $Global:KioskNextReconcileUtc) { return }
    $Global:KioskNextReconcileUtc = $NowUtc.AddSeconds($KioskReconcileEverySeconds)
    try { Invoke-KioskReconcileTick -NowUtc $NowUtc } catch { }
}

function Get-KioskLauncherDeferral([DateTime]$NowUtc, [scriptblock]$CommandLineOf = $null) {
    # At StartSession Start: leave the launcher to the shell only while a live, supervising, non-degraded shell runs
    # under a companion policy AND the intent says wanted. Anything else: BayAgent starts it itself, as before.
    if ($null -eq $CommandLineOf) { $CommandLineOf = { param($procId) Get-KioskProcessCommandLine $procId } }
    try {
        $policy = Get-KioskReleasePolicy
        if ($policy.Mode -ne "companion") { return @{ Defer = $false; Why = "policy " + $policy.Mode } }
        $want = Get-KioskLauncherWanted -IntentRead (Read-KioskJsonFile -Path $KioskIntentPath -MaxBytes 8192) -NowUtc $NowUtc
        if (-not $want.Wanted) { return @{ Defer = $false; Why = $want.Reason } }
        $live = Get-KioskShellLiveness -HeartbeatRead (Read-KioskJsonFile -Path $KioskHeartbeatPath -MaxBytes 65536) -NowUtc $NowUtc -CommandLineOf $CommandLineOf
        if ($live.State -ne "alive") { return @{ Defer = $false; Why = "shell " + $live.State } }
        if (-not $live.Supervising -or $live.Degraded) { return @{ Defer = $false; Why = "shell not supervising" } }
        return @{ Defer = $true; Why = "the kiosk shell starts and places the launcher" }
    } catch { return @{ Defer = $false; Why = "deferral check failed: " + $_.Exception.Message } }
}

function Get-KioskWallDeferral([DateTime]$NowUtc, [scriptblock]$CommandLineOf = $null) {
    # The wall window: left to the shell while a live, supervising, non-degraded shell runs under a companion policy.
    # Anything else (and any failure to tell): BayAgent starts and routes it, as before. Never throws.
    if ($null -eq $CommandLineOf) { $CommandLineOf = { param($procId) Get-KioskProcessCommandLine $procId } }
    try {
        $policy = Get-KioskReleasePolicy
        if ($policy.Mode -ne "companion") { return @{ Defer = $false; Why = "wall: policy " + $policy.Mode } }
        $live = Get-KioskShellLiveness -HeartbeatRead (Read-KioskJsonFile -Path $KioskHeartbeatPath -MaxBytes 65536) -NowUtc $NowUtc -CommandLineOf $CommandLineOf
        if ($live.State -ne "alive") { return @{ Defer = $false; Why = "wall: shell " + $live.State } }
        if (-not $live.Supervising -or $live.Degraded) { return @{ Defer = $false; Why = "wall: shell not supervising" } }
        return @{ Defer = $true; Why = "the kiosk shell keeps the wall" }
    } catch { return @{ Defer = $false; Why = "wall deferral check failed: " + $_.Exception.Message } }
}

function Wait-KioskShellLauncher([int]$TimeoutSeconds) {
    # After deferring: report whether the shell actually brought the launcher up (from its heartbeat), within the wait.
    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    do {
        $hb = Read-KioskJsonFile -Path $KioskHeartbeatPath -MaxBytes 65536
        if ($hb.Ok) {
            $lo = Get-KioskProp $hb.Obj "launcher" $null
            if ((Get-KioskProp $lo "running" $false) -eq $true) { return @{ running = $true; pid = (Get-KioskProp $lo "pid" $null) } }
        }
        Start-Sleep -Milliseconds 500
    } while ((Get-Date) -lt $deadline)
    return @{ running = $false; note = ("the shell did not report the launcher running within {0} s" -f $TimeoutSeconds) }
}

function Get-KioskCapability {
    # The kiosk block of build_agentcapabilitiesjson (and, compact, of HealthCheck).
    $k = [ordered]@{ codeVersion = $AgentCodeVersion }
    $r = $Global:KioskReport
    if ($null -ne $r) { foreach ($kv in $r.GetEnumerator()) { $k[$kv.Key] = $kv.Value } }
    try {
        $w = Get-KioskLauncherWanted -IntentRead (Read-KioskJsonFile -Path $KioskIntentPath -MaxBytes 8192) -NowUtc ((Get-Date).ToUniversalTime())
        $k["intent"] = [ordered]@{ wanted = [bool]$w.Wanted; closed = [bool]$w.Closed; reason = $w.Reason; untilUtc = $(if ($null -ne $w.UntilUtc) { $w.UntilUtc.ToString("yyyy-MM-ddTHH:mm:ssZ") } else { $null }); lastWrite = $Global:KioskIntentLast }
    } catch { }
    $k["signerKnown"] = (-not [string]::IsNullOrWhiteSpace([string]$Global:KioskSignerThumbprint))
    $k["intentRestored"] = $Global:KioskIntentTamper
    $k["intentPending"] = [bool]$Global:KioskIntentPending
    # The shell reads session.json at the LOCAL config's path; a platform overlay that moved it would leave the shell
    # unable to confirm any session (it then neither restarts nor closes anything). Say so if they differ.
    try {
        $localSj = $null
        $lr = Read-KioskJsonFile -Path $CfgPath -MaxBytes 262144
        if ($lr.Ok) { $localSj = Get-KioskProp $lr.Obj "sessionJsonPath" $null }
        if ($localSj -isnot [string] -or [string]::IsNullOrWhiteSpace($localSj)) { $localSj = "C:\AllBirdies\SessionDisplay\data\session.json" }
        $k["sessionJsonPathSharedWithShell"] = ([IO.Path]::GetFullPath([string](Get-SessionJsonPath)) -ieq [IO.Path]::GetFullPath($localSj))
    } catch { $k["sessionJsonPathSharedWithShell"] = $null }
    return $k
}

function Get-KioskHealthSummary {
    $r = $Global:KioskReport
    if ($null -eq $r) { return $null }
    $s = [ordered]@{ target = $r["target"] }
    try { $s["shell"] = $r["shell"]["State"] } catch { }
    try { $s["shellFileOk"] = $r["shellFile"]["ok"] } catch { }
    try { $s["hkcuShell"] = $r["winlogon"]["hkcuShell"]; $s["hklmShell"] = $r["winlogon"]["hklmShell"] } catch { }
    try { $s["action"] = $r["action"] } catch { }
    return $s
}

# ---------------- A0.327 Phase 2: the bay heals itself (frozen-program watchdog + health self-reports) ----------------
# Kevin, A0.327(2), 2026-10-01: a frozen golf program is restarted by the BAY ITSELF, by a local watchdog that nothing
# outside the bay can trigger. There is NO new bay command; A0.316(4) and the 2026-08-18 safe-controls ruling stand.
#
# WHAT THIS SECTION DOES, AND ONLY WHEN agent-config.json SAYS selfHeal.enabled = true (OFF BY DEFAULT)
#   1. Watchdog. Every few seconds it reads whether each CONFIGURED golf program is responding. A program that has
#      been unresponsive for 30 seconds or more, outside its launch grace, and not visibly loading, is closed BY ITS
#      PROCESS ID so the kiosk shell (ABG.LauncherShell.ps1) reopens it. At most 2 restarts per 15 minutes, counted
#      in a file so an agent restart does not reset the count. It touches no other process.
#   2. Health self-reports into the EXISTING diagnostic pipe (build_diagnosticlog -> the platform's
#      EquipDiagIngestRollup port): golf program running and responding, screen count, audio output present.
#   3. Restart events (restarting, recovered with the lost minutes, gave up) into the same pipe, so the platform can
#      tell the member "We spotted it. The golf software froze and is restarting." The club decides any make-good BY
#      HAND (A0.327(4)); the bay only records the minutes.
#
# NOTHING OUTSIDE THE BAY CAN STEER IT. Its settings are read from the LOCAL agent-config.json file at startup, never
# from the platform's BayProfile / ConfigItem overlay (Apply-EffectiveConfigToRuntime rewrites $cfg.launcher.* from
# Dataverse; the watchdog never reads $cfg). The only platform input it honors is the bay's Maintenance/Offline mode
# and the emergency-stop latch, and both can only STOP a restart, never cause one.
#
# SEVERITY. Every row this section writes is Info by default, so the ingest opens NO issue and sends NO email:
# A0.327(3) alerts a person only after the automatic fix AND the member's steps fail, and the member's steps live in
# the platform's fix flow, not here. selfHeal.watchdog.giveUpSeverity = "warning" makes the gave-up row open an issue.
#
# OPEN QUESTION (bench Test 4): whether the Uneekor Launcher and its games report "not responding" to Windows when
# frozen is UNVERIFIED. Detection is therefore PLUGGABLE: selfHeal.watchdog.detector names an entry in
# $script:SelfHealDetectors. A reading of $null ("cannot tell") never counts toward a restart.

$SelfHealDenyNames = @(
    "powershell", "pwsh", "powershell_ise", "cmd", "conhost", "explorer", "msedge", "msedgewebview2", "winlogon",
    "csrss", "lsass", "services", "svchost", "smss", "wininit", "dwm", "system", "idle", "registry", "taskmgr",
    "fontdrvhost", "sihost", "ctfmon", "runtimebroker", "searchhost", "searchapp", "startmenuexperiencehost",
    "textinputhost", "userinit", "logonui", "audiodg", "spoolsv", "wmiprvse", "dllhost", "taskhostw", "mmc",
    "regedit", "schtasks", "msiexec", "rundll32", "wscript", "cscript", "mshta", "bayagent"
)

# Check ids. The ingest derives the issue type from the LAST space-separated token of build_diagnosticname, so each
# name ends in exactly one of these.
$SelfHealCheckResponding = "software.golf.responding"
$SelfHealCheckScreens    = "display.screens"
$SelfHealCheckAudio      = "pc.audio"
$SelfHealCheckRestarting = "software.golf.restarting"
$SelfHealCheckRecovered  = "software.golf.recovered"
$SelfHealCheckFrozen     = "software.golf.frozen"

# build_diagnosticlog choice values (AceOfClubs Entities/build_DiagnosticLog/Entity.xml).
$SelfHealCatPC        = 100000000
$SelfHealCatSoftware  = 100000004
$SelfHealCatDisplay   = 100000005
$SelfHealSevInfo      = 100000000
$SelfHealSevWarning   = 100000001
$SelfHealStatusPassed       = 1
$SelfHealStatusFailed       = 271980001
$SelfHealStatusInconclusive = 271980002
$SelfHealDiagEntitySet      = "build_diagnosticlogs"

$SelfHealStatePath  = Join-Path $BaseDir "state\selfheal-watchdog.json"
$SelfHealOutboxPath = Join-Path $BaseDir "state\selfheal-outbox.json"
$SelfHealOutboxMax  = 200

function ConvertTo-SelfHealUtc($value) {
    # ISO text (Windows PowerShell 5.1 leaves it as a string) or a DateTime (PowerShell 7 converts it): UTC either way.
    if ($null -eq $value) { return $null }
    if ($value -is [DateTime]) { return $value.ToUniversalTime() }
    $s = [string]$value
    if ([string]::IsNullOrWhiteSpace($s)) { return $null }
    try {
        return [DateTime]::Parse($s, [Globalization.CultureInfo]::InvariantCulture,
            ([Globalization.DateTimeStyles]::AdjustToUniversal -bor [Globalization.DateTimeStyles]::AssumeUniversal))
    } catch { return $null }
}

function Format-SelfHealUtc($value) {
    if ($null -eq $value) { return $null }
    return ([DateTime]$value).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
}

function Get-SelfHealSettingInt($obj, [string]$name, [int]$default, [int]$min, [int]$max) {
    # Out of range CLAMPS toward the safe side; unreadable falls back to the default.
    $v = Get-PropValue $obj $name $null
    if ($null -eq $v) { return $default }
    $n = 0
    try { $n = [int]$v } catch { return $default }
    if ($n -lt $min) { return $min }
    if ($n -gt $max) { return $max }
    return $n
}

function Test-SelfHealFlag($obj, [string]$name) {
    # Only a JSON true turns a flag on. "true" as text, 1, [true], or anything else is OFF. The property is read
    # directly: Get-PropValue returns through the pipeline, which unrolls [true] into $true (verifier R7).
    if ($null -eq $obj -or -not ($obj -is [System.Management.Automation.PSCustomObject])) { return $false }
    $hit = @($obj.PSObject.Properties | Where-Object { $_.Name -ceq $name })
    if ($hit.Count -ne 1) { return $false }
    $v = $hit[0].Value
    return (($v -is [bool]) -and ($v -eq $true))
}

function ConvertTo-SelfHealTargetName([string]$raw) {
    # A target is an exact process name: no path, no wildcard, no deny-listed system or agent process.
    if ([string]::IsNullOrWhiteSpace($raw)) { return $null }
    $n = $raw.Trim()
    if ($n.EndsWith(".exe", [StringComparison]::OrdinalIgnoreCase)) { $n = $n.Substring(0, $n.Length - 4) }
    if ($n -notmatch '^[A-Za-z0-9][A-Za-z0-9 ._-]{0,63}$') { return $null }
    foreach ($d in $SelfHealDenyNames) { if ($n -ieq $d) { return $null } }
    return $n
}

function Read-SelfHealSettings {
    # Reads the LOCAL agent-config.json from disk. Never $cfg: by the time the main loop runs, $cfg.launcher has been
    # rewritten from the platform's BayProfile / ConfigItems, and a platform-side value must never pick what this kills.
    param([Parameter(Mandatory=$true)][string]$Path)

    $s = [ordered]@{
        Enabled = $false; WatchdogEnabled = $false; HealthEnabled = $false
        Targets = @(); Detector = "hungAppWindow"
        UnresponsiveSeconds = 30; LaunchGraceSeconds = 120; LoadingMaxSeconds = 180
        MaxRestarts = 2; WindowMinutes = 15; SampleSeconds = 5; MaxSampleGapSeconds = 15
        RecoveryWaitSeconds = 120; RelaunchWaitSeconds = 15
        CpuBusyFraction = 0.10; IoBusyBytes = 1048576
        GiveUpSeverity = $SelfHealSevInfo
        HealthIntervalMinutes = 60; HealthMinGapMinutes = 5; HealthSampleSeconds = 60; ExpectedScreens = $null
        Errors = @()
    }

    $root = $null
    try { $root = Get-Content -LiteralPath $Path -Raw -ErrorAction Stop | ConvertFrom-Json }
    catch { $s.Errors += "agent-config.json unreadable: $($_.Exception.Message)"; return [pscustomobject]$s }

    $sh = Get-PropValue $root "selfHeal" $null
    if ($null -eq $sh) { return [pscustomobject]$s }

    $s.Enabled = (Test-SelfHealFlag $sh "enabled")
    $wd = Get-PropValue $sh "watchdog" $null
    $hr = Get-PropValue $sh "healthReports" $null

    if ($null -ne $wd) {
        $s.WatchdogEnabled = (Test-SelfHealFlag $wd "enabled")
        $det = Get-PropValue $wd "detector" $null
        if (-not [string]::IsNullOrWhiteSpace([string]$det)) { $s.Detector = ([string]$det).Trim() }

        # Floors are the ruling's numbers: config may make the watchdog MORE patient, never quicker or more often.
        $s.UnresponsiveSeconds = Get-SelfHealSettingInt $wd "unresponsiveSeconds" 30 30 600
        $s.LaunchGraceSeconds  = Get-SelfHealSettingInt $wd "launchGraceSeconds" 120 120 1800
        $s.LoadingMaxSeconds   = Get-SelfHealSettingInt $wd "loadingMaxSeconds" 180 ([Math]::Max(180, $s.UnresponsiveSeconds)) 3600
        $s.MaxRestarts         = Get-SelfHealSettingInt $wd "maxRestarts" 2 0 2
        $s.WindowMinutes       = Get-SelfHealSettingInt $wd "windowMinutes" 15 15 1440
        $s.SampleSeconds       = Get-SelfHealSettingInt $wd "sampleSeconds" 5 2 15
        $s.MaxSampleGapSeconds = [Math]::Max(15, 3 * $s.SampleSeconds)
        $s.RecoveryWaitSeconds = Get-SelfHealSettingInt $wd "recoveryWaitSeconds" 120 30 900
        $s.RelaunchWaitSeconds = Get-SelfHealSettingInt $wd "relaunchWaitSeconds" 15 5 120
        $cpuPct = Get-SelfHealSettingInt $wd "cpuBusyPercent" 10 1 100
        $s.CpuBusyFraction = $cpuPct / 100.0
        $s.IoBusyBytes = [double](Get-SelfHealSettingInt $wd "ioBusyKilobytes" 1024 64 1048576) * 1024
        $gus = [string](Get-PropValue $wd "giveUpSeverity" "info")
        if ($gus -ieq "warning") { $s.GiveUpSeverity = $SelfHealSevWarning }

        $rawTargets = Get-PropValue $wd "targets" $null
        $targets = @()
        if ($null -ne $rawTargets) {
            foreach ($t in @($rawTargets)) {
                $name = ConvertTo-SelfHealTargetName ([string](Get-PropValue $t "processName" ""))
                if ($null -eq $name) { $s.Errors += "watchdog target refused: '$([string](Get-PropValue $t 'processName' ''))'"; continue }
                $relaunch = ([string](Get-PropValue $t "relaunch" "shell")).Trim().ToLowerInvariant()
                if ($relaunch -notin @("shell", "agent", "none")) { $s.Errors += "watchdog target '$name': relaunch must be shell, agent or none"; continue }
                $tPath = [string](Get-PropValue $t "path" "")
                if ($relaunch -eq "agent" -and [string]::IsNullOrWhiteSpace($tPath)) { $s.Errors += "watchdog target '$name': relaunch agent needs a path"; continue }
                $targets += [pscustomobject]@{ Name = $name; Relaunch = $relaunch; Path = $tPath; ArgLine = [string](Get-PropValue $t "args" "") }
            }
        } else {
            # No explicit list: the golf launcher named in the LOCAL file (not the overlaid $cfg), reopened by the shell.
            $lname = ConvertTo-SelfHealTargetName ([string](Get-PropValue (Get-PropValue $root "launcher" $null) "processName" ""))
            if ($null -ne $lname) { $targets += [pscustomobject]@{ Name = $lname; Relaunch = "shell"; Path = ""; ArgLine = "" } }
        }
        $s.Targets = $targets
        if ($s.WatchdogEnabled -and $targets.Count -eq 0) {
            $s.Errors += "watchdog has no valid target; it stays off"
            $s.WatchdogEnabled = $false
        }
    }

    if ($null -ne $hr) {
        $s.HealthEnabled = (Test-SelfHealFlag $hr "enabled")
        $s.HealthIntervalMinutes = Get-SelfHealSettingInt $hr "intervalMinutes" 60 15 1440
        $s.HealthMinGapMinutes   = Get-SelfHealSettingInt $hr "minGapMinutes" 5 1 60
        $exp = Get-PropValue $hr "expectedScreens" $null
        if ($null -ne $exp) { try { $e = [int]$exp; if ($e -ge 1 -and $e -le 16) { $s.ExpectedScreens = $e } } catch {} }
        if ($s.Targets.Count -eq 0) {
            $lname2 = ConvertTo-SelfHealTargetName ([string](Get-PropValue (Get-PropValue $root "launcher" $null) "processName" ""))
            if ($null -ne $lname2) { $s.Targets = @([pscustomobject]@{ Name = $lname2; Relaunch = "shell"; Path = ""; ArgLine = "" }) }
        }
    }

    if (-not $s.Enabled) { $s.WatchdogEnabled = $false; $s.HealthEnabled = $false }
    return [pscustomobject]$s
}

# ---- native helpers, compiled ONLY when the feature is on (flag off = no Add-Type, no new runtime behavior) ----
$script:SelfHealNativeState = "unloaded"

function Initialize-SelfHealNative {
    if ($script:SelfHealNativeState -eq "ok") { return $true }
    if ($script:SelfHealNativeState -eq "failed") { return $false }
    try {
        if (-not ("ABGSelfHealNative" -as [type])) {
Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;

public static class ABGSelfHealNative {
    [DllImport("user32.dll")] public static extern bool IsHungAppWindow(IntPtr hWnd);
    [DllImport("user32.dll")] public static extern bool IsWindow(IntPtr hWnd);

    [StructLayout(LayoutKind.Sequential)]
    public struct IO_COUNTERS {
        public ulong ReadOperationCount; public ulong WriteOperationCount; public ulong OtherOperationCount;
        public ulong ReadTransferCount; public ulong WriteTransferCount; public ulong OtherTransferCount;
    }
    [DllImport("kernel32.dll", SetLastError=true)] public static extern bool GetProcessIoCounters(IntPtr hProcess, out IO_COUNTERS counters);

    [ComImport, Guid("BCDE0395-E52F-467C-8E3D-C4579291692E")] private class MMDeviceEnumeratorCom { }

    [Guid("A95664D2-9614-4F35-A746-DE8DB63617E6"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
    private interface IMMDeviceEnumerator {
        [PreserveSig] int EnumAudioEndpoints(int dataFlow, int stateMask, out IntPtr devices);
        [PreserveSig] int GetDefaultAudioEndpoint(int dataFlow, int role, out IMMDevice endpoint);
    }
    [Guid("D666063F-1587-4E43-81F1-B948E807363F"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
    private interface IMMDevice {
        [PreserveSig] int Activate(ref Guid iid, int clsCtx, IntPtr activationParams, [MarshalAs(UnmanagedType.IUnknown)] out object iface);
        [PreserveSig] int OpenPropertyStore(int stgmAccess, out IntPtr properties);
        [PreserveSig] int GetId([MarshalAs(UnmanagedType.LPWStr)] out string id);
        [PreserveSig] int GetState(out int state);
    }
    [Guid("5CDF2C82-841E-4546-9722-0CF74078229A"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
    private interface IAudioEndpointVolume {
        [PreserveSig] int RegisterControlChangeNotify(IntPtr notify);
        [PreserveSig] int UnregisterControlChangeNotify(IntPtr notify);
        [PreserveSig] int GetChannelCount(out int count);
        [PreserveSig] int SetMasterVolumeLevel(float levelDb, ref Guid ctx);
        [PreserveSig] int SetMasterVolumeLevelScalar(float level, ref Guid ctx);
        [PreserveSig] int GetMasterVolumeLevel(out float levelDb);
        [PreserveSig] int GetMasterVolumeLevelScalar(out float level);
        [PreserveSig] int SetChannelVolumeLevel(uint channel, float levelDb, ref Guid ctx);
        [PreserveSig] int SetChannelVolumeLevelScalar(uint channel, float level, ref Guid ctx);
        [PreserveSig] int GetChannelVolumeLevel(uint channel, out float levelDb);
        [PreserveSig] int GetChannelVolumeLevelScalar(uint channel, out float level);
        [PreserveSig] int SetMute([MarshalAs(UnmanagedType.Bool)] bool mute, ref Guid ctx);
        [PreserveSig] int GetMute([MarshalAs(UnmanagedType.Bool)] out bool mute);
    }

    public sealed class AudioReading {
        public bool Present; public int HResult; public string DeviceId; public bool? Muted; public float? VolumeScalar;
    }

    // READ ONLY: the default render endpoint for multimedia (eRender 0, eMultimedia 1). HRESULT 0x80070490 (E_NOTFOUND)
    // means Windows has no output device at all. Measured 2026-10-02 on a dev PC whose sound CARDS read "OK" in
    // Win32_SoundDevice while no output endpoint was active: WMI would have said "present", this says "absent".
    public static AudioReading ReadDefaultOutput() {
        var r = new AudioReading();
        var enumerator = (IMMDeviceEnumerator)(new MMDeviceEnumeratorCom());
        try {
            IMMDevice dev;
            int hr = enumerator.GetDefaultAudioEndpoint(0, 1, out dev);
            r.HResult = hr;
            if (hr != 0 || dev == null) { r.Present = false; return r; }
            r.Present = true;
            try {
                string id; if (dev.GetId(out id) == 0) { r.DeviceId = id; }
                Guid iid = typeof(IAudioEndpointVolume).GUID;
                object o;
                if (dev.Activate(ref iid, 23, IntPtr.Zero, out o) == 0 && o != null) {
                    var vol = (IAudioEndpointVolume)o;
                    bool m; if (vol.GetMute(out m) == 0) { r.Muted = m; }
                    float s; if (vol.GetMasterVolumeLevelScalar(out s) == 0) { r.VolumeScalar = s; }
                    Marshal.ReleaseComObject(o);
                }
            } finally { Marshal.ReleaseComObject(dev); }
            return r;
        } finally { Marshal.ReleaseComObject(enumerator); }
    }
}
"@
        }
        $script:SelfHealNativeState = "ok"
        return $true
    } catch {
        $script:SelfHealNativeState = "failed"
        Write-Log ("[SELFHEAL] native helpers unavailable ({0}); responding and audio read as unknown" -f $_.Exception.Message) "WARN"
        return $false
    }
}

# ---- the process layer: everything that touches a real process goes through these entries (tests swap in a fake) ----
function ConvertTo-SelfHealProcInfo($proc) {
    $start = $null; $cpu = $null; $io = $null; $hwnd = [Int64]0; $sess = $null
    try { $start = $proc.StartTime.ToUniversalTime() } catch {}
    try { $cpu = [double]$proc.TotalProcessorTime.TotalSeconds } catch {}
    try { $hwnd = [Int64]$proc.MainWindowHandle } catch {}
    try { $sess = [int]$proc.SessionId } catch {}
    try {
        if (Initialize-SelfHealNative) {
            $c = New-Object ABGSelfHealNative+IO_COUNTERS
            if ([ABGSelfHealNative]::GetProcessIoCounters($proc.Handle, [ref]$c)) { $io = [double]$c.ReadTransferCount }
        }
    } catch {}
    return [pscustomobject]@{
        Id = [int]$proc.Id; Name = [string]$proc.ProcessName; SessionId = $sess; StartTimeUtc = $start
        MainWindowHandle = $hwnd; CpuSeconds = $cpu; IoReadBytes = $io
    }
}

function New-SelfHealProcessLayer {
    # -SessionOfProcessId exists for the real-process test only: it proves the session is READ from a process, not
    # assumed (on a dev PC the agent's own session is 1, so a hardcoded 1 would pass). The agent never passes it.
    param([int]$SessionOfProcessId = 0)
    if ($SessionOfProcessId -le 0) { $SessionOfProcessId = $PID }
    $own = $null
    try { $own = [int](Get-Process -Id $SessionOfProcessId).SessionId } catch {}
    return @{
        OwnSessionId = $own
        List = {
            param([string]$name)
            foreach ($p in @(Get-Process -Name $name -ErrorAction SilentlyContinue)) {
                if ($p.ProcessName -ieq $name) { ConvertTo-SelfHealProcInfo $p }
            }
        }
        GetById = {
            param([int]$procId)
            $p = $null
            try { $p = Get-Process -Id $procId -ErrorAction Stop } catch { return $null }
            ConvertTo-SelfHealProcInfo $p
        }
        Stop = {
            param([int]$procId)
            Stop-Process -Id $procId -Force -ErrorAction Stop
        }
        Start = {
            param([string]$path, [string]$argLine)
            if ([string]::IsNullOrWhiteSpace($argLine)) { Start-Process -FilePath $path | Out-Null }
            else { Start-Process -FilePath $path -ArgumentList $argLine | Out-Null }
        }
        ScreenCount = {
            # The agent loads WinForms at script level for display routing; load it here too rather than rely on that.
            try { Add-Type -AssemblyName System.Windows.Forms -ErrorAction Stop } catch {}
            [int]@([System.Windows.Forms.Screen]::AllScreens).Count
        }
        Audio = {
            if (-not (Initialize-SelfHealNative)) { return $null }
            $a = [ABGSelfHealNative]::ReadDefaultOutput()
            [pscustomobject]@{ Present = [bool]$a.Present; HResult = [int]$a.HResult; DeviceId = $a.DeviceId; Muted = $a.Muted; VolumeScalar = $a.VolumeScalar }
        }
    }
}

# ---- detectors: THE PLUG-IN POINT. Each answers Responding = $true, $false, or $null (cannot tell). ----
# hungAppWindow     user32 IsHungAppWindow on the main window: the "Not Responding" signal Windows itself uses to
#                   ghost a window (no message pumped for about 5 seconds). Non-blocking. The default.
# processResponding .NET Process.Responding (SendMessageTimeout, blocks up to 5 seconds on a hung window).
# Adding one after the bench: add an entry here and set selfHeal.watchdog.detector to its name.
$script:SelfHealDetectors = @{
    hungAppWindow = {
        param($procInfo, $layer)
        $h = [Int64]$procInfo.MainWindowHandle
        if ($h -eq 0) { return @{ Responding = $null; Detail = "no_main_window" } }
        if (-not (Initialize-SelfHealNative)) { return @{ Responding = $null; Detail = "native_unavailable" } }
        $hw = [IntPtr]$h
        if (-not [ABGSelfHealNative]::IsWindow($hw)) { return @{ Responding = $null; Detail = "window_gone" } }
        $hung = [bool][ABGSelfHealNative]::IsHungAppWindow($hw)
        return @{ Responding = (-not $hung); Detail = $(if ($hung) { "hung_app_window" } else { "window_ok" }) }
    }
    processResponding = {
        param($procInfo, $layer)
        try {
            $p = Get-Process -Id ([int]$procInfo.Id) -ErrorAction Stop
            $p.Refresh()
            if ($p.MainWindowHandle -eq [IntPtr]::Zero) { return @{ Responding = $null; Detail = "no_main_window" } }
            return @{ Responding = [bool]$p.Responding; Detail = "process_responding" }
        } catch { return @{ Responding = $null; Detail = "probe_failed" } }
    }
}

function Get-SelfHealReading($procInfo, $layer, [string]$detectorName) {
    $det = $null
    if ($script:SelfHealDetectors.ContainsKey($detectorName)) { $det = $script:SelfHealDetectors[$detectorName] }
    if ($null -eq $det) { return @{ Responding = $null; Detail = "unknown_detector" } }
    try {
        $r = & $det $procInfo $layer
        $resp = Get-PropValue $r "Responding" $null
        if ($null -ne $resp -and -not ($resp -is [bool])) { $resp = $null }
        return @{ Responding = $resp; Detail = [string](Get-PropValue $r "Detail" "") }
    } catch { return @{ Responding = $null; Detail = "detector_threw" } }
}

# ---- pure decisions (no I/O): what one reading of one process instance means ----
function Get-SelfHealInstanceVerdict {
    # Verdicts: grace | ok | unknown | unresponsive | loading | frozen.
    # FROZEN needs, outside the launch grace, an unbroken run of "not responding" readings no further apart than
    # MaxSampleGapSeconds, and EITHER no sign of work (CPU and disk reads both quiet) for UnresponsiveSeconds, OR
    # LoadingMaxSeconds of not responding whatever the work signs say. A loading game is busy, so it gets the long
    # bound; a deadlocked one is quiet, so it gets the short one. A $null reading ("cannot tell") breaks the run.
    param(
        $PriorState,
        [Parameter(Mandatory=$true)]$Sample,
        [Parameter(Mandatory=$true)][DateTime]$Now,
        [Parameter(Mandatory=$true)]$Settings
    )
    $st = @{ LastAt = $null; LastCpu = $null; LastIo = $null; UnrespSince = $null; QuietSince = $null }
    if ($null -ne $PriorState) { foreach ($k in @($PriorState.Keys)) { $st[$k] = $PriorState[$k] } }

    $prevAt = $st.LastAt; $prevCpu = $st.LastCpu; $prevIo = $st.LastIo
    $st.LastAt = $Now; $st.LastCpu = $Sample.CpuSeconds; $st.LastIo = $Sample.IoReadBytes

    $start = $Sample.StartTimeUtc
    if ($null -eq $start) { $st.UnrespSince = $null; $st.QuietSince = $null; return @{ Verdict = "unknown"; State = $st } }
    if (($Now - $start).TotalSeconds -lt $Settings.LaunchGraceSeconds) {
        $st.UnrespSince = $null; $st.QuietSince = $null
        return @{ Verdict = "grace"; State = $st }
    }
    if ($null -eq $Sample.Responding) { $st.UnrespSince = $null; $st.QuietSince = $null; return @{ Verdict = "unknown"; State = $st } }
    if ($Sample.Responding -eq $true) { $st.UnrespSince = $null; $st.QuietSince = $null; return @{ Verdict = "ok"; State = $st } }

    # Not responding. A long gap since the last reading means we were not watching: start the run again.
    $gapOk = ($null -ne $prevAt) -and (($Now - $prevAt).TotalSeconds -le $Settings.MaxSampleGapSeconds)
    if (-not $gapOk -or $null -eq $st.UnrespSince) {
        $st.UnrespSince = $Now
        $st.QuietSince = $null
        return @{ Verdict = "unresponsive"; State = $st }
    }

    # Work signs over the interval since the last reading. A counter we cannot read counts as BUSY, so an unreadable
    # counter can only make the watchdog slower (LoadingMaxSeconds), never quicker.
    $elapsed = [Math]::Max(0.001, ($Now - $prevAt).TotalSeconds)
    $cpuBusy = $true
    if ($null -ne $Sample.CpuSeconds -and $null -ne $prevCpu) { $cpuBusy = (([double]$Sample.CpuSeconds - [double]$prevCpu) / $elapsed) -ge $Settings.CpuBusyFraction }
    $ioBusy = $true
    if ($null -ne $Sample.IoReadBytes -and $null -ne $prevIo) { $ioBusy = (([double]$Sample.IoReadBytes - [double]$prevIo) -ge $Settings.IoBusyBytes) }
    $busy = $cpuBusy -or $ioBusy

    if ($busy) { $st.QuietSince = $null }
    elseif ($null -eq $st.QuietSince) { $st.QuietSince = $Now }

    $unrespFor = ($Now - $st.UnrespSince).TotalSeconds
    $quietFor = $(if ($null -ne $st.QuietSince) { ($Now - $st.QuietSince).TotalSeconds } else { 0 })
    if ($unrespFor -ge $Settings.LoadingMaxSeconds) { return @{ Verdict = "frozen"; State = $st } }
    if ($null -ne $st.QuietSince -and $unrespFor -ge $Settings.UnresponsiveSeconds -and $quietFor -ge $Settings.UnresponsiveSeconds) {
        return @{ Verdict = "frozen"; State = $st }
    }
    return @{ Verdict = $(if ($busy) { "loading" } else { "unresponsive" }); State = $st }
}

function Get-SelfHealRestartAllowed {
    # Pure. At most MaxRestarts restarts in any rolling WindowMinutes, counting every ATTEMPT (a failed close counts).
    param([DateTime[]]$History, [Parameter(Mandatory=$true)][DateTime]$Now, [int]$MaxRestarts, [int]$WindowMinutes)
    $cut = $Now.AddMinutes(-$WindowMinutes)
    $inWindow = @(@($History) | Where-Object { $null -ne $_ -and $_ -gt $cut } | Sort-Object)
    $allowed = ($inWindow.Count -lt $MaxRestarts)
    $next = $null
    if (-not $allowed -and $MaxRestarts -ge 1 -and $inWindow.Count -ge $MaxRestarts) { $next = $inWindow[$inWindow.Count - $MaxRestarts].AddMinutes($WindowMinutes) }
    return @{ Allowed = $allowed; CountInWindow = $inWindow.Count; NextAllowedUtc = $next }
}

function Test-SelfHealNameAllowed([string]$name, $targets) {
    if ([string]::IsNullOrWhiteSpace($name)) { return $false }
    foreach ($d in $SelfHealDenyNames) { if ($name -ieq $d) { return $false } }
    foreach ($t in @($targets)) { if ($null -ne $t -and $name -ieq [string]$t.Name) { return $true } }
    return $false
}

function Invoke-SelfHealRestart {
    # Closes ONE process, by Id, only after re-reading it and finding the SAME process (name, start time, session)
    # that was judged frozen. Never by name. Never this agent. Never another session's copy.
    param([Parameter(Mandatory=$true)]$Layer, [Parameter(Mandatory=$true)]$ProcInfo, $Targets)
    if ($null -eq $ProcInfo.StartTimeUtc) { return @{ Stopped = $false; Reason = "no_start_time" } }
    if ([int]$ProcInfo.Id -eq $PID) { return @{ Stopped = $false; Reason = "self" } }
    if (-not (Test-SelfHealNameAllowed ([string]$ProcInfo.Name) $Targets)) { return @{ Stopped = $false; Reason = "not_a_target" } }
    if ($null -eq $Layer.OwnSessionId -or $ProcInfo.SessionId -ne $Layer.OwnSessionId) { return @{ Stopped = $false; Reason = "other_session" } }
    $fresh = $null
    try { $fresh = & $Layer.GetById ([int]$ProcInfo.Id) } catch {}
    if ($null -eq $fresh) { return @{ Stopped = $false; Reason = "gone" } }
    if ([string]$fresh.Name -ine [string]$ProcInfo.Name) { return @{ Stopped = $false; Reason = "pid_reused" } }
    if ($null -eq $fresh.StartTimeUtc -or $fresh.StartTimeUtc -ne $ProcInfo.StartTimeUtc) { return @{ Stopped = $false; Reason = "pid_reused" } }
    if ($fresh.SessionId -ne $Layer.OwnSessionId) { return @{ Stopped = $false; Reason = "other_session" } }
    try {
        & $Layer.Stop ([int]$ProcInfo.Id)
        return @{ Stopped = $true; Reason = "stopped" }
    } catch {
        return @{ Stopped = $false; Reason = ("stop_failed: " + $_.Exception.Message) }
    }
}

# ---- rows into the existing diagnostic pipe ----
function New-SelfHealDiagRow {
    param(
        [Parameter(Mandatory=$true)][string]$CheckId,
        [Parameter(Mandatory=$true)][int]$Category,
        [Parameter(Mandatory=$true)][int]$Severity,
        [Parameter(Mandatory=$true)][int]$Status,
        $MetricValue,
        $Metric,
        [string]$Details,
        [Parameter(Mandatory=$true)][string]$RunId,
        [Parameter(Mandatory=$true)][DateTime]$AtUtc
    )
    $metricJson = $null
    if ($null -ne $Metric) {
        $metricJson = ($Metric | ConvertTo-Json -Depth 6 -Compress)
        if ($metricJson.Length -gt 4000) { $metricJson = ($metricJson.Substring(0, 3980) + "...[truncated]") }
    }
    if ($null -ne $Details -and $Details.Length -gt 2000) { $Details = $Details.Substring(0, 1985) + "...[truncated]" }
    if ($RunId.Length -gt 100) { $RunId = $RunId.Substring(0, 100) }
    $label = Get-BayLabel
    $row = [ordered]@{
        build_diagnosticlogid = ([guid]::NewGuid().ToString("D"))
        build_diagnosticname  = ("{0} | {1}" -f $label, $CheckId)
        build_checkcategory   = $Category
        build_severity        = $Severity
        statuscode            = $Status
        build_details         = $Details
        build_diagnosticrunid = $RunId
        build_timestamp       = (Format-SelfHealUtc $AtUtc)
        "build_Bay@odata.bind" = ("/{0}({1})" -f $BayEntitySet, ($BayId.ToString().Trim("{}")))
    }
    if ($null -ne $MetricValue) { $row["build_metricvalue"] = [double]$MetricValue }
    if ($null -ne $metricJson) { $row["build_metricjson"] = $metricJson }
    return $row
}

function Read-SelfHealOutbox {
    if (-not (Test-Path -LiteralPath $SelfHealOutboxPath)) { return @() }
    try {
        $o = Get-Content -LiteralPath $SelfHealOutboxPath -Raw -ErrorAction Stop | ConvertFrom-Json
        return @(@($o) | Where-Object { $null -ne $_ })
    } catch {
        Write-Log ("[SELFHEAL] outbox unreadable ({0}); starting a new one" -f $_.Exception.Message) "WARN"
        return @()
    }
}

function Save-SelfHealOutbox {
    try { Write-TextAtomic -path $SelfHealOutboxPath -text (ConvertTo-Json -InputObject @($script:SelfHealOutbox) -Depth 8) }
    catch { Write-Log ("[SELFHEAL] could not save the outbox: {0}" -f $_.Exception.Message) "WARN" }
}

function Add-SelfHealOutbox($row) {
    $script:SelfHealOutbox = @($script:SelfHealOutbox) + @([pscustomobject]@{ row = $row; queuedUtc = $row.build_timestamp; attempts = 0 })
    if ($script:SelfHealOutbox.Count -gt $SelfHealOutboxMax) {
        $drop = $script:SelfHealOutbox.Count - $SelfHealOutboxMax
        $script:SelfHealOutbox = @($script:SelfHealOutbox | Select-Object -Skip $drop)
        Write-Log ("[SELFHEAL] outbox full: dropped the {0} oldest unsent report(s)" -f $drop) "WARN"
    }
    Save-SelfHealOutbox
    Write-Log ("[SELFHEAL] queued {0} severity={1} status={2}" -f $row.build_diagnosticname, $row.build_severity, $row.statuscode) "INFO"
}

function Invoke-SelfHealDvPost {
    param([Parameter(Mandatory=$true)][string]$token, [Parameter(Mandatory=$true)][string]$entitySet, [Parameter(Mandatory=$true)]$bodyObj)
    $uri = "$OrgUrl/api/data/v9.2/$entitySet"
    $json = ($bodyObj | ConvertTo-Json -Depth 8 -Compress)
    try {
        Invoke-RestMethod -Method Post -Uri $uri -Headers (New-DvHeaders $token) -ContentType "application/json; charset=utf-8" `
            -Body ([Text.Encoding]::UTF8.GetBytes($json)) -ErrorAction Stop | Out-Null
        return @{ Ok = $true; Duplicate = $false; Status = 204; Detail = $null }
    } catch {
        $postErr = $_
        $ex = $postErr.Exception
        $status = $null
        try { $status = [int]$ex.Response.StatusCode } catch {}
        # Windows PowerShell's Invoke-RestMethod has already READ the error body into ErrorDetails by the time it
        # throws, so the response stream is empty. MEASURED in BayAgent.SelfHeal.Tests.ps1 W7: reading only the
        # stream lost Dataverse's error code, and a duplicate-key answer was retried forever.
        $body = $null
        try { if ($postErr.ErrorDetails -and $postErr.ErrorDetails.Message) { $body = [string]$postErr.ErrorDetails.Message } } catch {}
        if ([string]::IsNullOrEmpty($body)) { $body = Read-WebExceptionBody -WebException $ex }
        if ($null -eq $body) { $body = "" }
        # Each row carries its own build_diagnosticlogid, so a retry of a POST that landed (response lost) is refused
        # as a duplicate key instead of writing the event twice. UNVERIFIED wire shape (no Dev write was allowed for
        # this build): DuplicateRecord is 0x80040237 in the error body.
        $dup = ($body -match '0x80040237') -or (($status -eq 412) -and ($body -match 'already exists'))
        $detail = $ex.Message
        if ($body.Length -gt 0) { $detail = $detail + " :: " + $body.Substring(0, [Math]::Min(300, $body.Length)) }
        return @{ Ok = $false; Duplicate = $dup; Status = $status; Detail = $detail }
    }
}

function Send-SelfHealOutboxIfDue {
    param([Parameter(Mandatory=$true)][string]$token, [Parameter(Mandatory=$true)][DateTime]$Now, [int]$MaxPerPass = 10)
    if ($null -eq $script:SelfHealSettings -or -not $script:SelfHealSettings.Enabled) { return }
    if (@($script:SelfHealOutbox).Count -eq 0) { return }
    if ($null -ne $script:SelfHealNextSendUtc -and $Now -lt $script:SelfHealNextSendUtc) { return }

    $sent = 0
    $remaining = @()
    $failed = $false
    foreach ($item in @($script:SelfHealOutbox)) {
        if ($failed -or $sent -ge $MaxPerPass) { $remaining += $item; continue }
        $r = Invoke-SelfHealDvPost -token $token -entitySet $SelfHealDiagEntitySet -bodyObj $item.row
        if ($r.Ok -or $r.Duplicate) {
            $sent++
            if ($r.Duplicate) { Write-Log ("[SELFHEAL] {0} was already delivered (duplicate key); dropped from the outbox" -f $item.row.build_diagnosticlogid) "INFO" }
            continue
        }
        $item.attempts = [int]$item.attempts + 1
        $remaining += $item
        $failed = $true
        Write-Log ("[SELFHEAL] report not delivered (status={0}); will retry: {1}" -f $r.Status, $r.Detail) "WARN"
    }
    $script:SelfHealOutbox = @($remaining)
    Save-SelfHealOutbox
    if ($failed) {
        $script:SelfHealSendBackoffSeconds = [Math]::Min(900, [Math]::Max(60, 2 * [int]$script:SelfHealSendBackoffSeconds))
        $script:SelfHealNextSendUtc = $Now.AddSeconds($script:SelfHealSendBackoffSeconds)
    } else {
        $script:SelfHealSendBackoffSeconds = 30
        $script:SelfHealNextSendUtc = $null
    }
    if ($sent -gt 0) { Write-Log ("[SELFHEAL] delivered {0} report(s); {1} waiting" -f $sent, @($script:SelfHealOutbox).Count) "INFO" }
}

# ---- persisted watchdog state: the restart count must survive an agent restart ----
function ConvertFrom-SelfHealStateText {
    # STRICT. The count file is valid only as an OBJECT whose restartHistoryUtc is an ARRAY of entries that are all
    # UTC timestamps in the form this agent writes. Anything else is UNREADABLE, never "zero restarts": a 0-byte, NUL,
    # whitespace or BOM-only file (power loss), null, {}, [], a missing, null or non-array key, and any entry that is
    # not such a timestamp. Measured by the verifier (2026-10-02): every one of those used to read as a zero count, and
    # a bay restarted 4 times in 13 minutes across an agent restart.
    param([string]$Text)
    $fail = @{ Ok = $false; Dates = @(); Reason = "" }
    if ([string]::IsNullOrWhiteSpace($Text)) { $fail.Reason = "empty"; return $fail }
    if ($Text.IndexOf([char]0) -ge 0) { $fail.Reason = "NUL bytes"; return $fail }
    $o = $null
    try { $o = ConvertFrom-Json -InputObject $Text -ErrorAction Stop } catch { $fail.Reason = "not JSON"; return $fail }
    if ($null -eq $o -or -not ($o -is [System.Management.Automation.PSCustomObject])) { $fail.Reason = "not an object"; return $fail }
    # Read the property directly: Get-PropValue would unroll a one-element array into a scalar.
    $prop = @($o.PSObject.Properties | Where-Object { $_.Name -ceq "restartHistoryUtc" })
    if ($prop.Count -ne 1) { $fail.Reason = "no restartHistoryUtc"; return $fail }
    $arr = $prop[0].Value
    if ($null -eq $arr -or -not ($arr -is [System.Array])) { $fail.Reason = "restartHistoryUtc is not an array"; return $fail }
    $dates = @()
    foreach ($e in $arr) {
        $d = $null
        if ($e -is [DateTime]) { $d = $e.ToUniversalTime() }
        elseif ($e -is [string]) {
            $parsed = [DateTime]::MinValue
            $formats = [string[]]@("yyyy-MM-ddTHH:mm:ss.fffffffZ", "yyyy-MM-ddTHH:mm:ssZ")
            if ([DateTime]::TryParseExact($e, $formats, [Globalization.CultureInfo]::InvariantCulture,
                    ([Globalization.DateTimeStyles]::AdjustToUniversal -bor [Globalization.DateTimeStyles]::AssumeUniversal), [ref]$parsed)) { $d = $parsed }
        }
        if ($null -eq $d) { $fail.Reason = "an entry is not a timestamp"; return $fail }
        $dates += $d
    }
    return @{ Ok = $true; Dates = $dates; Reason = "" }
}

function Read-SelfHealState {
    param([Parameter(Mandatory=$true)][DateTime]$Now, [int]$MaxRestarts)
    $hist = @()
    if (Test-Path -LiteralPath $SelfHealStatePath) {
        $parsed = @{ Ok = $false; Dates = @(); Reason = "unreadable" }
        try { $parsed = ConvertFrom-SelfHealStateText -Text ([IO.File]::ReadAllText($SelfHealStatePath)) }
        catch { $parsed = @{ Ok = $false; Dates = @(); Reason = $_.Exception.Message } }
        if ($parsed.Ok) {
            foreach ($d in @($parsed.Dates)) { if ($d -gt $Now.AddDays(-1)) { $hist += $d } }
        } else {
            # An unreadable count is not a zero count: assume the limit is used up for one window.
            Write-Log ("[SELFHEAL] watchdog state unreadable ({0}); restarts are held for one window" -f $parsed.Reason) "WARN"
            $hist = @(); for ($i = 0; $i -lt [Math]::Max(1, $MaxRestarts); $i++) { $hist += $Now }
        }
    }
    return ,([DateTime[]]$hist)
}

function Save-SelfHealState {
    # Returns $true only when the file on disk reads back, through the same strict reader, holding every attempt in
    # memory. The caller never closes a program on $false: an attempt that is not durable could be repeated after an
    # agent restart. Full tick precision, so a slot never frees early after a restart (verifier R5).
    $hist = @(@($script:SelfHealRuntime.History))
    $o = [ordered]@{ restartHistoryUtc = @($hist | ForEach-Object { ([DateTime]$_).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffffffZ", [Globalization.CultureInfo]::InvariantCulture) }) }
    try {
        Write-TextAtomic -path $SelfHealStatePath -text (ConvertTo-Json -InputObject $o -Depth 4)
        $back = ConvertFrom-SelfHealStateText -Text ([IO.File]::ReadAllText($SelfHealStatePath))
        if (-not $back.Ok -or @($back.Dates).Count -ne $hist.Count) {
            Write-Log ("[SELFHEAL] the restart count did not read back ({0})" -f $(if ($back.Ok) { "count differs" } else { $back.Reason })) "ERROR"
            return $false
        }
        return $true
    } catch {
        Write-Log ("[SELFHEAL] could not save the restart count: {0}" -f $_.Exception.Message) "ERROR"
        return $false
    }
}

function Initialize-SelfHeal {
    param([Parameter(Mandatory=$true)][string]$ConfigPath, [Parameter(Mandatory=$true)][DateTime]$Now, $Layer = $null)
    $script:SelfHealSettings = Read-SelfHealSettings -Path $ConfigPath
    $script:SelfHealRuntime = @{
        Instances = @{}; Episodes = @{}; History = [DateTime[]]@()
        NextWatchUtc = [DateTime]::MinValue; NextHealthSampleUtc = [DateTime]::MinValue
        NextHealthDueUtc = [DateTime]::MinValue; LastHealthSentUtc = $null; LastHealthSignature = $null
        SuppressLogged = $false
    }
    $script:SelfHealOutbox = @()
    $script:SelfHealNextSendUtc = $null
    $script:SelfHealSendBackoffSeconds = 30
    foreach ($e in @($script:SelfHealSettings.Errors)) { Write-Log "[SELFHEAL] config: $e" "WARN" }
    if (-not $script:SelfHealSettings.Enabled) {
        Write-Log "[SELFHEAL] off (selfHeal.enabled is not true in agent-config.json)" "DEBUG"
        return
    }
    $script:SelfHealLayer = $(if ($null -ne $Layer) { $Layer } else { New-SelfHealProcessLayer })
    $script:SelfHealRuntime.History = Read-SelfHealState -Now $Now -MaxRestarts $script:SelfHealSettings.MaxRestarts
    $script:SelfHealOutbox = @(Read-SelfHealOutbox)
    Write-Log ("[SELFHEAL] on: watchdog={0} health={1} detector={2} targets={3} unresponsive={4}s grace={5}s loadingMax={6}s limit={7}/{8}min" -f `
        $script:SelfHealSettings.WatchdogEnabled, $script:SelfHealSettings.HealthEnabled, $script:SelfHealSettings.Detector,
        ((@($script:SelfHealSettings.Targets) | ForEach-Object { "$($_.Name)($($_.Relaunch))" }) -join ","),
        $script:SelfHealSettings.UnresponsiveSeconds, $script:SelfHealSettings.LaunchGraceSeconds, $script:SelfHealSettings.LoadingMaxSeconds,
        $script:SelfHealSettings.MaxRestarts, $script:SelfHealSettings.WindowMinutes) "INFO"
    if ($script:SelfHealSettings.WatchdogEnabled -and -not $script:SelfHealDetectors.ContainsKey($script:SelfHealSettings.Detector)) {
        Write-Log ("[SELFHEAL] detector '{0}' is not known; every reading is 'cannot tell', so nothing is ever restarted" -f $script:SelfHealSettings.Detector) "ERROR"
    }
}

function Get-SelfHealRestartsBlockedReason {
    # Platform-side inputs may only HOLD a restart. Maintenance/Offline (a technician may be at the bay) and the
    # emergency-stop latch hold; nothing here can start one.
    if ($Global:EmergencyStopEngaged) { return "emergency_stop" }
    try {
        $effNow = $(if ($Global:EffectiveConfig) { $Global:EffectiveConfig } else { @{} })
        $op = Get-AgentOperationalState -eff $effNow
        if ($op.Blocked) { return ("bay_" + $op.ModeLabel.ToLowerInvariant()) }
    } catch {}
    return $null
}

function New-SelfHealEpisodeRow {
    param([string]$Kind, $Episode, [DateTime]$Now, [string]$Reason = "")
    $s = $script:SelfHealSettings
    $frozenFor = [int][Math]::Round(($Now - $Episode.FrozenSinceUtc).TotalSeconds)
    $metric = [ordered]@{
        event = $Kind; episodeId = $Episode.Id; target = $Episode.Target
        frozenSinceUtc = (Format-SelfHealUtc $Episode.FrozenSinceUtc); atUtc = (Format-SelfHealUtc $Now)
        restarts = $Episode.Restarts; detector = $s.Detector
    }
    switch ($Kind) {
        "restarting" {
            $metric["restartNumber"] = $Episode.Restarts
            $metric["unresponsiveSeconds"] = $frozenFor
            return New-SelfHealDiagRow -CheckId $SelfHealCheckRestarting -Category $SelfHealCatSoftware -Severity $SelfHealSevInfo `
                -Status $SelfHealStatusFailed -MetricValue $Episode.Restarts -Metric $metric -RunId $Episode.Id -AtUtc $Now `
                -Details ("The golf software ({0}) stopped responding for {1} seconds. The bay closed it so it restarts by itself (restart {2})." -f $Episode.Target, $frozenFor, $Episode.Restarts)
        }
        "recovered" {
            # Lost minutes: from the first unresponsive reading to the first healthy one. Recorded, not acted on: the
            # club decides any make-good by hand (A0.327(4)).
            $faultMinutes = [int][Math]::Ceiling([Math]::Max(0, $frozenFor) / 60.0)
            $metric["recoveredAtUtc"] = (Format-SelfHealUtc $Now)
            $metric["faultSeconds"] = $frozenFor
            $metric["faultMinutes"] = $faultMinutes
            return New-SelfHealDiagRow -CheckId $SelfHealCheckRecovered -Category $SelfHealCatSoftware -Severity $SelfHealSevInfo `
                -Status $SelfHealStatusPassed -MetricValue $faultMinutes -Metric $metric -RunId $Episode.Id -AtUtc $Now `
                -Details ("The golf software ({0}) is responding again after {1} seconds ({2} minutes lost, {3} automatic restarts)." -f $Episode.Target, $frozenFor, $faultMinutes, $Episode.Restarts)
        }
        default {
            $metric["reason"] = $Reason
            $metric["faultSecondsSoFar"] = $frozenFor
            return New-SelfHealDiagRow -CheckId $SelfHealCheckFrozen -Category $SelfHealCatSoftware -Severity $s.GiveUpSeverity `
                -Status $SelfHealStatusFailed -MetricValue $Episode.Restarts -Metric $metric -RunId $Episode.Id -AtUtc $Now `
                -Details ("The golf software ({0}) is still not responding after {1} automatic restarts; the bay has stopped trying ({2})." -f $Episode.Target, $Episode.Restarts, $Reason)
        }
    }
}

function Invoke-SelfHealWatchdogTick {
    param([Parameter(Mandatory=$true)][DateTime]$Now)
    $s = $script:SelfHealSettings
    $rt = $script:SelfHealRuntime
    if (-not $s.WatchdogEnabled) { return }
    if ($Now -lt $rt.NextWatchUtc) { return }
    $rt.NextWatchUtc = $Now.AddSeconds($s.SampleSeconds)
    $layer = $script:SelfHealLayer

    $seenKeys = @{}
    foreach ($target in @($s.Targets)) {
        $instances = @()
        foreach ($pi in @(& $layer.List $target.Name)) {
            if ($null -eq $pi) { continue }
            if ([string]$pi.Name -ine $target.Name) { continue }
            if ([int]$pi.Id -eq $PID) { continue }
            if ($null -eq $layer.OwnSessionId -or $pi.SessionId -ne $layer.OwnSessionId) { continue }
            $instances += $pi
        }

        $judged = @()
        foreach ($pi in $instances) {
            $key = "{0}|{1}" -f $pi.Id, $(if ($null -ne $pi.StartTimeUtc) { $pi.StartTimeUtc.Ticks } else { "nostart" })
            $seenKeys[$key] = $true
            $reading = Get-SelfHealReading $pi $layer $s.Detector
            $sample = @{ Responding = $reading.Responding; CpuSeconds = $pi.CpuSeconds; IoReadBytes = $pi.IoReadBytes; StartTimeUtc = $pi.StartTimeUtc }
            $prior = $null
            if ($rt.Instances.ContainsKey($key)) { $prior = $rt.Instances[$key] }
            $v = Get-SelfHealInstanceVerdict -PriorState $prior -Sample $sample -Now $Now -Settings $s
            $rt.Instances[$key] = $v.State
            $judged += [pscustomobject]@{ Proc = $pi; Verdict = $v.Verdict; Responding = $reading.Responding; Detail = $reading.Detail; UnrespSince = $v.State.UnrespSince }
            if ($v.Verdict -in @("unresponsive", "loading", "frozen")) {
                Write-Log ("[SELFHEAL] {0} pid={1} {2} ({3})" -f $target.Name, $pi.Id, $v.Verdict, $reading.Detail) "DEBUG"
            }
        }

        $ep = $null
        if ($rt.Episodes.ContainsKey($target.Name)) { $ep = $rt.Episodes[$target.Name] }
        $frozen = @($judged | Where-Object { $_.Verdict -eq "frozen" } | Sort-Object { $_.UnrespSince })

        if ($frozen.Count -gt 0) {
            if ($null -eq $ep) {
                $ep = @{ Id = ([guid]::NewGuid().ToString("D")); Target = $target.Name; FrozenSinceUtc = $frozen[0].UnrespSince
                         Restarts = 0; RestartedAtUtc = $null; DetectedAtUtc = $Now; GaveUp = $false; RelaunchDueUtc = $null }
                $rt.Episodes[$target.Name] = $ep
                Write-Log ("[SELFHEAL] {0} pid={1} FROZEN: not responding since {2} ({3})" -f $target.Name, $frozen[0].Proc.Id, (Format-SelfHealUtc $ep.FrozenSinceUtc), $frozen[0].Detail) "WARN"
            }
            $blocked = Get-SelfHealRestartsBlockedReason
            if ($null -ne $blocked) {
                if (-not $rt.SuppressLogged) { Write-Log "[SELFHEAL] restart held: $blocked" "WARN"; $rt.SuppressLogged = $true }
                continue
            }
            $rt.SuppressLogged = $false
            $gate = Get-SelfHealRestartAllowed -History $rt.History -Now $Now -MaxRestarts $s.MaxRestarts -WindowMinutes $s.WindowMinutes
            if (-not $gate.Allowed) {
                if (-not $ep.GaveUp) {
                    $ep.GaveUp = $true
                    Write-Log ("[SELFHEAL] {0} still frozen; restart limit reached ({1} in {2} min); next allowed {3}" -f $target.Name, $gate.CountInWindow, $s.WindowMinutes, (Format-SelfHealUtc $gate.NextAllowedUtc)) "WARN"
                    Add-SelfHealOutbox (New-SelfHealEpisodeRow -Kind "frozen" -Episode $ep -Now $Now -Reason "rate_limit")
                }
                continue
            }
            # One restart per tick: the oldest frozen instance.
            $victim = $frozen[0].Proc
            # The attempt is counted in memory first (so a save that keeps failing still uses up the limit) and must be
            # DURABLE before anything is closed; otherwise an agent restart could forget it and close again.
            $rt.History = [DateTime[]](@($rt.History) + @($Now))
            if (-not (Save-SelfHealState)) {
                Write-Log ("[SELFHEAL] {0} pid={1} NOT closed: the restart count could not be saved" -f $target.Name, $victim.Id) "ERROR"
                if (-not $ep.GaveUp) {
                    $ep.GaveUp = $true
                    Add-SelfHealOutbox (New-SelfHealEpisodeRow -Kind "frozen" -Episode $ep -Now $Now -Reason "count_not_saved")
                }
                continue
            }
            $res = Invoke-SelfHealRestart -Layer $layer -ProcInfo $victim -Targets $s.Targets
            if ($res.Stopped) {
                $ep.Restarts = [int]$ep.Restarts + 1
                $ep.RestartedAtUtc = $Now
                $ep.GaveUp = $false
                if ($target.Relaunch -eq "agent") { $ep.RelaunchDueUtc = $Now.AddSeconds($s.RelaunchWaitSeconds) }
                foreach ($k in @($rt.Instances.Keys)) { if ($k.StartsWith("$($victim.Id)|")) { $rt.Instances.Remove($k) } }
                Write-Log ("[SELFHEAL] {0} pid={1} closed to restart it (restart {2} of this episode)" -f $target.Name, $victim.Id, $ep.Restarts) "WARN"
                Add-SelfHealOutbox (New-SelfHealEpisodeRow -Kind "restarting" -Episode $ep -Now $Now)
            } else {
                Write-Log ("[SELFHEAL] {0} pid={1} NOT closed: {2}" -f $target.Name, $victim.Id, $res.Reason) "ERROR"
                if (-not $ep.GaveUp) {
                    $ep.GaveUp = $true
                    Add-SelfHealOutbox (New-SelfHealEpisodeRow -Kind "frozen" -Episode $ep -Now $Now -Reason ("restart_failed: " + $res.Reason))
                }
            }
            continue
        }

        if ($null -eq $ep) { continue }

        # An episode is open and nothing is frozen right now. Agent relaunch first, if this target asks for it.
        if ($target.Relaunch -eq "agent" -and $null -ne $ep.RelaunchDueUtc -and $Now -ge $ep.RelaunchDueUtc) {
            $ep.RelaunchDueUtc = $null
            if ($instances.Count -eq 0) {
                try { & $layer.Start $target.Path $target.ArgLine; Write-Log ("[SELFHEAL] {0} started again by the agent" -f $target.Name) "INFO" }
                catch { Write-Log ("[SELFHEAL] {0} could not be started again: {1}" -f $target.Name, $_.Exception.Message) "ERROR" }
            }
        }

        # Recovered: for a program the shell or agent reopens, a copy is back and responding with none still stuck; for
        # relaunch "none", the frozen copy is gone and nothing left is stuck.
        $stuck = @($judged | Where-Object { $_.Verdict -in @("unresponsive", "loading", "frozen") }).Count
        $healthy = @($judged | Where-Object { $_.Responding -eq $true -and $_.Verdict -in @("ok", "grace") }).Count
        $recovered = $false
        if ($target.Relaunch -eq "none") { $recovered = ($stuck -eq 0 -and ($instances.Count -eq 0 -or $healthy -gt 0)) }
        else { $recovered = ($stuck -eq 0 -and $healthy -gt 0) }

        if ($recovered) {
            Write-Log ("[SELFHEAL] {0} recovered after {1}s ({2} restarts)" -f $target.Name, [int]($Now - $ep.FrozenSinceUtc).TotalSeconds, $ep.Restarts) "INFO"
            Add-SelfHealOutbox (New-SelfHealEpisodeRow -Kind "recovered" -Episode $ep -Now $Now)
            $rt.Episodes.Remove($target.Name)
            continue
        }

        $waitFrom = $(if ($null -ne $ep.RestartedAtUtc) { $ep.RestartedAtUtc } else { $ep.DetectedAtUtc })
        if (-not $ep.GaveUp -and ($Now - $waitFrom).TotalSeconds -ge $s.RecoveryWaitSeconds) {
            $ep.GaveUp = $true
            Write-Log ("[SELFHEAL] {0} has not come back {1}s after the restart" -f $target.Name, $s.RecoveryWaitSeconds) "WARN"
            Add-SelfHealOutbox (New-SelfHealEpisodeRow -Kind "frozen" -Episode $ep -Now $Now -Reason "not_recovered")
        }
    }

    foreach ($k in @($rt.Instances.Keys)) { if (-not $seenKeys.ContainsKey($k)) { $rt.Instances.Remove($k) } }
}

# ---- health self-reports ----
function Get-SelfHealHealthSnapshot {
    param([Parameter(Mandatory=$true)][DateTime]$Now)
    $s = $script:SelfHealSettings
    $layer = $script:SelfHealLayer
    $progs = @()
    foreach ($target in @($s.Targets)) {
        $inst = @(@(& $layer.List $target.Name) | Where-Object { $null -ne $_ -and [string]$_.Name -ieq $target.Name -and $null -ne $layer.OwnSessionId -and $_.SessionId -eq $layer.OwnSessionId })
        $resp = @()
        foreach ($pi in $inst) { $resp += (Get-SelfHealReading $pi $layer $s.Detector).Responding }
        $responding = $null
        if ($inst.Count -gt 0) {
            if (@($resp | Where-Object { $_ -eq $false }).Count -gt 0) { $responding = $false }
            elseif (@($resp | Where-Object { $_ -eq $true }).Count -eq $inst.Count) { $responding = $true }
        }
        $progs += [pscustomobject]@{ Name = $target.Name; Running = ($inst.Count -gt 0); Instances = $inst.Count; Responding = $responding
                                    FrozenEpisodeOpen = ($null -ne $script:SelfHealRuntime -and $script:SelfHealRuntime.Episodes.ContainsKey($target.Name)) }
    }
    $screens = $null
    try { $screens = [int](& $layer.ScreenCount) } catch {}
    $audio = $null
    try { $audio = & $layer.Audio } catch {}
    return [pscustomobject]@{ AtUtc = $Now; Programs = $progs; Screens = $screens; Audio = $audio }
}

function Get-SelfHealHealthSignature($snap) {
    $parts = @()
    foreach ($p in @($snap.Programs)) {
        $r = $(if ($script:SelfHealSettings.WatchdogEnabled) { if ($p.FrozenEpisodeOpen) { "frozen" } else { "ok" } } else { [string]$p.Responding })
        $parts += ("{0}:{1}:{2}" -f $p.Name, $p.Running, $r)
    }
    $parts += ("screens:{0}" -f $snap.Screens)
    if ($null -eq $snap.Audio) { $parts += "audio:unknown" } else { $parts += ("audio:{0}:{1}" -f $snap.Audio.Present, $snap.Audio.Muted) }
    return ($parts -join "|")
}

function New-SelfHealHealthRows($snap) {
    $s = $script:SelfHealSettings
    $runId = ("health-{0}-{1}" -f $snap.AtUtc.ToString("yyyyMMddTHHmmssZ"), ($BayId.ToString().Trim("{}").Substring(0, 8)))
    $rows = @()

    # Golf program: running and responding.
    $progs = @($snap.Programs)
    $allRunning = ($progs.Count -gt 0) -and (@($progs | Where-Object { -not $_.Running }).Count -eq 0)
    $anyFalse = (@($progs | Where-Object { $_.Responding -eq $false }).Count -gt 0)
    $allTrue = ($progs.Count -gt 0) -and (@($progs | Where-Object { $_.Responding -ne $true }).Count -eq 0)
    $status = $SelfHealStatusInconclusive
    if (-not $allRunning -or $anyFalse) { $status = $SelfHealStatusFailed } elseif ($allTrue) { $status = $SelfHealStatusPassed }
    $progMetric = @($progs | ForEach-Object { [ordered]@{ name = $_.Name; running = $_.Running; instances = $_.Instances; responding = $_.Responding; frozenEpisodeOpen = $_.FrozenEpisodeOpen } })
    $progText = (($progs | ForEach-Object { "{0}: {1}" -f $_.Name, $(if (-not $_.Running) { "not running" } elseif ($_.Responding -eq $true) { "running and responding" } elseif ($_.Responding -eq $false) { "running, NOT responding" } else { "running, responding unknown" }) }) -join "; ")
    $rows += New-SelfHealDiagRow -CheckId $SelfHealCheckResponding -Category $SelfHealCatSoftware -Severity $SelfHealSevInfo -Status $status `
        -MetricValue $(if ($status -eq $SelfHealStatusPassed) { 1 } else { 0 }) -Metric ([ordered]@{ programs = $progMetric; detector = $s.Detector }) `
        -Details ("Golf software: " + $progText) -RunId $runId -AtUtc $snap.AtUtc

    # Screens Windows can see.
    $scrStatus = $SelfHealStatusInconclusive
    if ($null -ne $snap.Screens) {
        if ($snap.Screens -lt 1) { $scrStatus = $SelfHealStatusFailed }
        elseif ($null -ne $s.ExpectedScreens -and $snap.Screens -lt $s.ExpectedScreens) { $scrStatus = $SelfHealStatusFailed }
        else { $scrStatus = $SelfHealStatusPassed }
    }
    $rows += New-SelfHealDiagRow -CheckId $SelfHealCheckScreens -Category $SelfHealCatDisplay -Severity $SelfHealSevInfo -Status $scrStatus `
        -MetricValue $snap.Screens -Metric ([ordered]@{ screens = $snap.Screens; expected = $s.ExpectedScreens }) `
        -Details $(if ($null -eq $snap.Screens) { "Screens: could not be read" } elseif ($null -ne $s.ExpectedScreens) { "Screens: Windows sees {0} of {1} expected" -f $snap.Screens, $s.ExpectedScreens } else { "Screens: Windows sees {0}" -f $snap.Screens }) `
        -RunId $runId -AtUtc $snap.AtUtc

    # Audio output.
    $au = $snap.Audio
    $auStatus = $SelfHealStatusInconclusive
    $auText = "Sound: could not be read"
    $auMetric = [ordered]@{ present = $null }
    if ($null -ne $au) {
        $auMetric = [ordered]@{ present = [bool]$au.Present; muted = $au.Muted; volume = $au.VolumeScalar; hresult = ("0x{0:X8}" -f [int]$au.HResult) }
        if (-not $au.Present) { $auStatus = $SelfHealStatusFailed; $auText = "Sound: Windows has no audio output device" }
        elseif ($au.Muted -eq $true) { $auStatus = $SelfHealStatusFailed; $auText = "Sound: the output is muted" }
        else { $auStatus = $SelfHealStatusPassed; $auText = "Sound: an output device is present" + $(if ($null -ne $au.VolumeScalar) { (", volume {0}%" -f [int][Math]::Round(100 * [double]$au.VolumeScalar)) } else { "" }) }
    }
    $rows += New-SelfHealDiagRow -CheckId $SelfHealCheckAudio -Category $SelfHealCatPC -Severity $SelfHealSevInfo -Status $auStatus `
        -MetricValue $(if ($null -ne $au -and $au.Present) { 1 } elseif ($null -ne $au) { 0 } else { $null }) -Metric $auMetric `
        -Details $auText -RunId $runId -AtUtc $snap.AtUtc

    return $rows
}

function Invoke-SelfHealHealthTick {
    param([Parameter(Mandatory=$true)][DateTime]$Now)
    $s = $script:SelfHealSettings
    $rt = $script:SelfHealRuntime
    if (-not $s.HealthEnabled) { return }
    if ($Now -lt $rt.NextHealthSampleUtc) { return }
    $rt.NextHealthSampleUtc = $Now.AddSeconds($s.HealthSampleSeconds)

    $snap = Get-SelfHealHealthSnapshot -Now $Now
    $sig = Get-SelfHealHealthSignature $snap
    $scheduled = ($Now -ge $rt.NextHealthDueUtc)
    $changed = ($null -ne $rt.LastHealthSignature -and $sig -ne $rt.LastHealthSignature)
    $gapOk = ($null -eq $rt.LastHealthSentUtc) -or (($Now - $rt.LastHealthSentUtc).TotalMinutes -ge $s.HealthMinGapMinutes)
    if (-not ($scheduled -or ($changed -and $gapOk))) { return }

    $healthRows = New-SelfHealHealthRows $snap
    foreach ($row in @($healthRows)) { Add-SelfHealOutbox $row }
    $rt.LastHealthSignature = $sig
    $rt.LastHealthSentUtc = $Now
    $rt.NextHealthDueUtc = $Now.AddMinutes($s.HealthIntervalMinutes)
}

function Invoke-SelfHealTick {
    # Called from the main loop BEFORE the token: the watchdog works with the internet down. Never throws.
    param([Parameter(Mandatory=$true)][DateTime]$Now)
    if ($null -eq $script:SelfHealSettings -or -not $script:SelfHealSettings.Enabled) { return }
    try { Invoke-SelfHealWatchdogTick -Now $Now } catch { Write-Log ("[SELFHEAL] watchdog tick failed: {0}" -f $_.Exception.Message) "ERROR" }
    try { Invoke-SelfHealHealthTick -Now $Now } catch { Write-Log ("[SELFHEAL] health tick failed: {0}" -f $_.Exception.Message) "ERROR" }
}

$script:SelfHealSettings = $null
$script:SelfHealRuntime = $null
$script:SelfHealOutbox = @()
$script:SelfHealLayer = $null
$script:SelfHealNextSendUtc = $null
$script:SelfHealSendBackoffSeconds = 30
# Restore the emergency-stop latch before any command can run (a restart must not release it).
try { Restore-EmergencyStopLatch }
catch {
    $Global:EmergencyStopEngaged = $true
    $Global:EmergencyStopReason = "Emergency-stop restore failed; the stop is held until an explicit clear"
    Write-Log ("[ESTOP] restore failed: {0}" -f $_.Exception.Message) "ERROR"
}
try { Initialize-SelfHeal -ConfigPath $CfgPath -Now ((Get-Date).ToUniversalTime()) }
catch { Write-Log ("[SELFHEAL] could not start; it stays off: {0}" -f $_.Exception.Message) "ERROR"; $script:SelfHealSettings = $null }
# A0.363: the kiosk intent is re-derived from session.json (after the emergency-stop latch is restored), and the first
# reconcile runs now, so the kiosk block is in the first capabilities report. Nothing here can stop the agent starting.
if (-not $EnrollCert -and -not $TokenOnly) {
    # RF-K1: who is playing, before any command can run (a Reset reads it).
    try { Initialize-RunningSession -NowUtc ((Get-Date).ToUniversalTime()) } catch { Write-Log ("[SESSION] could not initialize: {0}" -f $_.Exception.Message) "ERROR" }
    try { Initialize-Kiosk -NowUtc ((Get-Date).ToUniversalTime()) } catch { Write-Log ("[KIOSK] could not initialize: {0}" -f $_.Exception.Message) "ERROR" }
    try { Invoke-KioskReconcileTickIfDue -NowUtc ((Get-Date).ToUniversalTime()) } catch { }
}

# ---------------- -EnrollCert: hands-on / Day-0 enrollment (no credential needed) ----------------
if ($EnrollCert) {
    $enrollPayload = New-EnrollCertPayload -ValidityDays $EnrollValidityDays -Store $EnrollStore -Force:$EnrollForce
    $r = Invoke-CredentialEnroll $enrollPayload
    Write-Host ""
    Write-Host ("ENROLLED certificate credential for bay {0}" -f $BayId)
    Write-Host ("  Thumbprint  : {0}" -f $r.thumbprint)
    Write-Host ("  Subject     : {0}" -f $r.subject)
    Write-Host ("  Store       : {0}" -f $r.store)
    Write-Host ("  NotAfter    : {0}" -f $r.notAfterUtc)
    Write-Host ("  State       : {0}" -f $(if ($r.activatedDirectly) { "ACTIVE (no prior credential)" } else { "PENDING (activate after registering in Entra)" }))
    Write-Host ("  Public cert : {0}" -f $r.publicCertPath)
    Write-Host "  Public cert (base64 DER) - register as a certificate credential on the Entra app:"
    Write-Host $r.publicCertBase64
    Write-Host ""
    Write-Host ("  Next: {0}" -f $r.next)
    exit 0
}

# ---------------- Main Loop ----------------
$didWhoAmI = $false

while ($true) {
    # A0.327 Phase 2: the self-heal watchdog runs BEFORE the token, so a frozen golf program is still restarted
    # with the club's internet down. Off unless agent-config.json says selfHeal.enabled = true. Never throws.
    if (-not $TokenOnly) {
        try { Invoke-SelfHealTick -Now ((Get-Date).ToUniversalTime()) } catch { }
        # A0.363: the kiosk reconciler, once a minute, also before the token (it needs no network). Never throws.
        try { Invoke-KioskReconcileTickIfDue -NowUtc ((Get-Date).ToUniversalTime()) } catch { }
        # A0.467: a booking canceled mid-play ends when its warning is over, network or not. Never throws.
        try { [void](Invoke-CancelEndIfDue -NowUtc ((Get-Date).ToUniversalTime())) } catch { }
    }

    try {
        $token = Get-AccessToken

        if ($TokenOnly) {
            Write-Log ("TokenOnly mode: token acquired via {0}. Exiting." -f $Global:CredentialTelemetry.lastMintMode) "INFO"
            break
        }

        if (-not $didWhoAmI) {
            Dataverse-WhoAmI $token
            $didWhoAmI = $true
            $Global:NextHeartbeatUtc = [DateTime]::MinValue
        }

        # Step 8.2: refresh effective config (BayProfile + ConfigItems overlay)
        Refresh-EffectiveConfigIfDue $token

        # Step 8.3: if a temporary Offline/Maintenance window has expired, auto-clear back to Online
        AutoClear-ExpiredAgentStatusIfDue $token

        # Update heartbeat on a timer, even if there are no commands
        Send-HeartbeatIfDue $token

        # A0.456: the bay's own wall pass, fetched and refreshed with its own identity. Off unless the release turns it on;
        # never throws.
        Update-DisplayPassIfDue -Now ((Get-Date).ToUniversalTime())

        # A0.327 Phase 2: deliver queued self-heal reports into the diagnostic pipe (no-op when self-heal is off)
        try { Send-SelfHealOutboxIfDue -token $token -Now ((Get-Date).ToUniversalTime()) }
        catch { Write-Log ("[SELFHEAL] report delivery failed: {0}" -f $_.Exception.Message) "WARN" }

        $cmd = Get-NextPendingCommand $token
        # The poll succeeded (it throws otherwise): with an accepted heartbeat, that is this agent "back" for the
        # update rollback guard. Never throws.
        Update-AgentAliveRecord -Now ((Get-Date).ToUniversalTime())
        # A0.458: the identity in force was accepted on this pass.
        Clear-IdentityProbationFailures
        if ($cmd) {
            Process-Command $token $cmd
        } else {
            Write-Log "No pending commands." "DEBUG"
        }
    }
    catch {
        Write-Log "Top-level exception: $($_.Exception.Message)" "ERROR"
        # A0.458: on probation, a refusal of the bay's own identity counts toward going back (an outage does not).
        Register-IdentityProbationFailure ("poll: " + $_.Exception.Message)
    }

    # A0.458: an identity switch nobody confirmed within the window is undone. Never throws.
    Test-IdentityProbationExpiry -Now ((Get-Date).ToUniversalTime())

    if ($Once) { break }

    $jitterMs = Get-Random -Minimum 0 -Maximum 300
    Start-Sleep -Milliseconds $jitterMs
    Start-Sleep -Seconds $PollSec
}

