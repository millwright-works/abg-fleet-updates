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

# Release version (prefer manifest.json next to this script)
$AgentVersion = "dev"

try {
    $manifestPath = Join-Path $PSScriptRoot "manifest.json"
    if (Test-Path $manifestPath) {
        $m = Get-Content $manifestPath -Raw | ConvertFrom-Json
        if ($m -and $m.version) { $AgentVersion = [string]$m.version }
    }
} catch {
    # If manifest read fails, keep "dev" and continue
}

Write-Log "BayAgent starting. pid=$PID. OrgUrl=$OrgUrl BayId=$BayId PollSec=$PollSec HeartbeatSec=$HeartbeatSec LogLevel=$Global:LogLevel Version=$AgentVersion TokenOnly=$TokenOnly Once=$Once" "INFO"

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

# Bay columns (logical names)
$Col_Heartbeat = "build_lastheartbeat"
$Col_Machine   = "build_agentmachinename"
$Col_Version   = "build_agentversion"

# Choice values
$STATUS_PENDING    = 100000000
$STATUS_INPROGRESS = 100000001
$STATUS_SUCCEEDED  = 100000002
$STATUS_FAILED     = 100000003


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

# Emergency stop latch (cleared only by explicit command)
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
    param([Parameter(Mandatory=$true)][string]$Thumbprint)
    $cert = Find-ClientCertificate $Thumbprint
    if ($null -eq $cert) { throw "Certificate $Thumbprint (with private key) not found in $((Get-CertStoreSearchOrder) -join ', ')" }
    if ($cert.NotAfter.ToUniversalTime() -lt (Get-Date).ToUniversalTime()) { throw "Certificate $Thumbprint expired $($cert.NotAfter.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ'))" }

    $tokenUrl  = Get-TokenUrl
    $assertion = New-ClientAssertionJwt -Certificate $cert -ClientId $ClientId -Audience $tokenUrl -Alg $AssertionAlg
    $body = @(
        "client_id=$([uri]::EscapeDataString($ClientId))"
        "client_assertion_type=$([uri]::EscapeDataString('urn:ietf:params:oauth:client-assertion-type:jwt-bearer'))"
        "client_assertion=$assertion"
        "grant_type=client_credentials"
        "scope=$([uri]::EscapeDataString("$OrgUrl/.default"))"
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

    $t = $Global:CredentialTelemetry
    return [ordered]@{
        schema                 = 2
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

    try {
        if ($Method -eq "PATCH") {
            Invoke-RestMethod -Method Patch -Uri $Uri -Headers $Headers -ContentType "application/json" -Body $BodyJson -ErrorAction Stop | Out-Null
            return $null
        } else {
            return Invoke-RestMethod -Method Get -Uri $Uri -Headers $Headers -ErrorAction Stop
        }
    }
    catch {
        $ex = $_.Exception
        Write-Log "Dataverse call failed: $Method $Uri :: $($ex.Message)" "ERROR"

        # Best-effort: read Dataverse error JSON body
        try {
            $resp = $ex.Response
            if ($resp -ne $null) {
                $reader = New-Object System.IO.StreamReader($resp.GetResponseStream())
                $body = $reader.ReadToEnd()
                $reader.Close()
                if ($body) { Write-Log "Dataverse response body: $body" "ERROR" }
            }
        } catch {}

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
    }

    return ($cap | ConvertTo-Json -Depth 6 -Compress)
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
            }
        }

        Patch-Row $token "${BayEntitySet}" $BayId $patch "*"

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
    $selectClause = "$Col_CommandId,$Col_Status,$Col_CommandType,$Col_Payload,$Col_AttemptCount,$Col_NotBefore,createdon,$Lookup_BayValue"

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
            # Atomic replace when the destination exists
            [System.IO.File]::Replace($tmp, $path, $null, $true)
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

function Write-SessionFiles($modelObj) {
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
                foreach ($id in $pids) { $null = Safe-RouteProcessWindow -context $context -pid ([int]$id) -role $role -payloadObj $null -Maximize }
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
        $null = Safe-RouteProcessWindow -context $context -pid ([int]$proc.Id) -role $role -payloadObj $null -Maximize
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

function Get-DisplayTopology {
    # Returns a stable-ish view of monitors for config + troubleshooting.
    $out = @()
    try {
        $screens = [System.Windows.Forms.Screen]::AllScreens
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
    if ($null -eq $screens) { $screens = [System.Windows.Forms.Screen]::AllScreens }
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
    try { $screens = [System.Windows.Forms.Screen]::AllScreens } catch { return $null }

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

function Get-FirstVisibleWindowHandleForPid([int]$pid) {
    # Returns the first visible top-level window for a PID, or IntPtr::Zero.
    $script:__abgFoundHwnd = [IntPtr]::Zero
    try {
        $cb = [ABGWin32+EnumWindowsProc]{
            param([IntPtr]$hWnd, [IntPtr]$lParam)
            try {
                if (-not [ABGWin32]::IsWindowVisible($hWnd)) { return $true }
                $outPid = 0
                [void][ABGWin32]::GetWindowThreadProcessId($hWnd, [ref]$outPid)
                if ([int]$outPid -eq $pid) {
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
        [Parameter(Mandatory=$true)][int]$pid,
        [Parameter(Mandatory=$true)][ValidateSet("play","control","session")][string]$role,
        $payloadObj,
        [int]$timeoutSec = 8,
        [switch]$Maximize
    )

    $screen = Get-ScreenForRole $role $payloadObj
    if ($null -eq $screen) { return @{ moved = $false; reason = "no_target_screen"; role = $role; pid = $pid } }

    $deadline = (Get-Date).AddSeconds($timeoutSec)
    $hWnd = [IntPtr]::Zero
    do {
        $hWnd = Get-FirstVisibleWindowHandleForPid $pid
        if ($hWnd -ne [IntPtr]::Zero) { break }
        Start-Sleep -Milliseconds 250
    } while ((Get-Date) -lt $deadline)

    if ($hWnd -eq [IntPtr]::Zero) {
        return @{ moved = $false; reason = "no_window_handle"; role = $role; pid = $pid }
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
            pid = $pid
            deviceName = $screen.DeviceName
            deviceDesc = (Get-DisplayDeviceString $screen.DeviceName)
            bounds = @{ left=$b.Left; top=$b.Top; width=$b.Width; height=$b.Height }
        }
    } catch {
        return @{ moved = $false; role = $role; pid = $pid; error = $_.Exception.Message }
    }
}

function Safe-RouteProcessWindow {
    param(
        [string]$context,
        [int]$pid,
        [string]$role,
        $payloadObj,
        [switch]$Maximize
    )
    try {
        $res = Move-ProcessWindowToRole -pid $pid -role $role -payloadObj $payloadObj -Maximize:$Maximize
        if ($res.moved) {
            Write-Log "DisplayRouting: moved pid=$pid to role=$role ($($res.deviceName) / $($res.deviceDesc)) context=$context" "INFO"
        } else {
            Write-Log "DisplayRouting: no move pid=$pid role=$role reason=$($res.reason) context=$context" "DEBUG"
        }
        return $res
    } catch {
        Write-Log "DisplayRouting: exception context=$context pid=$pid role=$role :: $($_.Exception.Message)" "WARN"
        return @{ moved = $false; role = $role; pid = $pid; error = $_.Exception.Message }
    }
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

function Invoke-EmergencyStopInternal {
    param($payloadObj)

    $reason = $null
    try { $reason = (Get-PropValue $payloadObj "reason" $null) } catch {}
    if ([string]::IsNullOrWhiteSpace([string]$reason)) { $reason = "Emergency stop requested" }

    $Global:EmergencyStopEngaged = $true
    $Global:EmergencyStopReason = $reason

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
        facility = $facility
    }
}

function Clear-EmergencyStopInternal {
    $Global:EmergencyStopEngaged = $false
    $Global:EmergencyStopReason = $null
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
        try { $null = Safe-RouteProcessWindow -context "SessionDisplay:already_running" -pid ([int]$pidToUse) -role $role -payloadObj $payloadObj -Maximize } catch {}

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
    try { $null = Safe-RouteProcessWindow -context "SessionDisplay:started" -pid ([int]$pidToRoute) -role $role -payloadObj $payloadObj -Maximize } catch {}

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

# Emergency stop latch (cleared only by explicit command)
$Global:EmergencyStopEngaged = $false
$Global:EmergencyStopReason = $null
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
    if ($tp) {
        try {
            $j = Acquire-TokenWithCertificate -Thumbprint $tp
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

    $cert = Find-ClientCertificate $tp
    if (-not $cert) { throw "activate: certificate $tp with a private key not found in $((Get-CertStoreSearchOrder) -join ', ')" }

    # PROVE before switching. A real token mint with the candidate; if this throws nothing below runs and the
    # active credential is untouched (Process-Command marks the command Failed with the AADSTS code).
    $j = Acquire-TokenWithCertificate -Thumbprint $tp

    $prevActive = Get-ActiveCertThumbprint
    $nowStr = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
    $changes = @{ activeThumbprint = $tp; activatedUtc = $nowStr }
    if ((Get-PendingCertThumbprint) -eq $tp) { $changes.pendingThumbprint = $null }
    if ($prevActive -and $prevActive -ne $tp) { $changes.previousThumbprint = $prevActive }
    Update-CredentialState $changes | Out-Null

    # Drop the cached token so the very next loop iteration mints with the new certificate.
    $Global:AccessToken = $null
    $Global:TokenExpiresUtc = [DateTime]::MinValue

    Write-Log ("Credential activated: certificate {0} is now the active credential (previous: {1})" -f $tp, $(if ($prevActive) { $prevActive } else { "secret" })) "INFO"
    return [ordered]@{
        ok                 = $true
        action             = "activate"
        activeThumbprint   = $tp
        previousThumbprint = $prevActive
        notAfterUtc        = $cert.NotAfter.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
        proof              = [ordered]@{ mintedWithCertificate = $true; expiresIn = $j.expires_in }
        next               = "Wait for a heartbeat showing credential.lastMintMode = certificate, THEN delete the old secret/certificate on the Entra app, THEN send action=retire"
    }
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
        default    { throw "CredentialRotate: unknown action '$action' (status | enroll | test | activate | retire)" }
    }
}

function Execute-Command {
    param(
        [Parameter(Mandatory=$true)][int]$CommandType,
        [string]$PayloadJson,
        [string]$BayLabel
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
            return @{
                ok = $true
                agentVersion = $AgentVersion
                machine = $env:COMPUTERNAME
                bayId = $BayId
                utc = $nowHb
            }
        }

        
$CMD_DISPLAY_TOPOLOGY {
    return @{
        ok = $true
        topology = @((Get-DisplayTopology))
    }
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

            # Facility scene tied to the session (Step 5).
            $facility = $null

            # If EmergencyStop is latched, block session starts and force a safe scene.
            if ($Global:EmergencyStopEngaged) {
                try {
                    $facility = Invoke-FacilitySetMode -Mode "Cleanup" -payloadObj $payloadObj
                } catch {
                    $facility = @{ ok = $false; error = $_.Exception.Message }
                }

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
            $paths = Write-SessionFiles $model

            # Ensure the Session Display is running (no duplicates).
            $display = Start-SessionDisplay $payloadObj

            # Launcher should start ONLY at "Start"
            $launcherCfg = Get-LauncherConfigFromPayloadOrConfig $payloadObj
            if ([string]::IsNullOrWhiteSpace([string]$launcherCfg.path)) { $launcherCfg.path = "C:\Uneekor\Launcher\UneekorLauncher.exe" }

            $launcher = $null
            if ($modeLower -eq "start") {
                $startOnStart = $launcherCfg.startOnStart
                if ($null -eq $startOnStart) { $startOnStart = $true }
                if ([bool]$startOnStart) {
                    $launcher = Start-LauncherIfNeeded "StartSession:Start" $launcherCfg
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
            }
        }


        $CMD_ENDSESSION {
            # End of session:
            #  - Close Uneekor Launcher by default (prevents overtime)
            #  - Keep Session Display open by default and show a thank-you message
            if ($null -eq $payloadObj) { $payloadObj = @{} }

            # Facility: EndSession always moves the bay to the Cleanup scene (Step 5).
            $facility = $null
            try {
                $facility = Invoke-FacilitySetMode -Mode "Cleanup" -payloadObj $payloadObj
            } catch {
                $facility = @{ ok = $false; error = $_.Exception.Message }
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
            $paths = Write-SessionFiles $model

            $apps = Stop-AppsIfRequested $payloadObj

            # Guard against late/out-of-order EndSession for an older session (e.g., back-to-back bookings).
            $payloadSessionId = [string](Get-PropValue $payloadObj "baySessionId" "")
            $currentSessionId = [string](Get-PropValue $existing "baySessionId" "")
            $sameSession = $true
            if (-not [string]::IsNullOrWhiteSpace($payloadSessionId) -and -not [string]::IsNullOrWhiteSpace($currentSessionId) -and ($payloadSessionId -ne $currentSessionId)) {
                $sameSession = $false
            }

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
                sessionJsonPath = $paths.sessionJsonPath
                sessionJsPath = $paths.sessionJsPath
                facility = $facility
                apps = $apps
                launcherStopped = $launcherStopped
                closeDisplay = $closeDisplay
                display = $display
                displayStopped = $displayStopped
            }
        }

        $CMD_RESET {
            # Reset to a known-good "READY" state.
            # Default behavior: keep the Session Display running (or restart it) so the bay never sits on a blank screen.
            if ($null -eq $payloadObj) { $payloadObj = @{} }

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
$resultObj = Execute-Command -CommandType $type -PayloadJson $payload -BayLabel $bayLabelFromCmd
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

        # Booking status write-back (non-fatal): update booking when session starts or ends.
        try {
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
        }
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
try { Initialize-SelfHeal -ConfigPath $CfgPath -Now ((Get-Date).ToUniversalTime()) }
catch { Write-Log ("[SELFHEAL] could not start; it stays off: {0}" -f $_.Exception.Message) "ERROR"; $script:SelfHealSettings = $null }

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

        # A0.327 Phase 2: deliver queued self-heal reports into the diagnostic pipe (no-op when self-heal is off)
        try { Send-SelfHealOutboxIfDue -token $token -Now ((Get-Date).ToUniversalTime()) }
        catch { Write-Log ("[SELFHEAL] report delivery failed: {0}" -f $_.Exception.Message) "WARN" }

        $cmd = Get-NextPendingCommand $token
        if ($cmd) {
            Process-Command $token $cmd
        } else {
            Write-Log "No pending commands." "DEBUG"
        }
    }
    catch {
        Write-Log "Top-level exception: $($_.Exception.Message)" "ERROR"
    }

    if ($Once) { break }

    $jitterMs = Get-Random -Minimum 0 -Maximum 300
    Start-Sleep -Milliseconds $jitterMs
    Start-Sleep -Seconds $PollSec
}

