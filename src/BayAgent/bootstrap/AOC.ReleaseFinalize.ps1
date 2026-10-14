<#
AOC.ReleaseFinalize.ps1 (v2.1 - Count fix)
Step 7 - Release discipline helper for All Birdies BayAgent.

What it does:
1) Creates/updates a release folder under:   C:\AceOfClubs\BayAgent\releases\<Version>\
2) Optionally copies files from a staging folder into the release folder
3) Writes/updates manifest.json (version + releasedUtc)
4) Signs all *.ps1 in the release folder with the specified Code Signing certificate,
   RFC 3161 timestamped so the signature outlives the certificate's own expiry
5) Verifies signatures are Valid AND timestamped
6) Switches C:\AceOfClubs\BayAgent\current junction to the new release folder
7) Optionally restarts AgentHost/BayAgent via scheduled tasks (preferred)

IMPORTANT (AllSigned):
- This script must be signed before you can run it under LocalMachine=AllSigned.
  You can sign it without running it.

Usage examples (run in elevated PowerShell):
  # 1) Save script to disk, unblock, sign, then run:
  Unblock-File C:\AceOfClubs\BayAgent\bootstrap\AOC.ReleaseFinalize.ps1
  $cert = Get-Item Cert:\CurrentUser\My\<thumbprint>
  Set-AuthenticodeSignature C:\AceOfClubs\BayAgent\bootstrap\AOC.ReleaseFinalize.ps1 -Certificate $cert -TimeStampServer http://timestamp.digicert.com

  # 2) Finalize a release folder you already prepared:
  .\AOC.ReleaseFinalize.ps1 -Version "1.4.3-step7.1" -CertThumbprint "<thumbprint>" -Restart

  # 3) Finalize from a staging folder (copies into releases\<Version>\):
  .\AOC.ReleaseFinalize.ps1 -Version "1.4.3-step7.1" -CertThumbprint "<thumbprint>" -SourceDir "C:\AceOfClubs\BayAgent\staging" -Restart -HealthCheck

Notes:
- By default, this script assumes a single file: BayAgent.ps1 in the release folder, but will sign any *.ps1 present.
- It does NOT modify bootstrap scripts (AgentHost/Watchdog). Keep those signed separately.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)]
    [string]$Version,

    [Parameter(Mandatory=$true)]
    [string]$CertThumbprint,

    [string]$BaseDir = "",   # empty = the root this script is installed in (Get-BayInstallRoot)

    # Optional: if provided, copies contents of SourceDir into the release folder before signing.
    [string]$SourceDir = "",

    # If true, restarts AgentHost/BayAgent using scheduled tasks after switching current.
    [switch]$Restart,

    # If true, runs BayAgent.ps1 -TokenOnly after switching current (best-effort).
    [switch]$HealthCheck,

    # Override UTC timestamp written to manifest (ISO 8601 Z). Default = now.
    [string]$ReleasedUtc = "",

    # RFC 3161 timestamp server used when signing every *.ps1 in the release folder.
    # A timestamped Authenticode signature stays valid after the signing certificate
    # itself expires; an untimestamped one does not. Must be HTTP, not HTTPS --
    # Set-AuthenticodeSignature does not support HTTPS timestamp URLs. Override only
    # if DigiCert's responder endpoint moves or a different CA is used.
    [string]$TimeStampServer = "http://timestamp.digicert.com"
)


# The install root is where this script is installed, not a constant (the rename, A0.634/A0.636). Get-BayInstallRoot
# is copied byte for byte into every script that needs it (tests\BayAgent.InstallRoot.Tests.ps1 pins the copies).
function Get-BayInstallRoot([string]$ScriptDir) {
    if ([string]::IsNullOrWhiteSpace($ScriptDir)) { throw "Cannot tell where this script is installed (no script folder)." }
    $d = $ScriptDir.TrimEnd('\')
    for ($i = 0; $i -lt 4; $i++) {
        $leaf = Split-Path -Leaf $d
        $parent = Split-Path -Parent $d
        if ([string]::IsNullOrEmpty($parent)) { break }
        if ($leaf -in @("tools", "bootstrap", "kiosk")) { $d = $parent; continue }
        if ($leaf -in @("current", "rollback")) { $d = $parent; break }
        if ((Split-Path -Leaf $parent) -eq "releases") { $d = Split-Path -Parent $parent; break }
        break
    }
    return $d
}
if ([string]::IsNullOrWhiteSpace($BaseDir)) { $BaseDir = Get-BayInstallRoot $PSScriptRoot }

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Test-IsAdmin {
    try {
        $id = [Security.Principal.WindowsIdentity]::GetCurrent()
        $p  = New-Object Security.Principal.WindowsPrincipal($id)
        return $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    } catch { return $false }
}

function Ensure-Dir([string]$p) {
    if (!(Test-Path $p)) { New-Item -ItemType Directory -Force -Path $p | Out-Null }
}

$LogDir = Join-Path $BaseDir "logs"
Ensure-Dir $LogDir
$LogFile = Join-Path $LogDir ("ReleaseFinalize-{0}.log" -f (Get-Date).ToString("yyyyMMdd"))

function Log([string]$msg, [ValidateSet("DEBUG","INFO","WARN","ERROR")] [string]$level="INFO") {
    $ts = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
    $line = "$ts [$level] $msg"
    Write-Host $line
    try { Add-Content -Path $LogFile -Value $line } catch {}
}

function Fail([string]$msg) {
    Log $msg "ERROR"
    exit 1
}

function Get-CodeSigningCert([string]$thumb) {
    $thumb = ($thumb -replace '\s','').ToUpperInvariant()
    $cert = $null
    try { $cert = Get-Item ("Cert:\CurrentUser\My\{0}" -f $thumb) -ErrorAction Stop } catch {}
    if (-not $cert) { try { $cert = Get-Item ("Cert:\LocalMachine\My\{0}" -f $thumb) -ErrorAction Stop } catch {} }

    if (-not $cert) { Fail "Code signing cert not found in CurrentUser\My or LocalMachine\My for thumbprint $thumb" }

    # Basic EKU check for Code Signing OID
    $ekuOk = $false
    try {
        foreach ($eku in $cert.EnhancedKeyUsageList) {
            if ($eku.ObjectId.Value -eq "1.3.6.1.5.5.7.3.3") { $ekuOk = $true; break }
        }
    } catch {}

    if (-not $ekuOk) {
        Log "WARNING: Cert does not appear to have Code Signing EKU (OID 1.3.6.1.5.5.7.3.3). Signing may still fail." "WARN"
    }
    return $cert
}

function Write-Manifest([string]$path, [string]$version, [string]$releasedUtcIso) {
    $obj = [ordered]@{
        version     = $version
        releasedUtc = $releasedUtcIso
    }
    $json = $obj | ConvertTo-Json -Depth 3
    # Ensure stable UTF-8 without BOM
    [IO.File]::WriteAllText($path, $json, (New-Object Text.UTF8Encoding($false)))
}

function Copy-ReleaseFiles([string]$src, [string]$dst) {
    if (-not (Test-Path $src)) { Fail "SourceDir not found: $src" }
    Log "Copying from SourceDir => ReleaseDir (best-effort). Source=$src Dest=$dst" "INFO"

    # Copy all files/folders from source into destination
    Get-ChildItem -Path $src -Force | ForEach-Object {
        $target = Join-Path $dst $_.Name
        if ($_.PSIsContainer) {
            Copy-Item -Path $_.FullName -Destination $target -Recurse -Force
        } else {
            Copy-Item -Path $_.FullName -Destination $target -Force
        }
    }
}

function Sign-Files([System.Security.Cryptography.X509Certificates.X509Certificate2]$cert, [string]$dir, [string]$timeStampServer) {
    $files = @(Get-ChildItem -Path $dir -Recurse -File -Filter *.ps1)
    if ($files.Count -eq 0) { Fail "No .ps1 files found in release folder to sign: $dir" }

    Log ("Signing {0} script(s) in {1} (timestamp server: {2})" -f $files.Count, $dir, $timeStampServer) "INFO"

    foreach ($f in $files) {
        $sig = Set-AuthenticodeSignature -FilePath $f.FullName -Certificate $cert -TimeStampServer $timeStampServer
        if ($sig.Status -ne "Valid") {
            Log ("Signature not valid for {0}. Status={1} Message={2}" -f $f.FullName, $sig.Status, $sig.StatusMessage) "ERROR"
            Fail "Signing failed for $($f.FullName)"
        }
        if ($null -eq $sig.TimeStamperCertificate) {
            # Set-AuthenticodeSignature can silently sign WITHOUT a timestamp and still
            # report Status=Valid if the timestamp server was unreachable or rejected the
            # request -- that untimestamped signature stops validating the moment the
            # signing cert expires. Refuse to ship it rather than fail silently.
            Log ("Signature for {0} is Valid but UNTIMESTAMPED (server: {1}). Refusing to ship an untimestamped release." -f $f.FullName, $timeStampServer) "ERROR"
            Fail "Timestamping failed for $($f.FullName) -- signature would stop validating when the signing certificate expires."
        }
    }
}

function Verify-Signatures([string]$dir) {
    $files = @(Get-ChildItem -Path $dir -Recurse -File -Filter *.ps1)
    foreach ($f in $files) {
        $sig = Get-AuthenticodeSignature -FilePath $f.FullName
        if ($sig.Status -ne "Valid") {
            Log ("INVALID signature: {0}. Status={1} Message={2}" -f $f.FullName, $sig.Status, $sig.StatusMessage) "ERROR"
            Fail "Signature verification failed for $($f.FullName)"
        }
        if ($null -eq $sig.TimeStamperCertificate) {
            Log ("UNTIMESTAMPED signature: {0}. Valid today, but will stop validating once the signing certificate expires." -f $f.FullName) "ERROR"
            Fail "Timestamp verification failed for $($f.FullName)"
        }
    }
    Log "All signatures verified as Valid and timestamped." "INFO"
}

function Switch-CurrentJunction([string]$baseDir, [string]$releaseDir) {
    $current = Join-Path $baseDir "current"

    if (-not (Test-IsAdmin)) {
        Fail "Switching the 'current' junction requires elevation. Re-run this script in an elevated PowerShell."
    }

    if (Test-Path $current) {
        Log "Removing existing current link/folder: $current" "INFO"
        cmd /c rmdir "$current" | Out-Null
        Start-Sleep -Milliseconds 200
    }

    Log "Creating junction: $current -> $releaseDir" "INFO"
    cmd /c mklink /J "$current" "$releaseDir" | Out-Null

    if (-not (Test-Path (Join-Path $current "BayAgent.ps1"))) {
        Fail "current junction created, but BayAgent.ps1 not found at: $current\BayAgent.ps1"
    }
}

function Restart-AgentViaTasks {
    param(
        [string]$HostTask = "\AOC Bay Agent",
        [string]$WatchdogTask = "\AOC Host Watchdog"
    )

    if (-not (Test-IsAdmin)) {
        Log "Restart requested, but not elevated. Skipping restart." "WARN"
        return
    }

    Log "Restarting AgentHost via scheduled tasks: End Host task then run Watchdog." "INFO"

    try { schtasks /End /TN $HostTask | Out-Null } catch {}
    Start-Sleep -Seconds 1
    try { schtasks /Run /TN $WatchdogTask | Out-Null } catch {
        Log ("Failed to run watchdog task: {0}" -f $_.Exception.Message) "WARN"
    }
}

function HealthCheck-TokenOnly([string]$baseDir) {
    $agent = Join-Path $baseDir "current\BayAgent.ps1"
    if (-not (Test-Path $agent)) { Log "HealthCheck skipped: current\BayAgent.ps1 not found." "WARN"; return }

    Log "Running TokenOnly health check (best-effort)..." "INFO"
    try {
        & powershell.exe -NoProfile -WindowStyle Hidden -File $agent -TokenOnly | ForEach-Object { Log $_ "DEBUG" }
        Log "HealthCheck completed." "INFO"
    } catch {
        Log ("HealthCheck failed: {0}" -f $_.Exception.Message) "WARN"
    }
}

# ---------------------------
# Main
# ---------------------------
$Version = $Version.Trim()
if ([string]::IsNullOrWhiteSpace($Version)) { Fail "Version is required." }

$releasesDir = Join-Path $BaseDir "releases"
$releaseDir  = Join-Path $releasesDir $Version
Ensure-Dir $releaseDir

if (-not [string]::IsNullOrWhiteSpace($SourceDir)) {
    Copy-ReleaseFiles -src $SourceDir -dst $releaseDir
}

# Write manifest
$releasedUtcIso = $ReleasedUtc
if ([string]::IsNullOrWhiteSpace($releasedUtcIso)) {
    $releasedUtcIso = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
}

$manifestPath = Join-Path $releaseDir "manifest.json"
Write-Manifest -path $manifestPath -version $Version -releasedUtcIso $releasedUtcIso
Log "Wrote manifest: $manifestPath (version=$Version releasedUtc=$releasedUtcIso)" "INFO"

# Sign & verify
$cert = Get-CodeSigningCert -thumb $CertThumbprint
Sign-Files -cert $cert -dir $releaseDir -timeStampServer $TimeStampServer
Verify-Signatures -dir $releaseDir

# Switch current to release
Switch-CurrentJunction -baseDir $BaseDir -releaseDir $releaseDir
Log "Switched current to release: $releaseDir" "INFO"

# Optional restart + healthcheck
if ($Restart) {
    Restart-AgentViaTasks
}

if ($HealthCheck) {
    HealthCheck-TokenOnly -baseDir $BaseDir
}

Log "Release finalize complete." "INFO"
exit 0
