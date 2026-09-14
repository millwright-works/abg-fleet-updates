<#
Build-ReleasePackage.ps1 -- build a BayAgent fleet package zip from the working tree.

WHY THIS EXISTS
  Every BayAgent zip before 1.2.0 was assembled by hand. That is why nobody could say what
  was in one without opening it, and why the 1.1.7 / 1.1.8 zips sitting in the repo root
  were never published -- there was no step that produced them, only a person who had done
  it before. This script is that step.

WHAT IT PRODUCES
  dist\BayAgent-<version>.zip, byte-for-byte reproducible: fixed entry order, fixed
  timestamps, forward-slash separators. Running it twice on the same tree gives the same
  SHA256, so the hash in the fleet-release row can be re-derived rather than remembered.

  The layout matches every shipped BayAgent package (verified against the published
  BayAgent-1.1.6.zip asset):

      BayAgent.ps1
      manifest.json
      agent-config.json
      tools/Update-BayAgent.ps1
      tools/Update-SessionDisplay.ps1
      tools/Update-PromosPack.ps1
      tools/Publish-Current.ps1

SIGNING -- READ THIS BEFORE ADDING A SIGNING STEP HERE
  The package ships UNSIGNED, and that is correct, not an omission. MEASURED 2026-09-14
  against the published release asset for 1.1.6 (fleet-v2026.04.16f): its BayAgent.ps1 is
  NotSigned. The bay signs on arrival -- Update-BayAgent.ps1 runs -SignAfterInstall (default
  true) with the bay's OWN LocalMachine code-signing certificate, timestamps every .ps1
  recursively inside the release folder (tools\ included), and REFUSES to promote to
  current\ unless the signature reads Valid AND carries a TimeStamperCertificate.
  So each bay signs with the certificate it trusts, and no signing certificate has to
  travel with the package or exist on the machine that builds it.

  Corollary: do not sign the files before zipping. It would change the SHA256 after the
  hash was computed, and the bay re-signs them anyway.

PRE-FLIGHT GATES (this script refuses to build if any fail)
  1. Every shipped .ps1 must parse. Publish-Current.ps1 is exempt and explained below.
  2. No non-ASCII bytes outside a leading UTF-8 BOM. BA-15: a non-ASCII character in a
     comment caused a SILENT parse failure on Bay 1 under AllSigned, with no log output.
  3. manifest.json version must match -Version.

KNOWN, DELIBERATE: tools\Publish-Current.ps1 is JavaScript with a .ps1 extension -- an MDA
  form web resource misfiled at the initial commit (d8d953a) and shipped in every package
  since. It is never executed on a bay. It is kept so this package matches 1.1.8 exactly
  rather than changing the fleet payload in the same cycle as the credential work; removing
  it is safe whenever someone decides to (the tools merge uses robocopy /E, not /MIR, so a
  dropped file is not deleted from a bay). Until then it is exempt from the parse gate.

USAGE
  powershell -NoProfile -ExecutionPolicy Bypass -File tools\Build-ReleasePackage.ps1 -Version 1.2.0

Hyphens only in comments -- em-dashes break AllSigned parsing.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$Version,
    [string]$RepoRoot = "",
    [string]$OutDir = ""
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

if ([string]::IsNullOrWhiteSpace($RepoRoot)) { $RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path }
if ([string]::IsNullOrWhiteSpace($OutDir))   { $OutDir   = Join-Path $RepoRoot "dist" }

$srcBay = Join-Path $RepoRoot "src\BayAgent"

# Order is fixed so the archive is reproducible. Paths are the zip entry names, forward
# slashes -- the zip format requires them, and Compress-Archive writes backslashes.
$Entries = @(
    @{ Zip = "BayAgent.ps1";                    Src = "BayAgent.ps1" },
    @{ Zip = "manifest.json";                   Src = "manifest.json" },
    @{ Zip = "agent-config.json";               Src = "agent-config.json" },
    @{ Zip = "tools/Update-BayAgent.ps1";       Src = "tools\Update-BayAgent.ps1" },
    @{ Zip = "tools/Update-SessionDisplay.ps1"; Src = "tools\Update-SessionDisplay.ps1" },
    @{ Zip = "tools/Update-PromosPack.ps1";     Src = "tools\Update-PromosPack.ps1" },
    @{ Zip = "tools/Publish-Current.ps1";       Src = "tools\Publish-Current.ps1" }
)

# See the header note: JavaScript misfiled as .ps1, never executed on a bay.
$ParseExempt = @("tools/Publish-Current.ps1")

function Fail([string]$m) { Write-Host "FAIL: $m" -ForegroundColor Red; exit 1 }

Write-Host "Repo root : $RepoRoot"
Write-Host "Version   : $Version"
Write-Host ""

# ---------------------------------------------------------------- gate 0: files exist
foreach ($e in $Entries) {
    $p = Join-Path $srcBay $e.Src
    if (-not (Test-Path -LiteralPath $p)) { Fail "missing source file: $p" }
}

# ---------------------------------------------------------------- gate 1: manifest agrees
$manifestPath = Join-Path $srcBay "manifest.json"
$manifest = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
if ($manifest.version -ne $Version) {
    Fail ("manifest.json says version '{0}' but -Version is '{1}'. The agent reports the manifest's value in its heartbeat, so a mismatch ships a package that lies about what it is." -f $manifest.version, $Version)
}
Write-Host ("  OK  manifest.json version = {0}" -f $manifest.version)

# ---------------------------------------------------------------- gate 2: parse + ASCII
foreach ($e in $Entries) {
    $p = Join-Path $srcBay $e.Src
    if (-not $e.Zip.EndsWith(".ps1")) { continue }

    if ($ParseExempt -notcontains $e.Zip) {
        $errs = $null; $toks = $null
        [System.Management.Automation.Language.Parser]::ParseFile($p, [ref]$toks, [ref]$errs) | Out-Null
        $n = @($errs).Count
        if ($n -gt 0) { Fail ("{0} has {1} parse error(s); it would be shipped to a bay running AllSigned" -f $e.Zip, $n) }
        Write-Host ("  OK  {0} parses" -f $e.Zip)
    } else {
        Write-Host ("  --  {0} parse gate exempt (known non-PowerShell payload, see header)" -f $e.Zip)
    }

    # BA-15: non-ASCII in a comment produced a silent parse failure on Bay 1 under AllSigned.
    # A leading UTF-8 BOM is fine and is skipped -- it DECLARES the encoding rather than
    # relying on the host to guess it.
    $bytes = [IO.File]::ReadAllBytes($p)
    $start = 0
    if ($bytes.Length -ge 3 -and $bytes[0] -eq 0xEF -and $bytes[1] -eq 0xBB -and $bytes[2] -eq 0xBF) { $start = 3 }
    $bad = 0
    for ($i = $start; $i -lt $bytes.Length; $i++) { if ($bytes[$i] -gt 127) { $bad++ } }
    if ($bad -gt 0) { Fail ("{0} carries {1} non-ASCII byte(s) outside the BOM (BA-15: silent parse failure under AllSigned)" -f $e.Zip, $bad) }
}
Write-Host "  OK  no non-ASCII bytes outside a BOM"
Write-Host ""

# ---------------------------------------------------------------- build
if (-not (Test-Path -LiteralPath $OutDir)) { New-Item -ItemType Directory -Force -Path $OutDir | Out-Null }
$zipPath = Join-Path $OutDir ("BayAgent-{0}.zip" -f $Version)
if (Test-Path -LiteralPath $zipPath) { Remove-Item -LiteralPath $zipPath -Force }

Add-Type -AssemblyName System.IO.Compression
Add-Type -AssemblyName System.IO.Compression.FileSystem

# Fixed entry timestamp so two builds of the same tree hash identically. The zip carries
# no provenance anyway -- what proves the package is the SHA256 in the fleet-release row
# and the Authenticode pass the bay runs on arrival.
$fixedDate = New-Object DateTimeOffset (New-Object DateTime(2026, 9, 14, 0, 0, 0, ([DateTimeKind]::Utc)))

$fs = [IO.File]::Open($zipPath, [IO.FileMode]::CreateNew)
try {
    $archive = New-Object IO.Compression.ZipArchive($fs, [IO.Compression.ZipArchiveMode]::Create)
    try {
        foreach ($e in $Entries) {
            $src = Join-Path $srcBay $e.Src
            $entry = $archive.CreateEntry($e.Zip, [IO.Compression.CompressionLevel]::Optimal)
            $entry.LastWriteTime = $fixedDate
            $es = $entry.Open()
            try { $b = [IO.File]::ReadAllBytes($src); $es.Write($b, 0, $b.Length) } finally { $es.Dispose() }
            Write-Host ("  +   {0,-34} {1,8} bytes" -f $e.Zip, (Get-Item -LiteralPath $src).Length)
        }
    } finally { $archive.Dispose() }
} finally { $fs.Dispose() }

$item = Get-Item -LiteralPath $zipPath
$sha  = (Get-FileHash -LiteralPath $zipPath -Algorithm SHA256).Hash

Write-Host ""
Write-Host "PACKAGE : $zipPath"
Write-Host ("SIZE    : {0}" -f $item.Length)
Write-Host ("SHA256  : {0}" -f $sha.ToLowerInvariant())
Write-Host ""
Write-Host "Next: attach this zip to a GitHub release, then set build_packageurl and"
Write-Host "build_sha256 on the fleet-release row to the asset URL and the hash above."
exit 0
