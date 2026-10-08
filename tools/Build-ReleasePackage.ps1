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
      tools/Watch-BayAgentUpdate.ps1     (1.3.1: the update rollback guard)
      kiosk/ABG.KioskShell.ps1           (1.4.0, A0.363: the kiosk shell; signed on arrival like every .ps1)
      kiosk/kiosk-policy.json            (1.4.0: the ONLY kiosk mode switch; 1.4.0 ships "explorer" = dormant)

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
  powershell -NoProfile -ExecutionPolicy Bypass -File tools\Build-ReleasePackage.ps1 -Version 1.2.1

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
    @{ Zip = "tools/Publish-Current.ps1";       Src = "tools\Publish-Current.ps1" },
    @{ Zip = "tools/Watch-BayAgentUpdate.ps1";  Src = "tools\Watch-BayAgentUpdate.ps1" },
    @{ Zip = "kiosk/ABG.KioskShell.ps1";        Src = "kiosk\ABG.KioskShell.ps1" },
    @{ Zip = "kiosk/kiosk-policy.json";         Src = "kiosk\kiosk-policy.json" }
)

# 1.4.0 (A0.363): every release from now on ships the kiosk shell AND its policy. The policy is the ONLY switch for the
# kiosk mode, so a package without it would be read on the bay as "no kiosk" (explorer): safe, but a silent change of
# mode that no release row says. Refuse to build one.
$RequiredKioskEntries = @("kiosk/ABG.KioskShell.ps1", "kiosk/kiosk-policy.json")
# Modes this release's code implements. "shell" (replace Explorer) is designed but NOT built; a package asking for it
# would be read as explorer by the agent, so the build refuses it rather than ship a policy that does not do what it says.
$BuildableKioskModes = @("explorer", "companion")

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

# ---------------------------------------------------------------- gate 0b: the kiosk files are in the package
foreach ($k in $RequiredKioskEntries) {
    if (@($Entries | Where-Object { $_.Zip -ceq $k }).Count -ne 1) { Fail ("the package must ship {0} exactly once (A0.363: the kiosk policy is the only mode switch)" -f $k) }
}

# ---------------------------------------------------------------- gate 1: manifest agrees
$manifestPath = Join-Path $srcBay "manifest.json"
$manifest = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
if ($manifest.version -ne $Version) {
    Fail ("manifest.json says version '{0}' but -Version is '{1}'. The agent reports the manifest's value in its heartbeat, so a mismatch ships a package that lies about what it is." -f $manifest.version, $Version)
}
Write-Host ("  OK  manifest.json version = {0}" -f $manifest.version)

# ---------------------------------------------------------------- gate 1b: the code's own version agrees (1.3.1)
# Since 1.3.1 the agent reports the version constant in BayAgent.ps1, not the manifest (F1, 2026-10-07: 1.3.0 ran on
# Bay 1 and reported 1.2.1 because the updater skipped an equal-sized manifest.json). Both must say -Version.
$agentText = [IO.File]::ReadAllText((Join-Path $srcBay "BayAgent.ps1"))
$cv = [regex]::Matches($agentText, '(?m)^\$AgentCodeVersion = "([^"]+)"\r?$')
if ($cv.Count -ne 1) { Fail ("BayAgent.ps1 must carry exactly one line `$AgentCodeVersion = `"<version>`" (found {0})" -f $cv.Count) }
if ($cv[0].Groups[1].Value -ne $Version) { Fail ("BayAgent.ps1 says `$AgentCodeVersion = '{0}' but -Version is '{1}'" -f $cv[0].Groups[1].Value, $Version) }
Write-Host ("  OK  BayAgent.ps1 AgentCodeVersion = {0}" -f $Version)

# ---------------------------------------------------------------- gate 1c: the manifest will actually be copied
# The updater ALREADY on a bay does the install, and through 1.3.0 it skipped a file whose size and time matched
# (every entry carries one fixed time, below). Every manifest from 1.2.0 to 1.3.0 was 68 bytes as shipped (65 in
# git, CRLF in the package). A new manifest of either length would be skipped by those updaters. The 1.3.1 updater
# copies every file and verifies by hash, so this gate only protects installs run by an older updater.
$manifestLen = (Get-Item -LiteralPath $manifestPath).Length
if ($manifestLen -in @(65, 68)) { Fail ("manifest.json is {0} bytes, the length of every shipped manifest from 1.2.0 to 1.3.0; an updater from before 1.3.1 would skip copying it. Change its length (add or remove a field)." -f $manifestLen) }
Write-Host ("  OK  manifest.json is {0} bytes (differs from the 65/68 of every earlier manifest)" -f $manifestLen)

# ---------------------------------------------------------------- gate 1d: the kiosk shell's own version agrees (1.4.0)
$shellText = [IO.File]::ReadAllText((Join-Path $srcBay "kiosk\ABG.KioskShell.ps1"))
$sv = [regex]::Matches($shellText, '(?m)^\$KioskShellCodeVersion = "([^"]+)"\r?$')
if ($sv.Count -ne 1) { Fail ("ABG.KioskShell.ps1 must carry exactly one line `$KioskShellCodeVersion = `"<version>`" (found {0})" -f $sv.Count) }
if ($sv[0].Groups[1].Value -ne $Version) { Fail ("ABG.KioskShell.ps1 says `$KioskShellCodeVersion = '{0}' but -Version is '{1}'" -f $sv[0].Groups[1].Value, $Version) }
Write-Host ("  OK  ABG.KioskShell.ps1 KioskShellCodeVersion = {0}" -f $Version)

# ---------------------------------------------------------------- gate 1e: the kiosk policy is exactly a policy this code runs
# The agent reads anything else as "explorer" (the safe answer), which would make the package say one thing and do
# another. So the BUILD is strict where the bay is forgiving: schema 1, a mode this release implements, a size floor.
$policyPath = Join-Path $srcBay "kiosk\kiosk-policy.json"
$policy = $null
try { $policy = [IO.File]::ReadAllText($policyPath) | ConvertFrom-Json } catch { Fail ("kiosk-policy.json is not valid JSON: {0}" -f $_.Exception.Message) }
if ($null -eq $policy -or $policy -is [Array]) { Fail "kiosk-policy.json must be a JSON object" }
$pSchema = $policy.PSObject.Properties["schema"]; $pMode = $policy.PSObject.Properties["mode"]; $pMin = $policy.PSObject.Properties["minShellBytes"]
if ($null -eq $pSchema -or -not ($pSchema.Value -is [int] -or $pSchema.Value -is [long]) -or [int64]$pSchema.Value -ne 1) { Fail "kiosk-policy.json schema must be the integer 1" }
if ($null -eq $pMode -or $pMode.Value -isnot [string] -or $pMode.Value -cnotin $BuildableKioskModes) { Fail ("kiosk-policy.json mode must be one of: {0} (shell mode is not built)" -f ($BuildableKioskModes -join ", ")) }
if ($null -eq $pMin -or -not ($pMin.Value -is [int] -or $pMin.Value -is [long]) -or [int64]$pMin.Value -lt 1024 -or [int64]$pMin.Value -gt 1048576) { Fail "kiosk-policy.json minShellBytes must be an integer from 1024 to 1048576" }
$shellLen = (Get-Item -LiteralPath (Join-Path $srcBay "kiosk\ABG.KioskShell.ps1")).Length
if ([int64]$pMin.Value -gt $shellLen) { Fail ("kiosk-policy.json minShellBytes {0} is larger than the shell itself ({1} bytes); the bay would refuse it" -f $pMin.Value, $shellLen) }
Write-Host ("  OK  kiosk-policy.json mode = {0}, minShellBytes = {1} (shell {2} bytes)" -f $pMode.Value, $pMin.Value, $shellLen)

# ---------------------------------------------------------------- gate 1f: the signed code carries the same mode (security review 2026-10-08)
# The policy file is writable on the bay, so the agent and the shell take "on" only from their own signed constants and
# let the file only turn the kiosk off. The three must agree in a package, or the release would not do what it says.
$amode = [regex]::Matches($agentText, '(?m)^\$KioskReleaseMode\s+= "([^"]+)"\r?$')
$smode = [regex]::Matches($shellText, '(?m)^\$KioskShellReleaseMode = "([^"]+)"\r?$')
if ($amode.Count -ne 1) { Fail ("BayAgent.ps1 must carry exactly one line `$KioskReleaseMode = `"<mode>`" (found {0})" -f $amode.Count) }
if ($smode.Count -ne 1) { Fail ("ABG.KioskShell.ps1 must carry exactly one line `$KioskShellReleaseMode = `"<mode>`" (found {0})" -f $smode.Count) }
if ($amode[0].Groups[1].Value -cne $pMode.Value -or $smode[0].Groups[1].Value -cne $pMode.Value) {
    Fail ("the kiosk mode disagrees: kiosk-policy.json '{0}', BayAgent.ps1 `$KioskReleaseMode '{1}', ABG.KioskShell.ps1 `$KioskShellReleaseMode '{2}'" -f $pMode.Value, $amode[0].Groups[1].Value, $smode[0].Groups[1].Value)
}
Write-Host ("  OK  the signed code carries the same kiosk mode ({0}) as the policy" -f $pMode.Value)

# ---------------------------------------------------------------- gate 2: parse + CRLF + ASCII (.ps1), CRLF + ASCII (.json)
# 1.4.0: the CRLF and ASCII gates cover the package's .json files too (AG-48 attack residual R1): the kiosk policy is
# read on the bay by a strict reader, and its bytes are part of the package hash like everything else.
foreach ($e in $Entries) {
    $p = Join-Path $srcBay $e.Src
    $isPs1 = $e.Zip.EndsWith(".ps1")
    if (-not $isPs1 -and -not $e.Zip.EndsWith(".json")) { continue }

    if (-not $isPs1) {
        # (.json: no parse step here; manifest.json and kiosk-policy.json are parsed by gates 1 and 1e above)
    } elseif ($ParseExempt -notcontains $e.Zip) {
        $errs = $null; $toks = $null
        [System.Management.Automation.Language.Parser]::ParseFile($p, [ref]$toks, [ref]$errs) | Out-Null
        $n = @($errs).Count
        if ($n -gt 0) { Fail ("{0} has {1} parse error(s); it would be shipped to a bay running AllSigned" -f $e.Zip, $n) }
        Write-Host ("  OK  {0} parses" -f $e.Zip)
    } else {
        Write-Host ("  --  {0} parse gate exempt (known non-PowerShell payload, see header)" -f $e.Zip)
    }

    $bytes = [IO.File]::ReadAllBytes($p)

    # LINE ENDINGS MUST BE CRLF, AND THIS GATE EXISTS BECAUSE THE ABSENCE OF IT SHIPPED A DEFECT.
    # .gitattributes pins `*.ps1 text eol=crlf`. Git normalizes text-marked files to LF in the INDEX,
    # so a worktree whose files are LF-only reports `git status` CLEAN -- the dirt is invisible to every
    # ordinary check. MEASURED 2026-09-14 by an independent verifier: the 1.2.0 package built from such a
    # worktree was 68,082 bytes / e2164e37..., while a clean checkout of the same commit built 68,407 /
    # f2141319... Same code, different bytes, and the release sheet carried the wrong hash into three
    # Dataverse fields.
    #
    # Two things went wrong and this gate closes both. The hash stopped being derivable from the commit --
    # which is the entire stated purpose of building reproducibly. And the package became the first ever
    # to ship MIXED line endings: two files LF, three CRLF, where 1.1.2 through 1.1.8 were all measured
    # internally consistent CRLF. Nobody chose that, in the file the bay Authenticode-signs.
    #
    # Refuse rather than silently repair: repairing here would hide a dirty worktree and let the next
    # build differ from the next clean checkout all over again. The fix is `git add --renormalize .`
    # followed by re-materializing the files, or simply building from a clean checkout.
    $lf = 0; $crlf = 0
    for ($i = 0; $i -lt $bytes.Length; $i++) {
        if ($bytes[$i] -eq 0x0A) {
            $lf++
            if ($i -gt 0 -and $bytes[$i - 1] -eq 0x0D) { $crlf++ }
        }
    }
    if ($lf -ne $crlf) {
        Fail ("{0} is not CRLF ({1} of {2} line endings are bare LF). .gitattributes pins *.ps1 text eol=crlf, but git normalizes to LF in the INDEX, so `git status` reads clean while the worktree is dirty. Run `git add --renormalize .` then re-materialize the files (git checkout-index -f -a), or build from a clean checkout of the commit." -f $e.Zip, ($lf - $crlf), $lf)
    }

    # BA-15: non-ASCII in a comment produced a silent parse failure on Bay 1 under AllSigned.
    # A leading UTF-8 BOM is fine and is skipped -- it DECLARES the encoding rather than
    # relying on the host to guess it.
    $start = 0
    if ($bytes.Length -ge 3 -and $bytes[0] -eq 0xEF -and $bytes[1] -eq 0xBB -and $bytes[2] -eq 0xBF) { $start = 3 }
    $bad = 0
    for ($i = $start; $i -lt $bytes.Length; $i++) { if ($bytes[$i] -gt 127) { $bad++ } }
    if ($bad -gt 0) { Fail ("{0} carries {1} non-ASCII byte(s) outside the BOM (BA-15: silent parse failure under AllSigned)" -f $e.Zip, $bad) }
}
Write-Host "  OK  every .ps1 and .json is CRLF, with no non-ASCII bytes outside a BOM"
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
