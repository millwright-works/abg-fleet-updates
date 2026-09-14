# Mutation harness: take the REAL source tree, apply one targeted mutation, run the credential
# suite against the mutated TREE, and record whether the suite goes red.
# A mutation that stays GREEN is a behavior the suite does not actually pin.
# Hyphens only in comments.
#
# ============================ WHAT THIS HARNESS GOT WRONG, AND WHY IT IS BUILT THIS WAY NOW
# Independent verification on 2026-09-14 found three faults, all of the same shape: the harness
# reported an absence of bad news as evidence of good news.
#
#  1. EOL-BLIND ANCHORS. It normalized the AGENT SOURCE to LF but its own multi-line `From` anchors
#     are string literals inside this file, which carries whatever line endings it was checked out
#     with. .gitattributes pins `*.ps1 text eol=crlf`, so on a CORRECT checkout the CRLF literals
#     could never match the LF-normalized source. The three multi-line mutants -- M6, M18, M29 --
#     silently never applied, and the run still printed "Survivors: 0". Both sides are normalized now.
#
#  2. NON-APPLICATION WAS SILENT AND UNCOUNTED. The ANCHOR MISS and PARSE ERR branches `continue`d
#     before their Write-Host, so nothing appeared in the console as the run went by, and
#     `Applied=$false` rows were excluded from the survivor count. THREE BEHAVIORS WERE NEVER TESTED
#     AND THE RUN REPORTED CLEAN. A mutation that did not apply measured nothing.
#
#  3. CRASH WAS SCORED AS CAUGHT. A run with no `RESULT:` line was recorded as "CAUGHT (crash)".
#     A crash is evidence the suite noticed SOMETHING; it is not evidence the suite ASSERTS the
#     behavior -- and it truncates the run, so most assertions never execute. Three mutants (M6, M12,
#     M25) were dying with ZERO failed assertions while wearing a caught label.
#
#  4. IT MUTATED ONLY BayAgent.ps1. The tests resolve the updater from the repo, so
#     Update-BayAgent.ps1 ran pristine under every mutant and nothing in F7 that lives there was
#     mutation-tested at all. This harness now copies the WHOLE TREE and can mutate any file in it.
#
# So: every verdict is now its own column, a crash with zero failed assertions is NOT a pass, and the
# run EXITS NON-ZERO if anything did not apply. "Survivors: 0" must never be printable while a
# mutant went untested.
[CmdletBinding()]
param([string]$Only = "")

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$Root = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$Work = Join-Path $env:TEMP ("bayagent-mut-" + [guid]::NewGuid().ToString("N").Substring(0, 6))
New-Item -ItemType Directory -Force -Path $Work | Out-Null

$crlf = [string][char]13 + [string][char]10
$lf   = [string][char]10
function Norm([string]$t) { return $t.Replace($crlf, $lf) }

# How many sections the suite declares, so each mutant's run can be reported as "N of M sections ran".
$script:TotalSections = @([regex]::Matches(
    [IO.File]::ReadAllText((Join-Path $Root "tests\BayAgent.Credential.Tests.ps1")),
    "(?m)^\s*Section\s+`"")).Count
Write-Host ("Suite declares {0} sections; each mutant reports how many it reached." -f $script:TotalSections)

$Muts = @(
  @{ Id="M1"; Target="4 retire self-proof";       From='        $null = Acquire-TokenWithCertificate -Thumbprint $active'
                                                   To='        # MUTANT M1: self-proof removed' }
  @{ Id="M2"; Target="4 retire refuses no-cert";  From='        if (-not $active) { throw "retire secret: no active certificate; refusing to remove the only credential" }'
                                                   To='        # MUTANT M2: no-active-cert refusal removed' }
  @{ Id="M3"; Target="2 durable fallback total";  From='    try { $persisted = [int](Get-PropValue $st "fallbackCountTotal" 0) } catch { $persisted = 0 }'
                                                   To='    $persisted = 0   # MUTANT M3: prior total ignored' }
  @{ Id="M4"; Target="1 non-exportable key";      From='        -KeyExportPolicy NonExportable `'
                                                   To='        -KeyExportPolicy Exportable `' }
  @{ Id="M5"; Target="3 activate proof";          From='    $j = Acquire-TokenWithCertificate -Thumbprint $tp'
                                                   To='    $j = [pscustomobject]@{ expires_in = 3599 }   # MUTANT M5: proof removed' }
  @{ Id="M6"; Target="2 cert preferred";          From='    if ($activeTp) {
        try {
            $json = Acquire-TokenWithCertificate -Thumbprint $activeTp'
                                                   To='    if ($false) {
        try {
            $json = Acquire-TokenWithCertificate -Thumbprint $activeTp' }
  @{ Id="M7"; Target="4 retire ownership guard";  From='        if (-not (Test-IsAgentOwnedCertificate -Thumbprint $tp)) { throw "retire:'
                                                   To='        if ($false) { throw "retire:' }
  @{ Id="M8"; Target="4 active never retired";    From='        if ($tp -eq $active) { throw "retire: $tp is the ACTIVE credential; activate another certificate first" }'
                                                   To='        # MUTANT M8: active-credential guard removed' }
  @{ Id="M9"; Target="1 enroll never auto-active";From='    $activateNow = (-not $activeTp) -and (-not (Test-HasUsableSecret))'
                                                   To='    $activateNow = $true   # MUTANT M9: every enroll activates itself' }
  @{ Id="M10";Target="1 keyProvider allowlist";   From='    else { throw "keyProvider must be ''software'' or ''tpm'' (got ''$KeyProvider'')" }'
                                                   To='    # MUTANT M10: free-text provider allowed' }
  @{ Id="M11";Target="1 keyLength bound";         From='    if ($KeyLength -notin @(2048, 3072)) { throw "keyLength'
                                                   To='    if ($false) { throw "keyLength' }
  @{ Id="M12";Target="2 authority from config";   From='    return "$TokenAuthorityHost/$TenantId/oauth2/v2.0/token"'
                                                   To='    return "http://127.0.0.1:9/evil/$TenantId/oauth2/v2.0/token"   # MUTANT M12: token endpoint no longer comes from config' }
  @{ Id="M13";Target="1 validityDays bound";      From='    if ($ValidityDays -lt 30 -or $ValidityDays -gt 1825) { throw "validityDays must be between 30 and 1825" }'
                                                   To='    # MUTANT M13: validity bounds removed' }
  @{ Id="M14";Target="2 fallback counted";        From='                $Global:CredentialTelemetry.fallbackCount++'
                                                   To='                # MUTANT M14: fallback not counted' }
  @{ Id="M15";Target="2 flush idempotent";        From='            $t.fallbackFlushed = $t.fallbackCount'
                                                   To='            # MUTANT M15: flush watermark not advanced' }
  @{ Id="M16";Target="4 dpapi file removed";      From='                Remove-Item -LiteralPath $script:SecretPath -Force'
                                                   To='                # MUTANT M16: dpapi file not actually removed' }
  @{ Id="M17";Target="5 expired cert refused";    From='    if ($cert.NotAfter.ToUniversalTime() -lt (Get-Date).ToUniversalTime()) { throw "Certificate $Thumbprint expired'
                                                   To='    if ($false) { throw "Certificate $Thumbprint expired' }
  @{ Id="M18";Target="2 state overrides config";  From='    if ($fromState) { return $fromState }
    return $CertThumbprintCfg'
                                                   To='    if ($CertThumbprintCfg) { return $CertThumbprintCfg }
    return $fromState' }
  @{ Id="M19";Target="3 activate needs privkey";  From='    if (-not $cert) { throw "activate: certificate $tp with a private key not found'
                                                   To='    if ($false) { throw "activate: certificate $tp with a private key not found' }
  @{ Id="M20";Target="1 subject length bound";    From='    if ($Subject.Length -gt 120) { throw "subject must be 120 characters or fewer'
                                                   To='    if ($false) { throw "subject must be 120 characters or fewer' }
  @{ Id="M21";Target="2 configuredMode honest";   From='        configuredMode         = $(if ($activeTp) { "certificate" } else { "secret" })'
                                                   To='        configuredMode         = "certificate"   # MUTANT M21: always claims certificate' }
  @{ Id="M22";Target="4 deprecation WARN";        From='        Write-Log "DEPRECATED: agent-config.json carries a plaintext clientSecret.'
                                                   To='        if ($false) { Write-Log "DEPRECATED: agent-config.json carries a plaintext clientSecret.' }
  @{ Id="M23";Target="2 missing dpapi fatal";     From='            throw "clientSecretDpapiPath is set but file not found: $SecretPathCfg"'
                                                   To='            $script:SecretPath = $null   # MUTANT M23: never fatal' }
  @{ Id="M24";Target="1 result cap honored";      From='$ResultJsonMaxChars = 2000'
                                                   To='$ResultJsonMaxChars = 100000   # MUTANT M24: cap raised past the column' }
  @{ Id="M25";Target="4 retire records thumbprint";From='        $changes.retiredThumbprints = $retired'
                                                   To='        # MUTANT M25: retirement not recorded' }
  @{ Id="M26";Target="1 thumbprint length check"; From='    if ($n.Length -ne 40) { throw "Thumbprint must be 40 hex characters (got ''$tp'')" }'
                                                   To='    # MUTANT M26: length check removed' }
  @{ Id="M27";Target="2 telemetry has no secret"; From='        plaintextSecretPresent = ($null -ne $Secret)'
                                                   To='        plaintextSecretPresent = $Secret   # MUTANT M27: leaks the secret into the heartbeat' }
  @{ Id="M28";Target="3 pending cleared on activate";From='    if ((Get-PendingCertThumbprint) -eq $tp) { $changes.pendingThumbprint = $null }'
                                                   To='    # MUTANT M28: pending never cleared' }
  @{ Id="M29";Target="3 cached token dropped";    From='    $Global:AccessToken = $null
    $Global:TokenExpiresUtc = [DateTime]::MinValue

    Write-Log ("Credential activated'
                                                   To='    Write-Log ("Credential activated' }
)

# Mutations that live OUTSIDE BayAgent.ps1. The old harness could not express these at all: it wrote a
# lone mutated copy of the agent into a temp dir, and the suite resolves the updater from the repo, so
# Update-BayAgent.ps1 always ran pristine. Both of F7's halves were untested by mutation.
$Muts += @(
  @{ Id="MU1"; File="src\BayAgent\tools\Update-BayAgent.ps1"; Target="7 failed update records a marker"
     From='Write-UpdateResult -ok $false -reason $msg -stage "unknown"'
     To='  # MUTANT MU1: a failed update leaves the previous run''s marker in place' }
  @{ Id="MU2"; File="src\BayAgent\tools\Update-BayAgent.ps1"; Target="7 log follows -BaseDir"
     From='if ([string]::IsNullOrWhiteSpace($LogPath)) { $LogPath = Join-Path $BaseDir "logs\Update-BayAgent.log" }'
     To='if ([string]::IsNullOrWhiteSpace($LogPath)) { $LogPath = "C:\AllBirdies\BayAgent\logs\Update-BayAgent.log" }   # MUTANT MU2: log ignores -BaseDir again' }
  @{ Id="MU3"; File="src\BayAgent\tools\Update-BayAgent.ps1"; Target="7 the failure reaches the log"
     From='  Write-Log ("UPDATE FAILED: " + $msg)'
     To='  # MUTANT MU3: the failure is not logged (the original silent-throw defect)' }
  @{ Id="M30"; Target="5 EnrollForce is opt-in"
     From='    [switch]$EnrollForce'
     To='    [switch]$EnrollForce = $true   # MUTANT M30: Day-0 re-runs mint and abandon a key again' }
  @{ Id="M31"; Target="2 bak written on EVERY write"
     From='    if (Test-Path -LiteralPath $CredentialStatePath) {
        try { Copy-Item -LiteralPath $CredentialStatePath -Destination "$CredentialStatePath.bak" -Force } catch {'
     To='    if ((Test-Path -LiteralPath $CredentialStatePath) -and $Global:BakDone) {
        $Global:BakDone = $true
        try { Copy-Item -LiteralPath $CredentialStatePath -Destination "$CredentialStatePath.bak" -Force } catch {' }
  @{ Id="M32"; Target="4 retire refuses on corrupt state"
     From='    if ($Global:CredentialStateCorrupt) {
        throw "retire: credential.json is corrupt'
     To='    if ($false) {
        throw "retire: credential.json is corrupt' }
  @{ Id="M33"; Target="2 corrupt total is null not zero"
     From='        return $null
    }
    try { $persisted = [int](Get-PropValue $st "fallbackCountTotal" 0) } catch { $persisted = 0 }'
     To='        return 0   # MUTANT M33: corruption renders as a clean zero, which unlocks the gate
    }
    try { $persisted = [int](Get-PropValue $st "fallbackCountTotal" 0) } catch { $persisted = 0 }' }
)

$rows = @()
foreach ($m in $Muts) {
    if ($Only -and $m.Id -ne $Only) { continue }

    $relFile = if ($m.ContainsKey("File")) { $m.File } else { "src\BayAgent\BayAgent.ps1" }

    # A FULL TREE per mutant, so any file can be mutated and the suite's own relative lookups still work.
    $tree = Join-Path $Work $m.Id
    if (Test-Path $tree) { Remove-Item -LiteralPath $tree -Recurse -Force }
    New-Item -ItemType Directory -Force -Path $tree | Out-Null
    foreach ($d in @("src", "tests", "tools")) {
        $s = Join-Path $Root $d
        if (Test-Path $s) { Copy-Item -LiteralPath $s -Destination $tree -Recurse -Force }
    }

    $target = Join-Path $tree $relFile
    if (-not (Test-Path $target)) {
        $rows += [pscustomobject]@{ Id = $m.Id; Target = $m.Target; Verdict = "NOT-APPLIED"; Ran = "0/$script:TotalSections sections"; Detail = "target file missing: $relFile" }
        Write-Host ("{0,-5} {1,-34} {2,-14} {3}" -f $m.Id, $m.Target, "NOT-APPLIED", "target file missing") -ForegroundColor Red
        continue
    }

    # BOTH SIDES NORMALIZED. This is fault 1: anchors are literals in THIS file and carry its line
    # endings, while the source carries its own. Normalizing only one side is how three mutants
    # silently stopped applying the moment someone checked the repo out correctly.
    $src = Norm ([IO.File]::ReadAllText($target))
    $from = Norm $m.From
    $to   = Norm $m.To

    if (-not $src.Contains($from)) {
        $rows += [pscustomobject]@{ Id = $m.Id; Target = $m.Target; Verdict = "NOT-APPLIED"; Ran = "0/$script:TotalSections sections"; Detail = "anchor not found in $relFile" }
        Write-Host ("{0,-5} {1,-34} {2,-14} {3}" -f $m.Id, $m.Target, "NOT-APPLIED", "ANCHOR MISS -- this behavior was NOT tested") -ForegroundColor Red
        continue
    }

    $new = $src.Replace($from, $to)
    if ($new -eq $src) {
        # An INERT mutant: the anchor matched but the text did not change. M12 was one of these for
        # weeks -- it could not be caught by any suite and was counted as an unpinned behavior.
        $rows += [pscustomobject]@{ Id = $m.Id; Target = $m.Target; Verdict = "INERT"; Ran = "0/$script:TotalSections sections"; Detail = "From and To are identical after normalization" }
        Write-Host ("{0,-5} {1,-34} {2,-14} {3}" -f $m.Id, $m.Target, "INERT", "mutant changes nothing -- it can never be caught") -ForegroundColor Red
        continue
    }
    [IO.File]::WriteAllText($target, $new, (New-Object Text.UTF8Encoding($false)))

    $errs = $null; $toks = $null
    [System.Management.Automation.Language.Parser]::ParseFile($target, [ref]$toks, [ref]$errs) | Out-Null
    if (@($errs).Count -gt 0) {
        $rows += [pscustomobject]@{ Id = $m.Id; Target = $m.Target; Verdict = "INVALID"; Ran = "0/$script:TotalSections sections"; Detail = "mutant does not parse" }
        Write-Host ("{0,-5} {1,-34} {2,-14} {3}" -f $m.Id, $m.Target, "INVALID", "mutant does not parse") -ForegroundColor Yellow
        continue
    }

    $mutTests = Join-Path $tree "tests\BayAgent.Credential.Tests.ps1"
    $out = ""
    $prevEA = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    try { $out = (& powershell -NoProfile -ExecutionPolicy Bypass -File $mutTests 2>&1 | Out-String) }
    catch { $out = "HARNESS EXCEPTION: $($_.Exception.Message)" }
    finally { $ErrorActionPreference = $prevEA; $global:LASTEXITCODE = 0 }

    # Count assertions that actually FAILED, whether or not the run reached its summary line. A crash
    # that carries a failed assertion did demonstrate the behavior; a crash with none did not.
    $failLines = @([regex]::Matches($out, "(?m)^\s+FAIL\s")).Count
    $res = [regex]::Match($out, "RESULT: (\d+) passed, (\d+) failed")

    # HOW MUCH OF THE SUITE ACTUALLY RAN. A crash truncates everything after it, so "caught" can hide the
    # fact that most of the battery never executed -- and an assertion that is not REACHED pins nothing.
    # Printing sections-run makes that visible per mutant instead of leaving it to be inferred from a
    # verdict word.
    $sectionsRun = @([regex]::Matches($out, "(?m)^== ")).Count
    $coverage = "{0}/{1} sections" -f $sectionsRun, $script:TotalSections

    if ($res.Success) {
        $failed = [int]$res.Groups[2].Value
        if ($failed -gt 0) {
            $verdict = "CAUGHT-ASSERT"; $detail = "$($res.Groups[1].Value)P/$($failed)F"
        } else {
            $verdict = "SURVIVED"; $detail = "$($res.Groups[1].Value)P/0F"
        }
    } elseif ($failLines -gt 0) {
        $verdict = "CRASH-ASSERT"; $detail = "crashed after $failLines failed assertion(s)"
    } else {
        # THE ONE THAT USED TO READ AS A PASS. Nothing asserted anything; the suite simply died.
        $verdict = "CRASH-ZERO"; $detail = "crashed with ZERO failed assertions -- behavior NOT demonstrated"
    }

    $color = switch ($verdict) {
        "CAUGHT-ASSERT" { "Green" }
        "CRASH-ASSERT"  { "DarkGreen" }
        "CRASH-ZERO"    { "Red" }
        "SURVIVED"      { "Red" }
        default         { "Yellow" }
    }
    $rows += [pscustomobject]@{ Id = $m.Id; Target = $m.Target; Verdict = $verdict; Ran = $coverage; Detail = $detail }
    Write-Host ("{0,-5} {1,-34} {2,-14} {3,-16} {4}" -f $m.Id, $m.Target, $verdict, $coverage, $detail) -ForegroundColor $color
}

Write-Host ""
Write-Host "==== MUTATION RESULTS ===="
$rows | Format-Table -AutoSize | Out-String -Width 200 | Write-Host

function Count([string]$v) { return @($rows | Where-Object { $_.Verdict -eq $v }).Count }

$nCaught  = Count "CAUGHT-ASSERT"
$nCrashA  = Count "CRASH-ASSERT"
$nCrashZ  = Count "CRASH-ZERO"
$nSurv    = Count "SURVIVED"
$nNotApp  = Count "NOT-APPLIED"
$nInert   = Count "INERT"
$nInvalid = Count "INVALID"

Write-Host ("Defined                       : {0}" -f @($rows).Count)
Write-Host ("Caught by a failed assertion  : {0}" -f $nCaught)
Write-Host ("Crashed WITH a failed assert  : {0}" -f $nCrashA)
Write-Host ("Crashed with ZERO asserts     : {0}   <- NOT demonstrated" -f $nCrashZ)
Write-Host ("SURVIVED (unpinned behavior)  : {0}" -f $nSurv)
Write-Host ("Did not apply                 : {0}   <- measured NOTHING" -f $nNotApp)
Write-Host ("Inert (mutant changes nothing): {0}   <- measured NOTHING" -f $nInert)
Write-Host ("Invalid (does not parse)      : {0}" -f $nInvalid)
Write-Host ("Workdir: {0}" -f $Work)

$rows | Where-Object { $_.Verdict -in @("SURVIVED", "NOT-APPLIED", "INERT", "CRASH-ZERO") } |
    ForEach-Object { Write-Host ("  !! {0}  {1}  [{2}]" -f $_.Id, $_.Target, $_.Verdict) -ForegroundColor Red }

# A run is only clean if every mutant APPLIED and every one was demonstrated by an assertion.
# "Survivors: 0" printed over three mutants that never ran is the exact failure this exit code closes.
if (($nSurv + $nNotApp + $nInert + $nCrashZ) -gt 0) { exit 1 }
exit 0
