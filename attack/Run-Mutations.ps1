# Mutation harness: take the REAL BayAgent.ps1, apply one targeted mutation, run the 127
# mock-mode assertions against the mutant, and record whether the suite goes red.
# A mutation that stays GREEN is a behavior the suite does not actually pin.
# Hyphens only in comments.
[CmdletBinding()]
param([string]$Only = "")

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$Root   = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$Agent  = Join-Path $Root "src\BayAgent\BayAgent.ps1"
$Tests  = Join-Path $Root "tests\BayAgent.Credential.Tests.ps1"
$Work   = Join-Path $env:TEMP ("bayagent-mut-" + [guid]::NewGuid().ToString("N").Substring(0,6))
New-Item -ItemType Directory -Force -Path $Work | Out-Null

$crlf = [string][char]13 + [string][char]10
$lf   = [string][char]10
$src = ([IO.File]::ReadAllText($Agent)).Replace($crlf, $lf)

# Each mutation: Id, Target (the invariant it breaks), From (exact substring), To (replacement).
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

$rows = @()
foreach ($m in $Muts) {
  if ($Only -and $m.Id -ne $Only) { continue }
  $mutPath = Join-Path $Work ("BayAgent-{0}.ps1" -f $m.Id)

  # NOTE: M12 used to have a hardcoded special case here, and it was an INERT MUTANT. It rewrote
  # Get-TokenUrl to read tokenAuthorityHost from $payloadObj -- but it also added
  # `param($payloadObj = $null)`, which DESTROYS the dynamic-scope lookup the mutation depends on. No
  # caller passes that argument, so $payloadObj was always $null, the branch never fired, and the
  # function behaved exactly like the original. It could not be caught by any suite, and it was being
  # counted as an unpinned behavior. Replaced with an ordinary From/To mutation (see $Muts).
  if ($false) {
  } else {
    if (-not $src.Contains($m.From)) {
      $rows += [pscustomobject]@{ Id=$m.Id; Target=$m.Target; Applied=$false; Suite="n/a"; Caught="ANCHOR MISS" }
      continue
    }
    $new = $src.Replace($m.From, $m.To)
  }

  [IO.File]::WriteAllText($mutPath, $new, (New-Object Text.UTF8Encoding($false)))

  # The mutant must still parse, or the suite fails for the wrong reason.
  $errs = $null; $toks = $null
  [System.Management.Automation.Language.Parser]::ParseFile($mutPath, [ref]$toks, [ref]$errs) | Out-Null
  if (@($errs).Count -gt 0) {
    $rows += [pscustomobject]@{ Id=$m.Id; Target=$m.Target; Applied=$true; Suite="PARSE ERR"; Caught="INVALID MUTANT" }
    continue
  }

  $out = ""
  $prevEA = $ErrorActionPreference
  $ErrorActionPreference = "Continue"
  try { $out = (& powershell -NoProfile -ExecutionPolicy Bypass -File $Tests -AgentScript $mutPath 2>&1 | Out-String) }
  catch { $out = "HARNESS EXCEPTION: $($_.Exception.Message)" }
  finally { $ErrorActionPreference = $prevEA; $global:LASTEXITCODE = 0 }
  $res = ([regex]::Match($out, "RESULT: (\d+) passed, (\d+) failed"))
  if ($res.Success) {
    $failed = [int]$res.Groups[2].Value
    $suite  = "$($res.Groups[1].Value)P/$($failed)F"
    $caught = if ($failed -gt 0) { "CAUGHT" } else { "*** SURVIVED ***" }
  } else {
    $suite  = "CRASH"
    $caught = "CAUGHT (crash)"
    if ($out -match "Function '([^']+)' not found") { $caught = "INVALID MUTANT (lift failed)" }
  }
  $rows += [pscustomobject]@{ Id=$m.Id; Target=$m.Target; Applied=$true; Suite=$suite; Caught=$caught }
  Write-Host ("{0,-4} {1,-32} {2,-12} {3}" -f $m.Id, $m.Target, $suite, $caught)
}

Write-Host ""
Write-Host "==== MUTATION RESULTS ===="
$rows | Format-Table -AutoSize | Out-String | Write-Host
$survivors = @($rows | Where-Object { $_.Caught -like "*SURVIVED*" })
Write-Host ("Survivors (unpinned behavior): {0}" -f $survivors.Count)
$survivors | ForEach-Object { Write-Host ("  {0}  {1}" -f $_.Id, $_.Target) }
Write-Host "Workdir: $Work"
