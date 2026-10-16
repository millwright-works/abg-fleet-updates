<#
FleetRelease.Helper.Tests.ps1

WHY THIS EXISTS (DEV-02, fix round R9/F16)
  tools\release\Publish-AocFleetRelease.ps1 publishes a BayAgent release on GitHub with a publish token it reads from a
  Key Vault. The token must never reach any output stream, and every GitHub call must carry it. Before DEV-02 the helper
  was one script that called exit and read the vault inline, so none of that could be tested. It is now
  tools\release\AocFleetRelease.Lib.ps1 (functions only) plus a thin entry script. This suite dot-sources the library,
  replaces the two edges (Read-AocFpVaultSecret, Invoke-AocFpGhRaw) and the anonymous download with doubles, and runs the
  real flow Invoke-AocFleetPublish with every stream captured:
    T5   exit 0; every recorded GitHub call carries "Authorization: Bearer <fake token>"; no stream shows the token
    T5b  the same run against a scratch copy of the library with a planted print of the token FAILS the masking check
    T5c  -DryRun / -CompareOnly / missing -VaultName behave as documented (entry script run as a child process)
    T5d  a vault read that throws gives exit 2, names -VaultName (not a vault), and makes no GitHub call
  No network, no vault, no Azure login. The fake token is not a real credential.

RUN (from the repo root)
  powershell -NoProfile -ExecutionPolicy Bypass -File tests\FleetRelease.Helper.Tests.ps1

Exit code 0 = all assertions passed. Hyphens only in comments.
#>
[CmdletBinding()]
param()

$ErrorActionPreference = "Stop"

$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$LibPath = Join-Path $RepoRoot "tools/release/AocFleetRelease.Lib.ps1"
$EntryPath = Join-Path $RepoRoot "tools/release/Publish-AocFleetRelease.ps1"
$SetterPath = Join-Path $RepoRoot "tools/release/Set-AocFleetPublishToken.ps1"

$script:Pass = 0; $script:Fail = 0; $script:Failures = @()
function Assert-True([bool]$cond, [string]$msg) {
    if ($cond) { $script:Pass++; Write-Host "  PASS  $msg" }
    else { $script:Fail++; $script:Failures += $msg; Write-Host "  FAIL  $msg" -ForegroundColor Red }
}
function Section([string]$name) { Write-Host ""; Write-Host "== $name" -ForegroundColor Cyan }

$FakeToken = "github_pat_FAKE0123456789abcdef"
$Sha = "0123456789abcdef0123456789abcdef01234567"
$TagName = "fleet-v2026.10.16"
$SentinelVault = "sentinelvaultname"

Add-Type -TypeDefinition @"
public class FleetHelperFakeHttpException : System.Exception {
    public FleetHelperFakeHttpException(string m, int status) : base(m) { Response = new FakeResp(status); }
    public FakeResp Response;
    public class FakeResp { public int StatusCode; public FakeResp(int s) { StatusCode = s; } }
}
"@

# Runs the real publish flow against doubles. Returns code, calls, output. -Scenario picks what the doubles do.
function Invoke-Scenario([string]$Lib, [string]$Pkg, [string]$Scenario) {
    $script:TestCalls = New-Object System.Collections.ArrayList
    $script:TestVaultCalls = 0
    $script:TestTagMade = $false
    $script:TestScenario = $Scenario
    $script:TestPkg = $Pkg
    . $Lib
    function Read-AocFpVaultSecret([string]$AocFpVaultName, [string]$AocFpSecretName) {
        $script:TestVaultCalls++
        if ($script:TestScenario -eq 'vaultthrows') { throw "vault access failed for $AocFpVaultName" }
        if ($script:TestScenario -eq 'badshape') { return 'not-a-github-token' }
        return $FakeToken
    }
    function Invoke-AocFpGhRaw([hashtable]$AocFpParams) {
        $null = $script:TestCalls.Add(@{ Method = $AocFpParams.Method; Uri = $AocFpParams.Uri; Headers = $AocFpParams.Headers })
        $m = $AocFpParams.Method; $u = $AocFpParams.Uri
        $api = 'https://api.github.com/repos/millwright-works/abg-fleet-updates'
        if ($m -eq 'GET' -and $u -eq $api) { return @{ permissions = @{ push = $true } } }
        if ($m -eq 'GET' -and $u -eq "$api/commits/$Sha") { return @{ sha = $Sha } }
        if ($m -eq 'GET' -and $u -like "$api/releases?per_page=*") { return @() }
        if ($m -eq 'GET' -and $u -eq "$api/git/ref/tags/$TagName") {
            if (-not $script:TestTagMade) { throw (New-Object FleetHelperFakeHttpException ("not found " + $FakeToken), 404) }
            return @{ object = @{ type = 'commit'; sha = $Sha } }
        }
        if ($m -eq 'POST' -and $u -eq "$api/git/refs") { $script:TestTagMade = $true; return @{ ref = 'x' } }
        if ($m -eq 'POST' -and $u -eq "$api/releases") { return @{ id = 424242 } }
        if ($m -eq 'POST' -and $u -like 'https://uploads.github.com/repos/millwright-works/abg-fleet-updates/releases/424242/assets?name=*') {
            if ($script:TestScenario -eq 'uploadfails') { throw (New-Object FleetHelperFakeHttpException ("boom FAKE0123456789abcdef"), 500) }
            return @{ id = 1 }
        }
        if ($m -eq 'GET' -and $u -eq "$api/releases/424242") {
            $item = Get-Item -LiteralPath $script:TestPkg
            return @{ draft = $false; prerelease = $false; assets = @(@{ state = 'uploaded'; name = $item.Name; size = $item.Length; browser_download_url = 'https://example.invalid/dl/pkg.zip' }) }
        }
        throw (New-Object FleetHelperFakeHttpException ("unexpected call $m $u"), 418)
    }
    function Invoke-AocFpAnonDownload([string]$AocFpUri, [string]$AocFpOutFile) {
        [IO.File]::WriteAllBytes($AocFpOutFile, [IO.File]::ReadAllBytes($script:TestPkg))
    }
    $out = @(Invoke-AocFleetPublish -VaultName $SentinelVault -Tag $TagName -Commit $Sha -Title "T" -Notes "n" -PackagePath $Pkg *>&1)
    $codes = @($out | Where-Object { $_ -is [int] })
    $text = (($out | Where-Object { $_ -isnot [int] } | ForEach-Object { "$_" }) -join "`n")
    return [pscustomobject]@{ Code = $(if ($codes.Count -eq 1) { $codes[0] } else { -1 }); CodeCount = $codes.Count; Calls = $script:TestCalls; Text = $text; Vault = $script:TestVaultCalls }
}

# True when the run shows the token on any stream, in any recorded call's URI, or lacks it on a call.
function Test-Leak($r) {
    foreach ($bad in @('github_pat_', 'ghp_', 'FAKE0123456789abcdef')) { if ($r.Text.IndexOf($bad, [StringComparison]::Ordinal) -ge 0) { return $true } }
    return $false
}
function Test-AllCallsCarryToken($r) {
    if ($r.Calls.Count -lt 8) { return $false }
    foreach ($c in $r.Calls) { if ($c.Headers.Authorization -ne ("Bearer " + $FakeToken)) { return $false } }
    return $true
}

$tmp = Join-Path ([IO.Path]::GetTempPath()) ("fleetrelease-helper-" + [Guid]::NewGuid().ToString("N"))
$null = New-Item -ItemType Directory -Path $tmp
try {
    $pkg = Join-Path $tmp "BayAgent-9.9.9.zip"
    [IO.File]::WriteAllBytes($pkg, [byte[]](80, 75, 3, 4, 1, 2, 3, 4, 5, 6, 7, 8))

    Section "static: no vault name in the release tools, the library has no top-level effect"
    $libText = [IO.File]::ReadAllText($LibPath)
    $entryText = [IO.File]::ReadAllText($EntryPath)
    $setterText = [IO.File]::ReadAllText($SetterPath)
    foreach ($pair in @(@('lib', $libText), @('entry', $entryText), @('setter', $setterText))) {
        Assert-True ($pair[1].IndexOf(('kv-' + 'aoc-'), [StringComparison]::OrdinalIgnoreCase) -lt 0) ("$($pair[0]) carries no vault name")
    }
    Assert-True ($entryText -match '\[Parameter\(Mandatory\s*=\s*\$true\)\]\[string\]\$VaultName') "the entry script takes -VaultName as a mandatory parameter"
    Assert-True ($setterText -match '\[Parameter\(Mandatory\s*=\s*\$true\)\]\[string\]\$VaultName') "the token setter takes -VaultName as a mandatory parameter"
    Assert-True ($entryText -notmatch '(?im)\$VaultName\s*=\s*[''"]') "the entry script gives -VaultName no default"
    $tok = $null; $perr = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseFile($LibPath, [ref]$tok, [ref]$perr)
    Assert-True ($perr.Count -eq 0) "the library parses"
    $topLevel = @($ast.EndBlock.Statements | Where-Object { $_ -isnot [System.Management.Automation.Language.FunctionDefinitionAst] })
    $topBad = @($topLevel | Where-Object { $_.Extent.Text -notmatch '^\$script:AocFp\w+\s*=' })
    Assert-True ($topBad.Count -eq 0) ("the library top level holds only function definitions and `$script:AocFp variable initialisers" + $(if ($topBad.Count) { ": " + $topBad[0].Extent.Text } else { "" }))
    $calls = @($ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.CommandAst] -and $n.GetCommandName() -eq 'Invoke-RestMethod' }, $true))
    $inFns = @($calls | ForEach-Object { $p = $_.Parent; while ($p -and $p -isnot [System.Management.Automation.Language.FunctionDefinitionAst]) { $p = $p.Parent }; $p.Name })
    Assert-True ($inFns -contains 'Invoke-AocFpGhRaw' -and $inFns -contains 'Read-AocFpVaultSecret' -and @($inFns | Where-Object { $_ -notin @('Invoke-AocFpGhRaw', 'Read-AocFpVaultSecret') }).Count -eq 0) "Invoke-RestMethod is called only inside Invoke-AocFpGhRaw and Read-AocFpVaultSecret"
    $exits = @($ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.ExitStatementAst] }, $true))
    Assert-True ($exits.Count -eq 0) "the library never calls exit (the flow returns a code)"

    Section "T5 the publish flow with the token path exercised"
    $r = Invoke-Scenario $LibPath $pkg 'ok'
    Assert-True ($r.Code -eq 0 -and $r.CodeCount -eq 1) "Invoke-AocFleetPublish returns exactly one [int], and it is 0 (got $($r.Code), $($r.CodeCount) ints)"
    Assert-True ($r.Vault -eq 1) "the vault is read once (through Read-AocFpVaultSecret)"
    Assert-True ($r.Calls.Count -eq 9) "nine GitHub calls were recorded: token check, commit, releases, tag x2, tag create, release, upload, read-back (got $($r.Calls.Count))"
    Assert-True (Test-AllCallsCarryToken $r) "every recorded GitHub call carries Authorization: Bearer <the fake token>"
    Assert-True (-not (Test-Leak $r)) "the captured output (all streams) never contains github_pat_, ghp_ or the fake token"
    Assert-True ($r.Text -match 'OK: tag fleet-v2026\.10\.16') "the run printed its OK line (so the masking check ran over a real run)"
    Assert-True (@($r.Calls | Where-Object { $_.Headers.Authorization -match 'Bearer\s*$' }).Count -eq 0) "no call went out with an empty bearer"

    Section "T5 failure paths mask the token too"
    $rf = Invoke-Scenario $LibPath $pkg 'uploadfails'
    Assert-True ($rf.Code -eq 3) "an upload failure after the release exists returns 3 (got $($rf.Code))"
    Assert-True ($rf.Text -match 'release 424242 may exist') "...and the message names the release id"
    Assert-True (-not (Test-Leak $rf)) "...and the failure output never shows the token even though the double's exception text carried it"
    $rb = Invoke-Scenario $LibPath $pkg 'badshape'
    Assert-True ($rb.Code -eq 2 -and $rb.Calls.Count -eq 0) "a vault value that is not github_pat_ is refused with 2 and no GitHub call"

    Section "T5b a planted print of the token is caught by the masking check"
    $scratchLib = Join-Path $tmp "AocFleetRelease.Lib.scratch.ps1"
    $needle = "    `$script:AocFpHdr = @{"
    $idx = $libText.IndexOf($needle)
    Assert-True ($idx -gt 0) "(found the header line in the library to plant against)"
    $plantedText = $libText.Insert($idx, '    Write-Host $valFp' + "`r`n")
    Assert-True ($plantedText -ne $libText) "(the scratch copy differs from the library)"
    [IO.File]::WriteAllText($scratchLib, $plantedText)
    $rp = Invoke-Scenario $scratchLib $pkg 'ok'
    Assert-True ($rp.Code -eq 0) "the scratch copy with the planted print still publishes (the flow is not what is under test)"
    Assert-True (Test-Leak $rp) "the masking check FAILS (reports a leak) for the planted Write-Host of the token"
    $plantedText2 = $libText.Insert($idx, '    Write-Output $valFp' + "`r`n")
    [IO.File]::WriteAllText($scratchLib, $plantedText2)
    $rp2 = Invoke-Scenario $scratchLib $pkg 'ok'
    Assert-True ($rp2.CodeCount -ne 1 -or (Test-Leak $rp2)) "a planted Write-Output of the token is also caught (leak, or a polluted return value)"

    Section "T5d the vault read throws"
    $rv = Invoke-Scenario $LibPath $pkg 'vaultthrows'
    Assert-True ($rv.Code -eq 2) "exit code 2 (got $($rv.Code))"
    Assert-True ($rv.Text -match 'named by -VaultName') "the message names the -VaultName parameter"
    Assert-True ($rv.Text.IndexOf($SentinelVault, [StringComparison]::OrdinalIgnoreCase) -lt 0) "the message does not echo the vault name the caller passed"
    Assert-True ($rv.Calls.Count -eq 0) "no GitHub call was recorded"

    Section "T5c the entry script as a child process (Windows PowerShell 5.1)"
    $notes = Join-Path $tmp "notes.txt"; [IO.File]::WriteAllText($notes, "release notes")
    function Invoke-Entry([string[]]$ArgList, [string]$Script = $EntryPath) {
        $ErrorActionPreference = 'Continue'   # native stderr is output here, not a terminating error
        $all = @('-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File', $Script) + $ArgList
        $o = @(& powershell @all *>&1)
        return [pscustomobject]@{ Code = [int]$LASTEXITCODE; Text = (($o | ForEach-Object { "$_" }) -join "`n") }
    }
    $good = @('-VaultName', 'not-a-real-vault', '-Tag', $TagName, '-Commit', $Sha, '-Title', 'T', '-NotesPath', $notes, '-PackagePath', $pkg)
    $d1 = Invoke-Entry (@('-VaultName', 'not-a-real-vault', '-Tag', $TagName, '-Commit', $Sha, '-NotesPath', $notes, '-PackagePath', $pkg, '-DryRun'))
    Assert-True ($d1.Code -eq 2 -and $d1.Text -match 'Title is required') "-DryRun with a missing -Title exits 2"
    $d2 = Invoke-Entry ($good + '-DryRun')
    Assert-True ($d2.Code -eq 0 -and $d2.Text -match 'Authorization: Bearer \*{12} \(masked\)' -and $d2.Text -match 'DRY RUN OK') "-DryRun with valid arguments exits 0 and prints the masked header line"
    Assert-True ($d2.Text -notmatch 'github_pat_|not-a-real-vault') "...and prints no token and no vault name"
    $same = Join-Path $tmp "same.zip"; Copy-Item -LiteralPath $pkg -Destination $same
    $c1 = Invoke-Entry @('-VaultName', 'v', '-CompareOnly', '-PackagePath', $pkg, '-DownloadedPath', $same)
    Assert-True ($c1.Code -eq 0 -and $c1.Text -match 'OK: identical, 12 bytes, sha256 [0-9a-f]{64}') "-CompareOnly on identical files exits 0"
    $off = Join-Path $tmp "off.zip"; $b = [IO.File]::ReadAllBytes($pkg); $b[5] = 99; [IO.File]::WriteAllBytes($off, $b)
    $c2 = Invoke-Entry @('-VaultName', 'v', '-CompareOnly', '-PackagePath', $pkg, '-DownloadedPath', $off)
    Assert-True ($c2.Code -eq 3 -and $c2.Text -match 'sha256 differs') "-CompareOnly on files one byte apart exits 3 naming sha256"
    $short = Join-Path $tmp "short.zip"; [IO.File]::WriteAllBytes($short, [byte[]](80, 75))
    $c3 = Invoke-Entry @('-VaultName', 'v', '-CompareOnly', '-PackagePath', $pkg, '-DownloadedPath', $short)
    Assert-True ($c3.Code -eq 3 -and $c3.Text -match 'size differs') "-CompareOnly on files of different size exits 3 naming size"
    $n1 = Invoke-Entry @('-Tag', $TagName, '-Commit', $Sha, '-Title', 'T', '-NotesPath', $notes, '-PackagePath', $pkg, '-DryRun')
    Assert-True ($n1.Code -ne 0 -and $n1.Text -match 'VaultName' -and $n1.Text -notmatch 'DRY RUN') "the publish script with no -VaultName is refused before any call (mandatory parameter)"
    $n2 = Invoke-Entry @('-Tag', $TagName, '-Commit', $Sha, '-Title', 'T', '-NotesPath', $notes, '-PackagePath', $pkg)
    Assert-True ($n2.Code -ne 0 -and $n2.Text -match 'VaultName') "...also without -DryRun"
    $s1 = Invoke-Entry @() $SetterPath
    Assert-True ($s1.Code -ne 0 -and $s1.Text -match 'VaultName') "the token setter with no -VaultName is refused (mandatory parameter)"
}
finally {
    if ($tmp -like (Join-Path ([IO.Path]::GetTempPath()) "fleetrelease-helper-*")) { try { Remove-Item -LiteralPath $tmp -Recurse -Force -ErrorAction SilentlyContinue } catch {} }
}

Write-Host ""
Write-Host ("RESULT: {0} passed, {1} failed" -f $script:Pass, $script:Fail) -ForegroundColor $(if ($script:Fail -eq 0) { "Green" } else { "Red" })
if ($script:Fail -gt 0) { $script:Failures | ForEach-Object { Write-Host "  - $_" -ForegroundColor Red }; exit 1 }
exit 0
