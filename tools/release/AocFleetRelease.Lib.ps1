# AocFleetRelease.Lib.ps1 - functions for publishing a BayAgent release on millwright-works/abg-fleet-updates (A0.462).
# Dot-source this file; it has no top-level effect. Publish-AocFleetRelease.ps1 is the entry point.
# The token (secret github-fleet-publish-token) lives only in a variable and an Authorization header. It is never
# printed, logged, put in a URL, or put in an error message: every failure prints a fixed reason plus an HTTP status
# code, never the exception text.
# Exit codes returned by Invoke-AocFleetPublish: 0 ok, 2 refused (bad arguments or state), 3 failed after GitHub accepted
# a write (read the message: it names the release id; do NOT blindly re-run, a half-made release must be inspected first).
# The vault name is never stored in this repository: the caller passes it (-AocFpVaultName).

$script:AocFpRepo = 'millwright-works/abg-fleet-updates'
$script:AocFpSecret = 'github-fleet-publish-token'
$script:AocFpHdr = $null
$script:AocFpStage = 'start'

function Get-AocFileSha256Hex([string]$Path) {
  return ((Get-FileHash -Algorithm SHA256 -LiteralPath $Path).Hash).ToLower()
}

# Throws a typed error carrying an exit code; Invoke-AocFleetPublish catches it and returns the code.
function Stop-AocFp([int]$Code, [string]$Reason) {
  Write-Host ('FAIL: ' + $Reason)
  $ex = New-Object System.Exception ('AocFpStop: ' + $Reason)
  $ex.Data['AocFpExitCode'] = $Code
  throw $ex
}

function Compare-AocAsset([string]$LocalPath, [string]$OtherPath, [string]$What) {
  if (-not (Test-Path -LiteralPath $OtherPath -PathType Leaf)) { return "$What file missing" }
  $a = (Get-Item -LiteralPath $LocalPath).Length; $b = (Get-Item -LiteralPath $OtherPath).Length
  if ($a -ne $b) { return "$What size differs (local $a bytes, other $b bytes)" }
  $ha = Get-AocFileSha256Hex $LocalPath; $hb = Get-AocFileSha256Hex $OtherPath
  if ($ha -ne $hb) { return "$What sha256 differs (local $ha, other $hb)" }
  return $null
}

# The only place a vault is read. Returns the secret value, or throws.
function Read-AocFpVaultSecret([string]$AocFpVaultName, [string]$AocFpSecretName) {
  $tokAz = az account get-access-token --resource https://vault.azure.net --query accessToken -o tsv
  if (-not $tokAz) { throw 'no az token' }
  $uriKv = 'https://{0}.vault.azure.net/secrets/{1}?api-version=7.4' -f $AocFpVaultName, $AocFpSecretName
  return (Invoke-RestMethod -Headers @{ Authorization = "Bearer $tokAz" } -Uri $uriKv).value
}

# The only place Invoke-RestMethod is called with the GitHub header.
function Invoke-AocFpGhRaw([hashtable]$AocFpParams) {
  return (Invoke-RestMethod @AocFpParams)
}

# The anonymous download: no Authorization header on purpose.
function Invoke-AocFpAnonDownload([string]$AocFpUri, [string]$AocFpOutFile) {
  Invoke-WebRequest -Uri $AocFpUri -OutFile $AocFpOutFile -UseBasicParsing
}

function Invoke-AocFpGh([string]$Method, [string]$Uri, $Body, [string]$InFile, [string]$ContentType, [switch]$AllowNotFound) {
  $p = @{ Method = $Method; Uri = $Uri; Headers = $script:AocFpHdr }
  if ($Body) { $p.Body = ($Body | ConvertTo-Json -Depth 5); $p.ContentType = 'application/json' }
  if ($InFile) { $p.InFile = $InFile; $p.ContentType = $ContentType }
  try { return (Invoke-AocFpGhRaw $p) }
  catch {
    $code = $null
    try { $code = [int]$_.Exception.Response.StatusCode } catch { }
    if ($AllowNotFound -and $code -eq 404) { return $null }
    throw ("GitHub {0} call at stage '{1}' failed (HTTP {2})" -f $Method, $script:AocFpStage, $code)
  }
}

# Compare-only mode (hash comparison, no network). Returns an exit code.
function Invoke-AocFleetCompare([string]$PackagePath, [string]$DownloadedPath) {
  try {
    if (-not $PackagePath -or -not $DownloadedPath) { Stop-AocFp 2 'CompareOnly needs -PackagePath and -DownloadedPath' }
    if (-not (Test-Path -LiteralPath $PackagePath -PathType Leaf)) { Stop-AocFp 2 'package file not found' }
    $r = Compare-AocAsset $PackagePath $DownloadedPath 'compared file'
    if ($r) { Stop-AocFp 3 $r }
    Write-Host ('OK: identical, {0} bytes, sha256 {1}' -f (Get-Item -LiteralPath $PackagePath).Length, (Get-AocFileSha256Hex $PackagePath))
    return 0
  } catch {
    if ($_.Exception.Data.Contains('AocFpExitCode')) { return [int]$_.Exception.Data['AocFpExitCode'] }
    Write-Host 'FAIL: unexpected error in compare'
    return 3
  }
}

# The publish flow (and -DryRun). Returns an exit code; never calls exit.
function Invoke-AocFleetPublish(
  [string]$VaultName, [string]$Tag, [string]$Commit, [string]$Title, [string]$Notes, [string]$NotesPath,
  [string]$PackagePath, [switch]$DryRun
) {
  $relId = $null
  try {
    # ---- argument checks (refusals) ----
    if ($Tag -notmatch '^fleet-v\d{4}\.\d{2}\.\d{2}[a-z]?$') { Stop-AocFp 2 'Tag must look like fleet-v2026.10.11 (optional one lowercase letter suffix)' }
    if ($Commit -notmatch '^[0-9a-f]{40}$') { Stop-AocFp 2 'Commit must be the full 40-character lowercase sha' }
    if ([string]::IsNullOrWhiteSpace($Title)) { Stop-AocFp 2 'Title is required' }
    if ($NotesPath) {
      if (-not (Test-Path -LiteralPath $NotesPath -PathType Leaf)) { Stop-AocFp 2 'NotesPath file not found' }
      $Notes = [IO.File]::ReadAllText($NotesPath)
    }
    if ([string]::IsNullOrWhiteSpace($Notes)) { Stop-AocFp 2 'Notes (or -NotesPath) is required' }
    if (-not $PackagePath -or -not (Test-Path -LiteralPath $PackagePath -PathType Leaf)) { Stop-AocFp 2 'package file not found' }
    $pkgItem = Get-Item -LiteralPath $PackagePath
    if ($pkgItem.Extension -ne '.zip') { Stop-AocFp 2 'package must be a .zip' }
    if ($pkgItem.Length -le 0) { Stop-AocFp 2 'package is empty' }
    if ($pkgItem.Length -gt 100MB) { Stop-AocFp 2 'package is over 100 MB; refusing' }
    $pkgName = $pkgItem.Name
    $pkgSize = $pkgItem.Length
    $pkgSha = Get-AocFileSha256Hex $PackagePath
    $apiRoot = 'https://api.github.com/repos/' + $script:AocFpRepo
    $upRoot = 'https://uploads.github.com/repos/' + $script:AocFpRepo

    $tagBody = [ordered]@{ ref = ('refs/tags/' + $Tag); sha = $Commit }
    $relBody = [ordered]@{ tag_name = $Tag; name = $Title; body = $Notes; draft = $false; prerelease = $false; make_latest = 'true' }

    if ($DryRun) {
      Write-Host 'DRY RUN: nothing is read from the vault and nothing is sent.'
      Write-Host ('repo           : {0}' -f $script:AocFpRepo)
      Write-Host ('headers        : Authorization: Bearer ************ (masked); Accept: application/vnd.github+json; X-GitHub-Api-Version: 2022-11-28')
      Write-Host ('1 GET  {0}/commits/{1}   (must exist)' -f $apiRoot, $Commit)
      Write-Host ('2 GET  {0}/git/ref/tags/{1}   (404 expected; if it exists it must point at the same commit)' -f $apiRoot, $Tag)
      Write-Host ('3 GET  {0}/releases?per_page=100   (refuse if any release already has tag {1})' -f $apiRoot, $Tag)
      Write-Host ('4 POST {0}/git/refs' -f $apiRoot)
      Write-Host ('   body: ' + ($tagBody | ConvertTo-Json -Compress))
      Write-Host ('5 POST {0}/releases' -f $apiRoot)
      Write-Host ('   body: ' + (([ordered]@{ tag_name = $Tag; name = $Title; body = ('<' + $Notes.Length + ' chars>'); draft = $false; prerelease = $false; make_latest = 'true' }) | ConvertTo-Json -Compress))
      Write-Host ('6 POST {0}/releases/<id>/assets?name={1}   Content-Type: application/zip' -f $upRoot, $pkgName)
      Write-Host ('   file: {0}, {1} bytes, sha256 {2}' -f $PackagePath, $pkgSize, $pkgSha)
      Write-Host '7 GET  release by id; expect exactly one asset, state uploaded, size equal'
      Write-Host '8 GET  asset browser_download_url with NO Authorization header into a fresh temp folder; size and sha256 must equal the local file'
      Write-Host 'DRY RUN OK'
      return 0
    }

    # ---- real run ----
    $script:AocFpStage = 'vault'
    $valFp = $null
    try { $valFp = Read-AocFpVaultSecret -AocFpVaultName $VaultName -AocFpSecretName $script:AocFpSecret }
    catch { Stop-AocFp 2 'could not read the publish token from the vault named by -VaultName (secret github-fleet-publish-token missing, no access, or -VaultName wrong; no az login?); Kevin must run Set-AocFleetPublishToken.ps1' }
    if (-not $valFp -or $valFp -notmatch '^github_pat_') { Stop-AocFp 2 'vault token missing or wrong shape; Kevin must run Set-AocFleetPublishToken.ps1' }
    $script:AocFpHdr = @{ Authorization = "Bearer $valFp"; Accept = 'application/vnd.github+json'; 'X-GitHub-Api-Version' = '2022-11-28'; 'User-Agent' = 'aoc-fleet-publisher' }
    $valFp = $null

    $script:AocFpStage = 'token check'
    $repoInfo = Invoke-AocFpGh 'GET' $apiRoot
    if (-not $repoInfo.permissions -or -not $repoInfo.permissions.push) { Stop-AocFp 2 'token is accepted but does not have write access to the repository (Contents write missing, or org approval pending)' }

    $script:AocFpStage = 'commit check'
    $c = Invoke-AocFpGh 'GET' ($apiRoot + '/commits/' + $Commit) -AllowNotFound
    if (-not $c -or $c.sha -ne $Commit) { Stop-AocFp 2 'that commit does not exist on the remote repository (push it first)' }

    $script:AocFpStage = 'existing release check'
    $rels = @(Invoke-AocFpGh 'GET' ($apiRoot + '/releases?per_page=100'))
    if (@($rels | Where-Object { $_.tag_name -eq $Tag }).Count -gt 0) { Stop-AocFp 2 "a release for tag $Tag already exists; refusing (never publish twice)" }

    $script:AocFpStage = 'existing tag check'
    $t = Invoke-AocFpGh 'GET' ($apiRoot + '/git/ref/tags/' + $Tag) -AllowNotFound
    $tagExisted = $false
    if ($t) {
      if ($t.object.type -ne 'commit' -or $t.object.sha -ne $Commit) { Stop-AocFp 2 "tag $Tag already exists and does not point at the requested commit as a lightweight tag; refusing" }
      $tagExisted = $true
    }

    # From here a write may have happened; failures return 3 and say so.
    if (-not $tagExisted) {
      $script:AocFpStage = 'create tag'
      $null = Invoke-AocFpGh 'POST' ($apiRoot + '/git/refs') $tagBody
      $t2 = Invoke-AocFpGh 'GET' ($apiRoot + '/git/ref/tags/' + $Tag)
      if ($t2.object.sha -ne $Commit -or $t2.object.type -ne 'commit') { Write-Host 'FAIL: tag was created but does not point at the requested commit; inspect before anything else'; return 3 }
    }

    $script:AocFpStage = 'create release'
    $rel = Invoke-AocFpGh 'POST' ($apiRoot + '/releases') $relBody
    $relId = $rel.id
    if (-not $relId) { Write-Host 'FAIL: release response had no id; inspect the releases page before retrying'; return 3 }

    $script:AocFpStage = 'upload asset'
    $null = Invoke-AocFpGh 'POST' ($upRoot + '/releases/' + $relId + '/assets?name=' + [uri]::EscapeDataString($pkgName)) $null $PackagePath 'application/zip'

    $script:AocFpStage = 'read release by id'
    $back = Invoke-AocFpGh 'GET' ($apiRoot + '/releases/' + $relId)
    $assets = @($back.assets)
    if ($back.draft -or $back.prerelease) { Write-Host "FAIL: release $relId is draft or prerelease"; return 3 }
    if ($assets.Count -ne 1) { Write-Host "FAIL: release $relId has $($assets.Count) assets, expected 1"; return 3 }
    if ($assets[0].state -ne 'uploaded') { Write-Host "FAIL: release $relId asset state is '$($assets[0].state)', expected uploaded"; return 3 }
    if ($assets[0].name -ne $pkgName) { Write-Host "FAIL: release $relId asset name differs from the package name"; return 3 }
    if ([long]$assets[0].size -ne $pkgSize) { Write-Host "FAIL: release $relId asset size $($assets[0].size) differs from local $pkgSize"; return 3 }

    $script:AocFpStage = 'download check'
    $dlDir = Join-Path ([IO.Path]::GetTempPath()) ('aoc-fleet-dl-' + [guid]::NewGuid().ToString('N'))
    $null = New-Item -ItemType Directory -Path $dlDir
    $dlFile = Join-Path $dlDir $pkgName
    try { Invoke-AocFpAnonDownload $assets[0].browser_download_url $dlFile }
    catch { Write-Host "FAIL: release $relId published but the anonymous download failed; inspect before retrying"; return 3 }
    $mm = Compare-AocAsset $PackagePath $dlFile 'downloaded asset'
    if ($mm) { Write-Host ("FAIL: release {0} published but {1}" -f $relId, $mm); return 3 }

    Write-Host ('OK: tag {0} on {1}; release id {2}; asset {3} {4} bytes sha256 {5} verified by anonymous download' -f $Tag, $Commit, $relId, $pkgName, $pkgSize, $pkgSha)
    Write-Host ('release url: https://github.com/{0}/releases/tag/{1}' -f $script:AocFpRepo, $Tag)
    return 0
  } catch {
    if ($_.Exception.Data.Contains('AocFpExitCode')) { return [int]$_.Exception.Data['AocFpExitCode'] }
    $why = ($_.Exception.Message -replace 'github_pat_[A-Za-z0-9_]+', '<redacted>')
    if ($relId) { Write-Host ("FAIL (release {0} may exist; inspect before retrying): {1}" -f $relId, $why); return 3 }
    Write-Host ('FAIL: ' + $why); return 3
  } finally {
    $script:AocFpHdr = $null
  }
}
