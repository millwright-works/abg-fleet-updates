# Set-AocFleetPublishToken.ps1 - run by Kevin ONCE, AFTER creating the GitHub fine-grained token for abg-fleet-updates
# (Contents read and write). Copy the token (github_pat_...) to the clipboard LAST, then run this script.
# It never prints the token and takes it from no parameter. Default source is the clipboard; if you would rather type
# it, run with -FromPrompt (hidden prompt). It checks the shape, writes secret github-fleet-publish-token to the vault
# named by -VaultName through the data-plane REST API with your az token, reads back and compares by SHA-256 only,
# clears the clipboard, and prints one OK or FAIL line. -VaultName is required and has no default: the vault name is not
# stored in this (public) repository. ASCII only.
param([Parameter(Mandatory = $true)][string]$VaultName, [switch]$FromPrompt)
$ErrorActionPreference = 'Stop'
$script:AocFpVault = $VaultName
$script:AocFpSecret = 'github-fleet-publish-token'
function Get-AocSha256Hex([string]$Text) {
  $bytes = [Text.Encoding]::UTF8.GetBytes($Text)
  $hash = [Security.Cryptography.SHA256]::Create().ComputeHash($bytes)
  return ([BitConverter]::ToString($hash) -replace '-', '').ToLower()
}
$script:AocFpNew = $null
try {
  if ($FromPrompt) {
    $secFp = Read-Host -Prompt 'Paste the token (hidden)' -AsSecureString
    $ptrFp = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secFp)
    try { $script:AocFpNew = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($ptrFp) }
    finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($ptrFp) }
  } else {
    $script:AocFpNew = (Get-Clipboard -Raw)
  }
  if ([string]::IsNullOrEmpty($script:AocFpNew)) { throw 'nothing to read (clipboard or prompt was empty)' }
  $script:AocFpNew = $script:AocFpNew.Trim()
  if ($script:AocFpNew -match '^ghp_|^gho_|^ghs_') { throw 'classic token copied; need a fine-grained token starting github_pat_' }
  if ($script:AocFpNew -notmatch '^github_pat_[A-Za-z0-9_]{50,120}$') { throw 'shape check failed (expected github_pat_ then 50-120 letters, digits, underscores)' }
  $tokAz = az account get-access-token --resource https://vault.azure.net --query accessToken -o tsv
  if (-not $tokAz) { throw 'no az token (run az login)' }
  $hdrAz = @{ Authorization = "Bearer $tokAz" }
  $uriAz = "https://{0}.vault.azure.net/secrets/{1}?api-version=7.4" -f $script:AocFpVault, $script:AocFpSecret
  $bodyAz = @{ value = $script:AocFpNew } | ConvertTo-Json
  $null = Invoke-RestMethod -Method PUT -Headers ($hdrAz + @{ 'Content-Type' = 'application/json' }) -Uri $uriAz -Body $bodyAz
  $backAz = (Invoke-RestMethod -Headers $hdrAz -Uri $uriAz).value
  if ((Get-AocSha256Hex $backAz) -ne (Get-AocSha256Hex $script:AocFpNew)) { throw 'readback mismatch' }
  Set-Clipboard -Value ' '
  Write-Host 'OK: github-fleet-publish-token stored in the vault named by -VaultName and read back identical'
} catch {
  try { Set-Clipboard -Value ' ' } catch { }
  $msgAz = ($_.Exception.Message -replace 'github_pat_[A-Za-z0-9_]+', '<redacted>')
  Write-Host ('FAIL: ' + $msgAz)
} finally {
  $script:AocFpNew = $null
}
