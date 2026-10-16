# Publish-AocFleetRelease.ps1 - agents publish a BayAgent release on millwright-works/abg-fleet-updates (A0.462).
# Creates the tag on the exact commit, creates the release (not draft, not prerelease, latest), uploads the package,
# then downloads the published asset anonymously and compares size and sha256 with the local file.
# All logic is in AocFleetRelease.Lib.ps1 (tested by tests/FleetRelease.Helper.Tests.ps1). This file only binds
# parameters, calls the flow and exits with its code.
#   -VaultName   REQUIRED, no default: the name of the Key Vault that holds secret github-fleet-publish-token. The name
#                is not stored in this repository (it is public); the caller supplies it.
#   -DryRun      checks all arguments and the local file, prints what would be sent with the token masked, reads no
#                vault and calls no network.
#   -CompareOnly -DownloadedPath <file>   compares -PackagePath to a local file by size and sha256 (no network).
# Exit codes: 0 ok, 2 refused (bad arguments or state), 3 failed after GitHub accepted a write (read the message:
# it names the release id; do NOT blindly re-run, a half-made release must be inspected first).
param(
  [Parameter(Mandatory = $true)][string]$VaultName,
  [string]$Tag, [string]$Commit, [string]$Title, [string]$Notes, [string]$NotesPath,
  [string]$PackagePath, [switch]$DryRun, [switch]$CompareOnly, [string]$DownloadedPath
)
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'AocFleetRelease.Lib.ps1')
if ($CompareOnly) {
  $codeFp = Invoke-AocFleetCompare -PackagePath $PackagePath -DownloadedPath $DownloadedPath
} else {
  $codeFp = Invoke-AocFleetPublish -VaultName $VaultName -Tag $Tag -Commit $Commit -Title $Title -Notes $Notes `
    -NotesPath $NotesPath -PackagePath $PackagePath -DryRun:$DryRun
}
exit ([int]$codeFp)
