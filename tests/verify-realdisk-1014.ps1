# Verifier probe (rename fleet sec check, 2026-10-14). Loads the tool's own judgment functions by AST (the main block never
# runs) and asks them about this PC's real volume root and ProgramData, and about who owns a folder made by this shell.
# Reads ACLs only; the one folder it makes is under C:\Temp with a unique name and is removed by that name.
param([string]$Tool = (Join-Path $PSScriptRoot "..\src\BayAgent\tools\Move-BayInstall.ps1"))
$ErrorActionPreference = "Stop"
$tok = $null; $err = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile((Resolve-Path $Tool).Path, [ref]$tok, [ref]$err)
$want = @('BmTrustedSids', 'BmMaskFull', 'BmMaskRename', 'BmNativeSource')
foreach ($a in $ast.EndBlock.Statements) {
  if ($a -is [System.Management.Automation.Language.AssignmentStatementAst]) {
    $n = $a.Left.Extent.Text.TrimStart('$')
    if ($want -contains $n) { . ([scriptblock]::Create($a.Extent.Text)) }
  }
}
foreach ($f in $ast.FindAll({ param($x) $x -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $false)) {
  if ($f.Name -like 'Get-Bm*' -or $f.Name -like 'Initialize-Bm*') { . ([scriptblock]::Create($f.Extent.Text)) }
}
$script:BmExtraTrusted = @()
$JournalTrustStop = ""
$elev = (New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
"elevated: $elev"
"user sid: " + [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
"--- C:\ judged as the folder a new root is made in (Rename, walk to the volume root):"
$p = @(Get-BmFolderProblems "C:\" "" "Rename" "Rename"); "problems: $($p.Count)"; $p
"--- C:\ judged Full (as a leaf that is itself used):"
$p = @(Get-BmFolderProblems "C:\" "" "Full" "Full"); "problems: $($p.Count)"; $p
"--- journal default, nearest existing, stop at ProgramData:"
$jr = Join-Path $env:ProgramData "AceOfClubs\BayMove"
"nearest existing: " + (Get-BmNearestExisting $jr)
$p = @(Get-BmJournalProblems $jr $env:ProgramData); "problems: $($p.Count)"; $p
"--- a folder and file made by THIS shell's token, judged Owner and Full:"
$d = "C:\Temp\vfy-baymove-owner-1014"
if (Test-Path -LiteralPath $d) { throw "$d already exists; not mine" }
[void][IO.Directory]::CreateDirectory($d)
[IO.File]::WriteAllText((Join-Path $d "x.ps1"), "x")
try {
  "owner (Get-Acl): " + (Get-Acl -LiteralPath $d).Owner
  $p = @(Get-BmOneFolderProblems $d "Owner"); "folder Owner problems: $($p.Count)"; $p
  $p = @(Get-BmOneFolderProblems $d "Full"); "folder Full problems: $($p.Count)"; $p
} finally {
  if ($d -eq "C:\Temp\vfy-baymove-owner-1014") { [IO.Directory]::Delete($d, $true) }
}
"removed: " + (-not (Test-Path -LiteralPath $d))
