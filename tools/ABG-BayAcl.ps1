<#
ABG-BayAcl.ps1  (functions only; dot-source it, nothing runs on load)

WHY THIS FILE EXISTS (A0.699 F-SEC, 2026-10-15). Before it, Day0 granted the kiosk account (BayKiosk) read on the bay's
code-signing private key, and a watchdog task runs as SYSTEM every minute under AllSigned. BayKiosk could sign any
script the machine's policy would run, and edit the watchdog (no tool set permissions under C:\AllBirdies, which
inherits Authenticated Users:Modify from C:\). This file holds the one definition of who may touch what:

  Key file      the code-signing private key: SYSTEM and Administrators only. Nobody else, BayKiosk least of all.
  Chain         C:\AllBirdies and BayAgent: SYSTEM and Administrators full, Users read and execute. BayKiosk cannot
                create, rename or replace anything there (so it cannot swap bootstrap\ for another folder).
  LockTree      BayAgent\bootstrap and everything in it (the watchdog SYSTEM runs, the agent host, the shells):
                same rights, inheritance cut from C:\, every file inherits only, owner Administrators.
  KioskData     BayAgent\{state,logs,control,current,releases,rollback,staging,tools}: what the agent and its updater
                write as BayKiosk. BayKiosk may create in the folder and has Modify on everything inside it, but NOT
                Delete / change-permissions on the folder itself, so it cannot replace "logs" or "control" (which the
                SYSTEM watchdog writes into) with a link.
  KioskTree     SessionDisplay: BayKiosk Modify (the browser profile, session.json, the display updater).
  Not touched   BayAgent\secrets (its own tool, ABG.SetClientSecretDpapi.ps1, sets its ACL for a legacy secret bay).

Set-* functions apply (and so repair); Test-* functions only read, and decide from the ACL Windows returns, never from
what Set-* was asked to do. Windows PowerShell 5.1. Hyphens only in comments.
#>

Set-StrictMode -Version Latest

$script:BaySid = @{
  System           = "S-1-5-18"
  Admins           = "S-1-5-32-544"
  Users            = "S-1-5-32-545"
  AuthUsers        = "S-1-5-11"
  Everyone         = "S-1-1-0"
  Interactive      = "S-1-5-4"
  Local            = "S-1-2-0"
  TrustedInstaller = "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464"
}
# Rights that let a principal change what a SYSTEM task will run: write, append, delete (also a child), write
# attributes or extended attributes, change permissions, take ownership. Numeric so a test does not share an enum.
$script:BayWriteMask = 0x2 -bor 0x4 -bor 0x10 -bor 0x40 -bor 0x100 -bor 0x10000 -bor 0x40000 -bor 0x80000
# Everything except SYNCHRONIZE: a key file must give the kiosk none of it.
$script:BayAnyMask = 0xF01FF

function Get-BaySidObject([string]$Sid) { return (New-Object System.Security.Principal.SecurityIdentifier($Sid)) }

# The account's SID, or $null when there is no such account. Get-LocalUser, not name translation, so a modeled PC works.
function Get-BayKioskSid([string]$User) {
  $u = Get-LocalUser -Name $User -ErrorAction SilentlyContinue
  if ($null -eq $u) { return $null }
  return $u.SID
}

# Everyone the kiosk's session token carries that an ACL may name.
function Get-BayKioskPrincipals($KioskSid) {
  $list = @(
    (Get-BaySidObject $script:BaySid.Everyone), (Get-BaySidObject $script:BaySid.Users), (Get-BaySidObject $script:BaySid.AuthUsers),
    (Get-BaySidObject $script:BaySid.Interactive), (Get-BaySidObject $script:BaySid.Local))
  if ($null -ne $KioskSid) { $list += $KioskSid }
  return $list
}

# ------------------------------------------------------------------ the plan

function Get-BayAclPlan([string]$Root, $KioskSid) {
  $agent = Join-Path $Root "BayAgent"
  $plan = @(
    [pscustomobject]@{ Kind = "Chain";     Path = $Root },
    [pscustomobject]@{ Kind = "Chain";     Path = $agent },
    [pscustomobject]@{ Kind = "LockTree";  Path = (Join-Path $agent "bootstrap") }
  )
  foreach ($d in @("state", "logs", "control", "current", "releases", "rollback", "staging", "tools")) {
    $plan += [pscustomobject]@{ Kind = "KioskData"; Path = (Join-Path $agent $d) }
  }
  $plan += [pscustomobject]@{ Kind = "KioskTree"; Path = (Join-Path $Root "SessionDisplay") }
  return $plan
}

# ------------------------------------------------------------------ apply

function Test-BayIsLink([string]$Path) {
  $it = Get-Item -LiteralPath $Path -Force -ErrorAction SilentlyContinue
  if ($null -eq $it) { return $false }
  return (($it.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0)
}

function New-BayRule($Sid, [int]$Rights, [string]$Inherit, [string]$Prop) {
  return (New-Object System.Security.AccessControl.FileSystemAccessRule($Sid, [System.Security.AccessControl.FileSystemRights]$Rights,
      [System.Security.AccessControl.InheritanceFlags]$Inherit, [System.Security.AccessControl.PropagationFlags]$Prop, [System.Security.AccessControl.AccessControlType]::Allow))
}

# Replaces the DACL of one directory or file with exactly $Rules. $Protect cuts inheritance (inherited ACEs are
# dropped, not copied). Refuses a link: Set-Acl through a junction would change the target.
function Set-BayDacl([string]$Path, $Rules, [bool]$Protect) {
  if (Test-BayIsLink $Path) { throw "ACL: '$Path' is a link; refusing to set permissions through it." }
  $item = Get-Item -LiteralPath $Path -Force
  $acl = $item.GetAccessControl([System.Security.AccessControl.AccessControlSections]::Access)
  $acl.SetAccessRuleProtection($Protect, $false)
  foreach ($r in @($acl.GetAccessRules($true, $false, [System.Security.Principal.SecurityIdentifier]))) { [void]$acl.RemoveAccessRuleSpecific($r) }
  foreach ($r in @($Rules)) { $acl.AddAccessRule($r) }
  $item.SetAccessControl($acl)
}

function Get-BayLockRules {
  $full = [int][System.Security.AccessControl.FileSystemRights]::FullControl
  $rx = [int][System.Security.AccessControl.FileSystemRights]::ReadAndExecute
  return @(
    (New-BayRule (Get-BaySidObject $script:BaySid.System) $full "ContainerInherit, ObjectInherit" "None"),
    (New-BayRule (Get-BaySidObject $script:BaySid.Admins) $full "ContainerInherit, ObjectInherit" "None"),
    (New-BayRule (Get-BaySidObject $script:BaySid.Users) $rx "ContainerInherit, ObjectInherit" "None"))
}

function Get-BayKioskDataRules($KioskSid) {
  $R = [System.Security.AccessControl.FileSystemRights]
  # On the folder itself: read, create files and folders, write attributes and extended attributes, delete CHILDREN.
  # No Delete, no ChangePermissions, no TakeOwnership: the folder cannot be removed or re-pointed by BayKiosk.
  $self = [int]($R::ReadAndExecute -bor $R::CreateFiles -bor $R::CreateDirectories -bor $R::WriteExtendedAttributes -bor $R::WriteAttributes -bor $R::DeleteSubdirectoriesAndFiles)
  return @(
    (New-BayRule $KioskSid $self "None" "None"),
    (New-BayRule $KioskSid ([int]$R::Modify) "ContainerInherit, ObjectInherit" "InheritOnly"))
}

# Administrators as owner, so no earlier owner (BayKiosk made a file here once) keeps the right to rewrite its DACL.
# icacls enables the privilege a plain Set-Acl owner change does not. A test replaces this function.
function Set-BayLockTreeOwner([string]$Path) {
  $global:LASTEXITCODE = 0
  icacls $Path /setowner ("*" + $script:BaySid.Admins) /T /C /L /Q | Out-Null
  if ($LASTEXITCODE -ne 0) { throw "ACL: could not set the owner of '$Path' to Administrators (icacls exit $LASTEXITCODE)." }
}

# Administrators as owner of ONE folder (not its contents), set BEFORE the folder's permissions are written: an owner keeps the
# right to rewrite its own DACL, so a chain folder (AllBirdies, BayAgent) owned by anyone else is not locked. A test replaces this.
function Set-BayFolderOwner([string]$Path) {
  $global:LASTEXITCODE = 0
  icacls $Path /setowner ("*" + $script:BaySid.Admins) /C /L /Q | Out-Null
  if ($LASTEXITCODE -ne 0) { throw "ACL: could not set the owner of '$Path' to Administrators (icacls exit $LASTEXITCODE)." }
}

# Read back what Windows holds for a chain folder after its owner and permissions were written. icacls /C exits 0 when it
# changed nothing, so the exit code proves nothing: the folder must not be a link, must be owned by Administrators (by SID), and
# must have inheritance cut. Anything else stops the run. A test that cannot be elevated names its own account in
# $script:BayReadBackExtraOwners.
$script:BayReadBackExtraOwners = @()
function Assert-BayChainFolder([string]$Path) {
  if (Test-BayIsLink $Path) { throw "ACL: '$Path' is a link; the lock cannot be trusted." }
  $acl = (Get-Item -LiteralPath $Path -Force).GetAccessControl([System.Security.AccessControl.AccessControlSections]"Owner, Access")
  $owner = $acl.GetOwner([System.Security.Principal.SecurityIdentifier])
  $ok = @($script:BaySid.Admins) + @($script:BayReadBackExtraOwners)
  if ($null -eq $owner -or $ok -notcontains $owner.Value) { throw ("ACL: '$Path' is owned by " + $(if ($null -eq $owner) { "an unknown account" } else { $owner.Value }) + ", not Administrators, after the owner change.") }
  if (-not $acl.AreAccessRulesProtected) { throw "ACL: '$Path' still inherits permissions after they were written." }
}

# Every file and folder under a locked folder inherits only: explicit ACEs removed, inheritance on. A link inside is
# a hard stop (it was planted while the folder was writable, or the tree is not what the installer made).
function Reset-BayLockTreeChildren([string]$Path) {
  $links = @()
  $stack = New-Object System.Collections.Generic.Stack[string]
  $stack.Push($Path)
  while ($stack.Count -gt 0) {
    $dir = $stack.Pop()
    foreach ($child in @((New-Object IO.DirectoryInfo($dir)).GetFileSystemInfos())) {
      if (($child.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { $links += $child.FullName; continue }
      Set-BayDacl -Path $child.FullName -Rules @() -Protect $false
      if (($child.Attributes -band [IO.FileAttributes]::Directory) -ne 0) { $stack.Push($child.FullName) }
    }
  }
  if ($links.Count -gt 0) { throw ("ACL: a link inside a folder SYSTEM runs code from: " + ($links -join "; ") + ". Remove it by hand (as Administrator) and run setup again.") }
}

function Set-BayPlanEntry($Entry, $KioskSid) {
  $p = [string]$Entry.Path
  switch ([string]$Entry.Kind) {
    "Chain" {
      if (-not (Test-Path -LiteralPath $p)) { New-Item -ItemType Directory -Path $p -Force | Out-Null }
      Set-BayFolderOwner -Path $p
      Set-BayDacl -Path $p -Rules (Get-BayLockRules) -Protect $true
      Assert-BayChainFolder -Path $p
    }
    "LockTree" {
      if (-not (Test-Path -LiteralPath $p)) { New-Item -ItemType Directory -Path $p -Force | Out-Null }
      Set-BayDacl -Path $p -Rules (Get-BayLockRules) -Protect $true
      Set-BayLockTreeOwner -Path $p
      Reset-BayLockTreeChildren -Path $p
    }
    "KioskData" {
      if (-not (Test-Path -LiteralPath $p)) { New-Item -ItemType Directory -Path $p -Force | Out-Null }
      $rules = @()
      if ($null -ne $KioskSid) { $rules = Get-BayKioskDataRules $KioskSid }
      Set-BayDacl -Path $p -Rules $rules -Protect $false
    }
    "KioskTree" {
      if (-not (Test-Path -LiteralPath $p)) { New-Item -ItemType Directory -Path $p -Force | Out-Null }
      $rules = @()
      if ($null -ne $KioskSid) { $rules = @(New-BayRule $KioskSid ([int][System.Security.AccessControl.FileSystemRights]::Modify) "ContainerInherit, ObjectInherit" "None") }
      Set-BayDacl -Path $p -Rules $rules -Protect $false
    }
    default { throw "ACL: unknown plan kind '$($Entry.Kind)'" }
  }
}

function Set-BayAcls([string]$Root, $KioskSid) {
  # Every folder exists BEFORE any is locked: once the chain is locked, the account running this may not create in it.
  foreach ($e in @(Get-BayAclPlan -Root $Root -KioskSid $KioskSid)) { if (-not (Test-Path -LiteralPath $e.Path)) { New-Item -ItemType Directory -Path $e.Path -Force | Out-Null } }
  foreach ($e in @(Get-BayAclPlan -Root $Root -KioskSid $KioskSid)) { Set-BayPlanEntry -Entry $e -KioskSid $KioskSid }
}

# The key file: SYSTEM and Administrators only, inheritance cut. Removes a BayKiosk grant from an earlier setup.
function Set-BayKeyFileAcl([string]$KeyPath) {
  $full = [int][System.Security.AccessControl.FileSystemRights]::FullControl
  Set-BayDacl -Path $KeyPath -Rules @(
    (New-BayRule (Get-BaySidObject $script:BaySid.System) $full "None" "None"),
    (New-BayRule (Get-BaySidObject $script:BaySid.Admins) $full "None" "None")) -Protect $true
}

function Get-BayKeyContainerName([string]$Thumbprint) {
  $out = (certutil -store My $Thumbprint) 2>&1 | Out-String
  $m = [regex]::Match($out, "Unique container name:\s*(.+)")
  if (-not $m.Success) { return "" }
  return $m.Groups[1].Value.Trim()
}

# The key files on disk for one container name (CNG, then the older CAPI machine folder). Empty when none.
function Get-BayKeyFilePaths([string]$UniqueName) {
  if ([string]::IsNullOrWhiteSpace($UniqueName)) { return @() }
  $found = @()
  foreach ($rel in @("Microsoft\Crypto\Keys", "Microsoft\Crypto\RSA\MachineKeys")) {
    $p = Join-Path (Join-Path $env:ProgramData $rel) $UniqueName
    if (Test-Path -LiteralPath $p) { $found += $p }
  }
  return $found
}

# Every ABG code-signing certificate in the machine store (an earlier setup may have left several), as thumbprints.
function Get-BayCodeSigningThumbprints {
  return @(Get-ChildItem Cert:\LocalMachine\My -ErrorAction SilentlyContinue | Where-Object {
      $_.EnhancedKeyUsageList.FriendlyName -contains "Code Signing" -and $_.HasPrivateKey -and $_.Subject -like "*ABG*"
    } | ForEach-Object { [string]$_.Thumbprint })
}

# Repairs the key file of EVERY ABG code-signing certificate. Returns the paths it locked.
function Set-BayAllKeyFileAcls {
  $done = @()
  foreach ($tp in @(Get-BayCodeSigningThumbprints)) {
    foreach ($kp in @(Get-BayKeyFilePaths (Get-BayKeyContainerName $tp))) { Set-BayKeyFileAcl -KeyPath $kp; $done += $kp }
  }
  return $done
}

# ------------------------------------------------------------------ read and judge

# The access mask $Sids hold together on one object, from the rules Windows returns. $Target: "self" (rules that apply to
# this object), "childFile" (what a file created inside inherits) or "childDir". Deny before allow is the order Windows
# keeps; an owner holds ReadControl and WriteDac implicitly.
function Get-BayEffectiveMask($Item, $Sids, [string]$Target) {
  $acl = $Item.GetAccessControl([System.Security.AccessControl.AccessControlSections]::Access -bor [System.Security.AccessControl.AccessControlSections]::Owner)
  $set = @($Sids | Where-Object { $null -ne $_ } | ForEach-Object { $_.Value })
  $granted = 0; $denied = 0
  foreach ($r in @($acl.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier]))) {
    if ($set -notcontains $r.IdentityReference.Value) { continue }
    $io = (($r.PropagationFlags -band [System.Security.AccessControl.PropagationFlags]::InheritOnly) -ne 0)
    $oi = (($r.InheritanceFlags -band [System.Security.AccessControl.InheritanceFlags]::ObjectInherit) -ne 0)
    $ci = (($r.InheritanceFlags -band [System.Security.AccessControl.InheritanceFlags]::ContainerInherit) -ne 0)
    $applies = $false
    switch ($Target) {
      "self"      { $applies = (-not $io) }
      "childFile" { $applies = $oi }
      "childDir"  { $applies = $ci }
    }
    if (-not $applies) { continue }
    $bits = [int]$r.FileSystemRights
    if ($bits -lt 0) { $bits = $bits -band 0x1F01FF }
    if ($r.AccessControlType -eq [System.Security.AccessControl.AccessControlType]::Deny) { $denied = $denied -bor ($bits -band (-bnot $granted)) }
    else { $granted = $granted -bor ($bits -band (-bnot $denied)) }
  }
  $owner = $acl.GetOwner([System.Security.Principal.SecurityIdentifier])
  if ($Target -eq "self" -and $null -ne $owner -and $set -contains $owner.Value) { $granted = $granted -bor 0x20000 -bor 0x40000 }
  return $granted
}

function Get-BayRightsNames([int]$Mask) {
  $names = @()
  foreach ($pair in @(@(0x2, "write/create-file"), @(0x4, "append/create-folder"), @(0x10, "write-attributes-ex"), @(0x40, "delete-child"), @(0x100, "write-attributes"),
      @(0x10000, "delete"), @(0x40000, "change-permissions"), @(0x80000, "take-ownership"))) {
    if (($Mask -band [int]$pair[0]) -ne 0) { $names += [string]$pair[1] }
  }
  return ($names -join ", ")
}

# Problems for one path that SYSTEM runs or loads: the kiosk's token holds no write-class right, and the owner is one of
# the trusted accounts. $ExtraOwners lets a test that cannot be elevated name its own account.
function Get-BayLockedPathProblems([string]$Path, $KioskSid, [string[]]$ExtraOwners = @()) {
  $problems = @()
  if (Test-BayIsLink $Path) { return @("$Path is a link") }
  $item = Get-Item -LiteralPath $Path -Force
  $mask = Get-BayEffectiveMask $item (Get-BayKioskPrincipals $KioskSid) "self"
  if (($mask -band $script:BayWriteMask) -ne 0) { $problems += ("{0}: BayKiosk or Users can {1}" -f $Path, (Get-BayRightsNames ($mask -band $script:BayWriteMask))) }
  $owner = $item.GetAccessControl([System.Security.AccessControl.AccessControlSections]::Owner).GetOwner([System.Security.Principal.SecurityIdentifier])
  $okOwners = @($script:BaySid.System, $script:BaySid.Admins, $script:BaySid.TrustedInstaller) + @($ExtraOwners)
  if ($null -eq $owner -or $okOwners -notcontains $owner.Value) { $problems += ("{0}: owned by {1} (must be Administrators or SYSTEM)" -f $Path, $(if ($null -eq $owner) { "unknown" } else { $owner.Value })) }
  return $problems
}

function Get-BayLockTreeProblems([string]$Path, $KioskSid, [string[]]$ExtraOwners = @()) {
  if (-not (Test-Path -LiteralPath $Path)) { return @("$Path is missing") }
  $problems = @(Get-BayLockedPathProblems $Path $KioskSid $ExtraOwners)
  $stack = New-Object System.Collections.Generic.Stack[string]
  $stack.Push($Path)
  while ($stack.Count -gt 0) {
    $dir = $stack.Pop()
    foreach ($c in @((New-Object IO.DirectoryInfo($dir)).GetFileSystemInfos())) {
      if (($c.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { $problems += ("{0} is a link" -f $c.FullName); continue }
      $problems += @(Get-BayLockedPathProblems $c.FullName $KioskSid $ExtraOwners)
      if (($c.Attributes -band [IO.FileAttributes]::Directory) -ne 0) { $stack.Push($c.FullName) }
    }
  }
  return $problems
}

# The key file: nothing for the kiosk's token, and nobody but SYSTEM and Administrators holds an allow.
function Get-BayKeyFileProblems([string]$Path, $KioskSid) {
  $problems = @()
  $item = Get-Item -LiteralPath $Path -Force
  $mask = Get-BayEffectiveMask $item (Get-BayKioskPrincipals $KioskSid) "self"
  if (($mask -band $script:BayAnyMask) -ne 0) { $problems += ("{0}: BayKiosk or Users hold rights on the signing key ({1})" -f $Path, ("0x{0:X}" -f $mask)) }
  $acl = $item.GetAccessControl([System.Security.AccessControl.AccessControlSections]::Access)
  foreach ($r in @($acl.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier]))) {
    if ($r.AccessControlType -ne [System.Security.AccessControl.AccessControlType]::Allow) { continue }
    if (@($script:BaySid.System, $script:BaySid.Admins) -notcontains $r.IdentityReference.Value) { $problems += ("{0}: also granted to {1}" -f $Path, $r.IdentityReference.Value) }
  }
  return $problems
}

# What the agent needs as BayKiosk, read back from the ACL: create and change inside the folder, and NOT delete,
# re-permission or take over the folder itself.
function Get-BayKioskDataProblems([string]$Path, $KioskSid) {
  if (-not (Test-Path -LiteralPath $Path)) { return @("$Path is missing") }
  if (Test-BayIsLink $Path) { return @("$Path is a link") }
  $item = Get-Item -LiteralPath $Path -Force
  $kiosk = @($KioskSid) + @((Get-BaySidObject $script:BaySid.Everyone), (Get-BaySidObject $script:BaySid.Users), (Get-BaySidObject $script:BaySid.AuthUsers), (Get-BaySidObject $script:BaySid.Interactive))
  $problems = @()
  $self = Get-BayEffectiveMask $item $kiosk "self"
  $needSelf = 0x1 -bor 0x2 -bor 0x4 -bor 0x20 -bor 0x80 -bor 0x100 -bor 0x40
  if (($self -band $needSelf) -ne $needSelf) { $problems += ("{0}: BayKiosk cannot read, create files and folders and clear it (has 0x{1:X}, needs 0x{2:X})" -f $Path, $self, $needSelf) }
  if (($self -band (0x10000 -bor 0x40000 -bor 0x80000)) -ne 0) { $problems += ("{0}: BayKiosk can delete, re-permission or take over the folder itself" -f $Path) }
  $needChild = 0x1 -bor 0x2 -bor 0x4 -bor 0x10 -bor 0x20 -bor 0x80 -bor 0x100 -bor 0x10000
  foreach ($t in @("childFile", "childDir")) {
    $m = Get-BayEffectiveMask $item $kiosk $t
    if (($m -band $needChild) -ne $needChild) { $problems += ("{0}: what BayKiosk creates inside is not fully its own ({1}: has 0x{2:X}, needs 0x{3:X})" -f $Path, $t, $m, $needChild) }
  }
  return $problems
}

function Get-BayKioskTreeProblems([string]$Path, $KioskSid) {
  if (-not (Test-Path -LiteralPath $Path)) { return @("$Path is missing") }
  $item = Get-Item -LiteralPath $Path -Force
  $kiosk = @($KioskSid) + @((Get-BaySidObject $script:BaySid.Everyone), (Get-BaySidObject $script:BaySid.Users), (Get-BaySidObject $script:BaySid.AuthUsers))
  $need = 0x1 -bor 0x2 -bor 0x4 -bor 0x10 -bor 0x20 -bor 0x80 -bor 0x100 -bor 0x10000
  $problems = @()
  foreach ($t in @("self", "childFile", "childDir")) {
    $m = Get-BayEffectiveMask $item $kiosk $t
    if (($m -band $need) -ne $need) { $problems += ("{0}: BayKiosk lacks modify rights ({1}: 0x{2:X})" -f $Path, $t, $m) }
  }
  return $problems
}

# The scheduled tasks as plain facts: one item per action, @{ Name; UserId; Execute; Arguments }. A property Task Scheduler
# did not return is an empty string, so a task read badly shows up as a task that does not match, not as nothing.
function Get-BayTaskFacts {
  $out = @()
  foreach ($t in @(Get-ScheduledTask -ErrorAction SilentlyContinue)) {
    $uid = ""; $actions = @()
    try { $uid = [string]$t.Principal.UserId } catch { }
    try { $actions = @($t.Actions) } catch { }
    if ($actions.Count -eq 0) { $actions = @($null) }
    foreach ($a in $actions) {
      $exe = ""; $arg = ""
      if ($null -ne $a) { try { $exe = [string]$a.Execute } catch { }; try { $arg = [string]$a.Arguments } catch { } }
      $out += [pscustomobject]@{ Name = [string]$t.TaskName; UserId = $uid; Execute = $exe; Arguments = $arg }
    }
  }
  return $out
}

# SYSTEM scheduled tasks: each task is @{ Name; UserId; Execute; Arguments }. A SYSTEM task whose action is an ABG one,
# or names a path under $Root, must run a system program and name only files inside a locked folder.
function Get-BaySystemTaskProblems($Tasks, [string]$Root, [string]$LockedDir, [string[]]$RequiredTaskNames = @()) {
  $problems = @()
  # A task that should exist and does not is a failure, never a pass: nothing found must not read as nothing wrong.
  foreach ($need in @($RequiredTaskNames)) {
    $hit = @(@($Tasks) | Where-Object { ([string]$_.Name).TrimStart("\") -eq $need -and (@("SYSTEM", "NT AUTHORITY\SYSTEM", $script:BaySid.System) -contains ([string]$_.UserId).Trim()) })
    if ($hit.Count -eq 0) { $problems += ("task '{0}' was not found running as SYSTEM" -f $need) }
  }
  $rootN = $Root.TrimEnd('\').ToLowerInvariant()
  $lockN = $LockedDir.TrimEnd('\').ToLowerInvariant() + "\"
  foreach ($t in @($Tasks)) {
    $uid = ([string]$t.UserId).Trim()
    if (@("SYSTEM", "NT AUTHORITY\SYSTEM", $script:BaySid.System) -notcontains $uid) { continue }
    $text = ([string]$t.Execute + " " + [string]$t.Arguments)
    if ($text.ToLowerInvariant().Contains($rootN) -eq $false -and ([string]$t.Name) -notlike "*ABG*") { continue }
    $exe = ([string]$t.Execute).Trim('"')
    $sysDir = [Environment]::GetFolderPath("System")
    if (-not $exe.StartsWith($sysDir, [StringComparison]::OrdinalIgnoreCase) -and -not $exe.StartsWith('%SystemRoot%', [StringComparison]::OrdinalIgnoreCase) -and -not $exe.StartsWith('%windir%', [StringComparison]::OrdinalIgnoreCase)) {
      $problems += ("task '{0}' runs '{1}' by a name or path that is not under System32" -f $t.Name, $exe)
    }
    $paths = @([regex]::Matches([string]$t.Arguments, '[A-Za-z]:\\[^"\r\n]*?\.(?:ps1|psm1|cmd|bat|exe|dll|vbs|js)', "IgnoreCase") | ForEach-Object { $_.Value })
    if ($exe.ToLowerInvariant().StartsWith($rootN)) { $problems += ("task '{0}' runs a program from {1}" -f $t.Name, $Root) }
    if ($paths.Count -eq 0 -and ([string]$t.Arguments).ToLowerInvariant().Contains($rootN)) { $problems += ("task '{0}' names a path under {1} that could not be read: {2}" -f $t.Name, $Root, $text) }
    foreach ($p in $paths) {
      if (-not $p.ToLowerInvariant().StartsWith($lockN)) { $problems += ("task '{0}' runs {1}, which is outside the locked folder {2}" -f $t.Name, $p, $LockedDir) }
    }
  }
  return $problems
}

function New-BayRow([string]$Check, $Problems) {
  $p = @($Problems | Where-Object { $_ })
  return [pscustomobject]@{ Check = $Check; Result = $(if ($p.Count -eq 0) { "PASS" } else { "FAIL (" + ($p -join " | ") + ")" }) }
}

# One report for the whole thing: rows of Check / Result (PASS or "FAIL (...)").
function Get-BayAclReport([string]$Root, $KioskSid, $Tasks, [string[]]$ExtraOwners = @(), [string[]]$RequiredTaskNames = @()) {
  $rows = @()
  $keyProblems = @(); $keysSeen = 0
  foreach ($tp in @(Get-BayCodeSigningThumbprints)) {
    foreach ($kp in @(Get-BayKeyFilePaths (Get-BayKeyContainerName $tp))) { $keysSeen++; $keyProblems += @(Get-BayKeyFileProblems $kp $KioskSid) }
  }
  if ($keysSeen -eq 0) { $keyProblems += "no key file found for the code-signing certificate" }
  $rows += New-BayRow "Code-signing key: SYSTEM and Administrators only" $keyProblems
  $agent = Join-Path $Root "BayAgent"
  $chain = @(); foreach ($d in @($Root, $agent)) { $chain += @(Get-BayLockedPathProblems $d $KioskSid $ExtraOwners) }
  $rows += New-BayRow "Folders above the scripts: BayKiosk cannot write" $chain
  $boot = Join-Path $agent "bootstrap"
  $rows += New-BayRow "SYSTEM-run folder (bootstrap): BayKiosk and Users cannot write" (Get-BayLockTreeProblems $boot $KioskSid $ExtraOwners)
  $rows += New-BayRow "SYSTEM tasks run only files from bootstrap" (Get-BaySystemTaskProblems $Tasks $Root $boot $RequiredTaskNames)
  $data = @()
  if ($null -eq $KioskSid) { $data += "the BayKiosk account does not exist" }
  else {
    foreach ($e in @(Get-BayAclPlan -Root $Root -KioskSid $KioskSid)) {
      if ($e.Kind -eq "KioskData") { $data += @(Get-BayKioskDataProblems $e.Path $KioskSid) }
      if ($e.Kind -eq "KioskTree") { $data += @(Get-BayKioskTreeProblems $e.Path $KioskSid) }
    }
  }
  $rows += New-BayRow "Agent data folders: BayKiosk keeps the access it needs" $data
  return $rows
}
