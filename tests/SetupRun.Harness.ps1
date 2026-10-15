<#
SetupRun.Harness.ps1  (not a suite; BayAgent.SetupRun.Tests.ps1 starts it in its own Windows PowerShell 5.1 process)

Runs the REAL text of Setup-BayPC.ps1 and ABG-Day0-Setup.ps1, top to bottom, on a MODELED blank PC. Every command
that touches the machine is replaced by a recorder: a function of the same name (a function outranks a cmdlet and a
program). Nothing is written outside -Root: no registry, no account, no certificate, no task, no policy, no download.

Taken from the independent verifier's Invoke-BlankPcRehearsal.ps1 (fleet swap-prep attack, 2026-10-11), which found
that a suite lifting functions out of the script could not fail on what the script does. Changes from it: it is
driven by a plan file, keeps the modeled machine between the runs of one plan (so a second run meets what the first
left), captures everything each run prints, and writes one result file a suite can assert on.

What it can show: where each run stops, what it wrote before that, what it printed, and where a typed password goes.
What it cannot show: what Windows itself does. Those answers are modeled, from measurements on Windows 11 Pro
(26100/26300) recorded in the verifier's probes: a fresh PC has no HKCU Shell, no DisableLockWorkstation, no
DisableTaskMgr, no AutoAdminLogon; its machine script policy is Undefined; Remote Desktop is denied (1); USBSTOR
Start is 3; and Set-ExecutionPolicy -Scope LocalMachine, in a process started with -ExecutionPolicy Bypass, WRITES
the value and then raises a terminating error.

The changes made to script text: Test-IsAdmin returns true (the harness is never elevated), and the served copy of
ABG-BayAcl.ps1 accepts the harness's own account as an owner and gives it full control of the locked folders (it cannot be
elevated, so it cannot re-own a folder to Administrators, and it stands in for the administrator who runs setup; the real
icacls /setowner call is recorded only). Everything else about permissions is REAL: the scratch
folders under -Root get real NTFS ACLs from the real helper, and the result carries them back as raw entries.
A census runs first, default deny: a command in either script that is neither recorded here nor on the read-only
list stops everything before a line of the script runs (so a write through a tool nobody modeled cannot slip by).

Hyphens only in comments. Windows PowerShell 5.1.
#>
param(
  [Parameter(Mandatory = $true)][string]$SetupScript,
  [Parameter(Mandatory = $true)][string]$Day0Script,
  [Parameter(Mandatory = $true)][string]$RepoRoot,
  [Parameter(Mandatory = $true)][string]$Root,
  [Parameter(Mandatory = $true)][string]$PlanFile,
  [Parameter(Mandatory = $true)][string]$ResultFile
)
$ErrorActionPreference = 'Stop'
$SrhMarker = 'SRHMARKPW' + [guid]::NewGuid().ToString('N').Substring(0, 12)

if (-not (Microsoft.PowerShell.Management\Test-Path -LiteralPath $Root)) { Microsoft.PowerShell.Management\New-Item -ItemType Directory -Force -Path $Root | Out-Null }
$Root = (Microsoft.PowerShell.Management\Get-Item -LiteralPath $Root).FullName.TrimEnd('\')

$global:Srh = @{
  Root = $Root; RepoRoot = $RepoRoot; Marker = $SrhMarker; Day0Source = $Day0Script
  Reg = @{}; RegKeys = @{}; Users = @{}; Certs = New-Object System.Collections.ArrayList; Tasks = @{}
  KioskSid = 'S-1-5-21-1111111111-2222222222-3333333333-1001'
  Log = New-Object System.Collections.ArrayList
  Policy = 'Undefined'; PolicyThrows = $true; PolicyTakes = $true
  FailDownloadMatch = ''; TimestampOk = $true; RebootAnswer = 'n'; RegStuck = @()
  TamperDownload = ''; MeSid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
  OwnerOk = @([Security.Principal.WindowsIdentity]::GetCurrent().User.Value); SwapOnIcacls = $false; Swapped = $false
}
function global:SrhRec([string]$m) { [void]$global:Srh.Log.Add($m) }
function global:SrhAssertScratch([string]$p) {
  $full = [IO.Path]::GetFullPath($p)
  if (-not $full.StartsWith($global:Srh.Root, [StringComparison]::OrdinalIgnoreCase)) { throw "HARNESS: refused a write outside the scratch root: $full" }
}
function global:SrhSeedBlankPc {
  $a = $global:Srh
  $a.Reg = @{}; $a.RegKeys = @{}; $a.Users = @{}; $a.Certs = New-Object System.Collections.ArrayList; $a.Tasks = @{}; $a.Policy = 'Undefined'
  foreach ($k in @(
      'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon', 'HKCU:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon',
      'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System', 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer',
      'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server', 'HKLM:\SYSTEM\CurrentControlSet\Services\USBSTOR')) { $a.RegKeys[$k.ToLower()] = $true }
  $a.Reg['hklm:\software\microsoft\windows nt\currentversion\winlogon|shell'] = 'explorer.exe'
  $a.Reg['hklm:\system\currentcontrolset\control\terminal server|fdenytsconnections'] = 1
  $a.Reg['hklm:\system\currentcontrolset\services\usbstor|start'] = 3
}

# ------------------------------------------------------------------ recorders
function global:Test-Path {
  [CmdletBinding()] param([Parameter(Position = 0)][string]$Path, [string]$LiteralPath)
  $p = $(if ($LiteralPath) { $LiteralPath } else { $Path })
  if ($p -match '^(HKLM|HKCU):') { return [bool]$global:Srh.RegKeys.ContainsKey($p.ToLower()) }
  if ($p -like ($env:ProgramData + '\Microsoft\Crypto\Keys\*')) { return $true }
  # The kiosk account's legacy Startup shortcut: not there on a blank PC. (Only this path under C:\Users is modeled;
  # the scratch root itself may sit under C:\Users when a suite uses the temp folder.)
  if ($p -like 'C:\Users\*\Start Menu\Programs\Startup\*') { return $false }
  return (Microsoft.PowerShell.Management\Test-Path -LiteralPath $p)
}
function global:Get-ItemProperty {
  [CmdletBinding()] param([Parameter(Position = 0)][string]$Path, [string]$Name)
  $key = $Path.ToLower() + '|' + $Name.ToLower()
  if ($global:Srh.Reg.ContainsKey($key)) {
    $o = New-Object psobject; Add-Member -InputObject $o -NotePropertyName $Name -NotePropertyValue $global:Srh.Reg[$key]; return $o
  }
  Write-Error "Property $Name does not exist at path $Path."
}
function global:Set-ItemProperty {
  [CmdletBinding()] param([string]$Path, [string]$Name, $Value, [string]$Type)
  if (-not $global:Srh.RegKeys.ContainsKey($Path.ToLower())) { Write-Error "Cannot find path '$Path' because it does not exist."; return }
  # A value named in the model's "regStuck" list is written and does not change (a policy or another tool holds it).
  if (@($global:Srh.RegStuck) -notcontains ($Path.ToLower() + '|' + $Name.ToLower())) { $global:Srh.Reg[$Path.ToLower() + '|' + $Name.ToLower()] = $Value }
  $shown = $(if ("$Value" -eq $global:Srh.Marker) { '<THE TYPED PASSWORD, IN THE CLEAR>' } else { "$Value" })
  SrhRec ("REG SET  {0} :: {1} = {2}" -f $Path, $Name, $shown)
}
function global:New-Item {
  [CmdletBinding()] param([string]$Path, [string]$ItemType, [switch]$Force)
  if ($Path -match '^(HKLM|HKCU):') { $global:Srh.RegKeys[$Path.ToLower()] = $true; SrhRec "REG KEY  $Path"; return [pscustomobject]@{ Name = $Path } }
  SrhAssertScratch $Path
  Microsoft.PowerShell.Management\New-Item -Path $Path -ItemType $ItemType -Force
}
function global:Set-Content {
  [CmdletBinding()] param([Parameter(ValueFromPipeline = $true)]$Value, [string]$LiteralPath, [string]$Path, [string]$Encoding = 'UTF8')
  begin { $buf = @() } process { $buf += $Value }
  end { $p = $(if ($LiteralPath) { $LiteralPath } else { $Path }); SrhAssertScratch $p; $buf | Microsoft.PowerShell.Management\Set-Content -LiteralPath $p -Encoding $Encoding; SrhRec ("FILE     " + $p.Replace($global:Srh.Root, '<root>')) }
}
function global:Remove-Item { [CmdletBinding()] param([Parameter(Position = 0)][string]$Path, [switch]$Force) SrhRec "REMOVE   $Path (recorded only)" }
function global:Invoke-WebRequest {
  [CmdletBinding()] param([string]$Uri, [string]$OutFile, [switch]$UseBasicParsing, [int]$MaximumRedirection)
  if ($global:Srh.FailDownloadMatch -and $Uri -match $global:Srh.FailDownloadMatch) { SrhRec "DOWNLOAD $Uri -> 404 (injected)"; throw "The remote server returned an error: (404) Not Found." }
  $m = [regex]::Match($Uri, '^https://raw\.githubusercontent\.com/millwright-works/abg-fleet-updates/main/(.+)$')
  if (-not $m.Success) { SrhRec "DOWNLOAD $Uri -> REFUSED (not an address of this repository's main branch under its current owner)"; throw "HARNESS: a download address this harness does not serve: $Uri" }
  $rel = $m.Groups[1].Value -replace '/', '\'
  $src = Join-Path $global:Srh.RepoRoot $rel
  if ($rel -eq 'tools\ABG-Day0-Setup.ps1') { $src = $global:Srh.Day0Source }
  if ($rel -eq 'tools\ABG-BayAcl.ps1') { $src = $global:Srh.AclHelperServed }
  if (-not (Microsoft.PowerShell.Management\Test-Path -LiteralPath $src)) { SrhRec "DOWNLOAD $Uri -> 404 (not in the repository tree)"; throw "The remote server returned an error: (404) Not Found." }
  SrhAssertScratch $OutFile
  # The model's "tamperDownload": the file of that name is served with one line added that leaves a marker file when it
  # runs, so a suite can tell whether a file that is not the pinned one was run.
  $leaf = Split-Path -Leaf $rel
  if ($global:Srh.TamperDownload -and $leaf -eq $global:Srh.TamperDownload) { $src = SrhTamperedCopy $src $leaf }
  # Whether anyone but SYSTEM, Administrators and the stand-in administrator could write the folder at this moment.
  SrhRec ("DLFOLDER $Uri " + (SrhFolderLockVerdict $OutFile))
  Microsoft.PowerShell.Management\Copy-Item -LiteralPath $src -Destination $OutFile -Force
  SrhRec "DOWNLOAD $Uri"
}
function global:SrhTamperedCopy([string]$src, [string]$leaf) {
  $text = [IO.File]::ReadAllText($src)
  $anchor = 'Set-StrictMode -Version Latest'
  $at = $text.IndexOf($anchor)
  if ($at -lt 0) { throw "HARNESS: no place to add the tamper marker in $leaf" }
  $marker = Join-Path $global:Srh.Root ('TAMPERED-RAN-' + $leaf + '.txt')
  $line = "[IO.File]::WriteAllText('" + $marker + "', 'ran')`r`n"
  $out = Join-Path $global:Srh.Root ('tampered-' + $leaf)
  [IO.File]::WriteAllText($out, $text.Substring(0, $at) + $line + $text.Substring($at), (New-Object Text.UTF8Encoding($false)))
  return $out
}
# "locked=yes" when, at the moment of the download: AllBirdies, BayAgent and bootstrap (those on the path) have inheritance
# cut, and no folder from the destination's up to AllBirdies, nor a file already at the destination, gives a write-class
# right on itself to anyone but SYSTEM, Administrators or this harness's own account (the stand-in administrator). Read
# from the ACL Windows returns, with the masks written out here; nothing from the scripts under test.
function global:SrhFolderLockVerdict([string]$outFile) {
  $allRoot = (Join-Path $global:Srh.Root 'AllBirdies').TrimEnd('\')
  $mustProtect = @($allRoot, (Join-Path $allRoot 'BayAgent'), (Join-Path $allRoot 'BayAgent\bootstrap')) | ForEach-Object { $_.ToLowerInvariant() }
  $okSids = @('S-1-5-18', 'S-1-5-32-544', $global:Srh.MeSid)
  $writeBits = 0x2 -bor 0x4 -bor 0x10 -bor 0x40 -bor 0x100 -bor 0x10000 -bor 0x40000 -bor 0x80000
  $why = @()
  $items = @()
  if (Microsoft.PowerShell.Management\Test-Path -LiteralPath $outFile) { $items += $outFile }
  $d = [IO.Path]::GetDirectoryName([IO.Path]::GetFullPath($outFile))
  while ($d -and $d.Length -ge $allRoot.Length) { $items += $d; if ($d.ToLowerInvariant() -eq $allRoot.ToLowerInvariant()) { break }; $d = [IO.Path]::GetDirectoryName($d) }
  foreach ($p in $items) {
    if (-not (Microsoft.PowerShell.Management\Test-Path -LiteralPath $p)) { $why += "$p missing"; continue }
    $acl = (Microsoft.PowerShell.Management\Get-Item -LiteralPath $p -Force).GetAccessControl()
    if ($mustProtect -contains $p.ToLowerInvariant() -and -not $acl.AreAccessRulesProtected) { $why += ((Split-Path -Leaf $p) + ' inherits') }
    foreach ($r in @($acl.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier]))) {
      if ($r.AccessControlType -ne 'Allow' -or (([int]$r.PropagationFlags -band 2) -ne 0) -or $okSids -contains $r.IdentityReference.Value) { continue }
      if (([int]$r.FileSystemRights -band $writeBits) -ne 0) { $why += ((Split-Path -Leaf $p) + ' writable by ' + $r.IdentityReference.Value) }
    }
  }
  # The owner: an owner can rewrite a folder's permissions, so a lock that leaves it with anyone else is not a lock. The
  # harness is not elevated, so the owner change is a recorded icacls call: AllBirdies and BayAgent (that folder only), and
  # bootstrap with /T, each re-owned to Administrators (S-1-5-32-544) before this download.
  $logNow = @($global:Srh.Log.ToArray())
  foreach ($m in $mustProtect) {
    $isBoot = $m.EndsWith('\bootstrap')
    $want = $(if ($isBoot) { ' /setowner *S-1-5-32-544 /T' } else { ' /setowner *S-1-5-32-544' })
    $seen = @($logNow | Where-Object { $_ -like 'ICACLS *' -and $_.ToLowerInvariant().Contains(($m + $want).ToLowerInvariant()) -and ($isBoot -or -not $_.Contains(' /T')) })
    if ($seen.Count -eq 0) { $why += ((Split-Path -Leaf $m) + ' not re-owned to Administrators') }
  }
  if ($why.Count -eq 0) { return 'locked=yes' }
  return ('locked=NO (' + ($why -join '; ') + ')')
}
function global:Invoke-RestMethod { throw "HARNESS: Invoke-RestMethod is not served (no Dataverse call may happen in a rehearsal)" }
function global:Get-ChildItem {
  [CmdletBinding()] param([Parameter(Position = 0)][string]$Path)
  if ($Path -like 'Cert:*') { return @($global:Srh.Certs.ToArray()) }
  throw "HARNESS: Get-ChildItem on $Path is not served"
}
function global:New-SelfSignedCertificate {
  [CmdletBinding()] param([string]$Type, [string]$Subject, [string]$CertStoreLocation, [string]$HashAlgorithm, [int]$KeyLength)
  $c = [pscustomobject]@{ Thumbprint = ('A1' * 20); Subject = $Subject; HasPrivateKey = $true; NotAfter = (Get-Date).AddYears(1); EnhancedKeyUsageList = @([pscustomobject]@{ FriendlyName = 'Code Signing' }) }
  [void]$global:Srh.Certs.Add($c); SrhRec "CERT     new self-signed code-signing certificate '$Subject' in $CertStoreLocation"; return $c
}
function global:Export-Certificate { [CmdletBinding()] param([string]$Cert, [string]$FilePath) SrhRec "CERT     export public certificate (recorded only)" }
function global:Import-Certificate { [CmdletBinding()] param([string]$FilePath, [string]$CertStoreLocation) SrhRec "CERT     import into $CertStoreLocation" }
function global:certutil { "  Unique container name: fake-container-0001" }
function global:icacls {
  SrhRec ("ICACLS   " + (@($args | ForEach-Object { "$_" }) -join ' '))
  # Model fact swapOnIcacls (R1c): at the FIRST icacls call, AllBirdies is replaced by a junction to a folder of the same shape
  # inside this scratch root, standing in for an account acting between the link check and the permission writes. The double
  # otherwise changes nothing and returns exit 0 (as icacls /C does when it fails).
  if ($global:Srh.SwapOnIcacls -and -not $global:Srh.Swapped) {
    $global:Srh.Swapped = $true
    $ab = Join-Path $global:Srh.Root 'AllBirdies'
    $tgt = Join-Path $global:Srh.Root 'JunctionTarget'
    if ($ab.StartsWith($global:Srh.Root + '\') -and (Split-Path -Leaf $ab) -eq 'AllBirdies' -and (Microsoft.PowerShell.Management\Test-Path -LiteralPath $ab)) {
      Microsoft.PowerShell.Management\New-Item -ItemType Directory -Force -Path (Join-Path $tgt 'BayAgent\bootstrap\setup') | Out-Null
      [IO.Directory]::Delete($ab, $true)
      Microsoft.PowerShell.Management\New-Item -ItemType Junction -Path $ab -Target $tgt | Out-Null
    }
  }
  $global:LASTEXITCODE = 0
  "processed (recorded only)"
}
function global:Set-AuthenticodeSignature { [CmdletBinding()] param([string]$FilePath, $Certificate, [string]$TimeStampServer) SrhRec ("SIGN     " + $FilePath.Replace($global:Srh.Root, '<root>')) }
function global:Get-AuthenticodeSignature {
  [CmdletBinding()] param([Parameter(Position = 0)][string]$FilePath)
  return [pscustomobject]@{ Status = 'Valid'; StatusMessage = 'ok'; TimeStamperCertificate = $(if ($global:Srh.TimestampOk) { 'a time stamp' } else { $null }) }
}
function global:schtasks {
  $a = @($args | ForEach-Object { "$_" }); $tn = ''
  for ($i = 0; $i -lt $a.Count; $i++) { if ($a[$i] -eq '/TN' -and ($i + 1) -lt $a.Count) { $tn = $a[$i + 1] } }
  $safe = @($a | ForEach-Object { if ($_ -eq $global:Srh.Marker) { '<THE TYPED PASSWORD, ON THE COMMAND LINE>' } else { $_ } })
  SrhRec ("SCHTASKS " + ($safe -join ' '))
  # A task whose name matches the model's "schtasksFailMatch" is refused the way Task Scheduler refuses: exit 1 and an
  # ERROR line (here as the output, which is where the script under test must find the text).
  if ($global:Srh.SchtasksFailMatch -and $tn -match $global:Srh.SchtasksFailMatch) { $global:LASTEXITCODE = 1; return "ERROR: Access is denied. (injected)" }
  $ru = ''; $tr = ''
  for ($i = 0; $i -lt $a.Count; $i++) { if ($a[$i] -eq '/RU' -and ($i + 1) -lt $a.Count) { $ru = $a[$i + 1] }; if ($a[$i] -eq '/TR' -and ($i + 1) -lt $a.Count) { $tr = $a[$i + 1] } }
  $sp = $tr.IndexOf(' '); $exe = $(if ($sp -gt 0) { $tr.Substring(0, $sp) } else { $tr }); $argText = $(if ($sp -gt 0) { $tr.Substring($sp + 1) } else { '' })
  $global:LASTEXITCODE = 0; $global:Srh.Tasks[$tn.TrimStart('\')] = [pscustomobject]@{ TaskName = $tn.TrimStart('\'); State = 'Ready'; Principal = [pscustomobject]@{ UserId = $ru }; Actions = @([pscustomobject]@{ Execute = $exe; Arguments = $argText }) }; "SUCCESS (recorded only)"
}
# The ScheduledTasks cmdlets Day0 uses for the agent task. Each New-* returns a tagged object; Register-ScheduledTask records
# the whole definition on one line so a test can assert the principal, the trigger and the limits, and no password.
function global:New-ScheduledTaskAction { [CmdletBinding()] param([string]$Execute, [string]$Argument) return [pscustomobject]@{ Kind = 'action'; Execute = $Execute; Argument = $Argument } }
function global:New-ScheduledTaskTrigger { [CmdletBinding()] param([switch]$AtLogOn, [string]$User) return [pscustomobject]@{ Kind = 'trigger'; AtLogOn = [bool]$AtLogOn; User = $User } }
function global:New-ScheduledTaskPrincipal { [CmdletBinding()] param([string]$UserId, [string]$LogonType, [string]$RunLevel) return [pscustomobject]@{ Kind = 'principal'; UserId = $UserId; LogonType = $LogonType; RunLevel = $RunLevel } }
function global:New-ScheduledTaskSettingsSet {
  [CmdletBinding()] param([switch]$AllowStartIfOnBatteries, [switch]$DontStopIfGoingOnBatteries, [string]$MultipleInstances, $ExecutionTimeLimit)
  return [pscustomobject]@{ Kind = 'settings'; Battery = ([bool]$AllowStartIfOnBatteries -and [bool]$DontStopIfGoingOnBatteries); MultipleInstances = $MultipleInstances; LimitSeconds = $(if ($null -eq $ExecutionTimeLimit) { 'default' } else { [string][int]$ExecutionTimeLimit.TotalSeconds }) }
}
function global:Register-ScheduledTask {
  [CmdletBinding()] param([string]$TaskName, [string]$TaskPath, $Action, $Trigger, $Principal, $Settings, [switch]$Force)
  SrhRec ("REGTASK  {0}{1} execute={2} args=[{3}] atLogOn={4} triggerUser=[{5}] principal={6} logonType={7} runLevel={8} multiple={9} limitSeconds={10} battery={11} storedCredential=absent" -f $TaskPath, $TaskName, $Action.Execute, $Action.Argument, $Trigger.AtLogOn, $Trigger.User, $Principal.UserId, $Principal.LogonType, $Principal.RunLevel, $Settings.MultipleInstances, $Settings.LimitSeconds, $Settings.Battery)
  $global:Srh.Tasks[$TaskName.TrimStart('\')] = [pscustomobject]@{ TaskName = $TaskName.TrimStart('\'); State = 'Ready'; Principal = [pscustomobject]@{ UserId = $Principal.UserId }; Actions = @([pscustomobject]@{ Execute = $Action.Execute; Arguments = $Action.Argument }) }
}
function global:Get-ScheduledTask {
  [CmdletBinding()] param([string]$TaskName)
  if (-not $TaskName) { return @($global:Srh.Tasks.Values) }
  if ($global:Srh.Tasks.ContainsKey($TaskName)) { return $global:Srh.Tasks[$TaskName] }
  Write-Error "No task $TaskName"
}
function global:Read-Host {
  [CmdletBinding()] param([Parameter(Position = 0)][string]$Prompt, [switch]$AsSecureString)
  SrhRec "PROMPT   $Prompt"
  if ($AsSecureString) { return (ConvertTo-SecureString $global:Srh.Marker -AsPlainText -Force) }
  return $global:Srh.RebootAnswer
}
function global:Rename-Computer { [CmdletBinding()] param([string]$NewName, [switch]$Force) SrhRec "RENAME   computer to $NewName (takes effect at restart)" }
function global:Get-LocalUser {
  [CmdletBinding()] param([string]$Name)
  if ($global:Srh.Users.ContainsKey($Name)) { return [pscustomobject]@{ Name = $Name; Enabled = $true; SID = (New-Object System.Security.Principal.SecurityIdentifier($global:Srh.KioskSid)) } }
  Write-Error "User $Name was not found."
}
function global:New-LocalUser {
  [CmdletBinding()] param([string]$Name, $Password, [switch]$PasswordNeverExpires, [switch]$UserMayNotChangePassword, [string]$Description)
  $global:Srh.Users[$Name] = $true; SrhRec "USER     created local user $Name"; return [pscustomobject]@{ Name = $Name }
}
function global:Add-LocalGroupMember { [CmdletBinding()] param([string]$Group, [string]$Member) SrhRec "USER     $Member added to group $Group" }
function global:Get-CimInstance { [CmdletBinding()] param([Parameter(Position = 0)][string]$ClassName) return [pscustomobject]@{ Caption = 'Microsoft Windows 11 Pro' } }
function global:Test-NetConnection { [CmdletBinding()] param([string]$ComputerName, [int]$Port) return [pscustomobject]@{ TcpTestSucceeded = $true } }
function global:powercfg { SrhRec ("POWERCFG " + (@($args) -join ' ')); $global:LASTEXITCODE = [int]$global:Srh.PowercfgExit }
function global:shutdown { SrhRec ("SHUTDOWN " + (@($args) -join ' ')) }
function global:Enable-NetFirewallRule { [CmdletBinding()] param([string]$DisplayGroup) SrhRec "FIREWALL enable group '$DisplayGroup'" }
function global:Disable-NetFirewallRule { [CmdletBinding()] param([string]$DisplayGroup) SrhRec "FIREWALL disable group '$DisplayGroup'" }
function global:Get-ExecutionPolicy { [CmdletBinding()] param([string]$Scope) return $global:Srh.Policy }
function global:Set-ExecutionPolicy {
  [CmdletBinding()] param([string]$ExecutionPolicy, [string]$Scope, [switch]$Force)
  if ($global:Srh.PolicyTakes) { $global:Srh.Policy = $ExecutionPolicy }
  SrhRec "POLICY   Set-ExecutionPolicy $ExecutionPolicy -Scope $Scope"
  if ($global:Srh.PolicyThrows) {
    # What Windows PowerShell 5.1 does when the process was started with -ExecutionPolicy Bypass (measured, verifier probe 2).
    $er = New-Object System.Management.Automation.ErrorRecord((New-Object System.Security.SecurityException), 'ExecutionPolicyOverride', [System.Management.Automation.ErrorCategory]::PermissionDenied, $null)
    $er.ErrorDetails = New-Object System.Management.Automation.ErrorDetails('Windows PowerShell updated your execution policy successfully, but the setting is overridden by a policy defined at a more specific scope. Due to the override, your shell will retain its current effective execution policy of Bypass.')
    $PSCmdlet.ThrowTerminatingError($er)
  }
}

$SrhStubbed = @('Test-Path', 'Get-ItemProperty', 'Set-ItemProperty', 'New-Item', 'Set-Content', 'Remove-Item', 'Invoke-WebRequest', 'Invoke-RestMethod', 'Get-ChildItem',
  'New-SelfSignedCertificate', 'Export-Certificate', 'Import-Certificate', 'certutil', 'icacls', 'Set-AuthenticodeSignature', 'Get-AuthenticodeSignature', 'schtasks',
  'New-ScheduledTaskAction', 'New-ScheduledTaskTrigger', 'New-ScheduledTaskPrincipal', 'New-ScheduledTaskSettingsSet', 'Register-ScheduledTask',
  'Get-ScheduledTask', 'Read-Host', 'Rename-Computer', 'Get-LocalUser', 'New-LocalUser', 'Add-LocalGroupMember', 'Get-CimInstance', 'Test-NetConnection', 'powercfg',
  'shutdown', 'Enable-NetFirewallRule', 'Disable-NetFirewallRule', 'Get-ExecutionPolicy', 'Set-ExecutionPolicy')
$SrhReadOnly = @('Add-Type', 'ForEach-Object', 'Format-Table', 'Get-FileHash', 'Get-Item', 'Join-Path', 'New-Object', 'Out-Null', 'Out-String', 'Set-StrictMode', 'Split-Path',
  'Where-Object', 'New-TimeSpan', 'Write-Error', 'Write-Host', 'ConvertTo-Json', 'Sort-Object')

# Raw ACL entries (SID|type|rights mask|inheritance flags|propagation flags|inherited) and the owner, per path, as Windows
# holds them. The suite reads these without any help from the helper under test.
function SrhDumpAcls([string]$allRoot, [string]$keyFile) {
  $out = [ordered]@{}
  $paths = [ordered]@{
    root = $allRoot; agent = (Join-Path $allRoot 'BayAgent'); bootstrap = (Join-Path $allRoot 'BayAgent\bootstrap'); watchdog = (Join-Path $allRoot 'BayAgent\bootstrap\ABG.HostWatchdog.ps1')
    agenthost = (Join-Path $allRoot 'BayAgent\bootstrap\ABG.AgentHost.ps1'); setupdir = (Join-Path $allRoot 'BayAgent\bootstrap\setup'); staging = (Join-Path $allRoot 'BayAgent\staging')
    state = (Join-Path $allRoot 'BayAgent\state'); logs = (Join-Path $allRoot 'BayAgent\logs'); control = (Join-Path $allRoot 'BayAgent\control'); current = (Join-Path $allRoot 'BayAgent\current')
    day0file = (Join-Path $allRoot 'BayAgent\bootstrap\setup\ABG-Day0-Setup.ps1'); stagingday0 = (Join-Path $allRoot 'BayAgent\staging\ABG-Day0-Setup.ps1'); aclhelper = (Join-Path $allRoot 'BayAgent\bootstrap\setup\ABG-BayAcl.ps1'); releases = (Join-Path $allRoot 'BayAgent\releases'); rollback = (Join-Path $allRoot 'BayAgent\rollback'); tools = (Join-Path $allRoot 'BayAgent\tools'); display = (Join-Path $allRoot 'SessionDisplay'); key = $keyFile
  }
  foreach ($k in $paths.Keys) {
    $pp = $paths[$k]
    if (-not (Microsoft.PowerShell.Management\Test-Path -LiteralPath $pp)) { $out[$k] = $null; continue }
    $it = Microsoft.PowerShell.Management\Get-Item -LiteralPath $pp -Force
    $acl = $it.GetAccessControl()
    $aces = @($acl.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier]) | ForEach-Object { '{0}|{1}|{2}|{3}|{4}|{5}' -f $_.IdentityReference.Value, $_.AccessControlType, [int]$_.FileSystemRights, [int]$_.InheritanceFlags, [int]$_.PropagationFlags, $_.IsInherited })
    $out[$k] = [ordered]@{ owner = $acl.GetOwner([System.Security.Principal.SecurityIdentifier]).Value; protected = $acl.AreAccessRulesProtected; aces = $aces }
  }
  return $out
}
$SrhResult = [ordered]@{ census = 'ok'; harnessError = ''; runs = @() }
function Write-SrhResult { [IO.File]::WriteAllText($ResultFile, ($SrhResult | ConvertTo-Json -Depth 8), (New-Object Text.UTF8Encoding($false))) }

try {
  # ---------------------------------------------------------------- census (default deny)
  # The permissions helper is censused too, and its function names count as defined for the two scripts that call it.
  $helperFile = Join-Path $RepoRoot 'tools\ABG-BayAcl.ps1'
  $htok = $null; $herr = $null
  $hast = [System.Management.Automation.Language.Parser]::ParseFile($helperFile, [ref]$htok, [ref]$herr)
  if (@($herr).Count -gt 0) { throw "CENSUS: $helperFile does not parse" }
  $helperDefs = @($hast.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $true) | ForEach-Object { $_.Name })
  foreach ($f in @($SetupScript, $Day0Script, $helperFile)) {
    $tok = $null; $err = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseFile($f, [ref]$tok, [ref]$err)
    if (@($err).Count -gt 0) { throw "CENSUS: $f does not parse" }
    $defs = @($ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $true) | ForEach-Object { $_.Name })
    $defs += $helperDefs
    foreach ($c in $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.CommandAst] }, $true)) {
      $n = $c.GetCommandName()
      if (-not $n) { if (@('$day0Path', '. $aclHelperPath', '. $aclHelper') -notcontains $c.Extent.Text.Trim() -and $c.CommandElements[0].Extent.Text -ne '$day0Path') { throw "CENSUS: a command whose name is not written out, in $(Split-Path -Leaf $f): $($c.Extent.Text)" }; continue }
      if ($defs -contains $n -or $SrhStubbed -contains $n -or $SrhReadOnly -contains $n) { continue }
      throw "CENSUS: command '$n' in $(Split-Path -Leaf $f) is neither recorded nor on the read-only list. Nothing was run."
    }
  }

  # The helper as served: ONE change, the owner list also names this harness's account (see the header).
  $helperText = [IO.File]::ReadAllText((Join-Path $RepoRoot 'tools\ABG-BayAcl.ps1'))
  $ownerNeedle = '$okOwners = @($script:BaySid.System, $script:BaySid.Admins, $script:BaySid.TrustedInstaller) + @($ExtraOwners)'
  if (([regex]::Matches($helperText, [regex]::Escape($ownerNeedle))).Count -ne 1) { throw "HARNESS: the owner line of ABG-BayAcl.ps1 was not found exactly once" }
  $meSid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
  $servedHelper = Join-Path $Root 'ABG-BayAcl.served.ps1'
  # Second change: the folders also grant this harness's account full control, standing in for the elevated administrator
  # who runs setup on a bay (the harness cannot be elevated; without it the run could not write below its own locked folders).
  $rulesNeedle = '(New-BayRule (Get-BaySidObject $script:BaySid.Users) $rx "ContainerInherit, ObjectInherit" "None"))'
  if (([regex]::Matches($helperText, [regex]::Escape($rulesNeedle))).Count -ne 1) { throw "HARNESS: the Users rule of ABG-BayAcl.ps1 was not found exactly once" }
  $served = $helperText.Replace($ownerNeedle, ($ownerNeedle + ' + @("' + $meSid + '")'))
  # Third change (R1c): the read-back after Chain accepts this harness's account as owner, unless the run's model says it
  # does not (ownerStandIn = false), read at run time from $global:Srh.OwnerOk.
  $rbNeedle = '$script:BayReadBackExtraOwners = @()'
  if (([regex]::Matches($served, [regex]::Escape($rbNeedle))).Count -ne 1) { throw "HARNESS: the read-back owner line of ABG-BayAcl.ps1 was not found exactly once" }
  $served = $served.Replace($rbNeedle, '$script:BayReadBackExtraOwners = @($global:Srh.OwnerOk)')
  $served = $served.Replace($rulesNeedle, ('(New-BayRule (Get-BaySidObject $script:BaySid.Users) $rx "ContainerInherit, ObjectInherit" "None"),' + "`r`n" + '    (New-BayRule (Get-BaySidObject "' + $meSid + '") $full "ContainerInherit, ObjectInherit" "None"))'))
  [IO.File]::WriteAllText($servedHelper, $served, (New-Object Text.UTF8Encoding($false)))
  $global:Srh.AclHelperServed = $servedHelper

  # ---------------------------------------------------------------- the script copy (three changes)
  # (1) Test-IsAdmin returns true. (2) Set-SetupFolderLock's rules also give this harness's account full control, as the
  # served helper does and for the same reason. (3) The two pinned SHA-256 values become those of the files this harness
  # serves (the served helper is changed above, and a suite may serve a changed Day0). The real values are pinned against
  # the stored repository bytes by BayAgent.SetupBlankPc.Tests.ps1; here what is proven is what the script DOES with a pin.
  $setupText = [IO.File]::ReadAllText($SetupScript)
  $needle = 'return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)'
  if (([regex]::Matches($setupText, [regex]::Escape($needle))).Count -ne 1) { throw "HARNESS: the Test-IsAdmin line was not found exactly once" }
  $setupText = $setupText.Replace($needle, 'return $true')
  $okNeedle = '$okOwners = @("S-1-5-32-544")'
  if (([regex]::Matches($setupText, [regex]::Escape($okNeedle))).Count -ne 1) { throw "HARNESS: the read-back owner list of Set-SetupFolderLock was not found exactly once" }
  $setupText = $setupText.Replace($okNeedle, '$okOwners = @("S-1-5-32-544") + @($global:Srh.OwnerOk)')
  $lockNeedle = '(New-Object Security.Principal.SecurityIdentifier("S-1-5-32-545")), $rx, $ci, $np, $allow)))'
  if (([regex]::Matches($setupText, [regex]::Escape($lockNeedle))).Count -ne 1) { throw "HARNESS: the Users rule of Set-SetupFolderLock was not found exactly once" }
  $setupText = $setupText.Replace($lockNeedle, ('(New-Object Security.Principal.SecurityIdentifier("S-1-5-32-545")), $rx, $ci, $np, $allow)),' + "`r`n" + '    (New-Object Security.AccessControl.FileSystemAccessRule((New-Object Security.Principal.SecurityIdentifier("' + $meSid + '")), $full, $ci, $np, $allow)))'))
  foreach ($pin in @(@{ Name = 'ABG-BayAcl.ps1'; File = $servedHelper }, @{ Name = 'ABG-Day0-Setup.ps1'; File = $Day0Script })) {
    $pinRx = '("' + [regex]::Escape($pin.Name) + '"\s*=\s*")[0-9A-F]{64}(")'
    if (([regex]::Matches($setupText, $pinRx)).Count -ne 1) { throw "HARNESS: the pin for $($pin.Name) was not found exactly once" }
    $servedHash = (([Security.Cryptography.SHA256]::Create().ComputeHash([IO.File]::ReadAllBytes($pin.File)) | ForEach-Object { $_.ToString('X2') }) -join '')
    $setupText = [regex]::Replace($setupText, $pinRx, ('${1}' + $servedHash + '${2}'))
  }
  $setupCopy = Join-Path $Root 'Setup-BayPC.harness.ps1'
  [IO.File]::WriteAllText($setupCopy, $setupText, (New-Object Text.UTF8Encoding($false)))
  # The machine key store, in the scratch root: ProgramData is this run's own, with one fake key file.
  $env:ProgramData = Join-Path $Root 'ProgramData'
  $keyDir = Join-Path $env:ProgramData 'Microsoft\Crypto\Keys'
  Microsoft.PowerShell.Management\New-Item -ItemType Directory -Force -Path $keyDir | Out-Null
  $keyFile = Join-Path $keyDir 'fake-container-0001'
  [IO.File]::WriteAllText($keyFile, 'stand-in, not a key')
  $plan = [IO.File]::ReadAllText($PlanFile) | ConvertFrom-Json
  SrhSeedBlankPc
  $allRoot = Join-Path $Root 'AllBirdies'
  foreach ($run in @($plan.runs)) {
    # ---- the modeled facts this run starts from
    $model = $run.model
    $global:Srh.PolicyThrows = $true; $global:Srh.PolicyTakes = $true; $global:Srh.TimestampOk = $true; $global:Srh.FailDownloadMatch = ''; $global:Srh.RebootAnswer = 'n'; $global:Srh.RegStuck = @(); $global:Srh.SchtasksFailMatch = ''; $global:Srh.PowercfgExit = 0; $global:Srh.TamperDownload = ''
    $global:Srh.OwnerOk = @($global:Srh.MeSid); $global:Srh.SwapOnIcacls = $false; $global:Srh.Swapped = $false
    if ($null -ne $model) {
      foreach ($p in $model.PSObject.Properties) {
        switch ($p.Name) {
          'policyThrows'      { $global:Srh.PolicyThrows = [bool]$p.Value }
          'policyTakes'       { $global:Srh.PolicyTakes = [bool]$p.Value }
          'timestampOk'       { $global:Srh.TimestampOk = [bool]$p.Value }
          'failDownloadMatch' { $global:Srh.FailDownloadMatch = [string]$p.Value }
          'rebootAnswer'      { $global:Srh.RebootAnswer = [string]$p.Value }
          'reg'               { foreach ($r in $p.Value.PSObject.Properties) { $global:Srh.Reg[$r.Name.ToLower()] = $r.Value } }
          'regRemove'         { foreach ($k in @($p.Value)) { $global:Srh.Reg.Remove(([string]$k).ToLower()) } }
          'schtasksFailMatch' { $global:Srh.SchtasksFailMatch = [string]$p.Value }
          'powercfgExit'      { $global:Srh.PowercfgExit = [int]$p.Value }
          'tamperDownload'    { $global:Srh.TamperDownload = [string]$p.Value }
          'ownerStandIn'      { if (-not [bool]$p.Value) { $global:Srh.OwnerOk = @() } }
          'swapOnIcacls'      { $global:Srh.SwapOnIcacls = [bool]$p.Value }
          'regStuck'          { $global:Srh.RegStuck = @($p.Value | ForEach-Object { ([string]$_).ToLower() }) }
          'keyGrantedToKiosk' { if ([bool]$p.Value) { $kf = New-Object IO.FileInfo($keyFile); $ks = $kf.GetAccessControl(); $ks.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule((New-Object Security.Principal.SecurityIdentifier($global:Srh.KioskSid)), 'Read', 'Allow'))); $kf.SetAccessControl($ks) } }
          'seedDrift'         { if ([bool]$p.Value) {
              # What a bay holds before this change: the kiosk account can modify the folder SYSTEM runs from, and an explicit grant sits on the watchdog.
              $ksid = New-Object Security.Principal.SecurityIdentifier($global:Srh.KioskSid)
              $dp = Join-Path $allRoot 'BayAgent\bootstrap'
              if (Microsoft.PowerShell.Management\Test-Path -LiteralPath $dp) { $di = New-Object IO.DirectoryInfo($dp); $ds = $di.GetAccessControl(); $ds.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule($ksid, 'Modify', 'ContainerInherit, ObjectInherit', 'None', 'Allow'))); $di.SetAccessControl($ds) }
              $wf = Join-Path $allRoot 'BayAgent\bootstrap\ABG.HostWatchdog.ps1'
              if (Microsoft.PowerShell.Management\Test-Path -LiteralPath $wf) { $fi = New-Object IO.FileInfo($wf); $fs = $fi.GetAccessControl(); $fs.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule($ksid, 'Modify', 'Allow'))); $fi.SetAccessControl($fs) }
              # And on the permissions file a previous run left in bootstrap\setup: overwritten in place, it would keep this grant.
              $hf = Join-Path $allRoot 'BayAgent\bootstrap\setup\ABG-BayAcl.ps1'
              if (Microsoft.PowerShell.Management\Test-Path -LiteralPath $hf) { $hi = New-Object IO.FileInfo($hf); $hs = $hi.GetAccessControl(); $hs.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule($ksid, 'Modify', 'Allow'))); $hi.SetAccessControl($hs) }
            } }
          'placeAgent'        { if ([bool]$p.Value) { $ap = Join-Path $allRoot 'BayAgent\current\BayAgent.ps1'; Microsoft.PowerShell.Management\New-Item -ItemType Directory -Force -Path (Split-Path -Parent $ap) | Out-Null; [IO.File]::WriteAllText($ap, '# stand-in for the installed agent') } }
          'placeSecretFile'   { if ([bool]$p.Value) { $sp = Join-Path $allRoot 'BayAgent\secrets\clientsecret.dpapi'; Microsoft.PowerShell.Management\New-Item -ItemType Directory -Force -Path (Split-Path -Parent $sp) | Out-Null; [IO.File]::WriteAllText($sp, 'stand-in, not a secret') } }
          default             { throw "HARNESS: unknown model fact '$($p.Name)'" }
        }
      }
    }
    $setupArgs = @{}
    foreach ($p in $run.args.PSObject.Properties) { $setupArgs[$p.Name] = $p.Value }
    $setupArgs['AllBirdiesRoot'] = $allRoot
    $env:COMPUTERNAME = [string]$run.computerName
    $global:Srh.Log.Clear()
    $console = New-Object System.Collections.ArrayList
    $ended = 'ran to its last line'; $stoppedAt = ''
    # A wide page, so a long line is one line in the record (a bay's console wraps; the record must not).
    try { & $setupCopy @setupArgs *>&1 | Out-String -Stream -Width 4096 | ForEach-Object { [void]$console.Add(([string]$_).TrimEnd()) } }
    catch {
      $where = (("$($_.ScriptStackTrace)" -split "`n") | Where-Object { $_ -match 'Setup-BayPC\.harness\.ps1|ABG-Day0-Setup\.ps1' } | Select-Object -First 1)
      $stoppedAt = ("$where" -replace [regex]::Escape($global:Srh.Root), '<root>').Trim()
      $ended = ("STOPPED: " + (("$($_.Exception.Message) " + $(if ($_.ErrorDetails) { $_.ErrorDetails.Message } else { '' })) -replace '\s+', ' ').Trim())
    }
    $cfgPath = Join-Path $allRoot 'BayAgent\agent-config.json'
    $cfgText = $null
    if (Microsoft.PowerShell.Management\Test-Path -LiteralPath $cfgPath) { $cfgText = [IO.File]::ReadAllText($cfgPath) }
    $consoleText = ($console -join "`n")
    $regOut = [ordered]@{}
    foreach ($k in @($global:Srh.Reg.Keys | Sort-Object)) { $v = $global:Srh.Reg[$k]; $regOut[$k] = $(if ("$v" -eq $global:Srh.Marker) { '<THE TYPED PASSWORD, IN THE CLEAR>' } else { $v }) }
    $SrhResult.runs += [ordered]@{
      title           = [string]$run.title
      ended           = $ended
      stoppedAt       = $stoppedAt
      console         = @($console | ForEach-Object { $_.Replace($global:Srh.Root, '<root>') })
      log             = @($global:Srh.Log | ForEach-Object { $_.Replace($global:Srh.Root, '<root>') })
      reg             = $regOut
      policy          = [string]$global:Srh.Policy
      tasks           = @($global:Srh.Tasks.Keys | Sort-Object)
      users           = @($global:Srh.Users.Keys | Sort-Object)
      configText      = $cfgText
      secretToolOnDisk = [bool](Microsoft.PowerShell.Management\Test-Path -LiteralPath (Join-Path $allRoot 'BayAgent\bootstrap\ABG.SetClientSecretDpapi.ps1'))
      acls            = (SrhDumpAcls $allRoot $keyFile)
      markerInConsole = [bool]($consoleText.Contains($global:Srh.Marker))
      # Marker files a tampered download left by running (cumulative over the plan's runs).
      tamperRan       = @([IO.Directory]::GetFiles($global:Srh.Root, 'TAMPERED-RAN-*') | ForEach-Object { [IO.Path]::GetFileName($_) })
    }
  }
}
catch {
  $msg = "$($_.Exception.Message)"
  if ($msg -like 'CENSUS:*') { $SrhResult.census = $msg } else { $SrhResult.harnessError = $msg + ' | ' + ("$($_.ScriptStackTrace)" -split "`n" | Select-Object -First 2) -join ' ' }
}
Write-SrhResult
exit 0
