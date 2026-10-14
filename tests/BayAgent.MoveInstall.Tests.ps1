<#
BayAgent.MoveInstall.Tests.ps1

What src\BayAgent\tools\Move-BayInstall.ps1 does to an installed bay, proven without touching a bay or this PC's own
install: the REAL tool text runs top to bottom on a fake install under C:\Temp\bmt-<id> (real files, real access
rules, a real junction, a fake secret file this process is DENIED reading), and every command that would touch the
machine (scheduled tasks, the registry, sessions, processes, signing, the certificate store, downloads, prompts) is
answered by a recorder on a modeled bay. A census refuses to run the tool if it holds a command that is neither
recorded nor on the read-only list.

PARTS
  A  The tool's own functions, lifted by AST: path rewriting in every form a bay file uses, task definitions (made by
     the Task Scheduler's own serializer, nothing registered), agent-config.json (the repository's own file), the tree
     listing (names, sizes and times only).
  B  The whole tool on a modeled bay: Plan writes nothing; Move; Verify before and after a modeled restart; Back puts
     every byte back; a failure at each stage of the cutover puts back everything already done; a failure while
     putting back is reported, not hidden; every refusal changes nothing.
  C  The real Task Scheduler: a task for this account, registered disabled with no trigger, is exported, rewritten by
     the tool's function and registered again under a new name by the tool's function; both removed by exact name.
  D  The password, with tool's Register-BmTask with the REAL Register-ScheduledTask, a fake account and a fake
     password, under -Debug and -Verbose preferences and a transcript; the fake value is searched in all six streams,
     the transcript, the error text and every record left in $Error.

WHAT THIS DOES NOT PROVE
  Anything Windows itself does at a bay: signing out an account, a real logon task with a real password, Edge on a
  moved profile, a restart. Those are the run sheet's (docs\runsheet-bay1-move.md), on Bay 1, with Kevin.

Run (Windows PowerShell 5.1, the host a bay runs; from the repo root):
  powershell -NoProfile -ExecutionPolicy Bypass -File tests\BayAgent.MoveInstall.Tests.ps1
Exit code 0 = all assertions passed. Hyphens only in comments. ASCII only.
#>
[CmdletBinding()]
param(
  [string]$ToolScript = "",
  [switch]$Child,
  [string]$PlanFile = "",
  [string]$ResultFile = "",
  [string]$Scratch = "",
  [string]$EvidenceDir = ""
)
Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# ====================================================================================================================
# CHILD: the harness. One modeled bay; the plan's runs one after another on it.
# ====================================================================================================================
if ($Child) {
  $plan = [IO.File]::ReadAllText($PlanFile) | ConvertFrom-Json
  $global:BmH = @{
    Scratch = $Scratch; Marker = [string]$plan.marker; Tasks = @{}; Reg = @{}; RegKeys = @{}; Procs = New-Object System.Collections.ArrayList
    Signed = @{}; Thumb = ("AB" * 20); Log = New-Object System.Collections.ArrayList; Answers = New-Object System.Collections.Queue
    Inject = @{}; Boot = (Get-Date).AddHours(-3); Sid = "S-1-5-21-1111111111-2222222222-3333333333-1001"; Web = ""; Sleeps = 0
  }
  function global:HRec([string]$m) { [void]$global:BmH.Log.Add($m) }
  function global:HScratch([string]$p) {
    $full = [IO.Path]::GetFullPath($p)
    if (-not $full.StartsWith($global:BmH.Scratch, [StringComparison]::OrdinalIgnoreCase)) { throw "HARNESS: refused a write outside the scratch folder: $full" }
  }
  function global:HInject([string]$point) {
    if ($global:BmH.Inject.ContainsKey($point)) { $m = $global:BmH.Inject[$point]; HRec ("INJECT  " + $point); throw $m }
  }
  function global:HSha([string]$path) { return (Microsoft.PowerShell.Utility\Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash }
  function global:HTaskFacts([string]$xml) {
    $d = New-Object System.Xml.XmlDocument; $d.LoadXml($xml)
    $ns = New-Object System.Xml.XmlNamespaceManager($d.NameTable); $ns.AddNamespace("t", "http://schemas.microsoft.com/windows/2004/02/mit/task")
    $acts = @()
    foreach ($e in @($d.SelectNodes("/t:Task/t:Actions/t:Exec", $ns))) {
      $c = $e.SelectSingleNode("t:Command", $ns); $a = $e.SelectSingleNode("t:Arguments", $ns); $w = $e.SelectSingleNode("t:WorkingDirectory", $ns)
      $acts += [pscustomobject]@{ Execute = $(if ($c) { $c.InnerText } else { $null }); Arguments = $(if ($a) { $a.InnerText } else { $null }); WorkingDirectory = $(if ($w) { $w.InnerText } else { $null }) }
    }
    $p = $d.SelectSingleNode("/t:Task/t:Principals/t:Principal", $ns)
    $lt = $p.SelectSingleNode("t:LogonType", $ns); $uid = $p.SelectSingleNode("t:UserId", $ns)
    $en = $d.SelectSingleNode("/t:Task/t:Settings/t:Enabled", $ns)
    return @{ Actions = $acts; LogonType = $(if ($lt) { $lt.InnerText } else { "" }); User = $(if ($uid) { $uid.InnerText } else { "" }); Enabled = ($null -eq $en -or $en.InnerText -ne "false") }
  }
  function global:HSetEnabled([string]$xml, [bool]$on) {
    $d = New-Object System.Xml.XmlDocument; $d.PreserveWhitespace = $true; $d.LoadXml($xml)
    $ns = New-Object System.Xml.XmlNamespaceManager($d.NameTable); $ns.AddNamespace("t", "http://schemas.microsoft.com/windows/2004/02/mit/task")
    $s = $d.SelectSingleNode("/t:Task/t:Settings", $ns); $en = $s.SelectSingleNode("t:Enabled", $ns)
    if ($null -eq $en) { $en = $d.CreateElement("Enabled", "http://schemas.microsoft.com/windows/2004/02/mit/task"); [void]$s.AppendChild($en) }
    $en.InnerText = $(if ($on) { "true" } else { "false" })
    return $d.OuterXml
  }

  # ---------------------------------------------------------------- recorders: scheduled tasks
  function global:Get-ScheduledTask {
    [CmdletBinding()] param([Parameter(Position = 0)][string]$TaskName, [string]$TaskPath)
    $names = $(if ($TaskName) { @($TaskName) } else { @($global:BmH.Tasks.Keys | Sort-Object) })
    $out = @()
    foreach ($n in $names) {
      if (-not $global:BmH.Tasks.ContainsKey($n)) { throw "No MSFT_ScheduledTask objects found with property 'TaskName' equal to '$n'." }
      $t = $global:BmH.Tasks[$n]; $f = HTaskFacts $t.Xml
      $out += [pscustomobject]@{ TaskName = $n; TaskPath = "\"; State = $(if ($t.Enabled) { "Ready" } else { "Disabled" }); Actions = $f.Actions }
    }
    return $out
  }
  function global:Export-ScheduledTask {
    [CmdletBinding()] param([string]$TaskName, [string]$TaskPath)
    if (-not $global:BmH.Tasks.ContainsKey($TaskName)) { throw "The system cannot find the file specified." }
    $x = HSetEnabled $global:BmH.Tasks[$TaskName].Xml $global:BmH.Tasks[$TaskName].Enabled
    if ($global:BmH.Inject.ContainsKey("export-user:" + $TaskName)) { $x = $x -replace '<UserId>[^<]*</UserId>', '<UserId>BAY1KIOSK\SomeoneElse</UserId>' }
    return $x
  }
  function global:Register-ScheduledTask {
    [CmdletBinding()] param([string]$TaskName, [string]$TaskPath, [string]$Xml, [string]$User, [string]$Password, [switch]$Force)
    HInject ("register:" + $TaskName)
    $f = HTaskFacts $Xml
    $needs = @("Password", "InteractiveTokenOrPassword") -contains $f.LogonType
    if ($needs -and [string]::IsNullOrEmpty($Password)) { throw "The task XML contains a value which is incorrectly formatted or out of range. (a password is required for this logon type)" }
    if (-not [string]::IsNullOrEmpty($Password) -and $Password -cne $global:BmH.Marker) { throw "The user name or password is incorrect. (8,44):UserId:" }
    if ($global:BmH.Tasks.ContainsKey($TaskName) -and -not $Force) { throw "Cannot create a file when that file already exists." }
    $global:BmH.Tasks[$TaskName] = @{ Xml = $Xml; Enabled = $f.Enabled; WithPw = (-not [string]::IsNullOrEmpty($Password)); UserArg = [string]$User }
    HRec ("TASK    register \{0} enabled={1} user-arg='{2}' pw={3}" -f $TaskName, $f.Enabled, $User, $(if ($Password) { "given" } else { "none" }))
  }
  function global:Enable-ScheduledTask { [CmdletBinding()] param([string]$TaskName, [string]$TaskPath) HInject ("enable:" + $TaskName); if (-not $global:BmH.Tasks.ContainsKey($TaskName)) { throw "no task $TaskName" }; $global:BmH.Tasks[$TaskName].Enabled = $true; HRec "TASK    enable \$TaskName" }
  function global:Disable-ScheduledTask { [CmdletBinding()] param([string]$TaskName, [string]$TaskPath) HInject ("disable:" + $TaskName); if (-not $global:BmH.Tasks.ContainsKey($TaskName)) { throw "no task $TaskName" }; $global:BmH.Tasks[$TaskName].Enabled = $false; HRec "TASK    disable \$TaskName" }
  function global:Stop-ScheduledTask { [CmdletBinding()] param([string]$TaskName, [string]$TaskPath) HRec "TASK    end \$TaskName" }
  function global:Unregister-ScheduledTask {
    [CmdletBinding(SupportsShouldProcess = $true)] param([string]$TaskName, [string]$TaskPath)
    HInject ("unregister:" + $TaskName)
    if (-not $global:BmH.Tasks.ContainsKey($TaskName)) { throw "no task $TaskName" }
    $global:BmH.Tasks.Remove($TaskName); HRec "TASK    unregister \$TaskName"
  }
  # ---------------------------------------------------------------- recorders: registry
  function global:Test-Path {
    [CmdletBinding()] param([Parameter(Position = 0)][string]$Path, [string]$LiteralPath, [string]$PathType)
    $p = $(if ($LiteralPath) { $LiteralPath } else { $Path })
    if ($p -like "Registry::*") { return [bool]$global:BmH.RegKeys.ContainsKey($p.ToLowerInvariant()) }
    if ($PathType) { return (Microsoft.PowerShell.Management\Test-Path -LiteralPath $p -PathType $PathType) }
    return (Microsoft.PowerShell.Management\Test-Path -LiteralPath $p)
  }
  function global:Get-ItemProperty {
    [CmdletBinding()] param([Parameter(Position = 0)][string]$Path, [string]$Name)
    if ($Path -notlike "Registry::*") { throw "HARNESS: Get-ItemProperty on $Path is not served" }
    $k = $Path.ToLowerInvariant()
    if (-not $global:BmH.RegKeys.ContainsKey($k)) { return $null }
    $o = New-Object psobject; $any = $false
    foreach ($e in @($global:BmH.Reg.Keys)) {
      $parts = $e.Split('|'); if ($parts[0] -ne $k) { continue }
      if ($Name -and $parts[1] -ne $Name.ToLowerInvariant()) { continue }
      Add-Member -InputObject $o -NotePropertyName $parts[1] -NotePropertyValue $global:BmH.Reg[$e]; $any = $true
    }
    if (-not $any) { return $null }
    return $o
  }
  function global:Set-ItemProperty {
    [CmdletBinding()] param([string]$Path, [string]$Name, $Value)
    HInject ("setreg:" + $Name)
    $k = $Path.ToLowerInvariant()
    if (-not $global:BmH.RegKeys.ContainsKey($k)) { throw "Cannot find path '$Path' because it does not exist." }
    $global:BmH.Reg[$k + "|" + $Name.ToLowerInvariant()] = $Value; HRec ("REG     set {0} = {1}" -f $Name, $Value)
  }
  function global:Remove-ItemProperty { [CmdletBinding()] param([string]$Path, [string]$Name) $global:BmH.Reg.Remove($Path.ToLowerInvariant() + "|" + $Name.ToLowerInvariant()); HRec "REG     remove $Name" }
  # ---------------------------------------------------------------- recorders: accounts, sessions, processes
  function global:Get-LocalUser { [CmdletBinding()] param([string]$Name) if ($Name -ne "BayKiosk") { throw "User $Name was not found." }; return [pscustomobject]@{ Name = $Name; SID = [pscustomobject]@{ Value = $global:BmH.Sid } } }
  function global:Get-Process {
    [CmdletBinding()] param([switch]$IncludeUserName)
    return @($global:BmH.Procs | ForEach-Object { [pscustomobject]@{ Id = $_.Id; ProcessName = $_.Name; SessionId = $_.Session; UserName = $_.User } })
  }
  function global:logoff {
    $sid = [int]$args[0]
    HRec "SESSION logoff $sid"
    if ($global:BmH.Inject.ContainsKey("logoff-keeps")) { return }
    $keep = @($global:BmH.Procs | Where-Object { $_.Session -ne $sid })
    $global:BmH.Procs.Clear(); foreach ($k in $keep) { [void]$global:BmH.Procs.Add($k) }
  }
  function global:Get-CimInstance {
    [CmdletBinding()] param([string]$ClassName)
    if ($ClassName -eq "Win32_OperatingSystem") { return [pscustomobject]@{ LastBootUpTime = $global:BmH.Boot } }
    if ($ClassName -eq "Win32_Process") { return @($global:BmH.Procs | ForEach-Object { [pscustomobject]@{ ProcessId = $_.Id; Name = $_.Name; CommandLine = $_.Cmd; ExecutablePath = $_.Exe } }) }
    throw "HARNESS: Get-CimInstance $ClassName is not served"
  }
  function global:Stop-Process {
    [CmdletBinding()] param([int]$Id, [switch]$Force)
    HRec "PROCESS stop $Id"
    $keep = @($global:BmH.Procs | Where-Object { $_.Id -ne $Id })
    $global:BmH.Procs.Clear(); foreach ($k in $keep) { [void]$global:BmH.Procs.Add($k) }
  }
  function global:Start-Sleep { [CmdletBinding()] param([int]$Seconds, [int]$Milliseconds) $global:BmH.Sleeps++ }
  # ---------------------------------------------------------------- recorders: signing, certificates, downloads, prompts
  function global:Get-AuthenticodeSignature {
    [CmdletBinding()] param([string]$FilePath)
    $h = HSha $FilePath
    if ($global:BmH.Signed.ContainsKey($h)) {
      $s = $global:BmH.Signed[$h]
      return [pscustomobject]@{ Status = "Valid"; StatusMessage = "Signature verified."; SignerCertificate = [pscustomobject]@{ Thumbprint = $s.Thumb }; TimeStamperCertificate = $(if ($s.Ts) { "timestamp" } else { $null }) }
    }
    return [pscustomobject]@{ Status = "NotSigned"; StatusMessage = "not signed"; SignerCertificate = $null; TimeStamperCertificate = $null }
  }
  function global:Set-AuthenticodeSignature {
    [CmdletBinding()] param([string]$FilePath, $Certificate, [string]$TimeStampServer)
    HScratch $FilePath
    [IO.File]::AppendAllText($FilePath, "`r`n# SIG # Begin signature block`r`n# MODELED`r`n# SIG # End signature block`r`n")
    $global:BmH.Signed[(HSha $FilePath)] = @{ Thumb = [string]$Certificate.Thumbprint; Ts = (-not $global:BmH.Inject.ContainsKey("sign-no-timestamp")) }
    HRec ("SIGN    " + [IO.Path]::GetFileName($FilePath) + " with " + $Certificate.Thumbprint)
  }
  function global:Get-ChildItem {
    [CmdletBinding()] param([Parameter(Position = 0)][string]$Path)
    if ($Path -like "Cert:*") { return @([pscustomobject]@{ Thumbprint = $global:BmH.Thumb; HasPrivateKey = $true; Subject = "CN=ABG Bay Code Signing" }) }
    throw "HARNESS: Get-ChildItem on $Path is not served"
  }
  function global:Invoke-WebRequest {
    [CmdletBinding()] param([string]$Uri, [string]$OutFile, [switch]$UseBasicParsing, [int]$MaximumRedirection)
    HScratch $OutFile
    $leaf = $Uri.Substring($Uri.LastIndexOf('/') + 1)
    $src = Join-Path $global:BmH.Web $leaf
    if (-not [IO.File]::Exists($src)) { HRec "DOWNLOAD $Uri -> 404"; throw "The remote server returned an error: (404) Not Found." }
    [IO.File]::Copy($src, $OutFile, $true); HRec "DOWNLOAD $Uri"
  }
  function global:Read-Host {
    [CmdletBinding()] param([Parameter(Position = 0)][string]$Prompt, [switch]$AsSecureString)
    HRec ("PROMPT  " + $Prompt)
    # Security tests: what a standard user could do between the plan and the move, done at the prompt the person answers.
    if ($global:BmH.Inject.ContainsKey("swap-new-open")) {
      $swapDir = [string]$global:BmH.Inject["swap-new-open"]; [void]$global:BmH.Inject.Remove("swap-new-open")
      HScratch $swapDir
      [void][IO.Directory]::CreateDirectory($swapDir)
      $swapAcl = Get-Acl -LiteralPath $swapDir
      $swapAcl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule("BUILTIN\Users", "Modify", "ContainerInherit,ObjectInherit", "None", "Allow")))
      Microsoft.PowerShell.Security\Set-Acl -LiteralPath $swapDir -AclObject $swapAcl
    }
    if ($global:BmH.Inject.ContainsKey("swap-src-link")) {
      $swapParts = ([string]$global:BmH.Inject["swap-src-link"]).Split('|'); [void]$global:BmH.Inject.Remove("swap-src-link")
      HScratch $swapParts[0]; HScratch $swapParts[1]
      [IO.Directory]::Move($swapParts[0], $swapParts[1])
      Microsoft.PowerShell.Management\New-Item -ItemType Junction -Path $swapParts[0] -Value $swapParts[1] | Out-Null
    }
    $a = $(if ($global:BmH.Answers.Count -gt 0) { [string]$global:BmH.Answers.Dequeue() } else { "" })
    if ($AsSecureString) {
      $v = $(if ($a -eq "pw:good") { $global:BmH.Marker } elseif ($a -eq "pw:wrong") { "not-" + $global:BmH.Marker } else { "" })
      if ($v -eq "") { return (New-Object System.Security.SecureString) }
      return (ConvertTo-SecureString $v -AsPlainText -Force)
    }
    return $a
  }
  # ---------------------------------------------------------------- real, but only inside the scratch folder
  function global:Set-Acl { [CmdletBinding()] param([string]$LiteralPath, $AclObject) HScratch $LiteralPath; Microsoft.PowerShell.Security\Set-Acl -LiteralPath $LiteralPath -AclObject $AclObject; HRec ("ACL     set " + $LiteralPath.Replace($global:BmH.Scratch, "<s>")) }
  function global:New-Item { [CmdletBinding()] param([string]$ItemType, [string]$Path, $Value) HScratch $Path; if ($ItemType -ne "Junction") { throw "HARNESS: New-Item $ItemType is not served" }; HScratch ([string]$Value); Microsoft.PowerShell.Management\New-Item -ItemType Junction -Path $Path -Value $Value }

  $stubbed = @("Get-ScheduledTask", "Export-ScheduledTask", "Register-ScheduledTask", "Enable-ScheduledTask", "Disable-ScheduledTask", "Stop-ScheduledTask",
    "Unregister-ScheduledTask", "Test-Path", "Get-ItemProperty", "Set-ItemProperty", "Remove-ItemProperty", "Get-LocalUser", "Get-Process", "logoff",
    "Get-CimInstance", "Stop-Process", "Start-Sleep", "Get-AuthenticodeSignature", "Set-AuthenticodeSignature", "Get-ChildItem", "Invoke-WebRequest",
    "Read-Host", "Set-Acl", "New-Item")
  $readOnly = @("Write-Host", "Join-Path", "ConvertFrom-Json", "ConvertTo-Json", "Sort-Object", "Where-Object", "ForEach-Object", "Out-Null", "Get-Date",
    "New-Object", "Get-Item", "Get-Location", "Get-Acl", "Set-StrictMode", "Add-Type")

  $res = [ordered]@{ census = "ok"; harnessError = ""; runs = @() }
  try {
    # ------------------------------------------------------------ census (default deny)
    $tok = $null; $err = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseFile($ToolScript, [ref]$tok, [ref]$err)
    if (@($err).Count -gt 0) { throw "CENSUS: the tool does not parse" }
    $defs = @($ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $true) | ForEach-Object { $_.Name })
    foreach ($c in $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.CommandAst] }, $true)) {
      $n = $c.GetCommandName()
      if (-not $n) { throw "CENSUS: a command whose name is not written out: $($c.Extent.Text)" }
      if ($defs -contains $n -or $stubbed -contains $n -or $readOnly -contains $n) { continue }
      throw "CENSUS: command '$n' in the tool is neither recorded nor on the read-only list. Nothing was run."
    }
    # ------------------------------------------------------------ the tool copy (one change: the administrator check)
    $text = [IO.File]::ReadAllText($ToolScript)
    $needle = 'return $bmPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)'
    if (([regex]::Matches($text, [regex]::Escape($needle))).Count -ne 1) { throw "HARNESS: the administrator check was not found exactly once" }
    $toolDir = Join-Path $Scratch "tool"; [void][IO.Directory]::CreateDirectory($toolDir)
    $toolCopy = Join-Path $toolDir "Move-BayInstall.ps1"
    [IO.File]::WriteAllText($toolCopy, $text.Replace($needle, 'return $true'), (New-Object Text.UTF8Encoding($false)))

    # ------------------------------------------------------------ the modeled bay
    $global:BmH.Web = [string]$plan.web
    $stateFile = $(if ($plan.PSObject.Properties["stateFile"]) { [string]$plan.stateFile } else { "" })
    if ($stateFile -and [IO.File]::Exists($stateFile)) {
      $st = [IO.File]::ReadAllText($stateFile) | ConvertFrom-Json
      foreach ($k in @($st.regKeys)) { $global:BmH.RegKeys[[string]$k] = $true }
      foreach ($p in @($st.reg.PSObject.Properties)) { $global:BmH.Reg[$p.Name] = $p.Value }
      foreach ($t in @($st.tasks)) { $global:BmH.Tasks[[string]$t.name] = @{ Xml = [string]$t.xml; Enabled = [bool]$t.enabled; WithPw = [bool]$t.withPw; UserArg = [string]$t.userArg } }
      foreach ($p in @($st.procs)) { [void]$global:BmH.Procs.Add(@{ Id = [int]$p.Id; Name = [string]$p.Name; Cmd = [string]$p.Cmd; Exe = [string]$p.Exe; Session = [int]$p.Session; User = [string]$p.User }) }
      foreach ($s in @($st.signed)) { $global:BmH.Signed[[string]$s.hash] = @{ Thumb = [string]$s.thumb; Ts = [bool]$s.ts } }
      $plan.regKeys = @(); $plan.reg = New-Object psobject; $plan.tasks = @(); $plan.procs = @(); $plan.signed = @()
    }
    foreach ($k in @($plan.regKeys)) { $global:BmH.RegKeys[([string]$k).ToLowerInvariant()] = $true }
    foreach ($p in @($plan.reg.PSObject.Properties)) { $global:BmH.Reg[$p.Name.ToLowerInvariant()] = $p.Value }
    foreach ($t in @($plan.tasks)) { $global:BmH.Tasks[[string]$t.name] = @{ Xml = [string]$t.xml; Enabled = $true; WithPw = $false; UserArg = "" } }
    foreach ($p in @($plan.procs)) { [void]$global:BmH.Procs.Add(@{ Id = [int]$p.id; Name = [string]$p.name; Cmd = [string]$p.cmd; Exe = [string]$p.exe; Session = [int]$p.session; User = [string]$p.user }) }
    foreach ($s in @($plan.signed)) { if ([IO.File]::Exists([string]$s)) { $global:BmH.Signed[(HSha ([string]$s))] = @{ Thumb = $global:BmH.Thumb; Ts = $true } } }

    foreach ($run in @($plan.runs)) {
      $global:BmH.Answers.Clear(); foreach ($a in @($run.answers)) { $global:BmH.Answers.Enqueue([string]$a) }
      $global:BmH.Inject = @{}
      if ($run.PSObject.Properties["inject"]) { foreach ($p in @($run.inject.PSObject.Properties)) { $global:BmH.Inject[$p.Name] = [string]$p.Value } }
      if ($run.PSObject.Properties["addProcs"]) { foreach ($p in @($run.addProcs)) { [void]$global:BmH.Procs.Add(@{ Id = [int]$p.id; Name = [string]$p.name; Cmd = [string]$p.cmd; Exe = [string]$p.exe; Session = [int]$p.session; User = [string]$p.user }) } }
      if ($run.PSObject.Properties["clearProcs"] -and [bool]$run.clearProcs) { $global:BmH.Procs.Clear() }
      if ($run.PSObject.Properties["touch"]) { foreach ($f in @($run.touch)) { HScratch ([string]$f); [IO.File]::WriteAllText([string]$f, "{}") } }
      if ($run.PSObject.Properties["regSet"]) { foreach ($p in @($run.regSet.PSObject.Properties)) { $global:BmH.Reg[$p.Name.ToLowerInvariant()] = $p.Value } }
      if ($run.PSObject.Properties["regKeysAdd"]) { foreach ($k in @($run.regKeysAdd)) { $global:BmH.RegKeys[([string]$k).ToLowerInvariant()] = $true } }
      if ($run.PSObject.Properties["addTasks"]) { foreach ($t in @($run.addTasks)) { $global:BmH.Tasks[[string]$t.name] = @{ Xml = [string]$t.xml; Enabled = $true; WithPw = $false; UserArg = "" } } }
      if ($run.PSObject.Properties["removeTasks"]) { foreach ($t in @($run.removeTasks)) { $global:BmH.Tasks.Remove([string]$t) } }
      $global:BmH.Log.Clear()
      $lockStream = $null
      if ($run.PSObject.Properties["lockFile"] -and $run.lockFile) { $lockStream = New-Object IO.FileStream([string]$run.lockFile, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::None) }
      $script_ = $(if ($run.PSObject.Properties["toolAt"] -and $run.toolAt) { [string]$run.toolAt } else { $toolCopy })
      if ($script_ -ne $toolCopy) { [IO.File]::Copy($toolCopy, $script_, $true) }
      $argTable = @{}
      foreach ($p in @($run.args.PSObject.Properties)) { $argTable[$p.Name] = $p.Value }
      $console = New-Object System.Collections.ArrayList
      $global:LASTEXITCODE = -99
      $threw = ""
      $DebugPreference = "SilentlyContinue"
      try { & $script_ @argTable *>&1 | Out-String -Stream -Width 4096 | ForEach-Object { [void]$console.Add(([string]$_).TrimEnd()) } }
      catch { $threw = ("THREW: " + $_.Exception.Message) }
      $code = $global:LASTEXITCODE
      if ($null -ne $lockStream) { $lockStream.Dispose() }
      $tasksOut = @()
      foreach ($n in @($global:BmH.Tasks.Keys | Sort-Object)) {
        $t = $global:BmH.Tasks[$n]; $f = HTaskFacts $t.Xml
        $tasksOut += [ordered]@{ name = $n; enabled = [bool]$t.Enabled; withPw = [bool]$t.WithPw; userArg = [string]$t.UserArg; user = $f.User; logon = $f.LogonType; text = (@($f.Actions | ForEach-Object { "$($_.Execute) $($_.Arguments) $($_.WorkingDirectory)" }) -join " | ") }
      }
      $regOut = [ordered]@{}; foreach ($k in @($global:BmH.Reg.Keys | Sort-Object)) { $regOut[$k] = $global:BmH.Reg[$k] }
      $res.runs += [ordered]@{
        title = [string]$run.title; exit = $code; threw = $threw; console = @($console); log = @($global:BmH.Log); tasks = $tasksOut; reg = $regOut
        procs = @($global:BmH.Procs | ForEach-Object { "{0} {1} {2}" -f $_.Id, $_.Name, $_.Cmd }); sleeps = $global:BmH.Sleeps
        signedByModel = @($global:BmH.Signed.Keys)
      }
    }
  } catch {
    $m = "$($_.Exception.Message)"
    if ($m -like "CENSUS:*") { $res.census = $m } else { $res.harnessError = $m + " | " + (("$($_.ScriptStackTrace)" -split "`n" | Select-Object -First 3) -join " / ") }
  }
  if ($plan.PSObject.Properties["stateFile"] -and [string]$plan.stateFile) {
    $st = [ordered]@{ regKeys = @($global:BmH.RegKeys.Keys); reg = $global:BmH.Reg; procs = @($global:BmH.Procs)
      tasks = @($global:BmH.Tasks.Keys | ForEach-Object { $x = $global:BmH.Tasks[$_]; [ordered]@{ name = $_; xml = $x.Xml; enabled = $x.Enabled; withPw = $x.WithPw; userArg = $x.UserArg } })
      signed = @($global:BmH.Signed.Keys | ForEach-Object { [ordered]@{ hash = $_; thumb = $global:BmH.Signed[$_].Thumb; ts = $global:BmH.Signed[$_].Ts } }) }
    [IO.File]::WriteAllText([string]$plan.stateFile, ($st | ConvertTo-Json -Depth 6), (New-Object Text.UTF8Encoding($false)))
  }
  [IO.File]::WriteAllText($ResultFile, ($res | ConvertTo-Json -Depth 8), (New-Object Text.UTF8Encoding($false)))
  exit 0
}

# ====================================================================================================================
# PARENT
# ====================================================================================================================
if ($PSVersionTable.PSVersion.Major -ne 5) { Write-Host "Run this suite under Windows PowerShell 5.1 (powershell.exe), the host a bay runs." -ForegroundColor Red; exit 2 }
# A 5.1 process started from PowerShell 7 inherits 7's module folders; keep only Windows PowerShell's own.
$env:PSModulePath = (@($env:PSModulePath -split ';' | Where-Object { $_ -and $_ -notmatch '(?i)\\PowerShell\\7|\\Documents\\PowerShell\\' }) -join ';')

$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
if ([string]::IsNullOrWhiteSpace($ToolScript)) { $ToolScript = Join-Path $RepoRoot "src\BayAgent\tools\Move-BayInstall.ps1" }
$ToolScript = (Resolve-Path $ToolScript).Path

$script:Pass = 0; $script:Fail = 0; $script:Failures = @()
function Assert-True([bool]$Cond, [string]$Msg) {
  if ($Cond) { $script:Pass++; Write-Host "  PASS  $Msg" }
  else { $script:Fail++; $script:Failures += $Msg; Write-Host "  FAIL  $Msg" -ForegroundColor Red }
}
function Section([string]$T) { Write-Host ""; Write-Host "== $T" -ForegroundColor Cyan }
# A check that throws (a file the tool should have made is missing) is counted as a FAILED check and the suite still
# ends with its RESULT line and exit 1. Measured: the sections after the one that threw do NOT run (the error leaves
# the outer try block), so a run with this line is read from its first failures.
trap { $script:Fail++; $script:Failures += ("the suite stopped on an error: " + $_.Exception.Message); Write-Host ("  FAIL  the suite stopped on an error: " + $_.Exception.Message) -ForegroundColor Red; continue }

# ------------------------------------------------------------------ lift the tool's functions and constants
$tok = $null; $err = $null
$toolAst = [System.Management.Automation.Language.Parser]::ParseFile($ToolScript, [ref]$tok, [ref]$err)
if (@($err).Count -gt 0) { Write-Host "the tool does not parse" -ForegroundColor Red; exit 1 }
foreach ($st in @($toolAst.EndBlock.Statements)) {
  if ($st -is [System.Management.Automation.Language.AssignmentStatementAst] -and $st.Left.Extent.Text -match '^\$Bm') { . ([scriptblock]::Create($st.Extent.Text)) }
}
foreach ($fd in @($toolAst.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $n.Parent -is [System.Management.Automation.Language.NamedBlockAst] }, $false))) {
  . ([scriptblock]::Create($fd.Extent.Text))
}

# ------------------------------------------------------------------ scratch: a unique folder of this run, under C:\Temp
$RunId = [guid]::NewGuid().ToString("N").Substring(0, 10)
$ScratchName = "bmt-" + $RunId
$S = Join-Path "C:\Temp" $ScratchName
[void][IO.Directory]::CreateDirectory($S)
$S = (Get-Item -LiteralPath $S).FullName.TrimEnd('\')
$Old = Join-Path $S "AllBirdies"
$New = Join-Path $S "AceOfClubs"
$JRoot = Join-Path $S "journal"
$Web = Join-Path $S "web"
$NewBoot = Join-Path $S "newboot"
$Marker = "BMTPW" + [guid]::NewGuid().ToString("N").Substring(0, 12)
$SecretMarker = "BMTSECRET" + [guid]::NewGuid().ToString("N").Substring(0, 12)
$Me = [Security.Principal.WindowsIdentity]::GetCurrent().Name
$AgentVersion = "1.7.0"
$OldFixtures = Join-Path $RepoRoot "tests\fixtures\old-bay"
$TasksMadeHere = @()

function New-AdminOnlyDir([string]$Path) {
  # A folder born admin-only (SYSTEM, Administrators and this account, not inheriting): what the tool now requires of the
  # folder the new bootstrap files are read from.
  $sec = New-Object System.Security.AccessControl.DirectorySecurity
  $sec.SetAccessRuleProtection($true, $false)
  foreach ($who in @("NT AUTHORITY\SYSTEM", "BUILTIN\Administrators", $Me)) { $sec.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($who, "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow"))) }
  [void][IO.Directory]::CreateDirectory($Path, $sec)
}
function Get-Dacl([string]$p) { if ([IO.Directory]::Exists($p)) { return (Get-BmDaclSddl $p) }; return "(absent)" }
function ConvertTo-JsonPath([string]$p) { return $p.Replace('\', '\\') }

function New-ModelTaskXml {
  # A definition written by the Task Scheduler's own serializer (Schedule.Service NewTask; nothing is registered).
  param([string]$Kind, [string]$Arguments, [string]$User, [int]$LogonType)
  $svc = New-Object -ComObject Schedule.Service
  $svc.Connect()
  $def = $svc.NewTask(0)
  $def.RegistrationInfo.Author = "BAY1KIOSK\admin"
  $def.Settings.Enabled = $true
  $def.Settings.MultipleInstances = 2
  if ($Kind -eq "logon") { $tr = $def.Triggers.Create(9); $tr.UserId = $User; $def.Principal.RunLevel = 0 }
  elseif ($Kind -eq "minute") { $tr = $def.Triggers.Create(1); $tr.StartBoundary = "2026-10-14T00:00:00"; $tr.Repetition.Interval = "PT1M"; $def.Principal.RunLevel = 1 }
  $def.Principal.UserId = $User
  $def.Principal.LogonType = $LogonType
  $a = $def.Actions.Create(0)
  $a.Path = "powershell.exe"
  $a.Arguments = $Arguments
  return [string]$def.XmlText
}

function Set-FakeInstall {
  # The bay as Setup-BayPC.ps1, Day0 and Update-BayAgent.ps1 leave it, plus the history that matters to a move.
  $ba = Join-Path $Old "BayAgent"; $sd = Join-Path $Old "SessionDisplay"
  foreach ($d in @("bootstrap", "tools", "releases\$AgentVersion\kiosk", "rollback\current", "staging", "logs", "state", "control", "secrets")) { [void][IO.Directory]::CreateDirectory((Join-Path $ba $d)) }
  foreach ($d in @("current", "releases\1.0.0", "staging", "data\promos", "edge-profile\Default")) { [void][IO.Directory]::CreateDirectory((Join-Path $sd $d)) }
  # the old root's own access rules, distinctive: an explicit rule for Users
  $acl = Get-Acl -LiteralPath $Old
  $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule("BUILTIN\Users", "Modify", "ContainerInherit,ObjectInherit", "None", "Allow")))
  Set-Acl -LiteralPath $Old -AclObject $acl
  # the old bay's bootstrap scripts (they still name C:\AllBirdies: that is what is on a bay at the old root). They are
  # committed under tests\fixtures\old-bay (copied from the 1.6.1 release, signature block removed), because the release
  # under test renamed the repository's own files to AOC.*.
  foreach ($b in @("ABG.AgentHost.ps1", "ABG.HostWatchdog.ps1", "ABG.LauncherShell.ps1")) { [IO.File]::Copy((Join-Path $OldFixtures "$b.fixture"), (Join-Path $ba "bootstrap\$b")) }
  foreach ($t in @("Update-BayAgent.ps1", "Update-SessionDisplay.ps1", "Update-PromosPack.ps1", "Watch-BayAgentUpdate.ps1")) { [IO.File]::Copy((Join-Path $RepoRoot "src\BayAgent\tools\$t"), (Join-Path $ba "tools\$t")) }
  $rel = Join-Path $ba "releases\$AgentVersion"
  [IO.File]::WriteAllText((Join-Path $rel "BayAgent.ps1"), "# stand-in for the installed agent $AgentVersion`r`n")
  [IO.File]::WriteAllText((Join-Path $rel "manifest.json"), "{`r`n  `"version`": `"$AgentVersion`",`r`n  `"releasedUtc`": `"2026-10-15T00:00:00Z`"`r`n}")
  [IO.File]::Copy((Join-Path $RepoRoot "src\BayAgent\kiosk\kiosk-policy.json"), (Join-Path $rel "kiosk\kiosk-policy.json"))
  # current\ as the junction ABG.ReleaseFinalize.ps1 makes (releases\<v>); Update-BayAgent.ps1 turns it into a folder later
  Microsoft.PowerShell.Management\New-Item -ItemType Junction -Path (Join-Path $ba "current") -Value $rel | Out-Null
  [IO.File]::WriteAllText((Join-Path $ba "rollback\current\BayAgent.ps1"), "# the snapshot of the release before`r`n")
  # agent-config.json: the repository's own file, its placeholders filled, written as Day0 writes it (UTF-8 with a BOM)
  $cfg = [IO.File]::ReadAllText((Join-Path $OldFixtures "agent-config.json.fixture"))   # the old bay's file: it names C:\AllBirdies
  $cfg = $cfg.Replace('C:\\AllBirdies', (ConvertTo-JsonPath $Old)).Replace('C:/AllBirdies', $Old.Replace('\', '/'))
  $cfg = $cfg.Replace('https://<your-org-placeholder>.crm.dynamics.com', 'https://builds-apps-dev.crm.dynamics.com').Replace('<tenant-guid-placeholder>', '11111111-1111-1111-1111-111111111111').Replace('<app-client-id-placeholder>', '22222222-2222-2222-2222-222222222222').Replace('<bay-guid-placeholder>', '33333333-3333-3333-3333-333333333333')
  [IO.File]::WriteAllText((Join-Path $ba "agent-config.json"), $cfg, (New-Object Text.UTF8Encoding($true)))
  foreach ($f in @("credential.json", "emergency-stop.json", "agent-alive.json", "running-session.json", "bay-cert-ABCDEF.cer", "update-pending.done.json")) { [IO.File]::WriteAllText((Join-Path $ba "state\$f"), "{ `"f`": `"$f`" }") }
  [IO.File]::WriteAllText((Join-Path $ba "logs\BayAgent-20261014.log"), "2026-10-14T09:00:00Z [INFO] a log line`r`n")
  [IO.File]::WriteAllText((Join-Path $ba "control\restart.ack.20261014-090000.host"), "ack")
  # the secret file: a FAKE value, in a folder with the restricted rules ABG.SetClientSecretDpapi.ps1 gives it, and this
  # process is DENIED reading it: any read by the tool would fail the move.
  $sec = Join-Path $ba "secrets"
  $sa = Get-Acl -LiteralPath $sec
  $sa.SetAccessRuleProtection($true, $false)
  foreach ($who in @("NT AUTHORITY\SYSTEM", "BUILTIN\Administrators", $Me)) { $sa.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($who, "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow"))) }
  Set-Acl -LiteralPath $sec -AclObject $sa
  $sf = Join-Path $sec "clientsecret.dpapi"
  [IO.File]::WriteAllText($sf, $SecretMarker)
  $fa = Get-Acl -LiteralPath $sf
  $fa.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($Me, "ReadData", "Allow")))
  $fa.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($Me, "ReadData", "Deny")))
  Set-Acl -LiteralPath $sf -AclObject $fa
  # SessionDisplay
  [IO.File]::WriteAllText((Join-Path $sd "current\index.html"), "<html>wall</html>")
  [IO.File]::WriteAllText((Join-Path $sd "data\session.json"), '{"status":"idle","updatedUtc":""}')
  [IO.File]::WriteAllText((Join-Path $sd "data\promos.json"), '{ "promos": [] }')
  [IO.File]::WriteAllText((Join-Path $sd "data\session-display.state.json"), '{}')
  [IO.File]::WriteAllText((Join-Path $sd "edge-profile\Default\Preferences"), '{"profile":{"name":"wall"}}')
  [IO.File]::WriteAllText((Join-Path $sd "edge-profile\Local State"), '{}')
  # the release's new bootstrap files: the repository's own AOC.* scripts (root-derived, what the release ships), without
  # any signature block (the tool signs them on the bay)
  New-AdminOnlyDir $NewBoot; [void][IO.Directory]::CreateDirectory($Web)
  foreach ($b in @("AgentHost", "HostWatchdog", "LauncherShell")) {
    $t = [IO.File]::ReadAllText((Join-Path $RepoRoot "src\BayAgent\bootstrap\AOC.$b.ps1"))
    $t = ($t -split '# SIG # Begin signature block')[0]
    [IO.File]::WriteAllText((Join-Path $NewBoot "AOC.$b.ps1"), $t)
    [IO.File]::WriteAllText((Join-Path $Web "AOC.$b.ps1"), $t)
  }
}

function Get-Snapshot {
  # What a bay is, read back: every entry under both roots (names, sizes, times, link targets), the access rules of the
  # roots and the secret folder, and the bytes of the configuration and the bootstrap files.
  $o = [ordered]@{}
  $o.oldTree = @(Get-BmTreeManifest $Old) -join "`n"
  $o.newTree = @(Get-BmTreeManifest $New) -join "`n"
  $o.oldExists = [IO.Directory]::Exists($Old); $o.newExists = [IO.Directory]::Exists($New)
  $o.oldDacl = $(if ($o.oldExists) { Get-BmDaclSddl $Old } else { "" })
  $o.secretsDacl = $(if ([IO.Directory]::Exists((Join-Path $Old "BayAgent\secrets"))) { Get-BmDaclSddl (Join-Path $Old "BayAgent\secrets") } else { "" })
  $cfgP = Join-Path $Old "BayAgent\agent-config.json"
  $o.cfgSha = $(if ([IO.File]::Exists($cfgP)) { (Get-FileHash -LiteralPath $cfgP -Algorithm SHA256).Hash } else { "" })
  $o.bootSha = (@(Get-ChildItem -LiteralPath (Join-Path $Old "BayAgent\bootstrap") -File -ErrorAction SilentlyContinue | Sort-Object Name | ForEach-Object { $_.Name + "=" + (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash }) -join ";")
  $o.currentTarget = Get-BmLinkTarget (Join-Path $Old "BayAgent\current")
  return $o
}

function Invoke-Harness([string]$Name, [object[]]$Runs, $Model, [string]$StateFile = "") {
  $planFile = Join-Path $S ("plan-" + $Name + ".json")
  $resultFile = Join-Path $S ("result-" + $Name + ".json")
  $p = [ordered]@{ marker = $Marker; web = $Web; regKeys = $Model.regKeys; reg = $Model.reg; tasks = $Model.tasks; procs = $Model.procs; signed = $Model.signed; stateFile = $StateFile; runs = @($Runs) }
  [IO.File]::WriteAllText($planFile, ($p | ConvertTo-Json -Depth 10))
  $psExe = Join-Path $env:WINDIR "System32\WindowsPowerShell\v1.0\powershell.exe"
  & $psExe -NoProfile -ExecutionPolicy Bypass -File $PSCommandPath -Child -ToolScript $ToolScript -PlanFile $planFile -ResultFile $resultFile -Scratch $S | Out-Null
  if (-not (Test-Path -LiteralPath $resultFile)) { return [pscustomobject]@{ census = "NO RESULT FILE"; harnessError = ""; runs = @() } }
  $r = [IO.File]::ReadAllText($resultFile) | ConvertFrom-Json
  if ($EvidenceDir) {
    $lines = @()
    foreach ($x in @($r.runs)) {
      $lines += ("######## " + $x.title + "  (exit " + $x.exit + ")")
      $lines += @($x.console | ForEach-Object { ([string]$_).Replace($Old, "C:\AllBirdies").Replace($New, "C:\AceOfClubs").Replace($JRoot, "C:\ProgramData\AceOfClubs\BayMove").Replace($S, "<scratch>") })
      $lines += "---- recorded machine calls"
      $lines += @($x.log | ForEach-Object { ([string]$_).Replace($Old, "C:\AllBirdies").Replace($New, "C:\AceOfClubs").Replace($S, "<scratch>") })
    }
    [IO.File]::WriteAllLines((Join-Path $EvidenceDir ("console-" + $Name + ".txt")), [string[]]$lines)
  }
  return $r
}

function Get-Run($R, [int]$I) { $runs = @($R.runs); if ($I -lt $runs.Count) { return $runs[$I] }; return [pscustomobject]@{ title = "(missing)"; exit = -1; threw = ""; console = @(); log = @(); tasks = @(); reg = [pscustomobject]@{}; procs = @(); sleeps = 0; signedByModel = @() } }
function Get-Console($Run) { return (@($Run.console) -join "`n") }
function Get-RunTask($Run, [string]$Name) { foreach ($t in @($Run.tasks)) { if ($t.name -eq $Name) { return $t } }; return $null }
function Get-RegVal($Run, [string]$Key) { $p = $Run.reg.PSObject.Properties[$Key.ToLowerInvariant()]; if ($null -eq $p) { return $null }; return $p.Value }

$WinlogonKey = "registry::hkey_local_machine\software\microsoft\windows nt\currentversion\winlogon"
$Sid = "S-1-5-21-1111111111-2222222222-3333333333-1001"
$KioskWinlogon = "registry::hkey_users\$Sid\software\microsoft\windows nt\currentversion\winlogon"
$ShellOld = 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -NoProfile -WindowStyle Hidden -File "' + $Old + '\BayAgent\bootstrap\ABG.LauncherShell.ps1"'
$ShellNew = 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -NoProfile -WindowStyle Hidden -File "' + $New + '\BayAgent\bootstrap\AOC.LauncherShell.ps1"'

function New-Model([int]$AgentLogon = 1) {
  $agentArgs = '-NoProfile -WindowStyle Minimized -File "' + $Old + '\BayAgent\bootstrap\ABG.AgentHost.ps1"'
  $dogArgs = '-NoProfile -File "' + $Old + '\BayAgent\bootstrap\ABG.HostWatchdog.ps1"'
  return [ordered]@{
    regKeys = @($WinlogonKey, "registry::hkey_users\$Sid", $KioskWinlogon)
    reg = [ordered]@{ ($WinlogonKey + "|shell") = $ShellOld; ($WinlogonKey + "|autoadminlogon") = "1" }
    tasks = @(
      [ordered]@{ name = "ABG Bay Agent"; xml = (New-ModelTaskXml -Kind "logon" -Arguments $agentArgs -User "BAY1KIOSK\BayKiosk" -LogonType $AgentLogon) },
      [ordered]@{ name = "ABG Host Watchdog"; xml = (New-ModelTaskXml -Kind "minute" -Arguments $dogArgs -User "S-1-5-18" -LogonType 5) },
      [ordered]@{ name = "OneDrive Standalone Update Task"; xml = (New-ModelTaskXml -Kind "logon" -Arguments "/reporting" -User "BAY1KIOSK\admin" -LogonType 3) }
    )
    procs = @(
      [ordered]@{ id = 4100; name = "powershell.exe"; cmd = ('powershell.exe ' + $agentArgs); exe = "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"; session = 1; user = "BAY1KIOSK\BayKiosk" },
      [ordered]@{ id = 4200; name = "powershell.exe"; cmd = ('powershell.exe -NoProfile -WindowStyle Minimized -File "' + $Old + '\BayAgent\current\BayAgent.ps1"'); exe = "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"; session = 1; user = "BAY1KIOSK\BayKiosk" },
      [ordered]@{ id = 4300; name = "msedge.exe"; cmd = ('msedge.exe --kiosk --user-data-dir=' + $Old + '\SessionDisplay\edge-profile file:///' + $Old.Replace('\', '/') + '/SessionDisplay/current/index.html'); exe = "C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe"; session = 1; user = "BAY1KIOSK\BayKiosk" },
      [ordered]@{ id = 4400; name = "explorer.exe"; cmd = "C:\Windows\explorer.exe"; exe = "C:\Windows\explorer.exe"; session = 1; user = "BAY1KIOSK\BayKiosk" },
      [ordered]@{ id = 5100; name = "powershell.exe"; cmd = "powershell.exe -NoProfile -ExecutionPolicy Bypass -File C:\BayMove\Move-BayInstall.ps1"; exe = "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"; session = 2; user = "BAY1KIOSK\admin" }
    )
    signed = @((Join-Path $Old "BayAgent\bootstrap\ABG.AgentHost.ps1"), (Join-Path $Old "BayAgent\bootstrap\ABG.HostWatchdog.ps1"), (Join-Path $Old "BayAgent\bootstrap\ABG.LauncherShell.ps1"), (Join-Path $Old "BayAgent\releases\$AgentVersion\BayAgent.ps1"))
  }
}

function Get-MoveArgs([string]$Mode, [hashtable]$Extra = @{}) {
  $a = [ordered]@{ Mode = $Mode; OldRoot = $Old; NewRoot = $New; JournalRoot = $JRoot; JournalTrustStop = $S; JournalExtraTrustedSid = @([Security.Principal.WindowsIdentity]::GetCurrent().User.Value); ExpectAgentVersion = $AgentVersion; BootstrapSource = $NewBoot; StopTimeoutSeconds = 10 }
  foreach ($k in @($Extra.Keys)) { $a[$k] = $Extra[$k] }
  return $a
}

function Remove-Scratch {
  # Only the folder this run created, checked by its own unique name right before; every link inside is removed on its
  # own first (never followed), and the deny rule on the fake secret is lifted so it can be deleted.
  if ([IO.Path]::GetFileName($S) -ne $ScratchName -or -not $S.StartsWith("C:\Temp\bmt-", [StringComparison]::OrdinalIgnoreCase)) { Write-Host "cleanup refused: $S" -ForegroundColor Red; return }
  if (-not [IO.Directory]::Exists($S)) { return }
  $root = Get-Item -LiteralPath $S -Force
  if (($root.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { Write-Host "cleanup refused: $S is a link" -ForegroundColor Red; return }
  foreach ($e in @(Microsoft.PowerShell.Management\Get-ChildItem -LiteralPath $S -Recurse -Force -Attributes ReparsePoint -ErrorAction SilentlyContinue)) {
    try { [IO.Directory]::Delete($e.FullName, $false) } catch { }
  }
  foreach ($f in @(Microsoft.PowerShell.Management\Get-ChildItem -LiteralPath $S -Recurse -Force -Filter "clientsecret.dpapi" -ErrorAction SilentlyContinue)) {
    try { $a = Get-Acl -LiteralPath $f.FullName; foreach ($r in @($a.Access | Where-Object { $_.AccessControlType -eq "Deny" })) { [void]$a.RemoveAccessRule($r) }; Set-Acl -LiteralPath $f.FullName -AclObject $a } catch { }
  }
  if ([IO.Path]::GetFileName($S) -eq $ScratchName) { [IO.Directory]::Delete($S, $true) }
}

try {
  # =================================================================================================================
  Section "A. the tool's functions"
  # A function that returns its array behind a leading comma comes back as ONE item inside @(...) (Windows PowerShell
  # 5.1 and 7 alike). The tool wraps calls in @(...), so such a function may not be called that way. Found on this
  # tool's first run (the configuration check could not run at all); checked here on the text, not remembered.
  $commaFns = @($toolAst.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $true) | Where-Object {
      @($_.Body.FindAll({ param($n) $n -is [System.Management.Automation.Language.ReturnStatementAst] -and $null -ne $n.Pipeline -and $n.Pipeline.Extent.Text -match '^\s*,' }, $true)).Count -gt 0 } | ForEach-Object { $_.Name })
  $wrapped = @()
  foreach ($fn in $commaFns) {
    $calls = @($toolAst.FindAll({ param($n) $n -is [System.Management.Automation.Language.CommandAst] -and $n.GetCommandName() -eq $fn }, $true))
    foreach ($c in $calls) { $p = $c.Parent; while ($null -ne $p -and -not ($p -is [System.Management.Automation.Language.StatementBlockAst]) -and -not ($p -is [System.Management.Automation.Language.NamedBlockAst])) { $p = $p.Parent }; if ($null -ne $p -and $p.Parent -is [System.Management.Automation.Language.ArrayExpressionAst]) { $wrapped += ("{0} (line {1})" -f $fn, $c.Extent.StartLineNumber) } }
  }
  Assert-True ($wrapped.Count -eq 0) ("no function that returns behind a leading comma is called inside @(...) (" + ($wrapped -join ", ") + "; comma-returning functions: " + ($commaFns -join ",") + ")")
  $o = "C:\AllBirdies"; $n = "C:\AceOfClubs"
  $cases = @(
    @('-File "C:\AllBirdies\BayAgent\bootstrap\ABG.AgentHost.ps1"', '-File "C:\AceOfClubs\BayAgent\bootstrap\AOC.AgentHost.ps1"', "a task's -File, with the bootstrap file name mapped"),
    @('"C:\\AllBirdies\\SessionDisplay\\edge-profile"', '"C:\\AceOfClubs\\SessionDisplay\\edge-profile"', "a JSON-escaped path keeps its escaping"),
    @('file:///C:/AllBirdies/SessionDisplay/current/index.html', 'file:///C:/AceOfClubs/SessionDisplay/current/index.html', "a file address keeps its forward slashes"),
    @('c:\allbirdies\BayAgent\tools\Update-BayAgent.ps1', 'C:\AceOfClubs\BayAgent\tools\Update-BayAgent.ps1', "letter case does not hide a mention"),
    @('C:\AllBirdiesOld\x', 'C:\AllBirdiesOld\x', "a longer name is not the root"),
    @('https://allbirdies.example/C:/x', 'https://allbirdies.example/C:/x', "a web address is not a folder"),
    @('"C:\\AllBirdies\\BayAgent\\bootstrap\\ABG.LauncherShell.ps1"', '"C:\\AceOfClubs\\BayAgent\\bootstrap\\AOC.LauncherShell.ps1"', "the kiosk shell path in JSON, name mapped"),
    @('C:\AllBirdies\BayAgent\tools\ABG.AgentHost.ps1', 'C:\AceOfClubs\BayAgent\tools\ABG.AgentHost.ps1', "a file name is mapped only under bootstrap"),
    @('C:\AllBirdies', 'C:\AceOfClubs', "the root alone")
  )
  foreach ($c in $cases) {
    $got = (Convert-BmPathText -Text $c[0] -From $o -To $n -NameMap $BmBootstrapNameMap).Text
    Assert-True ($got -ceq $c[1]) ("path text: " + $c[2] + " (got: " + $got + ")")
  }
  Assert-True ((Test-BmNamesRoot 'x "C:\AllBirdies\BayAgent" y' $o) -and -not (Test-BmNamesRoot 'C:\AllBirdiesX' $o) -and -not (Test-BmNamesRoot 'https://allbirdies.x' $o)) "Test-BmNamesRoot: a mention, not a longer name, not a web address"

  $realCfg = [IO.File]::ReadAllText((Join-Path $OldFixtures "agent-config.json.fixture"))   # the old bay's own file (it names the old root)
  $cc = Convert-BmConfigText -Text $realCfg -From $o -To $n -NameMap $BmBootstrapNameMap
  $changed = @($cc.Changes | ForEach-Object { $_.Path }) -join ","
  Assert-True ($changed -eq ".clientSecretDpapiPath,.sessionJsonPath,.sessionDisplay.url,.sessionDisplay.profileDir,.kiosk.shell") ("the repository's agent-config.json: exactly the five values that name the root change (" + $changed + ")")
  Assert-True (($cc.Text.Length - $realCfg.Length) -eq (5 * ("AceOfClubs".Length - "AllBirdies".Length) + ("AOC".Length - "ABG".Length))) "...and nothing else in the text changes (length differs by exactly the five renames)"
  Assert-True ($cc.Text.Contains('"C:\\AceOfClubs\\BayAgent\\bootstrap\\AOC.LauncherShell.ps1"') -and $cc.Text.Contains('"url": "file:///C:/AceOfClubs/SessionDisplay/current/index.html"')) "...the kiosk shell gets the new file name and the wall address keeps its form"
  $back = Convert-BmConfigText -Text $cc.Text -From $n -To $o -NameMap (Get-BmReverseMap $BmBootstrapNameMap)
  Assert-True ($back.Text -ceq $realCfg) "...and the way back gives the original text, byte for byte"
  $threwShape = $false
  try { [void](Convert-BmConfigText -Text '{"a":"C:\\AllBirdies\\x","b":"y"' -From $o -To $n -NameMap $null) } catch { $threwShape = $true }
  Assert-True $threwShape "a configuration that does not parse is refused, not rewritten"

  $agentXml = New-ModelTaskXml -Kind "logon" -Arguments '-NoProfile -WindowStyle Minimized -File "C:\AllBirdies\BayAgent\bootstrap\ABG.AgentHost.ps1"' -User "BAY1KIOSK\BayKiosk" -LogonType 1
  $tx = Convert-BmTaskXml -Xml $agentXml -From $o -To $n -NameMap $BmBootstrapNameMap -NewName "AOC Bay Agent" -Enabled $false
  $f1 = Get-BmTaskXmlFacts $agentXml; $f2 = Get-BmTaskXmlFacts $tx.Xml
  Assert-True ($tx.Changed -eq 1 -and @($f2.Files)[0] -eq "C:\AceOfClubs\BayAgent\bootstrap\AOC.AgentHost.ps1") ("a task definition from the Task Scheduler's own serializer: the -File path moves and takes the new name (" + (@($f2.Files) -join ",") + ")")
  Assert-True ($f2.User -eq $f1.User -and $f2.LogonType -eq "Password" -and $f2.NeedsPw -and -not $f2.Enabled -and $f1.Enabled) "...its account and sign-in kind are kept, it is registered disabled, and a Password task is known to need the password"
  $stripA = ($agentXml -replace '(?s)<Actions.*?</Actions>', '' -replace '<Enabled>[a-z]+</Enabled>', '' -replace '<URI>[^<]*</URI>', '' -replace '\s', '')
  $stripB = ($tx.Xml -replace '(?s)<Actions.*?</Actions>', '' -replace '<Enabled>[a-z]+</Enabled>', '' -replace '<URI>[^<]*</URI>', '' -replace '\s', '')
  Assert-True ($stripA -ceq $stripB) "...and nothing outside the actions, Enabled and the URI changes (triggers, settings, principal kept)"
  $dogXml = New-ModelTaskXml -Kind "minute" -Arguments '-NoProfile -File "C:\AllBirdies\BayAgent\bootstrap\ABG.HostWatchdog.ps1"' -User "S-1-5-18" -LogonType 5
  $fd = Get-BmTaskXmlFacts $dogXml
  Assert-True (@("", "ServiceAccount") -contains $fd.LogonType -and -not $fd.NeedsPw) ("the SYSTEM watchdog task needs no password (the serializer writes no LogonType for SYSTEM: '" + $fd.LogonType + "')")
  Assert-True ((ConvertTo-BmSid "SYSTEM") -eq "S-1-5-18" -and (ConvertTo-BmSid "NT AUTHORITY\SYSTEM") -eq "S-1-5-18") "an account compares by SID (SYSTEM written three ways is one account)"

  $mt = Join-Path $S "manifest-test"; [void][IO.Directory]::CreateDirectory((Join-Path $mt "a\b")); [IO.File]::WriteAllText((Join-Path $mt "a\b\f.txt"), "x")
  Microsoft.PowerShell.Management\New-Item -ItemType Junction -Path (Join-Path $mt "j") -Value (Join-Path $mt "a") | Out-Null
  $man = @(Get-BmTreeManifest $mt)
  Assert-True ($man.Count -eq 4 -and ($man -join "`n") -match '(?m)^j\|link\|0\|0\|' -and -not (($man -join "`n") -match '(?m)^j\\')) ("the tree listing lists a link with its target and does not walk into it (" + ($man -join " ; ") + ")")
  [IO.Directory]::Delete((Join-Path $mt "j"), $false)

  # =================================================================================================================
  Section "B1. Plan, Move, Verify, Back on a modeled bay"
  Set-FakeInstall
  $snap0 = Get-Snapshot
  $readable = $true
  try { [void][IO.File]::ReadAllText((Join-Path $Old "BayAgent\secrets\clientsecret.dpapi")) } catch { $readable = $false }
  Assert-True (-not $readable) "the fake secret file cannot be read by this process (so a read by the tool would fail it)"
  $model = New-Model -AgentLogon 1
  $boot = Join-Path $New "BayAgent\state\agent-alive.json"
  $machine = Join-Path $S "machine-main.json"
  $runs1 = @(
    [ordered]@{ title = "Plan"; args = (Get-MoveArgs "Plan"); answers = @() },
    [ordered]@{ title = "Move"; args = (Get-MoveArgs "Move"); answers = @("MOVE", "pw:good") })
  $runs2 = @(
    [ordered]@{ title = "Verify before the restart"; args = (Get-MoveArgs "Verify"); answers = @() },
    [ordered]@{ title = "Verify after a modeled restart"; args = (Get-MoveArgs "Verify"); answers = @(); touch = @($boot)
      addProcs = @(
        [ordered]@{ id = 6100; name = "powershell.exe"; cmd = ('powershell.exe -NoProfile -WindowStyle Minimized -File "' + $New + '\BayAgent\bootstrap\AOC.AgentHost.ps1"'); exe = ""; session = 1; user = "BAY1KIOSK\BayKiosk" },
        [ordered]@{ id = 6200; name = "powershell.exe"; cmd = ('powershell.exe -NoProfile -WindowStyle Minimized -File "' + $New + '\BayAgent\current\BayAgent.ps1"'); exe = ""; session = 1; user = "BAY1KIOSK\BayKiosk" }) },
    [ordered]@{ title = "Back"; args = (Get-MoveArgs "Back" @{ BootstrapSource = "" }); answers = @("BACK", "pw:good") }
  )
  $r = Invoke-Harness "main-move" $runs1 $model $machine
  Assert-True ($r.census -eq "ok" -and [string]::IsNullOrEmpty([string]$r.harnessError) -and @($r.runs).Count -eq 2) ("census ok, harness clean, Plan and Move ran (" + $r.census + " " + $r.harnessError + ")")
  $p = Get-Run $r 0; $mv = Get-Run $r 1

  Assert-True ($p.exit -eq 0 -and (Get-Console $p) -match 'RESULT: Move would proceed \(nothing was changed\)') ("Plan: exit 0 and says Move would proceed (" + $p.exit + " " + $p.threw + ")")
  Assert-True (@($p.log | Where-Object { $_ -notmatch '^PROMPT' }).Count -eq 0) ("Plan: no machine write was recorded (" + (@($p.log) -join " ; ") + ")")
  Assert-True ((Get-Console $p) -match 'move folder' -and (Get-Console $p) -match 're-point link BayAgent\\current' -and (Get-Console $p) -match 'task +\\ABG Bay Agent -> \\AOC Bay Agent \(account BAY1KIOSK\\BayKiosk, needs its password\)') "Plan: names the folders, the link, and each task with its account"

  $cm = Get-Console $mv
  Assert-True ($mv.exit -eq 0 -and $cm -match 'RESULT: MOVED to') ("Move: exit 0 and RESULT: MOVED (" + $mv.exit + " " + $mv.threw + ")")
  $snap1 = [ordered]@{ old = [IO.Directory]::Exists($Old); newBa = [IO.Directory]::Exists((Join-Path $New "BayAgent")); newSd = [IO.Directory]::Exists((Join-Path $New "SessionDisplay")) }
  Assert-True (-not $snap1.old -and $snap1.newBa -and $snap1.newSd) "Move: the old root is gone; BayAgent and SessionDisplay are under the new root"
  $ignore = @("bayagent\stop.host", "bayagent\agent-config.json", "bayagent\bootstrap\abg.agenthost.ps1", "bayagent\bootstrap\abg.hostwatchdog.ps1", "bayagent\bootstrap\abg.launchershell.ps1", "bayagent\bootstrap\aoc.agenthost.ps1", "bayagent\bootstrap\aoc.hostwatchdog.ps1", "bayagent\bootstrap\aoc.launchershell.ps1", "bayagent\current")
  $dOld = @(Compare-BmManifest @($snap0.oldTree -split "`n") @(Get-BmTreeManifest $New) $ignore)
  Assert-True ($dOld.Count -eq 0) ("Move: every other entry is under the new root with the same size and time, nothing extra (" + ($dOld -join "; ") + ")")
  Assert-True ((Get-Dacl $New) -eq $snap0.oldDacl) "Move: the new root has the old root's access rules"
  Assert-True ((Get-Dacl (Join-Path $New "BayAgent\secrets")) -eq $snap0.secretsDacl) "Move: the secret folder keeps its own restricted access rules"
  $sfNew = New-Object IO.FileInfo((Join-Path $New "BayAgent\secrets\clientsecret.dpapi"))
  Assert-True ($sfNew.Exists -and $sfNew.Length -eq $SecretMarker.Length) "Move: the fake secret file moved (same length) though this process may not read it"
  Assert-True ((Get-BmLinkTarget (Join-Path $New "BayAgent\current")) -eq (Join-Path $New "BayAgent\releases\$AgentVersion")) "Move: the current\ junction points into the new root"
  $cfgNew = Read-BmBytesAsText (Join-Path $New "BayAgent\agent-config.json")
  $cfgObj = $cfgNew.Text | ConvertFrom-Json
  Assert-True ($cfgNew.Bom -and $cfgObj.sessionDisplay.profileDir -eq (Join-Path $New "SessionDisplay\edge-profile") -and $cfgObj.clientSecretDpapiPath -eq (Join-Path $New "BayAgent\secrets\clientsecret.dpapi") -and $cfgObj.kiosk.shell -eq (Join-Path $New "BayAgent\bootstrap\AOC.LauncherShell.ps1") -and $cfgObj.sessionDisplay.url -eq ("file:///" + $New.Replace('\', '/') + "/SessionDisplay/current/index.html") -and $cfgObj.bayId -eq "33333333-3333-3333-3333-333333333333") "Move: agent-config.json names the new root in all five places, keeps its byte-order mark and every other value"
  Assert-True (-not (Test-BmNamesRoot $cfgNew.Text $Old)) "Move: agent-config.json no longer names the old root anywhere"
  $bsNew = @(Get-ChildItem -LiteralPath (Join-Path $New "BayAgent\bootstrap") -File | ForEach-Object { $_.Name } | Sort-Object) -join ","
  Assert-True ($bsNew -eq "AOC.AgentHost.ps1,AOC.HostWatchdog.ps1,AOC.LauncherShell.ps1") ("Move: bootstrap holds the three new-named files and no old one (" + $bsNew + ")")
  $signedOk = $true
  foreach ($bn in @("AOC.AgentHost.ps1", "AOC.HostWatchdog.ps1", "AOC.LauncherShell.ps1")) { if (@($mv.signedByModel) -notcontains (Get-FileHash -LiteralPath (Join-Path $New "BayAgent\bootstrap\$bn") -Algorithm SHA256).Hash) { $signedOk = $false } }
  Assert-True ($signedOk -and @($mv.log | Where-Object { $_ -match '^SIGN +AOC\..* with ' + ("AB" * 20) }).Count -eq 3) "Move: each new bootstrap file was signed with the certificate that signed the old ones"
  $ta = Get-RunTask $mv "AOC Bay Agent"; $tw = Get-RunTask $mv "AOC Host Watchdog"
  Assert-True ($null -eq (Get-RunTask $mv "ABG Bay Agent") -and $null -eq (Get-RunTask $mv "ABG Host Watchdog")) "Move: the two old tasks are gone"
  Assert-True ($null -ne $ta -and $ta.enabled -and $ta.text -match [regex]::Escape($New + '\BayAgent\bootstrap\AOC.AgentHost.ps1') -and $ta.user -eq "BAY1KIOSK\BayKiosk" -and $ta.logon -eq "Password" -and $ta.withPw) "Move: \AOC Bay Agent is enabled, starts the new AgentHost, same account and sign-in kind, registered with the typed password"
  Assert-True ($null -ne $tw -and $tw.enabled -and $tw.text -match [regex]::Escape($New + '\BayAgent\bootstrap\AOC.HostWatchdog.ps1') -and $tw.user -eq "S-1-5-18" -and -not $tw.withPw -and $tw.userArg -eq "") "Move: \AOC Host Watchdog is enabled, starts the new watchdog, still SYSTEM, no password and no account argument"
  Assert-True ($null -ne (Get-RunTask $mv "OneDrive Standalone Update Task")) "Move: a task that does not name the root is left alone"
  Assert-True ((Get-RegVal $mv ($WinlogonKey + "|shell")) -eq $ShellNew) "Move: the Winlogon Shell starts the new-named launcher shell under the new root"
  Assert-True (@($mv.log | Where-Object { $_ -eq "SESSION logoff 1" }).Count -eq 1 -and @($mv.procs | Where-Object { $_ -match '^4[1-4]00 ' }).Count -eq 0 -and @($mv.procs | Where-Object { $_ -match '^5100 ' }).Count -eq 1) "Move: BayKiosk's session (1) was signed out; the administrator's session was not touched"
  Assert-True (@($mv.log | Where-Object { $_ -match '^PROCESS stop' }).Count -eq 0) "Move: no process was stopped (signing out was enough)"
  $iReg = [array]::IndexOf(@($mv.log), (@($mv.log | Where-Object { $_ -match '^TASK +register \\AOC Bay Agent enabled=False' }) | Select-Object -First 1))
  $iLogoff = [array]::IndexOf(@($mv.log), "SESSION logoff 1")
  Assert-True ($iReg -ge 0 -and $iLogoff -gt $iReg) "Move: the new tasks were registered (and a wrong password would have failed) BEFORE the bay was stopped"
  Assert-True (-not [IO.File]::Exists((Join-Path $New "BayAgent\stop.host"))) "Move: stop.host is gone at the end"
  $jDirs = @([IO.Directory]::GetDirectories($JRoot) | Where-Object { $_ -match '-move$' })
  $jj = $(if ($jDirs.Count -eq 1) { [IO.File]::ReadAllText((Join-Path $jDirs[0] "journal.json")) | ConvertFrom-Json } else { $null })
  Assert-True ($null -ne $jj -and $jj.state -eq "moved" -and [IO.File]::Exists((Join-Path $jDirs[0] "replaced-bootstrap\ABG.AgentHost.ps1")) -and [IO.File]::Exists((Join-Path $jDirs[0] "task-ABG_Bay_Agent.xml"))) "Move: one journal, state moved, holding the old bootstrap files and the old task definitions"

  # Security review: a journal in a folder a standard user can write is refused by Back (its saved files are put back as
  # scripts that run as SYSTEM). The folder the Move just made is admin-only; open it to BUILTIN\Users, try Back, close it again.
  $jd0 = @([IO.Directory]::GetDirectories($JRoot) | Where-Object { $_ -match '-move$' } | Sort-Object -Descending)[0]
  $jdAclSaved = Get-Acl -LiteralPath $jd0
  $jdAclOpen = Get-Acl -LiteralPath $jd0
  $jdAclOpen.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule("BUILTIN\Users", "Modify", "ContainerInherit,ObjectInherit", "None", "Allow")))
  Set-Acl -LiteralPath $jd0 -AclObject $jdAclOpen
  $snapPl0 = Get-Snapshot
  $rpl = Invoke-Harness "planted-journal" @([ordered]@{ title = "Back with a journal a standard user can write"; args = (Get-MoveArgs "Back" @{ BootstrapSource = "" }); answers = @("BACK", "pw:good") }) $model $machine
  Set-Acl -LiteralPath $jd0 -AclObject $jdAclSaved
  $xpl = Get-Run $rpl 0
  $snapPl1 = Get-Snapshot
  Assert-True ($xpl.exit -eq 1 -and (Get-Console $xpl) -match 'not in an admin-only folder' -and @($xpl.log | Where-Object { $_ -notmatch '^(PROMPT|SIGN|DOWNLOAD)' }).Count -eq 0 -and $snapPl1.newTree -eq $snapPl0.newTree) ("Back refuses a journal in a folder BUILTIN\Users can write, and changes nothing (exit " + $xpl.exit + ")")
  $r2 = Invoke-Harness "main-back" $runs2 $model $machine
  Assert-True ($r2.census -eq "ok" -and [string]::IsNullOrEmpty([string]$r2.harnessError) -and @($r2.runs).Count -eq 3) ("harness clean, Verify, Verify and Back ran on the same modeled machine (" + $r2.harnessError + ")")
  $v1 = Get-Run $r2 0; $v2 = Get-Run $r2 1; $bk = Get-Run $r2 2
  Assert-True ($v1.exit -eq 1 -and (Get-Console $v1) -match 'RESULT: NOT VERIFIED' -and (Get-Console $v1) -match 'no BayAgent.ps1 runs') "Verify before the restart: NOT VERIFIED (no agent runs yet)"
  Assert-True ($v2.exit -eq 0 -and (Get-Console $v2) -match 'RESULT: VERIFIED') ("Verify after a modeled restart: VERIFIED (" + $v2.exit + ")")

  $cb = Get-Console $bk
  Assert-True ($bk.exit -eq 0 -and $cb -match 'RESULT: MOVED to') ("Back: exit 0 (" + $bk.exit + " " + $bk.threw + ")")
  $snap2 = Get-Snapshot
  $dBack = @(Compare-BmManifest @($snap0.oldTree -split "`n") @($snap2.oldTree -split "`n") @("bayagent\state\agent-alive.json", "bayagent\stop.host", "bayagent\agent-config.json"))
  Assert-True ($snap2.oldExists -and -not [IO.Directory]::Exists((Join-Path $New "BayAgent")) -and $dBack.Count -eq 0) ("Back: the install is under the old root again, every entry as it was (" + ($dBack -join "; ") + ")")
  Assert-True ($snap2.cfgSha -eq $snap0.cfgSha) "Back: agent-config.json is byte for byte what it was before the Move (its write time is new: Back writes it)"
  Assert-True ($snap2.bootSha -eq $snap0.bootSha) "Back: the bootstrap folder holds exactly the original files, byte for byte (signatures intact)"
  Assert-True ($snap2.oldDacl -eq $snap0.oldDacl -and $snap2.secretsDacl -eq $snap0.secretsDacl) "Back: the old root and the secret folder have their original access rules"
  Assert-True ($snap2.currentTarget -eq $snap0.currentTarget) "Back: the current\ junction points where it did"
  $tb = Get-RunTask $bk "ABG Bay Agent"; $twb = Get-RunTask $bk "ABG Host Watchdog"
  Assert-True ($null -ne $tb -and $tb.enabled -and $tb.text -match [regex]::Escape($Old + '\BayAgent\bootstrap\ABG.AgentHost.ps1') -and $tb.logon -eq "Password" -and $null -ne $twb -and $twb.enabled -and $twb.user -eq "S-1-5-18" -and $null -eq (Get-RunTask $bk "AOC Bay Agent") -and $null -eq (Get-RunTask $bk "AOC Host Watchdog")) "Back: the two original tasks are back and enabled; the new ones are gone"
  Assert-True ((Get-RegVal $bk ($WinlogonKey + "|shell")) -eq $ShellOld) "Back: the Winlogon Shell is the original value"
  Assert-True (-not [IO.Directory]::Exists($New)) "Back: the new root is removed (it was empty)"

  $allText = (@(@($r.runs) + @($r2.runs) | ForEach-Object { (@($_.console) + @($_.log)) -join "`n" }) -join "`n")
  $jText = (@(Get-ChildItem -LiteralPath $JRoot -Recurse -File | Where-Object { $_.Extension -in ".json", ".txt", ".xml" } | ForEach-Object { [IO.File]::ReadAllText($_.FullName) }) -join "`n")
  Assert-True (-not $allText.Contains($Marker) -and -not $jText.Contains($Marker)) "the typed password appears in no console line, no recorded call, no journal or log file"
  Assert-True (-not $allText.Contains($SecretMarker) -and -not $jText.Contains($SecretMarker)) "the fake secret's content appears nowhere the tool wrote or printed"

  # =================================================================================================================
  Section "B2. a failure at each stage of a Move puts back everything already done"
  $failCases = @(
    @{ name = "wrong-password"; why = "the typed password is wrong (the first write)"; answers = @("MOVE", "pw:wrong"); inject = @{} },
    @{ name = "stop-other-process"; why = "a program that is not the bay's own keeps a file under the old root open"; answers = @("MOVE", "pw:good"); inject = @{}
       addProcs = @([ordered]@{ id = 7100; name = "notepad.exe"; cmd = ('notepad.exe ' + $Old + '\BayAgent\logs\BayAgent-20261014.log'); exe = "C:\Windows\notepad.exe"; session = 2; user = "BAY1KIOSK\admin" }) },
    @{ name = "folder-locked"; why = "a file in SessionDisplay is held open (the second folder cannot move)"; answers = @("MOVE", "pw:good"); inject = @{}; lockFile = (Join-Path $Old "SessionDisplay\data\session.json") },
    @{ name = "winlogon"; why = "the Winlogon Shell write is refused"; answers = @("MOVE", "pw:good"); inject = @{ "setreg:Shell" = "Requested registry access is not allowed." } },
    @{ name = "enable"; why = "enabling the new agent task fails"; answers = @("MOVE", "pw:good"); inject = @{ "enable:AOC Bay Agent" = "Access is denied." } },
    @{ name = "unregister-old"; why = "removing the old watchdog task fails"; answers = @("MOVE", "pw:good"); inject = @{ "unregister:ABG Host Watchdog" = "Access is denied." } },
    @{ name = "done-check"; why = "the last check of done finds the new task under another account"; answers = @("MOVE", "pw:good"); inject = @{ "export-user:AOC Bay Agent" = "x" } }
  )
  foreach ($fc in $failCases) {
    Remove-Scratch; [void][IO.Directory]::CreateDirectory($S); Set-FakeInstall
    $s0 = Get-Snapshot
    $run = [ordered]@{ title = $fc.name; args = (Get-MoveArgs "Move"); answers = $fc.answers; inject = $fc.inject }
    if ($fc.ContainsKey("addProcs")) { $run.addProcs = $fc.addProcs }
    if ($fc.ContainsKey("lockFile")) { $run.lockFile = $fc.lockFile }
    $rf = Invoke-Harness ("fail-" + $fc.name) @($run) (New-Model -AgentLogon 1)
    $x = Get-Run $rf 0
    $s1 = Get-Snapshot
    $tasksBack = ($null -ne (Get-RunTask $x "ABG Bay Agent") -and (Get-RunTask $x "ABG Bay Agent").enabled -and $null -ne (Get-RunTask $x "ABG Host Watchdog") -and (Get-RunTask $x "ABG Host Watchdog").enabled -and $null -eq (Get-RunTask $x "AOC Bay Agent") -and $null -eq (Get-RunTask $x "AOC Host Watchdog"))
    $why = @()
    $why += @(Compare-BmManifest @($s0.oldTree -split "`n") @($s1.oldTree -split "`n") @())
    if ([IO.Directory]::Exists($New)) { $why += "the new root exists" }
    if ($s1.cfgSha -ne $s0.cfgSha) { $why += "configuration bytes" }
    if ($s1.bootSha -ne $s0.bootSha) { $why += "bootstrap bytes" }
    if ($s1.oldDacl -ne $s0.oldDacl) { $why += "old root access rules" }
    if ($s1.secretsDacl -ne $s0.secretsDacl) { $why += "secret folder access rules" }
    if ($s1.currentTarget -ne $s0.currentTarget) { $why += "current link target" }
    if ((Get-RegVal $x ($WinlogonKey + "|shell")) -ne $ShellOld) { $why += "Winlogon Shell" }
    $same = ($why.Count -eq 0)
    Assert-True ($x.exit -eq 2 -and (Get-Console $x) -match 'RESULT: FAILED and everything was put back') ("{0}: exit 2, everything put back (exit {1} {2})" -f $fc.why, $x.exit, $x.threw)
    Assert-True ($same -and $tasksBack) ("{0}: the bay is exactly as before (tree with sizes and times, configuration, bootstrap, access rules, link, Winlogon, tasks) {1}" -f $fc.why, ($why -join "; "))
    if ($fc.name -eq "stop-other-process") { Assert-True (@($x.log | Where-Object { $_ -match '^PROCESS stop 7100' }).Count -eq 0) "...and the other program's process was never stopped" }
  }

  Section "B3. the bay program's own process left running from the old root is stopped by its id"
  Remove-Scratch; [void][IO.Directory]::CreateDirectory($S); Set-FakeInstall
  $run = [ordered]@{ title = "own process"; args = (Get-MoveArgs "Move"); answers = @("MOVE", "pw:good")
    addProcs = @([ordered]@{ id = 8100; name = "powershell.exe"; cmd = ('powershell.exe -NoProfile -WindowStyle Minimized -File "' + $Old + '\BayAgent\bootstrap\ABG.AgentHost.ps1"'); exe = ""; session = 0; user = "NT AUTHORITY\SYSTEM" }) }
  $ro = Invoke-Harness "own-process" @($run) (New-Model -AgentLogon 3)
  $x = Get-Run $ro 0
  Assert-True ($x.exit -eq 0 -and @($x.log | Where-Object { $_ -eq "PROCESS stop 8100" }).Count -eq 1) ("an AgentHost the watchdog started as SYSTEM in session 0 is stopped by its id, and the move finishes (exit " + $x.exit + ")")
  $tai = Get-RunTask $x "AOC Bay Agent"
  Assert-True ($null -ne $tai -and $tai.logon -eq "InteractiveToken" -and -not $tai.withPw -and @($x.log | Where-Object { $_ -match '^PROMPT +Password' }).Count -eq 0) "a logon task that signs in with the interactive token is moved without asking for any password"

  Section "B4. a failure while putting back is reported, not hidden"
  Remove-Scratch; [void][IO.Directory]::CreateDirectory($S); Set-FakeInstall
  $run = [ordered]@{ title = "undo fails"; args = (Get-MoveArgs "Move"); answers = @("MOVE", "pw:good"); inject = @{ "setreg:Shell" = "Requested registry access is not allowed."; "unregister:AOC Bay Agent" = "Access is denied." } }
  $ru = Invoke-Harness "undo-fails" @($run) (New-Model -AgentLogon 1)
  $x = Get-Run $ru 0
  $jd = @([IO.Directory]::GetDirectories($JRoot) | Where-Object { $_ -match '-move$' } | Sort-Object -Descending)
  $ju = $(if ($jd.Count -gt 0) { [IO.File]::ReadAllText((Join-Path $jd[0] "journal.json")) | ConvertFrom-Json } else { $null })
  Assert-True ($x.exit -eq 3 -and (Get-Console $x) -match 'could NOT be put back' -and $null -ne $ju -and $ju.state -eq "rollback-incomplete" -and (@($ju.left) -join " ") -match 'AOC Bay Agent') ("exit 3, and the journal names the new task that could not be removed (exit " + $x.exit + ")")
  $s1 = Get-Snapshot
  Assert-True ($s1.cfgSha -ne "" -and [IO.Directory]::Exists($Old) -and -not [IO.Directory]::Exists((Join-Path $New "BayAgent"))) "...and every other step was still put back (the folders are under the old root)"

  Section "B5. refusals change nothing"
  $refusals = @(
    @{ name = "version"; why = "the installed agent is not the release named"; args = @{ ExpectAgentVersion = "1.6.1" }; expect = 'not ''1\.6\.1''' },
    @{ name = "no-version"; why = "no release version was named"; args = @{ ExpectAgentVersion = "" }; expect = 'ExpectAgentVersion is required' },
    @{ name = "pending"; why = "an update is being watched"; touchRel = "BayAgent\state\update-pending.json"; touchText = '{"phase":"promoted"}'; expect = 'an update is in flight' },
    @{ name = "stopped"; why = "the bay was stopped on purpose"; touchRel = "BayAgent\control\stop.host"; touchText = 'x'; expect = 'stopped on purpose' },
    @{ name = "guard-task"; why = "the update guard's task exists"; addTask = "ABG BayAgent Update Guard"; expect = 'rollback guard is registered' },
    @{ name = "other-task"; why = "another task starts something under the old root"; addTask = "Bay Nightly Thing"; expect = 'this tool does not move it' },
    @{ name = "kiosk-shell"; why = "BayKiosk's own Shell value names the old root"; regSet = @{ ($KioskWinlogon + "|shell") = $ShellOld }; expect = 'own Shell value' },
    @{ name = "target-exists"; why = "the new root already holds a BayAgent folder"; mkNew = $true; expect = 'already exists; a move never merges' },
    @{ name = "new-root-open"; why = "the new root already exists and BUILTIN\Users can write it"; mkNewOpen = $true; expect = 'already exists and is not admin-only' },
    @{ name = "journal-root-open"; why = "the journal folder already exists and BUILTIN\Users can write it"; mkJournalOpen = $true; expect = 'journal folder is not admin-only' },
    @{ name = "link-outside"; why = "a link points outside the old root"; linkOutside = $true; expect = 'points outside the old root' },
    @{ name = "no-source"; why = "a new bootstrap file is missing from the source"; dropNew = "AOC.HostWatchdog.ps1"; expect = 'AOC.HostWatchdog.ps1: not in' },
    @{ name = "still-hardcoded"; why = "a new bootstrap file still names the old root"; hardcode = $true; expect = 'still names' },
    @{ name = "inside-root"; why = "the tool runs from inside the old root"; toolInside = $true; expect = 'running from inside a root it moves' },
    @{ name = "cancel"; why = "the typed word is not MOVE"; answers = @("move"); expect = 'RESULT: cancelled' },
    @{ name = "unsigned-timestamp"; why = "signing returns no timestamp"; inject = @{ "sign-no-timestamp" = "x" }; expect = 'not timestamped' }
  )
  foreach ($rc in $refusals) {
    Remove-Scratch; [void][IO.Directory]::CreateDirectory($S); Set-FakeInstall
    $mdl = New-Model -AgentLogon 1
    $extra = @{}; if ($rc.ContainsKey("args")) { $extra = $rc.args }
    $run = [ordered]@{ title = $rc.name; args = (Get-MoveArgs "Move" $extra); answers = $(if ($rc.ContainsKey("answers")) { $rc.answers } else { @("MOVE", "pw:good") }) }
    if ($rc.ContainsKey("inject")) { $run.inject = $rc.inject }
    if ($rc.ContainsKey("touchRel")) { [IO.File]::WriteAllText((Join-Path $Old $rc.touchRel), $rc.touchText) }
    if ($rc.ContainsKey("addTask")) { $run.addTasks = @([ordered]@{ name = $rc.addTask; xml = (New-ModelTaskXml -Kind "logon" -Arguments ('-File "' + $Old + '\BayAgent\tools\Watch-BayAgentUpdate.ps1"') -User "BAY1KIOSK\BayKiosk" -LogonType 3) }) }
    if ($rc.ContainsKey("regSet")) { $run.regSet = $rc.regSet }
    if ($rc.ContainsKey("mkNew")) { [void][IO.Directory]::CreateDirectory((Join-Path $New "BayAgent")) }
    foreach ($openKey in @("mkNewOpen", "mkJournalOpen")) {
      if ($rc.ContainsKey($openKey)) {
        $openDir = $(if ($openKey -eq "mkNewOpen") { $New } else { $JRoot })
        [void][IO.Directory]::CreateDirectory($openDir)
        $oa = Get-Acl -LiteralPath $openDir
        $oa.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule("BUILTIN\Users", "Modify", "ContainerInherit,ObjectInherit", "None", "Allow")))
        Set-Acl -LiteralPath $openDir -AclObject $oa
      }
    }
    if ($rc.ContainsKey("linkOutside")) { [void][IO.Directory]::CreateDirectory((Join-Path $S "elsewhere")); Microsoft.PowerShell.Management\New-Item -ItemType Junction -Path (Join-Path $Old "BayAgent\staging\out") -Value (Join-Path $S "elsewhere") | Out-Null }
    if ($rc.ContainsKey("dropNew")) { [IO.File]::Delete((Join-Path $NewBoot $rc.dropNew)) }
    if ($rc.ContainsKey("hardcode")) { [IO.File]::AppendAllText((Join-Path $NewBoot "AOC.AgentHost.ps1"), "`r`n# `$BaseDir = `"" + $Old + "\BayAgent`"`r`n`$x = `"" + $Old + "\BayAgent`"`r`n") }
    if ($rc.ContainsKey("toolInside")) { $run.toolAt = (Join-Path $Old "BayAgent\tools\Move-BayInstall.ps1") }
    $s0 = Get-Snapshot
    $rr = Invoke-Harness ("refuse-" + $rc.name) @($run) $mdl
    $x = Get-Run $rr 0
    if ($rc.ContainsKey("toolInside")) { [IO.File]::Delete((Join-Path $Old "BayAgent\tools\Move-BayInstall.ps1")) }
    $s1 = Get-Snapshot
    $writes = @($x.log | Where-Object { $_ -notmatch '^(PROMPT|SIGN|DOWNLOAD)' })
    Assert-True ($x.exit -eq 1 -and (Get-Console $x) -match $rc.expect -and $writes.Count -eq 0 -and $s1.oldTree -eq $s0.oldTree -and $s1.cfgSha -eq $s0.cfgSha) ("{0}: refused with its reason, nothing on the bay changed (exit {1}; machine calls: {2})" -f $rc.why, $x.exit, ($writes -join " ; "))
  }

  # =================================================================================================================
  Section "B6. security review 2: links, a swap between the plan and the move, the same judgment at every entry point"
  # Real folders, real access rules, real junctions. Findings: (1) a check on a path that is used later (a junction put
  # in the path, a folder made or swapped between the plan and the move), (2) one entry point judging what a sibling does
  # not (Plan, Back, -Journal, -BootstrapSource, the files inside the journal), (3) an admin-only test that misses a grant.
  $meSid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
  $script:BmExtraTrusted = @($meSid)
  function Edit-Acl([string]$Path, [scriptblock]$Mod) {
    # Only the access section is read and written (Set-Acl asks for the audit privilege on a folder made with explicit rules).
    $isDir = [IO.Directory]::Exists($Path)
    $i = $(if ($isDir) { New-Object IO.DirectoryInfo($Path) } else { New-Object IO.FileInfo($Path) })
    $a = $i.GetAccessControl([Security.AccessControl.AccessControlSections]::Access)
    & $Mod $a
    $i.SetAccessControl($a)
  }
  function Add-UsersModify([string]$Dir) {
    Edit-Acl $Dir { param($a) $a.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule("BUILTIN\Users", "Modify", "ContainerInherit,ObjectInherit", "None", "Allow"))) }
  }
  function New-TestJunction([string]$Link, [string]$Target) { Microsoft.PowerShell.Management\New-Item -ItemType Junction -Path $Link -Value $Target | Out-Null }

  # -- B6a. the judgment itself, on real folders (Get-BmFolderProblems reads the owner and rules from an open handle)
  $aclRoot = Join-Path $S "acl"; [void][IO.Directory]::CreateDirectory($aclRoot)
  $aclN = 0
  function New-AclCase([string]$Label, [scriptblock]$Grant) {
    $script:aclN++
    $d = Join-Path $aclRoot ("c" + $script:aclN)
    New-AdminOnlyDir $d
    Edit-Acl $d $Grant
    return $d
  }
  function New-Rule($Who, $Rights, [string]$Inherit = "ContainerInherit,ObjectInherit", [string]$Prop = "None", [string]$Type = "Allow") {
    $id = $(if ($Who -is [Security.Principal.SecurityIdentifier]) { $Who } else { New-Object Security.Principal.NTAccount($Who) })
    return (New-Object System.Security.AccessControl.FileSystemAccessRule($id, $Rights, $Inherit, $Prop, $Type))
  }
  $cases = @(
    @{ n = "Authenticated Users may modify"; g = { param($a) $a.AddAccessRule((New-Rule "NT AUTHORITY\Authenticated Users" "Modify")) }; full = $true; ren = $true },
    @{ n = "Everyone may write"; g = { param($a) $a.AddAccessRule((New-Rule "Everyone" "Write")) }; full = $true; ren = $false },
    @{ n = "a user group (INTERACTIVE) has full control"; g = { param($a) $a.AddAccessRule((New-Rule "NT AUTHORITY\INTERACTIVE" "FullControl")) }; full = $true; ren = $true },
    @{ n = "Users may only write attributes"; g = { param($a) $a.AddAccessRule((New-Rule "BUILTIN\Users" "WriteAttributes")) }; full = $true; ren = $false },
    @{ n = "Users may delete it"; g = { param($a) $a.AddAccessRule((New-Rule "BUILTIN\Users" "Delete")) }; full = $true; ren = $true },
    @{ n = "Users may delete a child"; g = { param($a) $a.AddAccessRule((New-Rule "BUILTIN\Users" "DeleteSubdirectoriesAndFiles")) }; full = $true; ren = $true },
    @{ n = "Users may change the rules"; g = { param($a) $a.AddAccessRule((New-Rule "BUILTIN\Users" "ChangePermissions")) }; full = $true; ren = $true },
    @{ n = "Users may take ownership"; g = { param($a) $a.AddAccessRule((New-Rule "BUILTIN\Users" "TakeOwnership")) }; full = $true; ren = $true },
    @{ n = "Users may only add a subfolder, this folder only (what C:\ gives every user)"; g = { param($a) $a.AddAccessRule((New-Rule "BUILTIN\Users" "AppendData" "None")) }; full = $true; ren = $false },
    @{ n = "Users may only read and run"; g = { param($a) $a.AddAccessRule((New-Rule "BUILTIN\Users" "ReadAndExecute")) }; full = $false; ren = $false },
    @{ n = "Users get Modify that only passes down to children (inherit-only), where the journal's files will live"; g = { param($a) $a.AddAccessRule((New-Rule "BUILTIN\Users" "Modify" "ContainerInherit,ObjectInherit" "InheritOnly")) }; full = $true; ren = $false },
    @{ n = "CREATOR OWNER Modify (Windows keeps it as an inherit-only rule plus a rule for the owner, a trusted account here)"; g = { param($a) $a.AddAccessRule((New-Rule (New-Object Security.Principal.SecurityIdentifier("S-1-3-0")) "Modify")) }; full = $false; ren = $false },
    @{ n = "CREATOR OWNER full control, inherit-only (the stock rule on a ProgramData folder: harmless)"; g = { param($a) $a.AddAccessRule((New-Rule (New-Object Security.Principal.SecurityIdentifier("S-1-3-0")) "FullControl" "ContainerInherit,ObjectInherit" "InheritOnly")) }; full = $false; ren = $false },
    @{ n = "Users get Modify and a deny for Write (a deny does not excuse the allow)"; g = { param($a) $a.AddAccessRule((New-Rule "BUILTIN\Users" "Modify")); $a.AddAccessRule((New-Rule "BUILTIN\Users" "Write" "ContainerInherit,ObjectInherit" "None" "Deny")) }; full = $true; ren = $true }
  )
  foreach ($c in $cases) {
    $d = New-AclCase $c.n $c.g
    $pf = @(Get-BmFolderProblems $d $aclRoot "Full" "Full")
    $pr = @(Get-BmFolderProblems $d $aclRoot "Rename" "Rename")
    Assert-True (($pf.Count -gt 0) -eq $c.full -and ($pr.Count -gt 0) -eq $c.ren) ("judged on the rights, not names - {0}: as the folder to use {1}, as a folder above {2} (found {3} / {4})" -f $c.n, $(if ($c.full) { "REFUSED" } else { "accepted" }), $(if ($c.ren) { "REFUSED" } else { "accepted" }), $pf.Count, $pr.Count)
  }
  # an owner who is not an administrator, and no access list at all (a security descriptor built from text: this process cannot make a folder owned by someone else)
  $sdOwner = New-Object Security.AccessControl.RawSecurityDescriptor("O:BUG:BAD:(A;;FA;;;SY)(A;;FA;;;BA)")
  Assert-True (@(Get-BmSdProblems $sdOwner "Full") -match 'owned by S-1-5-32-545' -and @(Get-BmSdProblems $sdOwner "Rename") -match 'owned by S-1-5-32-545' -and @(Get-BmSdProblems $sdOwner "Owner") -match 'owned by S-1-5-32-545') "a folder owned by BUILTIN\Users is refused whatever its rules, as the folder to use and as a folder above it"
  $sdOk = New-Object Security.AccessControl.RawSecurityDescriptor("O:BAG:BAD:(A;;FA;;;SY)(A;;FA;;;BA)")
  Assert-True (@(Get-BmSdProblems $sdOk "Full").Count -eq 0 -and @(Get-BmSdProblems $sdOk "Rename").Count -eq 0) "control: owned by Administrators with SYSTEM and Administrators only is accepted"
  $sdNull = New-Object Security.AccessControl.RawSecurityDescriptor("O:BAG:BA")
  Assert-True (@(Get-BmSdProblems $sdNull "Full").Count -gt 0) "a folder with no access list at all (everyone may do anything) is refused"
  $sdCallback = New-Object Security.AccessControl.RawSecurityDescriptor("O:BAG:BAD:(XA;;FA;;;WD;(Member_of {SID(BU)}))")
  Assert-True (@(Get-BmSdProblems $sdCallback "Full").Count -gt 0) "a conditional allow rule for Everyone is refused (judged as an allow)"
  $sdObject = New-Object Security.AccessControl.RawSecurityDescriptor("O:BAG:BAD:(OA;;CR;ab721a53-1e2f-11d0-9819-00aa0040529b;;WD)")
  Assert-True (@(Get-BmSdProblems $sdObject "Full").Count -gt 0) "an access rule of a kind this tool cannot judge (an object rule) is refused, not skipped"
  # a folder that is itself admin-only, below one that is not: whoever can delete a child of the folder above can swap it
  $ancW = Join-Path $aclRoot "ancW"; New-AdminOnlyDir $ancW
  Edit-Acl $ancW { param($a) $a.AddAccessRule((New-Rule "BUILTIN\Users" "DeleteSubdirectoriesAndFiles")) }
  $leafW = Join-Path $ancW "leaf"; New-AdminOnlyDir $leafW
  Assert-True (@(Get-BmFolderProblems $leafW $aclRoot "Full" "Rename").Count -gt 0) "an admin-only folder below a folder where Users can delete a child is refused (they could swap it for a junction)"
  $ancA = Join-Path $aclRoot "ancA"; New-AdminOnlyDir $ancA
  Edit-Acl $ancA { param($a) $a.AddAccessRule((New-Rule "BUILTIN\Users" "AppendData" "None")) }
  $leafA = Join-Path $ancA "leaf"; New-AdminOnlyDir $leafA
  Assert-True (@(Get-BmFolderProblems $leafA $aclRoot "Full" "Rename").Count -eq 0) "control: an admin-only folder below one where Users may only add a subfolder (as on C:\) is accepted"
  # links: the folder itself, and a folder above it
  $realA = Join-Path $aclRoot "real"; New-AdminOnlyDir $realA; New-AdminOnlyDir (Join-Path $realA "inner")
  $lnkTop = Join-Path $aclRoot "lnk"; New-TestJunction $lnkTop $realA
  $pTop = @(Get-BmFolderProblems $lnkTop $aclRoot "Full" "Full")
  $pMid = @(Get-BmFolderProblems (Join-Path $lnkTop "inner") $aclRoot "Full" "Full")
  Assert-True (($pTop -join " ") -match 'is a link' -and ($pMid -join " ") -match 'is a link') ("a junction as the folder, or anywhere above it, is refused even when it points at an admin-only folder (found: " + $pTop.Count + " / " + $pMid.Count + ")")
  Assert-True (@(Get-BmFolderProblems $realA $aclRoot "Full" "Full").Count -eq 0) "control: the same folder reached without the junction is accepted"
  [IO.File]::WriteAllText((Join-Path $realA "inner\f.txt"), "x")
  $rb = $null; try { $rb = Read-BmTrustedBytes (Join-Path $lnkTop "inner\f.txt") $true } catch { $rb = "THREW " + $_.Exception.Message }
  Assert-True ([string]$rb -match 'THREW .*(link|alias)') ("a file read through a junction in its path is refused (" + [string]$rb + ")")
  $rb2 = $null; try { $rb2 = Read-BmTrustedBytes (Join-Path $realA "inner\f.txt") $true } catch { $rb2 = "THREW " + $_.Exception.Message }
  Assert-True ($rb2 -is [byte[]] -and $rb2.Length -eq 1) "control: the same file read directly returns its bytes"
  Edit-Acl (Join-Path $realA "inner\f.txt") { param($a) $a.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule("BUILTIN\Users", "Write", "Allow"))) }
  $rb3 = $null; try { $rb3 = Read-BmTrustedBytes (Join-Path $realA "inner\f.txt") $true } catch { $rb3 = "THREW " + $_.Exception.Message }
  Assert-True ([string]$rb3 -match 'THREW .*cannot be trusted') ("a file with its own rule that lets Users write is not read, though its folder is admin-only (" + [string]$rb3 + ")")

  # the same folder reached through a drive letter that stands for it (subst) is an alias, not the path it was named by
  $letter = $null
  foreach ($l in @("Z", "Y", "X", "W", "V", "U")) { if (-not [IO.Directory]::Exists($l + ":\")) { $letter = $l; break } }
  if ($null -ne $letter) {
    $aliasDir = Join-Path $aclRoot "alias-target"; New-AdminOnlyDir $aliasDir
    & subst.exe ($letter + ":") $aliasDir | Out-Null
    try {
      $viaDrive = @(Get-BmFolderProblems ($letter + ":\") ($letter + ":\") "Full" "Full")
      $viaDrive2 = @(Get-BmFolderProblems $aliasDir $aclRoot "Full" "Full")
      Assert-True ((@(Get-BmFolderProblems ($letter + ":\") $null "Link" "Link") -join " ") -match 'link or an alias' -and $viaDrive2.Count -eq 0) "a folder named through a drive letter that stands for it is refused as an alias of another path; named by its own path it is accepted"
    } finally { & subst.exe ($letter + ":") /d | Out-Null }
  } else { Write-Host "  INFO  no free drive letter: the alias check was NOT exercised by this run" -ForegroundColor Yellow }

  # -- B6b. entry points that must say what Move says, and a path that changes under the tool
  function New-SecCase([string]$Name, [hashtable]$Extra, [string]$Mode, [scriptblock]$Setup) {
    Remove-Scratch; [void][IO.Directory]::CreateDirectory($S); Set-FakeInstall
    if ($null -ne $Setup) { & $Setup }
    $s0 = Get-Snapshot
    $run = [ordered]@{ title = $Name; args = (Get-MoveArgs $Mode $Extra); answers = $(if ($Mode -eq "Plan") { @() } else { @("MOVE", "pw:good") }) }
    $rr = Invoke-Harness ("sec-" + $Name) @($run) (New-Model -AgentLogon 1)
    return @{ x = (Get-Run $rr 0); s0 = $s0; s1 = (Get-Snapshot) }
  }
  function Test-SecRefused($R, [string]$Why, [string]$Expect) {
    $x = $R.x
    $writes = @($x.log | Where-Object { $_ -notmatch '^(PROMPT|SIGN|DOWNLOAD)' })
    Assert-True ($x.exit -eq 1 -and (Get-Console $x) -match $Expect -and $writes.Count -eq 0 -and $R.s1.oldTree -eq $R.s0.oldTree -and $R.s1.cfgSha -eq $R.s0.cfgSha) ("{0}: refused with its reason, nothing on the bay changed (exit {1}; machine calls: {2}; console: {3})" -f $Why, $x.exit, ($writes -join " ; "), $(if ($x.exit -ne 1 -or (Get-Console $x) -notmatch $Expect) { (Get-Console $x) -replace '\s+', ' ' } else { "" }))
  }
  $jreal = Join-Path $S "jreal"
  $r = New-SecCase "journal-is-link" @{ JournalRoot = (Join-Path $S "jlink") } "Move" { New-AdminOnlyDir $jreal; New-TestJunction (Join-Path $S "jlink") $jreal }
  Test-SecRefused $r "the journal folder is a junction to an admin-only folder" 'is a link'
  Assert-True (@([IO.Directory]::GetFileSystemEntries($jreal)).Count -eq 0) "...and nothing was written through the junction"
  $r = New-SecCase "journal-under-link" @{ JournalRoot = (Join-Path $S "jlm\journal") } "Move" { New-AdminOnlyDir $jreal; New-TestJunction (Join-Path $S "jlm") $jreal }
  Test-SecRefused $r "a folder above the journal folder is a junction to an admin-only folder" 'is a link'
  Assert-True (@([IO.Directory]::GetFileSystemEntries($jreal)).Count -eq 0) "...and nothing was made inside the folder it points to"
  $r = New-SecCase "new-root-is-link" @{} "Move" { $nreal = Join-Path $S "nreal"; New-AdminOnlyDir $nreal; New-TestJunction $New $nreal }
  Test-SecRefused $r "the new root is a junction to an admin-only folder" 'is a link'
  Assert-True (@([IO.Directory]::GetFileSystemEntries((Join-Path $S "nreal"))).Count -eq 0) "...and nothing was moved through the junction"
  $r = New-SecCase "plan-journal-open" @{} "Plan" { [void][IO.Directory]::CreateDirectory($JRoot); Add-UsersModify $JRoot }
  Test-SecRefused $r "Plan, like Move, refuses a journal folder Users can write" 'journal folder is not admin-only'
  $r = New-SecCase "source-open-move" @{} "Move" { Add-UsersModify $NewBoot }
  Test-SecRefused $r "Move refuses new bootstrap files from a folder Users can write (they are signed with the bay's certificate)" 'BootstrapSource is not admin-only'
  $r = New-SecCase "source-open-plan" @{} "Plan" { Add-UsersModify $NewBoot }
  Test-SecRefused $r "Plan says the same about the folder the new bootstrap files come from" 'BootstrapSource is not admin-only'
  $r = New-SecCase "source-file-open" @{} "Move" { Edit-Acl (Join-Path $NewBoot "AOC.AgentHost.ps1") { param($a) $a.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule("BUILTIN\Users", "Modify", "Allow"))) } }
  Test-SecRefused $r "a new bootstrap file in the admin-only source folder has its own rule that lets Users write: it is not staged or signed" 'AOC\.AgentHost\.ps1: .*cannot be trusted'
  $npar = Join-Path $S "np"
  $r = New-SecCase "new-parent-open" @{ NewRoot = (Join-Path $npar "AceOfClubs") } "Plan" { [void][IO.Directory]::CreateDirectory($npar); Add-UsersModify $npar }
  Test-SecRefused $r "the folder the new root would be made in can be written by Users" 'does not exist, and the folder it would be made in is not safe'
  $jpar = Join-Path $S "jp"
  $r = New-SecCase "journal-parent-open" @{ JournalRoot = (Join-Path $jpar "journal") } "Move" { [void][IO.Directory]::CreateDirectory($jpar); Add-UsersModify $jpar }
  Test-SecRefused $r "the folder the journal folder would be made in is writable by Users" 'journal folder is not admin-only'
  Assert-True (-not [IO.Directory]::Exists((Join-Path $jpar "journal"))) "...and the journal folder was not made there (judged before it is made, not after)"

  # a swap between the plan and the move: the harness runs a step at the prompt the person answers, after the plan
  Remove-Scratch; [void][IO.Directory]::CreateDirectory($S); Set-FakeInstall
  $s0 = Get-Snapshot
  $run = [ordered]@{ title = "swap-new-root"; args = (Get-MoveArgs "Move"); answers = @("MOVE", "pw:good"); inject = @{ "swap-new-open" = $New } }
  $rr = Invoke-Harness "sec-swap-new" @($run) (New-Model -AgentLogon 1)
  $x = Get-Run $rr 0
  Assert-True ($x.exit -eq 2 -and (Get-Console $x) -match 'is not safe to move into any more' -and -not [IO.Directory]::Exists((Join-Path $New "BayAgent")) -and [IO.Directory]::Exists((Join-Path $Old "BayAgent"))) ("a standard user makes the new root, writable by Users, after the plan: the move refuses it and puts everything back (exit {0}; {1})" -f $x.exit, ((Get-Console $x) -replace '\s+', ' ').Substring(0, [Math]::Min(300, ((Get-Console $x) -replace '\s+', ' ').Length)))
  Remove-Scratch; [void][IO.Directory]::CreateDirectory($S); Set-FakeInstall
  $elsewhere = Join-Path $S "elsewhere"
  $run = [ordered]@{ title = "swap-src"; args = (Get-MoveArgs "Move"); answers = @("MOVE", "pw:good"); inject = @{ "swap-src-link" = ((Join-Path $Old "SessionDisplay") + "|" + $elsewhere) } }
  $rr = Invoke-Harness "sec-swap-src" @($run) (New-Model -AgentLogon 1)
  $x = Get-Run $rr 0
  Assert-True ($x.exit -eq 2 -and (Get-Console $x) -match 'changed since the plan' -and -not [IO.Directory]::Exists((Join-Path $New "SessionDisplay")) -and [IO.Directory]::Exists((Join-Path $Old "BayAgent")) -and (Get-BmLinkTarget (Join-Path $Old "SessionDisplay")) -ne "") ("a folder swapped for a junction after the plan is not moved, and what was already moved is put back (exit {0})" -f $x.exit)

  # Back: the files inside the journal, a path through a link, a saved script that was changed
  Remove-Scratch; [void][IO.Directory]::CreateDirectory($S); Set-FakeInstall
  $m6 = New-Model -AgentLogon 1; $st6 = Join-Path $S "machine-b6.json"
  $rm = Invoke-Harness "b6-move" @([ordered]@{ title = "Move"; args = (Get-MoveArgs "Move"); answers = @("MOVE", "pw:good") }) $m6 $st6
  Assert-True ((Get-Run $rm 0).exit -eq 0) "B6 set-up: a Move completed on the modeled bay (exit $((Get-Run $rm 0).exit))"
  $jd6 = @([IO.Directory]::GetDirectories($JRoot) | Where-Object { $_ -match '-move$' } | Sort-Object -Descending)[0]
  $backRun = { param($title, $extra) $a = Get-MoveArgs "Back" (@{ BootstrapSource = "" } + $extra); $rrb = Invoke-Harness ("b6-" + $title) @([ordered]@{ title = $title; args = $a; answers = @("BACK", "pw:good") }) $m6 $st6; return (Get-Run $rrb 0) }
  function Test-BackRefused($X, [string]$Why, [string]$Expect, $Before) {
    $writes = @($X.log | Where-Object { $_ -notmatch '^(PROMPT|SIGN|DOWNLOAD)' })
    $now = Get-Snapshot
    Assert-True ($X.exit -eq 1 -and (Get-Console $X) -match $Expect -and $writes.Count -eq 0 -and $now.newTree -eq $Before.newTree) ("Back: {0}: refused, nothing changed (exit {1}; calls: {2}; console: {3})" -f $Why, $X.exit, ($writes -join " ; "), $(if ((Get-Console $X) -notmatch $Expect) { (Get-Console $X) -replace '\s+', ' ' } else { "" }))
  }
  $before6 = Get-Snapshot
  $jf6 = Join-Path $jd6 "journal.json"
  $usersRule = New-Object System.Security.AccessControl.FileSystemAccessRule("BUILTIN\Users", "Modify", "Allow")
  Edit-Acl $jf6 { param($a) $a.AddAccessRule($usersRule) }
  $xb = & $backRun "file-open" @{}
  Edit-Acl $jf6 { param($a) [void]$a.RemoveAccessRuleSpecific($usersRule) }
  Test-BackRefused $xb "journal.json itself carries a rule that lets Users write (its folder is admin-only)" 'journal file cannot be trusted' $before6
  $tx6 = Join-Path $jd6 "task-ABG_Bay_Agent.xml"
  Edit-Acl $tx6 { param($a) $a.AddAccessRule($usersRule) }
  $xb = & $backRun "task-open" @{}
  Edit-Acl $tx6 { param($a) [void]$a.RemoveAccessRuleSpecific($usersRule) }
  Test-BackRefused $xb "a saved task definition in the journal carries a rule that lets Users write" 'saved definition for .* cannot be trusted' $before6
  $jl = Join-Path $S "jl"; New-TestJunction $jl $JRoot
  $xb = & $backRun "via-link" @{ Journal = (Join-Path $jl ([IO.Path]::GetFileName($jd6))) }
  [IO.Directory]::Delete($jl, $false)
  Test-BackRefused $xb "-Journal names the right journal through a junction" 'not in an admin-only folder' $before6
  $kept = Join-Path $jd6 "replaced-bootstrap\ABG.AgentHost.ps1"
  $keptBytes = [IO.File]::ReadAllBytes($kept); $keptTime = [IO.File]::GetLastWriteTimeUtc($kept)
  [IO.File]::AppendAllText($kept, "`r`n# changed after the Move`r`n")
  $xb = & $backRun "tampered-script" @{}
  [IO.File]::WriteAllBytes($kept, $keptBytes); [IO.File]::SetLastWriteTimeUtc($kept, $keptTime)
  Test-BackRefused $xb "a saved bootstrap script was changed after the Move: Back does not sign it with the bay's certificate" 'not signed by the bay''s signer' $before6
  $xb = & $backRun "control" @{}
  Assert-True ($xb.exit -eq 0 -and (Get-Console $xb) -match 'RESULT: MOVED to') ("control: the same Back, with the journal as the Move left it, succeeds (exit " + $xb.exit + ")")

  # =================================================================================================================
  Section "E. the run sheet's owner step (docs\runsheet-bay1-move.md, step 2): the tool's own owner check, and the sheet's own commands"
  # 2026-10-14: a copy made in a normal window is owned by the user, and icacls /grant:r does not change the owner, so Plan
  # said "-BootstrapSource is not admin-only (owned by S-1-5-21-...)". The sheet now makes, locks, fills and re-owns the
  # folder in the administrator window and reads the owner back. What this part proves WITHOUT elevation: the tool's own
  # judgment on the exact shapes (owner = a user SID vs Administrators, rules otherwise identical), the folder this
  # process really creates, and the sheet's commands (gates, labels, order) by running them. What it cannot prove: the
  # owner an ELEVATED copy gets (when this suite is run from an administrator window, E3 proves it as well).
  $savedTrusted = $script:BmExtraTrusted
  $script:BmExtraTrusted = @()   # as on a bay: no extra trusted account
  $eRoot = Join-Path $S "e"; [void][IO.Directory]::CreateDirectory($eRoot)
  $eUserSid = "S-1-5-21-1111111111-2222222222-3333333333-1001"
  try {
    # E1. the shapes, as security descriptors (what a copy gets from a normal window vs from an administrator window)
    $dirRules = "(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)"
    $sdU = New-Object Security.AccessControl.RawSecurityDescriptor("O:" + $eUserSid + "G:BAD:PAI" + $dirRules)
    $sdA = New-Object Security.AccessControl.RawSecurityDescriptor("O:BAG:BAD:PAI" + $dirRules)
    $pU = @(Get-BmSdProblems $sdU "Full"); $pUr = @(Get-BmSdProblems $sdU "Rename"); $pUo = @(Get-BmSdProblems $sdU "Owner")
    Assert-True ($pU.Count -eq 1 -and $pU[0] -eq ("owned by " + $eUserSid) -and $pUr.Count -eq 1 -and $pUo.Count -eq 1) ("a folder with the sheet's rules (SYSTEM and Administrators only) but owned by the user is refused for its OWNER alone: '" + ($pU -join "; ") + "'")
    Assert-True (@(Get-BmSdProblems $sdA "Full").Count -eq 0 -and @(Get-BmSdProblems $sdA "Rename").Count -eq 0 -and @(Get-BmSdProblems $sdA "Owner").Count -eq 0) "the same rules owned by BUILTIN\Administrators are accepted (what the sheet's setowner leaves)"
    # a file inside the folder: rules inherited from it (the sheet's copy comes after the lock), owner is what judges
    $fileRules = "(A;ID;FA;;;SY)(A;ID;FA;;;BA)"
    $sdFU = New-Object Security.AccessControl.RawSecurityDescriptor("O:" + $eUserSid + "G:BAD:AI" + $fileRules)
    $sdFA = New-Object Security.AccessControl.RawSecurityDescriptor("O:BAG:BAD:AI" + $fileRules)
    Assert-True (@(Get-BmSdProblems $sdFU "Full").Count -eq 1 -and @(Get-BmSdProblems $sdFA "Full").Count -eq 0) "a file with inherited admin-only rules: refused when the user owns it, accepted when Administrators own it"
    foreach ($ownerSddl in @("SY", "BA")) {
      $sdT = New-Object Security.AccessControl.RawSecurityDescriptor("O:" + $ownerSddl + "G:BAD:PAI" + $dirRules)
      Assert-True (@(Get-BmSdProblems $sdT "Full").Count -eq 0) ("owner " + $ownerSddl + " is accepted")
    }

    # E2. the folder this process really creates, with the sheet's rules and no extra trusted account
    $eDir = Join-Path $eRoot "locked"
    $eSec = New-Object System.Security.AccessControl.DirectorySecurity
    $eSec.SetAccessRuleProtection($true, $false)
    foreach ($who in @("NT AUTHORITY\SYSTEM", "BUILTIN\Administrators")) { $eSec.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($who, "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow"))) }
    # the user also gets read-and-execute only: the tool opens the folder to judge it, and a read rule is not a writer
    $eSec.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule((New-Object Security.Principal.SecurityIdentifier($meSid)), "ReadAndExecute", "ContainerInherit,ObjectInherit", "None", "Allow")))
    [void][IO.Directory]::CreateDirectory($eDir, $eSec)
    try {
      $eOwner = (New-Object IO.DirectoryInfo($eDir)).GetAccessControl([Security.AccessControl.AccessControlSections]::Owner).GetOwner([Security.Principal.SecurityIdentifier]).Value
      $eProb = @(Get-BmFolderProblems $eDir $eRoot "Full" "Rename")
      if ($eOwner -eq "S-1-5-32-544") {
        Assert-True ($eProb.Count -eq 0) ("E2 (this process is ELEVATED): a folder it creates is owned by Administrators (" + $eOwner + ") and the tool accepts it: this is the elevated-owner proof")
      } else {
        Assert-True ($eProb.Count -eq 1 -and $eProb[0] -like ("* (owned by " + $eOwner + ")")) ("E2 (not elevated): a folder this process creates with the sheet's rules is owned by '" + $eOwner + "' and the tool refuses it for that alone: '" + ($eProb -join "; ") + "'")
      }
    } finally {
      Edit-Acl $eDir { param($a) $a.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule((New-Object Security.Principal.SecurityIdentifier($meSid)), "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow"))) }
    }

    # E3. the sheet itself: parse it and run its commands
    $sheet = (Join-Path $RepoRoot "docs\runsheet-bay1-move.md")
    $lines = [IO.File]::ReadAllText($sheet).Replace("`r`n", "`n").Split("`n")
    $blocks = @(); $inB = $false; $lang = ""; $start = 0; $buf = @()
    for ($n = 0; $n -lt $lines.Count; $n++) {
      if ($lines[$n] -match '^```(.*)$') {
        if (-not $inB) { $inB = $true; $lang = $Matches[1].Trim(); $start = $n; $buf = @() }
        else { $inB = $false; $blocks += [pscustomobject]@{ Lang = $lang; Start = $start; End = $n; Text = ($buf -join "`n") } }
      } elseif ($inB) { $buf += $lines[$n] }
    }
    $cmds = @($blocks | Where-Object { $_.Lang -eq "powershell" })
    Assert-True (@($blocks | Where-Object { $_.Lang -eq "" }).Count -eq 0) "E3: every fenced block in the sheet is typed (powershell for a command, text for output)"
    Assert-True ($cmds.Count -ge 7) ("E3: the sheet has its commands as powershell blocks (found " + $cmds.Count + ": 2b, 2c, the owner fix, Plan, Move, Verify, Back)")
    $labelBad = @(); $guardBad = @(); $expBad = @()
    foreach ($c in $cmds) {
      $before = ($lines[([Math]::Max(0, $c.Start - 6))..($c.Start - 1)] -join "`n")
      $around = ($lines[([Math]::Max(0, $c.Start - 6))..([Math]::Min($lines.Count - 1, $c.End + 14))] -join "`n")
      if ($before -notmatch 'Window: \*\*(administrator|normal)\*\*') { $labelBad += $c.Start + 1 }
      if ($c.Text -notmatch 'Write-Host \("Computer: " \+ \$env:COMPUTERNAME\)' -or $c.Text -notmatch '\$env:COMPUTERNAME -ne \$pc' -or $c.Text -notmatch "WRONG PC\. STOP" -or $c.Text -notmatch "\`$pc = '<PC>'") { $guardBad += $c.Start + 1 }
      if ($before -match 'Window: \*\*administrator\*\*' -and ($c.Text -notmatch 'IsInRole\(\[Security\.Principal\.WindowsBuiltInRole\]::Administrator\)' -or $c.Text -notmatch 'NOT AN ADMINISTRATOR WINDOW')) { $guardBad += $c.Start + 1 }
      if ($around -notmatch 'Expect') { $expBad += $c.Start + 1 }
    }
    Assert-True ($labelBad.Count -eq 0) ("E3: every command says which window it runs in (lines without: " + ($labelBad -join ",") + ")")
    Assert-True ($guardBad.Count -eq 0) ("E3: every command prints the computer name first, stops on the wrong PC, and an administrator one checks it is elevated (lines failing: " + ($guardBad -join ",") + ")")
    Assert-True ($expBad.Count -eq 0) ("E3: every command has an Expect line (lines without: " + ($expBad -join ",") + ")")
    $copyBlock = @($cmds | Where-Object { $_.Text -match 'Copy-Item' })
    $lockBlock = @($cmds | Where-Object { $_.Text -match 'inheritance:r' })
    $ownBlock = @($cmds | Where-Object { $_.Text -match 'setowner "BUILTIN\\Administrators" /T /C' })
    $chkBlock = @($cmds | Where-Object { $_.Text -match "S-1-5-32-544" -and $_.Text -match "GetOwner" })
    Assert-True ($copyBlock.Count -eq 1 -and $lockBlock.Count -eq 1 -and $copyBlock[0].Start -eq $lockBlock[0].Start) "E3: one block makes, locks and copies (lock first, then copy, so the files inherit the lock)"
    $t2 = $copyBlock[0].Text
    Assert-True ($t2.IndexOf("New-Item -ItemType Directory") -lt $t2.IndexOf("inheritance:r") -and $t2.IndexOf("inheritance:r") -lt $t2.IndexOf("Copy-Item") -and $t2.IndexOf("Copy-Item") -lt $t2.IndexOf("/setowner")) "E3: the order in the block is create, lock, copy, set owner"
    Assert-True ($ownBlock.Count -ge 2 -and $chkBlock.Count -eq 1) "E3: the owner is set (in 2b and in the fix) and read back by the SID of Administrators in 2c"
    $adminLine = [Array]::FindIndex($lines, [Predicate[string]]{ param($l) $l -match '^\*\*2a\. Open Windows PowerShell as administrator' })
    Assert-True ($adminLine -ge 0 -and $adminLine -lt $copyBlock[0].Start) "E3: the administrator window is opened (2a) before the copy"
    $stepAfter = [Array]::FindIndex($lines, [Predicate[string]]{ param($l) $l -match '^\*\*3\. Run Plan' })
    Assert-True ($stepAfter -gt $chkBlock[0].End -and $stepAfter -gt 0) "E3: the read-back (2c) comes before Plan (step 3)"
    Assert-True (([string]::Join("`n", $lines)) -notmatch '\*\*2\. Copy the tool\*\* from the stick') "E3: the old step 2 (copy first, lock later) is gone"

    # E3 run: the real 2b and 2c commands, with only the PC name, the stick and the folder swapped for scratch values
    $pcReal = $env:COMPUTERNAME
    $eStick = Join-Path $eRoot "stick"; [void][IO.Directory]::CreateDirectory((Join-Path $eStick "bootstrap"))
    [IO.File]::WriteAllText((Join-Path $eStick "Move-BayInstall.ps1"), "# fixture`r`n"); [IO.File]::WriteAllText((Join-Path $eStick "bootstrap\AOC.AgentHost.ps1"), "# fixture`r`n")
    $isElev = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    $runBlock = {
      param([string]$Text, [string]$Pc, [string]$Dest, [string]$Tag, [bool]$DropAdminGate)
      $t = $Text.Replace("'<PC>'", "'" + $Pc + "'").Replace("'C:\BayMove'", "'" + $Dest + "'").Replace("'<D>:\'", "'" + $eStick + "\'")
      if ($DropAdminGate) { $t = $t.Replace('if (-not $admin) {', 'if ($false) {') }
      $f = Join-Path $eRoot ("run-" + $Tag + ".ps1")
      [IO.File]::WriteAllText($f, $t.Replace("`n", "`r`n"), (New-Object Text.UTF8Encoding($false)))
      $ErrorActionPreference = "Continue"
      $o = & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $f 2>&1 | ForEach-Object { [string]$_ }
      return ($o -join "`n")
    }
    $d1 = Join-Path $eRoot "dest-wrongpc"
    $o1 = & $runBlock $copyBlock[0].Text ("NOT-THIS-PC-" + $RunId) $d1 "2b-wrongpc" $false
    Assert-True ($o1 -match "WRONG PC\. STOP" -and $o1 -match "Computer: " -and $o1 -notmatch "Copied" -and -not (Test-Path -LiteralPath $d1)) "E3 run: 2b on the wrong PC prints the name, says STOP and creates nothing"
    $d2 = Join-Path $eRoot "dest-normal"
    if (-not $isElev) {
      $o2 = & $runBlock $copyBlock[0].Text $pcReal $d2 "2b-normal" $false
      Assert-True ($o2 -match ("Computer: " + [regex]::Escape($pcReal)) -and $o2 -match "Administrator window: False" -and $o2 -match "NOT AN ADMINISTRATOR WINDOW\. STOP" -and $o2 -notmatch "Copied" -and -not (Test-Path -LiteralPath $d2)) "E3 run: 2b in a normal window stops before creating or copying anything"
      # 2c's reading logic (admin gate dropped in this copy only) on a folder this user owns: it names the owner and says STOP
      $d3 = Join-Path $eRoot "dest-userowned"; [void][IO.Directory]::CreateDirectory($d3)
      [IO.File]::WriteAllText((Join-Path $d3 "f.ps1"), "# fixture`r`n")
      $o3 = & $runBlock $chkBlock[0].Text $pcReal $d3 "2c-userowned" $true
      Assert-True ($o3 -match ("owner is " + [regex]::Escape($meSid) + ": ") -and $o3 -match "STOP\. Photograph" -and $o3 -notmatch "OK: every item") "E3 run: 2c on a folder and file owned by the user lists the owner SID and says STOP (admin gate removed in this copy)"
      $o3b = & $runBlock $chkBlock[0].Text $pcReal $d3 "2c-gate" $false
      Assert-True ($o3b -match "NOT AN ADMINISTRATOR WINDOW\. STOP" -and $o3b -notmatch "Items checked") "E3 run: 2c itself in a normal window stops at the gate"
    } else {
      $o2 = & $runBlock $copyBlock[0].Text $pcReal $d2 "2b-admin" $false
      Assert-True ($o2 -match "Copied, locked and owner set") ("E3 run (ELEVATED): 2b ran to the end: " + ($o2 -replace "`n", " | "))
      $o4 = & $runBlock $chkBlock[0].Text $pcReal $d2 "2c-admin" $false
      Assert-True ($o4 -match "Owner of .*: BUILTIN\\Administrators" -and $o4 -match "Items checked: 4" -and $o4 -match "OK: every item") ("E3 run (ELEVATED): 2c reads back Administrators as owner of all 4 items: " + ($o4 -replace "`n", " | "))
      $pcB = @(Get-BmFolderProblems $d2 $eRoot "Full" "Rename")
      Assert-True ($pcB.Count -eq 0) "E3 run (ELEVATED): the tool's own folder judgment accepts the folder 2b made"
    }
    Write-Host ("  (suite elevated: " + $isElev + "; the E3 branches that need elevation ran only if True)")
  } finally {
    $script:BmExtraTrusted = $savedTrusted
  }

  # =================================================================================================================
  Section "C. the real Task Scheduler: export, rewrite, register under the new name"
  $uniq = "AocBmTest-" + $RunId
  $tOld = $uniq + " ABG Bay Agent"; $tNew = $uniq + " AOC Bay Agent"
  try {
    $act = New-ScheduledTaskAction -Execute "powershell.exe" -Argument ('-NoProfile -File "C:\AllBirdies\BayAgent\bootstrap\ABG.AgentHost.ps1"')
    $prin = New-ScheduledTaskPrincipal -UserId $Me -LogonType Interactive -RunLevel Limited
    $set = New-ScheduledTaskSettingsSet -Disable
    Register-ScheduledTask -TaskName $tOld -TaskPath "\" -Action $act -Principal $prin -Settings $set | Out-Null
    $TasksMadeHere += $tOld
    $x0 = [string](Export-ScheduledTask -TaskName $tOld -TaskPath "\")
    $cv = Convert-BmTaskXml -Xml $x0 -From "C:\AllBirdies" -To "C:\AceOfClubs" -NameMap $BmBootstrapNameMap -NewName $tNew -Enabled $false
    Register-BmTask -Name $tNew -Xml $cv.Xml -User "" -Password $null
    $TasksMadeHere += $tNew
    $rt = Get-ScheduledTask -TaskName $tNew -TaskPath "\"
    $fx = Get-BmTaskXmlFacts ([string](Export-ScheduledTask -TaskName $tNew -TaskPath "\"))
    Assert-True ([string]$rt.State -eq "Disabled" -and [string]@($rt.Actions)[0].Arguments -eq '-NoProfile -File "C:\AceOfClubs\BayAgent\bootstrap\AOC.AgentHost.ps1"') ("a real definition exported, rewritten and registered again reads back with the new path and name, disabled (" + [string]@($rt.Actions)[0].Arguments + ")")
    Assert-True ((ConvertTo-BmSid $fx.User) -eq (ConvertTo-BmSid $Me) -and $fx.LogonType -eq "InteractiveToken") ("...with the same account and sign-in kind (" + $fx.User + ", " + $fx.LogonType + ")")
  } catch { Assert-True $false ("the real Task Scheduler round trip ran: " + $_.Exception.Message) }
  finally {
    foreach ($tn in $TasksMadeHere) { try { Unregister-ScheduledTask -TaskName $tn -TaskPath "\" -Confirm:$false -ErrorAction Stop } catch { } }
    $left = @(Get-ScheduledTask -TaskPath "\" -ErrorAction SilentlyContinue | Where-Object { $_.TaskName -like ($uniq + "*") })
    Assert-True ($left.Count -eq 0) "no test task is left in the Task Scheduler (by exact name)"
  }

  # =================================================================================================================
  Section "D. the password with the REAL Register-ScheduledTask, debug and verbose output on"
  # Windows PowerShell 5.1 turns -Debug into Inquire (a prompt), so the debug and verbose preferences are set to
  # Continue around the call instead: every debug and verbose record is written, nothing waits for an answer.
  $fakeUser = "AocBmNoSuchUser" + $RunId
  $xmlLeak = New-ModelTaskXml -Kind "logon" -Arguments '-NoProfile -File "C:\AceOfClubs\BayAgent\bootstrap\AOC.AgentHost.ps1"' -User $fakeUser -LogonType 1
  function Invoke-LeakProbe([string]$Tag, [scriptblock]$Body) {
    # Runs $Body with debug and verbose on, under a transcript, all six streams captured; returns everything a reader
    # could find afterwards: the transcript, the streams, the caught message, and every field of every $Error record.
    $tr = Join-Path $S ("leak-" + $Tag + "-transcript.txt"); $streams = Join-Path $S ("leak-" + $Tag + "-streams.txt")
    $global:Error.Clear(); $script:LeakMsg = ""
    $oldD = $DebugPreference; $oldV = $VerbosePreference
    Start-Transcript -LiteralPath $tr | Out-Null
    try {
      $DebugPreference = "Continue"; $VerbosePreference = "Continue"
      & { try { & $Body } catch { $script:LeakMsg = $_.Exception.Message; Write-Host ("caught: " + $_.Exception.Message) } } *>&1 | Out-String -Width 4096 | Tee-Object -FilePath $streams | Out-Host
    } finally { $DebugPreference = $oldD; $VerbosePreference = $oldV; Stop-Transcript | Out-Null }
    $errText = (@($global:Error | ForEach-Object {
          $e = $_; $x = @("$e")
          try { $x += [string]$e.Exception.Message } catch { }
          try { $x += [string]$e.TargetObject } catch { }
          try { $x += [string]$e.InvocationInfo.Line } catch { }
          try { foreach ($v in @($e.InvocationInfo.BoundParameters.Values)) { $x += [string]$v } } catch { }
          try { $x += [string]$e.Exception.InnerException } catch { }
          $x -join "`n" }) -join "`n")
    return @{ Msg = [string]$script:LeakMsg; Transcript = [IO.File]::ReadAllText($tr); Streams = [IO.File]::ReadAllText($streams); Errors = $errText }
  }
  function Get-LeakPlaces($Probe, [string]$Value) {
    $where = @()
    foreach ($k in @("Transcript", "Streams", "Msg", "Errors")) { if ([string]$Probe[$k] -and ([string]$Probe[$k]).Contains($Value)) { $where += $k } }
    return ,$where
  }
  # 1. the tool's own call
  $tLeak = $uniq + " leak"
  $fakePw = "BMTFAKEPW" + [guid]::NewGuid().ToString("N")
  $secure = ConvertTo-SecureString $fakePw -AsPlainText -Force
  try { $pr = Invoke-LeakProbe "tool" { Register-BmTask -Name $tLeak -Xml $xmlLeak -User $fakeUser -Password $secure } }
  finally { try { Unregister-ScheduledTask -TaskName $tLeak -TaskPath "\" -Confirm:$false -ErrorAction Stop } catch { } }
  $places = Get-LeakPlaces $pr $fakePw
  Assert-True ($pr.Msg -match "registering the task") ("the real cmdlet refused the fake account, and the tool's error says which task (" + $pr.Msg + ")")
  Assert-True ($places.Count -eq 0) ("the fake password is in none of: the six streams, the transcript, the error text, any record in `$Error (found in: " + ($places -join ",") + ")")
  Assert-True ($null -eq (Get-ScheduledTask -TaskName $tLeak -TaskPath "\" -ErrorAction SilentlyContinue)) "...and no task was registered"
  # 2. measured, not asserted: the same real cmdlet called directly, as a careless script would. On Windows PowerShell
  # 5.1 its error record (a RemotingErrorRecord from the CIM module) carries no bound parameters and the value is in no
  # stream; this line records where it was found, so a change in Windows shows up here.
  $tPlant = $uniq + " plant"
  $plantPw = "BMTPLANTPW" + [guid]::NewGuid().ToString("N")
  try { $pp = Invoke-LeakProbe "plant" { Register-ScheduledTask -TaskName $tPlant -TaskPath "\" -Xml $xmlLeak -User $fakeUser -Password $plantPw -Force -ErrorAction Stop | Out-Null } }
  finally { try { Unregister-ScheduledTask -TaskName $tPlant -TaskPath "\" -Confirm:$false -ErrorAction Stop } catch { } }
  $plantPlaces = Get-LeakPlaces $pp $plantPw
  Write-Host ("  INFO  the same cmdlet called directly: its password was found in: [" + ($plantPlaces -join ",") + "]")
  # 3. the plants: a value thrown and written as an error record is found in the caught text and in $Error
  $errPw = "BMTERRPW" + [guid]::NewGuid().ToString("N")
  $pe = Invoke-LeakProbe "errors" { Write-Error -Message ("e " + $errPw) -TargetObject $errPw -ErrorAction Continue; throw ("t " + $errPw) }
  $ep = Get-LeakPlaces $pe $errPw
  Assert-True ($ep -contains "Msg" -and $ep -contains "Errors") ("the plant: a value in an error is found in the caught text and in the `$Error records (found in: " + ($ep -join ",") + ")")
  # 4. a second plant in the streams themselves: a value written to the verbose and debug streams is found
  $streamPw = "BMTSTREAMPW" + [guid]::NewGuid().ToString("N")
  $ps2 = Invoke-LeakProbe "streams" { Write-Verbose ("v " + $streamPw); Write-Debug ("d " + $streamPw) }
  $sp = Get-LeakPlaces $ps2 $streamPw
  Assert-True ($sp -contains "Streams" -and $sp -contains "Transcript") ("the plant: a value written to the verbose and debug streams is found in the captured streams and the transcript (found in: " + ($sp -join ",") + ")")} finally {
  Remove-Scratch
}

Write-Host ""
Write-Host ("RESULT: {0} passed, {1} failed" -f $script:Pass, $script:Fail) -ForegroundColor $(if ($script:Fail -eq 0) { "Green" } else { "Red" })
foreach ($f in $script:Failures) { Write-Host ("  FAILED: " + $f) -ForegroundColor Red }
if ($script:Fail -gt 0) { exit 1 }
exit 0
