<#
Move-BayInstall.ps1

Moves ONE installed bay from the old root (C:\AllBirdies) to the new root (C:\AceOfClubs), and puts it back.
A0.634: the bay program's folder becomes C:\AceOfClubs\BayAgent. A0.636: one fleet release renames the folder, the
repository address, the seven ABG.*.ps1 files and the two scheduled tasks together.

RUN IT AS ADMINISTRATOR, FROM A FOLDER OUTSIDE BOTH ROOTS (it refuses to run from inside the folder it moves):
  powershell.exe -NoProfile -ExecutionPolicy Bypass -File C:\BayMove\Move-BayInstall.ps1 -Mode Plan -ExpectAgentVersion <v> -BootstrapBaseUrl <url>
  powershell.exe -NoProfile -ExecutionPolicy Bypass -File C:\BayMove\Move-BayInstall.ps1 -Mode Move -ExpectAgentVersion <v> -BootstrapBaseUrl <url>
  powershell.exe -NoProfile -ExecutionPolicy Bypass -File C:\BayMove\Move-BayInstall.ps1 -Mode Verify
  powershell.exe -NoProfile -ExecutionPolicy Bypass -File C:\BayMove\Move-BayInstall.ps1 -Mode Back -ExpectAgentVersion <v>

MODES
  Plan    Reads only. Says what it found and what Move would do, or why Move would refuse. Writes nothing anywhere.
  Move    Old root to new root. Asks for the typed word MOVE first, and for the BayKiosk password only when a task's
          own definition needs one to be registered again.
  Verify  Reads only. After the reboot that follows a Move (or a Back): is the agent running from the root it should?
  Back    The way back: the last Move undone from its journal, the same steps in the other direction.

WHAT A BAY INSTALL IS (read from the bay program at 1.6.1) AND WHAT THIS TOOL DOES WITH EACH PART
  1. Two folders under the root, BayAgent (the agent, bootstrap, tools, releases, rollback snapshot, state, logs,
     control markers, the legacy secret file) and SessionDisplay (the wall's pages, data, promos, and the Edge profile
     the wall runs in). Each is MOVED as a whole: a rename on the same volume, so every file keeps its bytes, its time
     and its security descriptor. Nothing is copied and NO FILE IS READ: the proof that nothing was lost is a list of
     names, sizes and times taken before and after (the secret file's content is never opened, hashed or copied).
     The new root is given the old root's access rules first.
  2. Links inside them (current\ was once a junction into releases\<v>): a link into the old root is re-pointed into
     the new one; a link anywhere else stops the run before anything changes.
  3. The bootstrap scripts the two tasks start (ABG.AgentHost.ps1, ABG.HostWatchdog.ps1, and any other mapped ABG.*
     file present): replaced by the release's new-named files (from -BootstrapSource or -BootstrapBaseUrl), each signed
     with the SAME certificate that signed the old ones and timestamped; the old files are kept in the journal.
  4. The two scheduled tasks: re-registered under their new names from their own exported definitions (only the
     paths and file names change; triggers, account, run level and settings are kept), then the old ones removed.
  5. agent-config.json: every value that names the old root names the new one; nothing else in the file changes.
  6. The machine's Winlogon Shell, only when it starts a file under the old root, and only to a file that exists.
  7. Everything else that can name the old root (any other scheduled task, BayKiosk's own Shell value, Run keys,
     Startup folders) is looked for; finding one stops the run before anything changes, because this tool does not
     know how to move it.
  Not this tool's: the Dev command templates that name tools\Update-*.ps1 under the old root (a Dev change), the
  repository rename (GitHub), and the agent's own code (the release; it must take its root from where it is installed).

ORDER OF A MOVE (a failure at any step puts back every step already done, newest first)
  read and check everything; stage and sign the new bootstrap files; register the new tasks DISABLED (a wrong password
  fails here, before the bay is touched); stop.host; old tasks disabled and ended; BayKiosk signed out; wait until no
  process names the old root; move the folders; re-point links; swap the bootstrap files; rewrite agent-config.json;
  Winlogon Shell; enable the new tasks; remove the old tasks; remove the old root if it is empty; check every item of
  "done" again; remove stop.host last. Then the PC is restarted and Verify is run.

EXIT CODES  0 done (or Plan: Move would proceed) | 1 refused, nothing changed | 2 failed, everything put back |
            3 failed and NOT everything could be put back (the journal names what is left) | 4 usage
Hyphens only in comments. ASCII only. Windows PowerShell 5.1.
#>
[CmdletBinding()]
param(
  [ValidateSet("Plan", "Move", "Verify", "Back")][string]$Mode = "Plan",
  [string]$OldRoot = "C:\AllBirdies",
  [string]$NewRoot = "C:\AceOfClubs",
  [string[]]$Folders = @("BayAgent", "SessionDisplay"),
  [string]$ExpectAgentVersion = "",
  [string]$BootstrapSource = "",
  [string]$BootstrapBaseUrl = "",
  [string]$BayKioskUser = "BayKiosk",
  [string]$JournalRoot = "",
  [string]$Journal = "",
  [string]$TimeStampServer = "http://timestamp.digicert.com",
  [int]$StopTimeoutSeconds = 120
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$BmToolVersion = "1.0.0"
# THE NEW NAMES. They must be exactly the names the fleet release gives these files and tasks (FLEET-A); the attack on
# the assembled fleet branch checks the two agree.
$BmTaskNameMap = [ordered]@{
  "ABG Bay Agent"     = "AOC Bay Agent"
  "ABG Host Watchdog" = "AOC Host Watchdog"
}
$BmBootstrapNameMap = [ordered]@{
  "ABG.AgentHost.ps1"                      = "AOC.AgentHost.ps1"
  "ABG.HostWatchdog.ps1"                   = "AOC.HostWatchdog.ps1"
  "ABG.LauncherShell.ps1"                  = "AOC.LauncherShell.ps1"
  "ABG.ReleaseFinalize.ps1"                = "AOC.ReleaseFinalize.ps1"
  "ABG.RotateClientSecretDpapiAndTest.ps1" = "AOC.RotateClientSecretDpapiAndTest.ps1"
  "ABG.SetClientSecretDpapi.ps1"           = "AOC.SetClientSecretDpapi.ps1"
}
# The update guard's own task exists only while an update is being watched; its presence stops a move.
$BmUpdateGuardTaskNames = @("ABG BayAgent Update Guard", "AOC BayAgent Update Guard")
$BmWinlogonKey = "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
$BmRunKeys = @("Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
               "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
               "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run")
$BmStopFileRel = "BayAgent\stop.host"
$BmConfigRel = "BayAgent\agent-config.json"
$BmBootstrapRel = "BayAgent\bootstrap"
$BmSecretsRel = "BayAgent\secrets"
$BmMinScriptBytes = 1024

# ------------------------------------------------------------------ output
$script:BmLogFile = $null
function Write-BmLine([string]$Text, [string]$Color = "Gray") {
  Write-Host $Text -ForegroundColor $Color
  if ($null -ne $script:BmLogFile) {
    try { [IO.File]::AppendAllText($script:BmLogFile, ((Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ") + " " + $Text + "`r`n")) } catch { }
  }
}
function Write-BmStep([string]$Text) { Write-BmLine "" ; Write-BmLine ("== " + $Text) "Cyan" }

# ------------------------------------------------------------------ pure helpers (no machine access)
function Get-BmFullPath([string]$Path) {
  return [IO.Path]::GetFullPath($Path).TrimEnd('\')
}

function Test-BmUnder([string]$Path, [string]$Root) {
  # True when $Path is $Root or inside it, on a path boundary, case-insensitive.
  if ([string]::IsNullOrWhiteSpace($Path) -or [string]::IsNullOrWhiteSpace($Root)) { return $false }
  $p = (Get-BmFullPath $Path) + '\'
  $r = (Get-BmFullPath $Root) + '\'
  return $p.StartsWith($r, [StringComparison]::OrdinalIgnoreCase)
}

function Get-BmRootPattern([string]$Root) {
  # A regex for $Root written with any separator a bay file uses: \ (a path), \\ (inside JSON), / (a file address).
  # Not preceded by a letter or digit (so "https://" is never read as a drive), and ending at a separator, a quote,
  # whitespace or the end of the text (so C:\AllBirdiesX is not C:\AllBirdies).
  $segs = @((Get-BmFullPath $Root).Split('\') | Where-Object { $_ -ne "" })
  $sep = '(?:\\\\|\\|/)'
  $body = (@($segs | ForEach-Object { [regex]::Escape($_) }) -join $sep)
  return ('(?i)(?<![A-Za-z0-9])' + $body + '(?=\\|/|"|''|\s|$)')
}

function Test-BmNamesRoot([string]$Text, [string]$Root) {
  if ([string]::IsNullOrEmpty($Text)) { return $false }
  return [regex]::IsMatch($Text, (Get-BmRootPattern $Root))
}

function Convert-BmPathText {
  # Every mention of $From in $Text becomes $To, written with the separator the mention used; a path to a mapped
  # bootstrap file also takes the mapped file name. Returns @{ Text; Count }. Never throws inside the evaluator
  # (a throw there is swallowed by [regex]::Replace).
  param([string]$Text, [string]$From, [string]$To, $NameMap)
  if ([string]::IsNullOrEmpty($Text)) { return @{ Text = $Text; Count = 0 } }
  $toSegs = @((Get-BmFullPath $To).Split('\') | Where-Object { $_ -ne "" })
  $segRx = '(?:(?:\\\\|\\|/)[A-Za-z0-9._-]+)*'
  $rx = New-Object System.Text.RegularExpressions.Regex(((Get-BmRootPattern $From) -replace '\(\?=.*$', '') + '(?<rest>' + $segRx + ')(?=\\|/|"|''|\s|$)')
  $state = @{ Count = 0 }
  $out = $rx.Replace($Text, [System.Text.RegularExpressions.MatchEvaluator] {
      param($m)
      $whole = $m.Value
      $rest = $m.Groups['rest'].Value
      $head = $whole.Substring(0, $whole.Length - $rest.Length)
      $sm = [regex]::Match($head, '\\\\|\\|/')
      $sepUsed = $(if ($sm.Success) { $sm.Value } else { '\' })
      $newHead = ($toSegs -join $sepUsed)
      $newRest = $rest
      if ($null -ne $NameMap) {
        $parts = [regex]::Split($rest, '\\\\|\\|/')
        if ($parts.Count -ge 4 -and $parts[1] -ieq 'BayAgent' -and $parts[2] -ieq 'bootstrap') {
          foreach ($k in @($NameMap.Keys)) {
            if ($parts[3] -ieq [string]$k) {
              $restSep = [regex]::Match($rest, '\\\\|\\|/').Value
              $parts[3] = [string]$NameMap[$k]
              $newRest = ($parts -join $restSep)
            }
          }
        }
      }
      $state.Count++
      return ($newHead + $newRest)
    })
  return @{ Text = $out; Count = $state.Count }
}

function Get-BmReverseMap($Map) {
  $r = [ordered]@{}
  foreach ($k in @($Map.Keys)) { $r[[string]$Map[$k]] = [string]$k }
  return $r
}

function Get-BmTaskNs { return "http://schemas.microsoft.com/windows/2004/02/mit/task" }

function Convert-BmTaskXml {
  # A task definition (Export-ScheduledTask's text) for its new place: every Exec action's command, arguments and
  # working folder converted, the URI set to the new name, Enabled set as asked. Everything else is kept as it was.
  param([string]$Xml, [string]$From, [string]$To, $NameMap, [string]$NewName, [bool]$Enabled)
  $doc = New-Object System.Xml.XmlDocument
  $doc.PreserveWhitespace = $true
  $doc.LoadXml($Xml)
  $ns = New-Object System.Xml.XmlNamespaceManager($doc.NameTable)
  $ns.AddNamespace("t", (Get-BmTaskNs))
  $changed = 0
  foreach ($n in @($doc.SelectNodes("/t:Task/t:Actions/t:Exec/t:Command | /t:Task/t:Actions/t:Exec/t:Arguments | /t:Task/t:Actions/t:Exec/t:WorkingDirectory", $ns))) {
    $c = Convert-BmPathText -Text $n.InnerText -From $From -To $To -NameMap $NameMap
    if ($c.Count -gt 0) { $n.InnerText = $c.Text; $changed += $c.Count }
  }
  $uri = $doc.SelectSingleNode("/t:Task/t:RegistrationInfo/t:URI", $ns)
  if ($null -ne $uri) { $uri.InnerText = ("\" + $NewName) }
  $settings = $doc.SelectSingleNode("/t:Task/t:Settings", $ns)
  if ($null -eq $settings) { throw "the task definition has no Settings element" }
  $en = $settings.SelectSingleNode("t:Enabled", $ns)
  if ($null -eq $en) { $en = $doc.CreateElement("Enabled", (Get-BmTaskNs)); [void]$settings.AppendChild($en) }
  $en.InnerText = $(if ($Enabled) { "true" } else { "false" })
  return @{ Xml = $doc.OuterXml; Changed = $changed }
}

function Get-BmFileArgs([string]$CommandText) {
  # The script(s) a PowerShell command line starts with -File.
  $out = @()
  foreach ($m in @([regex]::Matches([string]$CommandText, '(?i)-File\s+(?:"([^"]+)"|(\S+))'))) {
    $out += $(if ($m.Groups[1].Success) { $m.Groups[1].Value } else { $m.Groups[2].Value })
  }
  return , $out
}

function ConvertTo-BmSid([string]$Account) {
  # An account as its SID, so "SYSTEM", "NT AUTHORITY\SYSTEM" and S-1-5-18 compare equal. An account that cannot be
  # resolved is compared as written, in lower case.
  if ([string]::IsNullOrWhiteSpace($Account)) { return "" }
  if ($Account -match '^S-1-') { return $Account.ToUpperInvariant() }
  try { return (New-Object Security.Principal.NTAccount($Account)).Translate([Security.Principal.SecurityIdentifier]).Value }
  catch { return $Account.ToLowerInvariant() }
}

function ConvertTo-BmAccountName([string]$Account) {
  # The name form of an account (a task definition may carry a SID; a password goes with a name).
  if ($Account -notmatch '^S-1-') { return $Account }
  try { return (New-Object Security.Principal.SecurityIdentifier($Account)).Translate([Security.Principal.NTAccount]).Value }
  catch { return $Account }
}

function Get-BmTaskXmlFacts([string]$Xml) {
  # The facts of a definition the move depends on: its account, how it signs in, and the script each action starts.
  $doc = New-Object System.Xml.XmlDocument
  $doc.LoadXml($Xml)
  $ns = New-Object System.Xml.XmlNamespaceManager($doc.NameTable)
  $ns.AddNamespace("t", (Get-BmTaskNs))
  $p = $doc.SelectSingleNode("/t:Task/t:Principals/t:Principal", $ns)
  $user = ""; $logon = ""
  if ($null -ne $p) {
    $u = $p.SelectSingleNode("t:UserId", $ns); if ($null -ne $u) { $user = $u.InnerText }
    $l = $p.SelectSingleNode("t:LogonType", $ns); if ($null -ne $l) { $logon = $l.InnerText }
  }
  $files = @()
  foreach ($a in @($doc.SelectNodes("/t:Task/t:Actions/t:Exec/t:Arguments", $ns))) { $files += @(Get-BmFileArgs $a.InnerText) }
  $en = $doc.SelectSingleNode("/t:Task/t:Settings/t:Enabled", $ns)
  return @{
    User = $user
    LogonType = $logon
    NeedsPw = (@("Password", "InteractiveTokenOrPassword") -contains $logon)
    Files = $files
    Enabled = ($null -eq $en -or $en.InnerText -ne "false")
  }
}

function Convert-BmConfigText {
  # agent-config.json for the new root: each string value that names $From names $To; nothing else changes. The text
  # is edited in place (so its layout, escaping and order stay), then both versions are parsed and compared value by
  # value: every changed value must be one that named $From, and no value may name $From afterwards.
  param([string]$Text, [string]$From, [string]$To, $NameMap)
  $c = Convert-BmPathText -Text $Text -From $From -To $To -NameMap $NameMap
  $before = @(Get-BmJsonLeaves ($Text | ConvertFrom-Json) "")
  $after = @(Get-BmJsonLeaves ($c.Text | ConvertFrom-Json) "")
  if ($before.Count -ne $after.Count) { throw "agent-config.json changed shape while its paths were rewritten" }
  $changes = @()
  for ($i = 0; $i -lt $before.Count; $i++) {
    if ($before[$i].Path -ne $after[$i].Path) { throw "agent-config.json changed shape at $($before[$i].Path)" }
    $bv = [string]$before[$i].Value; $av = [string]$after[$i].Value
    if ($bv -cne $av) {
      if (-not (Test-BmNamesRoot $bv $From)) { throw "agent-config.json value $($before[$i].Path) changed though it did not name $From" }
      $changes += @{ Path = $before[$i].Path; Before = $bv; After = $av }
    }
    if (Test-BmNamesRoot $av $From) { throw "agent-config.json value $($after[$i].Path) still names $From" }
  }
  return @{ Text = $c.Text; Changes = $changes }
}

function Get-BmJsonLeaves($Node, [string]$Prefix) {
  $out = @()
  if ($null -eq $Node) { return , @(@{ Path = $Prefix; Value = $null }) }
  if ($Node -is [System.Management.Automation.PSCustomObject]) {
    foreach ($p in @($Node.PSObject.Properties)) { $out += @(Get-BmJsonLeaves $p.Value ($Prefix + "." + $p.Name)) }
    return , $out
  }
  if ($Node -is [Array]) {
    for ($i = 0; $i -lt $Node.Count; $i++) { $out += @(Get-BmJsonLeaves $Node[$i] ($Prefix + "[" + $i + "]")) }
    return , $out
  }
  return , @(@{ Path = $Prefix; Value = $Node })
}

function Read-BmBytesAsText([string]$Path) {
  # @{ Text; Bom } for a UTF-8 file, so it can be written back the way it was found.
  $b = [IO.File]::ReadAllBytes($Path)
  $bom = ($b.Length -ge 3 -and $b[0] -eq 0xEF -and $b[1] -eq 0xBB -and $b[2] -eq 0xBF)
  $start = $(if ($bom) { 3 } else { 0 })
  return @{ Text = [Text.Encoding]::UTF8.GetString($b, $start, $b.Length - $start); Bom = $bom }
}

function Get-BmTextBytes([string]$Text, [bool]$Bom) {
  $body = [Text.Encoding]::UTF8.GetBytes($Text)
  if (-not $Bom) { return , $body }
  $all = New-Object byte[] ($body.Length + 3)
  $all[0] = 0xEF; $all[1] = 0xBB; $all[2] = 0xBF
  [Array]::Copy($body, 0, $all, 3, $body.Length)
  return , $all
}

function Write-BmFileAtomic([string]$Path, [byte[]]$Bytes) {
  $tmp = $Path + ".bmtmp"
  [IO.File]::WriteAllBytes($tmp, $Bytes)
  if ([IO.File]::Exists($Path)) { [IO.File]::Replace($tmp, $Path, [NullString]::Value, $true) }
  else { [IO.File]::Move($tmp, $Path) }
}

function Get-BmTreeManifest([string]$Root) {
  # Every entry under $Root as "relative path|kind|length|last write ticks|link target", from directory listings only:
  # no file is opened. A link is listed with its target and never followed.
  $list = New-Object System.Collections.ArrayList
  if (-not [IO.Directory]::Exists($Root)) { return , @() }
  $full = (Get-BmFullPath $Root)
  $stack = New-Object System.Collections.Stack
  $stack.Push((New-Object IO.DirectoryInfo($full)))
  while ($stack.Count -gt 0) {
    $d = $stack.Pop()
    foreach ($e in @($d.GetFileSystemInfos())) {
      $rel = $e.FullName.Substring($full.Length).TrimStart('\')
      $isLink = (($e.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0)
      if ($e -is [IO.DirectoryInfo]) {
        if ($isLink) { [void]$list.Add(("{0}|link|0|0|{1}" -f $rel, (Get-BmLinkTarget $e.FullName))) }
        else { [void]$list.Add(("{0}|dir|0|0|" -f $rel)); $stack.Push($e) }
      } else {
        $kind = $(if ($isLink) { "filelink" } else { "file" })
        [void]$list.Add(("{0}|{1}|{2}|{3}|" -f $rel, $kind, $e.Length, $e.LastWriteTimeUtc.Ticks))
      }
    }
  }
  return , @($list.ToArray() | Sort-Object)
}

function Get-BmLinkTarget([string]$Path) {
  try {
    $t = @((Get-Item -LiteralPath $Path -Force).Target)
    return ([string]($t -join ";"))
  } catch { return "" }
}

function Get-BmLinks([string]$Root) {
  $out = @()
  foreach ($line in @(Get-BmTreeManifest $Root)) {
    $f = $line.Split('|')
    if ($f[1] -eq "link" -or $f[1] -eq "filelink") { $out += @{ Rel = $f[0]; Kind = $f[1]; Target = $f[4] } }
  }
  return , $out
}

function Compare-BmManifest([string[]]$Before, [string[]]$After, [string[]]$Ignore) {
  # Differences as text; empty means equal. $Ignore: relative paths (lower case) expected to differ.
  $ig = @{}; foreach ($i in @($Ignore)) { $ig[$i.ToLowerInvariant()] = $true }
  $b = @{}; foreach ($l in @($Before)) { $k = $l.Split('|')[0].ToLowerInvariant(); if (-not $ig.ContainsKey($k)) { $b[$k] = $l } }
  $a = @{}; foreach ($l in @($After)) { $k = $l.Split('|')[0].ToLowerInvariant(); if (-not $ig.ContainsKey($k)) { $a[$k] = $l } }
  $d = @()
  foreach ($k in @($b.Keys | Sort-Object)) {
    if (-not $a.ContainsKey($k)) { $d += "missing $k" }
    elseif ($a[$k] -ne $b[$k] -and -not ($b[$k].Split('|')[1] -eq 'link')) { $d += "different $k" }
  }
  foreach ($k in @($a.Keys | Sort-Object)) { if (-not $b.ContainsKey($k)) { $d += "extra $k" } }
  return , $d
}

function Get-BmDaclSddl([string]$Path) {
  return (Get-Acl -LiteralPath $Path).GetSecurityDescriptorSddlForm([System.Security.AccessControl.AccessControlSections]::Access)
}

function Test-BmScriptText([string]$Path, [string]$MustNotName) {
  # A script that is going to be started by a task: it exists, is not a stub, parses, is ASCII, and does not name the
  # root it is moving away from (a release whose bootstrap still hardcodes the old root would start nothing).
  $why = @()
  if (-not [IO.File]::Exists($Path)) { return , @("not found") }
  $len = (New-Object IO.FileInfo($Path)).Length
  if ($len -lt $BmMinScriptBytes) { $why += "only $len bytes" }
  $bytes = [IO.File]::ReadAllBytes($Path)
  $start = $(if ($bytes.Length -ge 3 -and $bytes[0] -eq 0xEF -and $bytes[1] -eq 0xBB -and $bytes[2] -eq 0xBF) { 3 } else { 0 })
  for ($i = $start; $i -lt $bytes.Length; $i++) { if ($bytes[$i] -gt 0x7F) { $why += "not ASCII (byte $i)"; break } }
  $tok = $null; $err = $null
  [void][System.Management.Automation.Language.Parser]::ParseFile($Path, [ref]$tok, [ref]$err)
  if (@($err).Count -gt 0) { $why += ("does not parse: " + $err[0].Message) }
  if (-not [string]::IsNullOrEmpty($MustNotName)) {
    $text = [IO.File]::ReadAllText($Path)
    $body = ($text -split '# SIG # Begin signature block')[0]
    if (Test-BmNamesRoot $body $MustNotName) { $why += "still names $MustNotName" }
  }
  return , $why
}

# ------------------------------------------------------------------ machine reads and writes (each through a cmdlet or program)
function Test-BmIsAdmin {
  $bmPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
  return $bmPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Get-BmRegValue([string]$Key, [string]$Name) {
  # A registry value or $null. Never throws: a missing key or value is an answer.
  $item = $null
  try { $item = Get-ItemProperty -Path $Key -Name $Name -ErrorAction SilentlyContinue } catch { $item = $null }
  if ($null -eq $item) { return $null }
  $p = $item.PSObject.Properties[$Name]
  if ($null -eq $p) { return $null }
  return $p.Value
}

function Get-BmRegValues([string]$Key) {
  # All values of a key as name -> value, or an empty table.
  $out = @{}
  $item = $null
  try { $item = Get-ItemProperty -Path $Key -ErrorAction SilentlyContinue } catch { $item = $null }
  if ($null -eq $item) { return $out }
  foreach ($p in @($item.PSObject.Properties)) { if ($p.Name -notlike "PS*") { $out[$p.Name] = $p.Value } }
  return $out
}

function Get-BmKioskSid([string]$User) {
  try { return [string](Get-LocalUser -Name $User -ErrorAction Stop).SID.Value } catch { return "" }
}

function Get-BmAllTasks {
  return @(Get-ScheduledTask -ErrorAction Stop)
}

function Get-BmTaskText($Task) {
  $t = @()
  foreach ($a in @($Task.Actions)) {
    foreach ($n in @("Execute", "Arguments", "WorkingDirectory")) {
      $p = $a.PSObject.Properties[$n]
      if ($null -ne $p -and $null -ne $p.Value) { $t += [string]$p.Value }
    }
  }
  return ($t -join " ")
}

function Get-BmTask([string]$Name) {
  try { return (Get-ScheduledTask -TaskName $Name -TaskPath "\" -ErrorAction Stop) } catch { return $null }
}

function Register-BmTask {
  # Registers a task from a definition. THE PASSWORD is taken from a SecureString only here, used for this one call,
  # never logged, never in an error text, and the error records of this call are removed from $Error (their bound
  # parameters would hold it). The verbose and debug streams of the cmdlet are off whatever the caller asked for.
  param([string]$Name, [string]$Xml, [string]$User, [System.Security.SecureString]$Password)
  $VerbosePreference = "SilentlyContinue"; $DebugPreference = "SilentlyContinue"
  $failed = $null
  if ($null -ne $Password) {
    $bstr = [IntPtr]::Zero
    $plainPw = $null
    try {
      $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($Password)
      $plainPw = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)
      Register-ScheduledTask -TaskName $Name -TaskPath "\" -Xml $Xml -User $User -Password $plainPw -Force -Verbose:$false -Debug:$false -ErrorAction Stop | Out-Null
    } catch {
      $msg = [string]$_.Exception.Message
      if (-not [string]::IsNullOrEmpty($plainPw)) { $msg = $msg.Replace($plainPw, "<password>") }
      $failed = $msg
    } finally {
      $plainPw = $null
      if ($bstr -ne [IntPtr]::Zero) { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr) }
      Remove-BmErrorsOf "Register-ScheduledTask"
    }
  } else {
    try {
      if ([string]::IsNullOrEmpty($User)) { Register-ScheduledTask -TaskName $Name -TaskPath "\" -Xml $Xml -Force -Verbose:$false -Debug:$false -ErrorAction Stop | Out-Null }
      else { Register-ScheduledTask -TaskName $Name -TaskPath "\" -Xml $Xml -User $User -Force -Verbose:$false -Debug:$false -ErrorAction Stop | Out-Null }
    } catch { $failed = [string]$_.Exception.Message }
  }
  if ($null -ne $failed) { throw ("registering the task '{0}' failed: {1}" -f $Name, $failed) }
}

function Remove-BmErrorsOf([string]$CommandName) {
  try {
    for ($i = $global:Error.Count - 1; $i -ge 0; $i--) {
      $e = $global:Error[$i]
      $n = ""
      try { $n = [string]$e.InvocationInfo.MyCommand.Name } catch { }
      if ($n -eq $CommandName -or ("$e" -match [regex]::Escape($CommandName))) { $global:Error.RemoveAt($i) }
    }
  } catch { }
}

function Get-BmKioskSessions([string]$User) {
  $ids = @()
  foreach ($p in @(Get-Process -IncludeUserName -ErrorAction SilentlyContinue)) {
    $u = [string]$p.UserName
    if ($u -ieq $User -or $u -like ("*\" + $User)) { $ids += [int]$p.SessionId }
  }
  return , @($ids | Sort-Object -Unique)
}

function Get-BmProcessesNaming([string]$Root) {
  $hits = @()
  foreach ($p in @(Get-CimInstance -ClassName Win32_Process -ErrorAction Stop)) {
    $cl = [string]$p.CommandLine; $ex = [string]$p.ExecutablePath
    if ((Test-BmNamesRoot $cl $Root) -or (Test-BmNamesRoot $ex $Root)) {
      $hits += @{ Id = [int]$p.ProcessId; Name = [string]$p.Name; CommandLine = $cl }
    }
  }
  return , $hits
}

function Get-BmSigningCert([string]$SignedFile) {
  # The certificate that signed $SignedFile, from the machine's store, with its private key. The new files are signed
  # with it so they are trusted exactly as the old ones were (the agent requires its kiosk shell to share its signer).
  $sig = Get-AuthenticodeSignature -FilePath $SignedFile
  if ([string]$sig.Status -ne "Valid" -or $null -eq $sig.SignerCertificate) { throw "$SignedFile is not validly signed ($($sig.Status)); the signing certificate cannot be found from it" }
  $tp = [string]$sig.SignerCertificate.Thumbprint
  $c = @(Get-ChildItem -Path "Cert:\LocalMachine\My" | Where-Object { $_.Thumbprint -eq $tp -and $_.HasPrivateKey })
  if ($c.Count -ne 1) { throw "the certificate that signed $SignedFile ($tp) is not in LocalMachine\My with its private key" }
  return $c[0]
}

function Test-BmSignedBy([string]$Path, [string]$Thumbprint) {
  $sig = Get-AuthenticodeSignature -FilePath $Path
  if ([string]$sig.Status -ne "Valid") { return ("signature " + [string]$sig.Status) }
  if ($null -eq $sig.TimeStamperCertificate) { return "signature not timestamped" }
  if ($null -eq $sig.SignerCertificate -or [string]$sig.SignerCertificate.Thumbprint -ne $Thumbprint) { return "signed by another certificate" }
  return ""
}

# ------------------------------------------------------------------ journal
$script:BmJ = $null
$script:BmJDir = $null
function Save-BmJournal {
  if ($null -eq $script:BmJDir) { return }
  $p = Join-Path $script:BmJDir "journal.json"
  Write-BmFileAtomic $p ([Text.Encoding]::UTF8.GetBytes(($script:BmJ | ConvertTo-Json -Depth 10)))
}
function Add-BmUndo([hashtable]$Rec) {
  $script:BmJ.undo += $Rec
  Save-BmJournal
}
function Get-BmLatestJournal([string]$JRoot) {
  if (-not [IO.Directory]::Exists($JRoot)) { return $null }
  foreach ($d in @([IO.Directory]::GetDirectories($JRoot) | Sort-Object -Descending)) {
    $jp = Join-Path $d "journal.json"
    if (-not [IO.File]::Exists($jp)) { continue }
    try { $j = [IO.File]::ReadAllText($jp) | ConvertFrom-Json } catch { continue }
    if ([string]$j.mode -eq "Move" -and [string]$j.state -eq "moved") { return $d }
    if ([string]$j.mode -eq "Back" -and [string]$j.state -eq "moved") { return $null }
  }
  return $null
}

# ------------------------------------------------------------------ the plan
function New-BmPlan {
  # Everything a cutover needs, read and checked before anything changes. Returns @{ Ok; Refusals; ... }.
  param([string]$Direction, [string]$From, [string]$To, $TaskMap, $FileMap, [string]$StagedDir, $JournalIn)
  $r = @{ Ok = $true; Refusals = @(); Notes = @(); Direction = $Direction; From = $From; To = $To; Folders = @(); Tasks = @();
          Bootstrap = @(); Config = $null; Winlogon = $null; Links = @(); KioskSessions = @(); NeedsPw = $false; SignerThumbprint = ""; KioskUser = $BayKioskUser }
  function Refuse([string]$m) { $r.Ok = $false; $r.Refusals += $m }

  # -- where this runs
  $self = [string]$PSCommandPath
  if ((Test-BmUnder $self $From) -or (Test-BmUnder $self $To)) { Refuse "this tool is running from inside a root it moves ($self); copy it to a folder outside both (for example C:\BayMove) and run it from there" }
  $here = (Get-Location).ProviderPath
  if ((Test-BmUnder $here $From) -or (Test-BmUnder $here $To)) { Refuse "the current folder ($here) is inside a root this tool moves; cd to another folder first" }
  if ((Test-BmUnder $From $To) -or (Test-BmUnder $To $From)) { Refuse "the two roots are inside one another ($From, $To)" }
  if ([IO.Path]::GetPathRoot((Get-BmFullPath $From)) -ine [IO.Path]::GetPathRoot((Get-BmFullPath $To))) { Refuse "the two roots are on different volumes; a move must be a rename on one volume" }

  # -- the folders
  foreach ($f in @($Folders)) {
    $src = Join-Path $From $f; $dst = Join-Path $To $f
    $present = [IO.Directory]::Exists($src)
    if ($f -ieq "BayAgent" -and -not $present) { Refuse "$src does not exist: there is no install here to move" }
    if ([IO.Directory]::Exists($dst) -or [IO.File]::Exists($dst)) { Refuse "$dst already exists; a move never merges into or over an existing folder" }
    if ($present) {
      $srcItem = Get-Item -LiteralPath $src -Force
      if (($srcItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { Refuse "$src is itself a link; this tool moves real folders only" }
      $r.Folders += @{ Name = $f; From = $src; To = $dst; Dacl = (Get-BmDaclSddl $src) }
      if ($f -ieq "BayAgent" -and [IO.Directory]::Exists((Join-Path $From $BmSecretsRel))) {
        # The secret folder's own (restricted) access rules are checked on their own after the move. Its files are
        # listed by name, size and time only; nothing in it is opened.
        $r.SecretsDacl = Get-BmDaclSddl (Join-Path $From $BmSecretsRel)
      }
    } else { $r.Notes += "$src is not present; nothing to move for it" }
  }
  if ([IO.Directory]::Exists($From)) {
    foreach ($d in @([IO.Directory]::GetFileSystemEntries($From))) {
      $leaf = [IO.Path]::GetFileName($d)
      if (@($Folders) -notcontains $leaf) { $r.Notes += "$d is not part of the install and is left where it is (the old root then stays)" }
    }
  }

  # -- links inside the folders
  foreach ($fo in @($r.Folders)) {
    foreach ($l in @(Get-BmLinks $fo.From)) {
      $abs = Join-Path $fo.From $l.Rel
      if ([string]::IsNullOrEmpty($l.Target)) { Refuse "the link $abs has a target this tool cannot read" ; continue }
      if (-not (Test-BmUnder $l.Target $From)) { Refuse "the link $abs points outside the old root ($($l.Target)); move it by hand first" ; continue }
      if ($l.Kind -ne "link") { Refuse "the file link $abs is not supported" ; continue }
      $newTarget = (Convert-BmPathText -Text $l.Target -From $From -To $To -NameMap $null).Text
      $r.Links += @{ Rel = (Join-Path $fo.Name $l.Rel); OldTarget = $l.Target; NewTarget = $newTarget }
    }
  }

  $baseFrom = Join-Path $From "BayAgent"
  # -- the agent that will run at the new root must take its root from where it is installed
  $manifestPath = Join-Path $baseFrom "current\manifest.json"
  $installed = ""
  try { $installed = [string]([IO.File]::ReadAllText($manifestPath) | ConvertFrom-Json).version } catch { $installed = "" }
  $r.InstalledVersion = $installed
  if ([string]::IsNullOrWhiteSpace($ExpectAgentVersion)) { Refuse "-ExpectAgentVersion is required: the version of the release that takes its root from where it is installed (the run sheet names it)" }
  elseif ($installed -ne $ExpectAgentVersion) { Refuse ("the installed agent is '{0}' (current\manifest.json), not '{1}': install that release at the old root first" -f $installed, $ExpectAgentVersion) }

  # -- the bay must be at rest: no update being watched, not stopped on purpose
  $pend = Join-Path $baseFrom "state\update-pending.json"
  if ([IO.File]::Exists($pend)) {
    $ph = ""
    try { $ph = [string]([IO.File]::ReadAllText($pend) | ConvertFrom-Json).phase } catch { $ph = "unreadable" }
    if ($ph -ne "aborted") { Refuse "an update is in flight or still being watched (state\update-pending.json phase '$ph'); wait for its guard to finish" }
  }
  foreach ($sf in @("stop.host", "control\stop.host")) {
    if ([IO.File]::Exists((Join-Path $baseFrom $sf))) { Refuse "BayAgent\$sf is present: the bay was stopped on purpose; find out why before moving it" }
  }

  # -- the configuration
  $cfgPath = Join-Path $From $BmConfigRel
  if (-not [IO.File]::Exists($cfgPath)) { Refuse "$cfgPath not found" }
  else {
    try {
      $raw = Read-BmBytesAsText $cfgPath
      $conv = Convert-BmConfigText -Text $raw.Text -From $From -To $To -NameMap $FileMap
      $r.Config = @{ Rel = $BmConfigRel; Bom = $raw.Bom; OldText = $raw.Text; NewText = $conv.Text; Changes = $conv.Changes }
    } catch { Refuse ("agent-config.json cannot be rewritten: " + $_.Exception.Message) }
  }

  # -- the bootstrap files
  $bsFrom = Join-Path $From $BmBootstrapRel
  $firstSigned = $null
  foreach ($k in @($FileMap.Keys)) {
    $oldFile = Join-Path $bsFrom $k
    if (-not [IO.File]::Exists($oldFile)) { continue }
    $newName = [string]$FileMap[$k]
    if ([IO.File]::Exists((Join-Path $bsFrom $newName))) { Refuse "bootstrap\$newName already exists beside bootstrap\$k; this tool does not know which one the bay runs" }
    $r.Bootstrap += @{ FromName = [string]$k; ToName = $newName; Staged = (Join-Path $StagedDir $newName) }
    if ($null -eq $firstSigned) { $firstSigned = $oldFile }
  }
  if (@($r.Bootstrap).Count -eq 0) { Refuse "no bootstrap file this tool maps was found in $bsFrom" }
  else {
    try { $r.SigningCert = Get-BmSigningCert $firstSigned; $r.SignerThumbprint = [string]$r.SigningCert.Thumbprint }
    catch { Refuse $_.Exception.Message }
  }

  # -- the scheduled tasks: the mapped ones, and nothing else may name the old root
  $all = @()
  try { $all = Get-BmAllTasks } catch { Refuse ("the scheduled tasks cannot be read: " + $_.Exception.Message) }
  foreach ($t in @($all)) {
    $tn = [string]$t.TaskName
    if ($BmUpdateGuardTaskNames -contains $tn) { Refuse "the task '$tn' exists: an update's rollback guard is registered; wait for it to finish" ; continue }
    if (Test-BmNamesRoot (Get-BmTaskText $t) $From) {
      if (-not ($TaskMap.Contains($tn) -and [string]$t.TaskPath -eq "\")) { Refuse ("the task '{0}{1}' starts something under {2} and this tool does not move it" -f $t.TaskPath, $tn, $From) }
    }
  }
  foreach ($k in @($TaskMap.Keys)) {
    $oldName = [string]$k; $newName = [string]$TaskMap[$k]
    if ($null -ne (Get-BmTask $newName)) { Refuse "a task named '$newName' already exists" }
    $xml = $null
    if ($Direction -eq "Back" -and $null -ne $JournalIn) {
      $jf = Join-Path $JournalIn ("task-" + ($newName -replace '[^A-Za-z0-9]', '_') + ".xml")
      if (-not [IO.File]::Exists($jf)) { Refuse "the journal has no saved definition for '$newName' ($jf)" ; continue }
      $xml = [IO.File]::ReadAllText($jf)
      if ($null -eq (Get-BmTask $oldName)) { Refuse "the task '$oldName' is not registered; the move it would undo is not in place" ; continue }
    } else {
      if ($null -eq (Get-BmTask $oldName)) { Refuse "the task '$oldName' is not registered; a set-up bay has it" ; continue }
      try { $xml = [string](Export-ScheduledTask -TaskName $oldName -TaskPath "\") } catch { Refuse ("the task '$oldName' cannot be exported: " + $_.Exception.Message) ; continue }
    }
    $oldXml = $(if ($Direction -eq "Back") { $null } else { $xml })
    if ($Direction -eq "Back") {
      try { $oldXml = [string](Export-ScheduledTask -TaskName $oldName -TaskPath "\") } catch { Refuse ("the task '$oldName' cannot be exported: " + $_.Exception.Message) ; continue }
    }
    $facts = Get-BmTaskXmlFacts $xml
    $conv = $(if ($Direction -eq "Back") { Convert-BmTaskXml -Xml $xml -From $To -To $To -NameMap $null -NewName $newName -Enabled $false }
              else { Convert-BmTaskXml -Xml $xml -From $From -To $To -NameMap $FileMap -NewName $newName -Enabled $false })
    if (Test-BmNamesRoot $conv.Xml $From) { Refuse "the new definition of '$newName' would still name $From" }
    foreach ($ff in @((Get-BmTaskXmlFacts $conv.Xml).Files)) {
      if (-not (Test-BmUnder $ff $To)) { $r.Notes += "the task '$newName' starts $ff, which is not under $To" }
    }
    if ($facts.NeedsPw) { $r.NeedsPw = $true }
    $r.Tasks += @{ OldName = $oldName; NewName = $newName; OldXml = $oldXml; NewXml = $conv.Xml; User = $facts.User; LogonType = $facts.LogonType; NeedsPw = $facts.NeedsPw; WasEnabled = $facts.Enabled }
  }

  # -- Winlogon Shell (the machine's), BayKiosk's own Shell, Run keys, Startup folders
  $shell = Get-BmRegValue $BmWinlogonKey "Shell"
  if ($null -ne $shell -and (Test-BmNamesRoot ([string]$shell) $From)) {
    $ns = (Convert-BmPathText -Text ([string]$shell) -From $From -To $To -NameMap $FileMap).Text
    $r.Winlogon = @{ Key = $BmWinlogonKey; Name = "Shell"; Old = [string]$shell; New = $ns }
  }
  $sid = Get-BmKioskSid $BayKioskUser
  if ([string]::IsNullOrEmpty($sid)) { $r.Notes += "the account $BayKioskUser was not found; its own registry was not read" }
  else {
    $uKey = "Registry::HKEY_USERS\$sid"
    if (-not (Test-Path -Path $uKey)) { $r.Notes += "$BayKioskUser is not signed in, so its own Shell value and Run keys could not be read" }
    else {
      $us = Get-BmRegValue ($uKey + "\Software\Microsoft\Windows NT\CurrentVersion\Winlogon") "Shell"
      if ($null -ne $us -and (Test-BmNamesRoot ([string]$us) $From)) { Refuse "$BayKioskUser's own Shell value starts a file under $From; this tool does not edit an account's own registry" }
      foreach ($rk in @("\Software\Microsoft\Windows\CurrentVersion\Run", "\Software\Microsoft\Windows\CurrentVersion\RunOnce")) {
        $vals = Get-BmRegValues ($uKey + $rk)
        foreach ($vn in @($vals.Keys)) { if (Test-BmNamesRoot ([string]$vals[$vn]) $From) { Refuse "$BayKioskUser's $rk value '$vn' names $From" } }
      }
    }
  }
  foreach ($rk in $BmRunKeys) {
    $vals = Get-BmRegValues $rk
    foreach ($vn in @($vals.Keys)) { if (Test-BmNamesRoot ([string]$vals[$vn]) $From) { Refuse "the Run value '$vn' in $rk names $From" } }
  }
  $startups = @((Join-Path $env:ProgramData "Microsoft\Windows\Start Menu\Programs\StartUp"),
                ("C:\Users\" + $BayKioskUser + "\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup"))
  foreach ($sd in $startups) {
    if (-not [IO.Directory]::Exists($sd)) { continue }
    foreach ($sf in @([IO.Directory]::GetFiles($sd))) {
      $ext = [IO.Path]::GetExtension($sf).ToLowerInvariant()
      $txt = ""
      if ($ext -eq ".lnk") {
        try { $ws = New-Object -ComObject WScript.Shell; $sc = $ws.CreateShortcut($sf); $txt = ([string]$sc.TargetPath + " " + [string]$sc.Arguments + " " + [string]$sc.WorkingDirectory) } catch { $txt = "" }
      } elseif (@(".cmd", ".bat", ".ps1", ".vbs", ".url") -contains $ext) { try { $txt = [IO.File]::ReadAllText($sf) } catch { $txt = "" } }
      if (Test-BmNamesRoot $txt $From) { Refuse "the Startup item $sf names $From" }
    }
  }

  # -- who is signed in as the kiosk account
  try { $r.KioskSessions = @(Get-BmKioskSessions $BayKioskUser) } catch { $r.Notes += "the kiosk account's sessions could not be read" }
  return $r
}

function Show-BmPlan($P) {
  Write-BmStep ("Plan: {0} from {1} to {2}" -f $P.Direction, $P.From, $P.To)
  Write-BmLine ("  installed agent version: " + $P.InstalledVersion)
  foreach ($f in @($P.Folders)) { Write-BmLine ("  move folder   {0} -> {1}" -f $f.From, $f.To) }
  foreach ($l in @($P.Links)) { Write-BmLine ("  re-point link {0}: {1} -> {2}" -f $l.Rel, $l.OldTarget, $l.NewTarget) }
  foreach ($b in @($P.Bootstrap)) { Write-BmLine ("  bootstrap     {0} -> {1}" -f $b.FromName, $b.ToName) }
  if ($P.SignerThumbprint) { Write-BmLine ("  signer        " + $P.SignerThumbprint + " (LocalMachine\My)") }
  foreach ($t in @($P.Tasks)) { Write-BmLine ("  task          \{0} -> \{1} (account {2}{3})" -f $t.OldName, $t.NewName, $t.User, $(if ($t.NeedsPw) { ", needs its password" } else { "" })) }
  if ($null -ne $P.Config) { foreach ($c in @($P.Config.Changes)) { Write-BmLine ("  config        {0}: {1} -> {2}" -f $c.Path, $c.Before, $c.After) } }
  if ($null -ne $P.Winlogon) { Write-BmLine ("  Winlogon Shell: {0} -> {1}" -f $P.Winlogon.Old, $P.Winlogon.New) } else { Write-BmLine "  Winlogon Shell: does not name the old root; left as it is" }
  Write-BmLine ("  {0} sessions to sign out: {1}" -f $P.KioskUser, $(if (@($P.KioskSessions).Count -gt 0) { (@($P.KioskSessions) -join ", ") } else { "none" }))
  foreach ($n in @($P.Notes)) { Write-BmLine ("  note: " + $n) "Yellow" }
  foreach ($x in @($P.Refusals)) { Write-BmLine ("  REFUSED: " + $x) "Red" }
}

# ------------------------------------------------------------------ staging the new bootstrap files
function Invoke-BmStage($P, [string]$SourceDir, [string]$BaseUrl, [string]$MustNotName) {
  # Puts each new bootstrap file in the journal's staging folder, signed by the bay's certificate and timestamped.
  # Nothing on the bay changes here. Returns the problems; empty means every file is ready.
  $why = @()
  foreach ($b in @($P.Bootstrap)) {
    $dst = $b.Staged
    try {
      if (-not [string]::IsNullOrWhiteSpace($SourceDir)) {
        $src = Join-Path $SourceDir $b.ToName
        if (-not [IO.File]::Exists($src)) { $why += "$($b.ToName): not in $SourceDir"; continue }
        [IO.File]::Copy($src, $dst, $true)
      } elseif (-not [string]::IsNullOrWhiteSpace($BaseUrl)) {
        if ($BaseUrl -notmatch '^https://') { $why += "-BootstrapBaseUrl must be an https address"; continue }
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        Invoke-WebRequest -Uri ($BaseUrl.TrimEnd('/') + '/' + $b.ToName) -OutFile $dst -UseBasicParsing -MaximumRedirection 10
        if (-not [IO.File]::Exists($dst)) { $why += "$($b.ToName): the download wrote nothing"; continue }
      } else { $why += "no -BootstrapSource or -BootstrapBaseUrl was given for the new bootstrap files"; break }
      $t = @(Test-BmScriptText $dst $MustNotName)
      if ($t.Count -gt 0) { $why += ("{0}: {1}" -f $b.ToName, ($t -join "; ")); continue }
      if ((Test-BmSignedBy $dst $P.SignerThumbprint) -ne "") {
        Set-AuthenticodeSignature -FilePath $dst -Certificate $P.SigningCert -TimeStampServer $TimeStampServer | Out-Null
        $s = Test-BmSignedBy $dst $P.SignerThumbprint
        if ($s -ne "") { $why += "$($b.ToName): after signing, $s" ; continue }
      }
    } catch { $why += ("{0}: {1}" -f $b.ToName, $_.Exception.Message) }
  }
  return , $why
}

# ------------------------------------------------------------------ undo
function Invoke-BmUndoStep($U) {
  switch ([string]$U.kind) {
    "unregister-task" { Unregister-ScheduledTask -TaskName $U.name -TaskPath "\" -Confirm:$false -ErrorAction Stop }
    "enable-task"     { Enable-ScheduledTask -TaskName $U.name -TaskPath "\" -ErrorAction Stop | Out-Null }
    "disable-task"    { Disable-ScheduledTask -TaskName $U.name -TaskPath "\" -ErrorAction Stop | Out-Null }
    "register-task"   {
      $x = [IO.File]::ReadAllText($U.xmlFile)
      $pw = $null
      if ([bool]$U.needsPw) { $pw = $script:BmKioskPw }
      Register-BmTask -Name $U.name -Xml $x -User $U.user -Password $pw
    }
    "delete-file"     { if ([IO.File]::Exists($U.path)) { [IO.File]::Delete($U.path) } }
    "create-file"     { [IO.File]::WriteAllText($U.path, [string]$U.text) }
    "write-file"      { Write-BmFileAtomic $U.path ([IO.File]::ReadAllBytes($U.fromFile)) }
    "move-dir"        { [IO.Directory]::Move($U.from, $U.to) }
    "move-file"       { [IO.File]::Move($U.from, $U.to) }
    "remove-empty-dir" { if ([IO.Directory]::Exists($U.path)) { [IO.Directory]::Delete($U.path, $false) } }
    "create-dir-acl"  {
      [void][IO.Directory]::CreateDirectory($U.path)
      $acl = Get-Acl -LiteralPath $U.path
      $acl.SetSecurityDescriptorSddlForm([string]$U.sddl, [System.Security.AccessControl.AccessControlSections]::Access)
      Set-Acl -LiteralPath $U.path -AclObject $acl
    }
    "relink"          { Set-BmJunction -Link $U.link -Target $U.target }
    "set-reg"         {
      if ([bool]$U.existed) { Set-ItemProperty -Path $U.key -Name $U.name -Value $U.value }
      else { Remove-ItemProperty -Path $U.key -Name $U.name -ErrorAction SilentlyContinue }
    }
    default { throw "unknown undo step '$($U.kind)'" }
  }
}

function Invoke-BmRollback {
  # Puts back every step done, newest first. Forgiving: a step that cannot be undone is recorded and the rest still
  # run. Returns what was left.
  $left = @()
  $steps = @($script:BmJ.undo)
  for ($i = $steps.Count - 1; $i -ge 0; $i--) {
    $u = $steps[$i]
    try { Invoke-BmUndoStep $u; Write-BmLine ("  put back: " + $u.label) "Yellow" }
    catch { $left += ("{0}: {1}" -f $u.label, $_.Exception.Message); Write-BmLine ("  COULD NOT put back: " + $u.label + ": " + $_.Exception.Message) "Red" }
  }
  return , $left
}

function Set-BmJunction([string]$Link, [string]$Target) {
  # Removes the link itself (never what it points to: a non-recursive delete of a reparse point) and makes it again.
  if ([IO.Directory]::Exists($Link)) {
    $it = Get-Item -LiteralPath $Link -Force
    if (($it.Attributes -band [IO.FileAttributes]::ReparsePoint) -eq 0) { throw "$Link is a real folder, not a link" }
    [IO.Directory]::Delete($Link, $false)
  }
  New-Item -ItemType Junction -Path $Link -Value $Target | Out-Null
  if ((Get-BmLinkTarget $Link) -ine $Target) { throw "the link $Link was made but does not point to $Target" }
}

# ------------------------------------------------------------------ the cutover
function Invoke-BmCutover($P, [string]$JDir) {
  $from = $P.From; $to = $P.To
  $stopFrom = Join-Path $from $BmStopFileRel
  $stopTo = Join-Path $to $BmStopFileRel

  Write-BmStep "1. register the new tasks, disabled"
  foreach ($t in @($P.Tasks)) {
    # A definition that needs no password carries its own account; only a password task is given the account by name.
    $pw = $(if ($t.NeedsPw) { $script:BmKioskPw } else { $null })
    $u = $(if ($t.NeedsPw) { ConvertTo-BmAccountName $t.User } else { "" })
    Register-BmTask -Name $t.NewName -Xml $t.NewXml -User $u -Password $pw
    Add-BmUndo @{ kind = "unregister-task"; name = $t.NewName; label = "the new task \$($t.NewName) removed" }
    Write-BmLine ("  registered \{0} (disabled)" -f $t.NewName)
  }

  Write-BmStep "2. stop the bay"
  [IO.File]::WriteAllText($stopFrom, ("bay move " + (Get-Date).ToUniversalTime().ToString("s") + "Z"))
  Add-BmUndo @{ kind = "delete-file"; path = $stopFrom; label = "stop.host removed" }
  foreach ($t in @($P.Tasks)) {
    Disable-ScheduledTask -TaskName $t.OldName -TaskPath "\" -ErrorAction Stop | Out-Null
    Add-BmUndo @{ kind = "enable-task"; name = $t.OldName; label = "the task \$($t.OldName) enabled again" }
    try { Stop-ScheduledTask -TaskName $t.OldName -TaskPath "\" -ErrorAction Stop } catch { Write-BmLine ("  (ending \{0}: {1})" -f $t.OldName, $_.Exception.Message) }
    Write-BmLine ("  disabled and ended \{0}" -f $t.OldName)
  }
  $sessions = @(Get-BmKioskSessions $P.KioskUser)
  foreach ($s in $sessions) {
    Write-BmLine ("  signing out {0} (session {1})" -f $P.KioskUser, $s)
    & logoff $s
  }
  # Wait until no process names the old root. Half way through, the bay program's OWN kinds of process that still
  # name it (PowerShell running a script under it, Edge on the wall's profile under it: what the watchdog's fallback
  # start or a lingering session can leave) are stopped by their process id, each one logged. Any other process is
  # never stopped: it is listed and the move is put back. A count of tries AND a clock bound this wait.
  $attempts = [Math]::Max(2, [int][Math]::Ceiling($StopTimeoutSeconds / 2))
  $deadline = (Get-Date).AddSeconds($StopTimeoutSeconds + 30)
  $ownKinds = @("powershell.exe", "pwsh.exe", "msedge.exe")
  $still = @()
  for ($i = 0; $i -lt $attempts; $i++) {
    $still = @(Get-BmProcessesNaming $from)
    if ($still.Count -eq 0) { break }
    if ($i -eq [int][Math]::Floor($attempts / 2)) {
      foreach ($s in $still) {
        if ($ownKinds -contains ([string]$s.Name).ToLowerInvariant()) {
          Write-BmLine ("  stopping process {0} ({1}), still running from the old root" -f $s.Id, $s.Name) "Yellow"
          try { Stop-Process -Id $s.Id -Force -ErrorAction Stop } catch { Write-BmLine ("  (process {0}: {1})" -f $s.Id, $_.Exception.Message) }
        }
      }
    }
    if ((Get-Date) -gt $deadline) { break }
    Start-Sleep -Seconds 2
  }
  if ($still.Count -gt 0) {
    foreach ($s in $still) { Write-BmLine ("  still running: {0} {1} {2}" -f $s.Id, $s.Name, $s.CommandLine) "Red" }
    throw ("{0} process(es) still use {1} after {2} s; close them and run Move again" -f $still.Count, $from, $StopTimeoutSeconds)
  }
  Write-BmLine "  nothing runs from the old root"

  Write-BmStep "3. move the folders"
  $before = @{}
  foreach ($f in @($P.Folders)) { $before[$f.Name] = @(Get-BmTreeManifest $f.From) }
  if (-not [IO.Directory]::Exists($to)) {
    [void][IO.Directory]::CreateDirectory($to)
    if ([IO.Directory]::Exists($from)) {
      $acl = Get-Acl -LiteralPath $to
      $acl.SetSecurityDescriptorSddlForm((Get-BmDaclSddl $from), [System.Security.AccessControl.AccessControlSections]::Access)
      Set-Acl -LiteralPath $to -AclObject $acl
    }
    Add-BmUndo @{ kind = "remove-empty-dir"; path = $to; label = "$to removed (it was empty)" }
    Write-BmLine "  created $to with the access rules of $from"
  }
  foreach ($f in @($P.Folders)) {
    $ok = $false; $lastErr = ""
    for ($k = 0; $k -lt 5 -and -not $ok; $k++) {
      try { [IO.Directory]::Move($f.From, $f.To); $ok = $true } catch { $lastErr = $_.Exception.Message; Start-Sleep -Seconds 2 }
    }
    if (-not $ok) { throw ("moving {0} failed: {1} (a window or a program has a file in it open)" -f $f.From, $lastErr) }
    Add-BmUndo @{ kind = "move-dir"; from = $f.To; to = $f.From; label = "$($f.To) moved back to $($f.From)" }
    Write-BmLine ("  moved {0} -> {1}" -f $f.From, $f.To)
  }

  Write-BmStep "4. links, bootstrap files, configuration, Winlogon"
  foreach ($l in @($P.Links)) {
    $lp = Join-Path $to $l.Rel
    Set-BmJunction -Link $lp -Target $l.NewTarget
    Add-BmUndo @{ kind = "relink"; link = $lp; target = $l.OldTarget; label = "the link $lp pointed back to $($l.OldTarget)" }
    Write-BmLine ("  link {0} -> {1}" -f $lp, $l.NewTarget)
  }
  $bsTo = Join-Path $to $BmBootstrapRel
  $keep = Join-Path $JDir "replaced-bootstrap"
  [void][IO.Directory]::CreateDirectory($keep)
  foreach ($b in @($P.Bootstrap)) {
    $oldAt = Join-Path $bsTo $b.FromName
    $kept = Join-Path $keep $b.FromName
    [IO.File]::Move($oldAt, $kept)
    Add-BmUndo @{ kind = "move-file"; from = $kept; to = $oldAt; label = "bootstrap\$($b.FromName) put back" }
    $newAt = Join-Path $bsTo $b.ToName
    [IO.File]::Copy($b.Staged, $newAt, $false)
    Add-BmUndo @{ kind = "delete-file"; path = $newAt; label = "bootstrap\$($b.ToName) removed" }
    Write-BmLine ("  bootstrap\{0} -> bootstrap\{1} (the old file is kept in the journal)" -f $b.FromName, $b.ToName)
  }
  if ($null -ne $P.Config) {
    $cfgAt = Join-Path $to $P.Config.Rel
    $saved = Join-Path $JDir "agent-config.before.json"
    [IO.File]::Copy($cfgAt, $saved, $true)
    $now = Read-BmBytesAsText $cfgAt
    if ($now.Text -cne $P.Config.OldText) { throw "agent-config.json changed between the plan and the move; run Move again" }
    Write-BmFileAtomic $cfgAt (Get-BmTextBytes $P.Config.NewText $P.Config.Bom)
    Add-BmUndo @{ kind = "write-file"; path = $cfgAt; fromFile = $saved; label = "agent-config.json put back" }
    Write-BmLine ("  agent-config.json: {0} value(s) now name {1}" -f @($P.Config.Changes).Count, $to)
  }
  if ($null -ne $P.Winlogon) {
    foreach ($tf in @(Get-BmFileArgs $P.Winlogon.New)) {
      if (-not [IO.File]::Exists($tf) -or (New-Object IO.FileInfo($tf)).Length -lt $BmMinScriptBytes) { throw "the Winlogon Shell would start $tf, which is not there (or is a stub)" }
    }
    Set-ItemProperty -Path $P.Winlogon.Key -Name $P.Winlogon.Name -Value $P.Winlogon.New
    Add-BmUndo @{ kind = "set-reg"; key = $P.Winlogon.Key; name = $P.Winlogon.Name; value = $P.Winlogon.Old; existed = $true; label = "the Winlogon Shell value put back" }
    Write-BmLine ("  Winlogon Shell -> " + $P.Winlogon.New)
  }

  Write-BmStep "5. the tasks"
  foreach ($t in @($P.Tasks)) {
    if ($t.WasEnabled) {
      Enable-ScheduledTask -TaskName $t.NewName -TaskPath "\" -ErrorAction Stop | Out-Null
      Add-BmUndo @{ kind = "disable-task"; name = $t.NewName; label = "the new task \$($t.NewName) disabled" }
      Write-BmLine ("  enabled \{0}" -f $t.NewName)
    } else { Write-BmLine ("  \{0} left disabled, as \{1} was" -f $t.NewName, $t.OldName) }
  }
  foreach ($t in @($P.Tasks)) {
    $xf = Join-Path $JDir ("task-" + ($t.OldName -replace '[^A-Za-z0-9]', '_') + ".xml")
    [IO.File]::WriteAllText($xf, $t.OldXml, (New-Object Text.UnicodeEncoding($false, $true)))
    Unregister-ScheduledTask -TaskName $t.OldName -TaskPath "\" -Confirm:$false -ErrorAction Stop
    Add-BmUndo @{ kind = "register-task"; name = $t.OldName; xmlFile = $xf; user = $(if ($t.NeedsPw) { ConvertTo-BmAccountName $t.User } else { "" }); needsPw = $t.NeedsPw; label = "the task \$($t.OldName) registered again" }
    Write-BmLine ("  removed \{0} (its definition is kept in the journal)" -f $t.OldName)
  }

  Write-BmStep "6. the old root"
  if ([IO.Directory]::Exists($from) -and @([IO.Directory]::GetFileSystemEntries($from)).Count -eq 0) {
    $sddl = Get-BmDaclSddl $from
    [IO.Directory]::Delete($from, $false)
    Add-BmUndo @{ kind = "create-dir-acl"; path = $from; sddl = $sddl; label = "$from made again" }
    Write-BmLine "  removed $from (it was empty)"
  } elseif ([IO.Directory]::Exists($from)) { Write-BmLine "  $from is not empty and stays (see the notes of the plan)" "Yellow" }

  Write-BmStep "7. check every item of done"
  $bad = @(Test-BmDone -P $P -Before $before)
  if ($bad.Count -gt 0) {
    foreach ($b in $bad) { Write-BmLine ("  NOT DONE: " + $b) "Red" }
    throw ("{0} item(s) of done failed" -f $bad.Count)
  }
  Write-BmLine "  every item holds" "Green"

  Write-BmStep "8. start allowed again"
  [IO.File]::Delete($stopTo)
  Add-BmUndo @{ kind = "create-file"; path = $stopTo; text = "bay move"; label = "stop.host written again" }
  Write-BmLine "  removed stop.host"
}

function Test-BmDone {
  # Every item of "done", read back from the machine. Returns the failures; empty means done.
  param($P, $Before)
  $bad = @()
  $from = $P.From; $to = $P.To
  foreach ($f in @($P.Folders)) {
    if ([IO.Directory]::Exists($f.From)) { $bad += "$($f.From) still exists" }
    if (-not [IO.Directory]::Exists($f.To)) { $bad += "$($f.To) does not exist"; continue }
    $ignore = @()
    if ($f.Name -ieq "BayAgent") {
      $ignore += "stop.host"
      foreach ($b in @($P.Bootstrap)) { $ignore += ("bootstrap\" + $b.FromName); $ignore += ("bootstrap\" + $b.ToName) }
      if ($null -ne $P.Config) { $ignore += "agent-config.json" }
    }
    foreach ($l in @($P.Links)) { if ($l.Rel -like ($f.Name + "\*")) { $ignore += $l.Rel.Substring($f.Name.Length + 1) } }
    $d = @(Compare-BmManifest $Before[$f.Name] @(Get-BmTreeManifest $f.To) $ignore)
    foreach ($x in $d) { $bad += ("{0}: {1}" -f $f.Name, $x) }
    $sd = Get-BmDaclSddl $f.To
    if ($sd -ne $f.Dacl) { $bad += "$($f.To): its access rules changed" }
    foreach ($l in @(Get-BmLinks $f.To)) { if (Test-BmUnder $l.Target $from) { $bad += "the link $($f.To)\$($l.Rel) still points into $from" } }
  }
  if ($P.ContainsKey("SecretsDacl")) {
    $sp = Join-Path $to $BmSecretsRel
    if (-not [IO.Directory]::Exists($sp)) { $bad += "$sp is missing" }
    elseif ((Get-BmDaclSddl $sp) -ne $P.SecretsDacl) { $bad += "$sp : its access rules changed" }
  }
  $bsTo = Join-Path $to $BmBootstrapRel
  foreach ($b in @($P.Bootstrap)) {
    if ([IO.File]::Exists((Join-Path $bsTo $b.FromName))) { $bad += "bootstrap\$($b.FromName) is still there" }
    $nf = Join-Path $bsTo $b.ToName
    if (-not [IO.File]::Exists($nf)) { $bad += "bootstrap\$($b.ToName) is missing"; continue }
    $s = Test-BmSignedBy $nf $P.SignerThumbprint
    if ($s -ne "") { $bad += "bootstrap\$($b.ToName): $s" }
  }
  if ($null -ne $P.Config) {
    $cfg = Read-BmBytesAsText (Join-Path $to $P.Config.Rel)
    if ($cfg.Text -cne $P.Config.NewText -or $cfg.Bom -ne $P.Config.Bom) { $bad += "agent-config.json does not hold the planned text" }
    foreach ($leaf in @(Get-BmJsonLeaves ($cfg.Text | ConvertFrom-Json) "")) { if (Test-BmNamesRoot ([string]$leaf.Value) $from) { $bad += "agent-config.json $($leaf.Path) names $from" } }
  }
  $all = @(Get-BmAllTasks)
  foreach ($t in $all) { if (Test-BmNamesRoot (Get-BmTaskText $t) $from) { $bad += ("the task {0}{1} still names {2}" -f $t.TaskPath, $t.TaskName, $from) } }
  foreach ($t in @($P.Tasks)) {
    if ($null -ne (Get-BmTask $t.OldName)) { $bad += "the task \$($t.OldName) is still registered" }
    $nt = Get-BmTask $t.NewName
    if ($null -eq $nt) { $bad += "the task \$($t.NewName) is not registered"; continue }
    if ($t.WasEnabled -and [string]$nt.State -eq "Disabled") { $bad += "the task \$($t.NewName) is disabled" }
    $xf = Get-BmTaskXmlFacts ([string](Export-ScheduledTask -TaskName $t.NewName -TaskPath "\"))
    foreach ($ff in @($xf.Files)) { if (-not [IO.File]::Exists($ff)) { $bad += "the task \$($t.NewName) starts $ff, which is not there" } }
    if ((ConvertTo-BmSid $xf.User) -ne (ConvertTo-BmSid $t.User)) { $bad += "the task \$($t.NewName) runs as '$($xf.User)', not '$($t.User)'" }
    if ($xf.LogonType -ne $t.LogonType) { $bad += "the task \$($t.NewName) signs in as '$($xf.LogonType)', not '$($t.LogonType)'" }
  }
  $shell = Get-BmRegValue $BmWinlogonKey "Shell"
  if ($null -ne $shell -and (Test-BmNamesRoot ([string]$shell) $from)) { $bad += "the Winlogon Shell still names $from" }
  return , $bad
}

# ------------------------------------------------------------------ Verify (after the reboot)
function Invoke-BmVerify([string]$Root, [string]$Other, $TaskNames) {
  $bad = @(); $ok = @()
  $boot = $null
  try { $boot = [datetime](Get-CimInstance -ClassName Win32_OperatingSystem).LastBootUpTime } catch { $boot = $null }
  if ($null -eq $boot) { $bad += "the time of the last start cannot be read" }
  foreach ($f in @($Folders)) {
    if ([IO.Directory]::Exists((Join-Path $Other $f))) { $bad += "$(Join-Path $Other $f) exists" }
  }
  if (-not [IO.Directory]::Exists((Join-Path $Root "BayAgent"))) { $bad += "$Root\BayAgent does not exist" }
  foreach ($tn in @($TaskNames)) {
    $t = Get-BmTask $tn
    if ($null -eq $t) { $bad += "the task \$tn is not registered"; continue }
    if ([string]$t.State -eq "Disabled") { $bad += "the task \$tn is disabled" } else { $ok += ("the task \{0} is {1}" -f $tn, $t.State) }
  }
  foreach ($t in @(Get-BmAllTasks)) { if (Test-BmNamesRoot (Get-BmTaskText $t) $Other) { $bad += ("the task {0}{1} names {2}" -f $t.TaskPath, $t.TaskName, $Other) } }
  $procs = @(Get-BmProcessesNaming $Root)
  $old = @(Get-BmProcessesNaming $Other)
  foreach ($o in $old) { $bad += ("process {0} {1} runs from {2}" -f $o.Id, $o.Name, $Other) }
  $agent = @($procs | Where-Object { $_.CommandLine -match '(?i)\\current\\BayAgent\.ps1' })
  $hostp = @($procs | Where-Object { $_.CommandLine -match '(?i)AgentHost\.ps1' })
  if ($agent.Count -lt 1) { $bad += "no BayAgent.ps1 runs from $Root\BayAgent\current" } else { $ok += ("BayAgent.ps1 runs from the new root (process {0})" -f $agent[0].Id) }
  if ($hostp.Count -lt 1) { $bad += "no AgentHost runs from $Root" } else { $ok += ("AgentHost runs from the new root (process {0})" -f $hostp[0].Id) }
  $alive = Join-Path $Root "BayAgent\state\agent-alive.json"
  if ($null -ne $boot) {
    if (-not [IO.File]::Exists($alive)) { $bad += "state\agent-alive.json is not there" }
    elseif ((New-Object IO.FileInfo($alive)).LastWriteTime -lt $boot) { $bad += "state\agent-alive.json was not written since the last start" }
    else { $ok += "state\agent-alive.json written since the last start" }
  }
  $shell = Get-BmRegValue $BmWinlogonKey "Shell"
  if ($null -ne $shell -and (Test-BmNamesRoot ([string]$shell) $Other)) { $bad += "the Winlogon Shell names $Other" }
  foreach ($x in $ok) { Write-BmLine ("  ok: " + $x) "Green" }
  foreach ($x in $bad) { Write-BmLine ("  NOT OK: " + $x) "Red" }
  return , $bad
}

# ------------------------------------------------------------------ main
$Folders = @($Folders | ForEach-Object { ([string]$_).Split(',') } | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne "" })
if ([string]::IsNullOrWhiteSpace($JournalRoot)) { $JournalRoot = Join-Path $env:ProgramData "AceOfClubs\BayMove" }
$OldRoot = Get-BmFullPath $OldRoot
$NewRoot = Get-BmFullPath $NewRoot
$script:BmKioskPw = $null

Write-BmLine ("Move-BayInstall {0}  mode {1}  old root {2}  new root {3}" -f $BmToolVersion, $Mode, $OldRoot, $NewRoot) "Cyan"
if (-not (Test-BmIsAdmin)) { Write-BmLine "REFUSED: run this as Administrator." "Red"; exit 1 }

if ($Mode -eq "Verify") {
  $here = $(if ([IO.Directory]::Exists((Join-Path $NewRoot "BayAgent"))) { $NewRoot } else { $OldRoot })
  $other = $(if ($here -eq $NewRoot) { $OldRoot } else { $NewRoot })
  $names = $(if ($here -eq $NewRoot) { @($BmTaskNameMap.Values) } else { @($BmTaskNameMap.Keys) })
  Write-BmStep ("Verify: the install is at {0}" -f $here)
  $vb = @(Invoke-BmVerify $here $other $names)
  if ($vb.Count -eq 0) { Write-BmLine "RESULT: VERIFIED" "Green"; exit 0 }
  Write-BmLine ("RESULT: NOT VERIFIED ({0} item(s))" -f $vb.Count) "Red"; exit 1
}

$jIn = $null
if ($Mode -eq "Back") {
  $jIn = $(if (-not [string]::IsNullOrWhiteSpace($Journal)) { $Journal } else { Get-BmLatestJournal $JournalRoot })
  if ($null -eq $jIn -or -not [IO.File]::Exists((Join-Path $jIn "journal.json"))) { Write-BmLine "REFUSED: no journal of a completed Move was found under $JournalRoot; name one with -Journal" "Red"; exit 1 }
  $jj = [IO.File]::ReadAllText((Join-Path $jIn "journal.json")) | ConvertFrom-Json
  if ([string]$jj.mode -ne "Move" -or [string]$jj.state -ne "moved") { Write-BmLine "REFUSED: $jIn is not the journal of a completed Move" "Red"; exit 1 }
  if ((Get-BmFullPath ([string]$jj.from)) -ine $OldRoot -or (Get-BmFullPath ([string]$jj.to)) -ine $NewRoot) { Write-BmLine "REFUSED: that journal moved $($jj.from) to $($jj.to), not $OldRoot to $NewRoot" "Red"; exit 1 }
}

$from = $(if ($Mode -eq "Back") { $NewRoot } else { $OldRoot })
$to = $(if ($Mode -eq "Back") { $OldRoot } else { $NewRoot })
$taskMap = $(if ($Mode -eq "Back") { Get-BmReverseMap $BmTaskNameMap } else { $BmTaskNameMap })
$fileMap = $(if ($Mode -eq "Back") { Get-BmReverseMap $BmBootstrapNameMap } else { $BmBootstrapNameMap })

# The journal folder exists only for Move and Back (Plan writes nothing). Staging needs it; it is outside both roots.
$stageDir = $null
if ($Mode -ne "Plan") {
  if ((Test-BmUnder $JournalRoot $OldRoot) -or (Test-BmUnder $JournalRoot $NewRoot)) { Write-BmLine "REFUSED: the journal folder may not be inside a root this tool moves" "Red"; exit 4 }
  $script:BmJDir = Join-Path $JournalRoot ((Get-Date).ToUniversalTime().ToString("yyyyMMdd-HHmmss") + "-" + $Mode.ToLowerInvariant())
  [void][IO.Directory]::CreateDirectory($script:BmJDir)
  $script:BmLogFile = Join-Path $script:BmJDir "log.txt"
  $stageDir = Join-Path $script:BmJDir "staged-bootstrap"
  [void][IO.Directory]::CreateDirectory($stageDir)
  $script:BmJ = [ordered]@{ tool = $BmToolVersion; mode = $Mode; from = $OldRoot; to = $NewRoot; machine = $env:COMPUTERNAME; startedUtc = (Get-Date).ToUniversalTime().ToString("s") + "Z"; state = "planning"; undo = @(); left = @() }
  Save-BmJournal
} else { $stageDir = Join-Path $env:TEMP "bm-plan-not-written" }

$plan = New-BmPlan -Direction $(if ($Mode -eq "Back") { "Back" } else { "Move" }) -From $from -To $to -TaskMap $taskMap -FileMap $fileMap -StagedDir $stageDir -JournalIn $jIn
Show-BmPlan $plan

if ($Mode -eq "Plan") {
  if ($plan.Ok) { Write-BmLine "RESULT: Move would proceed (nothing was changed)" "Green"; exit 0 }
  Write-BmLine ("RESULT: Move would be REFUSED ({0} reason(s)); nothing was changed" -f @($plan.Refusals).Count) "Red"; exit 1
}
if (-not $plan.Ok) { $script:BmJ.state = "refused"; Save-BmJournal; Write-BmLine "RESULT: REFUSED; nothing on the bay was changed" "Red"; exit 1 }

Write-BmStep "Stage the bootstrap files (nothing on the bay changes yet)"
$srcDir = $(if ($Mode -eq "Back") { Join-Path $jIn "replaced-bootstrap" } else { $BootstrapSource })
$baseUrl = $(if ($Mode -eq "Back") { "" } else { $BootstrapBaseUrl })
$stageWhy = @(Invoke-BmStage $plan $srcDir $baseUrl $from)
if ($stageWhy.Count -gt 0) {
  foreach ($w in $stageWhy) { Write-BmLine ("  REFUSED: " + $w) "Red" }
  $script:BmJ.state = "refused"; Save-BmJournal
  Write-BmLine "RESULT: REFUSED; nothing on the bay was changed" "Red"; exit 1
}
foreach ($b in @($plan.Bootstrap)) { Write-BmLine ("  ready: {0} (signed by {1}, timestamped)" -f $b.ToName, $plan.SignerThumbprint) }

$word = $(if ($Mode -eq "Back") { "BACK" } else { "MOVE" })
$typed = Read-Host ("Type {0} to stop this bay and {1}" -f $word, $(if ($Mode -eq "Back") { "put it back" } else { "move it" }))
if ([string]$typed -cne $word) { $script:BmJ.state = "cancelled"; Save-BmJournal; Write-BmLine "RESULT: cancelled; nothing on the bay was changed" "Yellow"; exit 1 }
if ($plan.NeedsPw) {
  $script:BmKioskPw = Read-Host ("Password of {0} (a task signs in as this account)" -f $BayKioskUser) -AsSecureString
  if ($null -eq $script:BmKioskPw -or $script:BmKioskPw.Length -eq 0) { $script:BmJ.state = "cancelled"; Save-BmJournal; Write-BmLine "RESULT: no password was typed; nothing on the bay was changed" "Yellow"; exit 1 }
}

$script:BmJ.state = "moving"; Save-BmJournal
$code = 0
try {
  Invoke-BmCutover $plan $script:BmJDir
  $script:BmJ.state = "moved"; Save-BmJournal
  Write-BmLine ""
  Write-BmLine ("RESULT: MOVED to {0}. Journal: {1}" -f $to, $script:BmJDir) "Green"
  Write-BmLine "Restart the PC now; after BayKiosk signs in, run this tool with -Mode Verify." "Green"
} catch {
  $why = $_.Exception.Message
  Write-BmLine ("FAILED: " + $why) "Red"
  Write-BmStep "Putting back every step done"
  $left = @(Invoke-BmRollback)
  $script:BmJ.left = $left
  if ($left.Count -eq 0) { $script:BmJ.state = "rolled-back"; Write-BmLine "RESULT: FAILED and everything was put back. Restart the PC to start the bay again." "Yellow"; $code = 2 }
  else { $script:BmJ.state = "rollback-incomplete"; Write-BmLine ("RESULT: FAILED and {0} step(s) could NOT be put back (journal: {1})" -f $left.Count, $script:BmJDir) "Red"; $code = 3 }
  $script:BmJ.failure = $why
  Save-BmJournal
} finally {
  $script:BmKioskPw = $null
}
exit $code
