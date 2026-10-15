<#
BayAgent.KioskAcl.Tests.ps1

A0.699 / F-SEC (2026-10-15): the kiosk account (BayKiosk) must hold NOTHING on the bay's code-signing private key, and
must not be able to write, modify or replace anything a SYSTEM task executes or loads. tools\ABG-BayAcl.ps1 is the one
definition of that; Day0 and Setup-BayPC call it. This suite runs its REAL functions on REAL NTFS folders (a scratch tree
under %TEMP%, and a stand-in SID for BayKiosk), in Windows PowerShell 5.1, the host a bay uses, and then:

  - reads every ACL back through icacls.exe (a different decoder from the .NET reader the helper uses), so "BayKiosk has
    no write" is not judged by the code that applied it;
  - plants each drift an attacker or an old setup could leave (a BayKiosk grant on the key, Users or BayKiosk modify on
    the watchdog folder, an unprotected folder above it, a link inside it, the wrong owner, a SYSTEM task that runs a
    script from somewhere BayKiosk can write, a BayKiosk grant that was removed) and requires the self-check to FAIL
    on exactly that row, and a setup run to repair it;
  - checks the other half, what the agent needs as BayKiosk (it writes state, logs, control, current, releases, rollback,
    staging, tools, and SessionDisplay; it reads agent-config.json and the bootstrap scripts), still works and cannot
    replace its own folders.

WHAT THIS DOES NOT PROVE: that a process really logged on as BayKiosk can or cannot do these things (no such account is
created here); that the real machine key store behaves like the scratch file; that the account running setup is elevated.
A real bay must show those (see the hand-over note).

Run (from the repo root; Windows only, Windows PowerShell 5.1):
  powershell -NoProfile -ExecutionPolicy Bypass -File tests\BayAgent.KioskAcl.Tests.ps1
Exit code 0 = all assertions passed. Hyphens only in comments.
#>
[CmdletBinding()]
param([string]$Helper = "")

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
if ([string]::IsNullOrWhiteSpace($Helper)) { $Helper = Join-Path $RepoRoot "tools\ABG-BayAcl.ps1" }
$Helper = (Resolve-Path $Helper).Path
$Icacls = Join-Path $env:WINDIR "System32\icacls.exe"

$script:Pass = 0; $script:Fail = 0; $script:Failures = @()
function Assert-True([bool]$cond, [string]$msg) {
    if ($cond) { $script:Pass++; Write-Host "  PASS  $msg" }
    else { $script:Fail++; $script:Failures += $msg; Write-Host "  FAIL  $msg" -ForegroundColor Red }
}
function Section([string]$name) { Write-Host ""; Write-Host "== $name" -ForegroundColor Cyan }

. $Helper
# Doubles: no owner change (the account running this is not elevated), and the key comes from a scratch file, not the
# machine store. Everything else in the helper is the real function.
function Set-BayLockTreeOwner([string]$Path) { }
$script:TestKeyPath = ""
function Get-BayCodeSigningThumbprints { return @("AABBCC") }
function Get-BayKeyContainerName([string]$Thumbprint) { return "scratch-key" }
function Get-BayKeyFilePaths([string]$UniqueName) { return @($script:TestKeyPath) }

$KioskSidText = "S-1-5-21-1111111111-2222222222-3333333333-1001"
$Kiosk = New-Object System.Security.Principal.SecurityIdentifier($KioskSidText)
$MeSid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
$Me = New-Object System.Security.Principal.SecurityIdentifier($MeSid)
$Base = Join-Path $env:TEMP ("bayagent-kioskacl-" + [guid]::NewGuid().ToString("N").Substring(0, 8))
New-Item -ItemType Directory -Force -Path $Base | Out-Null

# --------------------------------------------------------------------------------------------- the independent reader
# icacls.exe's own text. One entry per ACE: who, flags (I, OI, CI, IO, NP), rights tokens (F, M, RX, R, W, D, DC, WD, AD,
# WEA, WA, WDAC, WO ...).
function Read-Icacls([string]$Path) {
    $text = (& $Icacls $Path 2>&1 | ForEach-Object { "$_" }) -join "`n"
    $entries = @()
    foreach ($line in ($text -split "`n")) {
        $l = $line
        if ($l.StartsWith($Path)) { $l = $l.Substring($Path.Length) }
        $m = [regex]::Match($l, '^\s*(?<who>[^\s:][^:]*?):(?<acl>(\([^)]*\))+)\s*$')
        if (-not $m.Success) { continue }
        $parts = [regex]::Matches($m.Groups["acl"].Value, '\(([^)]*)\)') | ForEach-Object { $_.Groups[1].Value }
        $flags = @(); $rights = @()
        foreach ($p in $parts) { if (@("I", "OI", "CI", "IO", "NP") -contains $p) { $flags += $p } else { $rights += ($p -split ",") } }
        $entries += [pscustomobject]@{ Who = $m.Groups["who"].Value.Trim(); Flags = $flags; Rights = $rights }
    }
    return $entries
}
$WriteTokens = @("F", "M", "W", "D", "DC", "WD", "AD", "WEA", "WA", "WDAC", "WO", "GA", "GW")
function Test-WhoIsKioskSide([string]$who) {
    return (@($KioskSidText, "BUILTIN\Users", "NT AUTHORITY\Authenticated Users", "Everyone", "NT AUTHORITY\INTERACTIVE", "NT AUTHORITY\LOCAL") -contains $who)
}
# Write-class tokens the kiosk side holds on the object ITSELF (an inherit-only entry is not on it).
function Get-KioskSelfWrite([string]$Path) {
    $hits = @()
    foreach ($e in @(Read-Icacls $Path)) {
        if (-not (Test-WhoIsKioskSide $e.Who)) { continue }
        if ($e.Flags -contains "IO") { continue }
        foreach ($r in $e.Rights) { if ($WriteTokens -contains $r) { $hits += ($e.Who + ":" + $r) } }
    }
    return $hits
}
function Get-KioskAnything([string]$Path) {
    $hits = @()
    foreach ($e in @(Read-Icacls $Path)) { if (Test-WhoIsKioskSide $e.Who) { $hits += ($e.Who + ":" + ($e.Rights -join ",")) } }
    return $hits
}
function Test-WalkNoKioskWrite([string]$Dir) {
    $bad = @()
    foreach ($i in (@(Get-Item -LiteralPath $Dir -Force) + @(Get-ChildItem -LiteralPath $Dir -Recurse -Force))) {
        $w = @(Get-KioskSelfWrite $i.FullName)
        if ($w.Count -gt 0) { $bad += ($i.FullName + " => " + ($w -join " ")) }
    }
    return $bad
}

# --------------------------------------------------------------------------------------------- tree and plants
function New-Tree([string]$Name) {
    $root = Join-Path (Join-Path $Base $Name) "AllBirdies"
    foreach ($d in @("BayAgent\bootstrap\setup", "BayAgent\state", "BayAgent\logs", "BayAgent\control", "BayAgent\current\kiosk", "BayAgent\releases", "BayAgent\rollback", "BayAgent\staging", "BayAgent\tools", "SessionDisplay\data", "SessionDisplay\edge-profile")) {
        New-Item -ItemType Directory -Force -Path (Join-Path $root $d) | Out-Null
    }
    foreach ($f in @("BayAgent\bootstrap\ABG.HostWatchdog.ps1", "BayAgent\bootstrap\ABG.AgentHost.ps1", "BayAgent\bootstrap\setup\ABG-Day0-Setup.ps1", "BayAgent\agent-config.json", "BayAgent\state\agent-alive.json",
            "BayAgent\logs\BayAgent-20261015.log", "BayAgent\control\restart.host", "BayAgent\current\BayAgent.ps1", "BayAgent\current\kiosk\kiosk-policy.json", "BayAgent\tools\Update-BayAgent.ps1",
            "BayAgent\rollback\snapshot.json", "SessionDisplay\data\session.json", "SessionDisplay\edge-profile\Preferences")) {
        [IO.File]::WriteAllText((Join-Path $root $f), "x")
    }
    $script:TestKeyPath = Join-Path (Join-Path $Base $Name) "scratch-key"
    [IO.File]::WriteAllText($script:TestKeyPath, "not a key")
    return $root
}
function Add-Ace([string]$Path, $Sid, [string]$Rights, [string]$Inherit = "None", [string]$Prop = "None", [string]$Type = "Allow") {
    $item = Get-Item -LiteralPath $Path -Force
    $acl = $item.GetAccessControl([System.Security.AccessControl.AccessControlSections]::Access)
    $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($Sid, $Rights, $Inherit, $Prop, $Type)))
    $item.SetAccessControl($acl)
}
function Invoke-Apply([string]$Root, $KioskSid) {
    Set-BayAcls -Root $Root -KioskSid $KioskSid
    Set-BayKeyFileAcl -KeyPath $script:TestKeyPath
}
$WatchdogTask = [pscustomobject]@{ Name = "ABG Host Watchdog"; UserId = "SYSTEM"; Execute = (Join-Path $env:SystemRoot "System32\WindowsPowerShell\v1.0\powershell.exe"); Arguments = $null }
function Get-Report([string]$Root, $Tasks = $null, [string[]]$Owners = @($MeSid)) {
    if ($null -eq $Tasks) {
        $WatchdogTask.Arguments = ('-NoProfile -File "' + (Join-Path $Root "BayAgent\bootstrap\ABG.HostWatchdog.ps1") + '"')
        $Tasks = @($WatchdogTask)
    }
    return @(Get-BayAclReport -Root $Root -KioskSid $Kiosk -Tasks $Tasks -ExtraOwners $Owners -RequiredTaskNames @("ABG Host Watchdog"))
}
function Get-RowResult($Rows, [string]$Like) { $r = @($Rows | Where-Object { $_.Check -like $Like }); if ($r.Count -ne 1) { return "NO SUCH ROW ($Like)" }; return [string]$r[0].Result }
function Test-AllPass($Rows) { return (@($Rows | Where-Object { $_.Result -ne "PASS" }).Count -eq 0 -and @($Rows).Count -eq 5) }

$RowKey = "Code-signing key*"; $RowAbove = "Folders above*"; $RowBoot = "SYSTEM-run folder*"; $RowTask = "SYSTEM tasks*"; $RowData = "Agent data folders*"

try {
    # =========================================================================================== A. the applied state
    Section "A. a tree set up by Set-BayAcls and Set-BayKeyFileAcl"
    $rootA = New-Tree "a"
    # An old setup left the key readable by BayKiosk, and every folder inherited Authenticated Users:Modify from C:\ :
    Add-Ace $script:TestKeyPath $Kiosk "Read"
    Add-Ace (Join-Path $rootA "BayAgent\bootstrap") (New-Object System.Security.Principal.SecurityIdentifier("S-1-5-11")) "Modify" "ContainerInherit, ObjectInherit"
    Add-Ace (Join-Path $rootA "BayAgent\bootstrap\ABG.HostWatchdog.ps1") $Kiosk "Modify"
    $before = Get-Report $rootA
    Assert-True ((Get-RowResult $before $RowKey) -match "^FAIL") "before: the self-check FAILs on the key that BayKiosk can read"
    Assert-True ((Get-RowResult $before $RowBoot) -match "^FAIL") "before: the self-check FAILs on the folder SYSTEM runs from"
    Assert-True (@(Get-KioskAnything $script:TestKeyPath).Count -gt 0) "before: icacls shows a BayKiosk entry on the key"
    Invoke-Apply $rootA $Kiosk
    $after = Get-Report $rootA
    Assert-True (Test-AllPass $after) ("after: all five self-check rows read PASS (" + (($after | ForEach-Object { $_.Check + "=" + $_.Result }) -join " | ") + ")")
    Assert-True (@(Get-KioskAnything $script:TestKeyPath).Count -eq 0) "the key file: icacls shows nothing for BayKiosk, Users, Authenticated Users or Everyone"
    $keyEntries = @(Read-Icacls $script:TestKeyPath)
    Assert-True (@($keyEntries | Where-Object { @("NT AUTHORITY\SYSTEM", "BUILTIN\Administrators") -notcontains $_.Who }).Count -eq 0 -and @($keyEntries | Where-Object { $_.Flags -contains "I" }).Count -eq 0) "...the entries left are SYSTEM and Administrators, none inherited"
    foreach ($d in @("", "BayAgent", "BayAgent\bootstrap")) {
        $pth = $(if ($d) { Join-Path $rootA $d } else { $rootA })
        Assert-True (@(Get-KioskSelfWrite $pth).Count -eq 0) ("icacls: BayKiosk and Users can write nothing in '" + $(if ($d) { $d } else { "AllBirdies" }) + "' (" + ((Get-KioskSelfWrite $pth) -join " ") + ")")
    }
    $bad = @(Test-WalkNoKioskWrite (Join-Path $rootA "BayAgent\bootstrap"))
    Assert-True ($bad.Count -eq 0) ("icacls, every file and folder under bootstrap (setup\ too): no write for BayKiosk or Users (" + ($bad -join "; ") + ")")
    Assert-True (@(Read-Icacls (Join-Path $rootA "BayAgent\bootstrap\ABG.HostWatchdog.ps1") | Where-Object { $_.Who -eq $KioskSidText }).Count -eq 0) "the planted explicit BayKiosk grant on the watchdog file is gone"
    $rootE = @(Read-Icacls $rootA)
    Assert-True (@($rootE | Where-Object { $_.Flags -contains "I" }).Count -eq 0) "AllBirdies inherits nothing from C:\ (Authenticated Users:Modify is not there)"

    Section "A2. what the agent needs as BayKiosk (reads and writes), judged on icacls text"
    foreach ($d in @("state", "logs", "control", "current", "releases", "rollback", "staging", "tools")) {
        $pth = Join-Path $rootA ("BayAgent\" + $d)
        $e = @(Read-Icacls $pth | Where-Object { $_.Who -eq $KioskSidText })
        $self = @($e | Where-Object { $_.Flags -notcontains "IO" }); $kids = @($e | Where-Object { $_.Flags -contains "IO" -and $_.Flags -contains "OI" -and $_.Flags -contains "CI" })
        $selfR = @($self | ForEach-Object { $_.Rights }); $kidR = @($kids | ForEach-Object { $_.Rights })
        Assert-True ($selfR -contains "W" -and $selfR -contains "DC" -and $selfR -contains "RX" -and $selfR -notcontains "D" -and $selfR -notcontains "F" -and $selfR -notcontains "M" -and $selfR -notcontains "WDAC" -and $selfR -notcontains "WO") "$d : BayKiosk can create files and folders in it and clear it; it cannot delete or re-permission the folder (so cannot swap it for a link)"
        Assert-True ($kidR -contains "M") "$d : what is created inside is Modify for BayKiosk"
        $sample = @(Get-ChildItem -LiteralPath $pth -Recurse -Force -File | Select-Object -First 1)
        if ($sample.Count -eq 1) {
            $se = @(Read-Icacls $sample[0].FullName | Where-Object { $_.Who -eq $KioskSidText })
            Assert-True ($se.Count -ge 1 -and (@($se | ForEach-Object { $_.Rights }) -contains "M") -and ($se[0].Flags -contains "I")) ("$d : an existing file in it (" + $sample[0].Name + ") is Modify for BayKiosk, inherited")
        }
    }
    $disp = @(Read-Icacls (Join-Path $rootA "SessionDisplay") | Where-Object { $_.Who -eq $KioskSidText })
    Assert-True ($disp.Count -ge 1 -and (@($disp | ForEach-Object { $_.Rights }) -contains "M") -and ($disp[0].Flags -contains "OI") -and ($disp[0].Flags -contains "CI")) "SessionDisplay : BayKiosk Modify over the folder and everything in it"
    foreach ($f in @("SessionDisplay\data\session.json", "SessionDisplay\edge-profile\Preferences")) {
        $se = @(Read-Icacls (Join-Path $rootA $f) | Where-Object { $_.Who -eq $KioskSidText })
        Assert-True ($se.Count -ge 1 -and (@($se | ForEach-Object { $_.Rights }) -contains "M")) "$f : an existing file BayKiosk writes is Modify for BayKiosk (inherited)"
    }
    # what BayKiosk only reads
    foreach ($f in @("BayAgent\agent-config.json", "BayAgent\bootstrap\ABG.AgentHost.ps1", "BayAgent\current\kiosk\kiosk-policy.json")) {
        $se = @(Read-Icacls (Join-Path $rootA $f))
        $readers = @($se | Where-Object { (Test-WhoIsKioskSide $_.Who) -and (@($_.Rights) -contains "RX" -or @($_.Rights) -contains "M" -or @($_.Rights) -contains "R") })
        Assert-True ($readers.Count -ge 1) "$f : BayKiosk (through Users or its own entry) can read and run it"
    }
    Assert-True (@(Read-Icacls (Join-Path $rootA "BayAgent\agent-config.json") | Where-Object { (Test-WhoIsKioskSide $_.Who) -and (@(@($_.Rights) | Where-Object { $WriteTokens -contains $_ }).Count -gt 0) }).Count -eq 0) "agent-config.json : BayKiosk cannot write it (nothing in the agent writes it)"
    $secrets = Join-Path $rootA "BayAgent\secrets"
    Assert-True (-not (Test-Path -LiteralPath $secrets)) "BayAgent\secrets is not created or touched by this change (its own tool sets its ACL)"

    Section "A3. running it again changes nothing"
    $dump1 = (@(Get-ChildItem -LiteralPath $rootA -Recurse -Force | ForEach-Object { $_.FullName.Substring($rootA.Length) + " " + ((Read-Icacls $_.FullName | ForEach-Object { $_.Who + ":" + ($_.Flags -join "") + ":" + ($_.Rights -join ",") }) -join ";") }) -join "`n")
    Invoke-Apply $rootA $Kiosk
    $dump2 = (@(Get-ChildItem -LiteralPath $rootA -Recurse -Force | ForEach-Object { $_.FullName.Substring($rootA.Length) + " " + ((Read-Icacls $_.FullName | ForEach-Object { $_.Who + ":" + ($_.Flags -join "") + ":" + ($_.Rights -join ",") }) -join ";") }) -join "`n")
    Assert-True ($dump1 -eq $dump2 -and $dump1.Length -gt 200) ("a second application leaves every ACL as it was (" + $dump1.Length + " characters compared)")

    # =========================================================================================== B. each drift is reported on its own row, and repaired
    $plants = @(
        @{ Name = "BayKiosk granted read on the key"; Row = $RowKey; Plant = { param($r) Add-Ace $script:TestKeyPath $Kiosk "Read" } },
        @{ Name = "Users granted read on the key"; Row = $RowKey; Plant = { param($r) Add-Ace $script:TestKeyPath (New-Object System.Security.Principal.SecurityIdentifier("S-1-5-32-545")) "Read" } },
        @{ Name = "Everyone granted read on the key"; Row = $RowKey; Plant = { param($r) Add-Ace $script:TestKeyPath (New-Object System.Security.Principal.SecurityIdentifier("S-1-1-0")) "Read" } },
        @{ Name = "BayKiosk can modify the watchdog folder"; Row = $RowBoot; Plant = { param($r) Add-Ace (Join-Path $r "BayAgent\bootstrap") $Kiosk "Modify" "ContainerInherit, ObjectInherit" } },
        @{ Name = "BayKiosk can write the watchdog file itself"; Row = $RowBoot; Plant = { param($r) Add-Ace (Join-Path $r "BayAgent\bootstrap\ABG.HostWatchdog.ps1") $Kiosk "Write" } },
        @{ Name = "Authenticated Users can modify a file in bootstrap\setup"; Row = $RowBoot; Plant = { param($r) Add-Ace (Join-Path $r "BayAgent\bootstrap\setup\ABG-Day0-Setup.ps1") (New-Object System.Security.Principal.SecurityIdentifier("S-1-5-11")) "Modify" } },
        @{ Name = "Users can append in the watchdog folder"; Row = $RowBoot; Plant = { param($r) Add-Ace (Join-Path $r "BayAgent\bootstrap") (New-Object System.Security.Principal.SecurityIdentifier("S-1-5-32-545")) "AppendData" } },
        @{ Name = "BayKiosk can create in BayAgent (could swap bootstrap for another folder)"; Row = $RowAbove; Also = @($RowData); Plant = { param($r) Add-Ace (Join-Path $r "BayAgent") $Kiosk "Modify" "ContainerInherit, ObjectInherit" } },
        @{ Name = "BayKiosk can delete children in AllBirdies"; Row = $RowAbove; Plant = { param($r) Add-Ace $r $Kiosk "DeleteSubdirectoriesAndFiles" } },
        @{ Name = "Authenticated Users:Modify inherited back into AllBirdies"; Row = $RowAbove; Plant = { param($r) Add-Ace $r (New-Object System.Security.Principal.SecurityIdentifier("S-1-5-11")) "Modify" "ContainerInherit, ObjectInherit" } },
        @{ Name = "BayKiosk lost its grant on logs"; Row = $RowData; Plant = { param($r) $it = Get-Item -LiteralPath (Join-Path $r "BayAgent\logs"); $a = $it.GetAccessControl([System.Security.AccessControl.AccessControlSections]::Access); foreach ($x in @($a.GetAccessRules($true, $false, [System.Security.Principal.SecurityIdentifier]))) { [void]$a.RemoveAccessRuleSpecific($x) }; $it.SetAccessControl($a) } },
        @{ Name = "BayKiosk can delete the control folder itself"; Row = $RowData; Plant = { param($r) Add-Ace (Join-Path $r "BayAgent\control") $Kiosk "Delete" } },
        @{ Name = "BayKiosk lost Modify over the files it creates in state"; Row = $RowData; Plant = { param($r) $it = Get-Item -LiteralPath (Join-Path $r "BayAgent\state"); $a = $it.GetAccessControl([System.Security.AccessControl.AccessControlSections]::Access); foreach ($x in @($a.GetAccessRules($true, $false, [System.Security.Principal.SecurityIdentifier]) | Where-Object { ([int]$_.PropagationFlags -band 2) -ne 0 })) { [void]$a.RemoveAccessRuleSpecific($x) }; $it.SetAccessControl($a) } },
        @{ Name = "SessionDisplay lost the BayKiosk grant"; Row = $RowData; Plant = { param($r) $it = Get-Item -LiteralPath (Join-Path $r "SessionDisplay"); $a = $it.GetAccessControl([System.Security.AccessControl.AccessControlSections]::Access); foreach ($x in @($a.GetAccessRules($true, $false, [System.Security.Principal.SecurityIdentifier]))) { [void]$a.RemoveAccessRuleSpecific($x) }; $it.SetAccessControl($a) } }
    )
    $n = 0
    foreach ($pl in $plants) {
        $n++
        Section ("B$n. drift: " + $pl.Name)
        $r = New-Tree ("b" + $n)
        Invoke-Apply $r $Kiosk
        Assert-True (Test-AllPass (Get-Report $r)) "the starting state is clean"
        & $pl.Plant $r
        $rows = Get-Report $r
        Assert-True ((Get-RowResult $rows $pl.Row) -match "^FAIL") ("the self-check FAILs the row '" + $pl.Row + "' (" + (Get-RowResult $rows $pl.Row) + ")")
        # A grant on BayAgent flows into the data folders below it, which is a second true finding (the kiosk could delete them).
        $allowed = @($pl.Row) + @($(if ($pl.ContainsKey("Also")) { $pl.Also } else { @() }))
        Assert-True (@($rows | Where-Object { $r2 = $_; $r2.Result -match "^FAIL" -and @($allowed | Where-Object { $r2.Check -like $_ }).Count -eq 0 }).Count -eq 0) "...and no unrelated row (the report points at the cause)"
        Invoke-Apply $r $Kiosk
        Assert-True (Test-AllPass (Get-Report $r)) "after Set-BayAcls and Set-BayKeyFileAcl every row reads PASS again"
        if ($pl.Row -eq $RowKey) { Assert-True (@(Get-KioskAnything $script:TestKeyPath).Count -eq 0 -and @(Read-Icacls $script:TestKeyPath).Count -eq 2) "...and icacls shows the key with its two entries only" }
    }

    Section "B-link. a link planted inside the watchdog folder"
    $rl = New-Tree "blink"
    Invoke-Apply $rl $Kiosk
    $target = Join-Path $Base "link-target"; New-Item -ItemType Directory -Force -Path $target | Out-Null
    $bootDir = Join-Path $rl "BayAgent\bootstrap"
    Add-Ace $bootDir $Me "FullControl" "ContainerInherit, ObjectInherit"
    New-Item -ItemType Junction -Path (Join-Path $bootDir "evil") -Value $target | Out-Null
    $rows = Get-Report $rl
    Assert-True ((Get-RowResult $rows $RowBoot) -match "^FAIL.*link") ("the self-check FAILs the row, naming a link (" + (Get-RowResult $rows $RowBoot) + ")")
    $threw = $false; $msg = ""
    try { Set-BayAcls -Root $rl -KioskSid $Kiosk } catch { $threw = $true; $msg = $_.Exception.Message }
    Assert-True ($threw -and $msg -match "link") ("Set-BayAcls refuses to go on and says why (" + $msg + ")")
    Assert-True (@(Read-Icacls $target).Count -ge 1 -and @(Get-ChildItem -LiteralPath $target -Force).Count -eq 0) "the link's target was not touched or written into"
    Add-Ace $bootDir $Me "FullControl" "ContainerInherit, ObjectInherit"
    [IO.Directory]::Delete((Join-Path $bootDir "evil"), $false)

    Section "B-owner. a file owned by an account that is not Administrators or SYSTEM"
    $ro = New-Tree "bowner"
    Invoke-Apply $ro $Kiosk
    $elevatedOwner = (Get-Item -LiteralPath (Join-Path $ro "BayAgent\bootstrap\ABG.HostWatchdog.ps1")).GetAccessControl([System.Security.AccessControl.AccessControlSections]::Owner).GetOwner([System.Security.Principal.SecurityIdentifier]).Value
    if (@("S-1-5-32-544", "S-1-5-18") -contains $elevatedOwner) {
        Write-Host "  SKIP  this account creates files owned by Administrators (it is elevated); the owner rule is exercised by the account-not-trusted case below only"
    } else {
        $rows = Get-Report $ro $null @()
        Assert-True ((Get-RowResult $rows $RowBoot) -match "^FAIL.*owned by $([regex]::Escape($MeSid))") ("owned by $MeSid : the row FAILs and names the owner (" + (Get-RowResult $rows $RowBoot) + ")")
        Assert-True ((Get-RowResult (Get-Report $ro) $RowBoot) -eq "PASS") "...and reads PASS once that account is the declared stand-in"
    }

    # =========================================================================================== C. the SYSTEM task
    Section "C. SYSTEM scheduled tasks: what they run, and from where"
    $rc = New-Tree "c"
    Invoke-Apply $rc $Kiosk
    $wdScript = Join-Path $rc "BayAgent\bootstrap\ABG.HostWatchdog.ps1"
    $psExe = Join-Path $env:SystemRoot "System32\WindowsPowerShell\v1.0\powershell.exe"
    $good = [pscustomobject]@{ Name = "ABG Host Watchdog"; UserId = "SYSTEM"; Execute = $psExe; Arguments = ('-NoProfile -File "' + $wdScript + '"') }
    $outside = [pscustomobject]@{ Name = "ABG Host Watchdog"; UserId = "SYSTEM"; Execute = $psExe; Arguments = ('-NoProfile -File "' + (Join-Path $rc "BayAgent\tools\Update-BayAgent.ps1") + '"') }
    $bare = [pscustomobject]@{ Name = "ABG Host Watchdog"; UserId = "SYSTEM"; Execute = "powershell.exe"; Arguments = ('-NoProfile -File "' + $wdScript + '"') }
    $fromRoot = [pscustomobject]@{ Name = "ABG Host Watchdog"; UserId = "SYSTEM"; Execute = (Join-Path $rc "BayAgent\current\evil.exe"); Arguments = "" }
    $notSystem = [pscustomobject]@{ Name = "ABG Host Watchdog"; UserId = "BAY1KIOSK\BayKiosk"; Execute = $psExe; Arguments = ('-NoProfile -File "' + $wdScript + '"') }
    $other = [pscustomobject]@{ Name = "Some Other SYSTEM Task"; UserId = "SYSTEM"; Execute = $psExe; Arguments = ('-File "' + (Join-Path $rc "BayAgent\state\x.ps1") + '"') }
    $unrelated = [pscustomobject]@{ Name = "Windows Update"; UserId = "SYSTEM"; Execute = "C:\Windows\System32\usoclient.exe"; Arguments = "StartScan" }
    Assert-True ((Get-RowResult (Get-Report $rc @($good, $unrelated)) $RowTask) -eq "PASS") "the registered watchdog (SYSTEM, full System32 path, a script in bootstrap) and an unrelated Windows task: PASS"
    Assert-True ((Get-RowResult (Get-Report $rc @($outside)) $RowTask) -match "^FAIL.*outside the locked folder") "a SYSTEM task that runs a script from tools\ (BayKiosk can write there): FAIL"
    Assert-True ((Get-RowResult (Get-Report $rc @($bare)) $RowTask) -match "^FAIL.*not under System32") "a SYSTEM task that names powershell.exe without a path (search order): FAIL"
    Assert-True ((Get-RowResult (Get-Report $rc @($fromRoot)) $RowTask) -match "^FAIL") "a SYSTEM task whose program is under AllBirdies: FAIL"
    Assert-True ((Get-RowResult (Get-Report $rc @($good, $other)) $RowTask) -match "^FAIL.*state") "a second SYSTEM task that names a path under AllBirdies\BayAgent\state: FAIL"
    Assert-True ((Get-RowResult (Get-Report $rc @($notSystem)) $RowTask) -match "^FAIL.*was not found running as SYSTEM") "the watchdog registered as BayKiosk instead of SYSTEM is not accepted as the SYSTEM task: FAIL"
    Assert-True ((Get-RowResult (Get-Report $rc @()) $RowTask) -match "^FAIL.*was not found") "no task found at all is a FAIL, not a pass (nothing found is not nothing wrong)"

    # =========================================================================================== D. no BayKiosk account
    Section "D. the BayKiosk account does not exist"
    $rd = New-Tree "d"
    Set-BayAcls -Root $rd -KioskSid $null
    Set-BayKeyFileAcl -KeyPath $script:TestKeyPath
    $rowsD = @(Get-BayAclReport -Root $rd -KioskSid $null -Tasks @() -ExtraOwners @($MeSid))
    Assert-True ((Get-RowResult $rowsD $RowData) -match "^FAIL.*does not exist") "the data-folder row FAILs and says the account is missing, instead of passing for nobody"
    Assert-True ($null -eq (Get-BayKioskSid -User "NoSuchKioskAccount-0001")) "(Get-BayKioskSid on a missing account returns nothing)"
}
finally {
    # The scratch folders carry real locked ACLs. This account owns every one (the owner change is a double here), so it
    # gives itself full control back on this run's own uniquely named folder, then deletes that folder only.
    if ((Split-Path -Leaf $Base) -like "bayagent-kioskacl-*" -and (Test-Path -LiteralPath $Base)) {
        & $Icacls $Base /grant ("*" + $MeSid + ":F") /T /C /Q | Out-Null
        try { Remove-Item -LiteralPath $Base -Recurse -Force -ErrorAction SilentlyContinue } catch { }
    }
}

Write-Host ""
Write-Host ("RESULT: {0} passed, {1} failed" -f $script:Pass, $script:Fail) -ForegroundColor $(if ($script:Fail -eq 0) { "Green" } else { "Red" })
if ($script:Fail -gt 0) { $script:Failures | ForEach-Object { Write-Host "  - $_" -ForegroundColor Red }; exit 1 }
exit 0
