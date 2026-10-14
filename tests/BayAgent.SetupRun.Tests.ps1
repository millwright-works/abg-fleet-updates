<#
BayAgent.SetupRun.Tests.ps1

Runs the REAL text of Setup-BayPC.ps1 and AOC-Day0-Setup.ps1, top to bottom, against recorders on a modeled blank PC,
in every argument shape a run sheet or an installer uses, and a second time; then asserts on what was written and on
what was printed.

WHY THIS SUITE EXISTS. BayAgent.SetupBlankPc.Tests.ps1 lifts decision functions out of the two scripts and checks
them. An independent attack (2026-10-11) showed what that cannot see: the script could not finish ANY run (three
stops, all older than the lifted functions), and 17 of 17 changes planted in the script's own body passed every
suite, among them Remote Desktop turned back on through reg.exe and a certificate bay told to create the secret.
A setup script proven by lifting its functions is unproven as a script. This suite is the other half.

HOW. Each plan below is one modeled PC. tests\SetupRun.Harness.ps1 (see its header for what is modeled and from which
measurements) runs the plan's runs one after another in its own Windows PowerShell 5.1 process, the host a bay uses,
keeping the modeled machine between them, and writes what each run printed, recorded and left behind. A census in the
harness refuses, before anything runs, a script holding any command that is neither recorded nor read-only.

WHAT THIS DOES NOT PROVE. What Windows itself does: account password rules, the automatic sign-in at the next boot,
real time-stamped signing, a real scheduled task starting, Smart App Control. Those answers are modeled. A run on a
real blank PC is still the first one.

Run (from the repo root):
  powershell -NoProfile -ExecutionPolicy Bypass -File tests\BayAgent.SetupRun.Tests.ps1
Exit code 0 = all assertions passed. Hyphens only in comments.
#>
[CmdletBinding()]
param(
    [string]$SetupScript = "",
    [string]$Day0Script = ""
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
$RootName = if ([string]::IsNullOrWhiteSpace($env:AOC_TEST_ROOT_NAME)) { "AceOfClubs" } else { $env:AOC_TEST_ROOT_NAME }   # run the suite twice: AceOfClubs (default) and AllBirdies (a bay not yet moved)

$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
if ([string]::IsNullOrWhiteSpace($SetupScript)) { $SetupScript = Join-Path $RepoRoot "src\BayAgent\tools\Setup-BayPC.ps1" }
if ([string]::IsNullOrWhiteSpace($Day0Script))  { $Day0Script  = Join-Path $RepoRoot "tools\AOC-Day0-Setup.ps1" }
$SetupScript = (Resolve-Path $SetupScript).Path
$Day0Script  = (Resolve-Path $Day0Script).Path
$Harness = Join-Path $PSScriptRoot "SetupRun.Harness.ps1"
$Ps51 = Join-Path $env:WINDIR "System32\WindowsPowerShell\v1.0\powershell.exe"

$script:Pass = 0; $script:Fail = 0; $script:Failures = @()
function Assert-True([bool]$cond, [string]$msg) {
    if ($cond) { $script:Pass++; Write-Host "  PASS  $msg" }
    else { $script:Fail++; $script:Failures += $msg; Write-Host "  FAIL  $msg" -ForegroundColor Red }
}
function Section([string]$name) { Write-Host ""; Write-Host "== $name" -ForegroundColor Cyan }

$BaseDir = Join-Path $env:TEMP ("bayagent-setupruntest-" + [guid]::NewGuid().ToString("N").Substring(0, 8))
New-Item -ItemType Directory -Force -Path $BaseDir | Out-Null

$EmptyRun = [pscustomobject]@{ title = "(this run did not happen)"; ended = "NOT RUN"; stoppedAt = ""; console = @(); log = @(); reg = [pscustomobject]@{}; policy = ""; tasks = @(); users = @(); configText = $null; secretToolOnDisk = $false; markerInConsole = $true }

function Invoke-SetupPlan {
    # One modeled PC, its runs in order. Returns the harness result; a missing or unreadable result is a result with
    # no runs and a census text saying so, so every assertion on it fails instead of the suite stopping.
    param([string]$Name, [object[]]$Runs, [string]$Setup = $SetupScript, [string]$Day0 = $Day0Script)
    $dir = Join-Path $BaseDir $Name
    New-Item -ItemType Directory -Force -Path $dir | Out-Null
    $planFile = Join-Path $dir "plan.json"; $resultFile = Join-Path $dir "result.json"
    [IO.File]::WriteAllText($planFile, (([ordered]@{ runs = @($Runs) }) | ConvertTo-Json -Depth 8))
    $said = & $Ps51 -NoProfile -ExecutionPolicy Bypass -File $Harness -SetupScript $Setup -Day0Script $Day0 -RepoRoot $RepoRoot -Root (Join-Path $dir "pc") -PlanFile $planFile -ResultFile $resultFile 2>&1 | ForEach-Object { "$_" }
    if (-not (Test-Path -LiteralPath $resultFile)) { return [pscustomobject]@{ census = ("NO RESULT FILE: " + (@($said) -join " ")); harnessError = ""; runs = @() } }
    try { return ([IO.File]::ReadAllText($resultFile) | ConvertFrom-Json) }
    catch { return [pscustomobject]@{ census = "UNREADABLE RESULT FILE"; harnessError = ""; runs = @() } }
}
function Get-PlanRun($Result, [int]$Index) {
    $runs = @($Result.runs)
    if ($Index -lt $runs.Count) { return $runs[$Index] }
    return $EmptyRun
}
function Get-RunText($Run) { return (@($Run.console) -join "`n") }
function Get-RunLog($Run) { return @($Run.log | ForEach-Object { [string]$_ }) }
function Get-RunReg($Run, [string]$Key) {
    $p = $Run.reg.PSObject.Properties[$Key]
    if ($null -eq $p) { return $null }
    return $p.Value
}
function Get-ChecklistRow($Run, [string]$Check) {
    # The Result text of one checklist row as printed, or $null when the row is not on the screen at all.
    foreach ($l in @($Run.console)) {
        $line = [string]$l
        if ($line.StartsWith($Check + " ")) { return $line.Substring($Check.Length).Trim() }
    }
    return $null
}
function Test-Row($Run, [string]$Check, [string]$Bucket) {
    $r = Get-ChecklistRow $Run $Check
    return (($null -ne $r) -and $r.StartsWith($Bucket))
}
function Get-RowsInBucket($Run, [string]$Bucket) {
    # Every printed checklist row whose result starts with the bucket word (rows are the lines between the table
    # header and the summary line).
    $out = @(); $inTable = $false
    foreach ($l in @($Run.console)) {
        $line = [string]$l
        if ($line -match '^Check\s+Result\s*$') { $inTable = $true; continue }
        if ($inTable -and $line -match '^(ALL \d+ CHECKS PASSED|\d+ PASSED,)') { break }
        if ($inTable -and $line -match ('\s' + $Bucket + '(\s|\(|$)') -and $line -notmatch '^\s') { $out += $line.Trim() }
    }
    return $out
}
function Test-NoFailedRow($Run) {
    # True only when the checklist table WAS printed and none of its rows reads FAIL. A run that stopped before the table
    # has no failed row on the screen either; that must not count as a clean checklist.
    $seen = $false
    foreach ($l in @($Run.console)) { if ([string]$l -match '^Check\s+Result\s*$') { $seen = $true; break } }
    return ($seen -and (@(Get-RowsInBucket $Run "FAIL").Count -eq 0))
}
function Get-LogCount($Run, [string]$Pattern) { return @(Get-RunLog $Run | Where-Object { $_ -match $Pattern }).Count }
function Get-LineIndex($Run, [string]$Pattern) {
    $c = @($Run.console)
    for ($i = 0; $i -lt $c.Count; $i++) { if ([string]$c[$i] -match $Pattern) { return $i } }
    return -1
}

function Get-EnrollLines($Run) {
    # Every printed line that runs the installed agent with -EnrollCert, trimmed.
    return @(@($Run.console) | ForEach-Object { [string]$_ } | Where-Object { $_ -match 'current\\BayAgent\.ps1" -EnrollCert' } | ForEach-Object { $_.Trim() })
}
$EnrollWords = "<this bay's own app id>"
$OwnApp = "0f1e2d3c-4b5a-4978-8a6b-5c4d3e2f1a0b"
$VendorShared = "0e77dbf6"   # the first block of the vendor's own shared app id: it must never reach a bay by default

$Bay1 = "44d35503-6d63-f011-bec2-0022480b527b"
$OrgUrl = "https://example-club.crm.dynamics.com"
$Tenant = "11111111-2222-3333-4444-555555555555"
$App = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
$Step9Args = [ordered]@{ BayNumber = 1; BayId = $Bay1; EnvironmentUrl = $OrgUrl; TenantId = $Tenant; ClientId = $App; SkipLockdown = $true; SkipReboot = $true }
$Step16Args = [ordered]@{ BayNumber = 1; BayId = $Bay1; SkipDay0 = $true; SkipKioskSetup = $true }
$FullArgs = [ordered]@{ BayNumber = 1; BayId = $Bay1; EnvironmentUrl = $OrgUrl; TenantId = $Tenant; ClientId = $App }
$KeyRdp = "hklm:\system\currentcontrolset\control\terminal server|fdenytsconnections"
$KeyUsb = "hklm:\system\currentcontrolset\services\usbstor|start"
$KeyWinlogon = "hklm:\software\microsoft\windows nt\currentversion\winlogon|"
$LockdownRows = @("USB storage disabled", "Admin shell override (HKCU)", "Win+L (lock) disabled", "Task Manager disabled")
$AllRows = @("Windows 11 Pro", "Computer name = BAY1KIOSK", "Bootstrap: AOC.AgentHost.ps1", "Bootstrap: AOC.HostWatchdog.ps1", "Tool: Update-BayAgent.ps1",
    "agent-config.json present", "Agent package installed (current\BayAgent.ps1)", "No DPAPI secret file (certificate bay)", "Code signing certificate",
    "Scheduled task: AOC Bay Agent", "Scheduled task: AOC Host Watchdog", "BayKiosk user exists", "Auto-login enabled", "Remote Desktop off",
    "USB storage disabled", "Dataverse connectivity", "Shell wrapper script", "Custom shell (HKLM)", "Admin shell override (HKCU)",
    "Win+L (lock) disabled", "Task Manager disabled", "Display count (3 required)", "Execution policy (AllSigned)")

try {
    # =========================================================================================== the two-run sitting
    Section "PLAN sheet: a blank PC named at Windows setup; the first run without the lockdown (twice), then the lockdown run (twice)"
    $sheet = Invoke-SetupPlan "sheet" @(
        [ordered]@{ title = "first run, lockdown skipped"; computerName = "BAY1KIOSK"; args = $Step9Args },
        [ordered]@{ title = "first run again"; computerName = "BAY1KIOSK"; args = $Step9Args },
        [ordered]@{ title = "lockdown run, agent installed, reboot answered y"; computerName = "BAY1KIOSK"; args = $Step16Args; model = [ordered]@{ placeAgent = $true; rebootAnswer = "y" } },
        [ordered]@{ title = "lockdown run again, reboot answered n"; computerName = "BAY1KIOSK"; args = $Step16Args }
    )
    Assert-True ($sheet.census -eq "ok") ("the census accepts both scripts: every command is recorded or read-only (" + $sheet.census + ")")
    Assert-True ([string]::IsNullOrEmpty([string]$sheet.harnessError)) ("the harness itself ran clean (" + $sheet.harnessError + ")")
    Assert-True (@($sheet.runs).Count -eq 4) "all four runs of the sitting happened"

    $r1 = Get-PlanRun $sheet 0; $t1 = Get-RunText $r1
    Section "sheet, first run (-SkipLockdown -SkipReboot): it finishes, and says the truth"
    Assert-True ($r1.ended -eq "ran to its last line") ("the run reaches the script's last line (" + $r1.ended + " " + $r1.stoppedAt + ")")
    Assert-True ($t1 -match "Setup-BayPC\.ps1 Complete") "...and prints its closing banner"
    $missingRows = @($AllRows | Where-Object { $null -eq (Get-ChecklistRow $r1 $_) })
    Assert-True ($missingRows.Count -eq 0) ("every checklist row is on the screen (missing: " + $(if ($missingRows.Count) { $missingRows -join "; " } else { "none" }) + ")")
    Assert-True ((Test-NoFailedRow $r1)) ("no row reads FAIL on a correct first run (" + (@(Get-RowsInBucket $r1 "FAIL") -join " | ") + ")")
    Assert-True (Test-Row $r1 "Remote Desktop off" "PASS") "Remote Desktop off: PASS (a fresh Windows has it off and this run did not touch it)"
    foreach ($row in $LockdownRows) { Assert-True (Test-Row $r1 $row "PENDING") "lockdown row '$row': PENDING, because the lockdown was skipped on purpose" }
    Assert-True (Test-Row $r1 "Agent package installed (current\BayAgent.ps1)" "PENDING") "Agent package installed: PENDING on a blank PC"
    Assert-True (Test-Row $r1 "No DPAPI secret file (certificate bay)" "PASS") "No DPAPI secret file: PASS"
    Assert-True ((Test-Row $r1 "Scheduled task: AOC Bay Agent" "PASS") -and (Test-Row $r1 "Scheduled task: AOC Host Watchdog" "PASS")) "both scheduled task rows: PASS"
    Assert-True (Test-Row $r1 "Execution policy (AllSigned)" "PASS") "Execution policy: PASS"
    Assert-True ($r1.policy -eq "AllSigned") "the machine script policy is AllSigned after a run that skipped the lockdown (the tasks can start)"
    Assert-True ((Get-LogCount $r1 '^POLICY   Set-ExecutionPolicy AllSigned -Scope LocalMachine') -eq 1) "...set once, through Set-ExecutionPolicy -Scope LocalMachine, whose override error did not stop the run"
    Assert-True ((Test-Row $r1 "Auto-login enabled" "PASS") -and (Test-Row $r1 "BayKiosk user exists" "PASS") -and (Test-Row $r1 "Code signing certificate" "PASS") -and (Test-Row $r1 "Computer name = BAY1KIOSK" "PASS")) "account, automatic sign-in, signing certificate and name rows: PASS"
    Assert-True ($t1 -match '(?m)^\d+ PASSED, \d+ PENDING \(non-blocking\)\s*$') "the summary line prints, with no FAILED count"

    Assert-True ((Get-LogCount $r1 'fDenyTSConnections') -eq 0 -and (Get-RunReg $r1 $KeyRdp) -eq 1) "with the lockdown skipped nothing writes the Remote Desktop value, and it is still 1 (off)"
    Assert-True ((Get-LogCount $r1 '^FIREWALL') -eq 0) "...and no firewall rule is touched"
    Assert-True ((Get-RunReg $r1 $KeyUsb) -eq 3) "...and USB storage is still allowed (the lockdown really was skipped)"
    Assert-True ((@($r1.tasks) -join ",") -eq "AOC Bay Agent,AOC Host Watchdog") "both scheduled tasks were registered"
    Assert-True ((@($r1.users) -join ",") -eq "BayKiosk" -and (Get-LogCount $r1 '^USER     created local user BayKiosk') -eq 1) "the BayKiosk account was created once"
    Assert-True ((Get-RunReg $r1 ($KeyWinlogon + "defaultdomainname")) -eq "BAY1KIOSK" -and "$(Get-RunReg $r1 ($KeyWinlogon + 'autoadminlogon'))" -eq "1" -and (Get-RunReg $r1 ($KeyWinlogon + "defaultusername")) -eq "BayKiosk") "automatic sign-in: on, as BayKiosk, with the bay's name"
    $dl1 = @(Get-RunLog $r1 | Where-Object { $_ -match '^DOWNLOAD ' })
    Assert-True ($dl1.Count -eq 6 -and @($dl1 | Where-Object { $_ -match 'REFUSED|404' }).Count -eq 0) ("six downloads, all from this repository's main branch under its current owner (" + $dl1.Count + ")")
    Assert-True (@($dl1 | Where-Object { $_ -match 'SetClientSecretDpapi' }).Count -eq 0 -and $r1.secretToolOnDisk -eq $false) "a certificate bay is NOT given the secret tool: no download, no file (A0.529)"
    Assert-True ((Get-LogCount $r1 '^SIGN ') -eq 5) "the five bootstrap and tool scripts were signed"

    $cfg1 = $null; try { $cfg1 = ([string]$r1.configText) | ConvertFrom-Json } catch { $cfg1 = $null }
    Assert-True ($null -ne $cfg1 -and $cfg1.environmentUrl -eq $OrgUrl -and $cfg1.tenantId -eq $Tenant -and $cfg1.clientId -eq $App -and $cfg1.bayId -eq $Bay1) "agent-config.json holds exactly the four values typed on the command line"
    Assert-True ($null -ne $r1.configText -and ([string]$r1.configText) -notmatch '<[a-z-]+>') "...with no <placeholder> left"

    Assert-True ($t1 -match "DO NOT create a DPAPI secret" -and $t1 -notmatch "SetClientSecretDpapi") "a certificate bay is told NOT to create the secret, and the tool that creates one is named nowhere on the screen"
    Assert-True ($t1 -match "IF ENROLLMENT FAILS, STOP HERE") "...and is told to stop, not to fall back, if enrollment fails (A0.529)"
    $iNext = Get-LineIndex $r1 '^\s*Next Steps\s*$'; $iInstall = Get-LineIndex $r1 'Install the agent package \(BayAgent\.ps1 is not on this PC'
    $c1 = @($r1.console); $iEnroll = -1
    for ($i = [Math]::Max(0, $iNext); $i -lt $c1.Count; $i++) { if ([string]$c1[$i] -match 'current\\BayAgent\.ps1" -EnrollCert') { $iEnroll = $i; break } }
    Assert-True ($iNext -ge 0 -and $iInstall -gt $iNext) "Next Steps is printed, and the first install of the agent package is in it"
    Assert-True ($iEnroll -gt $iInstall -and $iInstall -ge 0) "...before the enroll step, which runs BayAgent\current\BayAgent.ps1"
    Assert-True ($t1 -notmatch '\\BayAgent\\BayAgent\.ps1') "no line on the screen names BayAgent\BayAgent.ps1 (nothing is installed there)"
    # 1.6.1: the enroll line names the bay's own app. This run typed -ClientId and no -BayAppId, so the line carries the
    # words to replace, never an id the operator did not type as the bay's own.
    $enr1 = @(Get-EnrollLines $r1)
    Assert-True ($enr1.Count -eq 2 -and @($enr1 | Where-Object { $_ -notmatch ('-EnrollCert -EnrollClientId ' + [regex]::Escape($EnrollWords) + '$') }).Count -eq 0) ("no -BayAppId typed: both enroll lines (Phase 6 and Next Steps) end '-EnrollCert -EnrollClientId " + $EnrollWords + "' (found " + $enr1.Count + ")")
    Assert-True ($t1 -notmatch '-EnrollClientId [0-9a-fA-F]{8}-') "...and no app id follows -EnrollClientId anywhere on the screen (the typed -ClientId is not presented as the bay's own app)"
    $pw1 = @(Get-RunLog $r1 | Where-Object { $_ -match '^PROMPT ' })
    Assert-True ($pw1.Count -eq 2 -and @($pw1 | Where-Object { $_ -match 'Reboot' }).Count -eq 0) "two password prompts and no reboot question (-SkipReboot)"
    Assert-True ($r1.markerInConsole -eq $false) "the password typed at the prompts appears nowhere in what the run printed"

    $r2 = Get-PlanRun $sheet 1
    Section "sheet, the same first run a second time: it finishes again and changes nothing it should not"
    Assert-True ($r2.ended -eq "ran to its last line") ("the second run reaches the last line (" + $r2.ended + " " + $r2.stoppedAt + ")")
    Assert-True ((Test-NoFailedRow $r2)) "no row reads FAIL"
    Assert-True ((Get-LogCount $r2 '^USER     created') -eq 0) "the account is not created a second time"
    Assert-True ([string]$r2.configText -eq [string]$r1.configText) "agent-config.json is byte for byte what the first run wrote (never overwritten)"
    Assert-True ($r2.markerInConsole -eq $false) "no typed password on the screen"

    $r3 = Get-PlanRun $sheet 2; $t3 = Get-RunText $r3
    Section "sheet, the lockdown run (-SkipDay0 -SkipKioskSetup): it finishes, locks down, and asks about the reboot"
    Assert-True ($r3.ended -eq "ran to its last line") ("the lockdown run reaches the last line (" + $r3.ended + " " + $r3.stoppedAt + ")")
    Assert-True ((Get-LogCount $r3 'fDenyTSConnections = 1$') -eq 1 -and (Get-LogCount $r3 'fDenyTSConnections') -eq 1 -and (Get-RunReg $r3 $KeyRdp) -eq 1) "Remote Desktop: written exactly once, as 1 (off), and it reads 1 afterward"
    Assert-True ((Get-LogCount $r3 "^FIREWALL disable group 'Remote Desktop'") -eq 1 -and (Get-LogCount $r3 '^FIREWALL enable') -eq 0) "the Remote Desktop firewall group is disabled once and enabled never"
    Assert-True ($t3 -match "Remote Desktop OFF") "...and the screen says Remote Desktop OFF"
    Assert-True ((Get-RunReg $r3 $KeyUsb) -eq 4) "USB storage is blocked"
    Assert-True ((Get-RunReg $r3 "hklm:\software\microsoft\windows\currentversion\policies\system|disabletaskmgr") -eq 1 -and (Get-RunReg $r3 "hklm:\software\microsoft\windows\currentversion\policies\system|disablelockworkstation") -eq 1) "Task Manager and the lock key are off"
    Assert-True ((Get-RunReg $r3 ($KeyWinlogon + "shell")) -eq "explorer.exe" -and (Get-RunReg $r3 "hkcu:\software\microsoft\windows nt\currentversion\winlogon|shell") -eq "explorer.exe") "the shell stays explorer.exe (the launcher wrapper is not on a bay), and the admin override is set"
    Assert-True ((Test-NoFailedRow $r3)) ("no row reads FAIL after the lockdown (" + (@(Get-RowsInBucket $r3 "FAIL") -join " | ") + ")")
    foreach ($row in $LockdownRows) { Assert-True (Test-Row $r3 $row "PASS") "lockdown row '$row': PASS" }
    Assert-True ((Test-Row $r3 "Remote Desktop off" "PASS") -and (Test-Row $r3 "Agent package installed (current\BayAgent.ps1)" "PASS") -and (Test-Row $r3 "Execution policy (AllSigned)" "PASS")) "Remote Desktop off, Agent package installed and Execution policy: PASS"
    Assert-True ($t3 -match '(?m)^(\d+ PASSED, \d+ PENDING \(non-blocking\)|ALL \d+ CHECKS PASSED)\s*$') "the summary line prints on a run with no failed row (zero rows in a bucket no longer stops it)"
    Assert-True ((Get-LineIndex $r3 '^\s*Next Steps\s*$') -ge 0 -and $t3 -notmatch 'Install the agent package \(BayAgent\.ps1 is not on this PC') "Next Steps prints, without the install step now that the agent is there"
    $p3 = @(Get-RunLog $r3 | Where-Object { $_ -match '^PROMPT ' })
    Assert-True ($p3.Count -eq 1 -and $p3[0] -match 'Reboot now\? \(y/N\)') "the only question is 'Reboot now? (y/N)': no password is asked for"
    Assert-True ((Get-LogCount $r3 '^SHUTDOWN /r') -eq 1) "answering y restarts the PC"
    Assert-True ((Get-LogCount $r3 '^DOWNLOAD ') -eq 0 -and (Get-LogCount $r3 '^SCHTASKS ') -eq 0) "nothing is downloaded and no task is re-registered (-SkipDay0)"
    Assert-True ($r3.policy -eq "AllSigned") "the machine script policy is AllSigned"

    $r4 = Get-PlanRun $sheet 3
    Section "sheet, the lockdown run a second time"
    Assert-True ($r4.ended -eq "ran to its last line") ("it reaches the last line again (" + $r4.ended + " " + $r4.stoppedAt + ")")
    Assert-True ((Get-RunReg $r4 $KeyRdp) -eq 1 -and (Get-RunReg $r4 $KeyUsb) -eq 4 -and (Test-NoFailedRow $r4)) "same end state: Remote Desktop off, USB blocked, no failed row"
    Assert-True ((Get-LogCount $r4 '^SHUTDOWN') -eq 0 -and (Get-LogCount $r4 'Reboot now') -eq 1) "answering n to the reboot question restarts nothing"

    # =========================================================================================== one full run
    Section "PLAN full: one run with no skips (the script header's own example), twice"
    $full = Invoke-SetupPlan "full" @(
        [ordered]@{ title = "full run"; computerName = "BAY1KIOSK"; args = $FullArgs },
        [ordered]@{ title = "full run again"; computerName = "BAY1KIOSK"; args = $FullArgs }
    )
    $f1 = Get-PlanRun $full 0; $f2 = Get-PlanRun $full 1
    Assert-True ($f1.ended -eq "ran to its last line") ("the full run reaches the last line (" + $f1.ended + " " + $f1.stoppedAt + ")")
    Assert-True ((Get-RunReg $f1 $KeyRdp) -eq 1 -and (Get-LogCount $f1 "^FIREWALL disable group 'Remote Desktop'") -eq 1 -and (Get-LogCount $f1 '^FIREWALL enable') -eq 0) "Remote Desktop off, its firewall group disabled"
    Assert-True ($f1.policy -eq "AllSigned" -and (Get-RunReg $f1 $KeyUsb) -eq 4) "script policy AllSigned, USB blocked"
    Assert-True ((Test-NoFailedRow $f1)) ("no failed row (" + (@(Get-RowsInBucket $f1 "FAIL") -join " | ") + ")")
    Assert-True ((Get-LogCount $f1 'Reboot now') -eq 1 -and (Get-LineIndex $f1 '^\s*Next Steps\s*$') -ge 0) "Next Steps and the reboot question are reached"
    Assert-True ($f2.ended -eq "ran to its last line" -and (Test-NoFailedRow $f2)) ("the same run a second time finishes with no failed row (" + $f2.ended + ")")

    # =========================================================================================== an installer that passes nothing
    Section "PLAN customer: Setup-BayPC.ps1 -BayNumber 2 and nothing else, on a PC with a factory name, twice"
    $cust = Invoke-SetupPlan "customer" @(
        [ordered]@{ title = "bay number only"; computerName = "DESKTOP-7Q2K9XA"; args = [ordered]@{ BayNumber = 2 } },
        [ordered]@{ title = "bay number only, again"; computerName = "DESKTOP-7Q2K9XA"; args = [ordered]@{ BayNumber = 2 } }
    )
    $c1r = Get-PlanRun $cust 0; $ct = Get-RunText $c1r; $ccfg = [string]$c1r.configText
    Assert-True ($c1r.ended -eq "ran to its last line") ("it reaches the last line (" + $c1r.ended + " " + $c1r.stoppedAt + ")")
    Assert-True ($ccfg.Contains("<your-org>") -and $ccfg.Contains("<tenant-guid>") -and $ccfg.Contains("<app-client-id>") -and $ccfg.Contains("<bay-guid>")) "nothing was passed, so all four placeholders stay in agent-config.json"
    Assert-True ($ccfg -notmatch 'builds-apps-dev|cc551e6a|0e77dbf6') "the vendor's own organization, tenant and shared app are NOT written into the bay's configuration"
    Assert-True ($ct -match 'STILL TO FILL IN[^\r\n]*<your-org>[^\r\n]*<tenant-guid>[^\r\n]*<app-client-id>[^\r\n]*<bay-guid>') "...and the screen names all four as still to fill in"
    Assert-True ((Get-LogCount $c1r '^RENAME   computer to BAY2KIOSK') -eq 1 -and (Get-RunReg $c1r ($KeyWinlogon + "defaultdomainname")) -eq "BAY2KIOSK") "the PC is renamed, and automatic sign-in is written with the NEW name"
    Assert-True ($ct -match '(?m)^\s*1\. Reboot to apply the computer name change to ''BAY2KIOSK''') "Next Steps starts with the reboot the rename needs"
    Assert-True ((Get-RunReg $c1r $KeyRdp) -eq 1 -and $c1r.policy -eq "AllSigned") "Remote Desktop off and script policy AllSigned on a default run"
    $c2r = Get-PlanRun $cust 1
    Assert-True ($c2r.ended -eq "ran to its last line") ("the second run finishes too (" + $c2r.ended + " " + $c2r.stoppedAt + ")")
    $enrC = @(Get-EnrollLines $c1r)
    Assert-True ($enrC.Count -eq 2 -and @($enrC | Where-Object { $_ -notmatch ('-EnrollCert -EnrollClientId ' + [regex]::Escape($EnrollWords) + '$') }).Count -eq 0) "an installer that passes nothing is shown the enroll line with the words to replace, in both places"
    Assert-True (-not $ct.Contains($VendorShared) -and $ct -notmatch '-EnrollClientId [0-9a-fA-F]{8}-') "...and no app id is on the screen at all: the vendor's shared app is not offered as this bay's identity"

    # =========================================================================================== the bay's own app (1.6.1)
    Section "PLAN own-identity: the sheet's first run with -BayAppId (twice), then the lockdown run (twice)"
    $Step9Own = [ordered]@{ BayNumber = 1; BayId = $Bay1; EnvironmentUrl = $OrgUrl; TenantId = $Tenant; BayAppId = $OwnApp.ToUpperInvariant(); SkipLockdown = $true; SkipReboot = $true }
    $own = Invoke-SetupPlan "own-identity" @(
        [ordered]@{ title = "first run with -BayAppId, lockdown skipped"; computerName = "BAY1KIOSK"; args = $Step9Own },
        [ordered]@{ title = "the same again"; computerName = "BAY1KIOSK"; args = $Step9Own },
        [ordered]@{ title = "lockdown run"; computerName = "BAY1KIOSK"; args = $Step16Args; model = [ordered]@{ placeAgent = $true; rebootAnswer = "n" } },
        [ordered]@{ title = "lockdown run again"; computerName = "BAY1KIOSK"; args = $Step16Args }
    )
    Assert-True ($own.census -eq "ok" -and [string]::IsNullOrEmpty([string]$own.harnessError) -and @($own.runs).Count -eq 4) ("census ok, harness clean, four runs (" + $own.census + " " + $own.harnessError + ")")
    $o1r = Get-PlanRun $own 0; $ot1 = Get-RunText $o1r
    Assert-True ($o1r.ended -eq "ran to its last line" -and (Test-NoFailedRow $o1r)) ("the first run reaches the last line with no failed row (" + $o1r.ended + " " + $o1r.stoppedAt + ")")
    $ocfg = $null; try { $ocfg = ([string]$o1r.configText) | ConvertFrom-Json } catch { $ocfg = $null }
    Assert-True ($null -ne $ocfg -and $ocfg.clientId -ceq $OwnApp -and $ocfg.environmentUrl -eq $OrgUrl -and $ocfg.tenantId -eq $Tenant -and $ocfg.bayId -eq $Bay1) "agent-config.json names the bay's OWN app as clientId (typed once, as -BayAppId, in upper case; written in canonical form)"
    Assert-True ($null -ne $o1r.configText -and ([string]$o1r.configText) -notmatch '<[a-z-]+>' -and $ot1 -match 'environmentUrl, tenantId, clientId and bayId were filled from this command line') "...with no <placeholder> left, and Day0 says all four were filled"
    Assert-True (-not ([string]$o1r.configText).Contains($VendorShared) -and -not $ot1.Contains($VendorShared)) "the vendor's shared app id is in neither the configuration nor anything printed"
    $enrO = @(Get-EnrollLines $o1r)
    $wantLine = (('powershell.exe -NoProfile -ExecutionPolicy Bypass -File "<root>\{0}\BayAgent\current\BayAgent.ps1" -EnrollCert -EnrollClientId ' -f $RootName) + $OwnApp)
    Assert-True ($enrO.Count -eq 2 -and @($enrO | Where-Object { $_ -cne $wantLine }).Count -eq 0) ("both enroll lines are exactly the line a person runs, with the bay's own app id (found: " + ($enrO -join " || ") + ")")
    Assert-True (-not $ot1.Contains($EnrollWords)) "...and the words-to-replace appear nowhere when the id was typed"
    Assert-True ($ot1 -match "RESULT: ENROLLED" -and $ot1 -match "RESULT: READY" -and $ot1 -match "NO 'RESULT:' LINE AT ALL" -and $ot1 -match "NOT as administrator") "the screen says what the line must end with, twice, that no RESULT line means the wrong agent, and not to run it as administrator"
    Assert-True ($ot1 -match "DO NOT create a DPAPI secret" -and $ot1 -match "IF ENROLLMENT FAILS, STOP HERE" -and $ot1 -notmatch "SetClientSecretDpapi") "...and still forbids the secret and the fallback (A0.529)"
    Assert-True ($ot1 -notmatch "PENDING instead of ACTIVE" -and $ot1 -notmatch "signs in as the app agent-config.json names") "the 1.6.0 wording (a secret makes the certificate PENDING; the certificate signs in as the configured app) is gone"
    Assert-True ($o1r.secretToolOnDisk -eq $false -and $o1r.markerInConsole -eq $false) "no secret tool on disk, no typed password on the screen"
    $o2r = Get-PlanRun $own 1
    Assert-True ($o2r.ended -eq "ran to its last line" -and [string]$o2r.configText -eq [string]$o1r.configText -and ((Get-EnrollLines $o2r) -join "|") -eq ($enrO -join "|")) "the same run a second time: same configuration bytes, same two enroll lines"
    $o3r = Get-PlanRun $own 2; $o4r = Get-PlanRun $own 3
    Assert-True ($o3r.ended -eq "ran to its last line" -and (Test-NoFailedRow $o3r) -and [string]$o3r.configText -eq [string]$o1r.configText) ("the lockdown run finishes with no failed row and leaves the configuration alone (" + $o3r.ended + ")")
    Assert-True (@(Get-EnrollLines $o3r | Where-Object { $_ -notmatch ('-EnrollClientId ' + [regex]::Escape($EnrollWords) + '$') }).Count -eq 0 -and @(Get-EnrollLines $o3r).Count -eq 2) "the lockdown run was not given -BayAppId, so its enroll lines carry the words to replace (it does not guess an id from the configuration)"
    Assert-True ($o4r.ended -eq "ran to its last line" -and (Test-NoFailedRow $o4r)) "the lockdown run a second time finishes too"

    Section "PLAN own-identity, both ids typed: -ClientId is kept, and the screen says the two differ"
    $both = Invoke-SetupPlan "both-ids" @(
        [ordered]@{ title = "-ClientId and a different -BayAppId"; computerName = "BAY1KIOSK"; args = [ordered]@{ BayNumber = 1; BayId = $Bay1; EnvironmentUrl = $OrgUrl; TenantId = $Tenant; ClientId = $App; BayAppId = $OwnApp; SkipLockdown = $true; SkipReboot = $true } }
    )
    $bo1 = Get-PlanRun $both 0; $bot = Get-RunText $bo1; $bocfg = $null; try { $bocfg = ([string]$bo1.configText) | ConvertFrom-Json } catch { }
    Assert-True ($bo1.ended -eq "ran to its last line" -and $null -ne $bocfg -and $bocfg.clientId -eq $App) ("the typed -ClientId is what the configuration holds (" + $bo1.ended + ")")
    Assert-True (@(Get-EnrollLines $bo1 | Where-Object { $_ -notmatch ('-EnrollClientId ' + $OwnApp + '$') }).Count -eq 0 -and @(Get-EnrollLines $bo1).Count -eq 2) "...the enroll lines name the bay's own app, not the -ClientId value"
    Assert-True ($bot -match "NOTE: -ClientId was typed as well and is not this bay's own app") "...and a NOTE says the two differ"
    $same = Invoke-SetupPlan "same-ids" @(
        [ordered]@{ title = "-ClientId equal to -BayAppId"; computerName = "BAY1KIOSK"; args = [ordered]@{ BayNumber = 1; BayId = $Bay1; EnvironmentUrl = $OrgUrl; TenantId = $Tenant; ClientId = $OwnApp; BayAppId = $OwnApp; SkipLockdown = $true; SkipReboot = $true } }
    )
    $sm1 = Get-PlanRun $same 0
    Assert-True ($sm1.ended -eq "ran to its last line" -and (Get-RunText $sm1) -notmatch "NOTE: -ClientId was typed") "when both name the same app there is no NOTE"

    Section "PLAN own-identity, a value that is not one: the run stops before ANYTHING on the PC is changed"
    $typedWrong = "ZZ-pasted-by-mistake-" + [guid]::NewGuid().ToString("N")
    foreach ($badCase in @(
            @{ label = "not a GUID"; args = [ordered]@{ BayNumber = 1; BayId = $Bay1; EnvironmentUrl = $OrgUrl; TenantId = $Tenant; BayAppId = $typedWrong; SkipLockdown = $true; SkipReboot = $true }; pattern = "-BayAppId must be this bay's own app id" },
            @{ label = "the all-zero GUID"; args = [ordered]@{ BayNumber = 1; BayId = $Bay1; BayAppId = "00000000-0000-0000-0000-000000000000"; SkipLockdown = $true; SkipReboot = $true }; pattern = "-BayAppId must be this bay's own app id" },
            @{ label = "with -Credential Secret"; args = [ordered]@{ BayNumber = 1; BayId = $Bay1; BayAppId = $OwnApp; Credential = "Secret"; SkipLockdown = $true; SkipReboot = $true }; pattern = "-BayAppId is for a bay set up with a certificate" })) {
        $bp = Invoke-SetupPlan ("bad-appid-" + ($badCase.label -replace '[^a-z]', '')) @(
            [ordered]@{ title = $badCase.label; computerName = "DESKTOP-7Q2K9XA"; args = $badCase.args },
            [ordered]@{ title = "then a good run on the same PC"; computerName = "DESKTOP-7Q2K9XA"; args = [ordered]@{ BayNumber = 1; BayId = $Bay1; EnvironmentUrl = $OrgUrl; TenantId = $Tenant; BayAppId = $OwnApp; SkipLockdown = $true; SkipReboot = $true } }
        )
        $bp1 = Get-PlanRun $bp 0; $bp2 = Get-PlanRun $bp 1
        Assert-True ([string]$bp1.ended -match '^STOPPED: ' -and [string]$bp1.ended -match $badCase.pattern) ("[" + $badCase.label + "] the run stops and says why (" + $bp1.ended + ")")
        Assert-True (@($bp1.log).Count -eq 0 -and $null -eq $bp1.configText -and @($bp1.users).Count -eq 0 -and @($bp1.tasks).Count -eq 0 -and $bp1.policy -eq "Undefined") ("[" + $badCase.label + "] nothing was changed: no rename, no account, no download, no registry write, no policy, no configuration (recorded actions: " + @($bp1.log).Count + ")")
        Assert-True (-not (([string]$bp1.ended) + (Get-RunText $bp1)).Contains($typedWrong)) ("[" + $badCase.label + "] what was typed is not echoed")
        $bp2cfg = $null; try { $bp2cfg = ([string]$bp2.configText) | ConvertFrom-Json } catch { }
        Assert-True ($bp2.ended -eq "ran to its last line" -and $null -ne $bp2cfg -and $bp2cfg.clientId -eq $OwnApp) ("[" + $badCase.label + "] the next run with a good value sets the PC up as usual (" + $bp2.ended + ")")
    }

    Section "Census: -BayAppId has no default, is read only when typed, and reaches the configuration in one guarded place"
    $tkS = $null; $erS = $null
    $sAst = [System.Management.Automation.Language.Parser]::ParseFile($SetupScript, [ref]$tkS, [ref]$erS)
    $bayAppParam = @($sAst.ParamBlock.Parameters | Where-Object { $_.Name.VariablePath.UserPath -eq "BayAppId" })
    Assert-True ($bayAppParam.Count -eq 1 -and $null -ne $bayAppParam[0].DefaultValue -and $bayAppParam[0].DefaultValue.Extent.Text -eq '""') "-BayAppId exists and its default is the empty string"
    $planCallsS = @($sAst.FindAll({ param($n) $n -is [System.Management.Automation.Language.CommandAst] -and $n.GetCommandName() -eq "Get-BayAppIdPlan" }, $true))
    Assert-True ($planCallsS.Count -eq 1 -and $planCallsS[0].Extent.Text -match '-Given \$PSBoundParameters\.ContainsKey\("BayAppId"\) -Value \$BayAppId ') "Get-BayAppIdPlan is called once, with -Given bound to `$PSBoundParameters.ContainsKey(`"BayAppId`") (only a typed value counts)"
    $cfgClient = @($sAst.FindAll({ param($n) $n -is [System.Management.Automation.Language.AssignmentStatementAst] -and $n.Left.Extent.Text -eq '$day0Args["ConfigClientId"]' }, $true))
    $rights = @($cfgClient | ForEach-Object { $_.Right.Extent.Text.Trim() } | Sort-Object)
    # Compared as a set: the two hosts sort text that starts with '$' and '[' in different orders.
    Assert-True ($cfgClient.Count -eq 2 -and ($rights -contains '$ClientId') -and ($rights -contains '[string]$bayAppPlan.configClientId')) ("the configuration's clientId is assigned in exactly two places: the typed -ClientId and the plan's configClientId (found: " + ($rights -join " | ") + ")")
    $uses = @([regex]::Matches([IO.File]::ReadAllText($SetupScript), '\$BayAppId\b') | ForEach-Object { $_.Index })
    Assert-True ($uses.Count -eq 2) ("`$BayAppId itself is read in one place besides its declaration, the call to Get-BayAppIdPlan (occurrences in code and comments: " + $uses.Count + ")")

    # =========================================================================================== the legacy secret credential
    Section "PLAN secret-bay: only a bay set up with -Credential Secret gets the tool that seals one"
    $sec = Invoke-SetupPlan "secret" @(
        [ordered]@{ title = "secret bay"; computerName = "BAY3KIOSK"; args = [ordered]@{ BayNumber = 3; Credential = "Secret"; SkipLockdown = $true; SkipReboot = $true } }
    )
    $s1 = Get-PlanRun $sec 0; $st = Get-RunText $s1
    Assert-True ($s1.ended -eq "ran to its last line") ("it reaches the last line (" + $s1.ended + " " + $s1.stoppedAt + ")")
    Assert-True ((Get-LogCount $s1 '^DOWNLOAD .*/bootstrap/AOC\.SetClientSecretDpapi\.ps1$') -eq 1 -and $s1.secretToolOnDisk -eq $true) "the secret tool is downloaded once and is on disk"
    Assert-True ((Get-LogCount $s1 '^SIGN .*SetClientSecretDpapi') -eq 0 -and (Get-LogCount $s1 '^SIGN ') -eq 5) "...and is not signed (five signed files, as before)"
    Assert-True ($st -match 'bootstrap\\AOC\.SetClientSecretDpapi\.ps1' -and (Test-Row $s1 "DPAPI secret exists" "PENDING")) "the screen gives the command that runs it, and the row reads PENDING until the file exists"

    # =========================================================================================== values that are not values
    Section "PLAN bad-values: a typed value that is not one is not written; a later run never rewrites the file"
    $badArgs = [ordered]@{ BayNumber = 1; BayId = $Bay1; EnvironmentUrl = "example-club.crm.dynamics.com"; TenantId = "not-a-guid"; ClientId = $App; SkipLockdown = $true; SkipReboot = $true }
    $bad = Invoke-SetupPlan "bad-values" @(
        [ordered]@{ title = "an address without https and a tenant id that is not a GUID"; computerName = "BAY1KIOSK"; args = $badArgs },
        [ordered]@{ title = "then the same PC with four good values"; computerName = "BAY1KIOSK"; args = $Step9Args }
    )
    $b1 = Get-PlanRun $bad 0; $b2 = Get-PlanRun $bad 1; $bcfg = [string]$b1.configText
    Assert-True ($b1.ended -eq "ran to its last line") ("it reaches the last line (" + $b1.ended + " " + $b1.stoppedAt + ")")
    Assert-True ($bcfg.Contains("<your-org>") -and $bcfg.Contains("<tenant-guid>") -and $bcfg -notmatch 'not-a-guid' -and $bcfg -notmatch '"environmentUrl":\s*"https://example-club') "the two bad values are not written: their placeholders stay"
    Assert-True ($bcfg.Contains($App) -and $bcfg.Contains($Bay1) -and -not $bcfg.Contains("<app-client-id>") -and -not $bcfg.Contains("<bay-guid>")) "...while the two good values beside them are written"
    Assert-True ((Get-RunText $b1) -match 'STILL TO FILL IN[^\r\n]*<your-org>[^\r\n]*<tenant-guid>' -and (Get-RunText $b1) -notmatch 'STILL TO FILL IN[^\r\n]*<bay-guid>') "...and the screen names exactly the two still to fill in"
    Assert-True ($b2.ended -eq "ran to its last line" -and $null -ne $b2.configText -and [string]$b2.configText -eq $bcfg) "a later run with different values does not rewrite an existing agent-config.json"

    # =========================================================================================== readings that cannot be trusted
    Section "PLAN unreadable and stuck: a value that cannot be read is not 'off', and a lockdown write that does not take is not 'pending'"
    $odd = Invoke-SetupPlan "unreadable" @(
        [ordered]@{ title = "the Remote Desktop value cannot be read"; computerName = "BAY1KIOSK"; args = $Step9Args; model = [ordered]@{ regRemove = @($KeyRdp) } }
    )
    $o1 = Get-PlanRun $odd 0
    Assert-True ($o1.ended -eq "ran to its last line") ("it reaches the last line (" + $o1.ended + " " + $o1.stoppedAt + ")")
    Assert-True ((Get-ChecklistRow $o1 "Remote Desktop off") -match '^FAIL \(could not read') "Remote Desktop value unreadable: the row reads FAIL (could not read), never PASS"
    $stuck = Invoke-SetupPlan "stuck" @(
        [ordered]@{ title = "a lockdown run in which the USB storage write does not take"; computerName = "BAY1KIOSK"; args = $FullArgs; model = [ordered]@{ regStuck = @($KeyUsb) } }
    )
    $k1 = Get-PlanRun $stuck 0
    Assert-True ($k1.ended -eq "ran to its last line" -and (Get-RunReg $k1 $KeyUsb) -eq 3) ("the run finishes with USB storage still allowed (" + $k1.ended + ")")
    Assert-True ((Get-ChecklistRow $k1 "USB storage disabled") -eq "FAIL") "after a lockdown run, a lockdown row that did not take reads FAIL, not PENDING"
    Assert-True ((Get-RunText $k1) -match '(?m)^\d+ PASSED, 1 FAILED, \d+ PENDING\s*$') "...and the summary counts it"

    # =========================================================================================== Remote Desktop asked for
    Section "PLAN rdp: -EnableRemoteDesktop is the only way Remote Desktop comes on"
    $rdpPlanRes = Invoke-SetupPlan "rdp" @(
        [ordered]@{ title = "asked for"; computerName = "BAY1KIOSK"; args = [ordered]@{ BayNumber = 1; BayId = $Bay1; EnableRemoteDesktop = $true } }
    )
    $e1 = Get-PlanRun $rdpPlanRes 0
    Assert-True ($e1.ended -eq "ran to its last line") ("it reaches the last line (" + $e1.ended + " " + $e1.stoppedAt + ")")
    Assert-True ((Get-RunReg $e1 $KeyRdp) -eq 0 -and (Get-LogCount $e1 "^FIREWALL enable group 'Remote Desktop'") -eq 1 -and (Get-LogCount $e1 '^FIREWALL disable') -eq 0) "Remote Desktop on, its firewall group enabled"
    Assert-True (Test-Row $e1 "Remote Desktop enabled (-EnableRemoteDesktop)" "PASS") "the row is named for what was asked and reads PASS"

    # =========================================================================================== a PC that is not as it should be
    Section "PLAN found-wrong: Remote Desktop found ON and a secret file found on a certificate bay"
    $wrong = Invoke-SetupPlan "found-wrong" @(
        [ordered]@{ title = "lockdown skipped on a PC with Remote Desktop on and a secret file"; computerName = "BAY1KIOSK"; args = $Step9Args; model = [ordered]@{ reg = [ordered]@{ $KeyRdp = 0 }; placeSecretFile = $true } },
        [ordered]@{ title = "then the lockdown run"; computerName = "BAY1KIOSK"; args = $Step16Args; model = [ordered]@{ placeAgent = $true } }
    )
    $w1 = Get-PlanRun $wrong 0; $w2 = Get-PlanRun $wrong 1; $wt1 = Get-RunText $w1
    Assert-True ($w1.ended -eq "ran to its last line") ("the first run reaches the last line (" + $w1.ended + " " + $w1.stoppedAt + ")")
    Assert-True (Test-Row $w1 "Remote Desktop off" "FAIL") "Remote Desktop found ON with the lockdown skipped: the row reads FAIL (it is fed the real reading and printed as returned)"
    Assert-True (Test-Row $w1 "No DPAPI secret file (certificate bay)" "FAIL") "a secret file on a certificate bay: the row reads FAIL"
    Assert-True ($wt1 -match 'WARNING: a DPAPI secret file EXISTS') "...and Phase 6 warns about it"
    Assert-True ($wt1 -match 'the enrollment refuses a PC that holds one' -and $wt1 -notmatch 'enroll as PENDING') "...in 1.6.1's terms: the enrollment refuses such a PC (not 'the certificate will enroll as PENDING')"
    Assert-True ($wt1 -match '(?m)^\d+ PASSED, 2 FAILED, \d+ PENDING\s*$') "the summary counts exactly those two failures"
    Assert-True ($w2.ended -eq "ran to its last line" -and (Get-LogCount $w2 'fDenyTSConnections = 1$') -eq 1 -and (Get-RunReg $w2 $KeyRdp) -eq 1 -and (Test-Row $w2 "Remote Desktop off" "PASS")) "the lockdown run turns Remote Desktop OFF and the row then reads PASS"

    # =========================================================================================== a policy that does not take
    Section "PLAN policy: when the machine script policy cannot be set, the run says so and the task rows fail"
    $pol = Invoke-SetupPlan "policy" @(
        [ordered]@{ title = "the policy write does not take"; computerName = "BAY1KIOSK"; args = $Step9Args; model = [ordered]@{ policyTakes = $false } }
    )
    $p1 = Get-PlanRun $pol 0
    Assert-True ($p1.ended -eq "ran to its last line") ("it still reaches the last line (" + $p1.ended + " " + $p1.stoppedAt + ")")
    Assert-True (Test-Row $p1 "Execution policy (AllSigned)" "FAIL") "Execution policy: FAIL (never a text outside the summary's buckets)"
    Assert-True ((Test-Row $p1 "Scheduled task: AOC Bay Agent" "FAIL") -and (Test-Row $p1 "Scheduled task: AOC Host Watchdog" "FAIL")) "both scheduled task rows: FAIL, because a registered task that cannot start is not a pass"
    Assert-True ((Get-RunText $p1) -match '(?m)^\d+ PASSED, 3 FAILED, \d+ PENDING\s*$') "the summary counts those three failures"
    Assert-True ((Get-RunText $p1) -match "The machine script policy reads 'Undefined', not AllSigned" -and (Get-RunText $p1) -notmatch "Machine script policy: AllSigned\.") "and the script-policy step itself says the policy did not take (it goes by the read-back, not by the absence of an error)"
    Assert-True ($t1 -match "Machine script policy: AllSigned\.") "(on the ordinary first run that step says AllSigned)"
    $pol2 = Invoke-SetupPlan "policy-quiet" @(
        [ordered]@{ title = "a host where Set-ExecutionPolicy raises nothing"; computerName = "BAY1KIOSK"; args = $Step9Args; model = [ordered]@{ policyThrows = $false } }
    )
    $p2 = Get-PlanRun $pol2 0
    Assert-True ($p2.ended -eq "ran to its last line" -and $p2.policy -eq "AllSigned" -and (Test-Row $p2 "Execution policy (AllSigned)" "PASS")) "where Set-ExecutionPolicy raises no error the result is the same: AllSigned, PASS"

    # =========================================================================================== the instrument can refuse
    Section "The census refuses a write through a tool nobody modeled (reg.exe)"
    $plantedDir = Join-Path $BaseDir "planted"; New-Item -ItemType Directory -Force -Path $plantedDir | Out-Null
    $plantedSetup = Join-Path $plantedDir "Setup-BayPC.ps1"
    $setupText = [IO.File]::ReadAllText($SetupScript)
    $anchor = '  Write-Host "  $($rdpPlan.message)" -ForegroundColor Green'
    $anchorCount = ([regex]::Matches($setupText, [regex]::Escape($anchor))).Count
    Assert-True ($anchorCount -eq 1) "the place to plant the reg.exe line is found exactly once in the script"
    if ($anchorCount -eq 1) {
        $nl = $(if ($setupText -match "`r`n") { "`r`n" } else { "`n" })
        [IO.File]::WriteAllText($plantedSetup, $setupText.Replace($anchor, ('  reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f | Out-Null' + $nl + $anchor)), (New-Object Text.UTF8Encoding($false)))
        $planted = Invoke-SetupPlan "planted" @([ordered]@{ title = "never runs"; computerName = "BAY1KIOSK"; args = $Step16Args }) $plantedSetup $Day0Script
        Assert-True ([string]$planted.census -match "command 'reg'" -and @($planted.runs).Count -eq 0) ("a script that turns Remote Desktop on through reg.exe is refused before a line of it runs (" + $planted.census + ")")
    } else { Assert-True $false "skipped -- the anchor was not found" }
}
finally {
    try { Remove-Item -LiteralPath $BaseDir -Recurse -Force -ErrorAction SilentlyContinue } catch {}
}

Write-Host ""
Write-Host ("RESULT: {0} passed, {1} failed" -f $script:Pass, $script:Fail) -ForegroundColor $(if ($script:Fail -eq 0) { "Green" } else { "Red" })
if ($script:Fail -gt 0) { $script:Failures | ForEach-Object { Write-Host "  - $_" -ForegroundColor Red }; exit 1 }
exit 0
