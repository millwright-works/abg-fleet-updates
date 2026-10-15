<#
Run-KioskAclMutations.ps1

A0.699 / F-SEC mutation run. For each planted change below it copies the repository files to a scratch folder, applies ONE
change, CONFIRMS the file differs from the original (a replace that matched nothing is a fake survivor), runs the two suites
that guard the permissions (BayAgent.KioskAcl.Tests.ps1 and BayAgent.SetupRun.Tests.ps1) in Windows PowerShell 5.1, and
reports KILLED (a suite exited non-zero and printed a FAIL line), SURVIVED, or ERROR (a suite did not finish: neither
killed nor survived). A control run of the unchanged copy must pass first.

The mutants that matter most: restore a BayKiosk grant on the signing key, and leave a SYSTEM-run path writable.

Run (from the repo root; Windows only):
  powershell -NoProfile -ExecutionPolicy Bypass -File attack\Run-KioskAclMutations.ps1 -WorkRoot <scratch folder> [-Only M1,M2]
Hyphens only in comments.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$WorkRoot,
    [string[]]$Only = @()
)
Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$Ps51 = Join-Path $env:WINDIR "System32\WindowsPowerShell\v1.0\powershell.exe"
New-Item -ItemType Directory -Force -Path $WorkRoot | Out-Null
$WorkRoot = (Resolve-Path $WorkRoot).Path

$Files = @("tools\ABG-BayAcl.ps1", "tools\ABG-Day0-Setup.ps1", "src\BayAgent\tools\Setup-BayPC.ps1", "tests\BayAgent.KioskAcl.Tests.ps1", "tests\BayAgent.SetupRun.Tests.ps1", "tests\SetupRun.Harness.ps1")

# Each mutant: Id, What, File, Old, New. NL in a pattern stands for the file's own line ending.
$Mutants = @(
    @{ Id = "M1"; What = "Day0 re-adds the BayKiosk read grant on the key (the old icacls /grant line)"; File = "tools\ABG-Day0-Setup.ps1"
       Old = 'foreach ($lk in $lockedKeys) { Write-Host "  Key file locked to SYSTEM and Administrators: $lk" }'
       New = 'foreach ($lk in $lockedKeys) { Write-Host "  Key file locked to SYSTEM and Administrators: $lk"; icacls "$lk" /grant "${kioskAccount}:(R)" | Out-Null }' },
    @{ Id = "M2"; What = "the key lock also lets Users read the key"; File = "tools\ABG-BayAcl.ps1"
       Old = '    (New-BayRule (Get-BaySidObject $script:BaySid.Admins) $full "None" "None")) -Protect $true'
       New = '    (New-BayRule (Get-BaySidObject $script:BaySid.Admins) $full "None" "None"), (New-BayRule (Get-BaySidObject $script:BaySid.Users) 1179785 "None" "None")) -Protect $true' },
    @{ Id = "M3"; What = "the key lock is not applied at all (a bay keeps whatever grant it had)"; File = "tools\ABG-BayAcl.ps1"
       Old = 'foreach ($kp in @(Get-BayKeyFilePaths (Get-BayKeyContainerName $tp))) { Set-BayKeyFileAcl -KeyPath $kp; $done += $kp }'
       New = 'foreach ($kp in @(Get-BayKeyFilePaths (Get-BayKeyContainerName $tp))) { $done += $kp }' },
    @{ Id = "M4"; What = "Users get Modify (not read and execute) on the locked folders"; File = "tools\ABG-BayAcl.ps1"
       Old = '$rx = [int][System.Security.AccessControl.FileSystemRights]::ReadAndExecute'
       New = '$rx = [int][System.Security.AccessControl.FileSystemRights]::Modify' },
    @{ Id = "M5"; What = "the watchdog folder's children are not reset (an explicit BayKiosk grant on the watchdog stays)"; File = "tools\ABG-BayAcl.ps1"
       Old = '      Reset-BayLockTreeChildren -Path $p'
       New = '      # mutant: children not reset' },
    @{ Id = "M6"; What = "the watchdog folder keeps inheritance from C:\ (not protected)"; File = "tools\ABG-BayAcl.ps1"
       Old = '      Set-BayDacl -Path $p -Rules (Get-BayLockRules) -Protect $true' + "NL" + '      Set-BayLockTreeOwner -Path $p'
       New = '      Set-BayDacl -Path $p -Rules (Get-BayLockRules) -Protect $false' + "NL" + '      Set-BayLockTreeOwner -Path $p' },
    @{ Id = "M7"; What = "Day0 no longer applies the folder rules (a standalone Day0 leaves SYSTEM-run paths writable)"; File = "tools\ABG-Day0-Setup.ps1"
       Old = 'Set-BayAcls -Root $AllBirdiesRoot -KioskSid $kioskSid'
       New = '# mutant: no Set-BayAcls' },
    @{ Id = "M8"; What = "Setup no longer applies the folder rules (a -SkipDay0 run leaves SYSTEM-run paths writable)"; File = "src\BayAgent\tools\Setup-BayPC.ps1"
       Old = 'Set-BayAcls -Root $AllBirdiesRoot -KioskSid $aclKioskSid'
       New = '# mutant: no Set-BayAcls' },
    @{ Id = "M9"; What = "Setup no longer repairs the key (a -SkipDay0 run leaves a BayKiosk grant)"; File = "src\BayAgent\tools\Setup-BayPC.ps1"
       Old = '$aclLockedKeys = @(Set-BayAllKeyFileAcls)'
       New = '$aclLockedKeys = @()' },
    @{ Id = "M10"; What = "the watchdog task is registered with a bare powershell.exe again"; File = "tools\ABG-Day0-Setup.ps1"
       Old = '$tr = "$psExe -NoProfile -File `"$watchdogPath`""'
       New = '$tr = "powershell.exe -NoProfile -File `"$watchdogPath`""' },
    @{ Id = "M11"; What = "the self-check ignores write rights on locked paths"; File = "tools\ABG-BayAcl.ps1"
       Old = '  if (($mask -band $script:BayWriteMask) -ne 0) { $problems += ("{0}: BayKiosk or Users can {1}"'
       New = '  if (($mask -band $script:BayWriteMask) -eq 123456789) { $problems += ("{0}: BayKiosk or Users can {1}"' },
    @{ Id = "M12"; What = "the self-check ignores the rights the kiosk token holds on the key (the mask detector only)"; File = "tools\ABG-BayAcl.ps1"
       Old = '  if (($mask -band $script:BayAnyMask) -ne 0) {'
       New = '  if (($mask -band $script:BayAnyMask) -eq 123456789) {' },
    @{ Id = "M22"; What = "the self-check ignores a grant on the key: BOTH detectors off (M12 and M13 together)"; File = "tools\ABG-BayAcl.ps1"
       Old = '  if (($mask -band $script:BayAnyMask) -ne 0) {'
       New = '  if (($mask -band $script:BayAnyMask) -eq 123456789) {'
       Old2 = '    if (@($script:BaySid.System, $script:BaySid.Admins) -notcontains $r.IdentityReference.Value) {'
       New2 = '    if ($false) {' },
    @{ Id = "M13"; What = "the self-check no longer lists other holders of the key (the second detector only)"; File = "tools\ABG-BayAcl.ps1"
       Old = '    if (@($script:BaySid.System, $script:BaySid.Admins) -notcontains $r.IdentityReference.Value) {'
       New = '    if ($false) {' },
    @{ Id = "M14"; What = "the data folders let BayKiosk delete the folder itself"; File = "tools\ABG-BayAcl.ps1"
       Old = '$R::WriteAttributes -bor $R::DeleteSubdirectoriesAndFiles)'
       New = '$R::WriteAttributes -bor $R::DeleteSubdirectoriesAndFiles -bor $R::Delete)' },
    @{ Id = "M15"; What = "a link inside the watchdog folder is skipped, not refused"; File = "tools\ABG-BayAcl.ps1"
       Old = '$links += $child.FullName; continue }'
       New = 'continue }' },
    @{ Id = "M16"; What = "a SYSTEM task running a script from outside the locked folder is accepted"; File = "tools\ABG-BayAcl.ps1"
       Old = '      if (-not $p.ToLowerInvariant().StartsWith($lockN)) {'
       New = '      if ($false) {' },
    @{ Id = "M17"; What = "a missing watchdog task is accepted (nothing found reads as nothing wrong)"; File = "tools\ABG-BayAcl.ps1"
       Old = '    if ($hit.Count -eq 0) { $problems += ("task ''{0}'' was not found running as SYSTEM" -f $need) }'
       New = '    if ($false) { $problems += ("task ''{0}'' was not found running as SYSTEM" -f $need) }' },
    @{ Id = "M18"; What = "Setup's verification leaves out the permissions rows"; File = "src\BayAgent\tools\Setup-BayPC.ps1"
       Old = 'foreach ($ar in $aclRows) { $checks += [PSCustomObject]@{ Check = $ar.Check; Result = $ar.Result } }'
       New = '# mutant: rows not added' },
    @{ Id = "M19"; What = "Day0 does not stop on a failed permissions self-check"; File = "tools\ABG-Day0-Setup.ps1"
       Old = 'if ($aclFailed.Count -gt 0) {'
       New = 'if ($false) {' },
    @{ Id = "M20"; What = "the installer scripts are again downloaded to and run from the agent's staging folder (BayKiosk-writable)"; File = "src\BayAgent\tools\Setup-BayPC.ps1"
       Old = '$setupDir = Join-Path $AllBirdiesRoot "BayAgent\bootstrap\setup"'
       New = '$setupDir = Join-Path $AllBirdiesRoot "BayAgent\staging"' },
    @{ Id = "M21"; What = "the data folders lose BayKiosk's inherit-only Modify on what it creates"; File = "tools\ABG-BayAcl.ps1"
       Old = '(New-BayRule $KioskSid ([int]$R::Modify) "ContainerInherit, ObjectInherit" "InheritOnly"))'
       New = '(New-BayRule $KioskSid ([int]$R::ReadAndExecute) "ContainerInherit, ObjectInherit" "InheritOnly"))' }
)
$Only = @($Only | ForEach-Object { $_ -split "," } | Where-Object { $_ })
if ($Only.Count -gt 0) { $Mutants = @($Mutants | Where-Object { $Only -contains $_.Id }) }

function Copy-Tree([string]$To) {
    if (Test-Path -LiteralPath $To) { throw "refusing to reuse $To" }
    foreach ($f in $Files) { New-Item -ItemType Directory -Force -Path (Split-Path -Parent (Join-Path $To $f)) | Out-Null; Copy-Item -LiteralPath (Join-Path $RepoRoot $f) -Destination (Join-Path $To $f) }
    # the rest of the files the two suites read: the whole src and tools trees, tests by name
    foreach ($d in @("src", "tools")) { & robocopy.exe (Join-Path $RepoRoot $d) (Join-Path $To $d) /E /XF (Split-Path -Leaf $Files[0]) "ABG-Day0-Setup.ps1" "Setup-BayPC.ps1" /NFL /NDL /NJH /NJS /NP | Out-Null }
}
function Invoke-Suites([string]$Tree, [string]$Tag) {
    $result = [ordered]@{}
    foreach ($s in @("BayAgent.KioskAcl.Tests.ps1", "BayAgent.SetupRun.Tests.ps1")) {
        $log = Join-Path $WorkRoot ("{0}-{1}.log" -f $Tag, $s)
        $p = Start-Process -FilePath $Ps51 -ArgumentList @("-NoProfile", "-ExecutionPolicy", "Bypass", "-File", (Join-Path $Tree ("tests\" + $s))) -WorkingDirectory $Tree -RedirectStandardOutput $log -RedirectStandardError ($log + ".err") -PassThru -Wait -WindowStyle Hidden
        $txt = ""; if (Test-Path -LiteralPath $log) { $txt = [IO.File]::ReadAllText($log) }
        $done = ($txt -match "(?m)^RESULT: \d+ passed, \d+ failed")
        $fails = @([regex]::Matches($txt, "(?m)^\s+FAIL\s+(.+)$") | ForEach-Object { $_.Groups[1].Value.Trim() })
        $result[$s] = [pscustomobject]@{ Exit = $p.ExitCode; Finished = $done; Fails = $fails; Result = $(if ($done) { ([regex]::Match($txt, "(?m)^RESULT: .*$")).Value } else { "NO RESULT LINE" }) }
    }
    return $result
}

$summary = @()
$ctl = Join-Path $WorkRoot "control"
Copy-Tree $ctl
$c = Invoke-Suites $ctl "control"
$ctlOk = (@($c.Values | Where-Object { $_.Exit -ne 0 -or -not $_.Finished }).Count -eq 0)
$summary += ("CONTROL`t{0}`t{1}" -f $(if ($ctlOk) { "PASS" } else { "CONTROL FAILED" }), (($c.Keys | ForEach-Object { $_ + ": " + $c[$_].Result }) -join " | "))
if (-not $ctlOk) { $summary; exit 2 }

foreach ($m in $Mutants) {
    $tree = Join-Path $WorkRoot $m.Id
    Copy-Tree $tree
    $path = Join-Path $tree $m.File
    $raw = [IO.File]::ReadAllText($path)
    $nl = $(if ($raw.Contains("`r`n")) { "`r`n" } else { "`n" })
    $old = $m.Old.Replace("NL", $nl); $new = $m.New.Replace("NL", $nl)
    $hits = ([regex]::Matches($raw, [regex]::Escape($old))).Count
    if ($hits -ne 1) { $summary += ("{0}`tERROR`tthe pattern matched {1} times (needs exactly 1): {2}" -f $m.Id, $hits, $m.What); continue }
    $mut = $raw.Replace($old, $new)
    if ($m.ContainsKey("Old2")) {
        $old2 = $m.Old2.Replace("NL", $nl)
        if (([regex]::Matches($mut, [regex]::Escape($old2))).Count -ne 1) { $summary += ("{0}`tERROR`tthe second pattern did not match exactly once" -f $m.Id); continue }
        $mut = $mut.Replace($old2, $m.New2.Replace("NL", $nl))
    }
    if ($mut -eq $raw) { $summary += ("{0}`tERROR`tthe file is unchanged after the replace: {1}" -f $m.Id, $m.What); continue }
    [IO.File]::WriteAllText($path, $mut, (New-Object Text.UTF8Encoding($false)))
    $r = Invoke-Suites $tree $m.Id
    $unfinished = @($r.Values | Where-Object { -not $_.Finished })
    $failing = @($r.Values | Where-Object { $_.Exit -ne 0 -and $_.Finished -and $_.Fails.Count -gt 0 })
    $verdict = $(if ($failing.Count -gt 0) { "KILLED" } elseif ($unfinished.Count -gt 0) { "ERROR" } else { "SURVIVED" })
    $by = ($r.Keys | Where-Object { $r[$_].Exit -ne 0 } | ForEach-Object { $_.Replace("BayAgent.", "").Replace(".Tests.ps1", "") + " (" + $r[$_].Fails.Count + " FAIL; first: " + ($r[$_].Fails | Select-Object -First 1) + ")" }) -join " | "
    $summary += ("{0}`t{1}`t{2}`t{3}" -f $m.Id, $verdict, $m.What, $by)
    [IO.File]::WriteAllLines((Join-Path $WorkRoot "SUMMARY.txt"), $summary)
}
[IO.File]::WriteAllLines((Join-Path $WorkRoot "SUMMARY.txt"), $summary)
$summary
