<#
BayAgent.KioskPackage.Tests.ps1 (A0.363, BayAgent 1.4.0)

The kiosk mode changes ONLY through a signed, hash-pinned fleet release, so the package build is where a wrong mode
must be stopped. This suite runs the real tools\Build-ReleasePackage.ps1 against sandbox copies of the source tree:
  P1  the shipped tree builds; the zip carries kiosk/ABG.KioskShell.ps1 and kiosk/kiosk-policy.json byte for byte;
      two builds hash the same (reproducible)
  P2  a policy the bay would silently read as "explorer" is refused at build time: mode "shell" (not built), a mode in
      another case, schema 2, minShellBytes too small or larger than the shell, not JSON, an array
  P3  the .json gates: an LF policy and a non-ASCII policy are refused (AG-48 residual R1)
  P4  the shell's version constant must equal -Version
  P5  a builder whose entry list drops the kiosk policy refuses to build
  P6  a companion policy builds (the companion stage is one policy edit and a release away)

RUN (from the repo root): powershell -NoProfile -ExecutionPolicy Bypass -File tests\BayAgent.KioskPackage.Tests.ps1
Exit code 0 = all assertions passed. Hyphens only in comments.
#>
[CmdletBinding()]
param([string]$RepoRoot = "")

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
if ([string]::IsNullOrWhiteSpace($RepoRoot)) { $RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path }

$script:Pass = 0; $script:Fail = 0; $script:Failures = @()
function Assert-True([bool]$cond, [string]$msg) {
    if ($cond) { $script:Pass++; Write-Host "  PASS  $msg" }
    else { $script:Fail++; $script:Failures += $msg; Write-Host "  FAIL  $msg" -ForegroundColor Red }
}
function Section([string]$name) { Write-Host ""; Write-Host "== $name" -ForegroundColor Cyan }

$Sandbox = Join-Path $env:TEMP ("bayagent-kiosk-pkg-" + [guid]::NewGuid().ToString("N").Substring(0, 8))
$ps51 = Join-Path $env:WINDIR "System32\WindowsPowerShell\v1.0\powershell.exe"
$script:N = 0

function New-Tree {
    # A sandbox repo: src\BayAgent copied byte for byte, and the builder.
    $script:N++
    $root = Join-Path $Sandbox ("t{0}" -f $script:N)
    New-Item -ItemType Directory -Force -Path (Join-Path $root "tools") | Out-Null
    Copy-Item -LiteralPath (Join-Path $RepoRoot "src") -Destination (Join-Path $root "src") -Recurse -Force
    Copy-Item -LiteralPath (Join-Path $RepoRoot "tools\Build-ReleasePackage.ps1") -Destination (Join-Path $root "tools\Build-ReleasePackage.ps1") -Force
    return $root
}
function Invoke-Build([string]$root, [string]$version = "1.5.0") {
    $out = Join-Path $root "dist"
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = $ps51
    $psi.Arguments = ('-NoProfile -ExecutionPolicy Bypass -File "{0}" -Version {1} -RepoRoot "{2}" -OutDir "{3}"' -f (Join-Path $root "tools\Build-ReleasePackage.ps1"), $version, $root, $out)
    $psi.UseShellExecute = $false; $psi.RedirectStandardOutput = $true; $psi.RedirectStandardError = $true; $psi.CreateNoWindow = $true
    if ($psi.EnvironmentVariables.ContainsKey("PSModulePath")) { $psi.EnvironmentVariables.Remove("PSModulePath") }
    $p = [System.Diagnostics.Process]::Start($psi)
    $so = $p.StandardOutput.ReadToEndAsync(); $se = $p.StandardError.ReadToEndAsync()
    if (-not $p.WaitForExit(120000)) { try { $p.Kill() } catch { }; return [pscustomobject]@{ Exit = -1; Out = "timeout"; Zip = $null } }
    $zip = Join-Path $out ("BayAgent-{0}.zip" -f $version)
    return [pscustomobject]@{ Exit = $p.ExitCode; Out = ([string]$so.Result + [string]$se.Result); Zip = $(if (Test-Path -LiteralPath $zip) { $zip } else { $null }) }
}
function Set-Bytes([string]$p, [string]$text) { [IO.File]::WriteAllBytes($p, [Text.Encoding]::UTF8.GetBytes($text)) }
function Get-PolicyPath([string]$root) { return (Join-Path $root "src\BayAgent\kiosk\kiosk-policy.json") }
function Get-Sha([string]$p) { $a = [Security.Cryptography.SHA256]::Create(); try { return ([BitConverter]::ToString($a.ComputeHash([IO.File]::ReadAllBytes($p))) -replace "-", "").ToLowerInvariant() } finally { $a.Dispose() } }

Add-Type -AssemblyName System.IO.Compression
Add-Type -AssemblyName System.IO.Compression.FileSystem

try {
    Section "P1 the tree as committed builds, with both kiosk files, reproducibly"
    $t1 = New-Tree
    $b1 = Invoke-Build $t1
    Assert-True ($b1.Exit -eq 0 -and $null -ne $b1.Zip) "exit 0 and a zip (exit $($b1.Exit))"
    if ($null -ne $b1.Zip) {
        $z = [IO.Compression.ZipFile]::OpenRead($b1.Zip)
        try {
            $names = @($z.Entries | ForEach-Object { $_.FullName })
            Assert-True ($names -contains "kiosk/ABG.KioskShell.ps1" -and $names -contains "kiosk/kiosk-policy.json") "the zip carries kiosk/ABG.KioskShell.ps1 and kiosk/kiosk-policy.json"
            Assert-True ($names.Count -eq 10) "ten entries ($($names.Count))"
            foreach ($pair in @(@("kiosk/kiosk-policy.json", "kiosk\kiosk-policy.json"), @("kiosk/ABG.KioskShell.ps1", "kiosk\ABG.KioskShell.ps1"))) {
                $e = $z.GetEntry($pair[0]); $ms = New-Object IO.MemoryStream; $s = $e.Open(); try { $s.CopyTo($ms) } finally { $s.Dispose() }
                $src = [IO.File]::ReadAllBytes((Join-Path $t1 ("src\BayAgent\" + $pair[1])))
                Assert-True ([Convert]::ToBase64String($ms.ToArray()) -eq [Convert]::ToBase64String($src)) ("{0} in the zip is the source byte for byte" -f $pair[0])
            }
            $pe = $z.GetEntry("kiosk/kiosk-policy.json"); $ms2 = New-Object IO.MemoryStream; $s2 = $pe.Open(); try { $s2.CopyTo($ms2) } finally { $s2.Dispose() }
            $pol = [Text.Encoding]::UTF8.GetString($ms2.ToArray()) | ConvertFrom-Json
            Assert-True ($pol.mode -ceq "explorer") "the shipped policy is explorer: 1.5.0 is DORMANT"
        } finally { $z.Dispose() }
        $sha1 = Get-Sha $b1.Zip
        Remove-Item -LiteralPath $b1.Zip -Force
        $b1b = Invoke-Build $t1
        Assert-True ($b1b.Exit -eq 0 -and (Get-Sha $b1b.Zip) -eq $sha1) "a second build of the same tree hashes the same ($sha1)"
    }

    Section "P2 a policy the bay would quietly read as explorer is refused at build time"
    $bad = @(
        @{ T = "{`r`n  `"schema`": 1,`r`n  `"mode`": `"shell`",`r`n  `"minShellBytes`": 4096`r`n}`r`n"; Why = "mode shell (designed, not built)"; Match = "mode must be one of" },
        @{ T = "{`r`n  `"schema`": 1,`r`n  `"mode`": `"Companion`",`r`n  `"minShellBytes`": 4096`r`n}`r`n"; Why = "mode in another case"; Match = "mode must be one of" },
        @{ T = "{`r`n  `"schema`": 1,`r`n  `"mode`": `"kiosk`",`r`n  `"minShellBytes`": 4096`r`n}`r`n"; Why = "an unknown mode"; Match = "mode must be one of" },
        @{ T = "{`r`n  `"schema`": 2,`r`n  `"mode`": `"explorer`",`r`n  `"minShellBytes`": 4096`r`n}`r`n"; Why = "schema 2"; Match = "schema must be the integer 1" },
        @{ T = "{`r`n  `"schema`": `"1`",`r`n  `"mode`": `"explorer`",`r`n  `"minShellBytes`": 4096`r`n}`r`n"; Why = "schema as text"; Match = "schema must be the integer 1" },
        @{ T = "{`r`n  `"schema`": 1,`r`n  `"mode`": `"explorer`",`r`n  `"minShellBytes`": 10`r`n}`r`n"; Why = "minShellBytes 10"; Match = "minShellBytes must be" },
        @{ T = "{`r`n  `"schema`": 1,`r`n  `"mode`": `"explorer`",`r`n  `"minShellBytes`": 900000`r`n}`r`n"; Why = "minShellBytes larger than the shell"; Match = "larger than the shell" },
        @{ T = "{`r`n  `"schema`": 1,`r`n  `"mode`": `"explorer`"`r`n}`r`n"; Why = "minShellBytes missing"; Match = "minShellBytes must be" },
        @{ T = "{ not json`r`n"; Why = "not JSON"; Match = "not valid JSON" },
        @{ T = "[`r`n  {`"schema`": 1, `"mode`": `"explorer`", `"minShellBytes`": 4096}`r`n]`r`n"; Why = "an array"; Match = "must be a JSON object" }
    )
    foreach ($c in $bad) {
        $t = New-Tree
        Set-Bytes (Get-PolicyPath $t) $c.T
        $b = Invoke-Build $t
        Assert-True ($b.Exit -ne 0 -and $null -eq $b.Zip -and $b.Out -match [regex]::Escape($c.Match)) ("{0}: refused, no zip ('{1}')" -f $c.Why, $c.Match)
    }

    Section "P3 the CRLF and ASCII gates cover .json"
    $t = New-Tree
    Set-Bytes (Get-PolicyPath $t) "{`n  `"schema`": 1,`n  `"mode`": `"explorer`",`n  `"minShellBytes`": 4096`n}`n"
    $b = Invoke-Build $t
    Assert-True ($b.Exit -ne 0 -and $b.Out -match "kiosk/kiosk-policy.json is not CRLF") "an LF policy is refused"
    $t = New-Tree
    Set-Bytes (Get-PolicyPath $t) ("{`r`n  `"schema`": 1,`r`n  `"mode`": `"explorer`",`r`n  `"minShellBytes`": 4096,`r`n  `"comment`": `"caf" + [char]0x00E9 + "`"`r`n}`r`n")
    $b = Invoke-Build $t
    Assert-True ($b.Exit -ne 0 -and $b.Out -match "kiosk/kiosk-policy.json carries") "a non-ASCII policy is refused"
    $t = New-Tree
    $cfgP = Join-Path $t "src\BayAgent\agent-config.json"
    Set-Bytes $cfgP (([IO.File]::ReadAllText($cfgP)) -replace "`r`n", "`n")
    $b = Invoke-Build $t
    Assert-True ($b.Exit -ne 0 -and $b.Out -match "agent-config.json is not CRLF") "an LF agent-config.json template is refused too"

    Section "P4 the shell's version constant must match"
    $t = New-Tree
    $sp = Join-Path $t "src\BayAgent\kiosk\ABG.KioskShell.ps1"
    [IO.File]::WriteAllText($sp, ([IO.File]::ReadAllText($sp).Replace('$KioskShellCodeVersion = "1.5.0"', '$KioskShellCodeVersion = "1.3.9"')), (New-Object Text.UTF8Encoding($false)))
    $b = Invoke-Build $t
    Assert-True ($b.Exit -ne 0 -and $b.Out -match "KioskShellCodeVersion = '1.3.9'") "a shell saying 1.3.9 in a 1.5.0 package is refused"

    Section "P5 a builder that drops the kiosk policy from its entries refuses to build"
    $t = New-Tree
    $bp = Join-Path $t "tools\Build-ReleasePackage.ps1"
    $btext = [IO.File]::ReadAllText($bp)
    $line = '    @{ Zip = "kiosk/kiosk-policy.json";         Src = "kiosk\kiosk-policy.json" }'
    Assert-True ($btext.Contains($line)) "precondition: the builder has the policy entry line"
    $btext = $btext.Replace(",`r`n" + $line, "").Replace(",`n" + $line, "")
    [IO.File]::WriteAllText($bp, $btext, (New-Object Text.UTF8Encoding($false)))
    $b = Invoke-Build $t
    Assert-True ($b.Exit -ne 0 -and $b.Out -match "must ship kiosk/kiosk-policy.json") "refused: the package must ship the policy"

    function Set-ReleaseModeConstants([string]$root, [string]$mode) {
        $ap = Join-Path $root "src\BayAgent\BayAgent.ps1"; $sp2 = Join-Path $root "src\BayAgent\kiosk\ABG.KioskShell.ps1"
        $at = [IO.File]::ReadAllText($ap); $st2 = [IO.File]::ReadAllText($sp2)
        if (-not $at.Contains('$KioskReleaseMode           = "explorer"') -or -not $st2.Contains('$KioskShellReleaseMode = "explorer"')) { throw "release-mode constants not found as shipped" }
        [IO.File]::WriteAllText($ap, $at.Replace('$KioskReleaseMode           = "explorer"', ('$KioskReleaseMode           = "{0}"' -f $mode)), (New-Object Text.UTF8Encoding($true)))
        [IO.File]::WriteAllText($sp2, $st2.Replace('$KioskShellReleaseMode = "explorer"', ('$KioskShellReleaseMode = "{0}"' -f $mode)), (New-Object Text.UTF8Encoding($false)))
    }
    $companionPolicy = "{`r`n  `"schema`": 1,`r`n  `"mode`": `"companion`",`r`n  `"minShellBytes`": 4096`r`n}`r`n"

    Section "P6 the companion release builds: the policy AND both signed constants say companion"
    $t = New-Tree
    Set-Bytes (Get-PolicyPath $t) $companionPolicy
    Set-ReleaseModeConstants $t "companion"
    $b = Invoke-Build $t
    Assert-True ($b.Exit -eq 0 -and $null -ne $b.Zip -and $b.Out -match "mode = companion" -and $b.Out -match "the signed code carries the same kiosk mode \(companion\)") "builds, and says companion"

    Section "P7 security review 2026-10-08: the policy file and the signed code must agree, or no package"
    $t = New-Tree
    Set-Bytes (Get-PolicyPath $t) $companionPolicy
    $b = Invoke-Build $t
    Assert-True ($b.Exit -ne 0 -and $null -eq $b.Zip -and $b.Out -match "the kiosk mode disagrees") "a companion policy over code built explorer: refused"
    $t = New-Tree
    Set-ReleaseModeConstants $t "companion"
    $b = Invoke-Build $t
    Assert-True ($b.Exit -ne 0 -and $null -eq $b.Zip -and $b.Out -match "the kiosk mode disagrees") "code built companion under an explorer policy: refused"
    $t = New-Tree
    $sp3 = Join-Path $t "src\BayAgent\kiosk\ABG.KioskShell.ps1"
    [IO.File]::WriteAllText($sp3, ([IO.File]::ReadAllText($sp3).Replace('$KioskShellReleaseMode = "explorer"', '$KioskShellReleaseMode = "companion"')), (New-Object Text.UTF8Encoding($false)))
    $b = Invoke-Build $t
    Assert-True ($b.Exit -ne 0 -and $b.Out -match "the kiosk mode disagrees") "the shell's constant alone disagreeing: refused"
}
finally {
    try { Remove-Item -LiteralPath $Sandbox -Recurse -Force -ErrorAction SilentlyContinue } catch { }
}

Write-Host ""
Write-Host ("RESULT: {0} passed, {1} failed" -f $script:Pass, $script:Fail) -ForegroundColor $(if ($script:Fail -eq 0) { "Green" } else { "Red" })
if ($script:Fail -gt 0) { $script:Failures | ForEach-Object { Write-Host "  - $_" -ForegroundColor Red }; exit 1 }
exit 0
