<#
BayAgent.InstallRoot.Tests.ps1

WHAT THIS PROVES (the rename's FLEET-A slice, A0.634 / A0.635 / A0.636)
  The bay program no longer carries its install folder as a constant. Every script that needs the root takes it from
  where it is installed (Get-BayInstallRoot), so the same files run at C:\AceOfClubs\BayAgent (the new root) and at
  C:\AllBirdies\BayAgent (a bay that has not moved yet). The suite is run under BOTH root names, inside this file.

  R1  Get-BayInstallRoot answers for every layout a script is installed in, under both roots (a real junction too).
  R2  The function is the same text in every script that carries it, and no shipped script keeps a root constant.
  R3  The bay's own command check (Test-ScriptPathUnderRoot) accepts a script under its own root and refuses the
      alternate data stream, doubled separators, dot segments, trailing dots and spaces, variable and wildcard
      characters, non-ASCII, and the OTHER root - the same rules as the plugin's IsUnderAgentBaseDir.
  R4  The same check inside Start-GenericProcess (lifted by AST, Start-Process replaced by a recorder): every -File must
      pass, and the short forms of -File ("-fi evil.ps1 -File ok.ps1") are refused.
  R5  A fresh setup lands at the new root by default and names the new repository outright; the 15 codes carry AOC_;
      the seven files, the Day 0 script and the scheduled tasks carry their new names.

RUN (from the repo root, Windows PowerShell 5.1, the host a bay runs):
  powershell -NoProfile -ExecutionPolicy Bypass -File tests\BayAgent.InstallRoot.Tests.ps1

Exit code 0 = all assertions passed. Hyphens only in comments (em-dashes break AllSigned parsing). ASCII only.
#>
[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$script:Pass = 0; $script:Fail = 0; $script:Failures = @()
function Assert-True([bool]$cond, [string]$msg) {
    if ($cond) { $script:Pass++; Write-Host "  PASS  $msg" }
    else { $script:Fail++; $script:Failures += $msg; Write-Host "  FAIL  $msg" -ForegroundColor Red }
}
function Section([string]$name) { Write-Host ""; Write-Host "== $name" -ForegroundColor Cyan }

function Get-FunctionText([string]$File, [string]$Name) {
    $tk = $null; $er = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseFile($File, [ref]$tk, [ref]$er)
    $defs = @($ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $true) | Where-Object { $_.Name -eq $Name })
    if ($defs.Count -ne 1) { return $null }
    return $defs[0].Extent.Text
}

$AgentScript = Join-Path $RepoRoot "src\BayAgent\BayAgent.ps1"
$rootFn = Get-FunctionText $AgentScript "Get-BayInstallRoot"
$checkFn = Get-FunctionText $AgentScript "Test-ScriptPathUnderRoot"
$startFn = Get-FunctionText $AgentScript "Start-GenericProcess"
$propFn = Get-FunctionText $AgentScript "Get-PropValue"
if ($null -eq $rootFn -or $null -eq $checkFn -or $null -eq $startFn -or $null -eq $propFn) { throw "a function this suite lifts is missing from BayAgent.ps1" }
. ([scriptblock]::Create($rootFn))
. ([scriptblock]::Create($checkFn))

$Sandbox = Join-Path $env:TEMP ("aoc-installroot-" + [guid]::NewGuid().ToString("N").Substring(0, 8))
New-Item -ItemType Directory -Force -Path $Sandbox | Out-Null
$RootNames = @("AceOfClubs", "AllBirdies")

try {
    # ================================================================== R1
    Section "R1 Get-BayInstallRoot answers for every layout, under both roots"
    foreach ($rn in $RootNames) {
        $root = "C:\$rn\BayAgent"
        $cases = @(
            @("current", "$root\current"), @("releases", "$root\releases\1.6.1"), @("directly in the root", $root),
            @("tools", "$root\tools"), @("bootstrap", "$root\bootstrap"), @("current\tools", "$root\current\tools"),
            @("releases\v\tools", "$root\releases\1.6.1\tools"), @("rollback\tools", "$root\rollback\tools"),
            @("releases\v\kiosk", "$root\releases\1.6.1\kiosk"), @("current\kiosk", "$root\current\kiosk"),
            @("a trailing backslash", "$root\current\"), @("lower case", $root.ToLowerInvariant() + "\CURRENT")
        )
        foreach ($c in $cases) {
            $got = Get-BayInstallRoot $c[1]
            Assert-True ($got -ieq $root) "[$rn] script in $($c[0]) ($($c[1])) -> $root (got $got)"
        }
    }
    $threw = $false; try { [void](Get-BayInstallRoot "") } catch { $threw = $true }
    Assert-True $threw "an empty script folder is refused, never guessed"
    $threw = $false; try { [void](Get-BayInstallRoot $null) } catch { $threw = $true }
    Assert-True $threw "a null script folder is refused, never guessed"

    # a real junction, run by the host a bay runs (Windows PowerShell 5.1), launched the way AgentHost launches the agent
    foreach ($rn in $RootNames) {
        $base = Join-Path $Sandbox ("junction-" + $rn + "\" + $rn + "\BayAgent")
        $rel = Join-Path $base "releases\1.6.1"
        New-Item -ItemType Directory -Force -Path $rel | Out-Null
        $probeText = $rootFn + "`r`nWrite-Output ('ROOT=' + (Get-BayInstallRoot `$PSScriptRoot))`r`n"
        [IO.File]::WriteAllText((Join-Path $rel "probe.ps1"), $probeText, (New-Object Text.UTF8Encoding($false)))
        $link = Join-Path $base "current"
        & cmd.exe /c mklink /J "$link" "$rel" | Out-Null
        Assert-True ((Get-Item -LiteralPath $link -Force).LinkType -eq "Junction") "[$rn] current is a real junction to releases\1.6.1"
        foreach ($launchPath in @((Join-Path $link "probe.ps1"), (Join-Path $rel "probe.ps1"))) {
            $outFile = Join-Path $Sandbox ("probe-" + [guid]::NewGuid().ToString("N").Substring(0, 6) + ".txt")
            $p = Start-Process -FilePath "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" -ArgumentList @("-NoProfile", "-ExecutionPolicy", "Bypass", "-File", ('"{0}"' -f $launchPath)) -RedirectStandardOutput $outFile -PassThru -WindowStyle Hidden
            if (-not $p.WaitForExit(60000)) { try { Stop-Process -Id $p.Id -Force } catch {} }
            $txt = ""; if (Test-Path -LiteralPath $outFile) { $txt = ([IO.File]::ReadAllText($outFile)).Trim() }
            Assert-True ($txt -ieq ("ROOT=" + $base)) "[$rn] launched as $($launchPath.Substring($Sandbox.Length)) in a real powershell.exe -> the root is the install, not the release folder (got '$txt')"
        }
        [System.IO.Directory]::Delete($link, $false)   # the link only, never its target
    }

    # ================================================================== R2
    Section "R2 one function everywhere, and no shipped script keeps a root constant"
    $carriers = @(
        "src\BayAgent\BayAgent.ps1", "src\BayAgent\RestartBayAgent.ps1", "src\BayAgent\kiosk\AOC.KioskShell.ps1",
        "src\BayAgent\bootstrap\AOC.AgentHost.ps1", "src\BayAgent\bootstrap\AOC.HostWatchdog.ps1", "src\BayAgent\bootstrap\AOC.LauncherShell.ps1",
        "src\BayAgent\bootstrap\AOC.ReleaseFinalize.ps1", "src\BayAgent\tools\Update-BayAgent.ps1", "src\BayAgent\tools\Update-SessionDisplay.ps1",
        "src\BayAgent\tools\Update-PromosPack.ps1", "src\BayAgent\tools\Watch-BayAgentUpdate.ps1"
    )
    $same = 0
    foreach ($c in $carriers) {
        $t = Get-FunctionText (Join-Path $RepoRoot $c) "Get-BayInstallRoot"
        $ok = ($null -ne $t -and (($t -replace "`r`n", "`n") -ceq ($rootFn -replace "`r`n", "`n")))
        if ($ok) { $same++ }
        Assert-True $ok "$c carries Get-BayInstallRoot, identical to BayAgent.ps1's"
    }
    Assert-True ($same -eq $carriers.Count) "all $($carriers.Count) carriers hold the same function text"

    # What the CODE can act on: every string literal in the AST (comments and help text are not code and are not read).
    $constants = @()
    foreach ($f in @(Get-ChildItem -LiteralPath (Join-Path $RepoRoot "src\BayAgent") -Recurse -Filter *.ps1)) {
        if ($f.Name -eq "Setup-BayPC.ps1") { continue }   # the setup's default root is the one place a root is named
        if ($f.Name -eq "Move-BayInstall.ps1") { continue }   # the move tool names BOTH roots by design and is not in the package (the build has a fixed entry list)
        $tk = $null; $er = $null
        $fa = [System.Management.Automation.Language.Parser]::ParseFile($f.FullName, [ref]$tk, [ref]$er)
        foreach ($s in @($fa.FindAll({ param($x) ($x -is [System.Management.Automation.Language.StringConstantExpressionAst]) -or ($x -is [System.Management.Automation.Language.ExpandableStringExpressionAst]) }, $true))) {
            if ([string]$s.Value -match '(?i)AllBirdies|(?<![A-Za-z.])AceOfClubs(?![A-Za-z.])') { $constants += ("{0}:{1}" -f $f.Name, $s.Extent.StartLineNumber) }
        }
    }
    Assert-True ($constants.Count -eq 0) ("no shipped script (other than the setup's default root) holds a root name in a string of its code: " + $(if ($constants.Count) { $constants -join ", " } else { "none" }))

    $setupText = [IO.File]::ReadAllText((Join-Path $RepoRoot "src\BayAgent\tools\Setup-BayPC.ps1"))
    $day0Text = [IO.File]::ReadAllText((Join-Path $RepoRoot "tools\AOC-Day0-Setup.ps1"))
    foreach ($pair in @(@("Setup-BayPC.ps1", $setupText), @("AOC-Day0-Setup.ps1", $day0Text))) {
        $m = [regex]::Matches($pair[1], '(?m)^\s*(\[Alias\("AllBirdiesRoot"\)\])?\[string\]\$AceOfClubsRoot = "([^"]*)"')
        Assert-True ($m.Count -eq 1 -and $m[0].Groups[2].Value -eq 'C:\AceOfClubs') "$($pair[0]): a fresh setup lands at C:\AceOfClubs by default"
        Assert-True ($m.Count -eq 1 -and $m[0].Groups[1].Success) "$($pair[0]): the old parameter name -AllBirdiesRoot still binds (alias)"
    }

    # ================================================================== R3
    Section "R3 the bay's own command check, under both roots"
    $ae = [char]0x00E9; $longS = [char]0x017F; $dotless = [char]0x0131; $fullA = [char]0xFF21
    foreach ($rn in $RootNames) {
        $root = "C:\$rn\BayAgent"
        $other = $(if ($rn -eq "AceOfClubs") { "C:\AllBirdies\BayAgent" } else { "C:\AceOfClubs\BayAgent" })
        $accept = @(
            "$root\tools\Update-BayAgent.ps1", "$root\current\BayAgent.ps1", "$root\bootstrap\AOC.AgentHost.ps1",
            "$root\rollback\tools\Watch-BayAgentUpdate.ps1", "$root\releases\1.6.1\tools\Update-SessionDisplay.ps1",
            ($root.ToUpperInvariant() + "\TOOLS\UPDATE-BAYAGENT.PS1"), "$root\tools\a-b_c.d.ps1"
        )
        foreach ($p in $accept) { Assert-True (Test-ScriptPathUnderRoot $p $root) "[$rn] accepts $p" }
        Assert-True (Test-ScriptPathUnderRoot ($root + "\tools\Update-BayAgent.ps1") ($root + "\")) "[$rn] a root given with a trailing backslash is the same root"

        $refuse = [ordered]@{
            "alternate data stream"                = "$root\tools\a.txt:evil.ps1"
            "alternate data stream on a script"    = "$root\tools\Update-BayAgent.ps1:evil.ps1"
            "doubled separator after the root"     = "$root\\tools\x.ps1"
            "doubled separator inside"             = "$root\tools\\x.ps1"
            "dot segment"                          = "$root\.\tools\x.ps1"
            "dot-dot segment"                      = "$root\tools\..\x.ps1"
            "traversal out of the root"            = "$root\..\Windows\x.ps1"
            "traversal back in"                    = "$root\..\BayAgent\tools\x.ps1"
            "folder ending in a dot"               = "$root\tools.\x.ps1"
            "folder ending in a space"             = "$root\tools \x.ps1"
            "file name ending in a dot"            = "$root\tools\x.ps1."
            "file name ending in a space"          = "$root\tools\x.ps1 "
            "an environment variable (percent)"    = "$root\tools\%TEMP%.ps1"
            "a variable (dollar)"                  = "$root\tools\`$env.ps1"
            "a variable with braces"               = "$root\tools\`${x}.ps1"
            "a wildcard star"                      = "$root\tools\*.ps1"
            "a wildcard question mark"             = "$root\tools\?.ps1"
            "an 8.3 short name"                    = "$root\tools\UPDATE~1.ps1"
            "a forward slash after the root"       = "$root/tools/x.ps1"
            "forward slashes everywhere"           = ($root.Replace('\', '/') + "/tools/x.ps1")
            "a forward slash inside a later segment" = "$root\tools/x.ps1"
            "a forward slash inside the file part" = "$root\tools\a/b.ps1"
            "non-ASCII (e acute)"                  = "$root\tools\x$ae.ps1"
            "non-ASCII (long s in the root)"       = ("C:\" + $rn.Replace("s", [string]$longS) + "\BayAgent\tools\x.ps1")
            "non-ASCII (dotless i in the file)"    = ("$root\tools\" + "Admin".Replace("i", [string]$dotless) + ".ps1")
            "non-ASCII (full-width A)"             = "$root\tools\$fullA.ps1"
            "a tab"                                = "$root\tools\x`t.ps1"
            "a NUL"                                = "$root\tools\x$([char]0).ps1"
            "a space inside the name"              = "$root\tools\my script.ps1"
            "a backtick"                           = "$root\tools\x``y.ps1"
            "a caret"                              = "$root\tools\x^y.ps1"
            "an ampersand"                         = "$root\tools\x&y.ps1"
            "a pipe"                               = "$root\tools\x|y.ps1"
            "a quote"                              = "$root\tools\x`"y.ps1"
            "a redirect"                           = "$root\tools\x>y.ps1"
            "two dots inside a name (a..b)"        = "$root\tools\a..b.ps1"
            "the root alone"                       = $root
            "the root and a backslash"             = "$root\"
            "not a .ps1"                           = "$root\tools\x.exe"
            "a .ps1 that is a folder name"         = "$root\x.ps1\y.txt"
            "a look-alike (BayAgentX)"             = ($root + "X\tools\x.ps1")
            "a look-alike root folder"             = ("C:\" + $rn + "X\BayAgent\tools\x.ps1")
            "a look-alike (BayAgent.evil)"         = ($root + ".evil\x.ps1")
            "the other root"                       = "$other\tools\x.ps1"
            "a third root"                         = "C:\Temp\BayAgent\tools\x.ps1"
            "a UNC path"                           = "\\server\share\BayAgent\tools\x.ps1"
            "a device path"                        = ("\\?\" + $root + "\tools\x.ps1")
            "a drive-relative path"                = "C:$rn\BayAgent\tools\x.ps1"
            "a relative path"                      = "tools\x.ps1"
            "a bare script name"                   = "x.ps1"
            "an empty string"                      = ""
        }
        foreach ($k in $refuse.Keys) { Assert-True (-not (Test-ScriptPathUnderRoot $refuse[$k] $root)) "[$rn] refuses $k" }
        Assert-True (-not (Test-ScriptPathUnderRoot $null $root)) "[$rn] refuses null"
        Assert-True (-not (Test-ScriptPathUnderRoot "$root\tools\x.ps1" "")) "[$rn] refuses everything when it has no root to compare with"
    }

    # ================================================================== R4
    Section "R4 Start-GenericProcess: every -File is checked, the short forms are refused (lifted by AST, Start-Process recorded)"
    . ([scriptblock]::Create($propFn))
    foreach ($cn in @("Test-BayCmdPlaceholder", "Test-BayCmdIn", "ConvertFrom-BayCmdPayload", "Split-BayCmdArgs", "Test-BayCmdVersionToken", "Test-BayCmdSegment", "Test-BayCmdDataverseUrl", "Assert-BayCmdPackageUrl", "Assert-BayCmdVersion", "Assert-BayCmdSha256", "Get-BayCmdLaunch")) {
        $ct = Get-FunctionText $AgentScript $cn
        if ($null -eq $ct) { throw "the command-check function $cn is missing from BayAgent.ps1" }
        . ([scriptblock]::Create($ct))
    }
    . ([scriptblock]::Create($startFn))
    $script:Launched = @()
    function Write-Log { param([string]$Message, [string]$Level = "INFO") }
    function Get-AccessToken { return "" }
    function Start-Process { param($FilePath, $ArgumentList, [switch]$PassThru) $script:Launched += [pscustomobject]@{ File = $FilePath; Args = $ArgumentList }; return [pscustomobject]@{ Id = 4242 } }
    $ps = "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe"
    function Invoke-Launch([string]$argLine) {
        $script:Launched = @()
        $err = $null
        # K1: the agent takes the raw payload text (the plugin's {path, args}), so the line is wrapped as JSON here
        $json = '{"path":"' + $ps.Replace('\', '\\') + '","args":"' + $argLine.Replace('\', '\\').Replace('"', '\"').Replace("`t", '\t') + '"}'
        try { [void](Start-GenericProcess $json) } catch { $err = $_.Exception.Message }
        return [pscustomobject]@{ Error = $err; Launched = @($script:Launched).Count }
    }
    foreach ($rn in $RootNames) {
        $root = "C:\$rn\BayAgent"
        $BaseDir = $root
        $ok = "$root\tools\Update-BayAgent.ps1"
        $r = Invoke-Launch ('-NoProfile -File "{0}" -Version 1.6.2' -f $ok)
        Assert-True ($null -eq $r.Error -and $r.Launched -eq 1) "[$rn] a quoted script under its own root launches"
        $r = Invoke-Launch ('-NoProfile -File {0} -RequestRestart' -f $ok)
        Assert-True ($null -eq $r.Error -and $r.Launched -eq 1) "[$rn] an unquoted script under its own root launches"

        $bad = [ordered]@{
            "an alternate data stream"                 = ('-NoProfile -File "{0}:evil.ps1"' -f "$root\tools\a.txt")
            "a doubled separator"                      = ('-NoProfile -File {0}' -f "$root\\tools\x.ps1")
            "a dot segment"                            = ('-NoProfile -File {0}' -f "$root\.\tools\x.ps1")
            "a traversal"                              = ('-NoProfile -File {0}' -f "$root\tools\..\..\x.ps1")
            "a look-alike root"                        = ('-NoProfile -File {0}' -f ($root + "X\x.ps1"))
            "the other root"                           = ('-NoProfile -File {0}' -f ($(if ($rn -eq "AceOfClubs") { "C:\AllBirdies\BayAgent" } else { "C:\AceOfClubs\BayAgent" }) + "\tools\x.ps1"))
            "a variable"                               = '-NoProfile -File $env:TEMP\x.ps1'
            "a wildcard"                               = ('-NoProfile -File {0}' -f "$root\tools\*.ps1")
            "a trailing dot folder"                    = ('-NoProfile -File {0}' -f "$root\tools.\x.ps1")
            "a second -File that leaves the root"      = ('-NoProfile -File "{0}" -File C:\Temp\evil.ps1' -f $ok)
            "the first -File leaving the root"         = ('-NoProfile -File C:\Temp\evil.ps1 -File "{0}"' -f $ok)
            "-fi in front of a good -File"             = ('-NoProfile -fi C:\Temp\evil.ps1 -File "{0}"' -f $ok)
            "-f in front of a good -File"              = ('-NoProfile -f C:\Temp\evil.ps1 -File "{0}"' -f $ok)
            "-fil in front of a good -File"            = ('-NoProfile -fil C:\Temp\evil.ps1 -File "{0}"' -f $ok)
            "-File: glued with a colon"                = ('-NoProfile -File:"{0}"' -f $ok)
            "-File: (glued) in front of a good -File"  = ('-NoProfile -File:C:\Temp\evil.ps1 -File "{0}"' -f $ok)
            "-Command"                                 = ('-NoProfile -Command "& ''{0}''"' -f $ok)
            "-c"                                       = ('-NoProfile -c "x"')
            "no -File at all"                          = '-NoProfile'
        }
        foreach ($k in $bad.Keys) {
            $r = Invoke-Launch $bad[$k]
            Assert-True ($null -ne $r.Error -and $r.Launched -eq 0) "[$rn] refuses $k, and starts nothing"
        }
    }
    Assert-True (@($script:Launched).Count -eq 0) "(after the last refusal) nothing was launched by a refused line"

    # ================================================================== R5
    Section "R5 the setup addresses, the codes, the files and the tasks carry the new names"
    function Get-CodeStrings([string]$File) {
        $tk = $null; $er = $null
        $fa = [System.Management.Automation.Language.Parser]::ParseFile($File, [ref]$tk, [ref]$er)
        return @($fa.FindAll({ param($x) ($x -is [System.Management.Automation.Language.StringConstantExpressionAst]) -or ($x -is [System.Management.Automation.Language.ExpandableStringExpressionAst]) }, $true) | ForEach-Object { [string]$_.Value })
    }
    # Move-BayInstall.ps1 is exempt: it names both roots and the old file and task names on purpose, and it is not in the package.
    $shipped = @(Get-ChildItem -LiteralPath (Join-Path $RepoRoot "src\BayAgent") -Recurse -Filter *.ps1 | Where-Object { $_.Name -ne "Move-BayInstall.ps1" }) + @(Get-ChildItem -LiteralPath (Join-Path $RepoRoot "tools") -Filter *.ps1)
    $allStrings = @(); foreach ($f in $shipped) { $allStrings += @(Get-CodeStrings $f.FullName | ForEach-Object { "{0}|{1}" -f $f.Name, $_ }) }

    $setupAst = [System.Management.Automation.Language.Parser]::ParseFile((Join-Path $RepoRoot "src\BayAgent\tools\Setup-BayPC.ps1"), [ref]$null, [ref]$null)
    $dv = @{}
    foreach ($pa in $setupAst.ParamBlock.Parameters) { if ($pa.DefaultValue) { $dv[$pa.Name.VariablePath.UserPath] = [string]$pa.DefaultValue.Value } }
    Assert-True ($dv["FleetRawBaseUrl"] -ceq "https://raw.githubusercontent.com/millwright-works/aoc-fleet-updates/main/src/BayAgent") "the setup's package address names the new repository outright"
    Assert-True ($dv["Day0Url"] -ceq "https://raw.githubusercontent.com/millwright-works/aoc-fleet-updates/main/tools/AOC-Day0-Setup.ps1") "the setup's Day 0 address names the new repository and the new script name outright"
    # The ONE place the old name stays is the bay's own copy of the plugin's fleet-asset list (K1: the plugin accepts both
    # names until the release after the repository has moved; the bay matches it switch for switch).
    $oldRepoAll = @($allStrings | Where-Object { $_ -match '(?i)abg-fleet-updates' })
    $oldRepoListed = @($oldRepoAll | Where-Object { $_ -ceq 'BayAgent.ps1|abg-fleet-updates' })
    $oldRepo = @($oldRepoAll | Where-Object { $_ -cne 'BayAgent.ps1|abg-fleet-updates' })
    Assert-True ($oldRepo.Count -eq 0) ("no string in any shipped script names the old repository, except the fleet-asset list (" + $oldRepo.Count + ")")
    Assert-True ($oldRepoListed.Count -eq 1) ("the old repository name appears exactly once in BayAgent.ps1, as the plugin's second list entry (" + $oldRepoListed.Count + ")")
    $readme = [IO.File]::ReadAllText((Join-Path $RepoRoot "README.md"))
    Assert-True ($readme -match '(?m)^# aoc-fleet-updates\s*$' -and $readme -notmatch '(?i)abg-fleet') "README names the new repository"

    $oldCodes = @($allStrings | Where-Object { $_ -match 'ABG_(OWNID|CRED)_' })
    Assert-True ($oldCodes.Count -eq 0) "none of the bay program's 15 codes keeps the ABG_ prefix (found: $($oldCodes.Count))"
    $newCodes = @{}
    foreach ($s in $allStrings) { foreach ($m in [regex]::Matches($s, 'AOC_(?:OWNID|CRED)_[A-Z_]+')) { $newCodes[$m.Value] = 1 } }
    Assert-True ($newCodes.Count -eq 15) "the bay program carries exactly 15 AOC_OWNID_* / AOC_CRED_* codes in code strings (found $($newCodes.Count))"

    $names = @("AgentHost", "HostWatchdog", "LauncherShell", "ReleaseFinalize", "RotateClientSecretDpapiAndTest", "SetClientSecretDpapi", "KioskShell")
    foreach ($n in $names) {
        $dir = $(if ($n -eq "KioskShell") { "kiosk" } else { "bootstrap" })
        Assert-True ((Test-Path -LiteralPath (Join-Path $RepoRoot "src\BayAgent\$dir\AOC.$n.ps1")) -and -not (Test-Path -LiteralPath (Join-Path $RepoRoot "src\BayAgent\$dir\ABG.$n.ps1"))) "AOC.$n.ps1 exists and ABG.$n.ps1 does not"
    }
    Assert-True ((Test-Path -LiteralPath (Join-Path $RepoRoot "tools\AOC-Day0-Setup.ps1")) -and -not (Test-Path -LiteralPath (Join-Path $RepoRoot "tools\ABG-Day0-Setup.ps1"))) "the Day 0 script is AOC-Day0-Setup.ps1"
    $oldNames = @($allStrings | Where-Object { $_ -match 'ABG[.-](AgentHost|HostWatchdog|LauncherShell|ReleaseFinalize|RotateClientSecretDpapiAndTest|SetClientSecretDpapi|KioskShell|Day0)' })
    Assert-True ($oldNames.Count -eq 0) "no string in any shipped script names an old ABG.* file (found $($oldNames.Count))"
    $oldTasks = @($allStrings | Where-Object { $_ -match 'ABG Bay Agent|ABG Host Watchdog|ABG BayAgent Update Guard' })
    Assert-True ($oldTasks.Count -eq 0) "no string names an old scheduled task (found $($oldTasks.Count))"
    # K3 (2026-10-14): the six embedded signature blocks certified nothing (five were already HashMismatch at the base, the
    # rename made the sixth stale) and every delivery path signs on arrival, so no repository script carries one.
    $signed = @($shipped | Where-Object { [IO.File]::ReadAllText($_.FullName) -match '(?m)^# SIG # Begin signature block' } | ForEach-Object { $_.Name })
    Assert-True ($signed.Count -eq 0) ("no shipped script carries an embedded signature block (found: " + $(if ($signed.Count) { $signed -join ", " } else { "none" }) + ")")
    $guardDefault = [regex]::Match([IO.File]::ReadAllText((Join-Path $RepoRoot "src\BayAgent\tools\Update-BayAgent.ps1")), '\[string\]\$GuardTaskName = "([^"]*)"').Groups[1].Value
    Assert-True ($guardDefault -ceq "AOC BayAgent Update Guard") "the update guard task is named AOC BayAgent Update Guard"
    $tasks = @($allStrings | Where-Object { $_ -match '^Setup-BayPC\.ps1\|AOC Bay Agent$' }) + @($allStrings | Where-Object { $_ -match '^AOC-Day0-Setup\.ps1\|\\AOC (Bay Agent|Host Watchdog)$' })
    Assert-True ($tasks.Count -ge 3) "the setup and Day 0 create/check AOC Bay Agent and AOC Host Watchdog (found $($tasks.Count) strings)"
    $advice = @($allStrings | Where-Object { $_ -match '(?i)set the Fleet\.BayAgent\.PackageUrl ConfigItem' })
    Assert-True ($advice.Count -eq 0) "the updater's Dataverse-URL advice no longer tells the operator to set the retired Fleet.BayAgent.* settings (N63)"
}
finally {
    # the sandbox folder was created by this run, under a unique name; check the name before the recursive delete
    if ($Sandbox -like "*\aoc-installroot-*" -and (Test-Path -LiteralPath $Sandbox)) {
        foreach ($j in @(Get-ChildItem -LiteralPath $Sandbox -Recurse -Force -ErrorAction SilentlyContinue | Where-Object { $_.LinkType })) {
            try { [System.IO.Directory]::Delete($j.FullName, $false) } catch {}
        }
        try { Remove-Item -LiteralPath $Sandbox -Recurse -Force -ErrorAction SilentlyContinue } catch {}
    }
}

Write-Host ""
Write-Host ("RESULT: {0} passed, {1} failed" -f $script:Pass, $script:Fail)
if ($script:Fail -gt 0) { $script:Failures | ForEach-Object { Write-Host "  FAILED: $_" -ForegroundColor Red }; exit 1 }
exit 0
