<#
BayAgent.CommandCheck.Tests.ps1

WHAT THIS PROVES (K1, 2026-10-14: the bay's own command check is a closed allowlist that is the plugin's)
  Before: the agent kept a BLOCKLIST for StartProcess (-command, -c, a leaf name) that PowerShell walks around. An independent
  attack ran inline code through "-com <code>" and a quoted "-c", and launched "powershell.exe." (trailing dot: the leaf was no
  longer powershell.exe, so no PowerShell rule ran). A row that reached the bay without passing the plugin ran.
  Now Start-GenericProcess takes the RAW payload text and asks the question GuardBayCommandPlugin asks: the payload is an
  object of exactly path and args (no repeated member, no other member), without a {placeholder}, at most 8192 characters;
  the program is EXACTLY powershell.exe or shutdown.exe (full path, case aside); PowerShell takes only the closed switch
  list with checked values and at least one -File under THIS root; shutdown takes /r /s /f /t <digits>.

  C1  what is accepted, and exactly what is launched (the program the list names, the line rebuilt from the checked tokens)
  C2  every probe the attack named, and every other way to a refusal, under both roots: refused, nothing launched
  C3  the call site passes the raw payload text, once

  The expected answers are the plugin's: tools Differential-K1.ps1 (in the hand-over evidence) runs the plugin's method text,
  read from git, against this code over 123,160 inputs and finds 0 differences. This suite pins the cases that matter in the
  repository, where the plugin is not available.

RUN (from the repo root, Windows PowerShell 5.1, the host a bay runs):
  powershell -NoProfile -ExecutionPolicy Bypass -File tests\BayAgent.CommandCheck.Tests.ps1

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

$AgentScript = Join-Path $RepoRoot "src\BayAgent\BayAgent.ps1"
$tk = $null; $er = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile($AgentScript, [ref]$tk, [ref]$er)
if ($er.Count -gt 0) { throw "BayAgent.ps1 has parse errors" }
$defs = @($ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $true))
foreach ($name in @("Test-ScriptPathUnderRoot", "Test-BayCmdPlaceholder", "Test-BayCmdIn", "ConvertFrom-BayCmdPayload", "Split-BayCmdArgs", "Test-BayCmdVersionToken", "Test-BayCmdSegment",
        "Test-BayCmdDataverseUrl", "Assert-BayCmdPackageUrl", "Assert-BayCmdVersion", "Assert-BayCmdSha256", "Get-BayCmdLaunch", "Start-GenericProcess")) {
    $d = @($defs | Where-Object { $_.Name -eq $name })
    if ($d.Count -ne 1) { throw "function $name found $($d.Count) times in BayAgent.ps1" }
    . ([scriptblock]::Create($d[0].Extent.Text))
}

# stand-ins: nothing real starts, no token is written
$script:Launched = @()
function Write-Log { param([string]$Message, [string]$Level = "INFO") }
function Get-AccessToken { return "" }
function Start-Process { param($FilePath, $ArgumentList, [switch]$PassThru) $script:Launched += [pscustomobject]@{ File = $FilePath; Args = $ArgumentList }; return [pscustomobject]@{ Id = 4242 } }

function J([string]$s) {
    $sb = New-Object System.Text.StringBuilder
    foreach ($ch in $s.ToCharArray()) {
        $c = [int]$ch
        if ($c -eq 34) { [void]$sb.Append('\"') } elseif ($c -eq 92) { [void]$sb.Append('\\') }
        elseif ($c -lt 32 -or $c -gt 126) { [void]$sb.Append(('\u{0:x4}' -f $c)) } else { [void]$sb.Append($ch) }
    }
    return $sb.ToString()
}
function P([string]$exe, [string]$a) { return ('{"path":"' + (J $exe) + '","args":"' + (J $a) + '"}') }

function Invoke-Start([string]$Json) {
    $script:Launched = @()
    $err = $null; $res = $null
    try { $res = Start-GenericProcess $Json } catch { $err = [string]$_.Exception.Message }
    return [pscustomobject]@{ Error = $err; Result = $res; Launched = @($script:Launched) }
}
function Test-Refused($r, [string]$code) { return ($null -ne $r.Error -and $r.Error.StartsWith($code, [StringComparison]::Ordinal) -and $r.Launched.Count -eq 0) }

$psExe = "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
$sdExe = "C:\Windows\System32\shutdown.exe"
$sha64 = ("ab" * 32)
$ARGS_BAD = "AOC_CMD_ARGS_NOT_ALLOWED"; $PATH_BAD = "AOC_CMD_PATH_NOT_ALLOWED"; $PAY_BAD = "AOC_CMD_PAYLOAD_INVALID"

foreach ($rn in @("AceOfClubs", "AllBirdies")) {
    $root = "C:\$rn\BayAgent"
    $other = $(if ($rn -eq "AceOfClubs") { "C:\AllBirdies\BayAgent" } else { "C:\AceOfClubs\BayAgent" })
    $BaseDir = $root
    $good = "$root\tools\Update-BayAgent.ps1"
    $urlNew = "https://github.com/millwright-works/aoc-fleet-updates/releases/download/v1.7.0/BayAgent-1.7.0.zip"
    $urlOld = "https://github.com/millwright-works/abg-fleet-updates/releases/download/v1.6.1/BayAgent-1.6.1.zip"

    Section "C1 [$rn] what is accepted, and exactly what is launched"
    $r = Invoke-Start (P $psExe ("-NoProfile -File `"$good`" -Version 1.7.0 -PackageUrl $urlNew -Sha256 $sha64 -RequestRestart"))
    Assert-True ($null -eq $r.Error -and $r.Launched.Count -eq 1 -and $r.Launched[0].File -ceq $psExe -and $r.Launched[0].Args -ceq ("-NoProfile -File $good -Version 1.7.0 -PackageUrl $urlNew -Sha256 $sha64 -RequestRestart")) "the updater line launches, the line rebuilt without quotes: $($r.Error)"
    $r = Invoke-Start (P $psExe ("-NoProfile -File $good -Version 1.6.1 -PackageUrl $urlOld -Sha256 $sha64"))
    Assert-True ($null -eq $r.Error -and $r.Launched.Count -eq 1) "the old repository name is still a fleet asset (the plugin's list has both until the release after the move)"
    $r = Invoke-Start (P $psExe ("-NoProfile -WindowStyle Hidden -File $root\RestartBayAgent.ps1"))
    Assert-True ($null -eq $r.Error -and $r.Launched.Count -eq 1) "RestartBayAgent.ps1 under the root with -WindowStyle launches"
    $r = Invoke-Start (P $psExe ("-NoProfile -NonInteractive -RollbackDrill -NoRollbackGuard -Restart -File $good"))
    Assert-True ($null -eq $r.Error -and $r.Launched.Count -eq 1) "the bare switches of the list are accepted"
    $r = Invoke-Start (P $psExe ("-noprofile  -FILE`t`"$good`""))
    Assert-True ($null -eq $r.Error -and $r.Launched.Count -eq 1 -and $r.Launched[0].Args -ceq ("-noprofile -FILE $good")) "switch case, a tab and a double space are tolerated, and the launched line is single-spaced"
    $r = Invoke-Start (P ("  " + $psExe.ToUpperInvariant() + "  ") ("-NoProfile -File $good"))
    Assert-True ($null -eq $r.Error -and $r.Launched.Count -eq 1 -and $r.Launched[0].File -ceq $psExe) "the program is matched without case and with edge spaces trimmed (as the plugin does), and the CANONICAL path is launched"
    $r = Invoke-Start (P ($psExe + [string][char]0xA0) "-NoProfile -File $good")
    Assert-True ($null -eq $r.Error -and $r.Launched.Count -eq 1 -and $r.Launched[0].File -ceq $psExe) "a trailing no-break space is trimmed too (the plugin's Trim does), and the canonical path is what launches, never the raw text"
    $r = Invoke-Start (P $sdExe "/r /t 30")
    Assert-True ($null -eq $r.Error -and $r.Launched.Count -eq 1 -and $r.Launched[0].File -ceq $sdExe -and $r.Launched[0].Args -ceq "/r /t 30") "shutdown.exe /r /t 30 launches"
    $r = Invoke-Start (P $sdExe "")
    Assert-True ($null -eq $r.Error -and $r.Launched.Count -eq 1 -and $null -eq $r.Launched[0].Args) "shutdown.exe with no arguments is accepted (the plugin accepts it) and launched bare"
    $r = Invoke-Start (P $psExe ("-NoProfile -File $good -Version `"1.7.0`""))
    Assert-True ($null -eq $r.Error -and $r.Launched[0].Args -ceq ("-NoProfile -File $good -Version 1.7.0")) "a quoted value is launched unquoted (what PowerShell parses is what was checked)"

    Section "C2 [$rn] every probe the attack named, and every other way to a refusal: refused, nothing launched"
    $refuse = [ordered]@{
        "-com (a prefix of -Command)"        = @($ARGS_BAD, (P $psExe "-NoProfile -com Write-Output X -File $good"))
        "-com with a one-word command"       = @($ARGS_BAD, (P $psExe "-NoProfile -com whoami -File $good"))
        "a quoted -c with a one-word command" = @($ARGS_BAD, (P $psExe "-NoProfile `"-c`" whoami -File $good"))
        "a quoted -c"                        = @($ARGS_BAD, (P $psExe "-NoProfile `"-c`" Write-Output X -File $good"))
        "-c then a tab"                      = @($ARGS_BAD, (P $psExe "-NoProfile -c`tWrite-Output X -File $good"))
        "-Command"                           = @($ARGS_BAD, (P $psExe "-NoProfile -Command Write-Output X"))
        "inline code with no -File"          = @($ARGS_BAD, (P $psExe "-NoProfile -c x"))
        "-ex bypass"                         = @($ARGS_BAD, (P $psExe "-NoProfile -ex bypass -File $good"))
        "-ExecutionPolicy:Bypass"            = @($ARGS_BAD, (P $psExe "-NoProfile -ExecutionPolicy:Bypass -File $good"))
        "-ExecutionPolicy with two spaces"   = @($ARGS_BAD, (P $psExe "-NoProfile -ExecutionPolicy  Bypass -File $good"))
        "-e (encoded)"                       = @($ARGS_BAD, (P $psExe "-NoProfile -e VwByAGkAdABl -File $good"))
        "-ec (encoded)"                      = @($ARGS_BAD, (P $psExe "-NoProfile -ec VwByAGkAdABl -File $good"))
        "-EncodedCommand"                    = @($ARGS_BAD, (P $psExe "-EncodedCommand VwByAGkAdABl -File $good"))
        "-BaseDir passed to the script"      = @($ARGS_BAD, (P $psExe "-NoProfile -File $good -BaseDir C:\Users\Public"))
        "-SignAfterInstall"                  = @($ARGS_BAD, (P $psExe "-NoProfile -File $good -SignAfterInstall:`$false"))
        "a trailing dot on the program"      = @($PATH_BAD, (P ($psExe + ".") "-NoProfile -Command Write-Output X"))
        "a trailing dot, a good -File"       = @($PATH_BAD, (P ($psExe + ".") "-NoProfile -File $good"))
        "a different file name"              = @($PATH_BAD, (P ($psExe + "x") "-NoProfile -File $good"))
        "a bare file name"                   = @($PATH_BAD, (P "powershell.exe" "-NoProfile -File $good"))
        "cmd.exe"                            = @($PATH_BAD, (P "C:\Windows\System32\cmd.exe" "/c echo X"))
        "powershell_ise.exe"                 = @($PATH_BAD, (P "C:\Windows\System32\WindowsPowerShell\v1.0\powershell_ise.exe" "-Command x"))
        "pwsh.exe"                           = @($PATH_BAD, (P "C:\Program Files\PowerShell\7\pwsh.exe" "-File $good"))
        "an empty path"                      = @($PAY_BAD, (P "" "-File $good"))
        "no args for PowerShell"             = @($ARGS_BAD, (P $psExe ""))
        "only a bare switch"                 = @($ARGS_BAD, (P $psExe "-NoProfile"))
        "-File missing but a value switch"   = @($ARGS_BAD, (P $psExe "-NoProfile -Version 1.7.0"))
        "the other root"                     = @($ARGS_BAD, (P $psExe "-NoProfile -File $other\tools\a.ps1"))
        "a look-alike root"                  = @($ARGS_BAD, (P $psExe "-NoProfile -File ${root}X\tools\a.ps1"))
        "a traversal"                        = @($ARGS_BAD, (P $psExe "-NoProfile -File $root\tools\..\..\x.ps1"))
        "a second -File that leaves"         = @($ARGS_BAD, (P $psExe "-NoProfile -File $good -File C:\Temp\evil.ps1"))
        "the first -File leaves"             = @($ARGS_BAD, (P $psExe "-NoProfile -File C:\Temp\evil.ps1 -File $good"))
        "-f"                                 = @($ARGS_BAD, (P $psExe "-NoProfile -f C:\Temp\evil.ps1 -File $good"))
        "-fi"                                = @($ARGS_BAD, (P $psExe "-NoProfile -fi C:\Temp\evil.ps1 -File $good"))
        "-fil"                               = @($ARGS_BAD, (P $psExe "-NoProfile -fil C:\Temp\evil.ps1 -File $good"))
        "-File: glued"                       = @($ARGS_BAD, (P $psExe "-NoProfile -File:$good"))
        "-File with a ligature (fi)"         = @($ARGS_BAD, (P $psExe ("-" + [string][char]0xFB01 + "le $good")))
        "-File with a dotted capital I"      = @($ARGS_BAD, (P $psExe ("-F" + [string][char]0x0130 + "le $good")))
        "-File with the Kelvin sign"         = @($ARGS_BAD, (P $psExe ("-" + [string][char]0x212A + "ile $good")))
        "an unclosed quote"                  = @($ARGS_BAD, (P $psExe "-NoProfile -File `"$good"))
        "a -File with no value"              = @($ARGS_BAD, (P $psExe "-NoProfile -File"))
        "an empty value"                     = @($ARGS_BAD, (P $psExe "-NoProfile -File $good -Version `"`""))
        "a bad -WindowStyle"                 = @($ARGS_BAD, (P $psExe "-NoProfile -WindowStyle Bogus -File $good"))
        "a value after a bare switch"        = @($ARGS_BAD, (P $psExe "-RollbackDrill extra -File $good"))
        "an unknown word between switches"   =@($ARGS_BAD, (P $psExe "-NoProfile stray -File $good"))
        "a version with an injection"        = @("AOC_FLEET_VERSION_INVALID", (P $psExe "-NoProfile -File $good -Version 1.7.0;x"))
        "a short -Sha256"                    = @("AOC_FLEET_SHA256_INVALID", (P $psExe "-NoProfile -File $good -Sha256 abc"))
        "a -Sha256 that is not hex"          = @("AOC_FLEET_SHA256_INVALID", (P $psExe ("-NoProfile -File $good -Sha256 " + ("g" * 64))))
        "another repository's asset"         = @("AOC_FLEET_PACKAGE_URL_INVALID", (P $psExe "-NoProfile -File $good -PackageUrl https://github.com/o/other-repo/releases/download/v1/BayAgent-1.0.zip"))
        "a query string on the asset"        = @("AOC_FLEET_PACKAGE_URL_INVALID", (P $psExe "-NoProfile -File $good -PackageUrl ${urlNew}?x=1"))
        "http instead of https"              = @("AOC_FLEET_PACKAGE_URL_INVALID", (P $psExe "-NoProfile -File $good -PackageUrl http://github.com/o/aoc-fleet-updates/releases/download/v1/BayAgent-1.0.zip"))
        "a Dataverse file URL"               = @("AOC_FLEET_PACKAGE_URL_INVALID", (P $psExe "-NoProfile -File $good -PackageUrl https://x.crm.dynamics.com/api/data/v9.2/a(1)/f/`$value"))
        "an asset of an unknown package"     = @("AOC_FLEET_PACKAGE_URL_INVALID", (P $psExe "-NoProfile -File $good -PackageUrl https://github.com/o/aoc-fleet-updates/releases/download/v1/Other-1.0.zip"))
        "an asset that is not a zip"         = @("AOC_FLEET_PACKAGE_URL_INVALID", (P $psExe "-NoProfile -File $good -PackageUrl https://github.com/o/aoc-fleet-updates/releases/download/v1/BayAgent-1.0.exe"))
        "shutdown /a"                        = @($ARGS_BAD, (P $sdExe "/a"))
        "shutdown /t abc"                    = @($ARGS_BAD, (P $sdExe "/t abc"))
        "shutdown /t with no value"          = @($ARGS_BAD, (P $sdExe "/t"))
        "shutdown /t seven digits"           = @($ARGS_BAD, (P $sdExe "/t 1234567"))
        "shutdown /c with a message"         = @($ARGS_BAD, (P $sdExe "/r /c hello"))
        "a trailing dot on shutdown.exe"     = @($PATH_BAD, (P ($sdExe + ".") "/r"))
        "a placeholder: braces"              = @("AOC_CMD_PAYLOAD_UNSUBSTITUTED", (P $psExe "-NoProfile -File $good -Version {version}"))
        "a placeholder: angle brackets"      = @("AOC_CMD_PAYLOAD_UNSUBSTITUTED", (P $psExe "-NoProfile -File $good -Sha256 <sha256>"))
        "a placeholder inside the path"      = @("AOC_CMD_PAYLOAD_UNSUBSTITUTED", (P $psExe "-NoProfile -File $root\tools\{x}.ps1"))
        "a repeated args member"             = @($PAY_BAD, ('{"path":"' + (J $psExe) + '","args":"' + (J "-NoProfile -File $good") + '","args":"-Command x"}'))
        "a repeated path member"             = @($PAY_BAD, ('{"path":"' + (J $psExe) + '","path":"C:\\Windows\\System32\\cmd.exe","args":"' + (J "-File $good") + '"}'))
        "a member other than path and args"  = @($PAY_BAD, ('{"path":"' + (J $psExe) + '","args":"' + (J "-NoProfile -File $good") + '","bayLabel":"Bay 1"}'))
        "the payload is an array"            = @($PAY_BAD, '[1,2]')
        "the payload is a string"            = @($PAY_BAD, '"text"')
        "the payload is not JSON"            = @($PAY_BAD, '{"path":')
        "trailing text after the object"     = @($PAY_BAD, ((P $psExe "-NoProfile -File $good") + " tail"))
        "an empty payload"                   = @($PAY_BAD, "")
        "a blank payload"                    = @($PAY_BAD, "   ")
        "args as an array"                   = @($ARGS_BAD, ('{"path":"' + (J $psExe) + '","args":["-NoProfile","-File","x"]}'))
        "args absent for PowerShell"         = @($ARGS_BAD, ('{"path":"' + (J $psExe) + '"}'))
        "a payload over 8192 characters"     = @("Payload too large", (P $psExe ("-NoProfile -File $root\tools\" + ("a" * 8200) + ".ps1")))
    }
    foreach ($k in $refuse.Keys) {
        $r = Invoke-Start $refuse[$k][1]
        Assert-True (Test-Refused $r $refuse[$k][0]) "[$rn] refuses $k with $($refuse[$k][0]), and starts nothing (got: $(if ($null -eq $r.Error) { 'launched' } else { $r.Error.Substring(0, [Math]::Min(70, $r.Error.Length)) }))"
    }
    $r = Invoke-Start ('{"path":"' + (J $psExe) + '","args":"' + (J "-NoProfile -File $good") + '"}')
    Assert-True ($null -eq $r.Error -and $r.Launched.Count -eq 1) "[$rn] (control) the plain object with exactly path and args still launches"
}

Section "C3 the call site passes the raw payload text, once"
$calls = @($ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.CommandAst] -and $n.GetCommandName() -eq "Start-GenericProcess" }, $true))
Assert-True ($calls.Count -eq 1) "exactly one call to Start-GenericProcess in BayAgent.ps1 (found $($calls.Count))"
$arg = $(if ($calls.Count -eq 1 -and $calls[0].CommandElements.Count -eq 2) { $calls[0].CommandElements[1] } else { $null })
Assert-True ($null -ne $arg -and $arg -is [System.Management.Automation.Language.VariableExpressionAst] -and $arg.VariablePath.UserPath -ceq "PayloadJson") "...and its one argument is the variable PayloadJson (Execute-Command's raw text), not the parsed object"
$exec = @($defs | Where-Object { $_.Name -eq "Execute-Command" })
Assert-True ($exec.Count -eq 1 -and $calls.Count -eq 1 -and $calls[0].Extent.StartOffset -ge $exec[0].Extent.StartOffset -and $calls[0].Extent.EndOffset -le $exec[0].Extent.EndOffset) "...inside Execute-Command, whose [string]`$PayloadJson parameter is the command row's text"
$startFnDef = @($defs | Where-Object { $_.Name -eq "Start-GenericProcess" })
Assert-True ($startFnDef.Count -eq 1 -and @($startFnDef[0].Parameters).Count -eq 1 -and $startFnDef[0].Parameters[0].Name.VariablePath.UserPath -ceq "PayloadJson" -and $startFnDef[0].Parameters[0].StaticType -eq [string]) "Start-GenericProcess takes one [string] parameter, PayloadJson: the raw text"

Write-Host ""
Write-Host ("RESULT: {0} passed, {1} failed" -f $script:Pass, $script:Fail)
if ($script:Fail -gt 0) { $script:Failures | ForEach-Object { Write-Host "  FAILED: $_" -ForegroundColor Red }; exit 1 }
exit 0
