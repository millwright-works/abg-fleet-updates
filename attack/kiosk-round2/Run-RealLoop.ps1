#Requires -Version 5.1
# Kiosk round 2 attack (2026-10-10). The REAL BayAgent.ps1 (only $BaseDir repointed at a sandbox, as the Launch suite does),
# run once (-Once) in a child Windows PowerShell 5.1 with NO network (the environment and token hosts point at a closed
# local port), over state files that say "session s-live was canceled mid-play, its warning ends at <cancelEnd>".
# Question: does one real main-loop pass, before any token, run the normal End (wall ENDED, intent closed, record cleared,
# a real stand-in launcher process closed)? Cases: due (warning over), notdue (10 minutes left), and the same "due" case on a
# copy whose main-loop line is commented out (the control that shows this probe can fail). Hyphens only in comments.
param([string]$Tree = "", [string]$OutDir = "")
$ErrorActionPreference = "Stop"
if ([string]::IsNullOrWhiteSpace($Tree)) { $Tree = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path }
if ([string]::IsNullOrWhiteSpace($OutDir)) { throw "OutDir is required" }
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
try { Add-Type -AssemblyName System.Security -ErrorAction SilentlyContinue } catch { }
$agentSrc = Join-Path $Tree "src\BayAgent\BayAgent.ps1"
$manifestSrc = Join-Path $Tree "src\BayAgent\manifest.json"
$sandbox = Join-Path $env:TEMP ("kr2-realloop-" + [guid]::NewGuid().ToString("N").Substring(0, 8))
New-Item -ItemType Directory -Force -Path $sandbox | Out-Null
$fmt = "yyyy-MM-ddTHH:mm:ssZ"
$utf8 = New-Object Text.UTF8Encoding($false)
$standInName = "AbgVyLoopStandIn" + [guid]::NewGuid().ToString("N").Substring(0, 8)
$standInExe = Join-Path $sandbox ($standInName + ".exe")
Add-Type -TypeDefinition "public static class AbgVyLoopStandInMain { public static void Main() { System.Threading.Thread.Sleep(600000); } }" -OutputAssembly $standInExe -OutputType ConsoleApplication
$lines = New-Object System.Collections.ArrayList
function Say([string]$m) { [void]$lines.Add($m); Write-Host $m }

function Invoke-Case([string]$Name, [int]$CancelEndOffsetSeconds, [switch]$DisableLoopLine) {
    $root = Join-Path $sandbox $Name
    foreach ($d in @("", "logs", "secrets", "state")) { New-Item -ItemType Directory -Force -Path (Join-Path $root $d) | Out-Null }
    $text = [IO.File]::ReadAllText($agentSrc)
    $needle = '$BaseDir = "C:\AllBirdies\BayAgent"'
    if (-not $text.Contains($needle)) { throw "BaseDir literal not found" }
    $text = $text.Replace($needle, ('$BaseDir = "{0}"' -f $root))
    if ($DisableLoopLine) {
        $loopLine = '        try { [void](Invoke-CancelEndIfDue -NowUtc ((Get-Date).ToUniversalTime())) } catch { }'
        if (-not $text.Contains($loopLine)) { throw "main-loop line not found" }
        $text = $text.Replace($loopLine, ('        # ' + $loopLine.Trim()))
    }
    $agent = Join-Path $root "BayAgent.ps1"
    [IO.File]::WriteAllText($agent, $text, $utf8)
    Copy-Item -LiteralPath $manifestSrc -Destination (Join-Path $root "manifest.json") -Force
    $plain = [Text.Encoding]::UTF8.GetBytes("not-a-real-secret-" + [guid]::NewGuid().ToString("N"))
    $prot = [System.Security.Cryptography.ProtectedData]::Protect($plain, $null, [System.Security.Cryptography.DataProtectionScope]::LocalMachine)
    [IO.File]::WriteAllBytes((Join-Path $root "secrets\clientsecret.dpapi"), $prot)
    $sessPath = Join-Path $root "session.json"
    $cfg = [ordered]@{
        environmentUrl = "http://127.0.0.1:9"; tenantId = "11111111-1111-1111-1111-111111111111"; clientId = "22222222-2222-2222-2222-222222222222"
        clientSecretDpapiPath = (Join-Path $root "secrets\clientsecret.dpapi"); clientCertThumbprint = ""; bayId = "33333333-3333-3333-3333-333333333333"
        pollSeconds = 3; heartbeatSeconds = 60; tokenAuthorityHost = "http://127.0.0.1:9"; logLevel = "DEBUG"
        sessionJsonPath = $sessPath
        launcher = [ordered]@{ path = $standInExe; args = ""; processName = $standInName; displayRole = "control"; startOnPrep = $false; startOnStart = $true }
        sessionDisplay = [ordered]@{ enabled = $false }
    }
    [IO.File]::WriteAllText((Join-Path $root "agent-config.json"), ($cfg | ConvertTo-Json -Depth 5), $utf8)
    $now = (Get-Date).ToUniversalTime()
    $cancelEnd = $now.AddSeconds($CancelEndOffsetSeconds).ToString($fmt)
    $bookEnd = $now.AddMinutes(40).ToString($fmt)
    $written = $now.AddMinutes(-4).ToString($fmt)
    $stamp = [ordered]@{ schema = 1; running = $true; baySessionId = "s-live"; endUtc = $bookEnd; since = $now.AddMinutes(-30).ToString($fmt); cancelEndUtc = $cancelEnd; status = "ENDING"; forSessionId = "s-live"; writtenUtc = $written }
    $wall = [ordered]@{ schema = 1; status = "ENDING"; baySessionId = "s-live"; displayName = "Guest"; playEndUtc = $cancelEnd; sessionEndUtc = $cancelEnd; endUtc = $cancelEnd; bannerText = "Booking canceled"; statusDetail = "This booking was canceled."; agentRunning = $stamp }
    [IO.File]::WriteAllText($sessPath, ($wall | ConvertTo-Json -Depth 6), $utf8)
    $rec = [ordered]@{ schema = 1; running = $true; baySessionId = "s-live"; endUtc = $bookEnd; since = $now.AddMinutes(-30).ToString($fmt); cancelEndUtc = $cancelEnd; finished = @(); writtenUtc = $written }
    [IO.File]::WriteAllText((Join-Path $root "state\running-session.json"), ($rec | ConvertTo-Json -Depth 4), $utf8)
    $until = $now.AddSeconds($CancelEndOffsetSeconds + 120).ToString($fmt)
    $intent = [ordered]@{ schema = 1; launcher = "wanted"; untilUtc = $until; baySessionId = "s-live"; reason = "booking canceled mid-play: wanted until its warning ends (A0.467)"; writtenUtc = $written; agentPid = 1 }
    [IO.File]::WriteAllText((Join-Path $root "state\kiosk-intent.json"), ($intent | ConvertTo-Json -Depth 3), $utf8)

    $standIn = Start-Process -FilePath $standInExe -WindowStyle Hidden -PassThru
    Start-Sleep -Milliseconds 800
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = Join-Path $env:WINDIR "System32\WindowsPowerShell\v1.0\powershell.exe"
    $psi.Arguments = "-NoProfile -WindowStyle Minimized -File `"$agent`" -Once"
    $psi.UseShellExecute = $false; $psi.RedirectStandardOutput = $true; $psi.RedirectStandardError = $true; $psi.CreateNoWindow = $true; $psi.WorkingDirectory = $root
    $psi.EnvironmentVariables["PSExecutionPolicyPreference"] = "Bypass"
    if ($psi.EnvironmentVariables.ContainsKey("PSModulePath")) { $psi.EnvironmentVariables.Remove("PSModulePath") }
    $sw = [Diagnostics.Stopwatch]::StartNew()
    $proc = [System.Diagnostics.Process]::Start($psi)
    $so = $proc.StandardOutput.ReadToEndAsync(); $se = $proc.StandardError.ReadToEndAsync()
    $exited = $proc.WaitForExit(180000)
    if (-not $exited) { try { $proc.Kill() } catch { } }
    $sw.Stop()
    $standIn.Refresh()
    $launcherExited = $standIn.HasExited
    if (-not $launcherExited) { try { Stop-Process -Id $standIn.Id -Force -ErrorAction SilentlyContinue } catch { } }
    $log = ""
    foreach ($f in @(Get-ChildItem -LiteralPath (Join-Path $root "logs") -Filter "*.log" -ErrorAction SilentlyContinue)) { $log += [IO.File]::ReadAllText($f.FullName) }
    [IO.File]::WriteAllText((Join-Path $OutDir ("realloop-" + $Name + "-agent.log")), $log, $utf8)
    $w = $null; try { $w = [IO.File]::ReadAllText($sessPath) | ConvertFrom-Json } catch { }
    $i = $null; try { $i = [IO.File]::ReadAllText((Join-Path $root "state\kiosk-intent.json")) | ConvertFrom-Json } catch { }
    $r = $null; try { $r = [IO.File]::ReadAllText((Join-Path $root "state\running-session.json")) | ConvertFrom-Json } catch { }
    $fin = ""; try { $fin = (@($r.finished) | ForEach-Object { $_.id }) -join "," } catch { }
    $tokenLine = @($log -split "`r?`n" | Where-Object { $_ -match "Top-level exception|Token request failed|acquired" } | Select-Object -First 1)
    $endLine = @($log -split "`r?`n" | Where-Object { $_ -match "ended after its warning|End of a canceled booking failed" } | Select-Object -First 1)
    $iEnd = $log.IndexOf("ended after its warning"); $iTok = $log.IndexOf("Top-level exception")
    Say ("REALLOOP {0}: agent exited={1} code={2} in {3}s | wall={4}/{5} | intent={6}/{7} | record running={8} finished=[{9}] | stand-in launcher exited={10} | FATAL in log={11}" -f $Name, $exited, $(if ($exited) { $proc.ExitCode } else { "-" }), [int]$sw.Elapsed.TotalSeconds, $(if ($w) { $w.status } else { "?" }), $(if ($w) { $w.baySessionId } else { "?" }), $(if ($i) { $i.launcher } else { "?" }), $(if ($i) { $i.baySessionId } else { "?" }), $(if ($r) { $r.running } else { "?" }), $fin, $launcherExited, ($log -match "FATAL"))
    Say ("REALLOOP {0}:   end line: {1}" -f $Name, $(if ($endLine.Count) { $endLine[0].Trim() } else { "(none)" }))
    Say ("REALLOOP {0}:   network line: {1} | the End was logged before the token failure={2}" -f $Name, $(if ($tokenLine.Count) { $tokenLine[0].Trim().Substring(0, [Math]::Min(170, $tokenLine[0].Trim().Length)) } else { "(none)" }), ($iEnd -ge 0 -and $iTok -gt $iEnd))
}

try {
    Invoke-Case -Name "due" -CancelEndOffsetSeconds -60
    Invoke-Case -Name "notdue" -CancelEndOffsetSeconds 600
    Invoke-Case -Name "due-loopline-disabled" -CancelEndOffsetSeconds -60 -DisableLoopLine
} finally {
    [IO.File]::WriteAllLines((Join-Path $OutDir "realloop-observations.txt"), [string[]]$lines)
    try { Remove-Item -LiteralPath $sandbox -Recurse -Force -ErrorAction SilentlyContinue } catch { }
}
