<#
BayAgent.UpdateGuard.Tests.ps1

WHY THIS EXISTS
  A0.437 (Kevin, 2026-10-07: "I don't like that you need me to be at the Bay PC in order to update the BayAgent.
  Shouldn't you be able to do that remotely?"). The 1.3.0 remote install found the update path itself defective
  (F1: the updater skipped an equal-sized manifest.json, so the bay reported 1.2.1 while running 1.3.0), a latent
  junction hazard (R-D: a /MIR into a current\ that is a junction overwrites the release it points at) and no way
  back if a new agent never returned. This suite drives the REAL scripts (Update-BayAgent.ps1 and
  Watch-BayAgentUpdate.ps1, in child Windows PowerShell 5.1 processes, against a sandbox bay and a loopback server
  for the package and the "cloud"):

    G   static: the build gates (code version, manifest length) refuse what they must; the package ships the guard;
        the guard's command line has no -ExecutionPolicy and is NOT matched by the kill patterns in
        ABG.HostWatchdog.ps1 and ABG.AgentHost.ps1 (read from those files; the agent's own command line is the
        positive control); the updater launches the guard from the snapshot.
    F   F1 regression: the 1.3.0 updater (git 514ad6d) leaves a same-size, same-time stale manifest.json in current\
        (red control); the 1.3.1 updater copies it and verifies current\ by hash.
    J   R-D: current\ a junction into releases\1.2.1. The 1.3.0 updater overwrites releases\1.2.1 (red control); the
        1.3.1 updater leaves it byte-identical, makes current\ a real folder and snapshots what ran.
    N   a guard that never arms: nothing is promoted (current\ hash-identical), the run fails with stage "guard", the
        pending record is stood down and the guard task removed.
    E   end to end with the guard (the updater copy with ONE line changed: -ExecutionPolicy Bypass added to the guard's
        argument line, because a sandbox script is unsigned; asserted to be the only difference): a new agent that
        proves itself back is confirmed; one that does not is rolled back (current\ and tools\ restored by hash,
        rolled-back result, restart requested) and the restored agent confirmed; an unreachable cloud never rolls
        back; a drill rolls back on purpose.
    K   the restart proof: the updater runs INSIDE a scheduled task standing in for \ABG Bay Agent, the task is ended
        the way ABG.HostWatchdog.ps1 ends it (schtasks /End), and the guard survives and finishes. Whether a plain
        child of the ended task survives is recorded, not asserted (it did on Windows 11 26300, 2026-10-07); the
        watchdog's command-line kill patterns are covered statically in G.
    U   guard rules one at a time: wrong hash, alive before promotion, soak not met, damaged snapshot, junction at
        rollback time, aborted, never promoted, foreign installId, lock, resume of the reachable-time count.

  What this does NOT prove: AllSigned (sandbox copies cannot carry the bay's signature) and a STANDARD user's right
  to register its own scheduled task (this machine's account may be an administrator). Both are real-bay proofs;
  a guard that cannot arm on a bay refuses the install (N), so neither can promote unguarded code by surprise.

RUN (from the repo root; Windows only)
  powershell -NoProfile -ExecutionPolicy Bypass -File tests\BayAgent.UpdateGuard.Tests.ps1
  -SkipTaskTests skips E and K (they register per-user scheduled tasks named AoC-ba131-test-*; both are removed).
  -Only G,F,J,N,U,E runs only those sections (E includes K); the setup always runs. For mutation runs.

Exit code 0 = all assertions passed. Hyphens only in comments.
#>
[CmdletBinding()]
param([switch]$SkipTaskTests, [string]$Only = "")

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$IsWin = ([Environment]::OSVersion.Platform -eq [PlatformID]::Win32NT)
$Updater = Join-Path $RepoRoot "src\BayAgent\tools\Update-BayAgent.ps1"
$Guard = Join-Path $RepoRoot "src\BayAgent\tools\Watch-BayAgentUpdate.ps1"
$Ps51 = Join-Path $env:SystemRoot "System32\WindowsPowerShell\v1.0\powershell.exe"

$script:Pass = 0; $script:Fail = 0; $script:Failures = @()
function Assert-True([bool]$cond, [string]$msg) {
    if ($cond) { $script:Pass++; Write-Host "  PASS  $msg" }
    else { $script:Fail++; $script:Failures += $msg; Write-Host "  FAIL  $msg" -ForegroundColor Red }
}
function Section([string]$name) { Write-Host ""; Write-Host "== $name" -ForegroundColor Cyan }
function Want([string]$s) { return ([string]::IsNullOrWhiteSpace($Only) -or (@($Only -split ',' | ForEach-Object { $_.Trim() }) -contains $s)) }

if (-not $IsWin) {
    Write-Host "SKIP: the updater and the guard are Windows-only (robocopy, Authenticode, scheduled tasks)"
    Write-Host "RESULT: 0 passed, 0 failed"
    exit 0
}

$tmp = Join-Path ([IO.Path]::GetTempPath()) ("ba131-guard-" + [Guid]::NewGuid().ToString("N").Substring(0, 12))
New-Item -ItemType Directory -Force -Path $tmp | Out-Null
$startedIds = New-Object System.Collections.Generic.List[int]
$links = New-Object System.Collections.Generic.List[string]
$tasks = New-Object System.Collections.Generic.List[string]
$srv = $null; $fake = $null

function Get-Sha([string]$p) { return (Get-FileHash -LiteralPath $p -Algorithm SHA256).Hash.ToLowerInvariant() }
function Get-Tree([string]$root) {
    $m = @{}
    if (-not (Test-Path -LiteralPath $root)) { return $m }
    $full = (Get-Item -LiteralPath $root -Force).FullName.TrimEnd('\')
    foreach ($f in @(Get-ChildItem -LiteralPath $root -Recurse -File -Force)) { $m[$f.FullName.Substring($full.Length).TrimStart('\').ToLowerInvariant()] = Get-Sha $f.FullName }
    return $m
}
function Test-TreeEqual([hashtable]$a, [hashtable]$b) {
    if ($a.Count -ne $b.Count) { return $false }
    foreach ($k in $a.Keys) { if (-not $b.ContainsKey($k) -or $b[$k] -ne $a[$k]) { return $false } }
    return $true
}
function Read-Json([string]$p) { if (-not (Test-Path -LiteralPath $p)) { return $null }; try { return ([IO.File]::ReadAllText($p) | ConvertFrom-Json) } catch { return $null } }
function Write-Json([string]$p, $o) { [IO.File]::WriteAllText($p, ($o | ConvertTo-Json -Depth 8), (New-Object Text.UTF8Encoding($false))) }
function Utc([DateTime]$d) { return $d.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ") }
function Is-Link([string]$p) { if (-not (Test-Path -LiteralPath $p)) { return $false }; return (((Get-Item -LiteralPath $p -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) }

function New-Ps51Process([string]$arguments) {
    # A Windows PowerShell 5.1 child with its OWN module path: started from PowerShell 7, a child inherits pwsh's
    # PSModulePath and cannot load Microsoft.PowerShell.Utility (Get-FileHash, Start-Sleep), MEASURED 2026-10-07.
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = $Ps51
    $psi.Arguments = $arguments
    $psi.UseShellExecute = $false; $psi.CreateNoWindow = $true
    if ($psi.EnvironmentVariables.ContainsKey("PSModulePath")) { $psi.EnvironmentVariables.Remove("PSModulePath") }
    $p = [System.Diagnostics.Process]::Start($psi)
    $startedIds.Add([int]$p.Id)
    return $p
}

function Invoke-Child([string]$script, [string[]]$argList, [int]$timeoutSec = 240) {
    # A real Windows PowerShell 5.1 child. Its stderr must not abort this harness.
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = $Ps51
    $q = @("-NoProfile", "-ExecutionPolicy", "Bypass", "-File", ('"{0}"' -f $script)) + @($argList | ForEach-Object { if ($_ -match '\s' -and $_ -notmatch '^".*"$') { '"' + $_ + '"' } else { $_ } })
    $psi.Arguments = ($q -join " ")
    $psi.UseShellExecute = $false; $psi.RedirectStandardOutput = $true; $psi.RedirectStandardError = $true; $psi.CreateNoWindow = $true
    if ($psi.EnvironmentVariables.ContainsKey("PSModulePath")) { $psi.EnvironmentVariables.Remove("PSModulePath") }
    $p = [System.Diagnostics.Process]::Start($psi)
    $startedIds.Add([int]$p.Id)
    $so = $p.StandardOutput.ReadToEndAsync(); $se = $p.StandardError.ReadToEndAsync()
    $done = $p.WaitForExit($timeoutSec * 1000)
    if (-not $done) { try { Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue } catch {} }
    return [pscustomobject]@{ Done = $done; Exit = $(if ($done) { $p.ExitCode } else { -1 }); Out = $so.Result; Err = $se.Result }
}

try {
    # ============================================================ loopback server: the package and the "cloud"
    $sync = [hashtable]::Synchronized(@{ Stop = $false; Port = 0; CloudDown = $false; Files = @{}; Errors = [System.Collections.ArrayList]::Synchronized((New-Object System.Collections.ArrayList)) })
    $rs = [runspacefactory]::CreateRunspace(); $rs.Open(); $rs.SessionStateProxy.SetVariable("sync", $sync)
    $ps = [powershell]::Create(); $ps.Runspace = $rs
    [void]$ps.AddScript({
        $l = New-Object System.Net.Sockets.TcpListener([System.Net.IPAddress]::Loopback, 0); $l.Start()
        $sync["Port"] = ([System.Net.IPEndPoint]$l.LocalEndpoint).Port
        try {
            while (-not $sync["Stop"]) {
                if (-not $l.Server.Poll(200000, [System.Net.Sockets.SelectMode]::SelectRead)) { continue }
                $c = $l.AcceptTcpClient()
                try {
                    $c.ReceiveTimeout = 5000; $s = $c.GetStream(); $buf = New-Object byte[] 8192; $ms = New-Object System.IO.MemoryStream; $he = -1
                    while ($he -lt 0) { $n = $s.Read($buf, 0, $buf.Length); if ($n -le 0) { break }; $ms.Write($buf, 0, $n); $he = ([Text.Encoding]::ASCII.GetString($ms.ToArray())).IndexOf("`r`n`r`n") }
                    $line = ([Text.Encoding]::ASCII.GetString($ms.ToArray()) -split "`r`n")[0]
                    $path = ($line -split " ")[1]
                    $code = 404; $ctype = "text/plain"; [byte[]]$body = [Text.Encoding]::ASCII.GetBytes("not found")
                    if ($sync["Files"].ContainsKey($path)) { $code = 200; $ctype = "application/zip"; $body = [IO.File]::ReadAllBytes($sync["Files"][$path]) }
                    elseif ($path -like "/api/data/v9.2/*") { if ($sync["CloudDown"]) { $code = 503 } else { $code = 401 }; $body = [Text.Encoding]::ASCII.GetBytes("{}"); $ctype = "application/json" }
                    elseif ($path -like "*/.well-known/openid-configuration") { if ($sync["CloudDown"]) { $code = 503 } else { $code = 200 }; $body = [Text.Encoding]::ASCII.GetBytes('{"issuer":"x"}'); $ctype = "application/json" }
                    $reason = @{ 200 = "OK"; 401 = "Unauthorized"; 404 = "Not Found"; 503 = "Service Unavailable" }[$code]
                    $head = "HTTP/1.1 $code $reason`r`nContent-Type: $ctype`r`nContent-Length: $($body.Length)`r`nConnection: close`r`n`r`n"
                    $hb = [Text.Encoding]::ASCII.GetBytes($head); $s.Write($hb, 0, $hb.Length); $s.Write($body, 0, $body.Length); $s.Flush()
                } catch { [void]$sync["Errors"].Add($_.Exception.Message) } finally { $c.Close() }
            }
        } finally { $l.Stop() }
    })
    $srvHandle = $ps.BeginInvoke(); $srv = @{ PS = $ps; RS = $rs; H = $srvHandle }
    $dl = (Get-Date).AddSeconds(10); while ($sync["Port"] -eq 0 -and (Get-Date) -lt $dl) { Start-Sleep -Milliseconds 50 }
    if ($sync["Port"] -eq 0) { throw "loopback server did not start" }
    $Base = "http://127.0.0.1:{0}" -f $sync["Port"]

    # ============================================================ the real package, built from this tree
    $manifest = Get-Content -LiteralPath (Join-Path $RepoRoot "src\BayAgent\manifest.json") -Raw | ConvertFrom-Json
    $Ver = [string]$manifest.version
    $dist = Join-Path $tmp "dist"
    $b = Invoke-Child (Join-Path $RepoRoot "tools\Build-ReleasePackage.ps1") @("-Version", $Ver, "-OutDir", $dist)
    $Zip = Join-Path $dist ("BayAgent-{0}.zip" -f $Ver)
    if ($b.Exit -ne 0 -or -not (Test-Path -LiteralPath $Zip)) { throw "the package did not build: $($b.Out) $($b.Err)" }
    $ZipSha = Get-Sha $Zip
    $sync["Files"]["/BayAgent-$Ver.zip"] = $Zip
    $PkgUrl = "$Base/BayAgent-$Ver.zip"
    $expRef = Join-Path $tmp "expand-ref"
    Expand-Archive -LiteralPath $Zip -DestinationPath $expRef -Force
    $NewAgentRaw = Get-Sha (Join-Path $expRef "BayAgent.ps1")
    $NewManifestItem = Get-Item -LiteralPath (Join-Path $expRef "manifest.json")

    function New-Bay([string]$name, [switch]$Junction, [switch]$GuardInTools, [string]$GuardStub = "") {
        # A bay running "1.2.1": current\ (or a junction to releases\1.2.1), tools\ with an old updater, a config that
        # points the guard's reachability probe at the loopback cloud.
        $bay = Join-Path $tmp $name
        foreach ($s in @("releases\1.2.1", "tools", "state", "control", "logs")) { New-Item -ItemType Directory -Force -Path (Join-Path $bay $s) | Out-Null }
        $rel = Join-Path $bay "releases\1.2.1"
        [IO.File]::WriteAllText((Join-Path $rel "BayAgent.ps1"), "# old agent 1.2.1`r`nWrite-Output 'old'`r`n")
        # F1's shape: same LENGTH as the new manifest, same TIME as the new manifest entry, saying 1.2.1.
        $stale = "{`"version`":`"1.2.1`",`"pad`":`"" + ("x" * 200) + "`"}"
        $stale = $stale.Substring(0, $NewManifestItem.Length - 2) + "`"}"
        [IO.File]::WriteAllText((Join-Path $rel "manifest.json"), $stale)
        (Get-Item -LiteralPath (Join-Path $rel "manifest.json")).LastWriteTimeUtc = $NewManifestItem.LastWriteTimeUtc
        [IO.File]::WriteAllText((Join-Path $rel "old-only.txt"), "a file only the old release has")
        $cur = Join-Path $bay "current"
        if ($Junction) { New-Item -ItemType Junction -Path $cur -Value $rel | Out-Null; $links.Add($cur) }
        else { New-Item -ItemType Directory -Force -Path $cur | Out-Null; Copy-Item -Path (Join-Path $rel "*") -Destination $cur -Recurse -Force; (Get-Item -LiteralPath (Join-Path $cur "manifest.json")).LastWriteTimeUtc = $NewManifestItem.LastWriteTimeUtc }
        [IO.File]::WriteAllText((Join-Path $bay "tools\Update-BayAgent.ps1"), "# old updater`r`n")
        [IO.File]::WriteAllText((Join-Path $bay "tools\Keep-Me.ps1"), "# a tool the package does not ship`r`n")
        if ($GuardInTools) { Copy-Item -LiteralPath $Guard -Destination (Join-Path $bay "tools\Watch-BayAgentUpdate.ps1") -Force }
        if ($GuardStub) { [IO.File]::WriteAllText((Join-Path $bay "tools\Watch-BayAgentUpdate.ps1"), $GuardStub) }
        Write-Json (Join-Path $bay "agent-config.json") ([ordered]@{ environmentUrl = $Base; tenantId = "11111111-1111-1111-1111-111111111111"; tokenAuthorityHost = $Base; clientId = "x"; bayId = "y" })
        return $bay
    }
    function Invoke-Update([string]$updaterPath, [string]$bay, [string[]]$extra = @()) {
        # -Command, not -File: a switch cannot be set to $false through -File (the value arrives as a string), and the
        # sandbox has no code-signing certificate, so signing is off here. "; exit $LASTEXITCODE" keeps the exit code.
        $toks = @("-Version", $Ver, "-PackageUrl", $PkgUrl, "-Sha256", $ZipSha, "-BaseDir", $bay) + $extra
        $parts = @("&", ("'{0}'" -f $updaterPath))
        foreach ($tk in $toks) { if ($tk.StartsWith("-")) { $parts += $tk } else { $parts += ("'{0}'" -f $tk) } }
        $parts += '-SignAfterInstall:$false;'
        $parts += 'exit $LASTEXITCODE'
        $psi = New-Object System.Diagnostics.ProcessStartInfo
        $psi.FileName = $Ps51
        $psi.Arguments = '-NoProfile -ExecutionPolicy Bypass -Command "' + ($parts -join " ") + '"'
        $psi.UseShellExecute = $false; $psi.RedirectStandardOutput = $true; $psi.RedirectStandardError = $true; $psi.CreateNoWindow = $true
        if ($psi.EnvironmentVariables.ContainsKey("PSModulePath")) { $psi.EnvironmentVariables.Remove("PSModulePath") }
        $p = [System.Diagnostics.Process]::Start($psi)
        $startedIds.Add([int]$p.Id)
        $so = $p.StandardOutput.ReadToEndAsync(); $se = $p.StandardError.ReadToEndAsync()
        $done = $p.WaitForExit(300000)
        if (-not $done) { try { Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue } catch {} }
        return [pscustomobject]@{ Done = $done; Exit = $(if ($done) { $p.ExitCode } else { -1 }); Out = $so.Result; Err = $se.Result }
    }

    $oldUpdater = Join-Path $tmp "Update-BayAgent-1.3.0.ps1"
    $oldText = (& git -C $RepoRoot show "514ad6d17560cc459af8930440f480373e357dda:src/BayAgent/tools/Update-BayAgent.ps1") -join "`r`n"
    [IO.File]::WriteAllText($oldUpdater, $oldText + "`r`n", (New-Object Text.UTF8Encoding($false)))

    # ============================================================ G static
    if (Want "G") {
    Section "G static: build gates, package contents, guard command line vs the kill patterns"
    $zipEntries = @()
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $za = [IO.Compression.ZipFile]::OpenRead($Zip); try { $zipEntries = @($za.Entries | ForEach-Object { $_.FullName }) } finally { $za.Dispose() }
    Assert-True ($zipEntries -contains "tools/Watch-BayAgentUpdate.ps1") "the package ships tools/Watch-BayAgentUpdate.ps1"
    Assert-True ((Get-Content -LiteralPath (Join-Path $expRef "manifest.json") -Raw) -match '"version":\s*"' + [regex]::Escape($Ver) + '"' -and $NewManifestItem.Length -notin @(65, 68)) "the package's manifest says $Ver and is not 65/68 bytes ($($NewManifestItem.Length))"
    # build gates, on a scratch copy of the tree
    $gr = Join-Path $tmp "gate-repo"
    New-Item -ItemType Directory -Force -Path $gr | Out-Null
    Copy-Item -LiteralPath (Join-Path $RepoRoot "src") -Destination $gr -Recurse -Force
    Copy-Item -LiteralPath (Join-Path $RepoRoot "tools") -Destination $gr -Recurse -Force
    $grAgent = Join-Path $gr "src\BayAgent\BayAgent.ps1"
    $agentText = [IO.File]::ReadAllText($grAgent)
    [IO.File]::WriteAllText($grAgent, $agentText.Replace('$AgentCodeVersion = "' + $Ver + '"', '$AgentCodeVersion = "9.9.9"'), (New-Object Text.UTF8Encoding($true)))
    Assert-True (([IO.File]::ReadAllText($grAgent)) -ne $agentText) "(sanity) the code-version mutant applied"
    $g1 = Invoke-Child (Join-Path $gr "tools\Build-ReleasePackage.ps1") @("-Version", $Ver, "-OutDir", (Join-Path $gr "dist"))
    Assert-True ($g1.Exit -eq 1 -and $g1.Out -match "AgentCodeVersion = '9\.9\.9'") "the build refuses a package whose code version disagrees with -Version"
    [IO.File]::WriteAllText($grAgent, $agentText, (New-Object Text.UTF8Encoding($true)))
    $grMan = Join-Path $gr "src\BayAgent\manifest.json"
    # the exact shape every manifest from 1.2.0 to 1.3.0 shipped in (68 bytes with CRLF)
    [IO.File]::WriteAllText($grMan, "{`r`n  `"version`": `"$Ver`",`r`n  `"releasedUtc`": `"2026-10-07T00:00:00Z`"`r`n}")
    Assert-True ((Get-Item -LiteralPath $grMan).Length -eq 68) "(sanity) the scratch manifest is 68 bytes"
    $g2 = Invoke-Child (Join-Path $gr "tools\Build-ReleasePackage.ps1") @("-Version", $Ver, "-OutDir", (Join-Path $gr "dist"))
    Assert-True ($g2.Exit -eq 1 -and $g2.Out -match "manifest\.json is 68 bytes") "the build refuses a 68-byte manifest (an older updater would skip copying it)"

    # the guard's command line and the two kill patterns
    $uAst = [System.Management.Automation.Language.Parser]::ParseFile($Updater, [ref]$null, [ref]$null)
    $fnArgs = $uAst.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq "Get-UpdateGuardArguments" }, $true) | Select-Object -First 1
    . ([scriptblock]::Create($fnArgs.Extent.Text))
    $BaseDir = "C:\AllBirdies\BayAgent"
    $guardArgs = Get-UpdateGuardArguments "C:\AllBirdies\BayAgent\rollback\tools\Watch-BayAgentUpdate.ps1" ([guid]::NewGuid().ToString()) "ABG BayAgent Update Guard"
    $guardCl = ('"{0}" {1}' -f "C:\WINDOWS\System32\WindowsPowerShell\v1.0\powershell.exe", $guardArgs)
    Assert-True ($guardArgs -notmatch '(?i)-ExecutionPolicy|-Command|-EncodedCommand|\s-c\s|\s-enc\s' -and $guardArgs -match '(?i)-File "C:\\AllBirdies\\BayAgent\\rollback\\tools\\Watch-BayAgentUpdate\.ps1"') "the guard runs with -File and no execution-policy override (AllSigned applies to it)"
    $wdText = [IO.File]::ReadAllText((Join-Path $RepoRoot "src\BayAgent\bootstrap\ABG.HostWatchdog.ps1"))
    $wdRx = [regex]::Match($wdText, 'function Get-BayAgentProcs[\s\S]*?\$cl -match "([^"]+)"').Groups[1].Value
    $ahText = [IO.File]::ReadAllText((Join-Path $RepoRoot "src\BayAgent\bootstrap\ABG.AgentHost.ps1"))
    $ahLike = [regex]::Match($ahText, 'Get-PSProcessesByCmdLike "([^"]+)"').Groups[1].Value
    $agentCl = '"C:\WINDOWS\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -WindowStyle Minimized -File "C:\AllBirdies\BayAgent\current\BayAgent.ps1"'
    Assert-True ($wdRx.Length -gt 0 -and $ahLike.Length -gt 0 -and ($agentCl -match $wdRx) -and ($agentCl -like $ahLike)) "(positive control) both kill patterns, read from the bootstrap files, DO match the agent's own command line ('$wdRx' / '$ahLike')"
    Assert-True (-not ($guardCl -match $wdRx) -and -not ($guardCl -like $ahLike)) "neither kill pattern matches the guard's command line, so a restart does not stop the guard"
    $uText = [IO.File]::ReadAllText($Updater)
    Assert-True ($uText -match '(?m)^\s*\$guardScript = Join-Path \$SnapTools "Watch-BayAgentUpdate\.ps1"\s*$') "the updater launches the guard from the snapshot (rollback\tools), not from the package being installed"
    $gText = [IO.File]::ReadAllText($Guard)
    Assert-True ($gText -notmatch '(?i)clientSecret|Get-ClientSecret|ProtectedData|Cert:\\') "the guard touches no credential"

    }

    # ============================================================ F F1 regression
    if (Want "F") {
    Section "F F1: the stale same-size, same-time manifest"
    $bayF0 = New-Bay "bayF0"
    $f0 = Invoke-Update $oldUpdater $bayF0
    $manAfterOld = Read-Json (Join-Path $bayF0 "current\manifest.json")
    Assert-True ($f0.Exit -eq 0 -and $null -ne $manAfterOld -and [string]$manAfterOld.version -eq "1.2.1") "(red control) the 1.3.0 updater reports success and leaves the stale 1.2.1 manifest in current\ (F1 reproduced; exit $($f0.Exit))"
    $bayF1 = New-Bay "bayF1"
    $f1 = Invoke-Update $Updater $bayF1 @("-NoRollbackGuard")
    $manAfterNew = Read-Json (Join-Path $bayF1 "current\manifest.json")
    $res1 = Read-Json (Join-Path $bayF1 "state\last-update-result.json")
    Assert-True ($f1.Exit -eq 0 -and $null -ne $manAfterNew -and [string]$manAfterNew.version -eq $Ver) "the 1.3.1 updater copies the manifest: current\ says $Ver (exit $($f1.Exit); stage $(if ($res1) { [string]$res1.stage + ': ' + [string]$res1.reason }); $($f1.Err))"
    Assert-True ($null -ne $res1 -and $res1.ok -eq $true -and $res1.verified -eq $true -and [string]$res1.guard -eq "off" -and [string]$res1.agentSha256 -eq $NewAgentRaw) "the result says ok, verified, guard off, and names the agent hash"
    Assert-True (Test-TreeEqual (Get-Tree (Join-Path $bayF1 "releases\$Ver")) (Get-Tree (Join-Path $bayF1 "current"))) "current\ hashes equal to releases\$Ver, file for file (old-only.txt removed)"
    Assert-True ((Get-Sha (Join-Path $bayF1 "tools\Update-BayAgent.ps1")) -eq (Get-Sha (Join-Path $expRef "tools\Update-BayAgent.ps1")) -and (Test-Path -LiteralPath (Join-Path $bayF1 "tools\Keep-Me.ps1"))) "tools\ carries the new updater and keeps a tool the package does not ship"
    $snap1 = Read-Json (Join-Path $bayF1 "rollback\snapshot.json")
    Assert-True ($null -ne $snap1 -and [string]$snap1.agentSha256 -eq (Get-Sha (Join-Path $bayF1 "releases\1.2.1\BayAgent.ps1")) -and [string]$snap1.manifestVersion -eq "1.2.1") "the snapshot records what was running (old agent hash, manifest 1.2.1)"
    Assert-True (Test-TreeEqual (Get-Tree (Join-Path $bayF1 "releases\1.2.1")) (Get-Tree (Join-Path $bayF1 "rollback\current"))) "rollback\current is byte-identical to what ran"

    # F2: the hash verification is not decoration. An updater copy reduced to the 1.3.0 copy behavior (TWO lines: the
    # explicit copy disabled, and /IM dropped from robocopy -- with /IM robocopy also copies on a changed NTFS change
    # time, which on this machine is enough on its own) must fail at "verify", put back exactly what was running, and
    # say so.
    $uLinesV = [IO.File]::ReadAllLines($Updater)
    $copyLine = "    [IO.File]::Copy(`$f.FullName, `$target, `$true)"
    $roboLine = '  Invoke-Robo $src $dst @($mode, "/IS", "/IT", "/IM", "/R:5", "/W:2", "/NP") | Out-Null'
    $f2Ok = (@($uLinesV | Where-Object { $_ -eq $copyLine }).Count -eq 1 -and @($uLinesV | Where-Object { $_ -eq $roboLine }).Count -eq 1)
    Assert-True $f2Ok "(harness) the two copy lines F2 rewrites are each in the updater exactly once"
    if ($f2Ok) {
    $vLines = @($uLinesV | ForEach-Object { if ($_ -eq $copyLine) { "    # explicit copy disabled for the verify test" } elseif ($_ -eq $roboLine) { $_.Replace(', "/IM"', '') } else { $_ } })
    $vDiff = 0; for ($i = 0; $i -lt $uLinesV.Count; $i++) { if ($uLinesV[$i] -ne $vLines[$i]) { $vDiff++ } }
    Assert-True ($vDiff -eq 2) "(sanity) the verify-test updater differs from the shipped one in exactly two lines"
    $uNoCopy = Join-Path $tmp "Update-BayAgent.nocopy.ps1"
    [IO.File]::WriteAllText($uNoCopy, (($vLines -join "`r`n") + "`r`n"), (New-Object Text.UTF8Encoding($false)))
    $bayF2 = New-Bay "bayF2"
    $curBeforeF2 = Get-Tree (Join-Path $bayF2 "current")
    $f2 = Invoke-Update $uNoCopy $bayF2 @("-NoRollbackGuard")
    $res2 = Read-Json (Join-Path $bayF2 "state\last-update-result.json")
    Assert-True ($f2.Exit -ne 0 -and $null -ne $res2 -and $res2.ok -eq $false -and [string]$res2.stage -eq "verify" -and [string]$res2.reason -match "different manifest\.json") "F2 a promotion that leaves a stale file fails at 'verify' and names the file ($(if ($res2) { [string]$res2.reason }))"
    Assert-True ($null -ne $res2 -and ($res2.PSObject.Properties.Name -contains "restored") -and $res2.restored -eq $true -and (Test-TreeEqual $curBeforeF2 (Get-Tree (Join-Path $bayF2 "current")))) "F2 ...and current\ is restored, byte for byte, to what was running"
    }

    # F3: the explicit copy step does the work when robocopy will not. ONE line changed: /IM dropped, so robocopy alone
    # skips the same-size, same-time manifest exactly as on F1's bay; the install must still succeed byte-exact.
    $uLinesW = [IO.File]::ReadAllLines($Updater)
    $roboLine3 = '  Invoke-Robo $src $dst @($mode, "/IS", "/IT", "/IM", "/R:5", "/W:2", "/NP") | Out-Null'
    if (@($uLinesW | Where-Object { $_ -eq $roboLine3 }).Count -eq 1) {
        $wLines = @($uLinesW | ForEach-Object { if ($_ -eq $roboLine3) { $_.Replace(', "/IM"', '') } else { $_ } })
        $uNoIm = Join-Path $tmp "Update-BayAgent.noim.ps1"
        [IO.File]::WriteAllText($uNoIm, (($wLines -join "`r`n") + "`r`n"), (New-Object Text.UTF8Encoding($false)))
        $bayF3 = New-Bay "bayF3"
        $f3 = Invoke-Update $uNoIm $bayF3 @("-NoRollbackGuard")
        $res3 = Read-Json (Join-Path $bayF3 "state\last-update-result.json")
        $man3 = Read-Json (Join-Path $bayF3 "current\manifest.json")
        Assert-True ($f3.Exit -eq 0 -and $null -ne $res3 -and $res3.ok -eq $true -and $null -ne $man3 -and [string]$man3.version -eq $Ver -and (Test-TreeEqual (Get-Tree (Join-Path $bayF3 "releases\$Ver")) (Get-Tree (Join-Path $bayF3 "current")))) "F3 with robocopy limited to /IS /IT (which skips the manifest) the explicit copy still makes current\ byte-exact ($(if ($res3) { [string]$res3.stage + ': ' + [string]$res3.reason }))"
    } else { Assert-True $false "(harness) the robocopy line F3 rewrites is in the updater exactly once" }
    }

    # ============================================================ J R-D junction
    if (Want "J") {
    Section "J R-D: current\ is a junction into releases\1.2.1"
    $bayJ0 = New-Bay "bayJ0" -Junction
    $relBefore0 = Get-Tree (Join-Path $bayJ0 "releases\1.2.1")
    $j0 = Invoke-Update $oldUpdater $bayJ0
    Assert-True (-not (Test-TreeEqual $relBefore0 (Get-Tree (Join-Path $bayJ0 "releases\1.2.1")))) "(red control) the 1.3.0 updater's /MIR through the junction overwrote releases\1.2.1, the rollback copy"
    $bayJ1 = New-Bay "bayJ1" -Junction
    $relBefore = Get-Tree (Join-Path $bayJ1 "releases\1.2.1")
    $j1 = Invoke-Update $Updater $bayJ1 @("-NoRollbackGuard")
    Assert-True ($j1.Exit -eq 0) "the 1.3.1 updater installs over a junctioned current\ (exit $($j1.Exit); $(([string](Get-Content -LiteralPath (Join-Path $bayJ1 'state\last-update-result.json') -Raw -ErrorAction SilentlyContinue)) -replace '\s+', ' '); $($j1.Err))"
    Assert-True (Test-TreeEqual $relBefore (Get-Tree (Join-Path $bayJ1 "releases\1.2.1"))) "releases\1.2.1 is byte-identical afterwards (the link was removed, never followed)"
    Assert-True (-not (Is-Link (Join-Path $bayJ1 "current")) -and (Test-TreeEqual (Get-Tree (Join-Path $bayJ1 "releases\$Ver")) (Get-Tree (Join-Path $bayJ1 "current")))) "current\ is now a real folder holding exactly releases\$Ver"
    Assert-True (Test-TreeEqual $relBefore (Get-Tree (Join-Path $bayJ1 "rollback\current"))) "the snapshot holds what the junction pointed at"
    if ($links.Contains((Join-Path $bayJ1 "current"))) { [void]$links.Remove((Join-Path $bayJ1 "current")) }

    }

    # ============================================================ N a guard that never arms
    if (Want "N") {
    Section "N a guard that never arms: nothing is promoted"
    $bayN = New-Bay "bayN" -GuardStub "# a guard that never says it is armed`r`nexit 0`r`n"
    $curBeforeN = Get-Tree (Join-Path $bayN "current")
    $taskN = "AoC-ba131-test-" + [guid]::NewGuid().ToString("N").Substring(0, 8); $tasks.Add($taskN)
    $n = Invoke-Update $Updater $bayN @("-RequestRestart", "-GuardTaskName", $taskN, "-GuardArmTimeoutSeconds", "10")
    $resN = Read-Json (Join-Path $bayN "state\last-update-result.json")
    $penN = Read-Json (Join-Path $bayN "state\update-pending.json")
    Assert-True ($n.Exit -ne 0 -and $null -ne $resN -and $resN.ok -eq $false -and [string]$resN.stage -eq "guard" -and [string]$resN.reason -match "did not arm") "the run fails with stage 'guard' and says the guard did not arm ($([string]$resN.stage): $([string]$resN.reason))"
    Assert-True (Test-TreeEqual $curBeforeN (Get-Tree (Join-Path $bayN "current"))) "current\ is hash-identical: nothing was promoted"
    Assert-True (-not (Test-Path -LiteralPath (Join-Path $bayN "control\restart.host"))) "no restart was requested"
    Assert-True ($null -ne $penN -and [string]$penN.phase -eq "aborted") "the pending record is stood down (phase aborted)"
    $tn = $null; try { $tn = Get-ScheduledTask -TaskName $taskN -ErrorAction Stop } catch { }
    Assert-True ($null -eq $tn) "the guard task it registered is removed"

    }

    # ============================================================ U guard rules, one at a time (direct runs)
    if (Want "U") {
    Section "U guard rules (Watch-BayAgentUpdate.ps1 run directly against a sandbox)"
    function New-GuardBay([string]$name, [switch]$CurrentJunction) {
        $bay = New-Bay $name
        $cur = Join-Path $bay "current"
        # snapshot = the old current\ + old tools; then "install" a new agent into current\
        foreach ($s in @("rollback\current", "rollback\tools")) { New-Item -ItemType Directory -Force -Path (Join-Path $bay $s) | Out-Null }
        Copy-Item -Path (Join-Path $cur "*") -Destination (Join-Path $bay "rollback\current") -Recurse -Force
        Copy-Item -Path (Join-Path $bay "tools\*") -Destination (Join-Path $bay "rollback\tools") -Recurse -Force
        Write-Json (Join-Path $bay "rollback\snapshot.json") ([ordered]@{ takenUtc = (Utc (Get-Date)); forVersion = $Ver; agentSha256 = (Get-Sha (Join-Path $bay "rollback\current\BayAgent.ps1")); manifestVersion = "1.2.1"; current = (Get-Tree (Join-Path $bay "rollback\current")); tools = (Get-Tree (Join-Path $bay "rollback\tools")) })
        Remove-Item -LiteralPath $cur -Recurse -Force
        $newRel = Join-Path $bay "releases\$Ver"
        New-Item -ItemType Directory -Force -Path $newRel | Out-Null
        [IO.File]::WriteAllText((Join-Path $newRel "BayAgent.ps1"), "# new agent $name`r`n")
        [IO.File]::WriteAllText((Join-Path $newRel "manifest.json"), "{`"version`":`"$Ver`"}")
        if ($CurrentJunction) { New-Item -ItemType Junction -Path $cur -Value $newRel | Out-Null; $links.Add($cur) }
        else { New-Item -ItemType Directory -Force -Path $cur | Out-Null; Copy-Item -Path (Join-Path $newRel "*") -Destination $cur -Force }
        [IO.File]::WriteAllText((Join-Path $bay "tools\Update-BayAgent.ps1"), "# NEW updater`r`n")
        return $bay
    }
    function Write-Pending([string]$bay, [string]$id, [string]$phase, [DateTime]$promoting, [int]$timeout, [int]$soak, [int]$maxWait, [bool]$drill) {
        Write-Json (Join-Path $bay "state\update-pending.json") ([ordered]@{
            installId = $id; version = $Ver; packageUrl = $PkgUrl; phase = $phase; createdUtc = (Utc (Get-Date)); promotingUtc = (Utc $promoting)
            expectedAgentSha256 = (Get-Sha (Join-Path $bay "releases\$Ver\BayAgent.ps1")); snapshotAgentSha256 = (Get-Sha (Join-Path $bay "rollback\current\BayAgent.ps1"))
            confirmTimeoutSeconds = $timeout; soakSeconds = $soak; maxWaitSeconds = $maxWait; drill = $drill; updaterPid = 0 })
    }
    function Write-Alive([string]$bay, [string]$sha, [DateTime]$first, [DateTime]$last) {
        Write-Json (Join-Path $bay "state\agent-alive.json") ([ordered]@{ codeSha256 = $sha; codeVersion = $Ver; pid = 1; processStartUtc = (Utc $first); firstOkUtc = (Utc $first); lastOkUtc = (Utc $last); writes = 2 })
    }
    function Invoke-Guard([string]$bay, [string]$id, [string[]]$extra = @()) {
        return (Invoke-Child $Guard (@("-InstallId", $id, "-BaseDir", $bay, "-PollSeconds", "1", "-ProbeEverySeconds", "1") + $extra) 180)
    }
    function Get-GuardState([string]$bay) { return (Read-Json (Join-Path $bay "state\update-guard.json")) }

    # U1 confirmed
    $bu = New-GuardBay "u1"; $id = [guid]::NewGuid().ToString(); $t = (Get-Date).ToUniversalTime().AddSeconds(-30)
    Write-Pending $bu $id "promoted" $t 20 10 600 $false
    Write-Alive $bu (Get-Sha (Join-Path $bu "current\BayAgent.ps1")) $t.AddSeconds(5) $t.AddSeconds(20)
    $curBefore = Get-Tree (Join-Path $bu "current")
    $null = Invoke-Guard $bu $id
    $gs = Get-GuardState $bu
    Assert-True ($null -ne $gs -and [string]$gs.state -eq "confirmed") "U1 an alive record for the promoted bytes, after promotion, past the soak: confirmed ($([string]$gs.state))"
    Assert-True ((Test-TreeEqual $curBefore (Get-Tree (Join-Path $bu "current"))) -and -not (Test-Path -LiteralPath (Join-Path $bu "control\restart.host"))) "U1 ...and nothing was touched"
    Assert-True (-not (Test-Path -LiteralPath (Join-Path $bu "state\update-pending.json")) -and (Test-Path -LiteralPath (Join-Path $bu "state\update-pending.done.json"))) "U1 the pending record is retired"

    foreach ($case in @(
        @{ n = "U2"; what = "the alive record carries the OLD agent's hash"; sha = "snapshot"; firstOff = 5; lastOff = 20 },
        @{ n = "U3"; what = "the alive record was first written BEFORE promotion"; sha = "new"; firstOff = -10; lastOff = 20 },
        @{ n = "U4"; what = "the soak is not met (one process up 3 s of a 10 s soak)"; sha = "new"; firstOff = 5; lastOff = 8 })) {
        $bu = New-GuardBay ("u-" + $case.n); $id = [guid]::NewGuid().ToString(); $t = (Get-Date).ToUniversalTime().AddSeconds(-30)
        Write-Pending $bu $id "promoted" $t 4 10 600 $false
        $sha = $(if ($case.sha -eq "new") { Get-Sha (Join-Path $bu "current\BayAgent.ps1") } else { Get-Sha (Join-Path $bu "rollback\current\BayAgent.ps1") })
        Write-Alive $bu $sha $t.AddSeconds($case.firstOff) $t.AddSeconds($case.lastOff)
        $snapTree = Get-Tree (Join-Path $bu "rollback\current")
        $null = Invoke-Guard $bu $id @("-NeverPromotedSeconds", "5")
        $gs = Get-GuardState $bu
        $res = Read-Json (Join-Path $bu "state\last-update-result.json")
        Assert-True ($null -ne $gs -and [string]$gs.state -like "rollback-*" -and [string]$gs.state -ne "rollback-failed" -and (Test-TreeEqual $snapTree (Get-Tree (Join-Path $bu "current")))) "$($case.n) $($case.what): not confirmed, rolled back to the snapshot ($([string]$gs.state))"
        Assert-True ($null -ne $res -and $res.ok -eq $false -and [string]$res.stage -eq "rolled-back" -and [string]$res.version -eq $Ver -and (Test-Path -LiteralPath (Join-Path $bu "control\restart.host"))) "$($case.n) ...the rollback is recorded where the old agent reports it, and a restart is requested"
        if ($case.n -eq "U2") {
            Assert-True ((Get-Content -LiteralPath (Join-Path $bu "tools\Update-BayAgent.ps1") -Raw) -match "old updater" -and (Test-Path -LiteralPath (Join-Path $bu "tools\Keep-Me.ps1"))) "U2 ...and tools\ is restored from the snapshot (old updater back, other tools kept)"
            Assert-True ([string]$gs.state -eq "rollback-unconfirmed") "U2 ...and an old-hash alive record written BEFORE the rollback does not count as the restored agent coming back ($([string]$gs.state))"
        }
    }

    # U5 damaged snapshot: refuse to roll back
    $bu = New-GuardBay "u5"; $id = [guid]::NewGuid().ToString(); $t = (Get-Date).ToUniversalTime().AddSeconds(-30)
    Write-Pending $bu $id "promoted" $t 3 5 600 $false
    [IO.File]::AppendAllText((Join-Path $bu "rollback\current\BayAgent.ps1"), "# tampered")
    $curBefore = Get-Tree (Join-Path $bu "current")
    $null = Invoke-Guard $bu $id
    $gs = Get-GuardState $bu
    Assert-True ($null -ne $gs -and [string]$gs.state -eq "rollback-failed" -and [string]$gs.detail -match "does not match its record") "U5 a snapshot that does not hash to its record is refused: rollback-failed ($([string]$gs.detail))"
    Assert-True ((Test-TreeEqual $curBefore (Get-Tree (Join-Path $bu "current"))) -and -not (Test-Path -LiteralPath (Join-Path $bu "control\restart.host"))) "U5 ...current\ untouched, no restart"

    # U6 current\ is a junction at rollback time: link removed, target intact
    $bu = New-GuardBay "u6" -CurrentJunction; $id = [guid]::NewGuid().ToString(); $t = (Get-Date).ToUniversalTime().AddSeconds(-30)
    Write-Pending $bu $id "promoted" $t 3 5 600 $false
    $relNewBefore = Get-Tree (Join-Path $bu "releases\$Ver")
    $null = Invoke-Guard $bu $id
    $gs = Get-GuardState $bu
    Assert-True ($null -ne $gs -and [string]$gs.state -like "rollback-*" -and [string]$gs.state -ne "rollback-failed" -and -not (Is-Link (Join-Path $bu "current"))) "U6 a junctioned current\ is rolled back into a real folder ($([string]$gs.state))"
    Assert-True (Test-TreeEqual $relNewBefore (Get-Tree (Join-Path $bu "releases\$Ver"))) "U6 ...and the release the junction pointed at is byte-identical"
    if ($links.Contains((Join-Path $bu "current"))) { [void]$links.Remove((Join-Path $bu "current")) }

    # U7 unreachable cloud: never rolls back, gives up at the wall cap
    $sync["CloudDown"] = $true
    $bu = New-GuardBay "u7"; $id = [guid]::NewGuid().ToString(); $t = (Get-Date).ToUniversalTime()
    Write-Pending $bu $id "promoted" $t 3 5 8 $false
    $curBefore = Get-Tree (Join-Path $bu "current")
    $null = Invoke-Guard $bu $id
    $gs = Get-GuardState $bu
    $sync["CloudDown"] = $false
    Assert-True ($null -ne $gs -and [string]$gs.state -eq "gave-up-unreachable" -and (Test-TreeEqual $curBefore (Get-Tree (Join-Path $bu "current"))) -and -not (Test-Path -LiteralPath (Join-Path $bu "control\restart.host"))) "U7 with the cloud answering 503 the guard gives up WITHOUT rolling back ($([string]$gs.state); $([string]$gs.detail))"

    # U8 aborted before promotion; U9 never promoted; U10 foreign installId
    $bu = New-GuardBay "u8"; $id = [guid]::NewGuid().ToString()
    Write-Pending $bu $id "aborted" (Get-Date) 3 5 600 $false
    $null = Invoke-Guard $bu $id
    $gs = Get-GuardState $bu
    Assert-True ($null -ne $gs -and [string]$gs.state -eq "aborted" -and -not (Test-Path -LiteralPath (Join-Path $bu "control\restart.host"))) "U8 a pending record the updater stood down ends the guard with no action ($([string]$gs.state))"
    $bu = New-GuardBay "u9"; $id = [guid]::NewGuid().ToString()
    Write-Pending $bu $id "armed" (Get-Date) 3 5 600 $false
    $null = Invoke-Guard $bu $id @("-NeverPromotedSeconds", "3")
    $gs = Get-GuardState $bu
    Assert-True ($null -ne $gs -and [string]$gs.state -eq "never-promoted") "U9 promotion that never begins ends the guard with no action ($([string]$gs.state))"
    $bu = New-GuardBay "u10"; $id = [guid]::NewGuid().ToString()
    Write-Pending $bu $id "promoted" (Get-Date) 3 5 600 $false
    $null = Invoke-Guard $bu ([guid]::NewGuid().ToString())
    Assert-True ($null -eq (Get-GuardState $bu) -and (Test-Path -LiteralPath (Join-Path $bu "state\update-pending.json"))) "U10 a guard started for another install does nothing at all"

    # U11 the lock: a second instance exits at once
    $bu = New-GuardBay "u11"; $id = [guid]::NewGuid().ToString()
    Write-Pending $bu $id "promoted" (Get-Date).ToUniversalTime() 3 5 600 $false
    $lockFs = [IO.File]::Open((Join-Path $bu "state\update-guard.lock"), [IO.FileMode]::OpenOrCreate, [IO.FileAccess]::ReadWrite, [IO.FileShare]::None)
    try { $sw = [Diagnostics.Stopwatch]::StartNew(); $null = Invoke-Guard $bu $id; $sw.Stop() } finally { $lockFs.Dispose() }
    Assert-True ($null -eq (Get-GuardState $bu) -and $sw.Elapsed.TotalSeconds -lt 20 -and -not (Test-Path -LiteralPath (Join-Path $bu "control\restart.host"))) "U11 a second guard instance (lock held) exits without acting ($([int]$sw.Elapsed.TotalSeconds) s)"

    # U12 resume: a restarted guard continues the reachable-time count
    $bu = New-GuardBay "u12"; $id = [guid]::NewGuid().ToString(); $t = (Get-Date).ToUniversalTime().AddSeconds(-5)
    Write-Pending $bu $id "promoted" $t 30 5 600 $false
    Write-Json (Join-Path $bu "state\update-guard.json") ([ordered]@{ installId = $id; version = $Ver; state = "watching"; utc = (Utc (Get-Date)); pid = 1; armedUtc = (Utc $t); reachableSeconds = 28; detail = "" })
    $gp = New-Ps51Process ('-NoProfile -ExecutionPolicy Bypass -File "{0}" -InstallId {1} -BaseDir "{2}" -PollSeconds 1 -ProbeEverySeconds 1' -f $Guard, $id, $bu)
    $sw = [Diagnostics.Stopwatch]::StartNew(); $rolledAt = $null
    while ($sw.Elapsed.TotalSeconds -lt 60 -and $null -eq $rolledAt) {
        $gsx = Get-GuardState $bu
        if ($null -ne $gsx -and [string]$gsx.state -in @("rolling-back", "rolled-back", "rollback-confirmed", "rollback-unconfirmed")) { $rolledAt = $sw.Elapsed.TotalSeconds }
        Start-Sleep -Milliseconds 250
    }
    [void]$gp.WaitForExit(90000)
    Assert-True ($null -ne $rolledAt -and $rolledAt -lt 15) "U12 a restarted guard resumes from 28 of 30 reachable seconds instead of starting over (rolled back after $(if ($rolledAt) { [int]$rolledAt } else { 'never' }) s)"

    }

    # ============================================================ E + K: the updater and the guard together
    $eNeedleOk = (@([IO.File]::ReadAllLines($Updater) | Where-Object { $_.Contains("'-NoProfile -NonInteractive -WindowStyle Hidden -File") }).Count -eq 1)
    if ((Want "E") -and -not $SkipTaskTests -and -not $eNeedleOk) { Assert-True $false "(harness) the guard argument line E rewrites is in the updater exactly once" }
    if ($SkipTaskTests -or -not (Want "E") -or -not $eNeedleOk) {
        Write-Host ""; Write-Host "  SKIP  E and K (-SkipTaskTests, -Only, or the harness line is missing)"
    } else {
        Section "E end to end: the updater arms the real guard in its own scheduled task"
        # The ONE-line change: the sandbox guard is unsigned, so its argument line gets -ExecutionPolicy Bypass.
        $uLines = [IO.File]::ReadAllLines($Updater)
        $needle = "'-NoProfile -NonInteractive -WindowStyle Hidden -File"
        $hits = @($uLines | Where-Object { $_.Contains($needle) })
        $uCopy = Join-Path $tmp "Update-BayAgent.e2e.ps1"
        $cLines = @($uLines | ForEach-Object { $_.Replace($needle, "'-NoProfile -NonInteractive -ExecutionPolicy Bypass -WindowStyle Hidden -File") })
        [IO.File]::WriteAllText($uCopy, (($cLines -join "`r`n") + "`r`n"), (New-Object Text.UTF8Encoding($false)))
        $diffCount = 0; for ($i = 0; $i -lt $uLines.Count; $i++) { if ($uLines[$i] -ne $cLines[$i]) { $diffCount++ } }
        Assert-True ($uLines.Count -eq $cLines.Count -and $diffCount -eq 1) "(sanity) the e2e updater differs from the shipped one in exactly one line (the guard's execution policy)"

        # A fake agent: on a restart request, "restart" by consuming the marker and write alive records for whatever
        # code is now in current\ -- unless that code is in its refusal list (a new agent that never comes back).
        $fsync = [hashtable]::Synchronized(@{ Stop = $false; Bays = [hashtable]::Synchronized(@{}) })
        $frs = [runspacefactory]::CreateRunspace(); $frs.Open(); $frs.SessionStateProxy.SetVariable("fsync", $fsync)
        $fps = [powershell]::Create(); $fps.Runspace = $frs
        [void]$fps.AddScript({
            while (-not $fsync["Stop"]) {
                $keys = @()
                try { $keys = @(@($fsync["Bays"].Keys) | ForEach-Object { [string]$_ }) } catch { }
                foreach ($bay in $keys) {
                    try {
                        $mk = Join-Path $bay "control\restart.host"
                        if (-not (Test-Path -LiteralPath $mk)) { continue }
                        Remove-Item -LiteralPath $mk -Force
                        $sha = (Get-FileHash -LiteralPath (Join-Path $bay "current\BayAgent.ps1") -Algorithm SHA256).Hash.ToLowerInvariant()
                        $refused = @(); try { $refused = @($fsync["Bays"][$bay]) } catch { }
                        if ($refused -contains $sha) { continue }
                        $first = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
                        $o = [ordered]@{ codeSha256 = $sha; codeVersion = "x"; pid = 1; processStartUtc = $first; firstOkUtc = $first; lastOkUtc = $first; writes = 1 }
                        [IO.File]::WriteAllText((Join-Path $bay "state\agent-alive.json"), ($o | ConvertTo-Json))
                        Start-Sleep -Seconds 4
                        $o.lastOkUtc = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ"); $o.writes = 2
                        [IO.File]::WriteAllText((Join-Path $bay "state\agent-alive.json"), ($o | ConvertTo-Json))
                    } catch { }
                }
                Start-Sleep -Milliseconds 300
            }
        })
        $fh = $fps.BeginInvoke(); $fake = @{ PS = $fps; RS = $frs; H = $fh }

        function Wait-GuardFinal([string]$bay, [int]$sec) {
            $end = (Get-Date).AddSeconds($sec)
            do {
                $g = Read-Json (Join-Path $bay "state\update-guard.json")
                if ($null -ne $g -and [string]$g.state -in @("confirmed", "rollback-confirmed", "rollback-unconfirmed", "rollback-failed", "gave-up-unreachable", "aborted", "never-promoted", "guard-error")) { return $g }
                Start-Sleep -Milliseconds 500
            } while ((Get-Date) -lt $end)
            return (Read-Json (Join-Path $bay "state\update-guard.json"))
        }
        function Start-E2E([string]$name, [string[]]$extra, [string[]]$refuse) {
            $bay = New-Bay $name -GuardInTools
            $fsync["Bays"][$bay] = @($refuse | ForEach-Object { $_ })
            $tn = "AoC-ba131-test-" + [guid]::NewGuid().ToString("N").Substring(0, 8); $tasks.Add($tn)
            $r = Invoke-Update $uCopy $bay (@("-RequestRestart", "-GuardTaskName", $tn, "-ConfirmSoakSeconds", "3", "-GuardArmTimeoutSeconds", "60") + $extra)
            return [pscustomobject]@{ Bay = $bay; Run = $r; Task = $tn }
        }

        # E1 a new agent that comes back
        $e1 = Start-E2E "e1" @("-ConfirmTimeoutSeconds", "60") @()
        $r1 = Read-Json (Join-Path $e1.Bay "state\last-update-result.json")
        Assert-True ($e1.Run.Exit -eq 0 -and $null -ne $r1 -and $r1.ok -eq $true -and [string]$r1.guard -eq "armed" -and [string]$r1.guardNote -match "via scheduledTask|via wmi") "E1 the install completes with the guard armed ($([string]$r1.guardNote); exit $($e1.Run.Exit) $($e1.Run.Err))"
        $g1 = Wait-GuardFinal $e1.Bay 90
        Assert-True ($null -ne $g1 -and [string]$g1.state -eq "confirmed") "E1 the guard confirms the new agent ($([string]$g1.state): $([string]$g1.detail))"
        Assert-True (Test-TreeEqual (Get-Tree (Join-Path $e1.Bay "releases\$Ver")) (Get-Tree (Join-Path $e1.Bay "current"))) "E1 current\ still holds the new release"
        # the guard unregisters its task as its last act (importing the ScheduledTasks module takes a few seconds)
        $t1 = $null; $endT = (Get-Date).AddSeconds(30)
        do { Start-Sleep -Seconds 1; $t1 = $null; try { $t1 = Get-ScheduledTask -TaskName $e1.Task -ErrorAction Stop } catch { } } while ($null -ne $t1 -and (Get-Date) -lt $endT)
        Assert-True ($null -eq $t1) "E1 the guard removed its own scheduled task"

        # E2 a new agent that never comes back: rolled back, and the restored agent confirmed
        $e2 = Start-E2E "e2" @("-ConfirmTimeoutSeconds", "10") @($NewAgentRaw)
        $snapCurE2 = Get-Tree (Join-Path $e2.Bay "releases\1.2.1")
        $g2 = Wait-GuardFinal $e2.Bay 120
        $r2 = Read-Json (Join-Path $e2.Bay "state\last-update-result.json")
        Assert-True ($null -ne $g2 -and [string]$g2.state -eq "rollback-confirmed") "E2 a new agent that never proves itself is rolled back and the restored agent confirms ($([string]$g2.state): $([string]$g2.detail))"
        Assert-True (Test-TreeEqual $snapCurE2 (Get-Tree (Join-Path $e2.Bay "current"))) "E2 current\ is byte-identical to what ran before the install"
        Assert-True ((Get-Content -LiteralPath (Join-Path $e2.Bay "tools\Update-BayAgent.ps1") -Raw) -match "old updater") "E2 tools\ is restored (the old updater is back)"
        Assert-True ($null -ne $r2 -and $r2.ok -eq $false -and [string]$r2.stage -eq "rolled-back" -and [string]$r2.version -eq $Ver -and [string]$r2.reason -match "did not prove itself") "E2 last-update-result.json says rolled-back, for $Ver, and why"

        # E3 unreachable cloud after promotion: no rollback
        $sync["CloudDown"] = $true
        $e3 = Start-E2E "e3" @("-ConfirmTimeoutSeconds", "5", "-GuardMaxWaitSeconds", "20") @($NewAgentRaw)
        $g3 = Wait-GuardFinal $e3.Bay 90
        $sync["CloudDown"] = $false
        Assert-True ($null -ne $g3 -and [string]$g3.state -eq "gave-up-unreachable" -and (Test-TreeEqual (Get-Tree (Join-Path $e3.Bay "releases\$Ver")) (Get-Tree (Join-Path $e3.Bay "current")))) "E3 with the cloud unreachable the new code stays and the guard gives up without rolling back ($([string]$g3.state))"

        # E4 drill: confirmed, then rolled back on purpose
        $e4 = Start-E2E "e4" @("-ConfirmTimeoutSeconds", "60", "-RollbackDrill") @()
        $g4 = Wait-GuardFinal $e4.Bay 120
        $r4 = Read-Json (Join-Path $e4.Bay "state\last-update-result.json")
        Assert-True ($null -ne $g4 -and [string]$g4.state -eq "rollback-confirmed" -and $null -ne $r4 -and $r4.drill -eq $true -and [string]$r4.reason -match "drill") "E4 a drill confirms the new agent, rolls back on purpose and confirms the restored one ($([string]$g4.state))"

        # E5 one update at a time
        $e5bay = New-Bay "e5" -GuardInTools
        $busyId = [guid]::NewGuid().ToString()
        Write-Json (Join-Path $e5bay "state\update-pending.json") ([ordered]@{ installId = $busyId; version = "1.3.0"; phase = "promoted" })
        $sleeper = New-Ps51Process '-NoProfile -Command "Start-Sleep -Seconds 120 # Watch-BayAgentUpdate.ps1 stand-in"'
        Write-Json (Join-Path $e5bay "state\update-guard.json") ([ordered]@{ installId = $busyId; state = "watching"; pid = $sleeper.Id })
        $curBefore5 = Get-Tree (Join-Path $e5bay "current")
        # A unique, recorded task name: should the refusal ever fail (a mutation run), the install would register it.
        $tn5 = "AoC-ba131-test-" + [guid]::NewGuid().ToString("N").Substring(0, 8); $tasks.Add($tn5)
        $e5 = Invoke-Update $uCopy $e5bay @("-RequestRestart", "-GuardTaskName", $tn5)
        $r5 = Read-Json (Join-Path $e5bay "state\last-update-result.json")
        Assert-True ($e5.Exit -ne 0 -and $null -ne $r5 -and [string]$r5.stage -eq "guard-busy" -and (Test-TreeEqual $curBefore5 (Get-Tree (Join-Path $e5bay "current")))) "E5 an install while the previous install's guard is still watching is refused (guard-busy) and touches nothing ($([string]$r5.stage))"
        Stop-Process -Id $sleeper.Id -Force -ErrorAction SilentlyContinue

        # ============================================================ K the job escape
        Section "K the guard survives the end of the task its updater ran in (the HostWatchdog restart)"
        $bayK = New-Bay "k" -GuardInTools
        $tnG = "AoC-ba131-test-" + [guid]::NewGuid().ToString("N").Substring(0, 8); $tasks.Add($tnG)
        $tnOuter = "AoC-ba131-test-outer-" + [guid]::NewGuid().ToString("N").Substring(0, 8); $tasks.Add($tnOuter)
        $outer = Join-Path $tmp "outer-task.ps1"
        $sleeperPidFile = Join-Path $tmp "outer-sleeper.pid"
        # The stand-in for \ABG Bay Agent: a plain child (the control), then the updater IN THIS PROCESS (as a StartProcess
        # child of the agent would be: inside the task), then it stays alive so there is a running task to end.
        $outerText = @"
`$p = Start-Process -FilePath "$Ps51" -ArgumentList @("-NoProfile", "-Command", "Start-Sleep -Seconds 600") -PassThru -WindowStyle Hidden
Set-Content -LiteralPath "$sleeperPidFile" -Value `$p.Id
try { & "$uCopy" -Version "$Ver" -PackageUrl "$PkgUrl" -Sha256 "$ZipSha" -BaseDir "$bayK" -SignAfterInstall:`$false -RequestRestart -GuardTaskName "$tnG" -ConfirmSoakSeconds 3 -ConfirmTimeoutSeconds 90 } catch { }
Start-Sleep -Seconds 600
"@
        [IO.File]::WriteAllText($outer, $outerText)
        $act = New-ScheduledTaskAction -Execute $Ps51 -Argument ('-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File "{0}"' -f $outer)
        $prin = New-ScheduledTaskPrincipal -UserId ("{0}\{1}" -f $env:USERDOMAIN, $env:USERNAME) -LogonType Interactive -RunLevel Limited
        Register-ScheduledTask -TaskName $tnOuter -Action $act -Principal $prin -Force | Out-Null
        # the fake agent is not watching this bay until the outer task is ended, so the guard is still WATCHING then
        Start-ScheduledTask -TaskName $tnOuter
        $end = (Get-Date).AddSeconds(120)
        do { Start-Sleep -Milliseconds 500; $rk = Read-Json (Join-Path $bayK "state\last-update-result.json") } while (($null -eq $rk) -and (Get-Date) -lt $end)
        $gk0 = Read-Json (Join-Path $bayK "state\update-guard.json")
        $sleeperPid = 0; if (Test-Path -LiteralPath $sleeperPidFile) { $sleeperPid = [int](Get-Content -LiteralPath $sleeperPidFile -Raw).Trim() }
        if ($sleeperPid -gt 0) { $startedIds.Add($sleeperPid) }   # the stand-in task's plain child: this suite's to stop
        Assert-True ($null -ne $rk -and $rk.ok -eq $true -and [string]$rk.guard -eq "armed" -and $sleeperPid -gt 0) "K the install inside the stand-in agent task completed with the guard armed ($(if ($rk) { [string]$rk.guardNote }))"
        Stop-ScheduledTask -TaskName $tnOuter
        Start-Sleep -Seconds 3
        # Recorded, not asserted: whether ending a task stops its children is a property of the Windows build, and the
        # design does not depend on it (MEASURED 2026-10-07 on Windows 11 26300: the plain child survived).
        $sleeperAlive = $null -ne (Get-Process -Id $sleeperPid -ErrorAction SilentlyContinue)
        Write-Host ("  INFO  ending the stand-in agent task left a plain child it had started {0} (pid {1})" -f $(if ($sleeperAlive) { "RUNNING" } else { "STOPPED" }), $sleeperPid)
        $outerGone = $true
        try { $ot = Get-ScheduledTask -TaskName $tnOuter -ErrorAction Stop; $outerGone = ([string]$ot.State -ne "Running") } catch { }
        Assert-True ($outerGone) "K the stand-in agent task is no longer running after it was ended"
        $guardPid = 0; if ($null -ne $gk0) { $guardPid = [int]$gk0.pid }
        $guardAlive = ($guardPid -gt 0) -and ($null -ne (Get-Process -Id $guardPid -ErrorAction SilentlyContinue))
        Assert-True ($guardAlive) "K the guard (pid $guardPid) is still running after the task that launched it was ended"
        $fsync["Bays"][$bayK] = @()
        if (-not (Test-Path -LiteralPath (Join-Path $bayK "control\restart.host"))) { Set-Content -LiteralPath (Join-Path $bayK "control\restart.host") -Value "restart" }
        $gk = Wait-GuardFinal $bayK 90
        Assert-True ($null -ne $gk -and [string]$gk.state -eq "confirmed") "K ...and it finishes its job: the new agent is confirmed ($(if ($gk) { [string]$gk.state }))"
    }
}
finally {
    if ($null -ne $fake) { $fsync["Stop"] = $true; try { [void]$fake.PS.EndInvoke($fake.H) } catch {}; try { $fake.PS.Dispose(); $fake.RS.Dispose() } catch {} }
    if ($null -ne $srv) { $sync["Stop"] = $true; try { [void]$srv.PS.EndInvoke($srv.H) } catch {}; try { $srv.PS.Dispose(); $srv.RS.Dispose() } catch {} }
    foreach ($tn in $tasks) { try { Stop-ScheduledTask -TaskName $tn -ErrorAction SilentlyContinue } catch {}; try { Unregister-ScheduledTask -TaskName $tn -Confirm:$false -ErrorAction SilentlyContinue } catch {} }
    # Guards this suite started through a task or WMI: stopped by the Id each one RECORDED in its own state file, and
    # only when that Id's command line is a guard inside this sandbox (never by name or pattern alone).
    try {
        foreach ($gf in @(Get-ChildItem -LiteralPath $tmp -Recurse -Filter "update-guard.json" -ErrorAction SilentlyContinue)) {
            $gj = Read-Json $gf.FullName
            if ($null -eq $gj) { continue }
            $gpid = 0; try { $gpid = [int]$gj.pid } catch { }
            if ($gpid -le 0) { continue }
            $gproc = Get-CimInstance Win32_Process -Filter ("ProcessId={0}" -f $gpid) -ErrorAction SilentlyContinue
            if ($null -ne $gproc -and [string]$gproc.CommandLine -like ("*" + $tmp + "*") -and [string]$gproc.CommandLine -like "*Watch-BayAgentUpdate.ps1*") {
                try { Stop-Process -Id $gpid -Force -ErrorAction SilentlyContinue } catch {}
            }
        }
    } catch {}
    foreach ($id in $startedIds) { try { Stop-Process -Id $id -Force -ErrorAction SilentlyContinue } catch {} }
    foreach ($l in $links) { try { if (Test-Path -LiteralPath $l) { [IO.Directory]::Delete($l, $false) } } catch {} }
    Start-Sleep -Milliseconds 500
    try { Remove-Item -LiteralPath $tmp -Recurse -Force -ErrorAction SilentlyContinue } catch {}
}

Write-Host ""
Write-Host ("RESULT: {0} passed, {1} failed" -f $script:Pass, $script:Fail) -ForegroundColor $(if ($script:Fail -eq 0) { "Green" } else { "Red" })
if ($script:Fail -gt 0) { $script:Failures | ForEach-Object { Write-Host "  - $_" -ForegroundColor Red }; exit 1 }
exit 0
