<#
BayAgent.EStopPersist.Tests.ps1

WHY THIS EXISTS
  Verifier findings on fix/bayagent-estop-latch (R1, R2), each pinned by BEHAVIOR on Windows PowerShell 5.1 and pwsh 7:

    P1  (R1, safety) The emergency-stop latch lived only in memory, so ANY agent restart (a crash relaunch,
        RestartBayAgent, Update-BayAgent with RequestRestart, the logon relaunch after a reboot or power loss)
        released an engaged stop with no clear command, and the platform could not see it. Now the latch is written
        to state\emergency-stop.json on engage and on clear, each write confirmed by reading it back, and read at
        startup. A present-but-unreadable file reads as ENGAGED (0 bytes, whitespace, BOM only, NULs, null, {}, [],
        wrong types, missing keys, one bad field). A missing file at first install reads as not engaged.
    P2  A write that cannot be read back never releases the stop: a failed clear is refused and the latch stays.
    P3  A REAL agent restart: the shipped script is installed in a sandbox with ONE literal repointed (as the Launch
        suite does), run in a real child powershell.exe against a loopback mock of Entra and Dataverse, and the
        heartbeat it PATCHes is read off the wire. Windows only (the bays run Windows PowerShell 5.1).
    P4  (R2) While the stop is engaged, UpdateSessionDisplay, EndSession and Reset keep the EMERGENCY STOP banner in
        the session files the display reads. After the explicit clear a Reset shows READY again.

  Functions are lifted from BayAgent.ps1 with the AST and dot-sourced, so the suite tests the SHIPPED text.

RUN (from the repo root)
  powershell -NoProfile -ExecutionPolicy Bypass -File tests\BayAgent.EStopPersist.Tests.ps1
  pwsh -NoProfile -File tests/BayAgent.EStopPersist.Tests.ps1
  -AgentScript <path> runs the same assertions against a mutated copy of the agent (mutation checks).

Exit code 0 = all assertions passed. Hyphens only in comments.
#>
[CmdletBinding()]
param([string]$AgentScript = "", [int]$RunTimeoutSeconds = 90)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
try { Add-Type -AssemblyName System.Security -ErrorAction SilentlyContinue } catch {}

$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
if ([string]::IsNullOrWhiteSpace($AgentScript)) { $AgentScript = Join-Path $RepoRoot "src/BayAgent/BayAgent.ps1" }
$AgentScript = (Resolve-Path $AgentScript).Path
$ManifestSrc = Join-Path $RepoRoot "src/BayAgent/manifest.json"
$IsWin = ([Environment]::OSVersion.Platform -eq [PlatformID]::Win32NT)

$script:Pass = 0; $script:Fail = 0; $script:Failures = @()
function Assert-True([bool]$cond, [string]$msg) {
    if ($cond) { $script:Pass++; Write-Host "  PASS  $msg" }
    else { $script:Fail++; $script:Failures += $msg; Write-Host "  FAIL  $msg" -ForegroundColor Red }
}
function Section([string]$name) { Write-Host ""; Write-Host "== $name" -ForegroundColor Cyan }

$tokens = $null; $errors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile($AgentScript, [ref]$tokens, [ref]$errors)
if ($errors.Count -gt 0) { throw "BayAgent.ps1 has parse errors" }
$topFns = @($ast.EndBlock.Statements | Where-Object { $_ -is [System.Management.Automation.Language.FunctionDefinitionAst] })

$startedIds = New-Object System.Collections.Generic.List[int]
$tmp = Join-Path ([IO.Path]::GetTempPath()) ("bayagent-estoppersist-" + [Guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Force -Path $tmp | Out-Null
$mockHolder = $null
$sync = $null

function Write-Bytes([string]$path, [byte[]]$bytes) {
    $dir = Split-Path -Parent $path
    if (-not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Force -Path $dir | Out-Null }
    [IO.File]::WriteAllBytes($path, $bytes)
}
function Utf8([string]$s) { return ,([Text.Encoding]::UTF8.GetBytes($s)) }
function Join-Bytes([byte[]]$x, [byte[]]$y) {
    $out = New-Object byte[] ($x.Length + $y.Length)
    [Array]::Copy($x, 0, $out, 0, $x.Length); [Array]::Copy($y, 0, $out, $x.Length, $y.Length)
    return ,$out
}

# every damaged shape the brief names, plus the near misses. Each must read as UNREADABLE (engaged at startup).
$validEngaged = '{"engaged":true,"reason":"bench-test-stop"}'
$damaged = [ordered]@{
    "0 bytes"                         = [byte[]]@()
    "whitespace only"                 = (Utf8 "  `r`n`t ")
    "BOM only"                        = [byte[]]@(0xEF, 0xBB, 0xBF)
    "NULs only"                       = (New-Object byte[] 64)
    "NUL inside the reason"           = (Join-Bytes (Join-Bytes (Utf8 '{"engaged":true,"reason":"x') (New-Object byte[] 1)) (Utf8 'y"}'))
    "valid text then NUL tail"        = (Join-Bytes (Utf8 $validEngaged) (New-Object byte[] 16))
    "null"                            = (Utf8 "null")
    "empty object"                    = (Utf8 "{}")
    "empty array"                     = (Utf8 "[]")
    "bare true"                       = (Utf8 "true")
    "bare string"                     = (Utf8 '"engaged"')
    "not JSON"                        = (Utf8 "engaged = true")
    "truncated JSON"                  = (Utf8 '{"engaged":true,"reas')
    "missing engaged"                 = (Utf8 '{"reason":"bench-test-stop"}')
    "missing reason"                  = (Utf8 '{"engaged":true}')
    "engaged is a string"             = (Utf8 '{"engaged":"true","reason":"bench-test-stop"}')
    "engaged is a number"             = (Utf8 '{"engaged":1,"reason":"bench-test-stop"}')
    "engaged is null"                 = (Utf8 '{"engaged":null,"reason":"bench-test-stop"}')
    "engaged reason is a number"      = (Utf8 '{"engaged":true,"reason":5}')
    "engaged reason is null"          = (Utf8 '{"engaged":true,"reason":null}')
    "engaged reason is empty"         = (Utf8 '{"engaged":true,"reason":""}')
    "engaged reason is an array"      = (Utf8 '{"engaged":true,"reason":["a"]}')
    "cleared but carries a reason"    = (Utf8 '{"engaged":false,"reason":"bench-test-stop"}')
    "cleared reason is a number"      = (Utf8 '{"engaged":false,"reason":5}')
    "cleared, reason key missing"     = (Utf8 '{"engaged":false}')
}

try {
    foreach ($d in $topFns) { . ([scriptblock]::Create($d.Extent.Text)) }
    foreach ($st in @($ast.EndBlock.Statements)) {
        if ($st -is [System.Management.Automation.Language.AssignmentStatementAst] -and $st.Left.Extent.Text -match '^\$(CMD_|AGENTSTATUS_)') {
            . ([scriptblock]::Create($st.Extent.Text))
        }
    }
    $script:logged = New-Object System.Collections.Generic.List[string]
    function Write-Log { param([string]$Message, [string]$Level = "INFO") $script:logged.Add("[$Level] $Message") }
    function Start-SessionDisplay { param($payloadObj) return @{ started = $true; stub = $true } }
    # Stop-SessionDisplay looks at every msedge window by title: never let a unit test touch someone's Edge.
    function Get-Process {
        [CmdletBinding()] param([string[]]$Name, [int[]]$Id)
        if ($PSBoundParameters.ContainsKey("Name") -and ($Name -contains "msedge")) { return @() }
        Microsoft.PowerShell.Management\Get-Process @PSBoundParameters
    }
    $sessionJson = Join-Path $tmp "display\session.json"
    $cfg = [pscustomobject]@{ sessionJsonPath = $sessionJson }
    $BayId = "00000000-0000-0000-0000-000000000000"; $AgentVersion = "test"
    $Global:SessionDisplayUrl = "file:///C:/bayagent-estoppersist-test-$([Guid]::NewGuid().ToString('N'))/index.html"
    $Global:SessionDisplayProfileDir = Join-Path $tmp "edge-profile-unique"
    $Global:SessionDisplayStatePath = Join-Path $tmp "display-state.json"
    $Global:SessionDisplayProcId = $null
    $Global:NextCapabilitiesUtc = [DateTime]::MaxValue
    $statePath = Join-Path $tmp "state\emergency-stop.json"
    $Global:EmergencyStopStatePath = $statePath
    $Global:EmergencyStopPersistOk = $true
    $Global:EmergencyStopEngaged = $false
    $Global:EmergencyStopReason = $null
    # The agent's script-level running-session state (RF-K1, 2026-10-09): nobody playing, its file in this sandbox.
    $Global:RunningSession = $null; $Global:RunningSessionPending = $false; $RunningSessionPath = Join-Path $tmp "state\running-session.json"
    # Kiosk round 2: the ended-session list and the canceled-booking warning length (script-level in the agent).
    $Global:RunningSessionFinished = @(); $RunningSessionFinishedMax = 50; $RunningSessionCancelWarningSeconds = 300

    function Invoke-Cmd([int]$type, [string]$json) { return (Execute-Command -CommandType $type -PayloadJson $json -BayLabel "TestBay") }
    function Reset-Latch { $Global:EmergencyStopEngaged = $false; $Global:EmergencyStopReason = $null; $Global:EmergencyStopPersistOk = $true; $Global:EmergencyStopStatePath = $statePath }
    function Get-StateSha([string]$p) { if (Test-Path -LiteralPath $p) { return (Get-FileHash -LiteralPath $p -Algorithm SHA256).Hash } else { return "missing" } }
    function Read-StateText { if (Test-Path -LiteralPath $statePath) { return [IO.File]::ReadAllText($statePath) } else { return "" } }
    function Remove-StateFile([string]$p = $statePath) { if (Test-Path -LiteralPath $p) { Remove-Item -LiteralPath $p -Recurse -Force } }

    # ============================================================ P1 the strict reader, shape by shape
    Section "P1 the strict reader: every damaged shape is unreadable, valid shapes read"
    $ok1 = ConvertFrom-EmergencyStopStateText -Text $validEngaged
    Assert-True ($ok1.Ok -and $ok1.Engaged -eq $true -and $ok1.Reason -eq "bench-test-stop") "a valid engaged file reads engaged with its reason"
    $ok2 = ConvertFrom-EmergencyStopStateText -Text '{"engaged":false,"reason":null}'
    Assert-True ($ok2.Ok -and $ok2.Engaged -eq $false -and $null -eq $ok2.Reason) "a valid cleared file reads not engaged"
    $ok3 = ConvertFrom-EmergencyStopStateText -Text ([char]0xFEFF + $validEngaged)
    Assert-True ($ok3.Ok -and $ok3.Engaged -eq $true) "a valid file with a leading BOM still reads"
    foreach ($name in $damaged.Keys) {
        $text = [Text.Encoding]::UTF8.GetString([byte[]]$damaged[$name])
        $r = ConvertFrom-EmergencyStopStateText -Text $text
        Assert-True (-not $r.Ok) "reader: '$name' is UNREADABLE (why: $($r.Why))"
    }

    # ============================================================ P1 startup restore, shape by shape
    Section "P1 startup restore: a missing file is not engaged; every present-but-unreadable file is ENGAGED"
    Reset-Latch; Remove-StateFile
    Restore-EmergencyStopLatch
    Assert-True (($Global:EmergencyStopEngaged -eq $false) -and ($null -eq $Global:EmergencyStopReason)) "no state file (first install): not engaged"

    Reset-Latch; Write-Bytes $statePath (Utf8 '{"engaged":false,"reason":null}')
    Restore-EmergencyStopLatch
    Assert-True (($Global:EmergencyStopEngaged -eq $false) -and ($null -eq $Global:EmergencyStopReason)) "a valid cleared file: not engaged"

    Reset-Latch; Write-Bytes $statePath (Utf8 $validEngaged); $Global:NextCapabilitiesUtc = [DateTime]::MaxValue
    Restore-EmergencyStopLatch
    Assert-True ($Global:NextCapabilitiesUtc -eq [DateTime]::MinValue) "a restored latch makes the first heartbeat carry it"
    Assert-True (($Global:EmergencyStopEngaged -eq $true) -and ($Global:EmergencyStopReason -eq "bench-test-stop")) "a valid engaged file: engaged with its own reason"

    foreach ($name in $damaged.Keys) {
        Reset-Latch; Write-Bytes $statePath ([byte[]]$damaged[$name])
        $script:logged.Clear()
        Restore-EmergencyStopLatch
        Assert-True (($Global:EmergencyStopEngaged -eq $true) -and ([string]$Global:EmergencyStopReason -match "unreadable")) "startup, file is '$name': latch ENGAGED with an unreadable-state reason"
        $sl = Invoke-Cmd $CMD_SETLIGHTS '{"scene":"Active"}'
        Assert-True ($sl.ok -eq $false -and $sl.note -eq "emergency_stop_engaged") "startup, file is '$name': SetLights is refused"
    }

    Reset-Latch; Remove-StateFile; New-Item -ItemType Directory -Force -Path $statePath | Out-Null
    Restore-EmergencyStopLatch
    Assert-True (($Global:EmergencyStopEngaged -eq $true) -and ([string]$Global:EmergencyStopReason -match "unreadable")) "startup, the state path is a DIRECTORY (cannot be read): ENGAGED"
    Remove-StateFile

    # ============================================================ P2 write on engage and clear, confirmed by read-back
    Section "P2 the latch is written on engage and on clear, and each write is confirmed"
    Reset-Latch; Remove-StateFile
    $Global:NextCapabilitiesUtc = [DateTime]::MaxValue
    $r = Invoke-Cmd $CMD_EMERGENCY_STOP '{"reason":"bench-test-stop"}'
    Assert-True ($r.ok -eq $true -and $r.engaged -eq $true -and $r.persisted -eq $true) "engage reports persisted=true"
    Assert-True ($Global:NextCapabilitiesUtc -eq [DateTime]::MinValue) "an engage makes the very next heartbeat carry the capabilities (and so the stop)"
    Assert-True (Test-Path -LiteralPath $statePath) "engage wrote the state file"
    $onDisk = ConvertFrom-EmergencyStopStateText -Text ((Read-StateText))
    Assert-True ($onDisk.Ok -and $onDisk.Engaged -eq $true -and $onDisk.Reason -eq "bench-test-stop") "the file on disk reads engaged with the reason"
    $r = Invoke-Cmd $CMD_EMERGENCY_STOP '{}'
    $onDisk = ConvertFrom-EmergencyStopStateText -Text ((Read-StateText))
    Assert-True ($onDisk.Ok -and $onDisk.Engaged -eq $true -and $onDisk.Reason -eq "Emergency stop requested") "an engage with no reason persists the default reason"

    # a restart after an engage: the in-memory latch is lost, the file brings it back
    $Global:EmergencyStopEngaged = $false; $Global:EmergencyStopReason = $null
    Restore-EmergencyStopLatch
    Assert-True (($Global:EmergencyStopEngaged -eq $true) -and ($Global:EmergencyStopReason -eq "Emergency stop requested")) "after a simulated restart the engaged stop is restored with its reason"

    $Global:NextCapabilitiesUtc = [DateTime]::MaxValue
    $r = Invoke-Cmd $CMD_EMERGENCY_STOP '{"action":"clear"}'
    Assert-True ($r.ok -eq $true -and $r.engaged -eq $false) "the explicit clear is accepted"
    Assert-True ($Global:NextCapabilitiesUtc -eq [DateTime]::MinValue) "a clear makes the very next heartbeat carry the released state"
    Assert-True (Test-Path -LiteralPath $statePath) "the clear leaves a file (a missing file is reserved for first install)"
    $onDisk = ConvertFrom-EmergencyStopStateText -Text ((Read-StateText))
    Assert-True ($onDisk.Ok -and $onDisk.Engaged -eq $false -and $null -eq $onDisk.Reason) "the file on disk reads cleared"
    Restore-EmergencyStopLatch
    Assert-True (($Global:EmergencyStopEngaged -eq $false) -and ($null -eq $Global:EmergencyStopReason)) "after a clear and a simulated restart the stop stays released"

    Section "P2 a write that cannot be made durable never releases the stop"
    # engage whose save fails: still engaged in memory, reported not persisted
    Reset-Latch; Remove-StateFile
    $blockedDir = Join-Path $tmp "blocked"
    New-Item -ItemType Directory -Force -Path $blockedDir | Out-Null
    New-Item -ItemType Directory -Force -Path ($blockedDir + "\estop.json.tmp") | Out-Null   # the temp file path is a directory: the write throws
    $Global:EmergencyStopStatePath = Join-Path $blockedDir "estop.json"
    $r = Invoke-Cmd $CMD_EMERGENCY_STOP '{"reason":"bench-test-stop"}'
    Assert-True (($Global:EmergencyStopEngaged -eq $true) -and ($r.ok -eq $true) -and ($r.persisted -eq $false)) "engage with an unwritable state file: engaged anyway, persisted=false is reported"
    Assert-True ($Global:EmergencyStopPersistOk -eq $false) "the heartbeat flag says the state was not persisted"
    $r = Invoke-Cmd $CMD_EMERGENCY_STOP '{"action":"clear"}'
    Assert-True ($r.ok -eq $false -and $r.note -eq "emergency_stop_clear_not_persisted") "a clear that cannot be written is REFUSED with a coded note"
    Assert-True (($Global:EmergencyStopEngaged -eq $true) -and ($Global:EmergencyStopReason -eq "bench-test-stop")) "...and the latch is still engaged with its reason"
    $sl = Invoke-Cmd $CMD_SETLIGHTS '{"scene":"Active"}'
    Assert-True ($sl.ok -eq $false -and $sl.note -eq "emergency_stop_engaged") "...and SetLights is still refused"

    # a write that lands but does not read back: stub the reader to say unreadable
    Reset-Latch; Remove-StateFile
    $null = Invoke-Cmd $CMD_EMERGENCY_STOP '{"reason":"bench-test-stop"}'
    Assert-True ($Global:EmergencyStopEngaged -eq $true) "engaged again, state file written"
    $realReader = ${function:ConvertFrom-EmergencyStopStateText}
    function ConvertFrom-EmergencyStopStateText { param([string]$Text) return @{ Ok = $false; Engaged = $false; Reason = $null; Why = "stubbed unreadable" } }
    $r = Invoke-Cmd $CMD_EMERGENCY_STOP '{"action":"clear"}'
    Assert-True ($r.ok -eq $false -and $r.note -eq "emergency_stop_clear_not_persisted") "a clear whose write does not read back is REFUSED"
    Assert-True ($Global:EmergencyStopEngaged -eq $true) "...and the latch is still engaged"
    Set-Item -Path function:ConvertFrom-EmergencyStopStateText -Value $realReader
    $r = Invoke-Cmd $CMD_EMERGENCY_STOP '{"action":"clear"}'
    Assert-True ($r.ok -eq $true -and $Global:EmergencyStopEngaged -eq $false) "with the reader restored the clear goes through"

    # a read-back that DISAGREES with what was written (valid file, wrong content) is also a failed write
    $null = Invoke-Cmd $CMD_EMERGENCY_STOP '{"reason":"bench-test-stop"}'
    function ConvertFrom-EmergencyStopStateText { param([string]$Text) return @{ Ok = $true; Engaged = $true; Reason = "bench-test-stop"; Why = "" } }
    $r = Invoke-Cmd $CMD_EMERGENCY_STOP '{"action":"clear"}'
    Assert-True ($r.ok -eq $false -and $r.note -eq "emergency_stop_clear_not_persisted" -and $Global:EmergencyStopEngaged -eq $true) "a clear whose file reads back as still ENGAGED is refused and the latch stays"
    function ConvertFrom-EmergencyStopStateText { param([string]$Text) return @{ Ok = $true; Engaged = $true; Reason = "some other reason"; Why = "" } }
    $r = Invoke-Cmd $CMD_EMERGENCY_STOP '{"reason":"bench-test-stop"}'
    Assert-True ($r.persisted -eq $false -and $Global:EmergencyStopPersistOk -eq $false -and $Global:EmergencyStopEngaged -eq $true) "an engage whose file reads back with a different reason is reported not persisted (and stays engaged)"
    Set-Item -Path function:ConvertFrom-EmergencyStopStateText -Value $realReader
    $r = Invoke-Cmd $CMD_EMERGENCY_STOP '{"action":"clear"}'
    Assert-True ($r.ok -eq $true -and $Global:EmergencyStopEngaged -eq $false) "with the reader restored the clear goes through again"

    # a damaged file is repaired by an engage or a clear (never stuck forever)
    Reset-Latch; Write-Bytes $statePath (New-Object byte[] 8)
    Restore-EmergencyStopLatch
    Assert-True ($Global:EmergencyStopEngaged -eq $true) "a NUL-filled file restores engaged"
    $r = Invoke-Cmd $CMD_EMERGENCY_STOP '{"action":"clear"}'
    $onDisk = ConvertFrom-EmergencyStopStateText -Text ((Read-StateText))
    Assert-True ($r.ok -eq $true -and $onDisk.Ok -and $onDisk.Engaged -eq $false) "the explicit clear replaces a damaged file with a valid cleared one"
    Reset-Latch; Remove-StateFile

    # ============================================================ P4 the display banner (R2)
    Section "P4 while engaged, UpdateSessionDisplay / EndSession / Reset keep the EMERGENCY STOP banner on the display files"
    function Read-Banner {
        $m = (Get-Content -LiteralPath $sessionJson -Raw -Encoding UTF8) | ConvertFrom-Json
        $js = [IO.File]::ReadAllText([IO.Path]::ChangeExtension($sessionJson, "js"))
        function Prop($o, [string]$n) { if ($o.PSObject.Properties.Name -contains $n) { return [string]$o.$n } else { return "" } }
        return [pscustomobject]@{ Banner = (Prop $m "bannerText"); Status = (Prop $m "status"); Detail = (Prop $m "statusDetail"); JsHasStop = ($js -match "EMERGENCY STOP") }
    }
    function Assert-Banner([string]$what) {
        $b = Read-Banner
        Assert-True ($b.Banner -eq "EMERGENCY STOP" -and $b.Status -eq "STOP" -and $b.Detail -eq "bench-test-stop" -and $b.JsHasStop) "$what : the display files still say EMERGENCY STOP (banner '$($b.Banner)', status '$($b.Status)', detail '$($b.Detail)')"
    }
    Reset-Latch; Remove-StateFile
    $null = Invoke-Cmd $CMD_EMERGENCY_STOP '{"reason":"bench-test-stop"}'
    Assert-Banner "right after the stop"

    $null = Invoke-Cmd $CMD_UPDATESESSIONDISPLAY '{"status":"ACTIVE","bannerText":"","statusDetail":"In progress.","displayName":"Pat"}'
    Assert-Banner "UpdateSessionDisplay (status ACTIVE, empty banner)"
    $null = Invoke-Cmd $CMD_UPDATESESSIONDISPLAY '{"mode":"warn5"}'
    Assert-Banner "UpdateSessionDisplay (warn5)"
    $null = Invoke-Cmd $CMD_ENDSESSION '{"closeDisplay":false,"closeLauncher":false,"closeApps":false}'
    Assert-Banner "EndSession (display kept)"
    $null = Invoke-Cmd $CMD_ENDSESSION '{"closeDisplay":true,"closeLauncher":false,"closeApps":false}'
    Assert-Banner "EndSession (display closed)"
    $null = Invoke-Cmd $CMD_RESET '{}'
    Assert-Banner "default Reset (the READY banner defect)"
    $null = Invoke-Cmd $CMD_RESET '{"closeDisplay":true}'
    Assert-Banner "Reset closeDisplay=true"

    $null = Invoke-Cmd $CMD_EMERGENCY_STOP '{"action":"clear"}'
    $null = Invoke-Cmd $CMD_RESET '{}'
    $b = Read-Banner
    Assert-True ($b.Status -eq "READY" -and $b.Banner -ne "EMERGENCY STOP") "after the explicit clear a Reset shows READY again (status '$($b.Status)', banner '$($b.Banner)')"

    # ============================================================ P3 a real agent restart
    Section "P3 a REAL agent restart reads the persisted latch and reports it in the heartbeat (Windows only)"
    if (-not $IsWin) {
        Write-Host "  SKIP  the real-restart run needs Windows PowerShell 5.1 and DPAPI"
    } else {
        $TenantId = "11111111-1111-1111-1111-111111111111"; $ClientId = "22222222-2222-2222-2222-222222222222"
        $AgentBayId = "33333333-3333-3333-3333-333333333333"
        $sync = [hashtable]::Synchronized(@{
            Stop = $false; Port = 0
            Requests = [System.Collections.ArrayList]::Synchronized((New-Object System.Collections.ArrayList))
            Errors   = [System.Collections.ArrayList]::Synchronized((New-Object System.Collections.ArrayList))
        })
        $rs = [runspacefactory]::CreateRunspace(); $rs.Open()
        $rs.SessionStateProxy.SetVariable("sync", $sync)
        $psm = [powershell]::Create(); $psm.Runspace = $rs
        [void]$psm.AddScript({
            $listener = New-Object System.Net.Sockets.TcpListener([System.Net.IPAddress]::Loopback, 0)
            $listener.Start()
            $sync["Port"] = ([System.Net.IPEndPoint]$listener.LocalEndpoint).Port
            try {
                while (-not $sync["Stop"]) {
                    if (-not $listener.Server.Poll(200000, [System.Net.Sockets.SelectMode]::SelectRead)) { continue }
                    $client = $listener.AcceptTcpClient()
                    try {
                        $client.ReceiveTimeout = 5000
                        $stream = $client.GetStream()
                        $buf = New-Object byte[] 65536
                        $ms = New-Object System.IO.MemoryStream
                        $headerEnd = -1
                        while ($headerEnd -lt 0) {
                            $n = $stream.Read($buf, 0, $buf.Length)
                            if ($n -le 0) { break }
                            $ms.Write($buf, 0, $n)
                            $headerEnd = ([Text.Encoding]::ASCII.GetString($ms.ToArray())).IndexOf("`r`n`r`n")
                        }
                        $all = $ms.ToArray()
                        $headText = [Text.Encoding]::ASCII.GetString($all, 0, $headerEnd)
                        $contentLength = 0
                        if ($headText -match "(?im)^Content-Length:\s*(\d+)") { $contentLength = [int]$Matches[1] }
                        $bodyStart = $headerEnd + 4
                        while (($all.Length - $bodyStart) -lt $contentLength) {
                            $n = $stream.Read($buf, 0, $buf.Length)
                            if ($n -le 0) { break }
                            $ms.Write($buf, 0, $n)
                            $all = $ms.ToArray()
                        }
                        $body = [Text.Encoding]::UTF8.GetString($all, $bodyStart, [Math]::Min($contentLength, $all.Length - $bodyStart))
                        $reqLine = (($headText -split "`r`n")[0])
                        [void]$sync["Requests"].Add(@{ requestLine = $reqLine; body = $body })
                        $respJson = '{"token_type":"Bearer","expires_in":3599,"access_token":"mock-estop-token"}'
                        if ($reqLine -match ' /api/data/') {
                            $respJson = '{"UserId":"44444444-4444-4444-4444-444444444444","OrganizationId":"55555555-5555-5555-5555-555555555555","BusinessUnitId":"66666666-6666-6666-6666-666666666666","value":[]}'
                        }
                        $bytes = [Text.Encoding]::UTF8.GetBytes($respJson)
                        $head = "HTTP/1.1 200 OK`r`nContent-Type: application/json; charset=utf-8`r`nContent-Length: $($bytes.Length)`r`nConnection: close`r`n`r`n"
                        $hb = [Text.Encoding]::ASCII.GetBytes($head)
                        $stream.Write($hb, 0, $hb.Length); $stream.Write($bytes, 0, $bytes.Length); $stream.Flush()
                    } catch { [void]$sync["Errors"].Add($_.Exception.Message) }
                    finally { $client.Close() }
                }
            } finally { $listener.Stop() }
        })
        $mockHandle = $psm.BeginInvoke()
        $mockHolder = @{ PS = $psm; RS = $rs; Handle = $mockHandle }
        $dl = (Get-Date).AddSeconds(10)
        while ($sync["Port"] -eq 0 -and (Get-Date) -lt $dl) { Start-Sleep -Milliseconds 50 }
        if ($sync["Port"] -eq 0) { throw "mock endpoint did not start" }
        $port = [int]$sync["Port"]

        $root = Join-Path $tmp "bay"
        foreach ($sub in @("logs", "secrets", "state")) { New-Item -ItemType Directory -Force -Path (Join-Path $root $sub) | Out-Null }
        $shipped = [IO.File]::ReadAllText($AgentScript)
        $needle = '$BaseDir = "C:\AllBirdies\BayAgent"'
        if (-not $shipped.Contains($needle)) { throw "could not find the BaseDir literal in $AgentScript" }
        $agentCopy = Join-Path $root "BayAgent.ps1"
        [IO.File]::WriteAllText($agentCopy, $shipped.Replace($needle, ('$BaseDir = "{0}"' -f $root)), (New-Object Text.UTF8Encoding($false)))
        Copy-Item -LiteralPath $ManifestSrc -Destination (Join-Path $root "manifest.json") -Force
        $plain = [Text.Encoding]::UTF8.GetBytes("not-a-real-secret-" + [guid]::NewGuid().ToString("N"))
        $prot = [System.Security.Cryptography.ProtectedData]::Protect($plain, $null, [System.Security.Cryptography.DataProtectionScope]::LocalMachine)
        [IO.File]::WriteAllBytes((Join-Path $root "secrets\clientsecret.dpapi"), $prot)
        $agentCfg = [ordered]@{
            environmentUrl        = ("http://127.0.0.1:{0}" -f $port)
            tenantId              = $TenantId
            clientId              = $ClientId
            clientSecretDpapiPath = (Join-Path $root "secrets\clientsecret.dpapi")
            clientCertThumbprint  = ""
            bayId                 = $AgentBayId
            pollSeconds           = 3
            heartbeatSeconds      = 60
            tokenAuthorityHost    = ("http://127.0.0.1:{0}" -f $port)
            logLevel              = "DEBUG"
            sessionJsonPath       = (Join-Path $root "display\session.json")
            launcher              = @{ path = "C:\no-such-dir\UneekorLauncher.exe"; processName = "UneekorLauncher" }
            sessionDisplay        = @{ mode = "kiosk" }
        }
        $agentCfgPath = Join-Path $root "agent-config.json"
        [IO.File]::WriteAllText($agentCfgPath, ($agentCfg | ConvertTo-Json -Depth 5), (New-Object Text.UTF8Encoding($false)))
        $agentState = Join-Path $root "state\emergency-stop.json"

        function Invoke-RealAgentOnce {
            # One real start of the shipped script in Windows PowerShell 5.1 (-Once: one pass of the main loop, which
            # sends the first heartbeat). Returns the log text and the emergencyStop object the heartbeat PATCH carried.
            $psExe = Join-Path $env:WINDIR "System32\WindowsPowerShell\v1.0\powershell.exe"
            $sync["Requests"].Clear()
            foreach ($f in @(Get-ChildItem -LiteralPath (Join-Path $root "logs") -Filter "BayAgent-*.log" -ErrorAction SilentlyContinue)) { Remove-Item -LiteralPath $f.FullName -Force }
            $psi = New-Object System.Diagnostics.ProcessStartInfo
            $psi.FileName = $psExe
            $psi.Arguments = "-NoProfile -File `"$agentCopy`" -Once"
            $psi.UseShellExecute = $false; $psi.RedirectStandardOutput = $true; $psi.RedirectStandardError = $true; $psi.CreateNoWindow = $true
            $psi.WorkingDirectory = $root
            $proc = [System.Diagnostics.Process]::Start($psi)
            $so = $proc.StandardOutput.ReadToEndAsync(); $se = $proc.StandardError.ReadToEndAsync()
            $exited = $proc.WaitForExit($RunTimeoutSeconds * 1000)
            if (-not $exited) { try { Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue } catch {} }
            $log = ""
            foreach ($f in @(Get-ChildItem -LiteralPath (Join-Path $root "logs") -Filter "BayAgent-*.log" -ErrorAction SilentlyContinue)) { $log += [IO.File]::ReadAllText($f.FullName) }
            $es = $null
            foreach ($req in @($sync["Requests"].ToArray())) {
                if ($req.requestLine -match '^PATCH ' -and $req.body -match "build_agentcapabilitiesjson") {
                    $o = $req.body | ConvertFrom-Json
                    $cap = $o.build_agentcapabilitiesjson | ConvertFrom-Json
                    if ($cap.PSObject.Properties.Name -contains "emergencyStop") { $es = $cap.emergencyStop }
                }
            }
            $reqLines = @($sync["Requests"].ToArray() | ForEach-Object { ([string]$_.requestLine).Split(" ")[0] + " " + (([string]$_.requestLine).Split(" ")[1] -replace "\?.*$", "") }) -join " | "
            $diag = "requests=[$reqLines] mockErrors=[$(@($sync["Errors"].ToArray()) -join "; ")] logErrors=[$((@($log -split "`n" | Where-Object { $_ -match "\[(ERROR|WARN)\]" }) | Select-Object -First 3) -join " // ")]"
            return [pscustomobject]@{ Exited = $exited; ExitCode = $(if ($exited) { $proc.ExitCode } else { -1 }); Log = $log; EStop = $es; Diag = $diag }
        }

        # R1 the engage happens in THIS process (the real handler, writing the sandbox state path), then the agent restarts
        Reset-Latch; Remove-StateFile $agentState
        $Global:EmergencyStopStatePath = $agentState
        $null = Invoke-Cmd $CMD_EMERGENCY_STOP '{"reason":"bench-test-stop"}'
        Assert-True (Test-Path -LiteralPath $agentState) "an engage wrote the sandbox bay's state file"
        $hashBefore = (Get-StateSha $agentState)

        $run1 = Invoke-RealAgentOnce
        Assert-True ($run1.Exited -and $run1.ExitCode -eq 0) "restart 1: the real agent ran one pass and exited 0 (exit $($run1.ExitCode))"
        Assert-True ($run1.Log -match "restored ENGAGED after a restart: bench-test-stop") "restart 1: the agent's own log says the stop was restored ENGAGED with its reason"
        Assert-True ($null -ne $run1.EStop -and $run1.EStop.engaged -eq $true -and $run1.EStop.reason -eq "bench-test-stop" -and $run1.EStop.persisted -eq $true) "restart 1: the heartbeat the platform receives carries engaged=true and the reason ($($run1.Diag))"
        $run2 = Invoke-RealAgentOnce
        Assert-True ($run2.Exited -and $null -ne $run2.EStop -and $run2.EStop.engaged -eq $true) "restart 2 (no command in between): still engaged in the heartbeat ($($run2.Diag))"
        Assert-True ((Get-StateSha $agentState) -eq $hashBefore) "the state file is byte-identical after two restarts"

        foreach ($shape in @("0 bytes", "NULs only", "empty object", "engaged is a string")) {
            Write-Bytes $agentState ([byte[]]$damaged[$shape])
            $rd = Invoke-RealAgentOnce
            Assert-True ($rd.Exited -and $rd.Log -match "Emergency-stop state file unreadable" -and $null -ne $rd.EStop -and $rd.EStop.engaged -eq $true -and [string]$rd.EStop.reason -match "unreadable") "real restart, state file is '$shape': heartbeat says engaged and the state is unreadable ($($rd.Diag) exited=$($rd.Exited) estop=$(if ($null -eq $rd.EStop) { 'none' } else { $rd.EStop.engaged }) logHasUnreadable=$($rd.Log -match 'Emergency-stop state file unreadable'))"
        }

        Remove-StateFile $agentState
        $rm = Invoke-RealAgentOnce
        Assert-True ($rm.Exited -and $null -ne $rm.EStop -and $rm.EStop.engaged -eq $false) "real first start (no state file): heartbeat says not engaged"
        Assert-True (-not (Test-Path -LiteralPath $agentState)) "a restart does not invent a state file"

        Reset-Latch; $Global:EmergencyStopStatePath = $agentState
        $null = Invoke-Cmd $CMD_EMERGENCY_STOP '{"reason":"bench-test-stop"}'
        $null = Invoke-Cmd $CMD_EMERGENCY_STOP '{"action":"clear"}'
        $rc = Invoke-RealAgentOnce
        Assert-True ($rc.Exited -and $null -ne $rc.EStop -and $rc.EStop.engaged -eq $false) "real restart after an explicit clear: heartbeat says not engaged"
        Assert-True ($rc.Log -notmatch "Capabilities update failed") "the full capabilities document was built on these runs (no fallback needed)"

        # the full capabilities cannot be built (config has no launcher section): the stop still reaches the platform
        Reset-Latch; $Global:EmergencyStopStatePath = $agentState
        $null = Invoke-Cmd $CMD_EMERGENCY_STOP '{"reason":"bench-test-stop"}'
        $stripped = [ordered]@{}; foreach ($k in $agentCfg.Keys) { if ($k -ne "launcher") { $stripped[$k] = $agentCfg[$k] } }
        [IO.File]::WriteAllText($agentCfgPath, ($stripped | ConvertTo-Json -Depth 5), (New-Object Text.UTF8Encoding($false)))
        $rf = Invoke-RealAgentOnce
        Assert-True ($rf.Log -match "Capabilities update failed" -and $null -ne $rf.EStop -and $rf.EStop.engaged -eq $true -and $rf.EStop.reason -eq "bench-test-stop") "real restart where the full capabilities fail to build: the heartbeat still carries the engaged stop"
    }
}
finally {
    if ($null -ne $sync) { $sync["Stop"] = $true }
    if ($null -ne $mockHolder) {
        try { [void]$mockHolder.PS.EndInvoke($mockHolder.Handle) } catch {}
        try { $mockHolder.PS.Dispose(); $mockHolder.RS.Dispose() } catch {}
    }
    foreach ($id in $startedIds) { try { Stop-Process -Id $id -Force -ErrorAction SilentlyContinue } catch {} }
    try { Remove-Item -LiteralPath $tmp -Recurse -Force -ErrorAction SilentlyContinue } catch {}
}

Write-Host ""
Write-Host ("RESULT: {0} passed, {1} failed" -f $script:Pass, $script:Fail) -ForegroundColor $(if ($script:Fail -eq 0) { "Green" } else { "Red" })
if ($script:Fail -gt 0) { $script:Failures | ForEach-Object { Write-Host "  - $_" -ForegroundColor Red }; exit 1 }
exit 0
