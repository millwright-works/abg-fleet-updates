<#
ABG.KioskShell.ps1 (A0.363, BayAgent 1.4.0)

WHAT THIS IS
  The bay kiosk shell: a small supervisor that runs in the BayKiosk desktop session and keeps the bay's two
  programs where a member expects them:
    - the golf launcher, restarted after it closes ONLY while BayAgent says a session wants it, placed and
      maximized on the control screen (the touchscreen);
    - the wall display (Edge, the same profile folder BayAgent uses), kept up on the session screen (the TV).
  Design: C:\aoc-wt\reports\kiosk-shell-design-2026-10-06.md. It replaces the never-shipped ABG.LauncherShell.ps1,
  which reopened the launcher 2 s after ANY exit (free play after every session) and never placed it.

WHAT THIS RELEASE DOES AND DOES NOT DO
  This release implements COMPANION mode only: BayAgent starts this script beside Explorer (Windows keeps its normal
  desktop), so a broken shell cannot take the desktop away. Replacing Explorer (shell mode) is NOT built: nothing in
  this release writes the Winlogon Shell value anywhere, and this script never touches the registry.
  The mode is decided ONLY by current\kiosk\kiosk-policy.json, which ships inside the signed, hash-pinned fleet
  package, plus the on-site kill switch control\kiosk.off. The dormant release ships mode "explorer", so this script
  is never started by it.

RULES IT KEEPS (each one is a test)
  - It NEVER closes the launcher and never stops any process at all (EndSession closes the launcher; the self-heal
    watchdog closes a frozen one; nothing else kills anything). With one screen it moves the wall display aside
    (minimizes it) rather than closing it.
  - It restarts the launcher only while state\kiosk-intent.json says "wanted" AND the time is before its untilUtc.
    Anything unreadable, absent, expired or unknown means "not wanted".
  - It takes its program paths and screen roles from the LOCAL agent-config.json only, never from the platform.
  - Every failure ends at the Windows desktop: in companion mode Explorer is already the desktop; if this script ever
    finds no Explorer in its session it starts one, and it never exits while there is no Explorer.
  - Single instance per session; a second copy writes one log line and exits 0.
  - It writes state\kiosk-shell.json (its heartbeat, every 15 s and on every change) so BayAgent and a remote operator
    can see it; it logs state changes only, and keeps 14 days of logs.

RUN (BayAgent does this; the argument list is built by Get-KioskShellArgumentList in BayAgent.ps1)
  powershell.exe -NoProfile -NonInteractive -WindowStyle Hidden -File "<this file>" -Companion

ASCII only, hyphens only in comments (AllSigned parse failures on Bay 1, BA-15).
#>
[CmdletBinding()]
param(
    [switch]$Companion
)

# The handler of last resort calls nothing this file defines (a trap is hoisted; see BayAgent.ps1).
trap {
    $abgKsErr = $null
    try { $abgKsErr = $_.Exception.Message } catch { $abgKsErr = "unknown" }
    try {
        $abgKsLog = Get-Variable -Name KioskLogFile -ValueOnly -ErrorAction SilentlyContinue
        if ($abgKsLog) { Add-Content -Path $abgKsLog -Value ("{0} [ERROR] FATAL (pid={1}): {2}" -f (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ"), $PID, $abgKsErr) }
    } catch { }
    continue
}

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# ---------------- Paths (one literal; the launch test repoints exactly this line) ----------------
$BaseDir = "C:\AllBirdies\BayAgent"

$KioskShellCodeVersion = "1.4.0"
$KioskCfgPath       = Join-Path $BaseDir "agent-config.json"
$KioskPolicyPath    = Join-Path $BaseDir "current\kiosk\kiosk-policy.json"
$KioskKillSwitch    = Join-Path $BaseDir "control\kiosk.off"
$KioskIntentPath    = Join-Path $BaseDir "state\kiosk-intent.json"
$KioskHeartbeatPath = Join-Path $BaseDir "state\kiosk-shell.json"
$KioskLogDir        = Join-Path $BaseDir "logs"
$KioskLogFile       = Join-Path $KioskLogDir ("KioskShell-{0}.log" -f (Get-Date).ToUniversalTime().ToString("yyyyMMdd"))

# ---------------- Tunables (constants, not config: nothing outside the package can change them) ----------------
$KioskTickMs                 = 2000
$KioskHeartbeatEverySeconds  = 15
$KioskEdgeCheckEverySeconds  = 10
$KioskTopologyStableSeconds  = 10
$KioskLauncherMaxStarts      = 4      # per window below; then it holds until the window frees
$KioskLauncherStartWindowSec = 120
$KioskEdgeMaxStarts          = 3
$KioskEdgeStartWindowSec     = 300
$KioskPlaceWaitSeconds       = 15     # how long a newly started program has to show a window before placement gives up
$KioskDegradeAfterFailures   = 5      # inner failures inside the window below = degraded (supervision stops)
$KioskDegradeWindowSec       = 600
$KioskLogRetentionDays       = 14

# ============================================================================================================
# Pure helpers (lifted by AST in tests\BayAgent.Kiosk.Tests.ps1; keep them free of script state)
# ============================================================================================================

function Get-KioskProp($obj, [string]$name, $default = $null) {
    # An array value is returned AS an array (the comma): PowerShell unrolls a one-element array on return, which made
    # a policy mode of ["companion"] read as the text "companion". Every strict check downstream must see the shape.
    if ($null -eq $obj) { return $default }
    try {
        $v = $null; $found = $false
        if ($obj -is [System.Collections.IDictionary]) {
            if ($obj.Contains($name)) { $v = $obj[$name]; $found = $true }
        } else {
            $p = $obj.PSObject.Properties[$name]
            if ($null -ne $p) { $v = $p.Value; $found = $true }
        }
        if (-not $found) { return $default }
        if ($v -is [Array]) { return ,$v }
        return $v
    } catch { }
    return $default
}

function Read-KioskJsonFile([string]$Path, [int]$MaxBytes = 65536) {
    # Strict reader. @{ Ok; Obj; Why }. Absent, empty, whitespace, BOM only, NULs, too large, not JSON, or JSON that
    # is not an object (null, [], a number, a string) are all Ok=false with a reason. Never throws.
    $r = @{ Ok = $false; Obj = $null; Why = "" }
    try {
        if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { $r.Why = "absent"; return $r }
        $bytes = [IO.File]::ReadAllBytes($Path)
        if ($bytes.Length -gt $MaxBytes) { $r.Why = "larger than $MaxBytes bytes"; return $r }
        $start = 0
        if ($bytes.Length -ge 3 -and $bytes[0] -eq 0xEF -and $bytes[1] -eq 0xBB -and $bytes[2] -eq 0xBF) { $start = 3 }
        for ($i = $start; $i -lt $bytes.Length; $i++) { if ($bytes[$i] -eq 0) { $r.Why = "contains NUL bytes"; return $r } }
        $text = [Text.Encoding]::UTF8.GetString($bytes, $start, $bytes.Length - $start)
        if ([string]::IsNullOrWhiteSpace($text)) { $r.Why = "empty"; return $r }
        $t = $text.Trim()
        if (-not $t.StartsWith("{")) { $r.Why = "not a JSON object"; return $r }
        $o = $null
        try { $o = ConvertFrom-Json -InputObject $t } catch { $r.Why = "not valid JSON"; return $r }
        if ($null -eq $o -or $o -is [Array] -or $o -is [string] -or $o -is [ValueType]) { $r.Why = "not a JSON object"; return $r }
        $r.Ok = $true; $r.Obj = $o
    } catch { $r.Why = "unreadable: " + $_.Exception.Message }
    return $r
}

function ConvertTo-KioskUtc($value) {
    # ISO text (Windows PowerShell 5.1 leaves it a string) or a DateTime (PowerShell 7 converts it). Text must carry
    # its zone (Z or an offset); anything else is $null. Never throws. PowerShell 7 turns zoned text into a Utc or
    # Local DateTime and zone-less text into an Unspecified one, so Unspecified is refused like zone-less text.
    if ($null -eq $value) { return $null }
    try {
        if ($value -is [DateTime]) {
            if ($value.Kind -eq [DateTimeKind]::Local) { return $value.ToUniversalTime() }
            if ($value.Kind -eq [DateTimeKind]::Utc) { return $value }
            return $null
        }
        if ($value -isnot [string]) { return $null }
        $s = $value.Trim()
        if ($s -notmatch '^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}(:\d{2}(\.\d{1,7})?)?(Z|[+-]\d{2}:\d{2})$') { return $null }
        $dto = [DateTimeOffset]::MinValue
        if ([DateTimeOffset]::TryParse($s, [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::None, [ref]$dto)) {
            return $dto.UtcDateTime
        }
    } catch { }
    return $null
}

function Get-KioskPolicyDecision($PolicyRead, [bool]$KillSwitchPresent, [string[]]$SupportedModes = @("explorer", "companion")) {
    # The ONLY place the kiosk mode is decided. Fails toward "explorer" (today's Windows desktop) for every shape that
    # is not exactly a known schema-1 policy naming a mode this code implements.
    $d = @{ Mode = "explorer"; Requested = $null; Reason = ""; MinShellBytes = 4096 }
    if ($KillSwitchPresent) { $d.Reason = "kill switch present (control\kiosk.off)"; return $d }
    if ($null -eq $PolicyRead -or -not $PolicyRead.Ok) {
        $why = $(if ($null -ne $PolicyRead) { [string]$PolicyRead.Why } else { "no read" })
        $d.Reason = "policy unreadable ($why)"; return $d
    }
    $o = $PolicyRead.Obj
    $schema = Get-KioskProp $o "schema" $null
    if (-not ($schema -is [int] -or $schema -is [long]) -or [int64]$schema -lt 1) { $d.Reason = "policy schema missing or not a positive integer"; return $d }
    $mode = Get-KioskProp $o "mode" $null
    if ($mode -isnot [string]) { $d.Reason = "policy mode missing or not text"; return $d }
    $d.Requested = $mode
    if ($mode -cnotin @("explorer", "companion", "shell")) { $d.Reason = "policy mode '$mode' is unknown"; return $d }
    $min = Get-KioskProp $o "minShellBytes" 4096
    if (-not ($min -is [int] -or $min -is [long]) -or [int64]$min -lt 1024 -or [int64]$min -gt 1048576) { $d.Reason = "policy minShellBytes missing or outside 1024..1048576"; return $d }
    $d.MinShellBytes = [int]$min
    if ($mode -cnotin $SupportedModes) { $d.Reason = "policy mode '$mode' is not implemented by this release"; return $d }
    $d.Mode = $mode
    $d.Reason = "policy"
    return $d
}

function Get-KioskLauncherWanted($IntentRead, [DateTime]$NowUtc) {
    # "Wanted" only for a readable intent whose launcher field is exactly "wanted" and whose untilUtc (with its zone)
    # is in the future. Any other shape is "not wanted" and says why. Newer schemas are read by field name.
    $w = @{ Wanted = $false; Reason = ""; UntilUtc = $null; SessionId = $null }
    if ($null -eq $IntentRead -or -not $IntentRead.Ok) {
        $why = $(if ($null -ne $IntentRead) { [string]$IntentRead.Why } else { "no read" })
        $w.Reason = "intent unreadable ($why)"; return $w
    }
    $o = $IntentRead.Obj
    $schema = Get-KioskProp $o "schema" $null
    if (-not ($schema -is [int] -or $schema -is [long]) -or [int64]$schema -lt 1) { $w.Reason = "intent schema missing or not a positive integer"; return $w }
    $sid = Get-KioskProp $o "baySessionId" $null
    if ($sid -is [string]) { $w.SessionId = $sid }
    $l = Get-KioskProp $o "launcher" $null
    if ($l -isnot [string] -or $l -cne "wanted") { $w.Reason = "intent says not wanted"; return $w }
    $until = ConvertTo-KioskUtc (Get-KioskProp $o "untilUtc" $null)
    if ($null -eq $until) { $w.Reason = "intent untilUtc missing or without a zone"; return $w }
    $w.UntilUtc = $until
    if ($NowUtc -ge $until) { $w.Reason = "intent expired"; return $w }
    $w.Wanted = $true
    $w.Reason = "intent wanted"
    return $w
}

function Get-KioskCountInWindow([DateTime[]]$Times, [DateTime]$NowUtc, [int]$WindowSeconds) {
    $cut = $NowUtc.AddSeconds(-1 * $WindowSeconds)
    return @(@($Times) | Where-Object { $_ -gt $cut }).Count
}

function Test-KioskStartAllowed([DateTime[]]$Times, [DateTime]$NowUtc, [int]$WindowSeconds, [int]$MaxStarts) {
    return ((Get-KioskCountInWindow -Times $Times -NowUtc $NowUtc -WindowSeconds $WindowSeconds) -lt $MaxStarts)
}

function Get-KioskDegradeVerdict([DateTime[]]$Failures, [DateTime]$NowUtc, [int]$WindowSeconds, [int]$Threshold) {
    return ((Get-KioskCountInWindow -Times $Failures -NowUtc $NowUtc -WindowSeconds $WindowSeconds) -ge $Threshold)
}

function Resolve-KioskSelector($Selector, $Screens) {
    # Same selector forms BayAgent accepts: a device name, the DISPLAYn shorthand, a numeric index, or text found in the
    # monitor's description. $null when nothing matches.
    if ($null -eq $Selector) { return $null }
    $list = @($Screens)
    if ($Selector -is [int] -or $Selector -is [long]) {
        $i = [int]$Selector
        if ($i -ge 0 -and $i -lt $list.Count) { return $list[$i] }
        return $null
    }
    $sel = ([string]$Selector).Trim()
    if ([string]::IsNullOrWhiteSpace($sel)) { return $null }
    foreach ($s in $list) { if ([string]$s.DeviceName -ieq $sel) { return $s } }
    if ($sel -match '^DISPLAY\d+$') { foreach ($s in $list) { if ([string]$s.DeviceName -ieq ("\\.\" + $sel)) { return $s } } }
    foreach ($s in $list) {
        $desc = [string](Get-KioskProp $s "MonitorName" "")
        if (-not [string]::IsNullOrWhiteSpace($desc) -and $desc.IndexOf($sel, [StringComparison]::OrdinalIgnoreCase) -ge 0) { return $s }
    }
    return $null
}

function Resolve-KioskRoleScreens($Screens, $ControlSelector, $SessionSelector) {
    # @{ Control; Session; Count }. Control: its selector, else the primary screen (the touchscreen on Bay 1), else the
    # first. Session: its selector when that is not the control screen, else the last screen that is not the control
    # screen; with one screen, that screen (the single-screen rule decides whether the wall may use it).
    $list = @($Screens)
    $out = @{ Control = $null; Session = $null; Count = $list.Count }
    if ($list.Count -eq 0) { return $out }
    $c = Resolve-KioskSelector $ControlSelector $list
    if ($null -eq $c) { foreach ($s in $list) { if ([bool](Get-KioskProp $s "Primary" $false)) { $c = $s; break } } }
    if ($null -eq $c) { $c = $list[0] }
    $out.Control = $c
    if ($list.Count -eq 1) { $out.Session = $list[0]; return $out }
    $s2 = Resolve-KioskSelector $SessionSelector $list
    if ($null -ne $s2 -and [string]$s2.DeviceName -ieq [string]$c.DeviceName) { $s2 = $null }
    if ($null -eq $s2) {
        $others = @($list | Where-Object { [string]$_.DeviceName -ine [string]$c.DeviceName })
        if ($others.Count -gt 0) { $s2 = $others[$others.Count - 1] }
    }
    $out.Session = $s2
    return $out
}

function Get-KioskTopologySignature($Screens) {
    $parts = @()
    foreach ($s in @($Screens)) {
        $parts += ("{0}|{1}|{2},{3},{4}x{5}" -f $s.DeviceName, $(if ([bool](Get-KioskProp $s "Primary" $false)) { "P" } else { "" }), $s.Left, $s.Top, $s.Width, $s.Height)
    }
    return (($parts | Sort-Object) -join ";")
}

function Get-KioskWallPlan([int]$ScreenCount, [bool]$LauncherWanted, [bool]$WallEnabled) {
    # What the wall display (Edge) should do. "show": keep it up on the session screen. "aside": one screen and the
    # member needs the launcher, so the wall must not cover it (never started; minimized if running). "none": no
    # screen at all, or the wall is switched off locally: start nothing, move nothing.
    if (-not $WallEnabled) { return "none" }
    if ($ScreenCount -le 0) { return "none" }
    if ($ScreenCount -eq 1 -and $LauncherWanted) { return "aside" }
    return "show"
}

function Get-KioskSupervision([bool]$CompanionRole, $PolicyDecision, [bool]$Degraded) {
    # Supervise only when started as the companion, the policy says companion, and the shell has not degraded.
    if (-not $CompanionRole) { return @{ Supervise = $false; Reason = "not started as the companion (this release has no shell mode)" } }
    if ($Degraded) { return @{ Supervise = $false; Reason = "degraded" } }
    if ($null -eq $PolicyDecision -or [string]$PolicyDecision.Mode -cne "companion") {
        $why = $(if ($null -ne $PolicyDecision) { "mode " + [string]$PolicyDecision.Mode + ": " + [string]$PolicyDecision.Reason } else { "no policy decision" })
        return @{ Supervise = $false; Reason = $why }
    }
    return @{ Supervise = $true; Reason = "companion" }
}

function Get-KioskFloorAction([bool]$CompanionRole, [bool]$Supervise, [bool]$ExplorerPresent, [bool]$PolicyWantsCompanion) {
    # The desktop floor. Never exit while there is no Explorer in this session: start one instead. A companion exits
    # only when the policy no longer asks for one AND Explorer is there. A degraded companion the policy still wants
    # idles (exiting would only be restarted by BayAgent). Anything else idles: a Windows shell that exits may sign the
    # user out, and a sign-out leaves the bay dark until a reboot (2026-10-04).
    if ($Supervise) { return "supervise" }
    if (-not $ExplorerPresent) { return "start-explorer" }
    if ($CompanionRole -and -not $PolicyWantsCompanion) { return "exit" }
    return "idle"
}

function Get-KioskLauncherAction([bool]$Wanted, [bool]$Running, [int]$AbsentTicks, [bool]$StartAllowed, [bool]$PathExists) {
    # Start only after the launcher has been seen absent on two ticks in a row (2 to 4 s; a member who closes it gets it
    # back, and a program that is just replacing its own process is not doubled). Never "stop": this shell closes
    # nothing.
    if (-not $Wanted) { return "none" }
    if ($Running) { return "none" }
    if (-not $PathExists) { return "missing" }
    if ($AbsentTicks -lt 2) { return "wait" }
    if (-not $StartAllowed) { return "held" }
    return "start"
}

# ============================================================================================================
# Side-effecting helpers
# ============================================================================================================

$script:KioskLastLogged = @{}

function Write-KioskLog([string]$Message, [string]$Level = "INFO", [string]$Key = "") {
    # State changes only: with a key, the same message under the same key is written once until it changes.
    try {
        if (-not [string]::IsNullOrWhiteSpace($Key)) {
            if ($script:KioskLastLogged.ContainsKey($Key) -and $script:KioskLastLogged[$Key] -eq $Message) { return }
            $script:KioskLastLogged[$Key] = $Message
        }
        $ts = (Get-Date).ToUniversalTime()
        $file = Join-Path $KioskLogDir ("KioskShell-{0}.log" -f $ts.ToString("yyyyMMdd"))
        Add-Content -Path $file -Value ("{0} [{1}] {2}" -f $ts.ToString("yyyy-MM-ddTHH:mm:ssZ"), $Level, $Message)
    } catch { }
}

function Remove-KioskOldLogs([string]$Dir, [int]$Days, [DateTime]$NowUtc) {
    try {
        $cut = $NowUtc.AddDays(-1 * $Days)
        foreach ($f in @(Get-ChildItem -LiteralPath $Dir -Filter "KioskShell-*.log" -File -ErrorAction SilentlyContinue)) {
            if ($f.LastWriteTimeUtc -lt $cut) { Remove-Item -LiteralPath $f.FullName -Force -ErrorAction SilentlyContinue }
        }
    } catch { }
}

function Write-KioskJsonAtomic([string]$Path, $Obj) {
    $dir = Split-Path -Parent $Path
    if (-not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Force -Path $dir | Out-Null }
    $tmp = "$Path.tmp"
    [IO.File]::WriteAllText($tmp, (ConvertTo-Json -InputObject $Obj -Depth 8), (New-Object Text.UTF8Encoding($false)))
    try {
        if (Test-Path -LiteralPath $Path) { [IO.File]::Replace($tmp, $Path, [NullString]::Value, $true) }
        else { [IO.File]::Move($tmp, $Path) }
    } catch {
        [IO.File]::Copy($tmp, $Path, $true)
        try { [IO.File]::Delete($tmp) } catch { }
    }
}

function Get-KioskFileSha256([string]$Path) {
    try {
        $alg = [System.Security.Cryptography.SHA256]::Create()
        $fs = [IO.File]::OpenRead($Path)
        try { return ([BitConverter]::ToString($alg.ComputeHash($fs)) -replace "-", "").ToLowerInvariant() }
        finally { $fs.Dispose(); $alg.Dispose() }
    } catch { return $null }
}

function Read-KioskLocalConfig([string]$Path) {
    # The LOCAL agent-config.json, never the platform overlay (I6). Missing or unreadable: defaults, and it says so.
    $c = [ordered]@{
        Source           = "defaults"
        LauncherPath     = "C:\Uneekor\Launcher\UneekorLauncher.exe"
        LauncherArgs     = ""
        LauncherName     = "UneekorLauncher"
        WallEnabled      = $true
        EdgePath         = ""
        WallUrl          = "file:///C:/AllBirdies/SessionDisplay/current/index.html"
        ProfileDir       = "C:\AllBirdies\SessionDisplay\edge-profile"
        WallMode         = "kiosk"
        ControlSelector  = $null
        SessionSelector  = $null
    }
    $read = Read-KioskJsonFile -Path $Path -MaxBytes 262144
    if (-not $read.Ok) { $c.Source = "defaults (agent-config.json " + $read.Why + ")"; return $c }
    $c.Source = "agent-config.json"
    $o = $read.Obj
    $l = Get-KioskProp $o "launcher" $null
    $v = Get-KioskProp $l "path" $null; if ($v -is [string] -and -not [string]::IsNullOrWhiteSpace($v)) { $c.LauncherPath = $v.Trim() }
    $v = Get-KioskProp $l "args" $null; if ($v -is [string]) { $c.LauncherArgs = $v }
    $v = Get-KioskProp $l "processName" $null; if ($v -is [string] -and -not [string]::IsNullOrWhiteSpace($v)) { $c.LauncherName = [IO.Path]::GetFileNameWithoutExtension($v.Trim()) }
    $sd = Get-KioskProp $o "sessionDisplay" $null
    $v = Get-KioskProp $sd "enabled" $null; if ($v -is [bool]) { $c.WallEnabled = $v }
    $v = Get-KioskProp $sd "edgePath" $null; if ($v -is [string] -and -not [string]::IsNullOrWhiteSpace($v)) { $c.EdgePath = $v.Trim() }
    $v = Get-KioskProp $sd "url" $null; if ($v -is [string] -and -not [string]::IsNullOrWhiteSpace($v)) { $c.WallUrl = $v.Trim() }
    $v = Get-KioskProp $sd "profileDir" $null; if ($v -is [string] -and -not [string]::IsNullOrWhiteSpace($v)) { $c.ProfileDir = $v.Trim() }
    $v = Get-KioskProp $sd "mode" $null; if ($v -is [string] -and -not [string]::IsNullOrWhiteSpace($v)) { $c.WallMode = $v.Trim().ToLowerInvariant() }
    $dr = Get-KioskProp $o "displayRouting" $null
    $en = Get-KioskProp $dr "enabled" $true
    if ($en -isnot [bool] -or $en) {
        $roles = Get-KioskProp $dr "roles" $null
        foreach ($pair in @(@("control", "ControlSelector"), @("session", "SessionSelector"))) {
            $ro = Get-KioskProp $roles $pair[0] $null
            $sel = Get-KioskProp $ro "selector" $null
            if ($null -eq $sel) { $sel = Get-KioskProp $ro "deviceName" $null }
            if ($null -eq $sel) { $sel = Get-KioskProp $ro "index" $null }
            $c[$pair[1]] = $sel
        }
    }
    return $c
}

function Get-KioskEdgePath([string]$Configured) {
    if (-not [string]::IsNullOrWhiteSpace($Configured)) { return $Configured }
    foreach ($p in @("C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe", "C:\Program Files\Microsoft\Edge\Application\msedge.exe")) {
        if (Test-Path -LiteralPath $p) { return $p }
    }
    return $null
}

function Get-KioskWallArgumentLine($Cfg, $Bounds) {
    # The same shape BayAgent's Start-SessionDisplay uses, so either side finds the other's window by profile folder.
    $a = "--allow-file-access-from-files --user-data-dir=" + $Cfg.ProfileDir + " --no-first-run --no-default-browser-check "
    if ($null -ne $Bounds) { $a += ("--window-position={0},{1} --window-size={2},{3} " -f $Bounds.Left, $Bounds.Top, $Bounds.Width, $Bounds.Height) }
    if ($Cfg.WallMode -eq "kiosk") { $a += ('--kiosk "' + $Cfg.WallUrl + '" --edge-kiosk-type=fullscreen --kiosk-idle-timeout-minutes=0') }
    else { $a += ('--app="' + $Cfg.WallUrl + '" --start-fullscreen') }
    return $a
}

if (-not ("ABGKioskNative" -as [type])) {
Add-Type @"
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;

public static class ABGKioskNative {
    [StructLayout(LayoutKind.Sequential)]
    public struct RECT { public int Left; public int Top; public int Right; public int Bottom; }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct MONITORINFOEX {
        public int cbSize; public RECT rcMonitor; public RECT rcWork; public uint dwFlags;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 32)] public string szDevice;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct DISPLAY_DEVICE {
        public int cb;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 32)] public string DeviceName;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 128)] public string DeviceString;
        public int StateFlags;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 128)] public string DeviceID;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 128)] public string DeviceKey;
    }

    public delegate bool MonitorEnumProc(IntPtr hMonitor, IntPtr hdc, IntPtr lprcMonitor, IntPtr dwData);
    public delegate bool EnumWindowsProc(IntPtr hWnd, IntPtr lParam);

    [DllImport("user32.dll")] static extern bool EnumDisplayMonitors(IntPtr hdc, IntPtr lprcClip, MonitorEnumProc lpfnEnum, IntPtr dwData);
    [DllImport("user32.dll", CharSet = CharSet.Unicode)] static extern bool GetMonitorInfo(IntPtr hMonitor, ref MONITORINFOEX lpmi);
    [DllImport("user32.dll", CharSet = CharSet.Unicode)] static extern bool EnumDisplayDevices(string lpDevice, uint iDevNum, ref DISPLAY_DEVICE lpDisplayDevice, uint dwFlags);
    [DllImport("user32.dll")] static extern IntPtr MonitorFromWindow(IntPtr hwnd, uint dwFlags);
    [DllImport("user32.dll")] static extern bool EnumWindows(EnumWindowsProc lpEnumFunc, IntPtr lParam);
    [DllImport("user32.dll")] static extern uint GetWindowThreadProcessId(IntPtr hWnd, out uint lpdwProcessId);
    [DllImport("user32.dll")] static extern bool IsWindowVisible(IntPtr hWnd);
    [DllImport("user32.dll")] static extern IntPtr GetWindow(IntPtr hWnd, uint uCmd);
    [DllImport("user32.dll")] public static extern bool IsZoomed(IntPtr hWnd);
    [DllImport("user32.dll")] public static extern bool IsIconic(IntPtr hWnd);
    [DllImport("user32.dll")] public static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);
    [DllImport("user32.dll")] public static extern bool SetWindowPos(IntPtr hWnd, IntPtr hWndInsertAfter, int X, int Y, int cx, int cy, uint uFlags);
    [DllImport("user32.dll")] public static extern bool GetWindowRect(IntPtr hWnd, out RECT rect);

    public sealed class MonitorRow {
        public string DeviceName; public bool Primary; public int Left; public int Top; public int Width; public int Height; public string MonitorName;
    }

    static string MonitorNameFor(string deviceName) {
        try {
            DISPLAY_DEVICE dd = new DISPLAY_DEVICE();
            dd.cb = Marshal.SizeOf(typeof(DISPLAY_DEVICE));
            if (EnumDisplayDevices(deviceName, 0, ref dd, 0)) { return dd.DeviceString; }
        } catch { }
        return null;
    }

    static MonitorRow Describe(IntPtr hMonitor) {
        MONITORINFOEX mi = new MONITORINFOEX();
        mi.cbSize = Marshal.SizeOf(typeof(MONITORINFOEX));
        if (!GetMonitorInfo(hMonitor, ref mi)) { return null; }
        MonitorRow r = new MonitorRow();
        r.DeviceName = mi.szDevice;
        r.Primary = (mi.dwFlags & 1) != 0;
        r.Left = mi.rcMonitor.Left; r.Top = mi.rcMonitor.Top;
        r.Width = mi.rcMonitor.Right - mi.rcMonitor.Left; r.Height = mi.rcMonitor.Bottom - mi.rcMonitor.Top;
        r.MonitorName = MonitorNameFor(mi.szDevice);
        return r;
    }

    // Asked fresh on every call: a cached screen list goes stale after a cable pull (S4).
    public static List<MonitorRow> GetMonitors() {
        List<MonitorRow> list = new List<MonitorRow>();
        MonitorEnumProc cb = delegate (IntPtr h, IntPtr hdc, IntPtr rc, IntPtr data) {
            MonitorRow row = Describe(h);
            if (row != null) { list.Add(row); }
            return true;
        };
        EnumDisplayMonitors(IntPtr.Zero, IntPtr.Zero, cb, IntPtr.Zero);
        GC.KeepAlive(cb);
        return list;
    }

    public static string MonitorDeviceForWindow(IntPtr hwnd) {
        IntPtr h = MonitorFromWindow(hwnd, 2);
        if (h == IntPtr.Zero) { return null; }
        MonitorRow r = Describe(h);
        return r == null ? null : r.DeviceName;
    }

    // The first visible top-level window (no owner) of any of the given process ids, or zero.
    public static IntPtr FirstVisibleWindow(int[] pids) {
        HashSet<uint> want = new HashSet<uint>();
        foreach (int p in pids) { want.Add((uint)p); }
        IntPtr found = IntPtr.Zero;
        EnumWindowsProc cb = delegate (IntPtr h, IntPtr l) {
            if (!IsWindowVisible(h)) { return true; }
            if (GetWindow(h, 4) != IntPtr.Zero) { return true; }
            uint owner;
            GetWindowThreadProcessId(h, out owner);
            if (want.Contains(owner)) { found = h; return false; }
            return true;
        };
        EnumWindows(cb, IntPtr.Zero);
        GC.KeepAlive(cb);
        return found;
    }
}
"@
}

function Get-KioskScreens {
    $out = @()
    foreach ($m in @([ABGKioskNative]::GetMonitors())) {
        $out += [pscustomobject]@{ DeviceName = [string]$m.DeviceName; Primary = [bool]$m.Primary; Left = [int]$m.Left; Top = [int]$m.Top; Width = [int]$m.Width; Height = [int]$m.Height; MonitorName = [string]$m.MonitorName }
    }
    return $out
}

function Get-KioskOwnSessionId { return [System.Diagnostics.Process]::GetCurrentProcess().SessionId }

function Get-KioskProcessesInSession([string]$Name, [int]$SessionId) {
    if ([string]::IsNullOrWhiteSpace($Name)) { return @() }
    return @(Get-Process -Name $Name -ErrorAction SilentlyContinue | Where-Object { $_.SessionId -eq $SessionId })
}

function Get-KioskWallPids([string]$ProfileDir) {
    # Edge processes whose command line names the wall's profile folder (the same match BayAgent uses).
    $ids = @()
    if ([string]::IsNullOrWhiteSpace($ProfileDir)) { return @() }
    try {
        foreach ($p in @(Get-CimInstance Win32_Process -Filter "Name='msedge.exe'" -OperationTimeoutSec 3 -ErrorAction SilentlyContinue)) {
            $cl = [string]$p.CommandLine
            if ($cl.IndexOf($ProfileDir, [StringComparison]::OrdinalIgnoreCase) -ge 0) { $ids += [int]$p.ProcessId }
        }
    } catch { }
    return $ids
}

function Get-KioskWallPidsByExe([string]$ExePath, [string]$ProfileDir) {
    # A configured wall program that is not msedge.exe (the launch test's stand-in) is matched the same way, by name.
    $leaf = [IO.Path]::GetFileName($ExePath)
    if ([string]::IsNullOrWhiteSpace($leaf) -or $leaf -ieq "msedge.exe") { return @(Get-KioskWallPids $ProfileDir) }
    $ids = @()
    try {
        foreach ($p in @(Get-CimInstance Win32_Process -Filter ("Name='{0}'" -f $leaf.Replace("'", "")) -OperationTimeoutSec 3 -ErrorAction SilentlyContinue)) {
            $cl = [string]$p.CommandLine
            if ($cl.IndexOf($ProfileDir, [StringComparison]::OrdinalIgnoreCase) -ge 0) { $ids += [int]$p.ProcessId }
        }
    } catch { }
    return $ids
}

function Test-KioskWindowCovers($Rect, $Screen) {
    return ($Rect.Left -le $Screen.Left -and $Rect.Top -le $Screen.Top -and $Rect.Right -ge ($Screen.Left + $Screen.Width) -and $Rect.Bottom -ge ($Screen.Top + $Screen.Height))
}

function Set-KioskWindowPlacement([int[]]$Pids, $Screen, [switch]$Maximize, [switch]$Aside, [switch]$CoverOnly) {
    # Moves the first visible window of these processes onto $Screen, or minimizes it when -Aside. Acts only when the
    # window is NOT already where it should be, so it never loops or steals focus twice. Returns @{ Done; Why; Device }.
    #   -Maximize   the launcher: restore, move, maximize (what BayAgent's routing does).
    #   -CoverOnly  the wall: a full-screen kiosk window is not "maximized" to Windows, and restoring it could take it
    #               out of full screen, so it counts as placed when it covers the target screen, and is only moved.
    $hw = [ABGKioskNative]::FirstVisibleWindow([int[]]@($Pids))
    if ($hw -eq [IntPtr]::Zero) { return @{ Done = $false; Why = "no window yet" } }
    if ($Aside) {
        if ([ABGKioskNative]::IsIconic($hw)) { return @{ Done = $true; Why = "already aside" } }
        [void][ABGKioskNative]::ShowWindow($hw, 6)
        return @{ Done = $true; Why = "moved aside (minimized)" }
    }
    if ($null -eq $Screen) { return @{ Done = $false; Why = "no target screen" } }
    $dev = [ABGKioskNative]::MonitorDeviceForWindow($hw)
    $iconic = [ABGKioskNative]::IsIconic($hw)
    $rect = New-Object ABGKioskNative+RECT
    [void][ABGKioskNative]::GetWindowRect($hw, [ref]$rect)
    $onTarget = (-not $iconic -and $dev -ieq [string]$Screen.DeviceName)
    if ($CoverOnly) {
        if ($onTarget -and (Test-KioskWindowCovers $rect $Screen)) { return @{ Done = $true; Why = "already placed"; Device = $dev } }
        if ($iconic) { [void][ABGKioskNative]::ShowWindow($hw, 9) }
        [void][ABGKioskNative]::SetWindowPos($hw, [IntPtr]::Zero, [int]$Screen.Left, [int]$Screen.Top, [int]$Screen.Width, [int]$Screen.Height, [uint32](0x0004 -bor 0x0010 -bor 0x0040))
        return @{ Done = $true; Why = "placed"; Device = [ABGKioskNative]::MonitorDeviceForWindow($hw) }
    }
    if ($onTarget -and (-not $Maximize -or [ABGKioskNative]::IsZoomed($hw))) {
        return @{ Done = $true; Why = "already placed"; Device = $dev }
    }
    [void][ABGKioskNative]::ShowWindow($hw, 9)
    [void][ABGKioskNative]::SetWindowPos($hw, [IntPtr]::Zero, [int]$Screen.Left, [int]$Screen.Top, [int]$Screen.Width, [int]$Screen.Height, [uint32](0x0004 -bor 0x0010 -bor 0x0040))
    if ($Maximize) { [void][ABGKioskNative]::ShowWindow($hw, 3) }
    return @{ Done = $true; Why = "placed"; Device = [ABGKioskNative]::MonitorDeviceForWindow($hw) }
}

# ============================================================================================================
# The supervisor
# ============================================================================================================

function New-KioskState {
    return @{
        StartUtc          = (Get-Date).ToUniversalTime()
        SessionId         = (Get-KioskOwnSessionId)
        Sha256            = (Get-KioskFileSha256 $PSCommandPath)
        Cfg               = $null
        CfgReadUtc        = [DateTime]::MinValue
        Policy            = $null
        Supervise         = $null
        Wanted            = $null
        LauncherAbsent    = 0
        LauncherStarts    = [DateTime[]]@()
        LauncherPid       = $null
        LauncherPlaceUntil = $null
        LauncherPlacedSig = ""
        WallPids          = @()
        WallRunning       = $false
        WallStarts        = [DateTime[]]@()
        WallCheckedUtc    = [DateTime]::MinValue
        WallPlaceUntil    = $null
        WallPlacedSig     = ""
        WallAside         = $false
        WallPlan          = "none"
        Screens           = @()
        TopoSig           = ""
        TopoStableSig     = ""
        TopoChangedUtc    = (Get-Date).ToUniversalTime()
        Failures          = [DateTime[]]@()
        InnerRestarts     = 0
        Degraded          = $false
        DegradedReason    = $null
        ExplorerStarts    = 0
        ExplorerStartUtc  = [DateTime]::MinValue
        HeartbeatUtc      = [DateTime]::MinValue
        HeartbeatSig      = ""
        Stop              = $false
        StopReason        = $null
    }
}

function Write-KioskHeartbeat($S, [DateTime]$NowUtc, [switch]$Force) {
    try {
        $launcherRunning = ($null -ne $S.LauncherPid)
        $hb = [ordered]@{
            schema         = 1
            role           = $(if ($Companion) { "companion" } else { "unsupported" })
            pid            = $PID
            sessionId      = $S.SessionId
            startUtc       = $S.StartUtc.ToString("yyyy-MM-ddTHH:mm:ssZ")
            lastLoopUtc    = $NowUtc.ToString("yyyy-MM-ddTHH:mm:ssZ")
            version        = $KioskShellCodeVersion
            sha256         = $S.Sha256
            supervising    = [bool]($null -ne $S.Supervise -and $S.Supervise.Supervise)
            superviseReason = $(if ($null -ne $S.Supervise) { $S.Supervise.Reason } else { $null })
            policyMode     = $(if ($null -ne $S.Policy) { $S.Policy.Mode } else { $null })
            policyReason   = $(if ($null -ne $S.Policy) { $S.Policy.Reason } else { $null })
            topology       = [ordered]@{ count = @($S.Screens).Count; signature = $S.TopoSig; stable = ($S.TopoSig -eq $S.TopoStableSig) }
            launcher       = [ordered]@{
                wanted   = $(if ($null -ne $S.Wanted) { [bool]$S.Wanted.Wanted } else { $false })
                reason   = $(if ($null -ne $S.Wanted) { $S.Wanted.Reason } else { $null })
                untilUtc = $(if ($null -ne $S.Wanted -and $null -ne $S.Wanted.UntilUtc) { $S.Wanted.UntilUtc.ToString("yyyy-MM-ddTHH:mm:ssZ") } else { $null })
                running  = $launcherRunning
                pid      = $S.LauncherPid
                startsInWindow = (Get-KioskCountInWindow -Times $S.LauncherStarts -NowUtc $NowUtc -WindowSeconds $KioskLauncherStartWindowSec)
            }
            wall           = [ordered]@{ plan = $S.WallPlan; running = [bool]$S.WallRunning; aside = [bool]$S.WallAside; pids = @($S.WallPids | Select-Object -First 4) }
            config         = $(if ($null -ne $S.Cfg) { $S.Cfg.Source } else { $null })
            innerRestarts  = $S.InnerRestarts
            degraded       = [bool]$S.Degraded
            degradedReason = $S.DegradedReason
            stopping       = [bool]$S.Stop
            stopReason     = $S.StopReason
        }
        $sig = (ConvertTo-Json -InputObject ([ordered]@{ a = $hb.supervising; b = $hb.launcher.wanted; c = $hb.launcher.running; d = $hb.wall; e = $hb.topology; f = $hb.degraded; g = $hb.stopping; h = $hb.policyMode }) -Compress -Depth 5)
        if (-not $Force -and $sig -eq $S.HeartbeatSig -and ($NowUtc - $S.HeartbeatUtc).TotalSeconds -lt $KioskHeartbeatEverySeconds) { return }
        Write-KioskJsonAtomic -Path $KioskHeartbeatPath -Obj $hb
        $S.HeartbeatUtc = $NowUtc
        $S.HeartbeatSig = $sig
    } catch {
        Write-KioskLog ("heartbeat could not be written: " + $_.Exception.Message) "WARN" "heartbeat-error"
    }
}

function Invoke-KioskExplorerFloor($S, [DateTime]$NowUtc) {
    # Start Explorer when this session has none (at most once a minute). The desktop is the floor every failure ends at.
    if (($NowUtc - $S.ExplorerStartUtc).TotalSeconds -lt 60) { return }
    $S.ExplorerStartUtc = $NowUtc
    $S.ExplorerStarts++
    try {
        Start-Process -FilePath (Join-Path $env:WINDIR "explorer.exe") | Out-Null
        Write-KioskLog "no Explorer in this session: started explorer.exe (the desktop floor)" "WARN"
    } catch { Write-KioskLog ("explorer.exe could not be started: " + $_.Exception.Message) "ERROR" "explorer-start" }
}

function Invoke-KioskTick($S, [DateTime]$NowUtc) {
    # One pass. Order: decide (policy, kill switch, intent), then the floor, then the launcher, then the wall, then
    # placement after a stable topology, then the heartbeat.
    if ($null -eq $S.Cfg -or ($NowUtc - $S.CfgReadUtc).TotalSeconds -ge 60) {
        $S.Cfg = Read-KioskLocalConfig -Path $KioskCfgPath
        $S.CfgReadUtc = $NowUtc
        Write-KioskLog ("config: " + $S.Cfg.Source + "; launcher " + $S.Cfg.LauncherName + " at " + $S.Cfg.LauncherPath) "INFO" "config"
    }
    $S.Policy = Get-KioskPolicyDecision -PolicyRead (Read-KioskJsonFile -Path $KioskPolicyPath -MaxBytes 4096) -KillSwitchPresent (Test-Path -LiteralPath $KioskKillSwitch)
    $S.Supervise = Get-KioskSupervision -CompanionRole ([bool]$Companion) -PolicyDecision $S.Policy -Degraded ([bool]$S.Degraded)
    Write-KioskLog ("supervision: " + $(if ($S.Supervise.Supervise) { "on" } else { "off" }) + " (" + $S.Supervise.Reason + ")") "INFO" "supervise"

    $explorer = @(Get-KioskProcessesInSession -Name "explorer" -SessionId $S.SessionId).Count -gt 0
    $floor = Get-KioskFloorAction -CompanionRole ([bool]$Companion) -Supervise ([bool]$S.Supervise.Supervise) -ExplorerPresent $explorer `
        -PolicyWantsCompanion ([string]$S.Policy.Mode -ceq "companion")
    if ($floor -eq "start-explorer") { Invoke-KioskExplorerFloor -S $S -NowUtc $NowUtc }
    if ($floor -eq "exit") {
        $S.Stop = $true
        $S.StopReason = $S.Supervise.Reason
        Write-KioskLog ("stopping: " + $S.StopReason + " (the launcher and the wall are left as they are)") "INFO"
        Write-KioskHeartbeat -S $S -NowUtc $NowUtc -Force
        return
    }
    if ($floor -ne "supervise") { Write-KioskHeartbeat -S $S -NowUtc $NowUtc; return }

    # ---- launcher ----
    $S.Wanted = Get-KioskLauncherWanted -IntentRead (Read-KioskJsonFile -Path $KioskIntentPath -MaxBytes 8192) -NowUtc $NowUtc
    Write-KioskLog ("launcher " + $(if ($S.Wanted.Wanted) { "wanted until " + $S.Wanted.UntilUtc.ToString("yyyy-MM-ddTHH:mm:ssZ") } else { "not wanted (" + $S.Wanted.Reason + ")" })) "INFO" "wanted"
    $procs = @(Get-KioskProcessesInSession -Name $S.Cfg.LauncherName -SessionId $S.SessionId)
    if ($procs.Count -gt 0) {
        $S.LauncherAbsent = 0
        $first = [int]$procs[0].Id
        if ($S.LauncherPid -ne $first) { $S.LauncherPid = $first }
    } else {
        $S.LauncherAbsent++
        $S.LauncherPid = $null
    }
    $action = Get-KioskLauncherAction -Wanted ([bool]$S.Wanted.Wanted) -Running ($procs.Count -gt 0) -AbsentTicks $S.LauncherAbsent `
        -StartAllowed (Test-KioskStartAllowed -Times $S.LauncherStarts -NowUtc $NowUtc -WindowSeconds $KioskLauncherStartWindowSec -MaxStarts $KioskLauncherMaxStarts) `
        -PathExists (Test-Path -LiteralPath $S.Cfg.LauncherPath -PathType Leaf)
    switch ($action) {
        "start" {
            $keep = $NowUtc.AddSeconds(-2 * $KioskLauncherStartWindowSec)
            $S.LauncherStarts = [DateTime[]]@(@(@($S.LauncherStarts) | Where-Object { $_ -gt $keep }) + $NowUtc)
            $p = $null
            $wd = Split-Path -Parent $S.Cfg.LauncherPath
            if ([string]::IsNullOrWhiteSpace($S.Cfg.LauncherArgs)) { $p = Start-Process -FilePath $S.Cfg.LauncherPath -WorkingDirectory $wd -PassThru }
            else { $p = Start-Process -FilePath $S.Cfg.LauncherPath -ArgumentList $S.Cfg.LauncherArgs -WorkingDirectory $wd -PassThru }
            $S.LauncherPid = [int]$p.Id
            $S.LauncherAbsent = 0
            $S.LauncherPlaceUntil = $NowUtc.AddSeconds($KioskPlaceWaitSeconds)
            $S.LauncherPlacedSig = ""
            Write-KioskLog ("launcher started (pid {0}; {1})" -f $p.Id, $S.Wanted.Reason) "INFO"
        }
        "held" { Write-KioskLog ("launcher restarts held: {0} starts in {1} s" -f $KioskLauncherMaxStarts, $KioskLauncherStartWindowSec) "WARN" "launcher-held" }
        "missing" { Write-KioskLog ("launcher not found at " + $S.Cfg.LauncherPath) "WARN" "launcher-missing" }
        default { }
    }
    if ($action -ne "held") { $script:KioskLastLogged.Remove("launcher-held") | Out-Null }

    # ---- screens ----
    $S.Screens = @(Get-KioskScreens)
    $sig = Get-KioskTopologySignature $S.Screens
    if ($sig -ne $S.TopoSig) {
        $S.TopoSig = $sig
        $S.TopoChangedUtc = $NowUtc
        Write-KioskLog ("screens: " + @($S.Screens).Count + " [" + $sig + "]") "INFO" "topology"
    }
    if ($S.TopoSig -ne $S.TopoStableSig -and ($NowUtc - $S.TopoChangedUtc).TotalSeconds -ge $KioskTopologyStableSeconds) {
        $S.TopoStableSig = $S.TopoSig
        # A stable new layout: re-check each window once (only misplaced ones move).
        $S.LauncherPlacedSig = ""
        $S.WallPlacedSig = ""
    }
    $stable = ($S.TopoSig -eq $S.TopoStableSig)
    $roles = Resolve-KioskRoleScreens -Screens $S.Screens -ControlSelector $S.Cfg.ControlSelector -SessionSelector $S.Cfg.SessionSelector

    # ---- wall display ----
    $edgeExe = Get-KioskEdgePath $S.Cfg.EdgePath
    $S.WallPlan = Get-KioskWallPlan -ScreenCount @($S.Screens).Count -LauncherWanted ([bool]$S.Wanted.Wanted) -WallEnabled ([bool]$S.Cfg.WallEnabled -and $null -ne $edgeExe)
    Write-KioskLog ("wall plan: " + $S.WallPlan) "INFO" "wallplan"
    if (($NowUtc - $S.WallCheckedUtc).TotalSeconds -ge $KioskEdgeCheckEverySeconds -or $null -ne $S.WallPlaceUntil) {
        $S.WallCheckedUtc = $NowUtc
        $S.WallPids = @(Get-KioskWallPidsByExe -ExePath ([string]$edgeExe) -ProfileDir $S.Cfg.ProfileDir)
        $S.WallRunning = ($S.WallPids.Count -gt 0)
        if (-not $S.WallRunning -and $S.WallPlan -eq "show" -and $stable) {
            if (Test-KioskStartAllowed -Times $S.WallStarts -NowUtc $NowUtc -WindowSeconds $KioskEdgeStartWindowSec -MaxStarts $KioskEdgeMaxStarts) {
                $keepW = $NowUtc.AddSeconds(-2 * $KioskEdgeStartWindowSec)
                $S.WallStarts = [DateTime[]]@(@(@($S.WallStarts) | Where-Object { $_ -gt $keepW }) + $NowUtc)
                $p = Start-Process -FilePath $edgeExe -ArgumentList (Get-KioskWallArgumentLine -Cfg $S.Cfg -Bounds $roles.Session) -PassThru
                $S.WallPids = @([int]$p.Id)
                $S.WallRunning = $true
                $S.WallAside = $false
                $S.WallPlaceUntil = $NowUtc.AddSeconds($KioskPlaceWaitSeconds)
                $S.WallPlacedSig = ""
                Write-KioskLog ("wall display started (pid {0}) on {1}" -f $p.Id, $(if ($null -ne $roles.Session) { $roles.Session.DeviceName } else { "no screen" })) "INFO"
            } else {
                Write-KioskLog ("wall display restarts held: {0} starts in {1} s" -f $KioskEdgeMaxStarts, $KioskEdgeStartWindowSec) "WARN" "wall-held"
            }
        }
    }

    # ---- placement, only on a stable layout, once per window per layout ----
    if ($stable -and @($S.Screens).Count -gt 0) {
        if ($null -ne $S.LauncherPid -and $S.LauncherPlacedSig -ne $S.TopoStableSig) {
            $r = Set-KioskWindowPlacement -Pids @([int]$S.LauncherPid) -Screen $roles.Control -Maximize
            if ($r.Done -or ($null -ne $S.LauncherPlaceUntil -and $NowUtc -ge $S.LauncherPlaceUntil) -or $null -eq $S.LauncherPlaceUntil) {
                $S.LauncherPlacedSig = $S.TopoStableSig
                $S.LauncherPlaceUntil = $null
                Write-KioskLog ("launcher placement: " + $r.Why + $(if ($r.Done -and $r.ContainsKey("Device")) { " on " + $r.Device } else { "" })) "INFO" "launcher-place"
            }
        }
        if ($S.WallRunning -and $S.WallPids.Count -gt 0 -and ($S.WallPlacedSig -ne $S.TopoStableSig -or ($S.WallPlan -eq "aside") -ne [bool]$S.WallAside)) {
            $aside = ($S.WallPlan -eq "aside")
            $r = $(if ($aside) { Set-KioskWindowPlacement -Pids $S.WallPids -Screen $null -Aside } else { Set-KioskWindowPlacement -Pids $S.WallPids -Screen $roles.Session -CoverOnly })
            if ($r.Done -or ($null -ne $S.WallPlaceUntil -and $NowUtc -ge $S.WallPlaceUntil) -or $null -eq $S.WallPlaceUntil) {
                $S.WallPlacedSig = $S.TopoStableSig
                $S.WallPlaceUntil = $null
                $S.WallAside = ($aside -and $r.Done)
                Write-KioskLog ("wall placement: " + $r.Why + $(if ($r.Done -and $r.ContainsKey("Device")) { " on " + $r.Device } else { "" })) "INFO" "wall-place"
            }
        } elseif ($S.WallRunning -and $S.WallPids.Count -gt 0 -and $S.WallPlan -eq "aside" -and $S.WallCheckedUtc -eq $NowUtc) {
            # Aside is re-checked at every wall check (10 s): something else may have restored the wall over the only
            # screen the member has. Minimizing a minimized window is a no-op, so this cannot loop or steal focus.
            $r = Set-KioskWindowPlacement -Pids $S.WallPids -Screen $null -Aside
            if ($r.Why -eq "moved aside (minimized)") { Write-KioskLog "wall was restored over the only screen while the launcher is wanted: moved aside again" "WARN" }
        }
    }

    Write-KioskHeartbeat -S $S -NowUtc $NowUtc
}

# ============================================================================================================
# Main
# ============================================================================================================

if (-not (Test-Path -LiteralPath $KioskLogDir)) { New-Item -ItemType Directory -Force -Path $KioskLogDir | Out-Null }
Remove-KioskOldLogs -Dir $KioskLogDir -Days $KioskLogRetentionDays -NowUtc ((Get-Date).ToUniversalTime())

$KioskMutex = $null
$KioskOwnsMutex = $false
try { $KioskMutex = New-Object System.Threading.Mutex($true, "Local\ABG.KioskShell", [ref]$KioskOwnsMutex) } catch { $KioskOwnsMutex = $true }
if (-not $KioskOwnsMutex) {
    Write-KioskLog ("another kiosk shell already runs in this session; this copy (pid {0}) exits" -f $PID) "INFO"
    exit 0
}

$KioskState = New-KioskState
Write-KioskLog ("kiosk shell {0} starting (pid {1}, session {2}, role {3})" -f $KioskShellCodeVersion, $PID, $KioskState.SessionId, $(if ($Companion) { "companion" } else { "unsupported" })) "INFO"

while ($true) {
    $now = (Get-Date).ToUniversalTime()
    try {
        # Degraded or not, the same tick runs: once degraded it supervises nothing and keeps only the floor and the
        # heartbeat (Get-KioskSupervision), and it leaves when the policy no longer wants a companion.
        Invoke-KioskTick -S $KioskState -NowUtc $now
        if ($KioskState.Stop) { break }
    } catch {
        $KioskState.InnerRestarts++
        $keepF = $now.AddSeconds(-2 * $KioskDegradeWindowSec)
        $KioskState.Failures = [DateTime[]]@(@(@($KioskState.Failures) | Where-Object { $_ -gt $keepF }) + $now)
        Write-KioskLog ("tick failed: " + $_.Exception.Message) "ERROR"
        if (-not $KioskState.Degraded -and (Get-KioskDegradeVerdict -Failures $KioskState.Failures -NowUtc $now -WindowSeconds $KioskDegradeWindowSec -Threshold $KioskDegradeAfterFailures)) {
            $KioskState.Degraded = $true
            $KioskState.DegradedReason = ("{0} failures in {1} s; last: {2}" -f $KioskDegradeAfterFailures, $KioskDegradeWindowSec, $_.Exception.Message)
            $KioskState.Supervise = @{ Supervise = $false; Reason = "degraded" }
            Write-KioskLog ("degraded: supervision stops (" + $KioskState.DegradedReason + ")") "ERROR"
            try { Write-KioskHeartbeat -S $KioskState -NowUtc $now -Force } catch { }
        }
    }
    Start-Sleep -Milliseconds $KioskTickMs
}

try { if ($null -ne $KioskMutex) { $KioskMutex.ReleaseMutex(); $KioskMutex.Dispose() } } catch { }
exit 0
