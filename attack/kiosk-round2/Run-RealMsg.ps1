#Requires -Version 5.1
# Kiosk round 2 attack (2026-10-10). The agent's REAL Send-ControlScreenWarning with its DEFAULT starter (no test runs it:
# the suite injects a starter). Lifted by AST from the tree's BayAgent.ps1 and called once, on THIS PC, with a clearly
# labeled 5-second text. Then: did msg.exe start, did it exit 0, and did a "Message from" window appear on this desktop?
# Hyphens only in comments.
param([string]$Tree = "", [string]$OutDir = "")
$ErrorActionPreference = "Stop"
if ([string]::IsNullOrWhiteSpace($Tree)) { $Tree = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path }
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
$tk = $null; $er = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile((Join-Path $Tree "src\BayAgent\BayAgent.ps1"), [ref]$tk, [ref]$er)
$def = @($ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq "Send-ControlScreenWarning" }, $true))
if ($def.Count -ne 1) { throw "Send-ControlScreenWarning found $($def.Count) times" }
. ([scriptblock]::Create($def[0].Extent.Text))
Add-Type @"
using System; using System.Text; using System.Collections.Generic; using System.Runtime.InteropServices;
public static class AbgVyWin {
    public delegate bool EnumProc(IntPtr h, IntPtr l);
    [DllImport("user32.dll")] static extern bool EnumWindows(EnumProc f, IntPtr l);
    [DllImport("user32.dll", CharSet=CharSet.Unicode)] static extern int GetWindowText(IntPtr h, StringBuilder s, int n);
    [DllImport("user32.dll")] static extern bool IsWindowVisible(IntPtr h);
    public static List<string> Titles() { var r = new List<string>(); EnumWindows((h, l) => { if (IsWindowVisible(h)) { var sb = new StringBuilder(512); GetWindowText(h, sb, 512); if (sb.Length > 0) r.Add(sb.ToString()); } return true; }, IntPtr.Zero); return r; }
}
"@
$lines = New-Object System.Collections.ArrayList
function Say([string]$m) { [void]$lines.Add($m); Write-Host $m }
$exe = Join-Path $env:WINDIR "System32\msg.exe"
Say ("REALMSG msg.exe present on this PC=" + (Test-Path -LiteralPath $exe) + " | OS=" + (Get-CimInstance Win32_OperatingSystem).Caption + " | this process session id=" + [System.Diagnostics.Process]::GetCurrentProcess().SessionId)
$before = @([AbgVyWin]::Titles() | Where-Object { $_ -like "Message from*" }).Count
$r = Send-ControlScreenWarning -Text "Automated test from the kiosk verifier. No action needed. This closes on its own in 5 seconds." -Seconds 5
Say ("REALMSG real sender result: shown=" + $r["shown"] + " via=" + $r["via"] + " pid=" + $r["pid"] + " why=" + $r["why"])
$seen = $false; $title = ""
$deadline = (Get-Date).AddSeconds(4)
do { $t = @([AbgVyWin]::Titles() | Where-Object { $_ -like "Message from*" }); if ($t.Count -gt $before) { $seen = $true; $title = $t[0]; break }; Start-Sleep -Milliseconds 200 } while ((Get-Date) -lt $deadline)
Say ("REALMSG a 'Message from' window appeared on this desktop=" + $seen + $(if ($seen) { " (title: " + $title + ")" } else { "" }))
Start-Sleep -Seconds 6
$after = @([AbgVyWin]::Titles() | Where-Object { $_ -like "Message from*" }).Count
Say ("REALMSG gone on its own after the 5 seconds=" + ($after -le $before))
[IO.File]::WriteAllLines((Join-Path $OutDir "realmsg-observations.txt"), [string[]]$lines)
