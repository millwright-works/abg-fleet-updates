#Requires -Version 5.1
# Kiosk round 2 FIX re-verdict (2026-10-10). The real Send-ControlScreenWarning and its real default sender, lifted from
# the agent by name, against the real msg.exe: once to a desktop session that does not exist (no box; the result must NOT
# say shown), once to this desktop session for 2 seconds (one small box that closes itself). Hyphens only in comments.
param([string]$AgentScript, [string]$Out)
$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest
$tok = $null; $perr = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile($AgentScript, [ref]$tok, [ref]$perr)
$defs = @($ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $true))
foreach ($n in @("Get-KioskProp", "Start-ControlScreenSender", "Send-ControlScreenWarning")) {
    $d = @($defs | Where-Object { $_.Name -eq $n })
    if ($d.Count -ne 1) { throw "function $n not found exactly once" }
    . ([scriptblock]::Create($d[0].Extent.Text))
}
$lines = @()
$exe = Join-Path $env:WINDIR "System32\msg.exe"
$lines += ("msg.exe present: " + (Test-Path -LiteralPath $exe))
# 1) a desktop session that does not exist, through the real default sender
$bad = Start-ControlScreenSender -Exe $exe -ArgLine '65000 /TIME:1 "kiosk fix reverdict probe: this session does not exist"'
$lines += ("real msg.exe to session 65000 (does not exist): exitCode=" + $bad["exitCode"])
# 2) the real Send-ControlScreenWarning, default starter, this desktop session, 2 seconds
$ok = Send-ControlScreenWarning -Text "Kiosk fix reverdict probe. This box closes itself in 2 seconds." -Seconds 2
$lines += ("real Send-ControlScreenWarning, this session: " + ($ok | ConvertTo-Json -Compress))
# 3) the real Send-ControlScreenWarning with a starter that runs the real sender against the missing session
$fail = Send-ControlScreenWarning -Text "probe" -Seconds 1 -Starter { param($f, $a) Start-ControlScreenSender -Exe $f -ArgLine ('65000 /TIME:1 "probe"') }
$lines += ("real Send-ControlScreenWarning, real msg.exe failing (session 65000): " + ($fail | ConvertTo-Json -Compress))
[IO.File]::WriteAllLines($Out, [string[]]$lines)
$lines | ForEach-Object { Write-Host $_ }
