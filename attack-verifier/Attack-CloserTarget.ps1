Set-StrictMode -Version Latest; $ErrorActionPreference = "Stop"
$tk = $null; $er = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile("C:\aoc-wt\kiosk-attack-r2\src\BayAgent\kiosk\ABG.KioskShell.ps1", [ref]$tk, [ref]$er)
. ([scriptblock]::Create(@($ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq "Test-KioskIsConfiguredLauncher" }, $true))[0].Extent.Text))
$me = Get-Process -Id $PID
$sid = $me.SessionId
"own powershell, cfg name powershell + its real path : " + (Test-KioskIsConfiguredLauncher -Proc $me -Cfg @{ LauncherName = "powershell"; LauncherPath = $me.Path } -SessionId $sid)
$ex = @(Get-Process -Name explorer | Where-Object { $_.SessionId -eq $sid })[0]
"explorer, cfg name explorer + its real path         : " + (Test-KioskIsConfiguredLauncher -Proc $ex -Cfg @{ LauncherName = "explorer"; LauncherPath = $ex.Path } -SessionId $sid)
$dir = Join-Path $env:TEMP ("kv-ct-" + [guid]::NewGuid().ToString("N").Substring(0,6)); New-Item -ItemType Directory -Path $dir | Out-Null
$a = Join-Path $dir "AbgVerifCt.exe"; Copy-Item (Join-Path $env:WINDIR "System32\PING.EXE") $a
$p = Start-Process -FilePath $a -ArgumentList "-n 30 127.0.0.1" -PassThru -WindowStyle Hidden
Start-Sleep -Milliseconds 500
"stand-in, right name + right path                    : " + (Test-KioskIsConfiguredLauncher -Proc (Get-Process -Id $p.Id) -Cfg @{ LauncherName = "AbgVerifCt"; LauncherPath = $a } -SessionId $sid)
"stand-in, right name + OTHER path                    : " + (Test-KioskIsConfiguredLauncher -Proc (Get-Process -Id $p.Id) -Cfg @{ LauncherName = "AbgVerifCt"; LauncherPath = "C:\Uneekor\Launcher\AbgVerifCt.exe" } -SessionId $sid)
"stand-in, path given in other case/8.3-free form     : " + (Test-KioskIsConfiguredLauncher -Proc (Get-Process -Id $p.Id) -Cfg @{ LauncherName = "abgverifct"; LauncherPath = $a.ToUpperInvariant() } -SessionId $sid)
Stop-Process -Id $p.Id -Force; Start-Sleep -Milliseconds 500; Remove-Item -LiteralPath $dir -Recurse -Force
