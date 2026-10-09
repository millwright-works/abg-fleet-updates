Set-StrictMode -Version Latest; $ErrorActionPreference = "Stop"
$AgentScript = "C:\aoc-wt\kiosk-attack-r2\src\BayAgent\BayAgent.ps1"
$tk = $null; $er = $null; $ast = [System.Management.Automation.Language.Parser]::ParseFile($AgentScript, [ref]$tk, [ref]$er)
$CMD_STARTSESSION = 100000010; $CMD_ENDSESSION = 100000011; $CMD_RESET = 100000012; $CMD_EMERGENCY_STOP = 100000027; $CMD_UPDATESESSIONDISPLAY = 100000005
$AgentCodeVersion = "1.4.0"; $BaseDir = Join-Path $env:TEMP ("kv-" + [guid]::NewGuid().ToString("N").Substring(0,8)); New-Item -ItemType Directory -Force -Path (Join-Path $BaseDir "state") | Out-Null
$Global:EmergencyStopEngaged = $false
function Write-Log([string]$m, [string]$l = "INFO") { }
function Read-SessionModelFromDisk { return $null }
foreach ($st in $ast.EndBlock.Statements) { if ($st -is [System.Management.Automation.Language.AssignmentStatementAst] -and $st.Left.Extent.Text -match '^\$(Global:)?Kiosk') { . ([scriptblock]::Create($st.Extent.Text)) } }
foreach ($f in @($ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -match 'Kiosk' }, $true))) { . ([scriptblock]::Create($f.Extent.Text)) }
# agent 1 writes closed (after an End), then is stopped; a member writes free play while no agent runs
$null = Set-KioskIntentForCommand -CommandType $CMD_ENDSESSION -Mode "End" -Payload @{ baySessionId = "S-A" } -SameSession $true
[IO.File]::WriteAllText($KioskIntentPath, '{"schema":1,"launcher":"wanted","untilUtc":"2099-01-01T00:00:00Z","baySessionId":"x","writtenUtc":"2026-10-08T00:00:00Z"}')
$Global:KioskIntentExpectedText = $null   # a fresh agent process
Initialize-KioskIntent -NowUtc ((Get-Date).ToUniversalTime())
$restored = Test-KioskIntentIntegrity
$w = Get-KioskLauncherWanted -IntentRead (Read-KioskJsonFile -Path $KioskIntentPath -MaxBytes 8192) -NowUtc ((Get-Date).ToUniversalTime())
"after agent restart: integrity restored=$restored; shell reads wanted=$($w.Wanted) until $($w.UntilUtc) ($($w.Reason))"
Remove-Item -LiteralPath $BaseDir -Recurse -Force

