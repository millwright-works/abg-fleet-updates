$root='C:\aoc-wt\kiosk-rr1-r7-attack'
$muts=@(
 @('M00 baseline (no change)','function Get-ResetGate {','function Get-ResetGate {'),
 @('G10 handler passes no model','-SessionModel (Read-SessionModelFromDisk) -Payload $payloadObj','-SessionModel $null -Payload $payloadObj'),
 @('G1 running always proceeds','if ($status -cnotin @("ACTIVE", "ENDING")) {','if ($true) {'),
 @('G2 ENDING not running','$status -cnotin @("ACTIVE", "ENDING")','$status -cnotin @("ACTIVE")'),
 @('G3 name-the-session proceed removed','if (-not [string]::IsNullOrWhiteSpace($paySid) -and $paySid -ceq $runSid)','if ($false)'),
 @('G4 id compare case-insensitive','$paySid -ceq $runSid','$paySid -eq $runSid'),
 @('G5 stale proceed removed','if ($null -ne $end -and $NowUtc -gt $end.AddMinutes($StaleMinutes))','if ($false)'),
 @('G6 stale threshold zero','[int]$StaleMinutes = 15','[int]$StaleMinutes = -1000'),
 @('G7 force removed','if ($force) {','if ($false) {'),
 @('G8 handler ignores gate','if (-not $resetGate.Proceed) {','if ($false) {'),
 @('G9 missing session.json holds','if ($null -eq $SessionModel) { return @{ Proceed = $true;','if ($null -eq $SessionModel) { return @{ Proceed = $false;')
)
foreach($m in $muts){
  $d='C:\Temp\kmutvx\work'; if(Test-Path $d){Remove-Item $d -Recurse -Force}
  New-Item -ItemType Directory $d | Out-Null
  Copy-Item "$root\src" "$d\src" -Recurse; Copy-Item "$root\tests" "$d\tests" -Recurse; Copy-Item "$root\tools" "$d\tools" -Recurse
  $f="$d\src\BayAgent\BayAgent.ps1"
  $t=[IO.File]::ReadAllText($f)
  $i=$t.IndexOf($m[1]); if($i -lt 0){ "$($m[0]): NOT APPLIED"; continue }
  $t=$t.Substring(0,$i)+$m[2]+$t.Substring($i+$m[1].Length)
  [IO.File]::WriteAllText($f,$t,(New-Object Text.UTF8Encoding($true)))
  $out = & powershell -NoProfile -ExecutionPolicy Bypass -File "$d\tests\BayAgent.Kiosk.Tests.ps1" 2>&1 | Out-String
  $res = ($out -split "`r?`n" | Where-Object {$_ -match '^RESULT'}) 
  $fails = ($out -split "`r?`n" | Where-Object {$_ -match '^\s+FAIL' } | Select-Object -First 2) -join ' | '
  "$($m[0]): $res :: $fails"
}
