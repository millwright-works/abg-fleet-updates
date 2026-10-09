param([string]$Src, [string]$Block, [string]$Out)
$t = [IO.File]::ReadAllText($Src)
$b = [IO.File]::ReadAllText($Block)
$marker = '    Section "K19 the shell'
$i = $t.IndexOf($marker)
if ($i -lt 0) { throw "marker not found" }
$t2 = $t.Substring(0, $i) + $b + "`r`n" + $t.Substring($i)
[IO.File]::WriteAllText($Out, $t2, (New-Object Text.UTF8Encoding($true)))
"spliced at $i"
