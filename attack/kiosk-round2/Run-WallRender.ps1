#Requires -Version 5.1
# Kiosk round 2 attack (2026-10-10). Renders the repo's own wall page (src\SessionDisplay\current) in headless Edge over
# the session files the REAL agent handlers wrote in probe VY12 (a running session, then its cancel warning), and saves a
# screenshot plus the rendered text of the status elements. Edge runs with its own throwaway profile. Hyphens only.
param([string]$Tree = "", [string]$WallFiles = "", [string]$OutDir = "")
$ErrorActionPreference = "Stop"
if ([string]::IsNullOrWhiteSpace($Tree)) { $Tree = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path }
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
$edge = @("C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe", "C:\Program Files\Microsoft\Edge\Application\msedge.exe") | Where-Object { Test-Path -LiteralPath $_ } | Select-Object -First 1
if (-not $edge) { throw "msedge.exe not found" }
$work = Join-Path $env:TEMP ("kr2-wall-" + [guid]::NewGuid().ToString("N").Substring(0, 8))
$lines = New-Object System.Collections.ArrayList
try {
    foreach ($case in @("active", "warning")) {
        $site = Join-Path $work $case
        New-Item -ItemType Directory -Force -Path $site | Out-Null
        Copy-Item -Path (Join-Path $Tree "src\SessionDisplay\current\*") -Destination $site -Recurse -Force
        New-Item -ItemType Directory -Force -Path (Join-Path $site "data") | Out-Null
        Copy-Item -LiteralPath (Join-Path $WallFiles ($case + "\session.js")) -Destination (Join-Path $site "data\session.js") -Force
        Copy-Item -LiteralPath (Join-Path $WallFiles ($case + "\session.json")) -Destination (Join-Path $site "data\session.json") -Force
        $url = "file:///" + ((Join-Path $site "index.html") -replace '\\', '/')
        $png = Join-Path $OutDir ("wall-" + $case + ".png")
        $prof = Join-Path $work ("profile-" + $case)
        foreach ($mode in @("shot", "dom")) {
            $psi = New-Object System.Diagnostics.ProcessStartInfo
            $psi.FileName = $edge
            $common = "--headless=new --disable-gpu --no-first-run --user-data-dir=`"$prof`" --window-size=1920,1080 --virtual-time-budget=6000 --allow-file-access-from-files"
            $psi.Arguments = $(if ($mode -eq "shot") { "$common --screenshot=`"$png`" `"$url`"" } else { "$common --dump-dom `"$url`"" })
            $psi.UseShellExecute = $false; $psi.RedirectStandardOutput = $true; $psi.RedirectStandardError = $true; $psi.CreateNoWindow = $true
            $p = [System.Diagnostics.Process]::Start($psi)
            $so = $p.StandardOutput.ReadToEndAsync(); $se = $p.StandardError.ReadToEndAsync()
            if (-not $p.WaitForExit(60000)) { try { $p.Kill() } catch { } }
            if ($mode -eq "dom") {
                $dom = $so.Result
                [IO.File]::WriteAllText((Join-Path $OutDir ("wall-" + $case + "-dom.html")), $dom, (New-Object Text.UTF8Encoding($false)))
                $get = { param($id) if ($dom -match ('id="' + $id + '"[^>]*>([^<]*)<')) { return $Matches[1].Trim() } else { return "(not found)" } }
                $banner = "(not found)"; if ($dom -match 'id="bannerText"([^>]*)>([^<]*)<') { $banner = $Matches[2].Trim() + " [attrs:" + $Matches[1].Trim() + "]" }
                $line = ("WALL {0}: statusPill='{1}' statusDetail='{2}' banner='{3}' countdown='{4}' name='{5}' | screenshot={6}" -f $case, (& $get "statusPill"), (& $get "statusDetail"), $banner, (& $get "countdown"), (& $get "displayName"), (Test-Path -LiteralPath $png))
                [void]$lines.Add($line); Write-Host $line
            }
        }
    }
} finally {
    [IO.File]::WriteAllLines((Join-Path $OutDir "wall-render-observations.txt"), [string[]]$lines)
    try { Remove-Item -LiteralPath $work -Recurse -Force -ErrorAction SilentlyContinue } catch { }
}
