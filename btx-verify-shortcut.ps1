# btx-verify-shortcut.ps1 — verifies the ENTIRE desktop-shortcut path end to end.
# Run after EVERY change to the mining stack. Exit 0 = shortcut-to-mining chain healthy.
#   powershell -ExecutionPolicy Bypass -File D:\BTX\btx-verify-shortcut.ps1
# Non-disruptive: probes status only; never starts or stops mining.

$ErrorActionPreference = 'Continue'
$fails = @()
function Check { param($Name, $Ok, $Detail='')
    if ($Ok) { Write-Host ("PASS  {0}" -f $Name) }
    else     { Write-Host ("FAIL  {0}  {1}" -f $Name, $Detail) -ForegroundColor Red; $script:fails += $Name }
}

$gui  = 'D:\BTX\btx-miner-gui.ps1'
$lnk  = Join-Path ([Environment]::GetFolderPath('Desktop')) 'BTX Miner.lnk'
$stop = Join-Path ([Environment]::GetFolderPath('Desktop')) 'Stop BTX Mining.lnk'

# [1] Shortcuts: exist, right target, right script, admin bit on the GUI one
$ws = New-Object -ComObject WScript.Shell
Check 'shortcut exists' (Test-Path $lnk)
Check 'stop shortcut exists' (Test-Path $stop)
if (Test-Path $lnk) {
    $sc = $ws.CreateShortcut($lnk)
    Check 'shortcut target is powershell.exe' ($sc.TargetPath -like '*\WindowsPowerShell\v1.0\powershell.exe')
    Check 'shortcut runs btx-miner-gui.ps1' ($sc.Arguments -like '*btx-miner-gui.ps1*')
    $b = [IO.File]::ReadAllBytes($lnk)
    Check 'shortcut has admin bit' ([bool]($b[0x15] -band 0x20))
}
Check 'GUI script exists' (Test-Path $gui)

# [2] GUI script: UTF-8 BOM (PS 5.1 requirement) + parses under the SHORTCUT'S engine (5.1)
$bytes = [IO.File]::ReadAllBytes($gui)
Check 'GUI has UTF-8 BOM' ($bytes.Length -gt 3 -and $bytes[0] -eq 0xEF -and $bytes[1] -eq 0xBB -and $bytes[2] -eq 0xBF)
$ps51parse = & "$env:WINDIR\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -Command `
    "`$t=`$null;`$e=`$null;[System.Management.Automation.Language.Parser]::ParseFile('$gui',[ref]`$t,[ref]`$e)|Out-Null; if(`$e.Count){'ERR:'+`$e[0].Message}else{'OK'}"
Check 'GUI parses under PS 5.1' ($ps51parse -match '^OK') "$ps51parse"

# [3] Known landmine patterns inside the GUI source
$src = [IO.File]::ReadAllText($gui)
Check 'no \$( bash-in-double-quotes hazard' (-not ($src -match '\\\$\('))
$badPgrep = [regex]::Matches($src, "pgrep -f ['`"]?(btx|dexbtx|faststart)") | Where-Object { $_.Value -notmatch '\[' }
Check 'all pgrep -f patterns bracketed (no self-match)' ($badPgrep.Count -eq 0) ("found: " + (($badPgrep | ForEach-Object Value) -join '; '))
Check 'no Start-Process wsl launches (silent-failure API)' (-not ($src -match "Start-Process[^\r\n]*wsl"))

# [4] Every WSL script the GUI depends on: exists, LF-only, bash -n clean
$deps = @('btx-smart-mine.sh','btx-mining-mode.sh','btx-sync-fast.sh','btx-solo-guard.sh',
          'btx-pool-guard.sh','btx-mine.sh','btx-hashrate.sh','btx-solo-hashrate.sh',
          'btx-solo-stats.sh','btx-autotune.sh','btx-restore-snapshot.sh','btx-racer.sh','btx-status-probe.sh')
$wslUp = ((& wsl.exe --list --running 2>$null | Out-String) -replace "`0","") -match 'Ubuntu'
if (-not $wslUp) { & wsl.exe -d Ubuntu -e true 2>$null | Out-Null }
foreach ($d in $deps) {
    $r = (& wsl.exe -d Ubuntu -e bash -lc "f=/mnt/d/BTX/$d; [ -f `$f ] || { echo MISSING; exit; }; grep -q `$'\r' `$f && { echo CRLF; exit; }; bash -n `$f 2>/dev/null && echo OK || echo SYNTAX" 2>$null | Out-String).Trim() -replace "`0",""
    Check "dep $d" ($r -match 'OK$') "$r"
}

# [5] The CLI status path (same engine + same functions the buttons use) answers with an Activity line
$status = & "$env:WINDIR\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -ExecutionPolicy Bypass -File $gui status 2>&1 | Out-String
Check 'status runs under PS 5.1' ($status -match 'Wsl=')
Check 'status reports Activity phase' ($status -match 'Activity:')
Check 'status resolves payout address' ($status -match 'Payout:\s*btx1[a-z0-9]{20,}')
Write-Host '--- live status ---'; Write-Host $status.Trim()

if ($fails.Count) { Write-Host ("`nRESULT: FAIL ({0}): {1}" -f $fails.Count, ($fails -join ' | ')) -ForegroundColor Red; exit 1 }
Write-Host "`nRESULT: PASS - shortcut path is healthy end to end" -ForegroundColor Green
exit 0
