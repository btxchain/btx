<#
  BTX kill switch — stops mining and frees the GPU + RAM immediately.
  Stops the miner/guard, then shuts down WSL entirely. No admin needed.
  Double-click the "Stop BTX Mining" desktop shortcut, or run:
      powershell -ExecutionPolicy Bypass -File btx-kill.ps1
#>
$ErrorActionPreference = 'SilentlyContinue'
$dist = 'Ubuntu'

# If WSL is up, set stop flags + graceful stop first so nothing respawns.
$run = (& wsl.exe --list --running 2>$null | Out-String) -replace "`0",""
if ($run -match [regex]::Escape($dist)) {
    & wsl.exe -d $dist -e bash -lc 'chmod +x /mnt/d/BTX/btx-mining-mode.sh 2>/dev/null; bash /mnt/d/BTX/btx-mining-mode.sh stop >/dev/null 2>&1; touch /tmp/btx-pool-guard.stop /tmp/btx-solo-guard.stop 2>/dev/null; true' 2>$null | Out-Null
}

# Nuke WSL: kills miner, guard, and node, and returns all WSL RAM to Windows.
& wsl.exe --shutdown 2>$null

Write-Host 'BTX mining stopped and WSL shut down — GPU and RAM freed.'
