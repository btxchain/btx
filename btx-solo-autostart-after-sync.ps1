# One-shot: wait until the BTX node is fully synced (ibd=false) and no re-sync is
# running, then start the solo supervisor exactly once. Lets solo come up on its own
# after the in-progress snapshot re-sync, with no operator present.
$ErrorActionPreference = 'SilentlyContinue'
$LOG = 'D:\BTX\btx-solo-autostart.log'
function Log($m){ ("[{0}] {1}" -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $m) | Out-File -FilePath $LOG -Append -Encoding utf8 }
Log "autostarter waiting for node to finish syncing..."
for($i=0; $i -lt 240; $i++){   # up to ~2h
  Start-Sleep -Seconds 30
  $info = & wsl -e bash -lc '/home/eldian/btx-node/bin/btx-cli -datadir=/home/eldian/.btx -rpcclienttimeout=5 getblockchaininfo 2>/dev/null' 2>$null
  $fs   = & wsl -e bash -lc 'pgrep -f "[b]tx-faststart" >/dev/null 2>&1 && echo Y || echo N' 2>$null
  if(([string]$info -match '"initialblockdownload"\s*:\s*false') -and ([string]$fs -match 'N')){
    Start-Sleep -Seconds 20
    $info2 = & wsl -e bash -lc '/home/eldian/btx-node/bin/btx-cli -datadir=/home/eldian/.btx -rpcclienttimeout=5 getblockchaininfo 2>/dev/null' 2>$null
    if([string]$info2 -match '"initialblockdownload"\s*:\s*false'){
      $sp = 'solo-' + 'supervisor'
      $running = @(Get-CimInstance Win32_Process | Where-Object { $_.CommandLine -like "*$sp*" }).Count
      if($running -eq 0){
        Start-Process powershell -ArgumentList '-NoProfile','-WindowStyle','Hidden','-ExecutionPolicy','Bypass','-File','D:\BTX\btx-solo-supervisor.ps1' -WindowStyle Hidden
        Log "node synced -> started solo supervisor"
      } else { Log "supervisor already running; nothing to do" }
      break
    }
  }
}
Log "autostarter done"
