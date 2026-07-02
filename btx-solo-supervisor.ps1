# BTX Solo Supervisor — keeps the lean solo miner alive for unattended/overnight running.
#  - Relaunches the lean miner (D:\BTX\btx-solo-lean.sh, which itself self-heals btxd) if it dies.
#  - Memory watchdog: if Windows commit % crosses the threshold, kills btxd so the box can't
#    freeze (the lean miner restarts btxd with the bounded -dbcache=200 config). Last resort.
#  - Single-instance via a Global mutex. Auto-starts at logon via the Startup-folder VBS.
$ErrorActionPreference = 'SilentlyContinue'
$LOG = 'D:\BTX\btx-solo-supervisor.log'
$COMMIT_KILL_PCT = 95
function Log($m){ ("[{0}] {1}" -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $m) | Out-File -FilePath $LOG -Append -Encoding utf8 }

try {
  $script:mtx = New-Object System.Threading.Mutex($false, 'Global\BTX_Solo_Supervisor_Singleton')
  if(-not $script:mtx.WaitOne(0)){ exit }
} catch { }

function LeanRunning {
  # bracketed pattern so this check's own shell isn't matched
  $out = & wsl -e bash -lc 'pgrep -f "/mnt/d/BTX/[b]tx-solo-lean.sh" >/dev/null 2>&1 && echo yes || echo no' 2>$null
  return ([string]$out -match 'yes')
}
function LaunchLean {
  # `flock -n` on a PERSISTENT lock file guarantees a single instance even if this
  # fires twice (the 2nd flock exits immediately). Hidden cmd keeps it persistent.
  Start-Process cmd.exe -ArgumentList '/c','wsl -e bash -lc "exec flock -n /tmp/btx-solo-lean.lock bash /mnt/d/BTX/btx-solo-lean.sh"' -WindowStyle Hidden
  Log "launched lean solo miner (flock-guarded)"
}

Log "supervisor started (pid $PID)"
while($true){
  try {
    if(-not (LeanRunning)){ Log "lean miner not running -> launching"; LaunchLean; Start-Sleep -Seconds 20 }
    $c = (Get-Counter '\Memory\% Committed Bytes In Use' -ErrorAction SilentlyContinue).CounterSamples[0].CookedValue
    if($c -gt $COMMIT_KILL_PCT){
      Log ("commit {0:N1}% > {1}% -> killing btxd to prevent freeze (lean miner restarts it bounded)" -f $c, $COMMIT_KILL_PCT)
      & wsl -e bash -lc 'pkill -x btxd.real 2>/dev/null; true' 2>$null
      Start-Sleep -Seconds 25
    }
  } catch {
    Log ("loop error: " + $_.Exception.Message)
  }
  Start-Sleep -Seconds 30
}
