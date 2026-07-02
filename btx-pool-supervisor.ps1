# BTX Pool Supervisor — keeps pool mining alive for unattended / reboot-persistent running.
# Detects MINING via the solver process (btx-gbt-solve, exact-name match — reliable, no
# space/quote garbling that made the old guard-name check misfire and restart the miner
# every ~75s). Only (re)launches the guard after the solver has been down for a sustained
# streak, so a transient solver restart never triggers a churn. No local node => no watchdog.
$ErrorActionPreference = 'SilentlyContinue'
$LOG = 'D:\BTX\btx-pool-supervisor.log'
function Log($m){ ("[{0}] {1}" -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $m) | Out-File -FilePath $LOG -Append -Encoding utf8 }

try {
  $script:mtx = New-Object System.Threading.Mutex($false, 'Global\BTX_Pool_Supervisor_Singleton')
  if(-not $script:mtx.WaitOne(0)){ exit }
} catch { }

function MiningUp {
  # solver running == GPU mining. pgrep -x matches the exact process name (no -f, no spaces).
  $r = & wsl -e bash -lc 'pgrep -x btx-gbt-solve >/dev/null 2>&1 && echo yes || echo no' 2>$null
  return ([string]$r -match 'yes')
}
function LaunchPool {
  # Clear stale stop-flag/lock and any half-dead guard, then launch ONE guard (it runs miner+solver).
  & wsl -e bash -lc 'rm -f /tmp/btx-pool-guard.stop 2>/dev/null; rmdir /tmp/btx-pool-guard.lock 2>/dev/null; for p in $(pgrep -f "[b]tx-pool-guard"); do kill $p 2>/dev/null; done; sleep 1; true' 2>$null
  Start-Process cmd.exe -ArgumentList '/c','wsl -e bash -lc "exec env DEXBTX_NO_SOLVER_AUTOUPDATE=0 bash /mnt/d/BTX/btx-pool-guard.sh run"' -WindowStyle Hidden
  Log "(re)launched pool guard"
}

Log "pool supervisor v2 started (pid $PID)"
$downStreak = 0
while($true){
  try {
    if(MiningUp){
      $downStreak = 0
    } else {
      $downStreak++
      if($downStreak -ge 3){   # ~90s of no solver before acting (lets the guard self-recover first)
        Log "solver down ${downStreak} checks -> (re)launching pool guard"
        LaunchPool
        $downStreak = 0
        Start-Sleep -Seconds 50
      }
    }
  } catch {
    Log ("loop error: " + $_.Exception.Message)
  }
  Start-Sleep -Seconds 30
}
