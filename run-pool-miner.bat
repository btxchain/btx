@echo off
REM Starts the D:\BTX BTX pool miner guard in WSL Ubuntu and shows immediate status.
wsl -d Ubuntu -- bash -lc "chmod +x /mnt/d/BTX/btx-pool-guard.sh /mnt/d/BTX/btx-update-latest.sh; echo [$(date '+%%F %%T')] BAT start requested >> /mnt/d/BTX/btx-pool-launch.log; rm -f /tmp/btx-pool-guard.stop; nohup bash /mnt/d/BTX/btx-pool-guard.sh run >> /mnt/d/BTX/btx-pool-launch.log 2>&1 < /dev/null & sleep 2; bash /mnt/d/BTX/btx-pool-guard.sh status; tail -20 /mnt/d/BTX/btx-pool-guard.log 2>/dev/null || true"
echo.
echo Logs: D:\BTX\btx-pool-guard.log, D:\BTX\btx-pool-launch.log, D:\BTX\dexbtx-miner.log
pause
