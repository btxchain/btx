@echo off
REM Stops the D:\BTX BTX pool miner guard and pool miner in WSL Ubuntu.
wsl -d Ubuntu -- bash -lc "bash /mnt/d/BTX/btx-pool-guard.sh stop"
echo BTX pool miner guard and pool miner stop requested.
