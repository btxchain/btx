@echo off
REM Repairs the WSL BTX node by backing up the old datadir and loading D:\BTX\snapshot.dat.
wsl -d Ubuntu -- bash -lc "chmod +x /mnt/d/BTX/btx-restore-snapshot.sh; bash /mnt/d/BTX/btx-restore-snapshot.sh"
echo.
echo Restore log: D:\BTX\btx-restore-snapshot.log
pause
