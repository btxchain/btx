@echo off
REM Updates /home/eldian/btx-node to the latest BTX GitHub Linux CUDA release.
wsl -d Ubuntu -- bash -lc "chmod +x /mnt/d/BTX/btx-update-latest.sh; bash /mnt/d/BTX/btx-update-latest.sh"
pause
