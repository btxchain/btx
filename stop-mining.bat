@echo off
echo Stopping BTX daemon (WSL)...
wsl -d Ubuntu -- /bin/bash -c "/home/eldian/btx-node/bin/btx-cli -datadir=/home/eldian/.btx stop"
echo BTX daemon stop requested.
pause
