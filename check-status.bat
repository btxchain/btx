@echo off
echo ============================================
echo   BTX Node Status (WSL)
echo ============================================
echo.
echo --- Mining Info ---
wsl -d Ubuntu -- /bin/bash -c "/home/eldian/btx-node/bin/btx-cli -datadir=/home/eldian/.btx getmininginfo"
echo.
echo --- Blockchain Info ---
wsl -d Ubuntu -- /bin/bash -c "/home/eldian/btx-node/bin/btx-cli -datadir=/home/eldian/.btx getblockchaininfo"
echo.
echo --- Peer Count ---
wsl -d Ubuntu -- /bin/bash -c "/home/eldian/btx-node/bin/btx-cli -datadir=/home/eldian/.btx getconnectioncount"
echo.
echo --- Mining Address ---
echo btx1z2w6cuz0ja7qkhxngf8hz290m4s7cjsy7glfsf0zmmqawvg8j9y8q5xwgsw
echo.
pause
