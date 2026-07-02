@echo off
setlocal

set BTXCLI=wsl -d Ubuntu -- /bin/bash -c "/home/eldian/btx-node/bin/btx-cli -datadir=/home/eldian/.btx
set MINING_ADDRESS=btx1z2w6cuz0ja7qkhxngf8hz290m4s7cjsy7glfsf0zmmqawvg8j9y8q5xwgsw

echo ============================================
echo   BTX MatMul Miner (WSL) — Starting
echo ============================================
echo.

:: Step 1 — Start the daemon in WSL
echo [1/4] Starting btxd daemon in WSL...
wsl -d Ubuntu -- /bin/bash -c "/home/eldian/btx-node/bin/btxd -datadir=/home/eldian/.btx -daemon"
echo       Waiting 10s for daemon startup...
timeout /t 10 /nobreak >nul

:: Step 2 — Wait for RPC
echo [2/4] Waiting for RPC to be ready...
:rpc_wait
wsl -d Ubuntu -- /bin/bash -c "/home/eldian/btx-node/bin/btx-cli -datadir=/home/eldian/.btx getblockchaininfo" >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo       RPC not ready yet, retrying in 5s...
    timeout /t 5 /nobreak >nul
    goto rpc_wait
)
echo       RPC is ready.

:: Step 3 — Load wallet
echo [3/4] Loading miner wallet...
wsl -d Ubuntu -- /bin/bash -c "/home/eldian/btx-node/bin/btx-cli -datadir=/home/eldian/.btx createwallet miner false false '' false true true" >nul 2>&1
wsl -d Ubuntu -- /bin/bash -c "/home/eldian/btx-node/bin/btx-cli -datadir=/home/eldian/.btx loadwallet miner" >nul 2>&1
echo       Wallet ready.

:: Step 4 — Wait for sync
echo [4/4] Waiting for chain sync...
:sync_wait
wsl -d Ubuntu -- /bin/bash -c "/home/eldian/btx-node/bin/btx-cli -datadir=/home/eldian/.btx getblockchaininfo" 2>nul | findstr "initialblockdownload" | findstr "true" >nul
if %ERRORLEVEL% EQU 0 (
    echo       Still syncing, checking again in 15s...
    timeout /t 15 /nobreak >nul
    goto sync_wait
)
echo       Chain synced!

echo.
echo ============================================
echo   Mining to: %MINING_ADDRESS%
echo   Close this window or run stop-mining.bat
echo ============================================
echo.

:mine_loop
wsl -d Ubuntu -- /bin/bash -c "/home/eldian/btx-node/bin/btx-cli -datadir=/home/eldian/.btx generatetoaddress 1 %MINING_ADDRESS%"
if %ERRORLEVEL% NEQ 0 (
    echo [%TIME%] Mining paused — retrying in 30s...
    timeout /t 30 /nobreak >nul
) else (
    echo [%TIME%] Block attempt completed.
)
goto mine_loop
