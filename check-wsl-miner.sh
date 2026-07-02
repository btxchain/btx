#!/usr/bin/env bash
echo procs
ps -ef | grep -E 'dexbtx|btx-gbt|btxd|btx-pool-guard' | grep -v grep || true
echo miner_bin
ls -l /home/eldian/.local/bin/dexbtx-miner /home/eldian/.dexbtx-miner/config.yaml 2>&1 || true
echo pgrep
pgrep -af dexbtx-miner || true
pgrep -af btx-pool-guard || true
