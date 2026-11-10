# Recover missing payments in Qt

Open the selected wallet's Transactions page and choose **Recover missing payments**.
Choose a finite number of new keys per descriptor large enough to cover addresses
used since the backup. Confirm the full-history scan and unlock when prompted.
The scan follows the tip using the existing rescanblockchain behavior and replays
mempool transactions. New blocks may extend the job. A reorganisation of the
starting recovery range reports incomplete.

Cancel is available during preparation and scanning. Cancellation is cooperative.
Key derivation or a current block read may finish before it takes effect. Partial
discoveries remain in the wallet, and recovery can be retried. Required pruned or
unavailable blocks cause an error. A finite key range cannot guarantee discovery
of addresses arbitrarily far beyond it.

A wallet unlocked by this action relocks after the worker exits on success,
failure or cancellation. A wallet already unlocked remains under its existing
policy. A newer RPC walletpassphrase unlock retains ownership of its timer.
Existing scans prevent another recovery from starting.

## Native regression

Build the normal wallet-enabled daemon, CLI and Qt targets. On Ubuntu 22.04 the
desktop fixture requires Qt's X11 platform plugin, Xvfb, xauth, D-Bus, Openbox,
xdotool, wmctrl, scrot, gcc, AT-SPI and python3-pyatspi. Supply the runtime libraries
reported by ldd for those exact binaries.

Run from the repository root in an isolated test environment.

    dbus-run-session -- xvfb-run -a -s '-screen 0 1440x1000x24 -nolisten tcp' \
      sh -c 'openbox >/dev/null 2>&1 & exec /usr/bin/python3 "$@"' sh \
      test/functional/feature_qt_wallet_recovery.py --descriptors \
      --configfile=build/test/config.ini --qt-binary="$PWD/build/bin/btx-qt" \
      --qt-records=/tmp/btx-qt-recovery-records

The test is registered in the extended functional list. Without its native Qt
option, display or AT-SPI module it explicitly skips. Treat a skip as missing
coverage. --expect-action-absent records the old baseline UI observation only.

The test constructs a disposable encrypted stale backup and real regtest receipts.
It drives the native action, cancels an active scan, retries for the exact missing
outpoints and checks relocking. It also checks ordinary RPC scanning, an existing
unlock, and a new block plus a newer RPC unlock during recovery.

qt_recovery_delay.c is compiled only by the test into its observation directory.
It delays a block-file read only after this test wallet's scanner starts. The
Cancel interaction and the scanner's abort response remain real. Monetary mining
uses explicit economic/cpu-diagnostic regtest policies. This is wallet/UI evidence,
not consensus or release qualification. Wallets and data directories are temporary.
