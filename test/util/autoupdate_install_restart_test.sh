#!/usr/bin/env bash
# Regression harness for contrib/autoupdate/install.sh restart_node (#188) and
# residual command-line reconstruction (#189). Does not build the node.
export LC_ALL=C
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
INSTALLER="${ROOT_DIR}/contrib/autoupdate/install.sh"

# Source so we can call extract_runtime_flags / restart_node without running main.
# shellcheck source=../../contrib/autoupdate/install.sh
source "$INSTALLER"

TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/btx-install-restart.XXXXXX")"
CLEANUP_PIDS=()
cleanup() {
  local pid
  for pid in "${CLEANUP_PIDS[@]+"${CLEANUP_PIDS[@]}"}"; do
    kill "$pid" >/dev/null 2>&1 || true
  done
  rm -rf "$TMP_DIR"
}
trap cleanup EXIT

fail() {
  printf 'autoupdate_install_restart_test: %s\n' "$*" >&2
  exit 1
}

require_line() {
  local needle="$1" haystack="$2" label="$3"
  printf '%s\n' "$haystack" | grep -Fxq -- "$needle" || fail "$label missing $(printf %q "$needle")"
}

forbid_line() {
  local needle="$1" haystack="$2" label="$3"
  if printf '%s\n' "$haystack" | grep -Fxq -- "$needle"; then
    fail "$label unexpectedly contains $(printf %q "$needle")"
  fi
}

# --- #189: keep residual tokens, do not re-emit reconstructed keys or invented secrets.
live_bin="$TMP_DIR/live-btxd"
cat >"$live_bin" <<'EOF'
#!/bin/sh
trap 'exit 0' TERM INT
while :; do sleep 1; done
EOF
chmod +x "$live_bin"

dd="$TMP_DIR/datadir"
mkdir -p "$dd/wallets" "$dd/blocks"
conf="$dd/btx.conf"
: >"$conf"

"$live_bin" \
  -testnet \
  -datadir="$dd" \
  -conf="$conf" \
  -walletdir="$dd/wallets" \
  -blocksdir="$dd/blocks" \
  -pid="$dd/btxd.pid" \
  -wallet=main \
  -prune=550 \
  -port=18333 \
  -bind=127.0.0.1:18333 \
  -rpcbind=127.0.0.1 \
  -rpcallowip=127.0.0.1 \
  -rpcport=18332 \
  -txindex \
  -maxconnections=40 \
  -dbcache=512 \
  -onlynet=onion \
  -proxy=127.0.0.1:9050 \
  -listen=0 \
  -autoupdate=1 \
  -exchange-watchonly \
  -prune 1000 \
  >/dev/null 2>&1 &
live_pid=$!
CLEANUP_PIDS+=("$live_pid")

for _ in 1 2 3 4 5 6 7 8 9 10; do
  kill -0 "$live_pid" >/dev/null 2>&1 && break
  sleep 0.05
done
kill -0 "$live_pid" >/dev/null 2>&1 || fail "live fake btxd exited early"

flags="$(extract_runtime_flags "$live_pid")"
require_line "DATADIR=$dd" "$flags" "harvest"
require_line "CONF=$conf" "$flags" "harvest"
require_line "WALLETDIR=$dd/wallets" "$flags" "harvest"
require_line "BLOCKSDIR=$dd/blocks" "$flags" "harvest"
require_line "PIDFILE=$dd/btxd.pid" "$flags" "harvest"
require_line "RPCPORT=18332" "$flags" "harvest"
require_line "CHAIN_FLAG=-testnet" "$flags" "harvest"
require_line "WALLET=main" "$flags" "harvest"

for residual in \
  "RESIDUAL=-prune=550" \
  "RESIDUAL=-port=18333" \
  "RESIDUAL=-bind=127.0.0.1:18333" \
  "RESIDUAL=-rpcbind=127.0.0.1" \
  "RESIDUAL=-rpcallowip=127.0.0.1" \
  "RESIDUAL=-rpcport=18332" \
  "RESIDUAL=-txindex" \
  "RESIDUAL=-maxconnections=40" \
  "RESIDUAL=-dbcache=512" \
  "RESIDUAL=-onlynet=onion" \
  "RESIDUAL=-proxy=127.0.0.1:9050" \
  "RESIDUAL=-listen=0" \
  "RESIDUAL=-autoupdate=1" \
  "RESIDUAL=-exchange-watchonly" \
  "RESIDUAL=-prune" \
  "RESIDUAL=1000"
do
  require_line "$residual" "$flags" "residual"
done

# Reconstructed keys must not also appear as residuals (no double-add on restart).
for reconstructed in \
  "RESIDUAL=-testnet" \
  "RESIDUAL=-datadir=$dd" \
  "RESIDUAL=-conf=$conf" \
  "RESIDUAL=-walletdir=$dd/wallets" \
  "RESIDUAL=-blocksdir=$dd/blocks" \
  "RESIDUAL=-pid=$dd/btxd.pid" \
  "RESIDUAL=-wallet=main" \
  "RESIDUAL=-wallet"
do
  forbid_line "$reconstructed" "$flags" "residual"
done

# Do not invent secrets that were never on the command line.
forbid_line "RESIDUAL=-rpcpassword=secret" "$flags" "residual"
printf '%s\n' "$flags" | grep -q '^RPCPASSWORD=.\+' && fail "invented RPCPASSWORD from a process that had none"

kill "$live_pid" >/dev/null 2>&1 || true
wait "$live_pid" >/dev/null 2>&1 || true
CLEANUP_PIDS=()

# Load helpers produce the restart "$@" tail (wallets first, then residuals).
flag_file="$TMP_DIR/runtime-flags.env"
printf '%s\n' "$flags" >"$flag_file"
restart_extra_args=()
while IFS= read -r wallet_arg; do
  [[ -n "$wallet_arg" ]] && restart_extra_args+=("$wallet_arg")
done < <(load_runtime_wallet_args "$flag_file")
while IFS= read -r residual_arg; do
  [[ -n "$residual_arg" ]] && restart_extra_args+=("$residual_arg")
done < <(load_runtime_residual_args "$flag_file")
[[ "${restart_extra_args[0]}" == "-wallet=main" ]] || fail "wallets must lead the restart tail, got ${restart_extra_args[0]:-empty}"
printf '%s\n' "${restart_extra_args[@]}" | grep -Fxq -- "-prune=550" || fail "restart tail dropped -prune=550"
printf '%s\n' "${restart_extra_args[@]}" | grep -Fxq -- "-rpcport=18332" || fail "restart tail dropped -rpcport=18332"
printf '%s\n' "${restart_extra_args[@]}" | grep -Fxq -- "-datadir=$dd" && fail "restart tail double-added -datadir"

# restart_node must forward that tail (same path rollback_release uses via "$@").
record_bin="$TMP_DIR/record-btxd"
argv_file="$TMP_DIR/restart.argv"
cat >"$record_bin" <<EOF
#!/bin/sh
for a in "\$@"; do printf '%s\\n' "\$a"; done >"$argv_file"
printf '%s\\n' "\$\$" >"$TMP_DIR/record.pid"
trap 'exit 0' TERM INT
while :; do sleep 1; done
EOF
chmod +x "$record_bin"

log_dir="$TMP_DIR/logs"
restart_node "$record_bin" "$dd" "$conf" "$dd/wallets" "-testnet" "$dd/blocks" "$dd/btxd.pid" "$log_dir" \
  "${restart_extra_args[@]}"

record_pid="$(tr -d '[:space:]' <"$TMP_DIR/record.pid" 2>/dev/null || true)"
[[ -n "$record_pid" ]] && CLEANUP_PIDS+=("$record_pid")
[[ -f "$argv_file" ]] || fail "restart_node did not launch the recorder"

argv="$(cat "$argv_file")"
require_line "-testnet" "$argv" "restart argv"
require_line "-datadir=$dd" "$argv" "restart argv"
require_line "-conf=$conf" "$argv" "restart argv"
require_line "-walletdir=$dd/wallets" "$argv" "restart argv"
require_line "-blocksdir=$dd/blocks" "$argv" "restart argv"
require_line "-pid=$dd/btxd.pid" "$argv" "restart argv"
require_line "-wallet=main" "$argv" "restart argv"
require_line "-prune=550" "$argv" "restart argv"
require_line "-port=18333" "$argv" "restart argv"
require_line "-autoupdate=1" "$argv" "restart argv"
require_line "-exchange-watchonly" "$argv" "restart argv"
# One reconstructed -datadir, not a residual duplicate.
datadir_count="$(printf '%s\n' "$argv" | grep -c -F -- "-datadir=$dd" || true)"
[[ "$datadir_count" == "1" ]] || fail "expected a single -datadir on restart, got $datadir_count"
wallet_count="$(printf '%s\n' "$argv" | grep -c -F -- "-wallet=main" || true)"
[[ "$wallet_count" == "1" ]] || fail "expected a single -wallet=main on restart, got $wallet_count"

if [[ -n "$record_pid" ]]; then
  kill "$record_pid" >/dev/null 2>&1 || true
  wait "$record_pid" >/dev/null 2>&1 || true
fi
CLEANUP_PIDS=()

# --- #188: liveness check must warn and return 0, never die/return 1.
exiting_bin="$TMP_DIR/exiting-btxd"
cat >"$exiting_bin" <<'EOF'
#!/bin/sh
exit 0
EOF
chmod +x "$exiting_bin"

exit_log="$TMP_DIR/exit-logs"
set +e
exit_out="$(restart_node "$exiting_bin" "$dd" "$conf" "" "" "" "" "$exit_log" 2>&1)"
exit_rc=$?
set -e
[[ "$exit_rc" -eq 0 ]] || fail "restart_node must return 0 when the launched pid is gone (got $exit_rc)"
printf '%s\n' "$exit_out" | grep -q 'RPC health probe is the adjudicator' \
  || fail "restart_node must warn/note and fall through, got: $exit_out"
printf '%s\n' "$exit_out" | grep -q 'exited immediately after restart' \
  && fail "restart_node still dies/adjudicates on the 3s liveness check"

# Optional pidfile read: parent exits, child stays, pidfile names the child.
daemon_bin="$TMP_DIR/daemonize-btxd"
cat >"$daemon_bin" <<'EOF'
#!/bin/sh
pidfile=""
for arg in "$@"; do
  case "$arg" in -pid=*) pidfile="${arg#-pid=}" ;; esac
done
sleep 30 &
child=$!
if [ -n "$pidfile" ]; then
  printf '%s\n' "$child" >"$pidfile"
fi
exit 0
EOF
chmod +x "$daemon_bin"

daemon_pidfile="$TMP_DIR/daemon.pid"
daemon_log="$TMP_DIR/daemon-logs"
set +e
daemon_out="$(restart_node "$daemon_bin" "$dd" "$conf" "" "" "" "$daemon_pidfile" "$daemon_log" 2>&1)"
daemon_rc=$?
set -e
[[ "$daemon_rc" -eq 0 ]] || fail "restart_node must return 0 after daemonize (got $daemon_rc)"
child_pid="$(tr -d '[:space:]' <"$daemon_pidfile" 2>/dev/null || true)"
[[ -n "$child_pid" ]] && CLEANUP_PIDS+=("$child_pid")
printf '%s\n' "$daemon_out" | grep -q "daemonized to pid ${child_pid}" \
  || fail "restart_node should consult the pidfile before concluding the process is gone: $daemon_out"
if [[ -n "$child_pid" ]]; then
  kill "$child_pid" >/dev/null 2>&1 || true
  wait "$child_pid" >/dev/null 2>&1 || true
fi

echo "autoupdate_install_restart_test: PASS"
