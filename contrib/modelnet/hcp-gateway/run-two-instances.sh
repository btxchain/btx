#!/usr/bin/env bash
# Start two independent loopback btx-hcpd processes (same HCP/1+CR11 binary).
# A: -walletless. B: -finance=1 enables Cognitive Reserve v1.1 on that
# existing daemon — not a second gateway product.
# Isolated REGTEST only. Does not touch production btxd. SIGTERM our PIDs only.
# Never ninja. Never bind non-loopback. automatic_spend_atoms stays 0.
# Topology required: two instances + one local client (btx-hosted walletless).
set -euo pipefail

die() { echo "run-two-instances: $*" >&2; exit 1; }

# Binaries: BUILDDIR (cmake tree) first, then the 0.34.8-regtest prefix if present.
# One btx-hcpd executable, launched twice. Do not look for a cr11/reserve daemon.
pick_bin() {
  local cand
  if [[ -n "${BUILDDIR:-}" ]]; then
    for cand in "${BUILDDIR%/}/bin" "${BUILDDIR%/}"; do
      if [[ -x "$cand/btx-hcpd" ]]; then
        printf '%s\n' "$cand"
        return 0
      fi
    done
  fi
  cand="${HOME}/.local/opt/btx-0.34.8-regtest/bin"
  if [[ -x "$cand/btx-hcpd" ]]; then
    printf '%s\n' "$cand"
    return 0
  fi
  return 1
}

BIN="$(pick_bin)" || die "no btx-hcpd (set BUILDDIR to a cmake tree, or install \$HOME/.local/opt/btx-0.34.8-regtest/bin; do not ninja from this script)"
HCPD="$BIN/btx-hcpd"
HOSTED="$BIN/btx-hosted"
[[ -x "$HCPD" ]] || die "missing executable $HCPD"

# Hard loopback. Ports may change; host must not.
HOST="127.0.0.1"
PORT_A="${HCP_PORT_A:-18780}"
PORT_B="${HCP_PORT_B:-18781}"
BIND_A="${HOST}:${PORT_A}"
BIND_B="${HOST}:${PORT_B}"

assert_loopback() {
  local bind="$1"
  case "$bind" in
    127.0.0.1:*|localhost:*) ;;
    *) die "refusing non-loopback bind: $bind (btx-hcpd loopback only)" ;;
  esac
}
assert_loopback "$BIND_A"
assert_loopback "$BIND_B"

PID_A=""
PID_B=""
DATAA=""
DATAB=""

cleanup() {
  local rc=$?
  trap - EXIT INT TERM
  # Terminate only the lab PIDs we started. Never SIGKILL production btxd.
  if [[ -n "$PID_A" ]] && kill -0 "$PID_A" 2>/dev/null; then
    kill -TERM "$PID_A" 2>/dev/null || true
  fi
  if [[ -n "$PID_B" ]] && kill -0 "$PID_B" 2>/dev/null; then
    kill -TERM "$PID_B" 2>/dev/null || true
  fi
  if [[ -n "$PID_A" ]]; then wait "$PID_A" 2>/dev/null || true; fi
  if [[ -n "$PID_B" ]]; then wait "$PID_B" 2>/dev/null || true; fi
  if [[ -n "$DATAA" && -d "$DATAA" ]]; then rm -rf "$DATAA"; fi
  if [[ -n "$DATAB" && -d "$DATAB" ]]; then rm -rf "$DATAB"; fi
  exit "$rc"
}
trap cleanup EXIT INT TERM

DATAA="$(mktemp -d /tmp/hcp-a.XXXXXX)"
DATAB="$(mktemp -d /tmp/hcp-b.XXXXXX)"

# Preset flags replace HcpConfig; they must precede -datadir / -instance.
# A: walletless DISCOVERY/HANDOFF (CR11 off → PROFILE_UNSUPPORTED).
# B: -finance=1 FUNDING + Cognitive Reserve v1.1 on the same btx-hcpd (default on).
"$HCPD" -walletless -datadir="$DATAA" -instance=hcp-a -bind="$BIND_A" \
  >"$DATAA/hcpd.log" 2>&1 &
PID_A=$!

if [[ "${HCP_FINANCE_B:-1}" == "1" ]]; then
  "$HCPD" -finance=1 -datadir="$DATAB" -instance=hcp-b -bind="$BIND_B" \
    >"$DATAB/hcpd.log" 2>&1 &
  PID_B=$!
  LABEL_B="finance+CR11 lab (-finance=1 on existing btx-hcpd)"
else
  "$HCPD" -walletless -datadir="$DATAB" -instance=hcp-b -bind="$BIND_B" \
    >"$DATAB/hcpd.log" 2>&1 &
  PID_B=$!
  LABEL_B="walletless (second origin; CR11 still off)"
fi

wait_profile() {
  local url="$1"
  local which="$2"
  local n=0
  while (( n < 50 )); do
    if curl -fsS --max-time 1 "$url" >/dev/null 2>&1; then
      return 0
    fi
    if [[ -n "$PID_A" ]] && ! kill -0 "$PID_A" 2>/dev/null; then
      die "walletless btx-hcpd exited; see $DATAA/hcpd.log"
    fi
    if [[ -n "$PID_B" ]] && ! kill -0 "$PID_B" 2>/dev/null; then
      die "second btx-hcpd exited; see $DATAB/hcpd.log"
    fi
    n=$((n + 1))
    sleep 0.1
  done
  die "timeout waiting for $which $url"
}

wait_profile "http://${BIND_A}/profile" "hcp-a"
wait_profile "http://${BIND_B}/profile" "hcp-b"

echo
echo "=== two loopback btx-hcpd instances are up (REGTEST lab) ==="
echo "same binary  $HCPD  (HCP/1+CR11; not a second gateway)"
echo "walletless  $BIND_A  -instance=hcp-a  datadir=$DATAA  pid=$PID_A"
echo "$LABEL_B $BIND_B  -instance=hcp-b  datadir=$DATAB  pid=$PID_B"
echo "binaries    $BIN"
echo "local client required: btx-hosted walletless (no HTTP bind)"
echo

echo "=== curl GET /profile (both) ==="
echo "--- ${BIND_A} ---"
curl -sS --max-time 5 "http://${BIND_A}/profile" || die "curl ${BIND_A}/profile failed"
echo
echo "--- ${BIND_B} ---"
curl -sS --max-time 5 "http://${BIND_B}/profile" || die "curl ${BIND_B}/profile failed"
echo
echo

echo "=== curl GET /health (cognitive_reserve follows -finance=1) ==="
echo "--- ${BIND_A} ---"
curl -sS --max-time 5 "http://${BIND_A}/health" || die "curl ${BIND_A}/health failed"
echo
echo "--- ${BIND_B} ---"
curl -sS --max-time 5 "http://${BIND_B}/health" || die "curl ${BIND_B}/health failed"
echo
echo

# Walletless must refuse CR11 routes. HTTP 403 is expected; do not use curl -f.
expect_profile_unsupported() {
  local path="$1"
  local url="http://${BIND_A}${path}"
  local body
  body="$(curl -sS --max-time 5 -X POST -H 'Content-Type: application/json' --data '{}' "$url" || true)"
  echo "--- POST ${BIND_A}${path} ---"
  echo "$body"
  echo
  printf '%s' "$body" | grep -q '"PROFILE_UNSUPPORTED"' \
    || die "walletless ${path} must return PROFILE_UNSUPPORTED (got: ${body:-empty})"
}

echo "=== walletless CR11 fail-closed (PROFILE_UNSUPPORTED) ==="
expect_profile_unsupported "/reserve/portfolios"
expect_profile_unsupported "/capital/plans"

if [[ -x "$HOSTED" ]]; then
  echo "=== local client: btx-hosted walletless ==="
  "$HOSTED" walletless || true
  echo
else
  echo "=== btx-hosted not found next to btx-hcpd; skip walletless connector ==="
  echo
fi

echo "=== DEMO steps (also contrib/modelnet/hcp-gateway/DEMO.md) ==="
cat <<EOF
Topology (required): two loopback btx-hcpd instances + one local client.
Same binary twice. -finance=1 enables Cognitive Reserve v1.1 on existing
btx-hcpd (HCP/1+CR11). There is no second gateway daemon.

1. GET /profile (public) — already curled above
   curl -sS http://${BIND_A}/profile
   curl -sS http://${BIND_B}/profile

2. POST /capabilities/search (catalogue; ranking is annotation not protocol)
   curl -sS -H 'Content-Type: application/json' --data '{}' \\
     http://${BIND_A}/capabilities/search

3. /rpc is 404 GENERIC_RPC_DISABLED (typed operations only)
   curl -sS -D - -o - -X POST --data '{}' http://${BIND_A}/rpc

4. Unauthenticated finance fail-closed
   curl -sS -D - -o - -X POST http://${BIND_B}/finance/quotes
     → 401 UNAUTHENTICATED when B is -finance=1
   curl -sS -D - -o - -X POST --data '{}' http://${BIND_A}/finance/quotes
     → 403 FUNDING_DISABLED

5. Walletless CR11 fail-closed (already curled above)
   curl -sS -X POST -H 'Content-Type: application/json' --data '{}' \\
     http://${BIND_A}/reserve/portfolios
     → 403 PROFILE_UNSUPPORTED
   curl -sS -X POST -H 'Content-Type: application/json' --data '{}' \\
     http://${BIND_A}/capital/plans
     → 403 PROFILE_UNSUPPORTED
   Same 403 on GET /extensions/cognitive-reserve when A is -walletless.
   When B is -finance=1, unauthenticated /reserve and /capital are 401
   UNAUTHENTICATED (extension on; credentials missing) — not PROFILE_UNSUPPORTED.

automatic_spend_atoms stays 0. Loopback only (127.0.0.1 / localhost).
Ctrl-C SIGTERM's these two lab PIDs only. Not production btxd. Not btxd.real.
EOF
echo
echo "lab running — Ctrl-C to SIGTERM pid $PID_A and $PID_B"
wait "$PID_A" "$PID_B" || true
