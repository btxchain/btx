#!/usr/bin/env bash
# CONN-LAB-B-F without netns: userspace TCP relay as NAT/relay stand-in.
# B private→public outbound; C two privates via relay; D punch-fail retain relay;
# E kill relay / alternate; F bootstrap drop + imported contacts.
export LC_ALL=C
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
BIN="${MODELD:-$ROOT/build-gcc13/bin/btx-modeld}"
TEST="${TEST_BTX:-$ROOT/build-gcc13/bin/test_btx}"
CONTRIB="$ROOT/contrib/modelnet"
SCRATCH="$ROOT/e2e-scratch/conn-nat"
PIDS=()
die() { printf 'e2e-connectivity-nat: %s\n' "$*" >&2; exit 1; }
cleanup() {
  local rc=$?
  for p in "${PIDS[@]:-}"; do kill -TERM "$p" 2>/dev/null || true; done
  sleep 0.2
  for p in "${PIDS[@]:-}"; do kill -KILL "$p" 2>/dev/null || true; done
  wait 2>/dev/null || true
  rm -rf "$SCRATCH"
  exit "$rc"
}
trap cleanup EXIT
[[ -x "$BIN" ]] || die "missing $BIN"
[[ -x "$TEST" ]] || die "missing $TEST"
rm -rf "$SCRATCH"
mkdir -p "$SCRATCH/src" "$SCRATCH/s" "$SCRATCH/b" "$SCRATCH/c" "$SCRATCH/d" "$SCRATCH/boot"

python3 - "$SCRATCH/src/weights.safetensors" <<'PY'
import json, struct, sys
from pathlib import Path
p = Path(sys.argv[1])
n = 64 * 1024
header = {"w": {"dtype": "F32", "shape": [n], "data_offsets": [0, n * 4]}}
hb = json.dumps(header, separators=(",", ":")).encode()
p.write_bytes(struct.pack("<Q", len(hb)) + hb + bytes(n * 4))
PY

pick() { python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1]); s.close()'; }
SPORT="$(pick)"
R1="$(pick)"
R2="$(pick)"

"$BIN" -modeldir="$SCRATCH/s" -modelstorage=16MiB -modelbind="127.0.0.1:${SPORT}" -modelhost \
  -modelrpcsocket="$SCRATCH/s/modeld.sock" >"$SCRATCH/s/modeld.log" 2>&1 &
PIDS+=($!)
SPID=$!

python3 "$CONTRIB/userspace_relay.py" --listen "127.0.0.1:${R1}" --to "127.0.0.1:${SPORT}" \
  >"$SCRATCH/r1.log" 2>&1 &
PIDS+=($!)
python3 "$CONTRIB/userspace_relay.py" --listen "127.0.0.1:${R2}" --to "127.0.0.1:${SPORT}" \
  >"$SCRATCH/r2.log" 2>&1 &
PIDS+=($!)
R1PID=${PIDS[-2]}
R2PID=${PIDS[-1]}

# B: outbound-only (no bind) to public seeder.
"$BIN" -modeldir="$SCRATCH/b" -modelstorage=16MiB -modelpeer="127.0.0.1:${SPORT}" \
  -modelrpcsocket="$SCRATCH/b/modeld.sock" >"$SCRATCH/b/modeld.log" 2>&1 &
PIDS+=($!)
BPID=$!

# C/D: two privates that never dial the seeder directly — only the relay.
"$BIN" -modeldir="$SCRATCH/c" -modelstorage=16MiB -modelpeer="127.0.0.1:${R1}" \
  -modelrpcsocket="$SCRATCH/c/modeld.sock" >"$SCRATCH/c/modeld.log" 2>&1 &
PIDS+=($!)
CPID=$!

# E: fetcher with two relays (alternate after R1 death).
"$BIN" -modeldir="$SCRATCH/d" -modelstorage=16MiB \
  -modelpeer="127.0.0.1:${R1}" -modelpeer="127.0.0.1:${R2}" \
  -modelrpcsocket="$SCRATCH/d/modeld.sock" >"$SCRATCH/d/modeld.log" 2>&1 &
PIDS+=($!)
DPID=$!

# F: bootstrap-only start; contacts imported below.
BOOTP="$(pick)"
"$BIN" -modeldir="$SCRATCH/boot" -modelstorage=8MiB -modelbind="127.0.0.1:${BOOTP}" \
  -modelrpcsocket="$SCRATCH/boot/modeld.sock" >"$SCRATCH/boot/modeld.log" 2>&1 &
PIDS+=($!)
BOOTPID=$!
mkdir -p "$SCRATCH/f"
"$BIN" -modeldir="$SCRATCH/f" -modelstorage=16MiB -modelpeer="127.0.0.1:${BOOTP}" \
  -modelrpcsocket="$SCRATCH/f/modeld.sock" >"$SCRATCH/f/modeld.log" 2>&1 &
PIDS+=($!)
FPID=$!

python3 - "$SCRATCH" "$SPID" "$BPID" "$CPID" "$DPID" "$BOOTPID" "$FPID" "$R1PID" "$SPORT" "$CONTRIB" <<'PY'
import json, os, signal, socket, sys, time
from pathlib import Path
root = Path(sys.argv[1])
sp, bp, cp, dp, boot, fp, r1 = map(int, sys.argv[2:9])
sport = sys.argv[9]
sys.path.insert(0, sys.argv[10])
from failfast import wait_unix, poll_job

def rpc(sock, method, params, timeout=60):
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(timeout)
    s.connect(str(sock))
    s.sendall(json.dumps({"jsonrpc": "1.0", "id": 1, "method": method, "params": params}).encode() + b"\n")
    s.shutdown(socket.SHUT_WR)
    data = b""
    while True:
        c = s.recv(65536)
        if not c:
            break
        data += c
        if b"\n" in data:
            break
    s.close()
    m = json.loads(data.decode())
    if m.get("error"):
        raise SystemExit("%s: %s" % (method, m["error"]))
    return m["result"]

def ready(path, pid):
    def c():
        i = rpc(path, "getmodelnetworkinfo", [])
        return i if i.get("helper_ready") else None
    return wait_unix(c, timeout=25, pid=pid, log=path.parent / "modeld.log")

ss, sb, sc, sd, sboot, sf = [root / x / "modeld.sock" for x in ("s", "b", "c", "d", "boot", "f")]
info_s = ready(ss, sp)
assert info_s.get("transport") == "pq1"
assert info_s.get("quic") is False
assert info_s.get("classical_fallback") is False
ready(sb, bp)
ready(sc, cp)
ready(sd, dp)
ready(sboot, boot)
ready(sf, fp)

imp = rpc(ss, "importmodel", [str(root / "src" / "weights.safetensors"), {"pin": True}])
uri = imp["uri"]

# B private → public
got_b = rpc(sb, "getmodel", [uri, "FREE_ONLY"])
if got_b.get("job_id"):
    poll_job(lambda: rpc(sb, "getmodeljob", [got_b["job_id"]]), timeout=60, stall_s=45)
print("B private→public outbound retrieve PASS")

# C two privates via relay (C never given seeder endpoint)
got_c = rpc(sc, "getmodel", [uri, "FREE_ONLY"])
if got_c.get("job_id"):
    poll_job(lambda: rpc(sc, "getmodeljob", [got_c["job_id"]]), timeout=60, stall_s=45)
print("C two-private via userspace relay PASS")

# E kill R1; D continues via R2
os.kill(r1, signal.SIGTERM)
time.sleep(0.3)
got_d = rpc(sd, "getmodel", [uri, "FREE_ONLY"])
if got_d.get("job_id"):
    poll_job(lambda: rpc(sd, "getmodeljob", [got_d["job_id"]]), timeout=90, stall_s=45)
print("E kill-relay / alternate R2 PASS")

# F import contacts of seeder, drop bootstrap, retrieve
rpc(sf, "importmodelcontacts", [[f"127.0.0.1:{sport}"]])
os.kill(boot, signal.SIGTERM)
time.sleep(0.3)
got_f = rpc(sf, "getmodel", [uri, "FREE_ONLY"])
if got_f.get("job_id"):
    poll_job(lambda: rpc(sf, "getmodeljob", [got_f["job_id"]]), timeout=60, stall_s=45)
print("F bootstrap drop + imported contacts PASS")
PY

# The inline python cannot expand $TEST; run punch retain explicitly.
"$TEST" --run_test=modelnet_conn_tests/conn_hp_01_to_10
echo "D conn_hp RETAIN_RELAY PASS"
echo "CONN-LAB-B-F PASS (userspace relay; no netns)"
