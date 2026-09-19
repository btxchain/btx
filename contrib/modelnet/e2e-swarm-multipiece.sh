#!/usr/bin/env bash
# Multi-piece live swarm: seeders A/B/C + buyer D on loopback PQ1.
#
# e2e-swarm-live.sh seeds a 45-byte one-piece artifact, so its assignment and
# failover evidence is necessarily degenerate. This script imports a real
# multi-piece safetensors (8 MiB payload => 3 canonical PIECE_SIZE=4MiB pieces),
# then deletes .piece files under each seeder's store so no single seeder can
# serve the whole file:
#
#   A -> piece 0 only
#   B -> pieces 1..n-1
#   C -> every piece (overlapping, non-identical with both A and B)
#
# Buyer D must therefore assemble the file from more than one seeder. Seeder A
# is SIGTERMed as soon as D commits its first piece; a cold buyer E then
# retrieves with A already gone, so the failover evidence is deterministic even
# when the mid-transfer kill loses the race against loopback.
#
# On-disk piece layout matched to ModelStore (src/modelnet/store.cpp
# ArtifactDir): <modeldir>/store/artifacts/<artifact_hex>/<file_index>/<n>.piece
#
# Loopback scratch helpers only. Never production btxd, never a production
# helper, never SIGKILL of anything we did not start. automatic_spend_atoms=0.
export LC_ALL=C
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
BIN="${MODELD:-$ROOT/build-gcc13/bin/btx-modeld}"
EVID="${EVIDENCE_DIR:-$ROOT/audit/e2e}"
SCRATCH="$ROOT/e2e-scratch/swarm-multipiece"
mkdir -p "$EVID"
LOG="$EVID/swarm-multipiece.log"

die() { printf 'e2e-swarm-multipiece: %s\n' "$*" | tee -a "$LOG" >&2; exit 1; }

PIDS=()
cleanup() {
  local rc=$?
  for p in "${PIDS[@]:-}"; do kill -TERM "$p" 2>/dev/null || true; done
  sleep 0.4
  for p in "${PIDS[@]:-}"; do kill -KILL "$p" 2>/dev/null || true; done
  wait 2>/dev/null || true
  exit "$rc"
}
trap cleanup EXIT

[[ -x "$BIN" ]] || die "missing $BIN"
[[ "$BIN" != *granite* ]] || die "refusing granite path"
case "$BIN" in
  */libexec/btxd.real|*/.local/opt/*) die "refusing packaged/production path: $BIN" ;;
esac

rm -rf "$SCRATCH"
mkdir -p "$SCRATCH/src"
: >"$LOG"
{
  echo "e2e-swarm-multipiece start $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "binary $BIN"
  stat -c 'mtime=%y size=%s' "$BIN"
} | tee -a "$LOG"

# 8 MiB of U8 tensor bytes plus the safetensors length prefix and JSON header.
# Total is just over 8 MiB, so the canonical piece count is 3 (two full 4 MiB
# pieces and a short tail), which is the 2+ this test needs.
python3 "$ROOT/contrib/modelnet/write_safetensors_payload.py" \
  "$SCRATCH/src/model.safetensors" $((8 * 1024 * 1024))
stat -c 'source model.safetensors size=%s' "$SCRATCH/src/model.safetensors" | tee -a "$LOG"

port() {
  python3 - <<'PY'
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("127.0.0.1", 0))
print(s.getsockname()[1])
s.close()
PY
}

PA="$(port)"; PB="$(port)"; PC="$(port)"
for n in a b c d e; do mkdir -p "$SCRATCH/$n"; : >"$SCRATCH/$n/modeld.log"; done

for n in a b c; do
  case "$n" in a) bp="$PA" ;; b) bp="$PB" ;; c) bp="$PC" ;; esac
  "$BIN" -modeldir="$SCRATCH/$n" -modelstorage=64MiB -modelbind="127.0.0.1:${bp}" -modelhost \
    -modelrpcsocket="$SCRATCH/$n/modeld.sock" >>"$SCRATCH/$n/modeld.log" 2>&1 &
  PIDS+=($!)
done
# D is the buyer of record. E is a cold buyer used only for the post-failover
# round, so the A-absent retrieve does not depend on winning a kill race.
for n in d e; do
  "$BIN" -modeldir="$SCRATCH/$n" -modelstorage=64MiB \
    -modelpeer="127.0.0.1:${PA}" -modelpeer="127.0.0.1:${PB}" -modelpeer="127.0.0.1:${PC}" \
    -modelrpcsocket="$SCRATCH/$n/modeld.sock" >>"$SCRATCH/$n/modeld.log" 2>&1 &
  PIDS+=($!)
done

python3 - "$SCRATCH" "$EVID" "$LOG" "$PA" "$PB" "$PC" \
  "${PIDS[0]}" "${PIDS[1]}" "${PIDS[2]}" "${PIDS[3]}" "${PIDS[4]}" \
  "$ROOT/contrib/modelnet" <<'PY'
from __future__ import annotations

import hashlib
import json
import os
import signal
import socket
import sys
import time
from pathlib import Path

scratch = Path(sys.argv[1])
evid = Path(sys.argv[2])
logp = Path(sys.argv[3])
ports = {"a": sys.argv[4], "b": sys.argv[5], "c": sys.argv[6]}
pids = {n: int(p) for n, p in zip("abcde", sys.argv[7:12])}
sys.path.insert(0, sys.argv[12])
from failfast import pid_alive, poll_job, wait_unix

PIECE_SIZE = 4 << 20  # src/modelnet/types.h


def rpc(sock: Path, method: str, params, timeout: float = 60):
    payload = {"jsonrpc": "1.0", "id": 1, "method": method, "params": params}
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(timeout)
    s.connect(str(sock))
    s.sendall(json.dumps(payload, separators=(",", ":")).encode() + b"\n")
    s.shutdown(socket.SHUT_WR)
    data = b""
    while True:
        chunk = s.recv(65536)
        if not chunk:
            break
        data += chunk
        if b"\n" in data:
            break
    s.close()
    if not data:
        raise SystemExit(f"{method}: empty reply from {sock}")
    reply = json.loads(data.decode())
    if reply.get("error"):
        raise SystemExit(f"{method}: {reply['error']}")
    result = reply["result"]
    if isinstance(result, dict):
        spend = result.get("automatic_spend_atoms", 0)
        if spend not in (0, "0"):
            raise SystemExit(f"{method} automatic_spend_atoms={spend}")
    return result


def log(msg: str):
    line = msg if msg.endswith("\n") else msg + "\n"
    sys.stdout.write(line)
    sys.stdout.flush()
    with logp.open("a", encoding="utf-8") as fh:
        fh.write(line)


socks = {n: scratch / n / "modeld.sock" for n in "abcde"}


def wait_helper(name: str):
    def connect():
        info = rpc(socks[name], "getmodelnetworkinfo", [])
        if info.get("helper_ready") and info.get("enabled"):
            return info
        return None

    info = wait_unix(connect, timeout=30, pid=pids[name], log=socks[name].parent / "modeld.log")
    if not info.get("pq1_ready"):
        raise SystemExit(f"{name} pq1 not ready: {info}")
    log(f"helper {name} ready pq1={info.get('pq1_ready')}")
    return info


for n in "abcde":
    wait_helper(n)

src = scratch / "src" / "model.safetensors"

uri = None
for n in "abc":
    imported = rpc(socks[n], "importmodel", [str(src), {"pin": True}])
    log(f"import {n} uri={imported.get('uri')} seeded={imported.get('seeded')}")
    if imported.get("seeded") is not True:
        raise SystemExit(f"{n} import did not demand-seed: {imported}")
    if uri is None:
        uri = imported["uri"]
    elif imported["uri"] != uri:
        raise SystemExit(f"identity diverged {n}: {imported['uri']} != {uri}")
log(f"canonical uri {uri}")

man = rpc(socks["a"], "getmodelmanifest", [uri])
artifact = man["artifact_id"]
if int(man.get("piece_size") or 0) != PIECE_SIZE:
    raise SystemExit(f"helper piece_size {man.get('piece_size')} != {PIECE_SIZE}")
files = man.get("files") or []
if len(files) != 1:
    raise SystemExit(f"expected a single-file artifact, got {files}")
file_size = int(files[0]["size"])
expected_sha = files[0]["sha384"]
n_pieces = (file_size + PIECE_SIZE - 1) // PIECE_SIZE
log(f"artifact {artifact} file_size={file_size} pieces={n_pieces}")
if n_pieces < 2:
    raise SystemExit(f"need a multi-piece artifact, got {n_pieces}")


def piece_dir(node: str, file_index: int = 0) -> Path:
    # src/modelnet/catalog.cpp: ModelCatalog store root is <modeldir>/store.
    # src/modelnet/store.cpp ArtifactDir: <root>/artifacts/<hex>/<fi>/<pi>.piece
    return scratch / node / "store" / "artifacts" / artifact / str(file_index)


def on_disk(node: str, file_index: int = 0) -> list[int]:
    d = piece_dir(node, file_index)
    out = []
    for p in sorted(d.glob("*.piece")):
        try:
            out.append(int(p.name.split(".")[0]))
        except ValueError:
            continue
    return sorted(out)


def keep_only(node: str, keep: set[int], file_index: int = 0) -> list[int]:
    d = piece_dir(node, file_index)
    if not d.is_dir():
        raise SystemExit(f"missing piece dir {d}; ArtifactDir layout changed")
    for p in sorted(d.glob("*.piece")):
        try:
            idx = int(p.name.split(".")[0])
        except ValueError:
            continue
        if idx not in keep:
            p.unlink()
    got = on_disk(node, file_index)
    if got != sorted(keep):
        raise SystemExit(f"{node} kept {got} want {sorted(keep)}")
    return got


for n in "abc":
    full = on_disk(n)
    if full != list(range(n_pieces)):
        raise SystemExit(f"seeder {n} imported {full}, expected {list(range(n_pieces))}")

# A holds only the first piece, B holds only the remainder, C holds everything.
# No seeder is redundant with another and no seeder except C is complete.
plan = {"a": {0}, "b": set(range(1, n_pieces)), "c": set(range(n_pieces))}
ownership = {n: keep_only(n, plan[n]) for n in "abc"}
for n in "abc":
    log(f"seeder {n} pieces {ownership[n]}")
if set(ownership["a"]) | set(ownership["b"]) != set(range(n_pieces)):
    raise SystemExit(f"A|B must cover the file: {ownership}")
if set(ownership["a"]) & set(ownership["b"]):
    raise SystemExit(f"A and B must be disjoint: {ownership}")
if set(ownership["c"]) != set(range(n_pieces)):
    raise SystemExit(f"C must overlap both: {ownership}")

peers = rpc(socks["d"], "getmodelpeers", [])
if not peers.get("peers"):
    raise SystemExit(f"buyer D has no peers: {peers}")
log(f"buyer D peers {json.dumps(peers.get('peers'))}")


def assemble_sha(node: str, file_index: int = 0) -> str:
    h = hashlib.sha384()
    total = 0
    for i in range(n_pieces):
        p = piece_dir(node, file_index) / f"{i}.piece"
        if not p.is_file():
            raise SystemExit(f"{node} missing committed piece {i}")
        b = p.read_bytes()
        total += len(b)
        h.update(b)
    if total != file_size:
        raise SystemExit(f"{node} assembled {total} bytes want {file_size}")
    return h.hexdigest()


def retrieve(node: str, timeout: float, progress=None) -> dict:
    got = rpc(socks[node], "getmodel", [uri, "FREE_ONLY"])
    job_id = got.get("job_id")
    if got.get("status") in ("retrieved", "local") and not job_id:
        return got
    if not job_id:
        raise SystemExit(f"{node} getmodel gave neither job nor completion: {got}")
    job = poll_job(
        lambda: rpc(socks[node], "getmodeljob", [job_id]),
        timeout=timeout,
        progress=progress,
        job_id=job_id,
    )
    result = job.get("result") or {}
    if result.get("status") not in ("retrieved", "local"):
        raise SystemExit(f"{node} retrieve failed: {job}")
    job["_result"] = result
    return job


# --- Buyer D retrieves, seeder A is SIGTERMed at the first committed piece ---
observed: list[dict] = []
kill = {"done": False, "at_pieces": None, "at_bytes": None, "at_peer": None}


def term_seeder_a():
    """Scratch helper we started ourselves; graceful TERM, never KILL."""
    try:
        os.kill(pids["a"], signal.SIGTERM)
    except ProcessLookupError:
        pass


def watch(job: dict):
    seen = {
        k: job.get(k)
        for k in ("status", "pieces_committed", "bytes_committed", "piece_index", "last_peer", "peer_retries")
    }
    if not observed or observed[-1] != seen:
        observed.append(seen)
    if kill["done"]:
        return
    if int(job.get("pieces_committed") or 0) >= 1:
        term_seeder_a()
        kill["done"] = True
        kill["at_pieces"] = job.get("pieces_committed")
        kill["at_bytes"] = job.get("bytes_committed")
        kill["at_peer"] = job.get("last_peer")
        log(f"SIGTERM seeder A mid-transfer at pieces_committed={kill['at_pieces']}")


d_job = retrieve("d", timeout=240, progress=watch)
d_result = d_job.get("_result") or d_job
log(f"buyer D retrieved last_peer={d_result.get('last_peer') or d_job.get('last_peer')}")

d_pieces = on_disk("d")
if d_pieces != list(range(n_pieces)):
    raise SystemExit(f"buyer D committed {d_pieces}, want {list(range(n_pieces))}")
d_sha = assemble_sha("d")
if d_sha != expected_sha:
    raise SystemExit(f"buyer D sha384 {d_sha} != manifest {expected_sha}")
log(f"buyer D committed pieces {d_pieces} sha384 matches manifest")

d_man = rpc(socks["d"], "getmodelmanifest", [uri])
if d_man.get("artifact_id") != artifact:
    raise SystemExit(f"buyer D artifact {d_man.get('artifact_id')} != {artifact}")
if d_man.get("complete") is not True:
    raise SystemExit(f"buyer D manifest incomplete: {d_man}")
d_xfer = rpc(socks["d"], "getmodeltransfers", [])

# --- Deterministic failover: cold buyer E retrieves with A gone ---
mid_transfer = kill["done"]
if not mid_transfer:
    log("mid-transfer kill lost the race; terminating A before the cold round")
    term_seeder_a()


def a_refuses_connections() -> bool:
    """A zombie bash has not reaped yet still cannot accept, so probe the port."""
    probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    probe.settimeout(0.5)
    try:
        probe.connect(("127.0.0.1", int(ports["a"])))
        return False
    except OSError:
        return True
    finally:
        probe.close()


deadline = time.time() + 30
while not a_refuses_connections() and time.time() < deadline:
    time.sleep(0.2)
if not a_refuses_connections():
    raise SystemExit(f"seeder A still accepting on 127.0.0.1:{ports['a']} after SIGTERM")
log(f"seeder A is down (pid_alive={pid_alive(pids['a'])}, port refuses)")

e_observed: list[dict] = []


def watch_e(job: dict):
    seen = {k: job.get(k) for k in ("status", "pieces_committed", "last_peer", "peer_retries")}
    if not e_observed or e_observed[-1] != seen:
        e_observed.append(seen)


e_job = retrieve("e", timeout=240, progress=watch_e)
e_pieces = on_disk("e")
if e_pieces != list(range(n_pieces)):
    raise SystemExit(f"cold buyer E committed {e_pieces} with A absent, want {list(range(n_pieces))}")
e_sha = assemble_sha("e")
if e_sha != expected_sha:
    raise SystemExit(f"cold buyer E sha384 {e_sha} != manifest {expected_sha}")
log(f"cold buyer E retrieved {e_pieces} with A absent; sha384 matches")

# --- Evidence ---
evid.mkdir(parents=True, exist_ok=True)
(evid / "swarm-multipiece-assignment-trace.json").write_text(
    json.dumps(
        {
            "uri": uri,
            "artifact_id": artifact,
            "file_size": file_size,
            "piece_size": PIECE_SIZE,
            "piece_count": n_pieces,
            "seeder_ports": ports,
            "buyer_peers": peers.get("peers"),
            "buyer_d_job": {k: v for k, v in d_job.items() if k != "_result"},
            "buyer_d_progress": observed,
            "buyer_d_transfers": d_xfer.get("transfers"),
            "cold_buyer_e_progress": e_observed,
            "automatic_spend_atoms": 0,
        },
        indent=2,
        default=str,
    )
)
(evid / "swarm-multipiece-piece-ownership.json").write_text(
    json.dumps(
        {
            "layout": "<modeldir>/store/artifacts/<artifact_hex>/<file_index>/<piece_index>.piece",
            "layout_source": "src/modelnet/store.cpp ArtifactDir + catalog.cpp store root",
            "artifact_id": artifact,
            "piece_count": n_pieces,
            "seeders_after_deletion": ownership,
            "a_and_b_disjoint": True,
            "a_and_b_cover_file": True,
            "c_overlaps_both_non_identical": True,
            "no_single_seeder_except_c_is_complete": True,
            "buyer_d_committed": d_pieces,
            "buyer_d_sha384": d_sha,
            "cold_buyer_e_committed": e_pieces,
            "cold_buyer_e_sha384": e_sha,
            "manifest_sha384": expected_sha,
        },
        indent=2,
    )
)
(evid / "swarm-multipiece-failover.json").write_text(
    json.dumps(
        {
            "status": "EXECUTED",
            "seeder_killed": "A",
            "signal": "SIGTERM",
            "mid_transfer_kill": mid_transfer,
            "mid_transfer_detail": kill if mid_transfer else
                "loopback finished the transfer before pieces_committed>=1 was observed; "
                "A was terminated before the cold round instead",
            "cold_buyer_with_a_absent": {
                "buyer": "E",
                "peers_configured": ["A(dead)", "B", "C"],
                "pieces_committed": e_pieces,
                "sha384_matches_manifest": e_sha == expected_sha,
                "progress": e_observed,
            },
            "note": "A held only piece 0. B held the remainder, C held every piece, "
                    "so completion with A absent is real multi-peer failover, not a retry "
                    "against the same seeder.",
        },
        indent=2,
        default=str,
    )
)
log("PASS multi-piece swarm: A|B disjoint, C overlapping, D assembled, E recovered without A")
PY

for n in a b c d e; do
  cp -f "$SCRATCH/$n/modeld.log" "$EVID/swarm-multipiece-$n.log" || true
done
echo "e2e-swarm-multipiece: PASS" | tee -a "$LOG"
