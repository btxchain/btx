#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""Two-node CUDA lifecycle campaign: toy rehearsal or production strict-device.

Measures one external solve-RPC-to-authenticated-tip wall-clock envelope and
records these exact-block diagnostic components without summing them:

  all nonce attempts and their accelerator queue waits
  strict winner reseal and its queue wait
  one-shot local winner-authority handoff
  authenticated relay
  receiving tip validation and its queue wait

Schema-4 steady samples use an observer wall clock from immediately before the
winning solve RPC through the receiving node reporting that exact authenticated
tip. Contention samples start before two concurrent sibling solve RPCs and end
only after their fork has converged and a direct child reaches that same exact
authenticated-tip condition. The observer result is accepted only when bounded
daemon telemetry binds the same block hash to the miner's strict winner
reseal/local-authority handoff, the receiving node's authenticated relay, and
its strict ExactReplay result.
Missing or cross-block stage data makes the attempt incomplete. Ratification
gates stay false; this script never flips them or installs an RC ASERT ratio.

Usage (GPU host, under flock):

  contrib/matmul-v4/measure-cuda-lifecycle-campaign.py \\
    --btxd build-cuda/bin/btxd --btx-cli build-cuda/bin/btx-cli \\
    --source-revision <exact-40-character-commit> \\
    --btxd-sha256 <reviewed-sha256> --btx-cli-sha256 <reviewed-sha256> \\
    --samples 20 --max-wall-s 5400 --mode production \\
    --workdir <temporary-empty-directory> \\
    --out-json <sanitized-evidence.json>
"""

from __future__ import annotations

import argparse
import concurrent.futures
import json
import math
import os
import signal
import statistics
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))
import evidence_source_identity as EVIDENCE_IDENTITY  # noqa: E402

ACTIVATION_HEIGHT = 6
V3_BINDING_HEIGHT = 2
DISABLED_HEIGHT = 2_147_483_647
REPO_ROOT = Path(__file__).resolve().parents[2]
TOOL = "btx_cuda_complete_lifecycle_campaign"
SCHEMA_VERSION = 4


def execution_policy_for_mode(mode: str) -> str:
    if mode == "toy":
        return "auto-fallback"
    if mode == "production":
        return "strict-device"
    raise ValueError(f"unsupported lifecycle mode: {mode}")


def public_exception_name(error: BaseException) -> str:
    """Return a stable public error class without local paths or arguments."""
    return type(error).__name__


def die(msg: str, code: int = 2) -> None:
    sys.stderr.write(f"measure-cuda-lifecycle-campaign: {msg}\n")
    sys.exit(code)


def percentile(sorted_vals: list[float], p: float) -> float | None:
    if not sorted_vals:
        return None
    if len(sorted_vals) == 1:
        return sorted_vals[0]
    # Nearest-rank, inclusive.
    k = max(1, math.ceil((p / 100.0) * len(sorted_vals))) - 1
    return sorted_vals[min(k, len(sorted_vals) - 1)]


def summarize(vals: list[float]) -> dict[str, Any]:
    ordered = sorted(vals)
    return {
        "n": len(ordered),
        "min": ordered[0] if ordered else None,
        "p50": percentile(ordered, 50),
        "p95": percentile(ordered, 95),
        "p99": percentile(ordered, 99),
        "max": ordered[-1] if ordered else None,
        "mean": statistics.fmean(ordered) if ordered else None,
    }


class Node:
    def __init__(
        self,
        *,
        label: str,
        btxd: Path,
        btx_cli: Path,
        datadir: Path,
        rpc_port: int,
        p2p_port: int,
        mode: str,
        env: dict[str, str],
        connect_to: str | None = None,
    ) -> None:
        self.label = label
        self.btxd = btxd
        self.btx_cli = btx_cli
        self.datadir = datadir
        self.rpc_port = rpc_port
        self.p2p_port = p2p_port
        self.mode = mode
        self.env = env
        self.connect_to = connect_to
        self.proc: subprocess.Popen[bytes] | None = None

    def _common_args(self) -> list[str]:
        toy = self.mode == "toy"
        dim = 128 if toy else 4096
        args = [
            str(self.btxd),
            "-regtest",
            f"-datadir={self.datadir}",
            f"-port={self.p2p_port}",
            f"-rpcport={self.rpc_port}",
            "-rpcuser=lifecycle",
            "-rpcpassword=lifecycle_campaign_password",
            "-server=1",
            "-listen=1",
            "-discover=0",
            "-dnsseed=0",
            "-fixedseeds=0",
            "-listenonion=0",
            "-upnp=0",
            "-natpmp=0",
            "-externalip=127.0.0.1",
            "-bind=127.0.0.1",
            # noban must be explicit (implicit whitelist omits it). Without it,
            # consensus-mode sync refuses block download from peers that do not
            # advertise NODE_MATMUL_CONSENSUS. Keeping noban explicit also lets
            # pre-manifest and negative-canary builds exercise relay behavior.
            "-whitelist=noban,in,out@127.0.0.1",
            "-peertimeout=30",
            "-miningminoutboundpeers=0",
            "-miningminsyncedoutboundpeers=0",
            "-matmulvalidation=consensus",
            # Toy RC uses toy-rc ExactReplay; strict-device fails AcceptBlock.
            f"-matmulrcexecution={execution_policy_for_mode(self.mode)}",
            "-matmulasyncverify=1",
            f"-regtestmatmulbindingheight={V3_BINDING_HEIGHT}",
            f"-regtestmatmulproductdigestheight={V3_BINDING_HEIGHT}",
            "-regtestmatmulrequireproductpayload=0",
            f"-regtestmatmulv4height={ACTIVATION_HEIGHT}",
            f"-regtestbmx4cheight={ACTIVATION_HEIGHT}",
            f"-regtestdrltheight={DISABLED_HEIGHT}",
            f"-regtestrcheight={ACTIVATION_HEIGHT}",
            f"-regtestrccoupledheight={DISABLED_HEIGHT}",
            "-regtestrcprofile=1",
            f"-regtestrctoydims={1 if toy else 0}",
            "-regtestrccoupledtoydims=0",
            "-regtestmatmulltsealaspow=0",
            f"-regtestmatmulv4dimension={dim}",
            f"-regtestmatmulv4maxdimension={dim}",
            "-printtoconsole=0",
        ]
        connect_to = getattr(self, "connect_to", None)
        if connect_to:
            args.append(f"-connect={connect_to}")
        return args

    def start(self) -> None:
        self.datadir.mkdir(parents=True, exist_ok=True)
        stdout_path = self.datadir / "btxd.stdout"
        stderr_path = self.datadir / "btxd.stderr"
        self._stdout_file = stdout_path.open("w", encoding="utf-8")
        self._stderr_file = stderr_path.open("w", encoding="utf-8")
        self.proc = subprocess.Popen(
            self._common_args(),
            env=self.env,
            stdout=self._stdout_file,
            stderr=self._stderr_file,
        )
        deadline = time.monotonic() + 240
        last_err = ""
        while time.monotonic() < deadline:
            try:
                self.cli("getblockchaininfo")
                return
            except (subprocess.SubprocessError, OSError, json.JSONDecodeError) as exc:
                last_err = str(exc)
                if self.proc.poll() is not None:
                    err_tail = ""
                    try:
                        err_tail = stderr_path.read_text(encoding="utf-8")[-2000:]
                    except OSError:
                        pass
                    die(
                        f"{self.label} exited early (code {self.proc.returncode}): "
                        f"{last_err}\n{err_tail}"
                    )
                time.sleep(0.5)
        die(f"{self.label} RPC not ready: {last_err}")

    def cli(self, *args: str, timeout: int = 180) -> Any:
        command = [
            str(self.btx_cli),
            "-regtest",
            f"-datadir={self.datadir}",
            f"-rpcport={self.rpc_port}",
            "-rpcuser=lifecycle",
            "-rpcpassword=lifecycle_campaign_password",
            "-rpcwait",
            f"-rpcwaittimeout={timeout}",
            *args,
        ]
        result = subprocess.run(
            command,
            check=True,
            capture_output=True,
            text=True,
            timeout=timeout + 30,
        )
        text = result.stdout.strip()
        if not text:
            return None
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            return text

    def stop(self) -> None:
        try:
            self.cli("stop", timeout=30)
        except (subprocess.SubprocessError, OSError):
            pass
        if self.proc is not None:
            try:
                self.proc.wait(timeout=60)
            except subprocess.TimeoutExpired:
                self.proc.send_signal(signal.SIGTERM)
                try:
                    self.proc.wait(timeout=15)
                except subprocess.TimeoutExpired:
                    self.proc.kill()
                    self.proc.wait(timeout=10)
            self.proc = None
        for attr in ("_stdout_file", "_stderr_file"):
            handle = getattr(self, attr, None)
            if handle is not None:
                try:
                    handle.close()
                except OSError:
                    pass
                setattr(self, attr, None)


def connect_peers(a: Node, b: Node) -> None:
    a.cli("addnode", f"127.0.0.1:{b.p2p_port}", "onetry")
    b.cli("addnode", f"127.0.0.1:{a.p2p_port}", "onetry")
    deadline = time.monotonic() + 60
    while time.monotonic() < deadline:
        peers_a = a.cli("getpeerinfo") or []
        peers_b = b.cli("getpeerinfo") or []
        if peers_a and peers_b:
            return
        time.sleep(0.2)
    # Non-fatal: mining may still proceed once handshakes complete.
    time.sleep(1.0)


def disconnect_peers(node: Node) -> None:
    peers = node.cli("getpeerinfo") or []
    for peer in peers:
        try:
            # Prefer node id: disconnectnode (address) (nodeid)
            node.cli("disconnectnode", "", str(int(peer["id"])))
        except (subprocess.SubprocessError, OSError, ValueError, KeyError):
            addr = peer.get("addr")
            if addr:
                try:
                    node.cli("disconnectnode", str(addr))
                except (subprocess.SubprocessError, OSError):
                    pass


def wait_equal_tips(a: Node, b: Node, timeout: float) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if a.cli("getbestblockhash") == b.cli("getbestblockhash"):
            return True
        time.sleep(0.5)
    return False


def wait_exact_tips(a: Node, b: Node, block_hash: str, timeout: float) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if (a.cli("getbestblockhash") == block_hash and
                b.cli("getbestblockhash") == block_hash):
            return True
        time.sleep(0.5)
    return False


def scheduler(node: Node) -> dict[str, Any]:
    info = node.cli("getmininginfo")
    return info["backend_runtime"]["rc_accelerator_scheduler"]


def _record_for_hash(records: object, block_hash: str, label: str) -> dict[str, Any]:
    if not isinstance(records, list):
        raise RuntimeError(f"{label} must be an array")
    matches = [
        record for record in records
        if isinstance(record, dict) and record.get("block_hash") == block_hash
    ]
    if len(matches) != 1:
        raise RuntimeError(
            f"{label} has {len(matches)} records for exact block hash"
        )
    return matches[0]


def _finite_nonnegative(value: object, label: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise RuntimeError(f"{label} must be numeric")
    result = float(value)
    if not math.isfinite(result) or result < 0:
        raise RuntimeError(f"{label} must be finite and non-negative")
    return result


def extract_exact_block_lifecycle(
    miner_info: object, validator_info: object, *, block_hash: str,
    block_height: int, observer_wall_s: float, observer_elapsed_ns: int,
    observer_start_event: str = "before_generatetodescriptor_rpc",
) -> dict[str, Any]:
    """Bind production stage telemetry to one exact accepted block hash."""
    if not isinstance(miner_info, dict) or not isinstance(validator_info, dict):
        raise RuntimeError("getmininginfo lifecycle responses must be objects")
    miner_runtime = miner_info.get("backend_runtime")
    validator_runtime = validator_info.get("backend_runtime")
    if not isinstance(miner_runtime, dict) or not isinstance(validator_runtime, dict):
        raise RuntimeError("backend_runtime lifecycle objects are missing")
    miner_scheduler = miner_runtime.get("rc_accelerator_scheduler")
    validator_scheduler = validator_runtime.get("rc_accelerator_scheduler")
    validator_rc = validator_runtime.get("rc_exact_replay")
    if not isinstance(miner_scheduler, dict) or not isinstance(validator_scheduler, dict):
        raise RuntimeError("RC scheduler lifecycle objects are missing")
    if not isinstance(validator_rc, dict):
        raise RuntimeError("validator RC ExactReplay object is missing")

    authority_parent = miner_scheduler.get("winner_reseal_authority")
    if not isinstance(authority_parent, dict):
        raise RuntimeError("miner winner authority telemetry is missing")
    authority = _record_for_hash(
        authority_parent.get("recent_consumed"), block_hash,
        "miner recent_consumed authority",
    )
    relay = _record_for_hash(
        validator_scheduler.get("recent_authenticated_relays"), block_hash,
        "validator recent_authenticated_relays",
    )
    validation = _record_for_hash(
        validator_rc.get("recent_validations"), block_hash,
        "validator recent_validations",
    )

    if authority.get("block_height") != block_height:
        raise RuntimeError("winner authority height mismatch")
    if validation.get("block_height") != block_height:
        raise RuntimeError("validator ExactReplay height mismatch")
    solve_attempts = authority.get("solve_attempts")
    if not isinstance(solve_attempts, int) or isinstance(solve_attempts, bool) or \
            solve_attempts <= 0:
        raise RuntimeError("solve_attempts must be a positive integer")
    solve_to_reseal = _finite_nonnegative(
        authority.get("solve_to_reseal_s"), "solve_to_reseal_s")
    reseal_to_consume = _finite_nonnegative(
        authority.get("reseal_to_consume_s"), "reseal_to_consume_s")
    solve_to_consume = _finite_nonnegative(
        authority.get("solve_to_consume_s"), "solve_to_consume_s")
    if abs(solve_to_reseal + reseal_to_consume - solve_to_consume) > 1e-6:
        raise RuntimeError("winner authority stage timings do not reconcile")
    relay_s = _finite_nonnegative(relay.get("relay_s"), "relay_s")
    validation_s = _finite_nonnegative(validation.get("wall_s"), "validation wall_s")
    observer = _finite_nonnegative(observer_wall_s, "observer wall_s")
    if not isinstance(observer_elapsed_ns, int) or \
            isinstance(observer_elapsed_ns, bool) or observer_elapsed_ns < 0:
        raise RuntimeError("observer elapsed_ns must be a non-negative integer")
    if abs(observer - observer_elapsed_ns / 1_000_000_000.0) > 1e-9:
        raise RuntimeError("observer elapsed_ns does not reproduce observer wall")
    if observer_start_event not in {
        "before_generatetodescriptor_rpc",
        "before_concurrent_competing_sibling_rpc_submission",
    }:
        raise RuntimeError("observer start event is not recognized")
    if max(solve_to_consume, relay_s, validation_s) > observer + 1e-6:
        raise RuntimeError("stage timing exceeds solve-to-authenticated-tip observer wall")
    for field, expected in (
        ("outcome", "valid"),
        ("execution_policy", "strict-device"),
        ("require_device", True),
        ("fully_accelerated", True),
        ("device_xof_fallbacks", 0),
        ("host_xof_calls", 0),
        ("cpu_gemm_calls", 0),
        ("cpu_gemm_fallbacks", 0),
    ):
        if validation.get(field) != expected:
            raise RuntimeError(f"validator ExactReplay {field} mismatch")
    if not isinstance(validation.get("device_gemm_calls"), int) or \
            isinstance(validation.get("device_gemm_calls"), bool) or \
            validation["device_gemm_calls"] <= 0:
        raise RuntimeError("validator ExactReplay recorded no device GEMM")
    for label, provider in (
        ("miner", authority.get("provider")),
        ("validator", validation.get("provider")),
    ):
        if not isinstance(provider, str) or not provider.startswith("cuda_"):
            raise RuntimeError(f"{label} exact-block provider is not CUDA")

    return {
        "complete": True,
        "authority_measured": True,
        "complete_lifecycle_s": observer,
        "observer_solve_rpc_to_authenticated_tip_s": observer,
        "observer_measurement": {
            "clock": "monotonic_ns",
            "start_event": observer_start_event,
            "stop_event": "both_nodes_exact_authenticated_tip",
            "elapsed_ns": observer_elapsed_ns,
        },
        "rpc_correlated_end_to_end_sample": True,
        "correlation_block_hash": block_hash,
        "miner_authority": authority,
        "authenticated_relay": relay,
        "validator_exact_replay": validation,
        "miner_provider": authority["provider"],
        "validator_provider": validation["provider"],
        "validator_execution_policy": validation["execution_policy"],
        "validator_fully_accelerated": validation["fully_accelerated"],
        "validator_cpu_gemm_calls": validation["cpu_gemm_calls"],
        "validator_cpu_gemm_fallbacks": validation["cpu_gemm_fallbacks"],
    }


def extract_exact_block_core_lifecycle(
    validator_info: object, *, block_hash: str, block_height: int,
    observer_wall_s: float, observer_elapsed_ns: int,
    observer_start_event: str = "before_generatetodescriptor_rpc",
) -> dict[str, Any]:
    """Retain a non-authorizing exact-block toy/core rehearsal sample."""
    if not isinstance(validator_info, dict):
        raise RuntimeError("validator getmininginfo response must be an object")
    runtime = validator_info.get("backend_runtime")
    if not isinstance(runtime, dict):
        raise RuntimeError("validator backend_runtime object is missing")
    scheduler_info = runtime.get("rc_accelerator_scheduler")
    validator_rc = runtime.get("rc_exact_replay")
    if not isinstance(scheduler_info, dict) or not isinstance(validator_rc, dict):
        raise RuntimeError("validator exact-block telemetry is missing")
    relay = _record_for_hash(
        scheduler_info.get("recent_authenticated_relays"), block_hash,
        "validator recent_authenticated_relays",
    )
    validation = _record_for_hash(
        validator_rc.get("recent_validations"), block_hash,
        "validator recent_validations",
    )
    if validation.get("block_height") != block_height:
        raise RuntimeError("validator ExactReplay height mismatch")
    if validation.get("outcome") != "valid":
        raise RuntimeError("validator ExactReplay outcome mismatch")
    relay_s = _finite_nonnegative(relay.get("relay_s"), "relay_s")
    validation_s = _finite_nonnegative(validation.get("wall_s"), "validation wall_s")
    observer = _finite_nonnegative(observer_wall_s, "observer wall_s")
    if not isinstance(observer_elapsed_ns, int) or \
            isinstance(observer_elapsed_ns, bool) or observer_elapsed_ns < 0:
        raise RuntimeError("observer elapsed_ns must be a non-negative integer")
    if abs(observer - observer_elapsed_ns / 1_000_000_000.0) > 1e-9:
        raise RuntimeError("observer elapsed_ns does not reproduce observer wall")
    if observer_start_event not in {
        "before_generatetodescriptor_rpc",
        "before_concurrent_competing_sibling_rpc_submission",
    }:
        raise RuntimeError("observer start event is not recognized")
    if max(relay_s, validation_s) > observer + 1e-6:
        raise RuntimeError("core stage timing exceeds observer wall")
    return {
        "complete": False,
        "core_complete_without_authority": True,
        "authority_measured": False,
        "core_lifecycle_s": observer,
        "observer_solve_rpc_to_authenticated_tip_s": observer,
        "observer_measurement": {
            "clock": "monotonic_ns",
            "start_event": observer_start_event,
            "stop_event": "both_nodes_exact_authenticated_tip",
            "elapsed_ns": observer_elapsed_ns,
        },
        "rpc_correlated_end_to_end_sample": True,
        "correlation_block_hash": block_hash,
        "authenticated_relay": relay,
        "validator_exact_replay": validation,
        "reason": "production winner authority unavailable in toy/core mode",
    }


def mine_one(miner: Node, timeout: int) -> str:
    hashes = miner.cli(
        "generatetodescriptor",
        "1",
        "raw(51)",
        timeout=timeout,
    )
    if not isinstance(hashes, list) or len(hashes) != 1:
        raise RuntimeError(f"unexpected generatetodescriptor result: {hashes!r}")
    return hashes[0]


def write_status(path: Path | None, payload: dict[str, Any]) -> None:
    if path is None:
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")


def validate_runtime_build_identity(
    mining_info: object, *, revision: str, fingerprint: str, label: str,
    require_production_canary: bool = True,
) -> dict[str, Any]:
    # Toy campaigns intentionally do not run the production startup canary.
    # They remain useful scheduler/relay rehearsals, but they cannot provide
    # production-canary provenance evidence.
    if not require_production_canary:
        return {}
    if not isinstance(mining_info, dict):
        raise EVIDENCE_IDENTITY.EvidenceIdentityError(
            f"{label} getmininginfo response must be an object"
        )
    runtime = mining_info.get("backend_runtime")
    rc = runtime.get("rc_exact_replay") if isinstance(runtime, dict) else None
    canary = rc.get("production_canary") if isinstance(rc, dict) else None
    if not isinstance(canary, dict):
        raise EVIDENCE_IDENTITY.EvidenceIdentityError(
            f"{label} production canary must be an object"
        )
    EVIDENCE_IDENTITY.validate_canary_build_identity(
        canary, revision=revision, fingerprint=fingerprint,
        prefix=f"{label}.production_canary",
        # The lifecycle campaign intentionally supports a pre-manifest mode
        # that records core timing without claiming activation authority.
        require_manifest_match=False,
    )
    return canary


def extract_public_runtime_evidence(
    mining_info: object, *, revision: str, fingerprint: str, label: str,
) -> dict[str, Any]:
    """Extract the fail-closed, machine-public runtime facts used by release review."""
    if not isinstance(mining_info, dict):
        raise EVIDENCE_IDENTITY.EvidenceIdentityError(
            f"{label} getmininginfo response must be an object"
        )
    runtime = mining_info.get("backend_runtime")
    rc = runtime.get("rc_exact_replay") if isinstance(runtime, dict) else None
    if not isinstance(rc, dict):
        raise EVIDENCE_IDENTITY.EvidenceIdentityError(
            f"{label}.backend_runtime.rc_exact_replay must be an object"
        )
    canary = rc.get("production_canary")
    if not isinstance(canary, dict):
        raise EVIDENCE_IDENTITY.EvidenceIdentityError(
            f"{label}.production_canary must be an object"
        )
    EVIDENCE_IDENTITY.validate_canary_build_identity(
        canary, revision=revision, fingerprint=fingerprint,
        prefix=f"{label}.production_canary", require_manifest_match=True,
    )
    validation = rc.get("last_validation")
    if not isinstance(validation, dict):
        validation = {}
    health = rc.get("provider_health")
    if not isinstance(health, dict):
        health = {}
    return {
        "resolved_provider": rc.get("resolved_provider"),
        "production_canary": {
            key: canary.get(key)
            for key in (
                "outcome", "attempted", "passed",
                "manifest_has_reviewed_goldens", "build_provenance_matches",
                "build_source_dirty", "build_source_revision",
                "build_source_tree_fingerprint", "exact_manifest_match",
                "provider", "provider_family", "device_architecture",
                "epoch_activation_height", "epoch_profile",
                "epoch_matmul_dimension", "device_macs",
                "device_xof_fallbacks", "host_xof_calls", "cpu_fallbacks",
                "reason",
            )
        },
        "last_validation": {
            key: validation.get(key)
            for key in (
                "available", "outcome", "execution_policy", "require_device",
                "provider", "fully_accelerated", "device_gemm_calls",
                "device_gemm_macs", "device_xof_fallbacks", "host_xof_calls",
                "cpu_gemm_calls", "cpu_gemm_fallbacks", "acceleration_failure",
                "failure_kind", "adjudication", "wall_s",
            )
        },
        "provider_health": {
            key: health.get(key)
            for key in (
                "quarantined", "validator_readiness_lost", "provider", "reason"
            )
        },
    }


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--btxd", type=Path, required=True)
    ap.add_argument("--btx-cli", type=Path, required=True)
    ap.add_argument("--workdir", type=Path, required=True)
    ap.add_argument("--out-json", type=Path, required=True)
    ap.add_argument("--samples", type=int, default=20)
    ap.add_argument("--max-wall-s", type=int, default=5400)
    ap.add_argument("--mode", choices=("production", "toy"), default="production")
    ap.add_argument("--mine-timeout-s", type=int, default=900)
    ap.add_argument("--sync-timeout-s", type=int, default=900)
    ap.add_argument("--base-rpc-port", type=int, default=19400)
    ap.add_argument("--base-p2p-port", type=int, default=19410)
    ap.add_argument(
        "--contention-every",
        type=int,
        default=5,
        help="Every N complete attempts, briefly mine competing tips on both nodes",
    )
    ap.add_argument("--status-json", type=Path, default=None)
    ap.add_argument("--source-revision", default=os.environ.get("BTX_SOURCE_REVISION"))
    ap.add_argument("--btxd-sha256", default=os.environ.get("BTXD_SHA256"))
    ap.add_argument("--btx-cli-sha256", default=os.environ.get("BTXCLI_SHA256"))
    ap.add_argument(
        "--allow-partial",
        action="store_true",
        help="exit 0 even when fewer than --samples complete samples were collected "
             "(without this a partial campaign exits 3, so a caller gating on the "
             "exit code cannot green-light an incomplete run)",
    )
    args = ap.parse_args()
    execution_policy = execution_policy_for_mode(args.mode)
    campaign_label = (
        "two-node CUDA toy auto-fallback lifecycle rehearsal"
        if args.mode == "toy"
        else "two-node CUDA strict-device complete lifecycle"
    )

    if not args.btxd.is_file():
        die(f"btxd not found: {args.btxd}")
    if not args.btx_cli.is_file():
        die(f"btx-cli not found: {args.btx_cli}")
    try:
        if not args.source_revision:
            raise EVIDENCE_IDENTITY.EvidenceIdentityError(
                "--source-revision (or BTX_SOURCE_REVISION) is required"
            )
        args.source_revision = EVIDENCE_IDENTITY.resolve_commit(
            REPO_ROOT, args.source_revision
        )
        source_tree_fingerprint = EVIDENCE_IDENTITY.tree_fingerprint(
            REPO_ROOT, args.source_revision
        )
        btxd_sha256 = EVIDENCE_IDENTITY.verify_binary(
            args.btxd, args.btxd_sha256, "btxd_sha256"
        )
        btx_cli_sha256 = EVIDENCE_IDENTITY.verify_binary(
            args.btx_cli, args.btx_cli_sha256, "btx_cli_sha256"
        )
    except EVIDENCE_IDENTITY.EvidenceIdentityError as error:
        die(str(error))

    env = dict(os.environ)
    env.update(
        {
            "BTX_MATMUL_BACKEND": "cuda",
            "BTX_MATMUL_V4_BACKEND": "cuda",
            "BTX_MATMUL_REQUIRE_BACKEND": "cuda",
        }
    )

    work = args.workdir
    if work.exists():
        # Refuse to clobber an unexpected tree; campaign dirs are ephemeral.
        for child in work.iterdir():
            die(f"workdir not empty: {work} contains {child.name}")
    work.mkdir(parents=True, exist_ok=True)

    miner = Node(
        label="miner",
        btxd=args.btxd,
        btx_cli=args.btx_cli,
        datadir=work / "miner",
        rpc_port=args.base_rpc_port,
        p2p_port=args.base_p2p_port,
        mode=args.mode,
        env=env,
    )
    validator = Node(
        label="validator",
        btxd=args.btxd,
        btx_cli=args.btx_cli,
        datadir=work / "validator",
        rpc_port=args.base_rpc_port + 1,
        p2p_port=args.base_p2p_port + 1,
        mode=args.mode,
        env=env,
        connect_to=f"127.0.0.1:{args.base_p2p_port}",
    )

    started = time.time()
    samples: list[dict[str, Any]] = []
    incomplete: list[dict[str, Any]] = []
    attempt = 0

    def status(note: str, state: str = "running") -> None:
        write_status(
            args.status_json,
            {
                "agent": "LIFECYCLE",
                "priority": 4,
                "status": state,
                "tip_sha": args.source_revision or None,
                "campaign": campaign_label,
                "mode": args.mode,
                "samples_target": args.samples,
                "samples_complete": len(samples),
                "samples_incomplete": len(incomplete),
                "attempts": attempt,
                "elapsed_s": round(time.time() - started, 1),
                "ratification_gates": False,
                "updated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "notes": note,
            },
        )

    try:
        status(f"starting two CUDA nodes with {execution_policy} execution")
        miner.start()
        validator.start()
        try:
            validate_runtime_build_identity(
                miner.cli("getmininginfo"), revision=args.source_revision,
                fingerprint=source_tree_fingerprint, label="miner",
                require_production_canary=args.mode == "production",
            )
            validate_runtime_build_identity(
                validator.cli("getmininginfo"), revision=args.source_revision,
                fingerprint=source_tree_fingerprint, label="validator",
                require_production_canary=args.mode == "production",
            )
        except EVIDENCE_IDENTITY.EvidenceIdentityError as error:
            die(str(error))
        connect_peers(miner, validator)
        status("nodes up; mining to RC parent")

        # Mine to parent of RC activation on miner; sync so both share the tip.
        while miner.cli("getblockcount") < ACTIVATION_HEIGHT - 1:
            height = int(miner.cli("getblockcount"))
            status(f"pre-activation mine height={height}")
            mine_one(miner, min(args.mine_timeout_s, 120))
            if not wait_equal_tips(miner, validator, min(args.sync_timeout_s, 180)):
                die("pre-activation sync failed")

        status("RC parent reached; collecting lifecycle samples")
        core_samples: list[dict[str, Any]] = []

        while (
            max(len(samples), len(core_samples)) < args.samples
            and (time.time() - started) < args.max_wall_s
        ):
            attempt += 1
            contention = (
                args.contention_every > 0 and attempt % args.contention_every == 0
            )
            block_hash = None
            phase = "steady_mine_relay"
            competing_block_hashes: list[str] = []
            contention_trace = None
            contention_timing = None
            observer_start_event = "before_generatetodescriptor_rpc"
            try:
                if contention:
                    phase = "competing_tip"
                    disconnect_peers(miner)
                    disconnect_peers(validator)
                    # Both mine one block from the same parent when possible.
                    parent = miner.cli("getbestblockhash")
                    if validator.cli("getbestblockhash") != parent:
                        connect_peers(miner, validator)
                        if not wait_equal_tips(miner, validator, args.sync_timeout_s):
                            incomplete.append(
                                {
                                    "attempt": attempt,
                                    "phase": phase,
                                    "reason": "tips_diverged_before_contention",
                                }
                            )
                            status(f"incomplete attempt {attempt}: pre-contention diverge")
                            continue
                    disconnect_peers(miner)
                    disconnect_peers(validator)
                    # Start the external contention clock before submitting
                    # either sibling solve. Both nodes mine concurrently while
                    # disconnected, so this interval includes competing GPU
                    # service, both local accepts, branch extension, reorg
                    # convergence, and the exact measured child below.
                    observer_start_event = (
                        "before_concurrent_competing_sibling_rpc_submission"
                    )
                    observer_started_ns = time.monotonic_ns()

                    def observed_mine(node: Node) -> tuple[str, int]:
                        sibling_hash = mine_one(node, args.mine_timeout_s)
                        return (
                            sibling_hash,
                            time.monotonic_ns() - observer_started_ns,
                        )

                    with concurrent.futures.ThreadPoolExecutor(
                        max_workers=2,
                        thread_name_prefix="btx-rc-contention",
                    ) as executor:
                        winning_future = executor.submit(observed_mine, miner)
                        losing_future = executor.submit(observed_mine, validator)
                        miner_parent_child, winning_accept_elapsed_ns = (
                            winning_future.result()
                        )
                        competing_hash, losing_accept_elapsed_ns = (
                            losing_future.result()
                        )
                    if competing_hash == miner_parent_child:
                        incomplete.append({
                            "attempt": attempt,
                            "phase": phase,
                            "reason": "competing_headers_identical",
                            "block_hash": competing_hash,
                        })
                        status(f"incomplete attempt {attempt}: no distinct competing tip")
                        connect_peers(miner, validator)
                        continue
                    miner_parent = miner.cli(
                        "getblockheader", miner_parent_child
                    ).get("previousblockhash")
                    competing_parent = validator.cli(
                        "getblockheader", competing_hash
                    ).get("previousblockhash")
                    if miner_parent != parent or competing_parent != parent:
                        incomplete.append({
                            "attempt": attempt,
                            "phase": phase,
                            "reason": "contention_not_from_common_parent",
                        })
                        status(
                            f"incomplete attempt {attempt}: "
                            "contention parent mismatch"
                        )
                        connect_peers(miner, validator)
                        continue
                    # Extend the miner branch while disconnected to force a
                    # deterministic reorg, wait for that contention to
                    # converge, then extend the same observer interval through
                    # one exact direct-tip child. This preserves ordinary
                    # direct-tip relay accounting without hiding the preceding
                    # competing work or reorg convergence from the sample.
                    contention_reorg_tip_hash = mine_one(
                        miner, args.mine_timeout_s)
                    winning_extension_elapsed_ns = (
                        time.monotonic_ns() - observer_started_ns
                    )
                    reorg_tip_parent = miner.cli(
                        "getblockheader", contention_reorg_tip_hash
                    ).get("previousblockhash")
                    if reorg_tip_parent != miner_parent_child:
                        incomplete.append({
                            "attempt": attempt,
                            "phase": phase,
                            "reason": "reorg_tip_not_on_winning_branch",
                        })
                        status(
                            f"incomplete attempt {attempt}: "
                            "reorg tip parent mismatch"
                        )
                        connect_peers(miner, validator)
                        continue
                    competing_block_hashes = [competing_hash]
                    connect_peers(miner, validator)
                    if not wait_exact_tips(
                        miner, validator, contention_reorg_tip_hash,
                        args.sync_timeout_s,
                    ):
                        incomplete.append({
                            "attempt": attempt,
                            "phase": phase,
                            "reason": "reorg_sync_failed",
                            "contention_reorg_tip_hash": contention_reorg_tip_hash,
                            "competing_block_hashes": competing_block_hashes,
                        })
                        status(f"incomplete attempt {attempt}: reorg sync failed")
                        continue
                    reorg_convergence_elapsed_ns = (
                        time.monotonic_ns() - observer_started_ns
                    )
                    block_hash = mine_one(miner, args.mine_timeout_s)
                    measured_parent = miner.cli(
                        "getblockheader", block_hash
                    ).get("previousblockhash")
                    if measured_parent != contention_reorg_tip_hash:
                        incomplete.append({
                            "attempt": attempt,
                            "phase": phase,
                            "reason": "measured_child_not_after_reorg",
                        })
                        status(
                            f"incomplete attempt {attempt}: "
                            "measured child parent mismatch"
                        )
                        continue
                    contention_trace = {
                        "common_parent_hash": parent,
                        "winning_branch_hash": miner_parent_child,
                        "winning_branch_parent_hash": miner_parent,
                        "losing_branch_hash": competing_hash,
                        "losing_branch_parent_hash": competing_parent,
                        "reorg_tip_hash": contention_reorg_tip_hash,
                        "reorg_tip_parent_hash": reorg_tip_parent,
                        "measured_block_parent_hash": measured_parent,
                    }
                    if not wait_exact_tips(
                        miner, validator, block_hash, args.sync_timeout_s
                    ):
                        incomplete.append({
                            "attempt": attempt,
                            "phase": phase,
                            "reason": "post_reorg_child_sync_failed",
                            "block_hash": block_hash,
                            "contention_reorg_tip_hash": contention_reorg_tip_hash,
                            "competing_block_hashes": competing_block_hashes,
                        })
                        status(
                            f"incomplete attempt {attempt}: "
                            "post-reorg child sync failed"
                        )
                        continue
                    measured_child_authenticated_elapsed_ns = (
                        time.monotonic_ns() - observer_started_ns
                    )
                    contention_timing = {
                        "clock": "monotonic_ns",
                        "start_mode": "concurrent_sibling_rpc_submission",
                        "winning_sibling_local_accept_elapsed_ns": (
                            winning_accept_elapsed_ns
                        ),
                        "losing_sibling_local_accept_elapsed_ns": (
                            losing_accept_elapsed_ns
                        ),
                        "winning_extension_local_accept_elapsed_ns": (
                            winning_extension_elapsed_ns
                        ),
                        "reorg_convergence_elapsed_ns": (
                            reorg_convergence_elapsed_ns
                        ),
                        "measured_child_authenticated_elapsed_ns": (
                            measured_child_authenticated_elapsed_ns
                        ),
                    }
                else:
                    contention_reorg_tip_hash = None
                    observer_started_ns = time.monotonic_ns()
                    block_hash = mine_one(miner, args.mine_timeout_s)
                    if not wait_exact_tips(
                        miner, validator, block_hash, args.sync_timeout_s
                    ):
                        incomplete.append(
                            {
                                "attempt": attempt,
                                "phase": phase,
                                "reason": "validator_sync_timeout",
                                "block_hash": block_hash,
                            }
                        )
                        status(f"incomplete attempt {attempt}: sync timeout")
                        continue

                observer_elapsed_ns = (
                    contention_timing[
                        "measured_child_authenticated_elapsed_ns"
                    ]
                    if contention_timing is not None
                    else time.monotonic_ns() - observer_started_ns
                )
                observer_wall_s = observer_elapsed_ns / 1_000_000_000.0
                height = int(miner.cli("getblockcount"))
                miner_info = miner.cli("getmininginfo")
                validator_info = validator.cli("getmininginfo")
                if args.mode == "production":
                    extracted = extract_exact_block_lifecycle(
                        miner_info, validator_info,
                        block_hash=block_hash, block_height=height,
                        observer_wall_s=observer_wall_s,
                        observer_elapsed_ns=observer_elapsed_ns,
                        observer_start_event=observer_start_event,
                    )
                else:
                    extracted = extract_exact_block_core_lifecycle(
                        validator_info,
                        block_hash=block_hash, block_height=height,
                        observer_wall_s=observer_wall_s,
                        observer_elapsed_ns=observer_elapsed_ns,
                        observer_start_event=observer_start_event,
                    )
                record = {
                    "attempt": attempt,
                    "phase": phase,
                    "height": height,
                    "block_hash": block_hash,
                    "competing_block_hashes": competing_block_hashes,
                    "contention_reorg_tip_hash": contention_reorg_tip_hash,
                    "contention_trace": contention_trace,
                    "contention_timing": contention_timing,
                    **extracted,
                }
                if args.mode == "production":
                    samples.append(record)
                    status(
                        f"complete exact-block sample {len(samples)}/{args.samples} "
                        f"lifecycle_s={extracted['complete_lifecycle_s']:.3f}"
                    )
                else:
                    core_samples.append(record)
                    status(
                        f"core exact-block sample {len(core_samples)}/{args.samples} "
                        f"lifecycle_s={extracted['core_lifecycle_s']:.3f}"
                    )
            except (subprocess.SubprocessError, OSError, RuntimeError) as exc:
                incomplete.append(
                    {
                        "attempt": attempt,
                        "phase": phase,
                        "reason": f"exception:{public_exception_name(exc)}",
                    }
                )
                status(f"incomplete attempt {attempt}: {type(exc).__name__}")

        # Identity/canary snapshot (machine-class only; strip host specifics later).
        mining = miner.cli("getmininginfo")
        validating = validator.cli("getmininginfo")
        runtime_builds = {}
        # Complete authority samples imply a reviewed manifest/canary and must
        # export both exact runtime identities. Pre-manifest production runs may
        # still emit explicitly non-authorizing core samples for diagnosis.
        if args.mode == "production" and samples:
            runtime_builds = {
                "miner": extract_public_runtime_evidence(
                    mining, revision=args.source_revision,
                    fingerprint=source_tree_fingerprint, label="miner",
                ),
                "validator": extract_public_runtime_evidence(
                    validating, revision=args.source_revision,
                    fingerprint=source_tree_fingerprint, label="validator",
                ),
            }
        rc = mining["backend_runtime"]["rc_exact_replay"]
        canary = rc.get("production_canary") or {}
        identity = {
            "resolved_provider": rc.get("resolved_provider"),
            "device_architecture_class": canary.get("device_architecture"),
            "driver_identity_class": canary.get("driver_identity"),
            "runtime_identity_class": canary.get("runtime_identity"),
            "canary_outcome": canary.get("outcome"),
            "cpu_gemm_fallback_calls": rc.get("cpu_gemm_fallback_calls"),
        }

        component_series = {
            "observer_solve_rpc_to_authenticated_tip_s": [
                s["observer_solve_rpc_to_authenticated_tip_s"] for s in samples
            ],
            "solve_to_reseal_s": [
                s["miner_authority"]["solve_to_reseal_s"] for s in samples
            ],
            "reseal_to_consume_s": [
                s["miner_authority"]["reseal_to_consume_s"] for s in samples
            ],
            "authenticated_relay_s": [
                s["authenticated_relay"]["relay_s"] for s in samples
            ],
            "tip_validation_s": [
                s["validator_exact_replay"]["wall_s"] for s in samples
            ],
        }
        lifecycle_vals = [float(s["complete_lifecycle_s"]) for s in samples]
        core_lifecycle_vals = [
            float(s["core_lifecycle_s"]) for s in core_samples
        ]
        core_component_series = {
            "observer_solve_rpc_to_authenticated_tip_s": [
                s["observer_solve_rpc_to_authenticated_tip_s"]
                for s in core_samples
            ],
            "authenticated_relay_s": [
                s["authenticated_relay"]["relay_s"] for s in core_samples
            ],
            "tip_validation_s": [
                s["validator_exact_replay"]["wall_s"] for s in core_samples
            ],
        }

        payload = {
            "tool": TOOL,
            "schema_version": SCHEMA_VERSION,
            "evidence_kind": (
                "cuda_lifecycle_toy_rehearsal"
                if args.mode == "toy"
                else "cuda_complete_lifecycle_asert_calibration"
            ),
            "date": time.strftime("%Y-%m-%d", time.gmtime()),
            "machine_class": EVIDENCE_IDENTITY.public_machine_class(
                provider_family="cuda",
                resolved_providers=[identity["resolved_provider"]]
                if identity["resolved_provider"] else [],
                device_architectures=[identity["device_architecture_class"]]
                if identity["device_architecture_class"] else [],
            ),
            "source_revision": args.source_revision or None,
            "source_tree_fingerprint": source_tree_fingerprint,
            "binary_sha256": {
                "btxd": btxd_sha256,
                "btx_cli": btx_cli_sha256,
            },
            "execution_policy": execution_policy,
            "profile": 1,
            "mode": args.mode,
            "matmul_dim": 128 if args.mode == "toy" else 4096,
            "activation_height_regtest": ACTIVATION_HEIGHT,
            "nodes": 2,
            "correlation": {
                "model": "exact_per_block_v2_concurrent_contention",
                "activation_eligible": args.mode == "production",
            },
            "contention": {
                "single_gpu_host": True,
                "competing_tip_every_n_attempts": args.contention_every,
                "phases_observed": sorted(
                    {s["phase"] for s in samples + core_samples + incomplete}
                ),
            },
            "ratification": {
                "campaign_authorizes_no_inversion_gate": False,
                "campaign_authorizes_gpu_lifecycle_gate": False,
                "installs_rc_asert_ratio": False,
                "operationally_ready_claim": False,
                "note": (
                    "This campaign is evidence input only. It neither reads nor "
                    "changes source ratification flags and installs no RC ASERT ratio."
                ),
            },
            "component_definition": [
                "observer_solve_rpc_to_authenticated_tip_s",
                "solve_to_reseal_s",
                "reseal_to_consume_s",
                "authenticated_relay_s",
                "tip_validation_s",
            ],
            "measurement_notes": [
                "The authoritative lifecycle value is an observer monotonic wall clock started immediately before the solve RPC and stopped only after both nodes report that exact block as authenticated tip.",
                "Bounded daemon records independently bind the same block hash to strict winner reseal/local-authority consumption, authenticated relay, and receiving strict ExactReplay.",
                "Stage durations are diagnostic containment checks and are not summed or substituted for the observer end-to-end wall time.",
                "Competing-tip samples mine a distinct losing branch, force and verify convergence on the designated branch, then measure one exact direct-tip child after that reorg.",
                "Missing authenticated-relay observations are recorded as incomplete; none are invented.",
            ],
            "gaps_vs_activation_gates": [
                "source ratification decisions are outside this measurement tool",
                "IBD multi-peer soak not claimed by this campaign",
            ],
            "identity": identity,
            "runtime_builds": runtime_builds,
            "wall_clock_s": round(time.time() - started, 1),
            "attempts": attempt,
            "complete_sample_count": len(samples),
            "core_sample_count_without_authority": len(core_samples),
            "incomplete_sample_count": len(incomplete),
            "complete_lifecycle_summary_s": summarize(lifecycle_vals),
            "core_lifecycle_summary_s": summarize(core_lifecycle_vals),
            "component_summaries_s": {
                key: summarize(vals) for key, vals in component_series.items()
            },
            "core_component_summaries_s": {
                key: summarize(vals) for key, vals in core_component_series.items()
            },
            "samples": samples,
            "core_samples_without_authority": core_samples,
            "incomplete_samples": incomplete,
        }

        args.out_json.parent.mkdir(parents=True, exist_ok=True)
        args.out_json.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
        status(
            f"wrote {args.out_json.name}; complete={len(samples)} "
            f"core={len(core_samples)} incomplete={len(incomplete)}",
            state=(
                "completed"
                if len(samples) >= args.samples
                else (
                    "completed_core_partial"
                    if core_samples
                    else "completed_partial"
                )
            ),
        )
        print(
            json.dumps(
                {
                    "complete_sample_count": len(samples),
                    "core_sample_count_without_authority": len(core_samples),
                    "incomplete_sample_count": len(incomplete),
                    "complete_lifecycle_summary_s": payload["complete_lifecycle_summary_s"],
                    "core_lifecycle_summary_s": payload["core_lifecycle_summary_s"],
                    "out_json": str(args.out_json),
                },
                indent=2,
            )
        )
        # A partial campaign is not a passing campaign: returning 0 here let
        # any caller gating on the exit code green-light a run that collected
        # fewer complete samples than requested, or never reached authority.
        if len(samples) >= args.samples:
            return 0
        if args.allow_partial:
            return 0
        return 3
    except Exception as exc:
        # Persist whatever was collected before a hard failure.
        try:
            if "core_samples" in locals() or "samples" in locals():
                partial = {
                    "evidence_kind": "cuda_complete_lifecycle_asert_calibration_partial",
                    # Exception strings can contain local binary, datadir, or
                    # workspace paths. Public evidence records only the stable
                    # exception class; operators retain detailed stderr/logs
                    # outside the publication artifact.
                    "error": public_exception_name(exc),
                    "complete_sample_count": len(samples) if "samples" in locals() else 0,
                    "core_sample_count_without_authority": len(core_samples)
                    if "core_samples" in locals()
                    else 0,
                    "incomplete_sample_count": len(incomplete)
                    if "incomplete" in locals()
                    else 0,
                    "samples": samples if "samples" in locals() else [],
                    "core_samples_without_authority": core_samples
                    if "core_samples" in locals()
                    else [],
                    "incomplete_samples": incomplete if "incomplete" in locals() else [],
                    "ratification": {
                        "campaign_authorizes_no_inversion_gate": False,
                        "campaign_authorizes_gpu_lifecycle_gate": False,
                        "installs_rc_asert_ratio": False,
                    },
                }
                partial_path = args.out_json.with_name(
                    args.out_json.stem + "-partial.json"
                )
                partial_path.write_text(json.dumps(partial, indent=2) + "\n")
        except Exception:
            pass
        raise
    finally:
        validator.stop()
        miner.stop()


if __name__ == "__main__":
    raise SystemExit(main())
