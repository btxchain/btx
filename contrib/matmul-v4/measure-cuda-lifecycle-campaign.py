#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""Two-node CUDA lifecycle campaign: toy rehearsal or production strict-device.

Measures the readiness-gate sum (not a single ExactReplay):

  candidate execution
  + candidate queue wait
  + winner reseal
  + reseal queue wait
  + one-shot local winner-authority handoff
  + authenticated relay
  + receiving tip validation
  + validation queue wait

Samples are diagnostic latest-component estimates: missing any component, or a
counter that did not advance during the attempt, drops the observation from the
complete set. The scheduler does not yet bind every component to one exact
block, so neither these samples nor the RPC `complete_lifecycle_readiness`
record are correlated activation evidence. Ratification gates stay false; this
script never flips them or installs an RC ASERT ratio.

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
SCHEMA_VERSION = 2


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


def scheduler(node: Node) -> dict[str, Any]:
    info = node.cli("getmininginfo")
    return info["backend_runtime"]["rc_accelerator_scheduler"]


def snapshot_counters(miner: Node, validator: Node) -> dict[str, Any]:
    ms = scheduler(miner)
    vs = scheduler(validator)
    return {
        "miner_candidate": ms["lanes"]["candidate_mining"]["completions"],
        "miner_reseal": ms["lanes"]["winner_reseal"]["completions"],
        "miner_authority_consumed": ms["winner_reseal_authority"]["consumed"],
        "miner_authority_published": ms["winner_reseal_authority"]["published"],
        "validator_relay": vs["authenticated_relay_samples"],
        "validator_tip": vs["lanes"]["tip_validation"]["completions"],
    }


def extract_components(miner: Node, validator: Node) -> dict[str, Any]:
    ms = scheduler(miner)
    vs = scheduler(validator)
    m_cand = ms["lanes"]["candidate_mining"]
    m_reseal = ms["lanes"]["winner_reseal"]
    m_auth = ms["winner_reseal_authority"]
    v_tip = vs["lanes"]["tip_validation"]
    components = {
        "candidate_execution_s": float(m_cand["last_execution_s"]),
        "candidate_queue_wait_s": float(m_cand["last_queue_wait_s"]),
        "winner_reseal_s": float(m_reseal["last_execution_s"]),
        "reseal_queue_wait_s": float(m_reseal["last_queue_wait_s"]),
        "winner_authority_handoff_s": float(m_auth["last_reseal_to_consume_s"]),
        "authenticated_relay_s": float(vs["last_authenticated_relay_s"]),
        "tip_validation_s": float(v_tip["last_execution_s"]),
        "validation_queue_wait_s": float(v_tip["last_queue_wait_s"]),
    }
    missing = [k for k, v in components.items() if not math.isfinite(v) or v < 0]
    authority_measured = m_auth["consumed"] > 0 and m_auth["published"] > 0
    core_complete = (
        not missing
        and m_cand["completions"] > 0
        and m_reseal["completions"] > 0
        and vs["authenticated_relay_samples"] > 0
        and v_tip["completions"] > 0
    )
    # Fail-closed for the readiness-gate sum: authority handoff is required.
    complete = core_complete and authority_measured
    core_lifecycle_s = None
    if core_complete:
        core_lifecycle_s = sum(
            v for k, v in components.items() if k != "winner_authority_handoff_s"
        )
    complete_lifecycle_s = sum(components.values()) if complete else None
    rpc_lifecycle = vs.get("complete_lifecycle_readiness") or ms.get(
        "complete_lifecycle_readiness"
    )
    validator_rc = validator.cli("getmininginfo")["backend_runtime"][
        "rc_exact_replay"
    ]
    validator_last = validator_rc.get("last_validation") or {}
    return {
        "complete": complete,
        "core_complete_without_authority": core_complete and not authority_measured,
        "authority_measured": authority_measured,
        "missing_fields": missing,
        "components": components,
        "core_lifecycle_s": core_lifecycle_s,
        "complete_lifecycle_s": complete_lifecycle_s,
        "rpc_assess_lifecycle_s": (rpc_lifecycle or {}).get("complete_lifecycle_s"),
        "rpc_complete_sample_set": (rpc_lifecycle or {}).get("complete_sample_set"),
        "rpc_correlated_end_to_end_sample": (rpc_lifecycle or {}).get(
            "correlated_end_to_end_sample"
        ),
        "rpc_operationally_ready": (rpc_lifecycle or {}).get("operationally_ready"),
        "rpc_omits_winner_authority_handoff": True,
        "miner_provider": (ms.get("winner_reseal_authority") or {}).get("last_provider"),
        "validator_provider": validator_last.get("provider"),
        "validator_execution_policy": validator_last.get("execution_policy"),
        "validator_fully_accelerated": validator_last.get("fully_accelerated"),
        "validator_cpu_gemm_calls": validator_last.get("cpu_gemm_calls"),
        "validator_cpu_gemm_fallbacks": validator_last.get("cpu_gemm_fallbacks"),
    }


def counters_advanced(
    before: dict[str, Any], after: dict[str, Any], *, require_authority: bool
) -> tuple[bool, list[str]]:
    required = [
        ("miner_candidate", 1),
        ("miner_reseal", 1),
        ("validator_relay", 1),
        ("validator_tip", 1),
    ]
    if require_authority:
        required.append(("miner_authority_consumed", 1))
    gaps = []
    for key, need in required:
        if after[key] < before[key] + need:
            gaps.append(f"{key}: {before[key]} -> {after[key]} (need +{need})")
    return (not gaps, gaps)


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
            before = snapshot_counters(miner, validator)
            block_hash = None
            phase = "steady_mine_relay"
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
                    h0 = mine_one(miner, args.mine_timeout_s)
                    h1 = mine_one(validator, args.mine_timeout_s)
                    connect_peers(miner, validator)
                    # Prefer miner tip; force reconnect/sync. Reorg may drop one.
                    if not wait_equal_tips(miner, validator, args.sync_timeout_s):
                        # Ask validator to reorg toward miner if miner is ahead in work.
                        # Fallback: mine another block on miner and sync.
                        mine_one(miner, args.mine_timeout_s)
                        if not wait_equal_tips(miner, validator, args.sync_timeout_s):
                            incomplete.append(
                                {
                                    "attempt": attempt,
                                    "phase": phase,
                                    "reason": "reorg_sync_failed",
                                    "miner_block": h0,
                                    "validator_block": h1,
                                }
                            )
                            status(f"incomplete attempt {attempt}: reorg sync failed")
                            continue
                    block_hash = miner.cli("getbestblockhash")
                else:
                    block_hash = mine_one(miner, args.mine_timeout_s)
                    if not wait_equal_tips(miner, validator, args.sync_timeout_s):
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

                after = snapshot_counters(miner, validator)
                advanced_full, gaps_full = counters_advanced(
                    before, after, require_authority=True
                )
                advanced_core, gaps_core = counters_advanced(
                    before, after, require_authority=False
                )
                extracted = extract_components(miner, validator)
                record = {
                    "attempt": attempt,
                    "phase": phase,
                    "height": miner.cli("getblockcount"),
                    "block_hash": block_hash,
                    "counters_before": before,
                    "counters_after": after,
                    "counter_gaps": gaps_full if not advanced_full else [],
                    "counter_gaps_core": gaps_core if not advanced_core else [],
                    **extracted,
                }
                if (
                    advanced_full
                    and extracted["complete"]
                    and extracted["complete_lifecycle_s"] is not None
                ):
                    samples.append(record)
                    status(
                        f"complete sample {len(samples)}/{args.samples} "
                        f"lifecycle_s={extracted['complete_lifecycle_s']:.3f}"
                    )
                elif (
                    advanced_core
                    and extracted.get("core_complete_without_authority")
                    and extracted.get("core_lifecycle_s") is not None
                ):
                    record["reason"] = "authority_handoff_unavailable_without_production_canary"
                    core_samples.append(record)
                    status(
                        f"core sample {len(core_samples)}/{args.samples} "
                        f"(no authority) core_s={extracted['core_lifecycle_s']:.3f}"
                    )
                else:
                    record["reason"] = "missing_component_or_counter"
                    incomplete.append(record)
                    status(
                        f"incomplete attempt {attempt}: "
                        + (
                            ", ".join(gaps_core)
                            if gaps_core
                            else "component gate"
                        )
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
            key: [s["components"][key] for s in samples]
            for key in (
                "candidate_execution_s",
                "candidate_queue_wait_s",
                "winner_reseal_s",
                "reseal_queue_wait_s",
                "winner_authority_handoff_s",
                "authenticated_relay_s",
                "tip_validation_s",
                "validation_queue_wait_s",
            )
        }
        core_component_series = {
            key: [s["components"][key] for s in core_samples]
            for key in (
                "candidate_execution_s",
                "candidate_queue_wait_s",
                "winner_reseal_s",
                "reseal_queue_wait_s",
                "authenticated_relay_s",
                "tip_validation_s",
                "validation_queue_wait_s",
            )
        }
        lifecycle_vals = [float(s["complete_lifecycle_s"]) for s in samples]
        core_lifecycle_vals = [float(s["core_lifecycle_s"]) for s in core_samples]

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
                "model": "independent_latest_components",
                "activation_eligible": False,
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
                "candidate_execution_s",
                "candidate_queue_wait_s",
                "winner_reseal_s",
                "reseal_queue_wait_s",
                "winner_authority_handoff_s",
                "authenticated_relay_s",
                "tip_validation_s",
                "validation_queue_wait_s",
            ],
            "measurement_notes": [
                "Complete diagnostic samples require counter advancement during an attempt on miner candidate, reseal, authority consume, validator authenticated relay, and tip validation.",
                "Core samples omit winner-authority handoff when the empty production-golden manifest prevents a production capability token; they are not treated as activation-ready complete lifecycle samples.",
                "RPC complete_lifecycle_readiness sums latest lane components and omits winner-authority handoff; campaign complete sum includes handoff and is fail-closed.",
                "correlated_end_to_end_sample remains false in RPC; counters and latest component values are not bound to one exact block and cannot authorize activation.",
                "Missing authenticated-relay observations are recorded as incomplete; none are invented.",
            ],
            "gaps_vs_activation_gates": [
                "winner_authority_handoff unavailable until reviewed production goldens + startup canary mint a process capability",
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
