#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see COPYING.
"""Run a real packaged btxd and its default model helper in a fresh regtest dir.

The LAN mode sends no addnode/modelpeer/bootstrap RPC and waits for native PQ1
admission. Launch it concurrently on enrolled physical hosts with runner.py.
The fresh mode is a one-host test and never claims a two-host deployment.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import socket
import subprocess
import sys
import time

try:
    from .evidence import EvidenceError, _terminate, run_command, sha256_file, strict_json
except ImportError:
    from evidence import EvidenceError, _terminate, run_command, sha256_file, strict_json


def free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def observe_guard(status_path: Path, expected_binary_sha256: str, parent_pid: int) -> dict:
    if not status_path.is_file() or status_path.is_symlink():
        raise EvidenceError("native guard process status is absent")
    status = strict_json(status_path.read_bytes())
    if status.get("schema") != "BTX/GuardProcess/1" or status.get("enabled") is not True or status.get("ready") is not True:
        raise EvidenceError("default guard subprocess has not completed its protocol handshake")
    pid = status.get("pid")
    if type(pid) is not int or pid <= 0 or status.get("execution_authorized") is not False or status.get("automatic_spend_atoms") != "0":
        raise EvidenceError("guard authority, PID or spend invariant differs")
    observed = {"status": status, "status_sha256": sha256_file(status_path)}
    if os.name == "posix":
        try:
            os.kill(pid, 0)
        except OSError as exc:
            raise EvidenceError("reported guard process is not alive") from exc
        observed["pid_alive"] = True
    if platform.system() == "Linux":
        process_root = Path("/proc") / str(pid)
        image = (process_root / "exe").resolve(strict=True)
        if sha256_file(image) != expected_binary_sha256:
            raise EvidenceError("guard PID is not running the pinned packaged guard binary")
        status_text = (process_root / "status").read_text()
        fields = dict(line.split(":", 1) for line in status_text.splitlines() if ":" in line)
        if fields.get("PPid", "").strip() != str(parent_pid):
            raise EvidenceError("guard process is not owned by this scenario's node")
        observed["observed_executable_sha256"] = expected_binary_sha256
        observed["observed_parent_pid"] = parent_pid
    return observed


def run_native(binary_dir: Path, workspace: Path, mode: str, timeout: int,
               minimum_peers: int = 1, seed_file: Path | None = None,
               seed_sha256: str | None = None, require_acquisition: bool = False,
               expect_system: str | None = None, nonce: str = "",
               model_run: Path | None = None, model_run_sha256: str | None = None,
               wan_enrollment: Path | None = None, wan_enrollment_sha256: str | None = None) -> dict:
    if mode not in {"fresh", "lan", "wan"} or not 10 <= timeout <= 900 or not 1 <= minimum_peers <= 16:
        raise EvidenceError("invalid bounded native scenario")
    if expect_system and platform.system() != expect_system:
        raise EvidenceError("native platform differs from advertised profile")
    binary_dir, workspace = Path(binary_dir).resolve(strict=True), Path(workspace)
    if workspace.exists() or workspace.is_symlink():
        raise EvidenceError("native scenario requires a new private work directory")
    suffix = ".exe" if platform.system() == "Windows" else ""
    required = ("btxd", "btx-cli", "btx-modeld", "btx-guardd", "btx-hcpd")
    binaries = {name: binary_dir / (name + suffix) for name in required}
    pins = {name: sha256_file(path) for name, path in binaries.items()}
    if seed_file is not None and (not seed_sha256 or sha256_file(seed_file) != seed_sha256):
        raise EvidenceError("publisher model bytes differ from explicit local pin")
    workspace.mkdir(parents=True, mode=0o700)
    model_config, process_env = None, dict(os.environ)
    if model_run is not None:
        try:
            from .native_model import prepare_model_run
        except ImportError:
            from native_model import prepare_model_run
        model_config, adapter_env = prepare_model_run(model_run, model_run_sha256 or "", workspace)
        # This private scenario authorizes only adapters named in its pinned
        # owner request. Do not inherit a second implicit inference command.
        for name in ("BTX_MODEL_GENERATE", "BTX_MODEL_CUDA_LOADER", "BTX_LLAMA_CLI", "BTX_MODEL_INFER_CMD"):
            process_env.pop(name, None)
        process_env.update(adapter_env)
    datadir = workspace / "node"
    datadir.mkdir(mode=0o700)
    wan, wan_observed = None, []
    if mode == "wan":
        if wan_enrollment is None or minimum_peers < 2:
            raise EvidenceError("WAN scenario requires independently pinned public enrollment and at least two remote peers")
        try:
            from .wan_peers import configure
        except ImportError:
            from wan_peers import configure
        wan = configure(wan_enrollment, wan_enrollment_sha256 or "", datadir)
    elif wan_enrollment is not None:
        raise EvidenceError("WAN enrollment cannot be silently used as LAN discovery evidence")
    rpcport = free_port()
    node_args = [str(binaries["btxd"]), "-regtest", "-server=1", "-daemon=0",
                 "-datadir=" + str(datadir.resolve()), "-rpcport=" + str(rpcport),
                 "-port=" + str(free_port()), "-listen=0", "-dnsseed=0", "-discover=0"]
    if mode == "fresh":
        node_args += ["-modelbind=127.0.0.1:" + str(free_port())]
    elif mode == "wan":
        node_args += ["-modelbind=0.0.0.0:" + str(wan["local"]["model_port"])]
        node_args += ["-modelpeer=" + row["endpoint"] for row in wan["peers"]]
    # Do not supply -modelnet=1, -modelhelper, disabled helper, -modelstorage=0,
    # a peer address, or the matmul-off flags. This checks ordinary defaults.
    log_path = workspace / "btxd.log"
    rpc_base = [str(binaries["btx-cli"]), "-regtest", "-datadir=" + str(datadir.resolve()),
                "-rpcport=" + str(rpcport)]

    def rpc(method, *params):
        rpc_timeout = min(timeout, 600) if method in {"hostmodel", "exportmodelpath", "loadmodel", "generatemodel"} else 30
        result = run_command(rpc_base + [method] + [p if isinstance(p, str) else json.dumps(p) for p in params], workspace, rpc_timeout)
        if result["returncode"] or result["failure"]:
            raise EvidenceError("RPC did not succeed: " + method + ": " + result["stderr"][-400:])
        return strict_json(result["stdout"])

    started, deadline = time.time_ns(), time.monotonic() + timeout
    last_error, info, chain, imported, report, guard = "", None, None, None, None, None
    guard_path = datadir / "regtest" / "modelnet" / "swarm" / "guard-process.json"
    with log_path.open("wb") as log:
        process = subprocess.Popen(node_args, stdout=log, stderr=log, stdin=subprocess.DEVNULL,
                                   start_new_session=(os.name == "posix"), env=process_env)
        try:
            while time.monotonic() < deadline:
                if process.poll() is not None:
                    raise EvidenceError("native daemon exited before model participation: " + str(process.returncode))
                try:
                    chain = rpc("getblockchaininfo")
                    if chain.get("chain") != "regtest":
                        raise EvidenceError("node is not isolated regtest")
                    info = rpc("getmodelnetworkinfo")
                    if not all(info.get(k) is True for k in ("enabled", "helper_ready", "pq1_ready")):
                        raise EvidenceError("real default model helper/PQ1 is not ready")
                    if info.get("automatic_spend_atoms") not in (0, "0"):
                        raise EvidenceError("automatic spend invariant failed")
                    native = info.get("native_participation", {})
                    if native.get("schema") != "BTX/NativeParticipation/1":
                        raise EvidenceError("native participation observation is absent")
                    guard = observe_guard(guard_path, pins["btx-guardd"], process.pid)
                    if seed_file is not None and imported is None:
                        imported = rpc("hostmodel", str(seed_file.resolve()), {"pin": True, "publish": True})
                    if mode in {"lan", "wan"}:
                        if mode == "lan" and native.get("lan_enabled") is not True:
                            raise EvidenceError("native LAN discovery is disabled")
                        if native.get("authenticated_peers", 0) < minimum_peers:
                            raise EvidenceError("required independently admitted PQ1 peers are absent")
                        observations = native.get("peer_observations", [])
                        pins_seen = {record.get("transport_pin") for record in observations if record.get("transport_pin")}
                        if len(pins_seen) < minimum_peers:
                            raise EvidenceError("peer count is not backed by distinct authenticated identities")
                        if mode == "wan":
                            try:
                                from .wan_peers import observed_peers
                            except ImportError:
                                from wan_peers import observed_peers
                            wan_observed = observed_peers(native, wan)
                    if require_acquisition and native.get("acquired_models", 0) < 1:
                        raise EvidenceError("empty store has not acquired a verified free model")
                    break
                except EvidenceError as exc:
                    last_error = str(exc)
                    time.sleep(0.2)
            else:
                raise EvidenceError("native observation timeout: " + last_error)
            # Query a second time so a transient stale reply cannot be the only
            # observation. Host membership still requires independent enrollment.
            time.sleep(1)
            confirmed = rpc("getmodelnetworkinfo")
            if confirmed.get("helper_ready") is not True or confirmed.get("automatic_spend_atoms") not in (0, "0"):
                raise EvidenceError("native helper did not remain operational")
            if mode in {"lan", "wan"} and confirmed.get("native_participation", {}).get("authenticated_peers", 0) < minimum_peers:
                raise EvidenceError("admitted peers disappeared before confirmation")
            if mode == "wan":
                wan_observed = observed_peers(confirmed.get("native_participation", {}), wan)
                if sha256_file(wan_enrollment) != wan_enrollment_sha256:
                    raise EvidenceError("WAN enrollment changed during native execution")
            status_path = datadir / "regtest" / "modelnet" / "swarm" / "native-participation.json"
            if not status_path.is_file():
                raise EvidenceError("native participation was not durably published")
            status = strict_json(status_path.read_bytes())
            if status.get("schema") != "BTX/NativeParticipation/1":
                raise EvidenceError("durable participation schema differs")
            guard = observe_guard(guard_path, pins["btx-guardd"], process.pid)
            model_result = None
            if model_config is not None:
                try:
                    from .native_model import exercise_model
                except ImportError:
                    from native_model import exercise_model
                model_result = exercise_model(rpc, model_config)
            report = {"schema": "BTX-NATIVE-NODE-RUN/1", "nonce": nonce,
                      "scenario": mode, "system": platform.system(), "architecture": platform.machine(),
                      "node_argv": node_args, "binary_sha256": pins,
                      "started_ns": started, "finished_ns": time.time_ns(),
                      "chain": chain, "network": confirmed, "durable_status_sha256": sha256_file(status_path),
                      "publisher_import": imported,
                      "manual_peer_addresses": [row["endpoint"] for row in wan["peers"]] if wan else [],
                      "wan_enrollment_sha256": wan_enrollment_sha256, "wan_observed_peers": wan_observed,
                      "guard_process": guard, "native_model_workload": model_result,
                      "observed_node_processes": 1, "physical_host_qualification": "REQUIRES_INDEPENDENT_ENROLLMENT",
                      "release_qualified": False}
            return report
        finally:
            if process.poll() is None:
                # Shutdown only this scenario's daemon, selected by its fresh
                # datadir, RPC port and cookie. Never use pkill/process-name scans.
                try:
                    run_command(rpc_base + ["stop"], workspace, 10)
                    process.wait(timeout=20)
                except (subprocess.TimeoutExpired, OSError):
                    _terminate(process)
                finally:
                    if process.poll() is None:
                        _terminate(process)
            log.flush()
            if report is not None:
                report["daemon_log_sha256"] = sha256_file(log_path)
                report["daemon_log_path"] = str(log_path.resolve())


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bin-dir", type=Path, required=True)
    parser.add_argument("--work-dir", type=Path, required=True)
    parser.add_argument("--mode", choices=("fresh", "lan", "wan"), default="fresh")
    parser.add_argument("--timeout", type=int, default=180)
    parser.add_argument("--minimum-peers", type=int, default=1)
    parser.add_argument("--seed-file", type=Path)
    parser.add_argument("--seed-sha256")
    parser.add_argument("--require-acquisition", action="store_true")
    parser.add_argument("--expect-system", choices=("Linux", "Darwin", "Windows"))
    parser.add_argument("--nonce", default="")
    parser.add_argument("--model-run", type=Path, help="explicit owner-pinned native model execution request")
    parser.add_argument("--model-run-sha256")
    parser.add_argument("--wan-enrollment", type=Path)
    parser.add_argument("--wan-enrollment-sha256")
    args = parser.parse_args(argv)
    try:
        result = run_native(args.bin_dir, args.work_dir, args.mode, args.timeout,
                            args.minimum_peers, args.seed_file, args.seed_sha256,
                            args.require_acquisition, args.expect_system, args.nonce,
                            args.model_run, args.model_run_sha256,
                            args.wan_enrollment, args.wan_enrollment_sha256)
        print(json.dumps(result, sort_keys=True))
        return 0
    except (EvidenceError, OSError, subprocess.SubprocessError) as exc:
        print(json.dumps({"error": str(exc), "release_qualified": False}))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
