#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see COPYING.
"""Create executable native-node plans from actual candidate bytes, or combine
independently enrolled host plans into one parallel deployment experiment.
"""

import argparse
import copy
import json
from pathlib import Path
import platform
import sys

try:
    from .evidence import EvidenceError, atomic_json, digest, machine_probe, sha256_file, strict_json
    from .runner import validate_plan
except ImportError:
    from evidence import EvidenceError, atomic_json, digest, machine_probe, sha256_file, strict_json
    from runner import validate_plan


def prepare(root, binary_dir, work_dir, profile, seed=None, require_acquisition=False,
            model_run=None, model_run_sha256=None, wan_enrollment=None, wan_enrollment_sha256=None):
    root, binary_dir = Path(root).resolve(strict=True), Path(binary_dir).resolve(strict=True)
    work_dir = Path(work_dir).resolve()
    if work_dir.exists() or work_dir.is_relative_to(root):
        raise EvidenceError("scenario work directory must be a new path outside the candidate checkout")
    if profile not in {"fresh-native-start", "local-cpu-useful-model", "macos-portable", "windows-portable", "lan-two-physical-hosts", "wan-three-native-peers"}:
        raise EvidenceError("this plan generator handles native start and peer scenarios; use measured driver plans for other profiles")
    python = Path(sys.executable).resolve(strict=True)
    directory = root / "contrib/swarm/native_acceptance"
    driver = directory / "native_node.py"
    files = [driver, directory / "evidence.py", directory / "runner.py", directory / "native_model.py", directory / "offline_image.py", directory / "wan_peers.py"]
    suffix = ".exe" if platform.system() == "Windows" else ""
    files += [binary_dir / (name + suffix) for name in ("btxd", "btx-cli", "btx-modeld", "btx-guardd", "btx-hcpd")]
    import secrets
    host = machine_probe(root, secrets.token_hex(32))
    mode = "wan" if profile == "wan-three-native-peers" else ("lan" if profile == "lan-two-physical-hosts" else "fresh")
    if mode == "wan" and seed is None:
        require_acquisition = True
    argv = [str(python), "-B", str(driver), "--bin-dir", str(binary_dir), "--work-dir", str(work_dir),
            "--mode", mode, "--nonce", "{nonce}", "--timeout", "180"]
    if profile in {"macos-portable", "windows-portable"}:
        argv += ["--expect-system", "Darwin" if profile == "macos-portable" else "Windows"]
    if seed is not None:
        seed = Path(seed).resolve(strict=True)
        files.append(seed)
        argv += ["--seed-file", str(seed), "--seed-sha256", sha256_file(seed)]
    if require_acquisition:
        argv.append("--require-acquisition")
    if mode == "wan":
        if wan_enrollment is None:
            raise EvidenceError("WAN qualification requires independently enrolled public endpoint and PQ1 identity bytes")
        try:
            from .wan_peers import validate_enrollment
        except ImportError:
            from wan_peers import validate_enrollment
        wan_enrollment = Path(wan_enrollment).resolve(strict=True)
        enrollment = validate_enrollment(wan_enrollment, wan_enrollment_sha256)
        files.append(wan_enrollment)
        files += [Path(enrollment["local"][name]["path"]) for name in ("certificate", "private_key")]
        argv += ["--wan-enrollment", str(wan_enrollment), "--wan-enrollment-sha256", wan_enrollment_sha256, "--minimum-peers", "2"]
    elif wan_enrollment is not None:
        raise EvidenceError("WAN enrollment cannot be relabeled as native LAN discovery")
    if profile == "local-cpu-useful-model" and model_run is None:
        raise EvidenceError("local useful-model profile requires an owner-pinned real model execution request")
    if model_run is not None:
        model_run = Path(model_run).resolve(strict=True)
        if sha256_file(model_run) != model_run_sha256:
            raise EvidenceError("owner model-run manifest digest differs")
        config = strict_json(model_run.read_bytes())
        if config.get("schema") != "BTX-NATIVE-MODEL-RUN/1":
            raise EvidenceError("invalid owner model execution request")
        if profile == "local-cpu-useful-model" and config.get("generate", {}).get("expected_device") != "cpu":
            raise EvidenceError("local CPU model profile requires observed CPU execution")
        files.append(model_run)
        for row in config["files"]:
            files.append(Path(config["model_root"]) / row["path"])
        for name in ("adapter", "cuda_loader", "llama_cli"):
            if config.get(name) is not None:
                files.append(Path(config[name]["path"]))
        if config["adapter"].get("kind") == "python":
            files.append(Path(config["adapter"]["python"]["path"]))
        argv += ["--model-run", str(model_run), "--model-run-sha256", model_run_sha256]
    assertions = [{"path": "network.enabled", "op": "eq", "value": True},
                  {"path": "network.helper_ready", "op": "eq", "value": True},
                  {"path": "network.pq1_ready", "op": "eq", "value": True},
                  {"path": "network.automatic_spend_atoms", "op": "eq", "value": 0},
                  {"path": "network.native_participation.schema", "op": "eq", "value": "BTX/NativeParticipation/1"},
                  {"path": "durable_status_sha256", "op": "sha256"},
                  {"path": "guard_process.status.ready", "op": "eq", "value": True},
                  {"path": "guard_process.status.execution_authorized", "op": "eq", "value": False},
                  {"path": "guard_process.status.automatic_spend_atoms", "op": "eq", "value": "0"},
                  {"path": "manual_peer_addresses", "op": "eq", "value": [row["endpoint"] for row in enrollment["peers"]] if mode == "wan" else []}]
    if mode == "lan":
        assertions += [{"path": "network.native_participation.authenticated_peers", "op": "min", "value": 1}]
    if mode == "wan":
        assertions += [{"path": "network.native_participation.authenticated_peers", "op": "min", "value": 2},
                       {"path": "wan_enrollment_sha256", "op": "eq", "value": wan_enrollment_sha256},
                       {"path": "wan_observed_peers", "op": "nonempty"}]
    if require_acquisition:
        assertions += [{"path": "network.native_participation.acquired_models", "op": "min", "value": 1}]
    if model_run is not None:
        assertions += [{"path": "native_model_workload.generatemodel.generated", "op": "eq", "value": True},
                       {"path": "native_model_workload.generatemodel.adapter.device", "op": "eq", "value": config["generate"]["expected_device"]},
                       {"path": "native_model_workload.owner_manifest_sha256", "op": "eq", "value": model_run_sha256}]
    requirements = ["P2P-SCN-B"] if mode == "lan" else (["P2P-SCN-D"] if mode == "wan" else ["P2P-SCN-O", "NIF-QA-007"])
    plan = {"schema": "BTX-NATIVE-PLAN/1", "profile": profile, "source": host["source"],
            "hosts": {"node": {"transport": "local", "root": str(root), "machine_id_sha256": host["machine_id_sha256"]}},
            "phases": [{"name": "native-execution", "steps": [{"id": "node-behavior", "host": "node", "argv": argv,
                       "executable_sha256": sha256_file(python), "timeout": 900 if model_run else 240,
                       "inputs": [{"path": str(path), "sha256": sha256_file(path)} for path in files],
                       "requirements": requirements, "assertions": assertions}]}]}
    validate_plan(plan)
    return plan


def merge(members, host_config):
    combined = None
    for name, plan in members.items():
        validate_plan(plan)
        if len(plan["hosts"]) != 1:
            raise EvidenceError("each enrolled member must originate from a one-host plan")
        if name not in host_config:
            raise EvidenceError("missing authenticated transport configuration: " + name)
        original = next(iter(plan["hosts"].values()))
        replacement = dict(host_config[name])
        if any(replacement.get(k) != original.get(k) for k in ("root", "machine_id_sha256")):
            raise EvidenceError("host configuration does not match independently recorded enrollment")
        if combined is None:
            combined = copy.deepcopy(plan)
            combined["hosts"] = {}
            for phase in combined["phases"]:
                phase["steps"] = []
        if plan["source"] != combined["source"] or plan["profile"] != combined["profile"]:
            raise EvidenceError("all machines must execute the same candidate and profile")
        if [phase.get("name") for phase in plan["phases"]] != [phase.get("name") for phase in combined["phases"]]:
            raise EvidenceError("phase sequence differs across host plans")
        combined["hosts"][name] = replacement
        for index, phase in enumerate(plan["phases"]):
            for step in phase["steps"]:
                step = copy.deepcopy(step)
                step["host"], step["id"] = name, name + "." + step["id"]
                combined["phases"][index]["steps"].append(step)
    if combined is None:
        raise EvidenceError("no member plans")
    identities = {host["machine_id_sha256"] for host in combined["hosts"].values()}
    if combined["profile"] == "lan-two-physical-hosts" and len(identities) < 2:
        raise EvidenceError("two process labels on one machine do not make a two-host plan")
    if combined["profile"] == "wan-three-native-peers" and len(identities) < 3:
        raise EvidenceError("WAN profile requires three independently enrolled physical host plans")
    validate_plan(combined)
    return combined


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    local = commands.add_parser("local")
    local.add_argument("--root", type=Path, required=True)
    local.add_argument("--bin-dir", type=Path, required=True)
    local.add_argument("--work-dir", type=Path, required=True)
    local.add_argument("--profile", required=True)
    local.add_argument("--seed-file", type=Path)
    local.add_argument("--require-acquisition", action="store_true")
    local.add_argument("--model-run", type=Path)
    local.add_argument("--model-run-sha256")
    local.add_argument("--wan-enrollment", type=Path)
    local.add_argument("--wan-enrollment-sha256")
    local.add_argument("--out", type=Path, required=True)
    group = commands.add_parser("merge")
    group.add_argument("--member", action="append", required=True, help="enrolled-name=/absolute/path/to/member-plan.json")
    group.add_argument("--host-config", type=Path, required=True)
    group.add_argument("--out", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == "local":
            if args.out.resolve().is_relative_to(args.root.resolve()):
                raise EvidenceError("store plans outside the source checkout")
            plan = prepare(args.root, args.bin_dir, args.work_dir, args.profile, args.seed_file, args.require_acquisition,
                           args.model_run, args.model_run_sha256, args.wan_enrollment, args.wan_enrollment_sha256)
        else:
            members = {}
            for item in args.member:
                name, path = item.split("=", 1)
                if name in members:
                    raise EvidenceError("duplicate member name")
                members[name] = strict_json(Path(path).read_bytes())
            plan = merge(members, strict_json(args.host_config.read_bytes()))
        atomic_json(args.out, plan)
        print(json.dumps({"plan": str(args.out), "plan_sha256": digest(plan), "profile": plan["profile"],
                          "hosts": len(plan["hosts"]), "native_execution": "NOT_RUN"}))
        return 0
    except (EvidenceError, OSError, ValueError) as exc:
        print(json.dumps({"error": str(exc), "native_execution": "NOT_RUN"}))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
