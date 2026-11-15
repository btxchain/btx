#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see COPYING.
"""Execute pinned native acceptance plans across explicitly enrolled machines.

Examples and trust boundaries are in README.md. This is an acceptance driver;
it does not grant work, change node policy, or automatically authorize spending.
"""

from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor
import csv
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import shlex
import sys
import time

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    from evidence import (SCHEMA, EvidenceError, HEX64, atomic_json, canonical, digest,
                          evaluate_assertions, load_key, machine_probe, run_command,
                          sha256_file, sign_receipt, source_identity, strict_json, verify_receipt)
else:
    from .evidence import (SCHEMA, EvidenceError, HEX64, atomic_json, canonical, digest,
                           evaluate_assertions, load_key, machine_probe, run_command,
                           sha256_file, sign_receipt, source_identity, strict_json, verify_receipt)

PROFILES = (
    "fresh-native-start", "whole-node-airgap", "local-cpu-useful-model",
    "private-case-revocation", "economic-regtest", "failure-and-rollback",
    "offline-runtime-image", "macos-portable", "windows-portable",
    "lan-two-physical-hosts", "wan-three-native-peers", "linux-sm100-deepinfer",
    "linux-ascend-deepinfer", "deepinfer-exact-multirank-state",
) + tuple(f"DT-Q{i:02d}" for i in range(1, 19))

# A policy may strengthen these minima; it cannot make a one-host experiment
# satisfy a named multi-host profile. Physical identities come from independent
# operator enrollment, not a host's own passed=true field.
PROFILE_MINIMA = {"lan-two-physical-hosts": (2, 0), "wan-three-native-peers": (3, 0),
                  "deepinfer-exact-multirank-state": (2, 2),
                  "linux-sm100-deepinfer": (1, 1), "linux-ascend-deepinfer": (1, 0)}


def read_json(path: Path) -> dict:
    return strict_json(Path(path).read_bytes())


def validate_plan(plan: dict) -> None:
    if plan.get("schema") != "BTX-NATIVE-PLAN/1":
        raise EvidenceError("unsupported plan schema")
    if plan.get("profile") not in PROFILES:
        raise EvidenceError("unknown native profile")
    source = plan.get("source", {})
    if not re.fullmatch(r"[0-9a-f]{40}", str(source.get("commit", ""))) or not HEX64.fullmatch(str(source.get("source_tree_sha256", ""))):
        raise EvidenceError("plan must pin commit and complete candidate source tree")
    hosts, phases = plan.get("hosts"), plan.get("phases")
    if not isinstance(hosts, dict) or not 1 <= len(hosts) <= 32:
        raise EvidenceError("plan requires 1..32 explicitly enrolled hosts")
    for name, host in hosts.items():
        if not re.fullmatch(r"[A-Za-z0-9_-]{1,64}", name):
            raise EvidenceError("invalid host identifier")
        if host.get("transport") not in {"local", "ssh"}:
            raise EvidenceError("host transport must be local or ssh")
        if not Path(host.get("root", "")).is_absolute():
            raise EvidenceError("host root must be absolute")
        if not HEX64.fullmatch(str(host.get("machine_id_sha256", ""))):
            raise EvidenceError("host must have an enrolled native machine identity")
        if host["transport"] == "ssh":
            if not re.fullmatch(r"[A-Za-z0-9_.@:\[\]-]+", host.get("target", "")) or host["target"].startswith("-"):
                raise EvidenceError("invalid SSH target")
            if not Path(host.get("known_hosts", "")).is_absolute():
                raise EvidenceError("SSH requires an explicit pinned known_hosts file")
            if not HEX64.fullmatch(str(host.get("known_hosts_sha256", ""))):
                raise EvidenceError("SSH known_hosts digest is required")
    if not isinstance(phases, list) or not 1 <= len(phases) <= 64:
        raise EvidenceError("plan requires 1..64 execution phases")
    seen = set()
    total = 0
    for phase in phases:
        if not isinstance(phase.get("steps"), list) or not phase["steps"]:
            raise EvidenceError("empty execution phase")
        if phase.get("always_run", False) not in (True, False):
            raise EvidenceError("invalid cleanup marker")
        for step in phase["steps"]:
            total += 1
            sid = step.get("id", "")
            if not re.fullmatch(r"[A-Za-z0-9_.-]{1,100}", sid) or sid in seen:
                raise EvidenceError("step ids must be unique")
            seen.add(sid)
            if step.get("host") not in hosts:
                raise EvidenceError("step refers to an unenrolled host")
            argv = step.get("argv", [])
            if not argv or not isinstance(argv, list) or not Path(argv[0]).is_absolute():
                raise EvidenceError("step executable must be absolute")
            if not HEX64.fullmatch(str(step.get("executable_sha256", ""))):
                raise EvidenceError("step executable must be pinned by SHA-256")
            if not isinstance(step.get("assertions"), list) or not step["assertions"]:
                raise EvidenceError("exit status alone cannot qualify a native step")
            if not isinstance(step.get("requirements", []), list):
                raise EvidenceError("requirements must be an explicit array")
            if type(step.get("timeout", 60)) is not int or not 1 <= step.get("timeout", 60) <= 3600:
                raise EvidenceError("invalid step timeout")
            # Inputs include native binaries and any script, harness, dataset or
            # adapter loaded by the executable; missing pins fail before launch.
            for item in step.get("inputs", []):
                if not Path(item.get("path", "")).is_absolute() or not HEX64.fullmatch(str(item.get("sha256", ""))):
                    raise EvidenceError("all test inputs must use absolute paths and SHA-256 pins")
    if total > 256:
        raise EvidenceError("too many steps in one finite plan")


def execute_step(root: Path, step: dict, nonce: str) -> dict:
    executable = Path(step["argv"][0])
    pins = [{"path": str(executable), "sha256": step["executable_sha256"]}] + step.get("inputs", [])
    observed_inputs = []
    for pin in pins:
        observed = sha256_file(Path(pin["path"]))
        if observed != pin["sha256"]:
            raise EvidenceError(f"input digest mismatch: {pin['path']}")
        observed_inputs.append({"path": pin["path"], "sha256": observed})
    argv = [value.replace("{nonce}", nonce) for value in step["argv"]]
    result = run_command(argv, root, step.get("timeout", 60))
    result.update({"id": step["id"], "host": step["host"], "nonce": nonce,
                   "inputs": observed_inputs, "requirements": step.get("requirements", []),
                   "assertions": step["assertions"], "artifacts": []})
    result["checks"] = []
    result["status"] = "FAIL"
    if result["returncode"] != 0 or result["failure"]:
        return result
    try:
        observation = strict_json(result["stdout"])
        # The program's own passed/release_qualified fields confer no authority.
        # Only the immutable assertion plan is evaluated here.
        result["checks"] = evaluate_assertions(observation, step["assertions"])
        for artifact in step.get("artifacts", []):
            path = Path(artifact["path"])
            result["artifacts"].append({"id": artifact["id"], "path": str(path),
                                         "sha256": sha256_file(path), "size": path.stat().st_size})
        # Executed code must not rewrite its own pinned inputs during a run.
        for pin in observed_inputs:
            if sha256_file(Path(pin["path"])) != pin["sha256"]:
                raise EvidenceError("test input changed while executing")
        if all(item["passed"] for item in result["checks"]):
            result["status"] = "PASS"
    except (EvidenceError, OSError, KeyError) as exc:
        result["failure"] = str(exc)
    return result


def agent(request: dict) -> dict:
    root = Path(request["root"]).resolve(strict=True)
    nonce = request.get("nonce", "")
    if not HEX64.fullmatch(nonce):
        raise EvidenceError("invalid run challenge")
    if request["action"] == "probe":
        return machine_probe(root, nonce)
    if request["action"] == "execute":
        candidate = source_identity(root)
        expected = request["source"]
        if candidate["commit"] != expected["commit"] or candidate["source_tree_sha256"] != expected["source_tree_sha256"]:
            raise EvidenceError("source changed since candidate enrollment")
        return execute_step(root, request["step"], nonce)
    raise EvidenceError("unsupported agent action")


def on_host(host: dict, request: dict) -> dict:
    request = dict(request, root=host["root"])
    if host["transport"] == "local":
        return agent(request)
    known_hosts = Path(host["known_hosts"])
    if sha256_file(known_hosts) != host["known_hosts_sha256"]:
        raise EvidenceError("SSH host trust file changed")
    script = str(Path(host["root"]) / "contrib/swarm/native_acceptance/runner.py")
    remote_command = shlex.join([host.get("python", "python3"), script, "agent"])
    argv = ["ssh", "-F", os.devnull, "-oBatchMode=yes", "-oStrictHostKeyChecking=yes",
            "-oUserKnownHostsFile=" + str(known_hosts), "-oConnectTimeout=15",
            "-oServerAliveInterval=15", "-oServerAliveCountMax=2"]
    if "port" in host:
        if type(host["port"]) is not int or not 1 <= host["port"] <= 65535:
            raise EvidenceError("invalid SSH port")
        argv += ["-p", str(host["port"])]
    argv += ["--", host["target"], remote_command]
    timeout = min(3600, request.get("step", {}).get("timeout", 60) + 30)
    response = run_command(argv, Path.cwd(), timeout, stdin=canonical(request))
    if response["returncode"] != 0 or response["failure"]:
        raise EvidenceError("authenticated SSH agent failed: " + response["stderr"][-1000:])
    value = strict_json(response["stdout"])
    if value.get("nonce") != request["nonce"]:
        raise EvidenceError("remote response challenge mismatch")
    return value


def run_plan(plan: dict) -> dict:
    validate_plan(plan)
    nonce = secrets.token_hex(32)
    started = time.time_ns()
    probes = {}
    for name, host in plan["hosts"].items():
        probe = on_host(host, {"action": "probe", "nonce": nonce})
        if probe["machine_id_sha256"] != host["machine_id_sha256"]:
            raise EvidenceError("machine identity differs from enrolled inventory: " + name)
        if any(probe["source"][k] != plan["source"][k] for k in ("commit", "source_tree_sha256")):
            raise EvidenceError("candidate differs across hosts: " + name)
        probes[name] = probe
    results = []
    failed = False

    def work(step):
        try:
            return on_host(plan["hosts"][step["host"]],
                           {"action": "execute", "nonce": nonce, "step": step, "source": plan["source"]})
        except Exception as exc:
            return {"id": step["id"], "host": step["host"], "nonce": nonce,
                    "requirements": step.get("requirements", []), "status": "FAIL",
                    "failure": f"{type(exc).__name__}: {exc}"}

    for phase in plan["phases"]:
        if failed and not phase.get("always_run", False):
            results.extend({"id": step["id"], "host": step["host"],
                            "requirements": step.get("requirements", []),
                            "status": "NOT_RUN", "failure": "PREREQUISITE_FAILED"}
                           for step in phase["steps"])
            continue
        with ThreadPoolExecutor(max_workers=min(16, len(phase["steps"]))) as pool:
            observed = list(pool.map(work, phase["steps"]))
        results.extend(observed)
        failed |= any(result["status"] != "PASS" for result in observed)
    return {"schema": SCHEMA, "nonce": nonce, "profile": plan["profile"],
            "plan_sha256": digest(plan), "source": plan["source"],
            "started_ns": started, "finished_ns": time.time_ns(), "hosts": probes,
            "steps": results, "status": "FAIL" if failed else "PASS",
            "classification": "NATIVE_PLAN_EXECUTION",
            "release_qualified": False,
            "qualification_note": "Run the independent catalogue gate; a successful plan alone is not release qualification."}


def catalogue_ids(path: Path) -> set[str]:
    if path.suffix.lower() == ".csv":
        with path.open(newline="", encoding="utf-8") as stream:
            rows = list(csv.DictReader(stream))
    else:
        raw = read_json(path)
        rows = raw if isinstance(raw, list) else raw.get("rows", [])
    result = set()
    for row in rows:
        identity = row.get("test_id") or row.get("id") or row.get("requirement_id")
        if not isinstance(identity, str) or not identity or identity in result:
            raise EvidenceError("catalogue must have a distinct nonempty id for every acceptance row")
        result.add(identity)
    if not result:
        raise EvidenceError("empty acceptance catalogue")
    return result


def release_gate(policy: dict, catalogue: Path, receipts: list[dict], key: bytes) -> dict:
    if policy.get("schema") != "BTX-NATIVE-GATE/1":
        raise EvidenceError("unsupported release gate policy")
    if sha256_file(catalogue) != policy.get("catalogue_sha256"):
        raise EvidenceError("sealed catalogue digest differs")
    required = catalogue_ids(catalogue)
    if len(required) != policy.get("catalogue_rows"):
        raise EvidenceError("catalogue row count differs")
    if len(required) < 573:
        raise EvidenceError("release qualification requires at least the 573 sealed acceptance rows reported for this candidate")
    bindings = policy.get("row_plans", {})
    if set(bindings) != required or any(not isinstance(v, list) or not v or
                                       any(not HEX64.fullmatch(str(x)) for x in v) for v in bindings.values()):
        raise EvidenceError("every sealed catalogue row requires an independently pinned test-plan digest")
    required_profiles = set(policy.get("required_profiles", PROFILES))
    if required_profiles != set(PROFILES):
        raise EvidenceError("release gate must account for all 32 advertised profiles")
    now = time.time_ns()
    max_age = policy.get("max_age_seconds", 86400)
    if type(max_age) is not int or not 1 <= max_age <= 30 * 86400:
        raise EvidenceError("invalid receipt freshness bound")
    enrollment = policy.get("machine_enrollment", {})
    seen_nonces, covered, profiles = set(), set(), set()
    physical_hosts, gpu_ids, accepted = set(), set(), []
    rejected = []
    for envelope in receipts:
        try:
            body = verify_receipt(envelope, key)
            if body.get("schema") != SCHEMA or body.get("status") != "PASS":
                raise EvidenceError("receipt is not a passing native execution")
            if body.get("source") != policy.get("source"):
                raise EvidenceError("receipt belongs to another candidate")
            nonce = body.get("nonce")
            if not isinstance(nonce, str) or not HEX64.fullmatch(nonce) or nonce in seen_nonces:
                raise EvidenceError("duplicate or invalid challenge")
            finish = body.get("finished_ns", 0)
            if not 0 <= now - finish <= max_age * 1_000_000_000:
                raise EvidenceError("stale or future receipt")
            proof_hosts, proof_gpu, proof_npu = set(), set(), set()
            observed_systems, observed_compute = set(), set()
            for host in body.get("hosts", {}).values():
                if host.get("nonce") != nonce or any(host.get("source", {}).get(k) != policy["source"][k]
                                                    for k in ("commit", "source_tree_sha256")):
                    raise EvidenceError("host evidence binding differs")
                identity = host.get("machine_id_sha256")
                if identity not in enrollment or not enrollment[identity].get("physical_host_id"):
                    raise EvidenceError("machine has no independently enrolled physical host")
                proof_hosts.add(enrollment[identity]["physical_host_id"])
                observed_systems.add(host.get("system"))
                known_gpu = set(enrollment[identity].get("gpu_uuids", []))
                observed_gpu = {gpu["uuid"] for gpu in host.get("gpus", [])}
                if not observed_gpu <= known_gpu:
                    raise EvidenceError("observed GPU is not independently enrolled")
                proof_gpu.update(observed_gpu)
                observed_compute.update(str(gpu.get("compute_capability", "")) for gpu in host.get("gpus", []))
                observed_npu = {npu["serial_sha256"] for npu in host.get("npus", [])}
                if not observed_npu <= set(enrollment[identity].get("npu_serial_hashes", [])):
                    raise EvidenceError("observed Ascend board is not independently enrolled")
                proof_npu.update(observed_npu)
            rule = policy.get("profile_rules", {}).get(body.get("profile"))
            if not rule or body.get("plan_sha256") not in rule.get("plan_sha256", []):
                raise EvidenceError("profile plan has not been independently pinned")
            minimum_hosts, minimum_gpus = PROFILE_MINIMA.get(body.get("profile"), (1, 0))
            minimum_hosts = max(minimum_hosts, rule.get("min_physical_hosts", 1))
            minimum_gpus = max(minimum_gpus, rule.get("min_gpus", 0))
            if len(proof_hosts) < minimum_hosts or len(proof_gpu) < minimum_gpus:
                raise EvidenceError("insufficient independently enrolled hosts or GPUs")
            if body.get("profile") == "linux-ascend-deepinfer" and not proof_npu:
                raise EvidenceError("Ascend profile requires an observed independently enrolled NPU board")
            expected_os = {"macos-portable": "Darwin", "windows-portable": "Windows",
                           "linux-sm100-deepinfer": "Linux", "linux-ascend-deepinfer": "Linux"}.get(body.get("profile"))
            if expected_os and observed_systems != {expected_os}:
                raise EvidenceError("native operating system does not match the advertised profile")
            if body.get("profile") == "linux-sm100-deepinfer" and "10.0" not in observed_compute:
                raise EvidenceError("SM100 profile requires observed compute capability 10.0")
            rows = set()
            for step in body.get("steps", []):
                if step.get("status") != "PASS" or not step.get("checks") or step.get("returncode") != 0 or step.get("failure"):
                    raise EvidenceError("native step did not pass")
                if not all(item["passed"] for item in evaluate_assertions(strict_json(step["stdout"]), step["assertions"])):
                    raise EvidenceError("observed native outputs do not satisfy assertions")
                if step.get("nonce") != nonce:
                    raise EvidenceError("step challenge differs")
                if not step.get("inputs"):
                    raise EvidenceError("native binary inputs were not recorded")
                for row in step.get("requirements", []):
                    if row in required and body["plan_sha256"] in bindings[row]:
                        rows.add(row)
            if not rows:
                raise EvidenceError("receipt covers no pinned catalogue row")
            seen_nonces.add(nonce)
            covered.update(rows)
            profiles.add(body["profile"])
            physical_hosts.update(proof_hosts)
            gpu_ids.update(proof_gpu)
            accepted.append(body["plan_sha256"])
        except (EvidenceError, KeyError, TypeError) as exc:
            rejected.append(str(exc))
    missing_rows = sorted(required - covered)
    missing_profiles = sorted(required_profiles - profiles)
    qualified = not missing_rows and not missing_profiles and not rejected
    return {"schema": "BTX-NATIVE-GATE-RESULT/1", "source": policy.get("source"),
            "policy_sha256": digest(policy), "catalogue_sha256": sha256_file(catalogue),
            "qualified": qualified, "release_qualified": qualified,
            "required_rows": len(required), "covered_rows": len(covered),
            "missing_rows": missing_rows, "missing_profiles": missing_profiles,
            "enrolled_physical_hosts_observed": len(physical_hosts), "gpu_uuids_observed": len(gpu_ids),
            "accepted_plan_digests": accepted, "rejected_receipts": rejected,
            "authority": "operator-authenticated execution evidence under independently pinned policy",
            "limit": "This gate does not create a release tag or provide hardware-root attestation."}


def cli(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    key = sub.add_parser("init-key")
    key.add_argument("path", type=Path)
    probe = sub.add_parser("probe")
    probe.add_argument("--root", type=Path, required=True)
    probe.add_argument("--out", type=Path)
    sub.add_parser("agent")
    run = sub.add_parser("run")
    run.add_argument("--plan", type=Path, required=True)
    run.add_argument("--key-file", type=Path, required=True)
    run.add_argument("--out", type=Path, required=True)
    gate = sub.add_parser("gate")
    gate.add_argument("--policy", type=Path, required=True)
    gate.add_argument("--policy-sha256", required=True)
    gate.add_argument("--catalogue", type=Path, required=True)
    gate.add_argument("--receipt", type=Path, action="append", required=True)
    gate.add_argument("--key-file", type=Path, required=True)
    gate.add_argument("--out", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == "init-key":
            fd = os.open(args.path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "wb") as stream:
                stream.write(secrets.token_bytes(32))
            return 0
        if args.command == "agent":
            request = strict_json(sys.stdin.buffer.read(8 * 1024 * 1024 + 1))
            print(canonical(agent(request)).decode())
            return 0
        if args.command == "probe":
            result = machine_probe(args.root, secrets.token_hex(32))
            if args.out:
                atomic_json(args.out, result)
            else:
                print(json.dumps(result, indent=2))
            return 0
        if args.command == "run":
            plan = read_json(args.plan)
            for host in plan.get("hosts", {}).values():
                if host.get("transport") == "local" and args.out.resolve().is_relative_to(Path(host["root"]).resolve()):
                    raise EvidenceError("write receipts outside the source checkout to preserve the candidate digest")
            result = run_plan(plan)
            atomic_json(args.out, sign_receipt(result, load_key(args.key_file)))
            print(json.dumps({"status": result["status"], "receipt": str(args.out), "release_qualified": False}))
            return 0 if result["status"] == "PASS" else 1
        policy = read_json(args.policy)
        if digest(policy) != args.policy_sha256:
            raise EvidenceError("release policy digest differs from independent approval")
        result = release_gate(policy, args.catalogue, [read_json(p) for p in args.receipt], load_key(args.key_file))
        atomic_json(args.out, result)
        print(json.dumps(result, indent=2))
        return 0 if result["qualified"] else 1
    except (EvidenceError, OSError, KeyError, ValueError) as exc:
        print(json.dumps({"error": str(exc), "release_qualified": False}), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(cli())
