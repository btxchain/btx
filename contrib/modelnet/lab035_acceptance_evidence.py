#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""Record native evidence for every 0.35 acceptance case.

A passing suite is cited only when that suite executed the requirement.
Every other case is sent to the shipped btxd lab035 command. An
unimplemented method is FAIL. This script does not edit the sealed
specification catalogue, whose package checker requires the initial
NOT_RUN column.
"""

from __future__ import annotations

import csv
import hashlib
import json
import os
import shutil
import subprocess
import time
from pathlib import Path

TREE = Path(os.environ.get("BTX035_ROOT", Path(__file__).resolve().parents[3]))
REPO = Path(__file__).resolve().parents[2]
SPEC = TREE / "spec" / "BTX035_v1_1"
SPEC_CSV = SPEC / "planning" / "acceptance.csv"
SCHEMA = SPEC / "planning" / "evidence.schema.json"
BIN = Path(os.environ.get("BTX035_BIN", TREE / "builds" / "gcc13-release" / "bin"))
LOGS = TREE / "logs" / "acceptance-suites"
OUT = TREE / "evidence" / "native"
OPEN = TREE / "agent-control" / "OPEN_REQUIREMENTS.csv"
COMMIT = "0f36daafd42b4b921696df9d4f3de4baeff437c8"
ROOT_DATA = TREE / "test-data" / "acceptance-probe"
PY = os.environ.get("BTX035_PYTHON", str(TREE / "spec" / ".venv" / "bin" / "python"))

# Requirement -> (log stem, evidence class). The log must contain a clean run.
COVERED = {
    "ID-001": ("modelnet_035_identity_tests", "UNIT_NATIVE"),
    "ID-002": ("modelnet_035_identity_tests", "UNIT_NATIVE"),
    "ID-003": ("modelnet_035_identity_tests", "UNIT_NATIVE"),
    "ID-004": ("modelnet_035_identity_tests", "UNIT_NATIVE"),
    "REV-006": ("modelnet_035_identity_tests", "UNIT_NATIVE"),
    "ECON-001": ("modelnet_035_identity_tests", "UNIT_NATIVE"),
    "CORE-004": ("modelnet_035_identity_tests", "UNIT_NATIVE"),
    "WIRE-001": ("modelnet_035_codec_tests", "UNIT_NATIVE"),
    "WIRE-002": ("modelnet_035_codec_tests", "UNIT_NATIVE"),
    "REV-001": ("modelnet_035_surface_tests", "UNIT_NATIVE"),
    "MIG-003": ("modelnet_035_surface_tests", "UNIT_NATIVE"),
    "NET-001": ("modelnet_035_transport_tests", "UNIT_NATIVE"),
    "NET-002": ("modelnet_035_session_tests", "UNIT_NATIVE"),
    "REV-007": ("modelnet_035_session_tests", "UNIT_NATIVE"),
    "GIT-002": ("modelnet_035_git_tests", "UNIT_NATIVE"),
    "GIT-003": ("modelnet_035_git_tests", "UNIT_NATIVE"),
    "GIT-004": ("modelnet_035_git_tests", "UNIT_NATIVE"),
    "SCM-001": ("modelnet_035_workspace_git_tests", "UNIT_NATIVE"),
    "SCM-002": ("modelnet_035_workspace_tests", "UNIT_NATIVE"),
    "RES-001": ("modelnet_035_research_tests", "UNIT_NATIVE"),
    "RES-002": ("modelnet_035_research_tests", "UNIT_NATIVE"),
    "RES-003": ("modelnet_035_research_tests", "UNIT_NATIVE"),
    "RES-005": ("modelnet_035_research_tests", "UNIT_NATIVE"),
    "RES-004": ("modelnet_035_remaining_tests", "UNIT_NATIVE"),
    "RUN-004": ("modelnet_035_remaining_tests", "UNIT_NATIVE"),
    "REV-002": ("modelnet_035_remaining_tests", "UNIT_NATIVE"),
    "NET-004": ("modelnet_035_discovery_tests", "UNIT_NATIVE"),
    "VER-002": ("modelnet_035_training_tests", "UNIT_NATIVE"),
    "VER-003": ("modelnet_035_admission_tests", "UNIT_NATIVE"),
    "ADM-001": ("modelnet_035_admission_tests", "UNIT_NATIVE"),
    "ADM-003": ("modelnet_035_admission_tests", "UNIT_NATIVE"),
    "RUN-001": ("modelnet_035_runtime_tests", "UNIT_NATIVE"),
    "RUN-003": ("modelnet_035_runtime_tests", "UNIT_NATIVE"),
    "WAN-001": ("modelnet_035_wan_tests", "UNIT_NATIVE"),
    "QA-002": ("validate_package", "PACKAGE_REFERENCE"),
    "API-001": ("modelnet_035_lab_api_tests", "UNIT_NATIVE"),
    "API-002": ("modelnet_035_lab_api_tests", "UNIT_NATIVE"),
    "WAN-002": ("modelnet_035_wan_endpoint_tests", "UNIT_NATIVE"),
    "WAN-003": ("modelnet_035_wan_endpoint_tests", "UNIT_NATIVE"),
    "WAN-004": ("modelnet_035_wan_endpoint_tests", "UNIT_NATIVE"),
    "WAN-005": ("modelnet_035_wan_endpoint_tests", "UNIT_NATIVE"),
    "REV-012": ("modelnet_035_wan_endpoint_tests", "UNIT_NATIVE"),
    "REV-013": ("modelnet_035_wan_endpoint_tests", "UNIT_NATIVE"),
    "STORE-001": ("modelnet_035_store_tests", "UNIT_NATIVE"),
    "STORE-002": ("modelnet_035_store_tests", "UNIT_NATIVE"),
    "STORE-003": ("modelnet_035_store_tests", "UNIT_NATIVE"),
    "REV-014": ("modelnet_035_store_tests", "UNIT_NATIVE"),
    "ART-001": ("modelnet_035_research_gate_tests", "UNIT_NATIVE"),
    "ART-002": ("modelnet_035_research_gate_tests", "UNIT_NATIVE"),
    "ART-003": ("modelnet_035_research_gate_tests", "UNIT_NATIVE"),
    "VER-001": ("modelnet_035_research_gate_tests", "UNIT_NATIVE"),
    "VER-004": ("modelnet_035_research_gate_tests", "UNIT_NATIVE"),
    "RSI-001": ("modelnet_035_research_gate_tests", "UNIT_NATIVE"),
    "RSI-002": ("modelnet_035_research_gate_tests", "UNIT_NATIVE"),
    "RSI-003": ("modelnet_035_research_gate_tests", "UNIT_NATIVE"),
    "INC-001": ("modelnet_035_research_gate_tests", "UNIT_NATIVE"),
    "INC-002": ("modelnet_035_research_gate_tests", "UNIT_NATIVE"),
    "REV-005": ("modelnet_035_research_gate_tests", "UNIT_NATIVE"),
    "REV-009": ("modelnet_035_research_gate_tests", "UNIT_NATIVE"),
    "REV-010": ("modelnet_035_research_gate_tests", "UNIT_NATIVE"),
    "REV-011": ("modelnet_035_research_gate_tests", "UNIT_NATIVE"),
    "REV-015": ("modelnet_035_research_gate_tests", "UNIT_NATIVE"),
    "BUILD-001": ("modelnet_035_release_tests", "UNIT_NATIVE"),
    "BUILD-003": ("modelnet_035_release_tests", "UNIT_NATIVE"),
    "MIG-001": ("modelnet_035_release_tests", "UNIT_NATIVE"),
    "MIG-002": ("modelnet_035_release_tests", "UNIT_NATIVE"),
    "MDT-001": ("modelnet_035_release_tests", "UNIT_NATIVE"),
    "MDT-002": ("modelnet_035_release_tests", "UNIT_NATIVE"),
    "MDT-003": ("modelnet_035_release_tests", "UNIT_NATIVE"),
    "MDT-004": ("modelnet_035_release_tests", "UNIT_NATIVE"),
    "REALM-001": ("modelnet_035_release_tests", "UNIT_NATIVE"),
    "REALM-002": ("modelnet_035_release_tests", "UNIT_NATIVE"),
    "REALM-003": ("modelnet_035_release_tests", "UNIT_NATIVE"),
    "SCM-003": ("modelnet_035_release_tests", "UNIT_NATIVE"),
    "SCM-004": ("modelnet_035_release_tests", "UNIT_NATIVE"),
    "DEV-001": ("modelnet_035_release_tests", "UNIT_NATIVE"),
    "DEV-002": ("modelnet_035_release_tests", "UNIT_NATIVE"),
    "QA-003": ("modelnet_035_release_tests", "UNIT_NATIVE"),
    "NET-003": ("modelnet_035_release_tests", "UNIT_NATIVE"),
    "ENT-001": ("modelnet_035_gateway_tests", "UNIT_NATIVE"),
    "ENT-002": ("modelnet_035_gateway_tests", "UNIT_NATIVE"),
    "ENT-003": ("modelnet_035_gateway_tests", "UNIT_NATIVE"),
    "ADM-002": ("modelnet_035_gateway_tests", "UNIT_NATIVE"),
    "API-003": ("test_lab035_cli", "INTEGRATION_NATIVE"),
    "API-004": ("test_lab035_cli", "INTEGRATION_NATIVE"),
    "ARCH-001": ("modelnet_035_assurance_tests", "UNIT_NATIVE"),
    "ARCH-002": ("modelnet_035_assurance_tests", "UNIT_NATIVE"),
    "ARCH-003": ("modelnet_035_assurance_tests", "UNIT_NATIVE"),
    "ARCH-004": ("modelnet_035_assurance_tests", "UNIT_NATIVE"),
    "SEC-001": ("modelnet_035_assurance_tests", "UNIT_NATIVE"),
    "SEC-002": ("modelnet_035_assurance_tests", "UNIT_NATIVE"),
    "SEC-003": ("modelnet_035_assurance_tests", "UNIT_NATIVE"),
    "SEC-004": ("modelnet_035_assurance_tests", "UNIT_NATIVE"),
    "CORE-002": ("modelnet_035_assurance_tests", "UNIT_NATIVE"),
    "CORE-003": ("modelnet_035_assurance_tests", "UNIT_NATIVE"),
    "CORE-005": ("modelnet_035_assurance_tests", "UNIT_NATIVE"),
    "RUN-002": ("modelnet_035_assurance_tests", "UNIT_NATIVE"),
    "ECON-002": ("modelnet_035_assurance_tests", "UNIT_NATIVE"),
    "WIRE-003": ("modelnet_035_wire_limit_tests", "UNIT_NATIVE"),
    "WIRE-004": ("modelnet_035_wire_limit_tests", "UNIT_NATIVE"),
    "REV-003": ("modelnet_035_wire_limit_tests", "UNIT_NATIVE"),
    "REV-004": ("modelnet_035_wire_limit_tests", "UNIT_NATIVE"),
    "E2E-001": ("modelnet_035_e2e_gate_tests", "UNIT_NATIVE"),
    "E2E-002": ("modelnet_035_e2e_gate_tests", "UNIT_NATIVE"),
    "E2E-003": ("modelnet_035_e2e_gate_tests", "UNIT_NATIVE"),
    "E2E-004": ("modelnet_035_e2e_gate_tests", "UNIT_NATIVE"),
    "E2E-005": ("modelnet_035_e2e_gate_tests", "UNIT_NATIVE"),
    "E2E-006": ("modelnet_035_e2e_gate_tests", "UNIT_NATIVE"),
    "GIT-001": ("test_git_remote_btx", "INTEGRATION_NATIVE"),
    "GIT-005": ("test_git_lfs_btx", "INTEGRATION_NATIVE"),
    "REV-008": ("test_git_remote_btx", "INTEGRATION_NATIVE"),
}


def sha384_file(path: Path) -> str:
    h = hashlib.sha384()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def dirty_hash() -> str:
    proc = subprocess.run(
        ["git", "-C", str(REPO), "status", "--porcelain"],
        check=True,
        stdout=subprocess.PIPE,
        text=True,
    )
    return hashlib.sha384(proc.stdout.encode()).hexdigest()


def passed_log(stem: str) -> bool:
    path = LOGS / f"{stem}.txt"
    if not path.exists():
        return False
    text = path.read_text(errors="replace")
    if stem == "validate_package":
        return '"failed": 0' in text and '"passed": 418' in text
    if stem.startswith("test_git_"):
        return text.strip().endswith("PASS") and "FAIL" not in text
    if stem == "test_lab035_cli":
        return text.rstrip().endswith("OK") and "FAILED" not in text
    return "No errors detected" in text and "failures are detected" not in text


def row_evidence(case, state, evidence_class, command, exit_code, logs, artifacts, binary, dirty, start, end):
    return {
        "case_id": case["case_id"],
        "requirement_id": case["requirement_id"],
        "commit": COMMIT,
        "dirty_tree_hash": dirty,
        "binary_sha384": binary,
        "environment_ref": "linux-x86_64",
        "reviewer_id": "local-native-runner",
        "state": state,
        "evidence_class": evidence_class,
        "command": command,
        "start_ms": start,
        "end_ms": end,
        "exit_code": exit_code,
        "logs": logs,
        "resulting_artifact_ids": artifacts,
    }


def start_node():
    if ROOT_DATA.exists():
        shutil.rmtree(ROOT_DATA)
    ROOT_DATA.mkdir(parents=True)
    datadir = ROOT_DATA / "node"
    datadir.mkdir()
    proc = subprocess.Popen(
        [
            str(BIN / "btxd"),
            "-regtest",
            f"-datadir={datadir}",
            "-port=29310",
            "-rpcport=29311",
            "-rpcbind=127.0.0.1",
            "-rpcallowip=127.0.0.1",
            "-bind=127.0.0.1",
            "-listen=1",
            "-server=1",
            "-dnsseed=0",
            "-fixedseeds=0",
            "-daemon=0",
            "-regtestmatmulbindingheight=2147483647",
            "-regtestmatmulproductdigestheight=2147483647",
            "-regtestmatmulv4height=2147483647",
            "-regtestmatmulrequireproductpayload=0",
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    deadline = time.time() + 40
    while time.time() < deadline:
        if proc.poll() is not None:
            raise RuntimeError(f"probe node exited {proc.returncode}")
        ping = subprocess.run(
            [str(BIN / "btx-cli"), "-regtest", f"-datadir={datadir}", "-rpcport=29311", "getblockchaininfo"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
        )
        if ping.returncode == 0:
            return datadir, proc
        time.sleep(0.2)
    raise RuntimeError("probe node did not answer")


def stop_node(datadir: Path, proc: subprocess.Popen) -> None:
    subprocess.run(
        [str(BIN / "btx-cli"), "-regtest", f"-datadir={datadir}", "-rpcport=29311", "stop"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=False,
    )
    try:
        proc.wait(timeout=30)
    except subprocess.TimeoutExpired:
        proc.kill()
    shutil.rmtree(ROOT_DATA, ignore_errors=True)


def main() -> int:
    cases = list(csv.DictReader(SPEC_CSV.open()))
    binary = sha384_file(BIN / "test_btx")
    dirty = dirty_hash()
    now = str(int(time.time() * 1000))
    OUT.mkdir(parents=True, exist_ok=True)
    results = []
    needs_probe = []
    for case in cases:
        req = case["requirement_id"]
        if req in ("CORE-001", "DEV-003", "QA-001", "REV-016", "BUILD-002"):
            continue
        covered = COVERED.get(req)
        if covered and passed_log(covered[0]):
            stem, kind = covered
            if stem.startswith("test_git_") or stem == "test_lab035_cli":
                command = ["python3", str(REPO / "contrib" / "modelnet" / f"{stem}.py")]
            elif kind == "UNIT_NATIVE":
                command = [str(BIN / "test_btx"), f"--run_test={stem}"]
            else:
                command = [PY, str(SPEC / "tools" / "validate_package.py")]
            results.append(row_evidence(
                case, "PASS", kind, command, 0,
                [str(LOGS / f"{stem}.txt")],
                [stem], binary, dirty, now, now,
            ))
        else:
            needs_probe.append(case)

    datadir, proc = start_node()
    try:
        for case in needs_probe:
            command = [str(BIN / "btx-cli"), "-regtest", f"-datadir={datadir}", "-rpcport=29311",
                       "lab035", "lab.info", "{}"]
            start = str(int(time.time() * 1000))
            run = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=False)
            end = str(int(time.time() * 1000))
            blob = run.stdout + run.stderr
            # A live lab.info response shows the daemon is running the lab API.
            # It does not prove this requirement's behavior, so the row stays FAIL.
            state = "FAIL"
            if "BTX035_NOT_IMPLEMENTED" in blob:
                note = blob[-500:]
            else:
                note = "requirement behavior is not proven by lab.info: " + blob[-400:]
            results.append(row_evidence(
                case, state, "INTEGRATION_NATIVE", command, 1,
                [note], ["lab.info"], binary, dirty, start, end,
            ))
    finally:
        stop_node(datadir, proc)

    any_not_pass = any(item["state"] != "PASS" for item in results)
    catalogue = subprocess.run(
        [PY, "-c",
         "import csv,sys; rows=list(csv.DictReader(open(sys.argv[1])));"
         "raise SystemExit(0 if {r['state'] for r in rows}=={'NOT_RUN'} else 1)",
         str(SPEC_CSV)],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=False,
    )
    for case in cases:
        req = case["requirement_id"]
        if req == "BUILD-002":
            release_log = LOGS / "modelnet_035_release_tests.txt"
            release_ok = passed_log("modelnet_035_release_tests")
            results.append(row_evidence(
                case, "BLOCKED" if release_ok else "FAIL", "UNIT_NATIVE",
                [str(BIN / "test_btx"), "--run_test=modelnet_035_release_tests"],
                0 if release_ok else 1,
                ["Windows x86-64 has no runner; PlatformMatrix reports BLOCKED" if release_ok else "release suite did not pass"],
                ["modelnet_035_release_tests"], binary, dirty, now, now,
            ))
        elif req == "REV-016":
            results.append(row_evidence(
                case, "PASS" if catalogue.returncode == 0 else "FAIL", "PACKAGE_REFERENCE",
                catalogue.args, catalogue.returncode,
                ["sealed catalogue states remain NOT_RUN" if catalogue.returncode == 0 else catalogue.stderr],
                ["planning/acceptance.csv"], binary, dirty, now, now,
            ))
        elif req == "CORE-001":
            gate_ok = passed_log("modelnet_035_remaining_tests") and not any_not_pass
            results.append(row_evidence(
                case, "PASS" if gate_ok else "FAIL", "UNIT_NATIVE",
                [str(BIN / "test_btx"), "--run_test=modelnet_035_remaining_tests"],
                0 if gate_ok else 1,
                ["release gate rejects unresolved, schema-only, and NOT_RUN rows; Windows stays BLOCKED so the release is not qualified"
                 if gate_ok else "remaining suite or a mandatory case failed"],
                ["modelnet_035_remaining_tests"], binary, dirty, now, now,
            ))
        elif req == "DEV-003":
            journeys_ok = (
                passed_log("modelnet_035_remaining_tests")
                and passed_log("modelnet_035_e2e_gate_tests")
                and passed_log("modelnet_035_journey_tests")
                and not any_not_pass
            )
            results.append(row_evidence(
                case, "PASS" if journeys_ok else "FAIL", "INTEGRATION_NATIVE",
                [str(BIN / "test_btx"), "--run_test=modelnet_035_remaining_tests"],
                0 if journeys_ok else 1,
                ["both journey suites ran in test_btx; completion stays false while a mandatory row is not PASS"
                 if journeys_ok else "a journey suite or mandatory case failed"],
                ["modelnet_035_e2e_gate_tests", "modelnet_035_journey_tests", "modelnet_035_remaining_tests"],
                binary, dirty, now, now,
            ))

    # QA-001 is the evidence shape itself. Validate after the other rows exist,
    # then append QA-001 and validate again.
    schema = json.loads(SCHEMA.read_text())
    from jsonschema import Draft202012Validator
    validator = Draft202012Validator(schema)
    shape = subprocess.run(
        [PY, "-c",
         "import json,sys; from jsonschema import Draft202012Validator; "
         "Draft202012Validator.check_schema(json.load(open(sys.argv[1])));",
         str(SCHEMA)],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=False,
    )
    for case in cases:
        if case["requirement_id"] != "QA-001":
            continue
        results.append(row_evidence(
            case, "PASS" if shape.returncode == 0 else "FAIL", "PACKAGE_REFERENCE",
            shape.args, shape.returncode,
            [shape.stderr or "evidence schema accepted by Draft202012Validator"],
            ["planning/evidence.schema.json"], binary, dirty, now, now,
        ))
    errors = []
    for item in results:
        errors.extend(validator.iter_errors(item))
    if errors:
        for item in results:
            if item["requirement_id"] == "QA-001":
                item["state"] = "FAIL"
                item["exit_code"] = 1
                item["logs"] = [errors[0].message]
        errors = []
        for item in results:
            errors.extend(validator.iter_errors(item))
        if errors:
            raise SystemExit(errors[0].message)

    for item in results:
        (OUT / f"{item['case_id']}.json").write_text(json.dumps(item, indent=2) + "\n")
    counts = {}
    for item in results:
        counts[item["state"]] = counts.get(item["state"], 0) + 1
    summary = {"commit": COMMIT, "cases": len(results), "counts": counts}
    (OUT / "SUMMARY.json").write_text(json.dumps(summary, indent=2) + "\n")

    open_rows = list(csv.DictReader(OPEN.open()))
    by_case = {item["case_id"]: item for item in results}
    for row in open_rows:
        item = by_case[row["case_id"]]
        row["state"] = item["state"]
        row["source_commit"] = COMMIT
        row["evidence"] = str(OUT / f"{item['case_id']}.json")
        row["blocker"] = "" if item["state"] == "PASS" else item["logs"][0][:180]
    with OPEN.open("w", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=list(open_rows[0].keys()))
        writer.writeheader()
        writer.writerows(open_rows)
    print(json.dumps(summary))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
