#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""Run the hosted shielded_v2 validation suite on disposable infrastructure."""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import shlex
import subprocess
import sys
import tarfile
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


REPO_ROOT = Path(__file__).resolve().parents[1]
REMOTE_ROOT = "/root/btx-remote-validation"
REMOTE_ARTIFACT_DIR = f"{REMOTE_ROOT}/artifacts"
REMOTE_BUILD_DIR = f"{REMOTE_ROOT}/build-validation"
REMOTE_SOURCE_ARCHIVE = "/root/btx-remote-validation-source.tar.gz"
REMOTE_ARTIFACT_BUNDLE = "/root/btx-remote-validation-artifacts.tar.gz"
REMOTE_REPORT_DIR = f"{REMOTE_ARTIFACT_DIR}/reports"
BUILD_TARGETS = [
    "btxd",
    "bitcoin-cli",
    "generate_shielded_v2_adversarial_proof_corpus",
    "generate_shielded_relay_fixture_tx",
    "generate_shielded_v2_send_runtime_report",
    "generate_shielded_ingress_proof_runtime_report",
    "generate_shielded_v2_egress_runtime_report",
    "generate_shielded_v2_netting_capacity_report",
    "generate_shielded_v2_chain_growth_projection_report",
]


def load_m22_module():
    script_path = REPO_ROOT / "scripts" / "m22_remote_shielded_redteam_campaign.py"
    spec = importlib.util.spec_from_file_location("m22_remote_shielded_redteam_campaign", script_path)
    if spec is None or spec.loader is None:
        raise ImportError(f"unable to load m22 helper module: {script_path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


M22_REMOTE_MODULE = load_m22_module()


def utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def shell_quote(value: str | Path) -> str:
    return shlex.quote(str(value))


def load_json_if_present(path: Path) -> dict[str, Any] | None:
    if not path.is_file():
        return None
    return json.loads(path.read_text(encoding="utf-8"))


def count_corpus_variants(payload: Any) -> int | None:
    if isinstance(payload, dict):
        variants = payload.get("variants")
        if isinstance(variants, list):
            return len(variants)
        cases = payload.get("cases")
        if isinstance(cases, list):
            return len(cases)
    if isinstance(payload, list):
        return len(payload)
    return None


def add_step_id(step: dict[str, Any], step_id: str) -> dict[str, Any]:
    step = dict(step)
    step["id"] = step_id
    return step


def record_step(manifest: dict[str, Any], output_dir: Path, step: dict[str, Any]) -> None:
    manifest["steps"].append(step)
    M22_REMOTE_MODULE.persist_manifest(output_dir, manifest)


def scenario_tps(max_transactions_per_block: int | None, block_interval_seconds: int) -> float | None:
    if max_transactions_per_block is None:
        return None
    return round(max_transactions_per_block / block_interval_seconds, 3)


def summarize_send_report(report: dict[str, Any], block_interval_seconds: int) -> list[dict[str, Any]]:
    summary: list[dict[str, Any]] = []
    for scenario in report.get("scenarios", []):
        tx_shape = scenario.get("tx_shape", {})
        block_capacity = scenario.get("block_capacity", {})
        summary.append(
            {
                "label": f"{scenario.get('spend_count')}x{scenario.get('output_count')}",
                "serialized_size_bytes": tx_shape.get("serialized_size_bytes"),
                "proof_payload_bytes": tx_shape.get("proof_payload_bytes"),
                "binding_limit": block_capacity.get("binding_limit"),
                "max_transactions_per_block": block_capacity.get("max_transactions_per_block"),
                "estimated_tps": scenario_tps(
                    block_capacity.get("max_transactions_per_block"),
                    block_interval_seconds,
                ),
                "within_standard_policy_weight": scenario.get("relay_policy", {}).get("within_standard_policy_weight"),
            }
        )
    return summary


def summarize_ingress_runtime(report: dict[str, Any], block_interval_seconds: int) -> dict[str, Any]:
    scenario = report.get("scenario", {})
    tx_shape = scenario.get("tx_shape", {})
    block_capacity = scenario.get("block_capacity", {})
    return {
        "leaf_count": scenario.get("ingress_leaf_count"),
        "serialized_size_bytes": tx_shape.get("serialized_size_bytes"),
        "proof_payload_bytes": tx_shape.get("proof_payload_size"),
        "binding_limit": block_capacity.get("binding_limit"),
        "max_transactions_per_block": block_capacity.get("max_transactions_per_block"),
        "estimated_tps": scenario_tps(block_capacity.get("max_transactions_per_block"), block_interval_seconds),
        "max_ingress_leaves_per_block": block_capacity.get("max_ingress_leaves_per_block"),
        "estimated_leaf_tps": (
            round(block_capacity["max_ingress_leaves_per_block"] / block_interval_seconds, 3)
            if isinstance(block_capacity.get("max_ingress_leaves_per_block"), int)
            else None
        ),
        "within_standard_policy_weight": scenario.get("relay_policy", {}).get("within_standard_policy_weight"),
    }


def summarize_ingress_capacity(report: dict[str, Any], block_interval_seconds: int) -> dict[str, Any]:
    bands = report.get("bands", [])
    highest_leaf = report.get("boundary", {}).get("highest_successful_leaf_count")
    selected = next((band for band in bands if band.get("leaf_count") == highest_leaf), bands[-1] if bands else {})
    return {
        "highest_successful_leaf_count": highest_leaf,
        "highest_successful_proof_payload_size": report.get("boundary", {}).get("highest_successful_proof_payload_size"),
        "binding_limit": selected.get("binding_limit"),
        "max_transactions_per_block": selected.get("max_transactions_per_block"),
        "estimated_tps": scenario_tps(selected.get("max_transactions_per_block"), block_interval_seconds),
        "max_ingress_leaves_per_block": selected.get("max_ingress_leaves_per_block"),
        "estimated_leaf_tps": (
            round(selected["max_ingress_leaves_per_block"] / block_interval_seconds, 3)
            if isinstance(selected.get("max_ingress_leaves_per_block"), int)
            else None
        ),
        "within_standard_policy_weight": selected.get("within_standard_policy_weight"),
    }


def summarize_egress_report(report: dict[str, Any], block_interval_seconds: int) -> list[dict[str, Any]]:
    summary: list[dict[str, Any]] = []
    for scenario in report.get("scenarios", []):
        tx_shape = scenario.get("tx_shape", {})
        block_capacity = scenario.get("block_capacity", {})
        summary.append(
            {
                "label": f"{scenario.get('output_count')}x{scenario.get('outputs_per_chunk')}",
                "serialized_size_bytes": tx_shape.get("serialized_size_bytes"),
                "proof_payload_bytes": tx_shape.get("proof_payload_bytes"),
                "binding_limit": block_capacity.get("binding_limit"),
                "max_transactions_per_block": block_capacity.get("max_transactions_per_block"),
                "estimated_tps": scenario_tps(
                    block_capacity.get("max_transactions_per_block"),
                    block_interval_seconds,
                ),
                "max_output_notes_per_block": block_capacity.get("max_output_notes_per_block"),
                "estimated_output_tps": (
                    round(block_capacity["max_output_notes_per_block"] / block_interval_seconds, 3)
                    if isinstance(block_capacity.get("max_output_notes_per_block"), int)
                    else None
                ),
                "is_standard_tx": scenario.get("relay_policy", {}).get("is_standard_tx"),
            }
        )
    return summary


def summarize_netting_report(report: dict[str, Any], block_interval_seconds: int) -> list[dict[str, Any]]:
    summary: list[dict[str, Any]] = []
    for scenario in report.get("scenarios", []):
        peak_window = scenario.get("peak_window", {})
        rebalance = peak_window.get("representative_rebalance_tx", {})
        block_capacity = rebalance.get("block_capacity", {})
        summary.append(
            {
                "label": scenario.get("label"),
                "achieved_netting_bps": peak_window.get("achieved_netting_bps"),
                "effective_capacity_multiplier_milli": peak_window.get("effective_capacity_multiplier_milli"),
                "representative_rebalance_size_bytes": rebalance.get("serialized_size_bytes"),
                "representative_rebalance_proof_payload_bytes": rebalance.get("proof_payload_bytes"),
                "binding_limit": block_capacity.get("binding_limit"),
                "max_transactions_per_block": block_capacity.get("max_transactions_per_block"),
                "estimated_tps": scenario_tps(
                    block_capacity.get("max_transactions_per_block"),
                    block_interval_seconds,
                ),
            }
        )
    return summary


def summarize_chain_growth(report: dict[str, Any]) -> dict[str, Any]:
    workload = next(
        (item for item in report.get("workloads", []) if item.get("label") == "1b_year_1pct_boundary"),
        {},
    )
    block_limits: dict[str, Any] = {}
    for projection in workload.get("block_limit_projections", []):
        capacity = projection.get("capacity_at_cadence", {})
        block_limits[projection.get("block_limit", "unknown")] = {
            "feasible_at_cadence": projection.get("feasible_at_cadence"),
            "binding_limit": capacity.get("binding_limit"),
            "max_boundary_actions_per_day_at_cadence": capacity.get("max_boundary_actions_per_day_at_cadence"),
            "max_boundary_actions_per_year_at_cadence": capacity.get("max_boundary_actions_per_year_at_cadence"),
        }
    return {
        "block_interval_seconds": report.get("cadence", {}).get("block_interval_seconds"),
        "workload": workload.get("label"),
        "boundary_actions_per_block_at_cadence": workload.get("boundary_actions_per_block_at_cadence"),
        "block_limits": block_limits,
    }


def summarize_suite(
    m19_artifact: dict[str, Any] | None,
    m21_artifact: dict[str, Any] | None,
    m21_inner_artifact: dict[str, Any] | None,
    m21_corpus: Any,
    send_report: dict[str, Any] | None,
    ingress_native_report: dict[str, Any] | None,
    ingress_receipt_report: dict[str, Any] | None,
    egress_report: dict[str, Any] | None,
    netting_report: dict[str, Any] | None,
    chain_growth_report: dict[str, Any] | None,
) -> dict[str, Any]:
    block_interval_seconds = int(chain_growth_report.get("cadence", {}).get("block_interval_seconds", 90)) if chain_growth_report else 90
    m19_launch = {} if m19_artifact is None else m19_artifact.get("launch_rehearsal", {})
    return {
        "simulated_testnet": {
            "overall_status": None if m19_artifact is None else m19_launch.get("overall_status", m19_artifact.get("overall_status")),
            "runtime_seconds": None if m19_artifact is None else m19_launch.get("runtime_seconds", m19_artifact.get("runtime_seconds")),
            "final_height": None if m19_artifact is None else m19_launch.get("final_height", m19_artifact.get("final_height")),
            "bestblockhash": None if m19_artifact is None else m19_launch.get("bestblockhash", m19_artifact.get("bestblockhash")),
        },
        "security_readiness": {
            "overall_status": None if m21_artifact is None else m21_artifact.get("overall_status"),
            "wrapper_runtime_seconds": None if m21_artifact is None else next(
                (
                    step.get("runtime_seconds")
                    for step in m21_artifact.get("steps", [])
                    if step.get("id") == "feature_shielded_v2_proof_redteam_campaign"
                ),
                None,
            ),
            "inner_runtime_seconds": None if m21_inner_artifact is None else m21_inner_artifact.get("runtime_seconds"),
            "variant_count": count_corpus_variants(m21_corpus),
            "teardown_confirmed": None if m21_artifact is None else m21_artifact.get("teardown_confirmed"),
        },
        "proof_size_and_tps": {
            "direct_send": [] if send_report is None else summarize_send_report(send_report, block_interval_seconds),
            "ingress_native": None if ingress_native_report is None else summarize_ingress_runtime(
                ingress_native_report,
                block_interval_seconds,
            ),
            "ingress_receipt": None if ingress_receipt_report is None else summarize_ingress_capacity(
                ingress_receipt_report,
                block_interval_seconds,
            ),
            "egress_batch": [] if egress_report is None else summarize_egress_report(egress_report, block_interval_seconds),
            "netting": [] if netting_report is None else summarize_netting_report(netting_report, block_interval_seconds),
            "chain_growth": None if chain_growth_report is None else summarize_chain_growth(chain_growth_report),
        },
    }


def artifact_entry(path: Path) -> dict[str, Any]:
    return {
        "path": str(path),
        "sha256": sha256_file(path),
        "bytes": path.stat().st_size,
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run the hosted shielded_v2 validation suite on a disposable DigitalOcean droplet."
    )
    parser.add_argument(
        "--output-dir",
        default=str(REPO_ROOT / ".btx-validation" / "m26-remote-shielded-validation"),
        help="Local output directory for manifests, logs, and fetched artifacts",
    )
    parser.add_argument("--region", default="sfo3", help="DigitalOcean region slug")
    parser.add_argument("--size", default="s-2vcpu-4gb-amd", help="DigitalOcean droplet size slug")
    parser.add_argument("--image", default="ubuntu-24-04-x64", help="DigitalOcean image slug")
    parser.add_argument("--ssh-key-id", type=int, default=54710021, help="DigitalOcean SSH key id")
    parser.add_argument(
        "--ssh-private-key",
        default=str(Path.home() / ".ssh" / "id_ed25519"),
        help="Local private key matching the DO SSH key id",
    )
    parser.add_argument(
        "--admin-cidr",
        default=None,
        help="CIDR allowed to SSH to the droplet; default auto-detects the current public IPv4 /32",
    )
    parser.add_argument("--build-jobs", type=int, default=2, help="Remote cmake --build parallelism")
    parser.add_argument("--create-timeout-seconds", type=int, default=600)
    parser.add_argument("--ssh-timeout-seconds", type=int, default=600)
    parser.add_argument("--install-timeout-seconds", type=int, default=1800)
    parser.add_argument("--build-timeout-seconds", type=int, default=5400)
    parser.add_argument("--launch-timeout-seconds", type=int, default=3600)
    parser.add_argument("--redteam-timeout-seconds", type=int, default=3600)
    parser.add_argument("--report-timeout-seconds", type=int, default=3600)
    parser.add_argument("--portseed", type=int, default=36000)
    parser.add_argument(
        "--do-token-file",
        default=str(M22_REMOTE_MODULE.default_do_token_file()),
        help="DigitalOcean API token file; defaults to the repo-adjacent infra key path when present",
    )
    parser.add_argument("--send-scenarios", default="1x2,2x2,2x4")
    parser.add_argument("--ingress-native-leaf-count", type=int, default=4)
    parser.add_argument("--ingress-receipt-leaf-counts", default="100,1000,5000,10000")
    parser.add_argument("--egress-scenarios", default="32x32,1300x32,5000x32")
    parser.add_argument("--netting-scenarios", default="2x50,8x80,32x95,64x99")
    parser.add_argument("--chain-block-sizes-mb", default="12,24,32")
    parser.add_argument("--keep-droplet", action="store_true", help="Do not delete the droplet/firewall on exit")
    parser.add_argument("--dry-run", action="store_true", help="Write a dry-run manifest without creating remote resources")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    output_dir = Path(args.output_dir).resolve()
    logs_dir = output_dir / "logs"
    artifacts_dir = output_dir / "artifacts"
    logs_dir.mkdir(parents=True, exist_ok=True)
    artifacts_dir.mkdir(parents=True, exist_ok=True)

    run_name = datetime.now(timezone.utc).strftime("btx-shielded-suite-%Y%m%d-%H%M%S")
    firewall_name = f"{run_name}-fw"
    manifest: dict[str, Any] = {
        "generated_at": utc_now(),
        "overall_status": "fail",
        "configuration": {
            "region": args.region,
            "size": args.size,
            "image": args.image,
            "ssh_key_id": args.ssh_key_id,
            "build_jobs": args.build_jobs,
            "portseed": args.portseed,
            "keep_droplet": args.keep_droplet,
            "send_scenarios": args.send_scenarios,
            "ingress_native_leaf_count": args.ingress_native_leaf_count,
            "ingress_receipt_leaf_counts": args.ingress_receipt_leaf_counts,
            "egress_scenarios": args.egress_scenarios,
            "netting_scenarios": args.netting_scenarios,
            "chain_block_sizes_mb": args.chain_block_sizes_mb,
        },
        "planned_suite": [
            "m19_reset_launch_rehearsal",
            "m21_shielded_redteam_campaign",
            "send_runtime_report",
            "ingress_native_runtime_report",
            "ingress_receipt_capacity_report",
            "egress_runtime_report",
            "netting_capacity_report",
            "chain_growth_projection_report",
        ],
        "resources": {},
        "steps": [],
        "artifacts": {},
        "validation_summary": {},
        "teardown": {
            "droplet_deleted": False,
            "firewall_deleted": False,
        },
    }
    M22_REMOTE_MODULE.persist_manifest(output_dir, manifest)

    if args.dry_run:
        manifest["overall_status"] = "dry_run"
        manifest["resources"] = {
            "droplet_name": run_name,
            "firewall_name": firewall_name,
        }
        M22_REMOTE_MODULE.persist_manifest(output_dir, manifest)
        print(json.dumps({"overall_status": "dry_run", "output_dir": str(output_dir)}, indent=2))
        return 0

    private_key = Path(args.ssh_private_key).expanduser().resolve()
    if not private_key.is_file():
        raise RuntimeError(f"ssh private key not found: {private_key}")

    token = ""
    size_entry: dict[str, Any] | None = None
    droplet_id: int | None = None
    firewall_id: str | None = None
    droplet_ip: str | None = None
    droplet_started: float | None = None

    try:
        token = M22_REMOTE_MODULE.read_key(Path(args.do_token_file))
        if not token:
            raise RuntimeError(f"DigitalOcean API token file is empty: {args.do_token_file}")

        admin_cidr = args.admin_cidr or f"{M22_REMOTE_MODULE.detect_public_ipv4()}/32"
        manifest["configuration"]["admin_cidr"] = admin_cidr
        manifest["configuration"]["ssh_private_key_name"] = private_key.name

        sizes_resp = M22_REMOTE_MODULE.do_request(token, "GET", "/sizes?per_page=200")
        size_entry = next((s for s in sizes_resp.get("sizes", []) if s.get("slug") == args.size), None)
        if size_entry is None:
            raise RuntimeError(f"size slug not found: {args.size}")
        manifest["configuration"]["price_hourly_usd"] = size_entry.get("price_hourly")
        if args.region not in size_entry.get("regions", []):
            raise RuntimeError(f"size {args.size} is not available in region {args.region}")

        droplet_started = time.time()
        create_resp = M22_REMOTE_MODULE.do_request(
            token,
            "POST",
            "/droplets",
            {
                "name": run_name,
                "region": args.region,
                "size": args.size,
                "image": args.image,
                "ssh_keys": [args.ssh_key_id],
                "backups": False,
                "ipv6": False,
                "monitoring": False,
                "tags": [run_name],
            },
        )
        droplet_id = int(create_resp["droplet"]["id"])
        manifest["resources"]["droplet_id"] = droplet_id
        manifest["resources"]["droplet_name"] = run_name
        M22_REMOTE_MODULE.persist_manifest(output_dir, manifest)

        droplet_ip, droplet_obj = M22_REMOTE_MODULE.wait_for_droplet_ip(
            token,
            droplet_id,
            args.create_timeout_seconds,
        )
        manifest["resources"]["droplet_ipv4"] = droplet_ip
        manifest["resources"]["droplet_status"] = droplet_obj.get("status")
        M22_REMOTE_MODULE.persist_manifest(output_dir, manifest)

        fw_resp = M22_REMOTE_MODULE.do_request(
            token,
            "POST",
            "/firewalls",
            {
                "name": firewall_name,
                "inbound_rules": [
                    {
                        "protocol": "tcp",
                        "ports": "22",
                        "sources": {"addresses": [admin_cidr]},
                    }
                ],
                "outbound_rules": [
                    {
                        "protocol": "tcp",
                        "ports": "all",
                        "destinations": {"addresses": ["0.0.0.0/0", "::/0"]},
                    },
                    {
                        "protocol": "udp",
                        "ports": "all",
                        "destinations": {"addresses": ["0.0.0.0/0", "::/0"]},
                    },
                    {
                        "protocol": "icmp",
                        "destinations": {"addresses": ["0.0.0.0/0", "::/0"]},
                    },
                ],
                "droplet_ids": [droplet_id],
            },
        )
        firewall_id = fw_resp["firewall"]["id"]
        manifest["resources"]["firewall_id"] = firewall_id
        manifest["resources"]["firewall_name"] = firewall_name
        M22_REMOTE_MODULE.persist_manifest(output_dir, manifest)

        M22_REMOTE_MODULE.wait_for_ssh(private_key, droplet_ip, args.ssh_timeout_seconds)

        install_step = add_step_id(
            M22_REMOTE_MODULE.run_remote(
                private_key,
                droplet_ip,
                "export DEBIAN_FRONTEND=noninteractive && "
                "apt-get update && "
                "apt-get install -y --no-install-recommends "
                "build-essential cmake ninja-build pkg-config python3 "
                "libboost-all-dev libevent-dev libsqlite3-dev ca-certificates && "
                "rm -rf /var/lib/apt/lists/*",
                logs_dir / "remote_install.log",
                args.install_timeout_seconds,
            ),
            "remote_install",
        )
        record_step(manifest, output_dir, install_step)
        if install_step["exit_code"] != 0:
            raise RuntimeError("remote dependency install failed")

        archive_path = output_dir / "source.tar.gz"
        M22_REMOTE_MODULE.create_source_archive(archive_path)
        manifest["artifacts"]["source_archive"] = artifact_entry(archive_path)
        M22_REMOTE_MODULE.persist_manifest(output_dir, manifest)

        upload_step = add_step_id(
            M22_REMOTE_MODULE.run_transfer(
                M22_REMOTE_MODULE.scp_base(private_key)
                + [str(archive_path), f"root@{droplet_ip}:{REMOTE_SOURCE_ARCHIVE}"],
                logs_dir / "source_upload.log",
                600,
            ),
            "source_upload",
        )
        record_step(manifest, output_dir, upload_step)
        if upload_step["exit_code"] != 0:
            raise RuntimeError("source archive upload failed")

        prepare_step = add_step_id(
            M22_REMOTE_MODULE.run_remote(
                private_key,
                droplet_ip,
                f"rm -rf {shell_quote(REMOTE_ROOT)} && "
                f"mkdir -p {shell_quote(REMOTE_ROOT)} {shell_quote(REMOTE_REPORT_DIR)} && "
                f"tar -xzf {shell_quote(REMOTE_SOURCE_ARCHIVE)} -C {shell_quote(REMOTE_ROOT)}",
                logs_dir / "remote_prepare.log",
                600,
            ),
            "remote_prepare",
        )
        record_step(manifest, output_dir, prepare_step)
        if prepare_step["exit_code"] != 0:
            raise RuntimeError("remote workspace preparation failed")

        configure_cmd = (
            f"cmake -S {shell_quote(REMOTE_ROOT)} -B {shell_quote(REMOTE_BUILD_DIR)} -G Ninja "
            "-DBUILD_DAEMON=ON -DBUILD_CLI=ON -DBUILD_TESTS=ON -DBUILD_UTIL=ON "
            "-DBUILD_GUI=OFF -DBUILD_TX=OFF -DBUILD_WALLET_TOOL=OFF -DBUILD_BENCH=OFF "
            "-DBUILD_FUZZ_BINARY=OFF -DBUILD_UTIL_CHAINSTATE=OFF -DWITH_BDB=OFF "
            "-DWITH_ZMQ=OFF -DWITH_USDT=OFF -DWITH_MINIUPNPC=OFF -DWITH_NATPMP=OFF "
            "-DINSTALL_MAN=OFF -DWITH_CCACHE=OFF"
        )
        configure_step = add_step_id(
            M22_REMOTE_MODULE.run_remote(
                private_key,
                droplet_ip,
                configure_cmd,
                logs_dir / "remote_configure.log",
                args.build_timeout_seconds,
            ),
            "remote_configure",
        )
        record_step(manifest, output_dir, configure_step)
        if configure_step["exit_code"] != 0:
            raise RuntimeError("remote cmake configure failed")

        build_step = add_step_id(
            M22_REMOTE_MODULE.run_remote(
                private_key,
                droplet_ip,
                "cmake --build "
                f"{shell_quote(REMOTE_BUILD_DIR)} --target {' '.join(BUILD_TARGETS)} -j{args.build_jobs}",
                logs_dir / "remote_build.log",
                args.build_timeout_seconds,
            ),
            "remote_build",
        )
        record_step(manifest, output_dir, build_step)
        if build_step["exit_code"] != 0:
            raise RuntimeError("remote cmake build failed")

        remote_commands = [
            (
                "remote_m19_launch_rehearsal",
                (
                    f"bash {shell_quote(f'{REMOTE_ROOT}/scripts/m19_reset_launch_rehearsal.sh')} "
                    f"--build-dir {shell_quote(REMOTE_BUILD_DIR)} "
                    f"--config-file {shell_quote(f'{REMOTE_BUILD_DIR}/test/config.ini')} "
                    f"--artifact {shell_quote(f'{REMOTE_ARTIFACT_DIR}/m19-reset-launch-rehearsal.json')} "
                    f"--log-dir {shell_quote(f'{REMOTE_ARTIFACT_DIR}/m19-logs')} "
                    f"--cachedir {shell_quote(f'{REMOTE_ARTIFACT_DIR}/cache')} "
                    f"--portseed {args.portseed}"
                ),
                logs_dir / "remote_m19_launch_rehearsal.log",
                args.launch_timeout_seconds,
            ),
            (
                "remote_m21_redteam_campaign",
                (
                    f"bash {shell_quote(f'{REMOTE_ROOT}/scripts/m21_shielded_redteam_campaign.sh')} "
                    f"--build-dir {shell_quote(REMOTE_BUILD_DIR)} "
                    f"--config-file {shell_quote(f'{REMOTE_BUILD_DIR}/test/config.ini')} "
                    f"--skip-build "
                    f"--artifact {shell_quote(f'{REMOTE_ARTIFACT_DIR}/m21-remote-redteam.json')} "
                    f"--log-dir {shell_quote(f'{REMOTE_ARTIFACT_DIR}/m21-logs')} "
                    f"--cachedir {shell_quote(f'{REMOTE_ARTIFACT_DIR}/cache')} "
                    f"--portseed {args.portseed + 100}"
                ),
                logs_dir / "remote_m21_redteam_campaign.log",
                args.redteam_timeout_seconds,
            ),
            (
                "remote_send_runtime_report",
                (
                    f"{shell_quote(f'{REMOTE_BUILD_DIR}/bin/gen_shielded_v2_send_runtime_report')} "
                    "--samples=1 --warmup=0 "
                    f"--scenarios={shell_quote(args.send_scenarios)} "
                    f"--output={shell_quote(f'{REMOTE_REPORT_DIR}/send_runtime_report.json')}"
                ),
                logs_dir / "remote_send_runtime_report.log",
                args.report_timeout_seconds,
            ),
            (
                "remote_ingress_native_runtime_report",
                (
                    f"{shell_quote(f'{REMOTE_BUILD_DIR}/bin/gen_shielded_ingress_proof_runtime_report')} "
                    "--backend=matrict --samples=1 --warmup=0 "
                    f"--leaf-count={args.ingress_native_leaf_count} "
                    f"--output={shell_quote(f'{REMOTE_REPORT_DIR}/ingress_native_runtime_report.json')}"
                ),
                logs_dir / "remote_ingress_native_runtime_report.log",
                args.report_timeout_seconds,
            ),
            (
                "remote_ingress_receipt_capacity_report",
                (
                    f"{shell_quote(f'{REMOTE_BUILD_DIR}/bin/gen_shielded_ingress_proof_runtime_report')} "
                    "--backend=receipt --samples=1 --warmup=0 "
                    f"--leaf-counts={shell_quote(args.ingress_receipt_leaf_counts)} "
                    f"--output={shell_quote(f'{REMOTE_REPORT_DIR}/ingress_receipt_capacity_report.json')}"
                ),
                logs_dir / "remote_ingress_receipt_capacity_report.log",
                args.report_timeout_seconds,
            ),
            (
                "remote_egress_runtime_report",
                (
                    f"{shell_quote(f'{REMOTE_BUILD_DIR}/bin/gen_shielded_v2_egress_runtime_report')} "
                    "--samples=1 --warmup=0 "
                    f"--scenarios={shell_quote(args.egress_scenarios)} "
                    f"--output={shell_quote(f'{REMOTE_REPORT_DIR}/egress_runtime_report.json')}"
                ),
                logs_dir / "remote_egress_runtime_report.log",
                args.report_timeout_seconds,
            ),
            (
                "remote_netting_capacity_report",
                (
                    f"{shell_quote(f'{REMOTE_BUILD_DIR}/bin/gen_shielded_v2_netting_capacity_report')} "
                    "--samples=1 --warmup=0 "
                    f"--scenarios={shell_quote(args.netting_scenarios)} "
                    f"--output={shell_quote(f'{REMOTE_REPORT_DIR}/netting_capacity_report.json')}"
                ),
                logs_dir / "remote_netting_capacity_report.log",
                args.report_timeout_seconds,
            ),
            (
                "remote_chain_growth_projection_report",
                (
                    f"{shell_quote(f'{REMOTE_BUILD_DIR}/bin/gen_shielded_v2_chain_growth_projection_report')} "
                    f"--block-sizes-mb={shell_quote(args.chain_block_sizes_mb)} "
                    f"--output={shell_quote(f'{REMOTE_REPORT_DIR}/chain_growth_projection_report.json')}"
                ),
                logs_dir / "remote_chain_growth_projection_report.log",
                args.report_timeout_seconds,
            ),
        ]

        failed_validation_steps: list[str] = []
        for step_id, command, log_path, timeout in remote_commands:
            step = add_step_id(
                M22_REMOTE_MODULE.run_remote(private_key, droplet_ip, command, log_path, timeout),
                step_id,
            )
            record_step(manifest, output_dir, step)
            if step["exit_code"] != 0:
                failed_validation_steps.append(step_id)

        bundle_step = add_step_id(
            M22_REMOTE_MODULE.run_remote(
                private_key,
                droplet_ip,
                f"tar -czf {shell_quote(REMOTE_ARTIFACT_BUNDLE)} -C {shell_quote(REMOTE_ARTIFACT_DIR)} .",
                logs_dir / "remote_bundle.log",
                600,
            ),
            "remote_bundle",
        )
        record_step(manifest, output_dir, bundle_step)

        local_bundle = artifacts_dir / "remote_artifacts.tar.gz"
        artifact_collection_errors: list[str] = []
        if bundle_step["exit_code"] == 0:
            download_step = add_step_id(
                M22_REMOTE_MODULE.run_transfer(
                    M22_REMOTE_MODULE.scp_base(private_key)
                    + [f"root@{droplet_ip}:{REMOTE_ARTIFACT_BUNDLE}", str(local_bundle)],
                    logs_dir / "artifact_download.log",
                    600,
                ),
                "artifact_download",
            )
            record_step(manifest, output_dir, download_step)
            if download_step["exit_code"] != 0:
                artifact_collection_errors.append("artifact bundle download failed")
        else:
            artifact_collection_errors.append("remote artifact bundle creation failed")

        extract_dir = artifacts_dir / "remote_artifacts"
        if local_bundle.is_file():
            if extract_dir.exists():
                subprocess.run(["rm", "-rf", str(extract_dir)], check=True)
            extract_dir.mkdir(parents=True, exist_ok=True)
            with tarfile.open(local_bundle, "r:gz") as archive:
                archive.extractall(extract_dir)
            manifest["artifacts"]["remote_bundle"] = artifact_entry(local_bundle)
            manifest["artifacts"]["remote_extract_dir"] = {"path": str(extract_dir)}
        elif not artifact_collection_errors:
            artifact_collection_errors.append("downloaded bundle missing")

        m19_path = extract_dir / "m19-reset-launch-rehearsal.json"
        m21_path = extract_dir / "m21-remote-redteam.json"
        m21_inner_path = extract_dir / "m21-logs" / "feature_shielded_v2_proof_redteam_campaign.artifact.json"
        m21_corpus_path = extract_dir / "m21-logs" / "feature_shielded_v2_proof_redteam_campaign.corpus.json"
        send_path = extract_dir / "reports" / "send_runtime_report.json"
        ingress_native_path = extract_dir / "reports" / "ingress_native_runtime_report.json"
        ingress_receipt_path = extract_dir / "reports" / "ingress_receipt_capacity_report.json"
        egress_path = extract_dir / "reports" / "egress_runtime_report.json"
        netting_path = extract_dir / "reports" / "netting_capacity_report.json"
        chain_growth_path = extract_dir / "reports" / "chain_growth_projection_report.json"

        for label, path in [
            ("m19_launch_rehearsal", m19_path),
            ("m21_redteam_wrapper", m21_path),
            ("m21_redteam_inner_artifact", m21_inner_path),
            ("m21_redteam_corpus", m21_corpus_path),
            ("send_runtime_report", send_path),
            ("ingress_native_runtime_report", ingress_native_path),
            ("ingress_receipt_capacity_report", ingress_receipt_path),
            ("egress_runtime_report", egress_path),
            ("netting_capacity_report", netting_path),
            ("chain_growth_projection_report", chain_growth_path),
        ]:
            if path.is_file():
                manifest["artifacts"][label] = artifact_entry(path)
            else:
                artifact_collection_errors.append(f"missing expected artifact: {label}")

        m19_artifact = load_json_if_present(m19_path)
        m21_artifact = load_json_if_present(m21_path)
        m21_inner_artifact = load_json_if_present(m21_inner_path)
        m21_corpus = load_json_if_present(m21_corpus_path)
        send_report = load_json_if_present(send_path)
        ingress_native_report = load_json_if_present(ingress_native_path)
        ingress_receipt_report = load_json_if_present(ingress_receipt_path)
        egress_report = load_json_if_present(egress_path)
        netting_report = load_json_if_present(netting_path)
        chain_growth_report = load_json_if_present(chain_growth_path)

        manifest["validation_summary"] = summarize_suite(
            m19_artifact,
            m21_artifact,
            m21_inner_artifact,
            m21_corpus,
            send_report,
            ingress_native_report,
            ingress_receipt_report,
            egress_report,
            netting_report,
            chain_growth_report,
        )
        if artifact_collection_errors:
            manifest["artifacts"]["collection_errors"] = artifact_collection_errors

        elapsed_hours = max(time.time() - droplet_started, 0.0) / 3600.0
        price_hourly = float(size_entry.get("price_hourly", 0.0) or 0.0)
        manifest["resources"]["estimated_cost_usd"] = round(elapsed_hours * price_hourly, 4)
        M22_REMOTE_MODULE.persist_manifest(output_dir, manifest)

        if failed_validation_steps:
            raise RuntimeError(
                "remote validation step failures: " + ", ".join(failed_validation_steps)
            )
        if artifact_collection_errors:
            raise RuntimeError("artifact collection failures: " + ", ".join(artifact_collection_errors))

        manifest["overall_status"] = "pass"
    except Exception as exc:  # noqa: BLE001
        manifest["overall_status"] = "fail"
        manifest["failure"] = {
            "type": exc.__class__.__name__,
            "message": str(exc),
        }
        M22_REMOTE_MODULE.persist_manifest(output_dir, manifest)
    finally:
        teardown_errors: list[str] = []
        if not args.keep_droplet and firewall_id is not None and token:
            try:
                M22_REMOTE_MODULE.do_request(token, "DELETE", f"/firewalls/{firewall_id}")
                manifest["teardown"]["firewall_deleted"] = True
            except Exception as exc:  # noqa: BLE001
                teardown_errors.append(f"firewall delete failed: {exc}")
        if not args.keep_droplet and droplet_id is not None and token:
            try:
                M22_REMOTE_MODULE.do_request(token, "DELETE", f"/droplets/{droplet_id}")
                manifest["teardown"]["droplet_deleted"] = True
            except Exception as exc:  # noqa: BLE001
                teardown_errors.append(f"droplet delete failed: {exc}")
        if teardown_errors:
            manifest["teardown"]["errors"] = teardown_errors
        M22_REMOTE_MODULE.persist_manifest(output_dir, manifest)

    if manifest["overall_status"] != "pass":
        print(json.dumps({"overall_status": manifest["overall_status"], "output_dir": str(output_dir)}, indent=2))
        return 1

    print(json.dumps({"overall_status": "pass", "output_dir": str(output_dir)}, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
