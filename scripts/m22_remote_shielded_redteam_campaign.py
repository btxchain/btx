#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""Provision a disposable DO droplet, run the shielded_v2 red-team campaign, and tear it down."""

from __future__ import annotations

import argparse
import json
import os
import shlex
import shutil
import subprocess
import sys
import tarfile
import tempfile
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


REPO_ROOT = Path(__file__).resolve().parents[1]
DO_API_ROOT = "https://api.digitalocean.com/v2"
SOURCE_PATHS = [
    "CMakeLists.txt",
    "CMakePresets.json",
    "COPYING",
    "INSTALL.md",
    "README.md",
    "SECURITY.md",
    "cmake",
    "contrib",
    "doc",
    "scripts",
    "share",
    "src",
    "test",
    "libbitcoinconsensus.pc.in",
    "libbitcoinkernel.pc.in",
    "vcpkg.json",
]
REMOTE_ROOT = "/root/btx-remote-redteam"
REMOTE_ARTIFACT_DIR = f"{REMOTE_ROOT}/artifacts"
REMOTE_LOG_DIR = f"{REMOTE_ARTIFACT_DIR}/m22-logs"
REMOTE_BUILD_DIR = f"{REMOTE_ROOT}/build-redteam"
REMOTE_SOURCE_ARCHIVE = "/root/btx-remote-redteam-source.tar.gz"
REMOTE_ARTIFACT_BUNDLE = "/root/btx-remote-redteam-artifacts.tar.gz"


def default_do_token_file() -> Path:
    return (REPO_ROOT.parent / "infra" / "digitalocean_api.key").resolve()


def utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def read_key(path: Path) -> str:
    return path.read_text(encoding="utf-8").strip()


def do_request(token: str, method: str, path: str, payload: dict[str, Any] | None = None) -> dict[str, Any]:
    url = f"{DO_API_ROOT}{path}"
    data = None
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/json",
    }
    if payload is not None:
        data = json.dumps(payload).encode("utf-8")
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(url, data=data, method=method, headers=headers)
    with urllib.request.urlopen(req, timeout=60) as resp:
        raw = resp.read()
    if not raw:
        return {}
    return json.loads(raw.decode("utf-8"))


def detect_public_ipv4() -> str:
    with urllib.request.urlopen("https://api.ipify.org", timeout=30) as resp:
        return resp.read().decode("utf-8").strip()


def write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def manifest_path_prefixes(path: Path) -> list[str]:
    prefixes: list[str] = []
    for candidate in (path, path.resolve()):
        text = str(candidate)
        if text not in prefixes:
            prefixes.append(text)
        if text.startswith("/private/tmp/"):
            alt = text.removeprefix("/private") if text != "/private/tmp" else "/tmp"
            if alt not in prefixes:
                prefixes.append(alt)
        elif text.startswith("/tmp/"):
            alt = f"/private{text}"
            if alt not in prefixes:
                prefixes.append(alt)
    return prefixes


def manifest_display_path(output_dir: Path, value: str) -> str:
    for root, label in (
        (output_dir, ""),
        (REPO_ROOT, "<repo>"),
        (Path.home(), "~"),
        # Preserve sanitization for bundled example manifests that use
        # placeholder paths rather than the local operator's actual home/repo.
        (Path("/home/example/btxchain/btx-node"), "<repo>"),
        (Path("/home/example"), "~"),
    ):
        for root_str in manifest_path_prefixes(root):
            if value == root_str:
                return label or "."
            prefix = root_str + os.sep
            if value.startswith(prefix):
                suffix = value[len(prefix):]
                if not label:
                    return suffix
                return f"{label}/{suffix}"
    return value


def sanitize_manifest_value(output_dir: Path, value: Any) -> Any:
    if isinstance(value, dict):
        return {key: sanitize_manifest_value(output_dir, item) for key, item in value.items()}
    if isinstance(value, list):
        return [sanitize_manifest_value(output_dir, item) for item in value]
    if isinstance(value, str):
        return manifest_display_path(output_dir, value)
    return value


def persist_manifest(output_dir: Path, manifest: dict[str, Any]) -> None:
    sanitized = sanitize_manifest_value(output_dir, manifest)
    write_text(output_dir / "manifest.json", json.dumps(sanitized, indent=2) + "\n")


def run_local(cmd: list[str], log_path: Path, timeout: int) -> dict[str, Any]:
    started = time.time()
    proc = subprocess.run(
        cmd,
        cwd=str(REPO_ROOT),
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        timeout=timeout,
        check=False,
    )
    write_text(log_path, proc.stdout)
    return {
        "command": cmd,
        "cwd": str(REPO_ROOT),
        "log": str(log_path),
        "exit_code": proc.returncode,
        "duration_seconds": round(time.time() - started, 3),
    }


def ssh_base(private_key: Path, host: str) -> list[str]:
    return [
        "ssh",
        "-n",
        "-i",
        str(private_key),
        "-o",
        "BatchMode=yes",
        "-o",
        "StrictHostKeyChecking=accept-new",
        "-o",
        "ConnectTimeout=10",
        f"root@{host}",
    ]


def scp_base(private_key: Path) -> list[str]:
    return [
        "scp",
        "-i",
        str(private_key),
        "-o",
        "BatchMode=yes",
        "-o",
        "StrictHostKeyChecking=accept-new",
        "-o",
        "ConnectTimeout=10",
    ]


def run_remote(private_key: Path, host: str, command: str, log_path: Path, timeout: int) -> dict[str, Any]:
    started = time.time()
    ssh_cmd = ssh_base(private_key, host) + [f"bash -lc {shlex.quote(command)}"]
    proc = subprocess.run(
        ssh_cmd,
        cwd=str(REPO_ROOT),
        text=True,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        timeout=timeout,
        check=False,
    )
    write_text(log_path, proc.stdout)
    return {
        "command": ssh_cmd,
        "log": str(log_path),
        "exit_code": proc.returncode,
        "duration_seconds": round(time.time() - started, 3),
    }


def run_transfer(cmd: list[str], log_path: Path, timeout: int) -> dict[str, Any]:
    started = time.time()
    proc = subprocess.run(
        cmd,
        cwd=str(REPO_ROOT),
        text=True,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        timeout=timeout,
        check=False,
    )
    write_text(log_path, proc.stdout)
    return {
        "command": cmd,
        "cwd": str(REPO_ROOT),
        "log": str(log_path),
        "exit_code": proc.returncode,
        "duration_seconds": round(time.time() - started, 3),
    }


def wait_for_droplet_ip(token: str, droplet_id: int, timeout: int) -> tuple[str, dict[str, Any]]:
    deadline = time.time() + timeout
    while time.time() < deadline:
        resp = do_request(token, "GET", f"/droplets/{droplet_id}")
        droplet = resp["droplet"]
        if droplet.get("status") == "active":
            for net in droplet.get("networks", {}).get("v4", []):
                if net.get("type") == "public":
                    return net["ip_address"], droplet
        time.sleep(5)
    raise RuntimeError(f"droplet {droplet_id} did not become active before timeout")


def wait_for_ssh(private_key: Path, host: str, timeout: int) -> None:
    deadline = time.time() + timeout
    while time.time() < deadline:
        proc = subprocess.run(
            ssh_base(private_key, host) + ["true"],
            cwd=str(REPO_ROOT),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
        )
        if proc.returncode == 0:
            return
        time.sleep(5)
    raise RuntimeError(f"ssh to {host} did not become ready before timeout")


def create_source_archive(output_path: Path) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with tarfile.open(output_path, mode="w:gz") as archive:
        for relative_path in SOURCE_PATHS:
            source_path = REPO_ROOT / relative_path
            if not source_path.exists():
                raise FileNotFoundError(f"required source path missing: {source_path}")
            archive.add(source_path, arcname=relative_path)


def load_json_if_present(path: Path) -> dict[str, Any] | None:
    if not path.is_file():
        return None
    return json.loads(path.read_text(encoding="utf-8"))


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run the shielded_v2 malformed-proof red-team campaign on a disposable DigitalOcean droplet."
    )
    parser.add_argument(
        "--output-dir",
        default=str(REPO_ROOT / ".btx-validation" / "m22-remote-redteam"),
        help="Local output directory for logs and fetched artifacts",
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
        help="CIDR allowed to SSH to the droplet; default auto-detects public IPv4 /32",
    )
    parser.add_argument("--build-jobs", type=int, default=2, help="Remote cmake --build parallelism")
    parser.add_argument("--create-timeout-seconds", type=int, default=600)
    parser.add_argument("--ssh-timeout-seconds", type=int, default=600)
    parser.add_argument("--install-timeout-seconds", type=int, default=1800)
    parser.add_argument("--build-timeout-seconds", type=int, default=5400)
    parser.add_argument("--campaign-timeout-seconds", type=int, default=3600)
    parser.add_argument("--portseed", type=int, default=35200)
    parser.add_argument(
        "--do-token-file",
        default=str(default_do_token_file()),
        help="DigitalOcean API token file; defaults to the repo-adjacent infra key path when present",
    )
    parser.add_argument("--keep-droplet", action="store_true", help="Do not delete the droplet/firewall on exit")
    parser.add_argument("--dry-run", action="store_true", help="Emit the planned configuration without creating resources")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    output_dir = Path(args.output_dir).resolve()
    logs_dir = output_dir / "logs"
    artifacts_dir = output_dir / "artifacts"
    logs_dir.mkdir(parents=True, exist_ok=True)
    artifacts_dir.mkdir(parents=True, exist_ok=True)

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
        },
        "resources": {},
        "steps": [],
        "artifacts": {},
        "teardown": {
            "droplet_deleted": False,
            "firewall_deleted": False,
        },
    }

    persist_manifest(output_dir, manifest)

    private_key = Path(args.ssh_private_key).expanduser().resolve()
    token = ""
    size_entry: dict[str, Any] | None = None
    run_name = datetime.now(timezone.utc).strftime("btx-redteam-%Y%m%d-%H%M%S")
    firewall_name = f"{run_name}-fw"

    droplet_id: int | None = None
    firewall_id: str | None = None
    droplet_ip: str | None = None
    droplet_started: float | None = None

    try:
        if not private_key.is_file():
            raise RuntimeError(f"ssh private key not found: {private_key}")

        token = read_key(Path(args.do_token_file))
        if not token:
            raise RuntimeError(f"DigitalOcean API token file is empty: {args.do_token_file}")

        admin_cidr = args.admin_cidr or f"{detect_public_ipv4()}/32"
        manifest["configuration"]["admin_cidr"] = admin_cidr
        manifest["configuration"]["ssh_private_key_name"] = private_key.name

        sizes_resp = do_request(token, "GET", "/sizes?per_page=200")
        size_entry = next((s for s in sizes_resp.get("sizes", []) if s.get("slug") == args.size), None)
        if size_entry is None:
            raise RuntimeError(f"size slug not found: {args.size}")
        manifest["configuration"]["price_hourly_usd"] = size_entry.get("price_hourly")
        if args.region not in size_entry.get("regions", []):
            raise RuntimeError(f"size {args.size} is not available in region {args.region}")

        if args.dry_run:
            manifest["overall_status"] = "dry_run"
            manifest["resources"] = {
                "droplet_name": run_name,
                "firewall_name": firewall_name,
            }
            persist_manifest(output_dir, manifest)
            print(json.dumps({"overall_status": "dry_run", "output_dir": str(output_dir)}, indent=2))
            return 0

        droplet_started = time.time()

        create_payload = {
            "name": run_name,
            "region": args.region,
            "size": args.size,
            "image": args.image,
            "ssh_keys": [args.ssh_key_id],
            "backups": False,
            "ipv6": False,
            "monitoring": False,
            "tags": [run_name],
        }
        create_resp = do_request(token, "POST", "/droplets", create_payload)
        droplet_id = int(create_resp["droplet"]["id"])
        manifest["resources"]["droplet_id"] = droplet_id
        manifest["resources"]["droplet_name"] = run_name
        persist_manifest(output_dir, manifest)

        droplet_ip, droplet_obj = wait_for_droplet_ip(token, droplet_id, args.create_timeout_seconds)
        manifest["resources"]["droplet_ipv4"] = droplet_ip
        manifest["resources"]["droplet_status"] = droplet_obj.get("status")
        persist_manifest(output_dir, manifest)

        fw_payload = {
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
        }
        fw_resp = do_request(token, "POST", "/firewalls", fw_payload)
        firewall_id = fw_resp["firewall"]["id"]
        manifest["resources"]["firewall_id"] = firewall_id
        manifest["resources"]["firewall_name"] = firewall_name
        persist_manifest(output_dir, manifest)

        wait_for_ssh(private_key, droplet_ip, args.ssh_timeout_seconds)

        install_cmd = (
            "export DEBIAN_FRONTEND=noninteractive && "
            "apt-get update && "
            "apt-get install -y --no-install-recommends "
            "build-essential cmake ninja-build pkg-config python3 "
            "libboost-all-dev libevent-dev libsqlite3-dev ca-certificates && "
            "rm -rf /var/lib/apt/lists/*"
        )
        manifest["steps"].append(
            run_remote(private_key, droplet_ip, install_cmd, logs_dir / "remote_install.log", args.install_timeout_seconds)
        )
        persist_manifest(output_dir, manifest)
        if manifest["steps"][-1]["exit_code"] != 0:
            raise RuntimeError("remote dependency install failed")

        archive_path = output_dir / "source.tar.gz"
        create_source_archive(archive_path)
        manifest["artifacts"]["source_archive"] = {
            "path": str(archive_path),
            "bytes": archive_path.stat().st_size,
        }

        upload_step = run_transfer(
            scp_base(private_key)
            + [str(archive_path), f"root@{droplet_ip}:{REMOTE_SOURCE_ARCHIVE}"],
            logs_dir / "source_upload.log",
            600,
        )
        manifest["steps"].append(upload_step)
        persist_manifest(output_dir, manifest)
        if upload_step["exit_code"] != 0:
            raise RuntimeError("source archive upload failed")

        prepare_cmd = (
            f"rm -rf {REMOTE_ROOT} && "
            f"mkdir -p {REMOTE_ROOT} {REMOTE_LOG_DIR} && "
            f"tar -xzf {REMOTE_SOURCE_ARCHIVE} -C {REMOTE_ROOT}"
        )
        manifest["steps"].append(
            run_remote(private_key, droplet_ip, prepare_cmd, logs_dir / "remote_prepare.log", 600)
        )
        persist_manifest(output_dir, manifest)
        if manifest["steps"][-1]["exit_code"] != 0:
            raise RuntimeError("remote workspace preparation failed")

        configure_cmd = (
            f"cmake -S {REMOTE_ROOT} -B {REMOTE_BUILD_DIR} -G Ninja "
            "-DBUILD_DAEMON=ON -DBUILD_CLI=ON -DBUILD_TESTS=ON -DBUILD_UTIL=ON "
            "-DBUILD_GUI=OFF -DBUILD_TX=OFF -DBUILD_WALLET_TOOL=OFF -DBUILD_BENCH=OFF "
            "-DBUILD_FUZZ_BINARY=OFF -DBUILD_UTIL_CHAINSTATE=OFF -DWITH_BDB=OFF "
            "-DWITH_ZMQ=OFF -DWITH_USDT=OFF -DWITH_MINIUPNPC=OFF -DWITH_NATPMP=OFF "
            "-DINSTALL_MAN=OFF -DWITH_CCACHE=OFF"
        )
        manifest["steps"].append(
            run_remote(private_key, droplet_ip, configure_cmd, logs_dir / "remote_configure.log", args.build_timeout_seconds)
        )
        persist_manifest(output_dir, manifest)
        if manifest["steps"][-1]["exit_code"] != 0:
            raise RuntimeError("remote cmake configure failed")

        build_cmd = (
            f"cmake --build {REMOTE_BUILD_DIR} --target btxd bitcoin-cli generate_shielded_v2_adversarial_proof_corpus "
            f"-j{args.build_jobs}"
        )
        manifest["steps"].append(
            run_remote(private_key, droplet_ip, build_cmd, logs_dir / "remote_build.log", args.build_timeout_seconds)
        )
        persist_manifest(output_dir, manifest)
        if manifest["steps"][-1]["exit_code"] != 0:
            raise RuntimeError("remote cmake build failed")

        campaign_cmd = (
            f"bash {REMOTE_ROOT}/scripts/m21_shielded_redteam_campaign.sh "
            f"--build-dir {REMOTE_BUILD_DIR} "
            f"--config-file {REMOTE_BUILD_DIR}/test/config.ini "
            f"--skip-build "
            f"--artifact {REMOTE_ARTIFACT_DIR}/m21-remote-redteam.json "
            f"--log-dir {REMOTE_ARTIFACT_DIR}/m21-logs "
            f"--cachedir {REMOTE_ARTIFACT_DIR}/cache "
            f"--portseed {args.portseed}"
        )
        manifest["steps"].append(
            run_remote(private_key, droplet_ip, campaign_cmd, logs_dir / "remote_campaign.log", args.campaign_timeout_seconds)
        )
        persist_manifest(output_dir, manifest)
        campaign_step = manifest["steps"][-1]

        bundle_cmd = (
            f"tar -czf {REMOTE_ARTIFACT_BUNDLE} -C {REMOTE_ARTIFACT_DIR} ."
        )
        manifest["steps"].append(
            run_remote(private_key, droplet_ip, bundle_cmd, logs_dir / "remote_bundle.log", 600)
        )
        persist_manifest(output_dir, manifest)
        bundle_step = manifest["steps"][-1]

        local_bundle = artifacts_dir / "remote_artifacts.tar.gz"
        remote_artifact: dict[str, Any] | None = None
        artifact_collection_errors: list[str] = []
        if bundle_step["exit_code"] == 0:
            download_step = run_transfer(
                scp_base(private_key)
                + [f"root@{droplet_ip}:{REMOTE_ARTIFACT_BUNDLE}", str(local_bundle)],
                logs_dir / "artifact_download.log",
                600,
            )
            manifest["steps"].append(download_step)
            persist_manifest(output_dir, manifest)
            if download_step["exit_code"] == 0:
                extract_dir = artifacts_dir / "remote_artifacts"
                if extract_dir.exists():
                    shutil.rmtree(extract_dir)
                extract_dir.mkdir(parents=True, exist_ok=True)
                subprocess.run(["tar", "-xzf", str(local_bundle), "-C", str(extract_dir)], check=True)
                manifest["artifacts"]["remote_bundle"] = {
                    "path": str(local_bundle),
                    "bytes": local_bundle.stat().st_size,
                }
                manifest["artifacts"]["remote_extract_dir"] = str(extract_dir)

                remote_artifact_path = extract_dir / "m21-remote-redteam.json"
                remote_artifact = load_json_if_present(remote_artifact_path)
                if remote_artifact is None:
                    manifest["artifacts"]["remote_campaign_artifact_missing"] = str(remote_artifact_path)
                else:
                    manifest["artifacts"]["remote_campaign_artifact"] = remote_artifact
            else:
                artifact_collection_errors.append("artifact bundle download failed")
        else:
            artifact_collection_errors.append("remote artifact bundle creation failed")

        if artifact_collection_errors:
            manifest["artifacts"]["collection_errors"] = artifact_collection_errors

        elapsed_hours = max(time.time() - droplet_started, 0.0) / 3600.0
        price_hourly = float(size_entry.get("price_hourly", 0.0) or 0.0)
        manifest["resources"]["estimated_cost_usd"] = round(elapsed_hours * price_hourly, 4)
        if campaign_step["exit_code"] != 0:
            if remote_artifact is not None:
                raise RuntimeError(
                    "remote red-team campaign failed after artifact collection: "
                    f"m21 overall_status={remote_artifact.get('overall_status')}"
                )
            collection_suffix = ""
            if artifact_collection_errors:
                collection_suffix = f"; artifact collection errors: {', '.join(artifact_collection_errors)}"
            raise RuntimeError(f"remote red-team campaign failed before artifact collection{collection_suffix}")

        if remote_artifact is None:
            if artifact_collection_errors:
                raise RuntimeError(
                    "remote red-team campaign completed but artifact collection failed: "
                    + ", ".join(artifact_collection_errors)
                )
            raise RuntimeError("remote red-team campaign completed but m21 artifact is missing")

        manifest["overall_status"] = "pass" if remote_artifact.get("overall_status") == "pass" else "fail"
        if manifest["overall_status"] != "pass":
            raise RuntimeError(
                "remote red-team campaign artifact reported failure: "
                f"m21 overall_status={remote_artifact.get('overall_status')}"
            )
    except Exception as exc:  # noqa: BLE001
        manifest["failure"] = {
            "type": exc.__class__.__name__,
            "message": str(exc),
        }
        manifest["overall_status"] = "fail"
        persist_manifest(output_dir, manifest)
    finally:
        teardown_errors: list[str] = []
        if not args.keep_droplet and firewall_id is not None and token:
            try:
                do_request(token, "DELETE", f"/firewalls/{firewall_id}")
                manifest["teardown"]["firewall_deleted"] = True
            except Exception as exc:  # noqa: BLE001
                teardown_errors.append(f"firewall delete failed: {exc}")
        if not args.keep_droplet and droplet_id is not None and token:
            try:
                do_request(token, "DELETE", f"/droplets/{droplet_id}")
                manifest["teardown"]["droplet_deleted"] = True
            except Exception as exc:  # noqa: BLE001
                teardown_errors.append(f"droplet delete failed: {exc}")
        if teardown_errors:
            manifest["teardown"]["errors"] = teardown_errors

        persist_manifest(output_dir, manifest)

    if manifest["overall_status"] != "pass":
        print(json.dumps({"overall_status": manifest["overall_status"], "output_dir": str(output_dir)}, indent=2))
        return 1

    print(json.dumps({"overall_status": "pass", "output_dir": str(output_dir)}, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
