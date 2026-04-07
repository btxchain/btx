#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""Generate BTX assumeutxo metadata from a trusted synced node."""

from __future__ import annotations

from dataclasses import dataclass
import argparse
import hashlib
import json
import pathlib
import subprocess
import sys
from typing import Any


@dataclass(frozen=True)
class AssumeutxoSnapshot:
    height: int
    txoutset_hash: str
    nchaintx: int
    blockhash: str
    path: str
    snapshot_sha256: str


def format_int_with_ticks(value: int) -> str:
    text = str(value)
    groups: list[str] = []
    while text:
        groups.append(text[-3:])
        text = text[:-3]
    return "'".join(reversed(groups))


def sha256_file(path: pathlib.Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def build_chainparams_entry(snapshot: AssumeutxoSnapshot, comment: str | None = None) -> str:
    lines = []
    if comment:
        lines.append(f"    // {comment}")
    lines.extend(
        [
            "    {",
            f"        .height = {format_int_with_ticks(snapshot.height)},",
            f"        .hash_serialized = AssumeutxoHash{{uint256{{\"{snapshot.txoutset_hash}\"}}}},",
            f"        .m_chain_tx_count = {snapshot.nchaintx},",
            f"        .blockhash = consteval_ctor(uint256{{\"{snapshot.blockhash}\"}}),",
            "    },",
        ]
    )
    return "\n".join(lines)


def build_release_manifest(
    snapshot: AssumeutxoSnapshot,
    chain: str,
    snapshot_type: str,
    published_name: str | None = None,
    asset_url: str | None = None,
) -> dict[str, Any]:
    snapshot_path = pathlib.Path(snapshot.path)
    manifest: dict[str, Any] = {
        "format_version": 1,
        "chain": chain,
        "snapshot_type": snapshot_type,
        "published_name": published_name or snapshot_path.name,
        "filename": published_name or snapshot_path.name,
        "height": snapshot.height,
        "txoutset_hash": snapshot.txoutset_hash,
        "nchaintx": snapshot.nchaintx,
        "blockhash": snapshot.blockhash,
        "snapshot_sha256": snapshot.snapshot_sha256,
        "sha256": snapshot.snapshot_sha256,
        "snapshot_size_bytes": snapshot_path.stat().st_size,
        "verification": {
            "loadtxoutset": f"btx-cli -rpcclienttimeout=0 loadtxoutset {published_name or snapshot_path.name}",
            "sha256sum": f"{snapshot.snapshot_sha256}  {published_name or snapshot_path.name}",
        },
    }
    if asset_url:
        manifest["asset_url"] = asset_url
        manifest["url"] = asset_url
    return manifest


def build_report(
    snapshot: AssumeutxoSnapshot,
    chain: str,
    cli_path: str,
    rpc_args: list[str],
    snapshot_type: str,
    asset_url: str | None,
) -> dict[str, Any]:
    release_manifest = build_release_manifest(snapshot, chain, snapshot_type, asset_url=asset_url)
    report: dict[str, Any] = {
        "chain": chain,
        "snapshot_type": snapshot_type,
        "cli_path": cli_path,
        "rpc_args": rpc_args,
        "snapshot": {
            "height": snapshot.height,
            "txoutset_hash": snapshot.txoutset_hash,
            "nchaintx": snapshot.nchaintx,
            "blockhash": snapshot.blockhash,
            "path": snapshot.path,
            "sha256": snapshot.snapshot_sha256,
        },
        "chainparams_snippet": "\n".join(
            [
                "m_assumeutxo_data = {",
                build_chainparams_entry(snapshot, comment=f"{chain} assumeutxo snapshot"),
                "};",
            ]
        ),
        "loadtxoutset_example": f"btx-cli -rpcclienttimeout=0 loadtxoutset {snapshot.path}",
        "release_asset_manifest": release_manifest,
    }
    if asset_url:
        report["asset"] = {
            "url": asset_url,
            "sha256": snapshot.snapshot_sha256,
        }
    return report


def run_dumptxoutset(
    cli_path: str,
    rpc_args: list[str],
    snapshot_path: pathlib.Path,
    snapshot_type: str,
    rollback: str | None,
) -> dict[str, Any]:
    command = [cli_path, "-rpcclienttimeout=0", *rpc_args, "-named", "dumptxoutset", str(snapshot_path)]
    if snapshot_type == "latest":
        command.append("type=latest")
    else:
        if rollback is None:
            raise ValueError("rollback snapshot generation requires --rollback")
        command.append(f"rollback={rollback}")
    output = subprocess.check_output(command, text=True)
    return json.loads(output)


def parse_snapshot_metadata(result: dict[str, Any], snapshot_path: pathlib.Path) -> AssumeutxoSnapshot:
    return AssumeutxoSnapshot(
        height=int(result["base_height"]),
        txoutset_hash=str(result["txoutset_hash"]),
        nchaintx=int(result["nchaintx"]),
        blockhash=str(result["base_hash"]),
        path=str(snapshot_path.resolve()),
        snapshot_sha256=sha256_file(snapshot_path),
    )


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--btx-cli", default="btx-cli", help="Path to btx-cli")
    parser.add_argument("--chain", default="main", help="Human-readable chain label for the report")
    parser.add_argument("--snapshot", required=True, help="Snapshot output path")
    parser.add_argument(
        "--snapshot-type",
        choices=("latest", "rollback"),
        default="rollback",
        help="Snapshot mode passed to dumptxoutset",
    )
    parser.add_argument("--rollback", help="Rollback height or blockhash for rollback snapshots")
    parser.add_argument("--rpc-arg", action="append", default=[], help="Extra argument passed directly to btx-cli")
    parser.add_argument("--asset-url", help="Optional published snapshot URL to include in the report")
    parser.add_argument("--manifest-out", help="Optional path for the compact published manifest JSON")
    parser.add_argument("--json-out", help="Optional path for the machine-readable report")
    return parser.parse_args(argv)


def main(argv: list[str]) -> int:
    args = parse_args(argv)
    snapshot_path = pathlib.Path(args.snapshot)
    snapshot_path.parent.mkdir(parents=True, exist_ok=True)

    dump_result = run_dumptxoutset(
        cli_path=args.btx_cli,
        rpc_args=list(args.rpc_arg),
        snapshot_path=snapshot_path,
        snapshot_type=args.snapshot_type,
        rollback=args.rollback,
    )
    snapshot = parse_snapshot_metadata(dump_result, snapshot_path)
    report = build_report(
        snapshot=snapshot,
        chain=args.chain,
        cli_path=args.btx_cli,
        rpc_args=list(args.rpc_arg),
        snapshot_type=args.snapshot_type,
        asset_url=args.asset_url,
    )
    release_manifest = report["release_asset_manifest"]

    if args.json_out:
        output_path = pathlib.Path(args.json_out)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")

    if args.manifest_out:
        manifest_path = pathlib.Path(args.manifest_out)
        manifest_path.parent.mkdir(parents=True, exist_ok=True)
        manifest_path.write_text(json.dumps(release_manifest, indent=2) + "\n", encoding="utf-8")

    json.dump(report, sys.stdout, indent=2)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
