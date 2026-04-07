#!/usr/bin/env python3
"""Generate deterministic chain-hardening parameters from a live node.

This script queries a running node via btx-cli and emits:
  - nMinimumChainWork
  - defaultAssumeValid
  - post-genesis checkpoint candidate
  - chainTxData tuple

The output is intended for release hardening updates in chainparams.
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


HEX64_RE = re.compile(r"^[0-9a-f]{64}$")


class CliError(RuntimeError):
    pass


@dataclass(frozen=True)
class ChainSnapshot:
    chain: str
    tip_height: int
    anchor_height: int
    txstats_window_blocks: int
    genesis_hash: str
    anchor_hash: str
    bestblockhash: str
    min_chain_work: str
    chain_tx_time: int
    chain_tx_count: int
    chain_tx_rate: float


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Generate chain hardening manifest from btx-cli RPC responses."
    )
    parser.add_argument(
        "--btx-cli",
        "--bitcoin-cli",
        dest="btx_cli",
        default="btx-cli",
        help="Path to btx-cli binary (legacy bitcoin-cli alias accepted).",
    )
    parser.add_argument(
        "--chain",
        default="main",
        choices=("main", "testnet", "testnet4", "signet", "regtest"),
        help="Chain context passed as -chain=<value> (default: main).",
    )
    parser.add_argument(
        "--anchor-height",
        type=int,
        default=None,
        help="Checkpoint anchor height. Defaults to tip-2.",
    )
    parser.add_argument(
        "--window-blocks",
        type=int,
        default=4096,
        help="Block window for getchaintxstats (default: 4096).",
    )
    parser.add_argument(
        "--min-anchor-height-mainnet",
        type=int,
        default=50000,
        help="Minimum allowed mainnet anchor height unless --allow-low-anchor-height is set (default: 50000).",
    )
    parser.add_argument(
        "--allow-low-anchor-height",
        action="store_true",
        help="Allow anchor below --min-anchor-height-mainnet for mainnet.",
    )
    parser.add_argument(
        "--rpc-arg",
        action="append",
        default=[],
        help="Extra argument forwarded to btx-cli (repeatable).",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=None,
        help="Optional JSON output path. Prints JSON to stdout when omitted.",
    )
    return parser.parse_args()


def run_cli(btx_cli: str, chain: str, rpc_args: list[str], *command: str) -> str:
    cmd = [btx_cli, f"-chain={chain}", *rpc_args, *command]
    proc = subprocess.run(cmd, capture_output=True, text=True, check=False)
    if proc.returncode != 0:
        stderr = proc.stderr.strip()
        stdout = proc.stdout.strip()
        details = stderr if stderr else stdout
        raise CliError(f"btx-cli command failed ({' '.join(command)}): {details}")
    return proc.stdout.strip()


def parse_hash(value: str, field_name: str) -> str:
    normalized = value.strip().lower()
    if not HEX64_RE.fullmatch(normalized):
        raise CliError(f"{field_name} must be 64 hex chars, got: {value!r}")
    return normalized


def parse_chainwork(value: str) -> str:
    normalized = value.strip().lower()
    if not re.fullmatch(r"[0-9a-f]+", normalized):
        raise CliError(f"chainwork must be hex, got: {value!r}")
    if len(normalized) > 64:
        raise CliError(f"chainwork must be <=64 hex chars, got length {len(normalized)}")
    return normalized.rjust(64, "0")


def format_rate(value: float) -> str:
    rendered = f"{value:.12f}".rstrip("0").rstrip(".")
    return rendered if rendered else "0"


def collect_snapshot(args: argparse.Namespace) -> ChainSnapshot:
    tip_height = int(run_cli(args.btx_cli, args.chain, args.rpc_arg, "getblockcount"))
    if tip_height < 0:
        raise CliError(f"tip height must be non-negative, got {tip_height}")

    anchor_height = args.anchor_height if args.anchor_height is not None else max(0, tip_height - 2)
    if anchor_height < 0 or anchor_height > tip_height:
        raise CliError(f"anchor height {anchor_height} is outside [0,{tip_height}]")

    if (
        args.chain == "main"
        and not args.allow_low_anchor_height
        and anchor_height < args.min_anchor_height_mainnet
    ):
        raise CliError(
            f"mainnet anchor height {anchor_height} is below required minimum "
            f"{args.min_anchor_height_mainnet}; pass --allow-low-anchor-height to override."
        )

    genesis_hash = parse_hash(
        run_cli(args.btx_cli, args.chain, args.rpc_arg, "getblockhash", "0"),
        "genesis hash",
    )
    anchor_hash = parse_hash(
        run_cli(args.btx_cli, args.chain, args.rpc_arg, "getblockhash", str(anchor_height)),
        "anchor hash",
    )
    best_hash = parse_hash(
        run_cli(args.btx_cli, args.chain, args.rpc_arg, "getbestblockhash"),
        "best block hash",
    )

    header_raw = run_cli(args.btx_cli, args.chain, args.rpc_arg, "getblockheader", anchor_hash, "true")
    header = json.loads(header_raw)
    chainwork = parse_chainwork(str(header["chainwork"]))

    if tip_height >= 1:
        txstats_window_blocks = min(args.window_blocks, tip_height - 1)
        txstats_raw = run_cli(
            args.btx_cli,
            args.chain,
            args.rpc_arg,
            "getchaintxstats",
            str(txstats_window_blocks),
            best_hash,
        )
        txstats = json.loads(txstats_raw)
        chain_tx_time = int(txstats["time"])
        chain_tx_count = int(txstats["txcount"])
        chain_tx_rate = float(txstats["txrate"])
    else:
        txstats_window_blocks = 0
        genesis_header_raw = run_cli(
            args.btx_cli,
            args.chain,
            args.rpc_arg,
            "getblockheader",
            genesis_hash,
            "true",
        )
        genesis_header = json.loads(genesis_header_raw)
        chain_tx_time = int(genesis_header.get("time", 0))
        chain_tx_count = 1
        chain_tx_rate = 0.0

    return ChainSnapshot(
        chain=args.chain,
        tip_height=tip_height,
        anchor_height=anchor_height,
        txstats_window_blocks=txstats_window_blocks,
        genesis_hash=genesis_hash,
        anchor_hash=anchor_hash,
        bestblockhash=best_hash,
        min_chain_work=chainwork,
        chain_tx_time=chain_tx_time,
        chain_tx_count=chain_tx_count,
        chain_tx_rate=chain_tx_rate,
    )


def build_cpp_snippet(snapshot: ChainSnapshot) -> str:
    return (
        f"consensus.nMinimumChainWork = uint256{{\"{snapshot.min_chain_work}\"}};\n"
        f"consensus.defaultAssumeValid = uint256{{\"{snapshot.anchor_hash}\"}};\n"
        "checkpointData = {\n"
        "    {\n"
        f"        {{0, uint256{{\"{snapshot.genesis_hash}\"}}}},\n"
        f"        {{{snapshot.anchor_height}, uint256{{\"{snapshot.anchor_hash}\"}}}},\n"
        "    }\n"
        "};\n"
        "chainTxData = ChainTxData{\n"
        f"    .nTime = {snapshot.chain_tx_time},\n"
        f"    .tx_count = {snapshot.chain_tx_count},\n"
        f"    .dTxRate = {format_rate(snapshot.chain_tx_rate)},\n"
        "};"
    )


def build_manifest(snapshot: ChainSnapshot) -> dict[str, Any]:
    return {
        "generated_at_utc": datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
        "chain": snapshot.chain,
        "tip_height": snapshot.tip_height,
        "anchor_height": snapshot.anchor_height,
        "txstats_window_blocks": snapshot.txstats_window_blocks,
        "genesis_hash": snapshot.genesis_hash,
        "anchor_hash": snapshot.anchor_hash,
        "bestblockhash": snapshot.bestblockhash,
        "nMinimumChainWork": snapshot.min_chain_work,
        "defaultAssumeValid": snapshot.anchor_hash,
        "checkpoint": {
            "height": snapshot.anchor_height,
            "hash": snapshot.anchor_hash,
        },
        "chainTxData": {
            "nTime": snapshot.chain_tx_time,
            "tx_count": snapshot.chain_tx_count,
            "dTxRate": snapshot.chain_tx_rate,
        },
        "cpp_snippet": build_cpp_snippet(snapshot),
    }


def main() -> int:
    args = parse_args()
    if args.window_blocks <= 0:
        print("error: --window-blocks must be positive", file=sys.stderr)
        return 2

    try:
        snapshot = collect_snapshot(args)
        manifest = build_manifest(snapshot)
    except (CliError, KeyError, ValueError, json.JSONDecodeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    rendered = json.dumps(manifest, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered, encoding="utf-8")
    else:
        sys.stdout.write(rendered)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
