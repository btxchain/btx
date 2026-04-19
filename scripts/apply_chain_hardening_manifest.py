#!/usr/bin/env python3
"""Apply a chain hardening manifest into src/kernel/chainparams.cpp."""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any


HEX64_RE = re.compile(r"^[0-9a-f]{64}$")


class ManifestError(RuntimeError):
    pass


@dataclass(frozen=True)
class HardeningData:
    chain: str
    genesis_hash: str
    anchor_height: int
    anchor_hash: str
    minimum_chain_work: str
    chain_tx_time: int
    chain_tx_count: int
    chain_tx_rate: float


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Apply chain hardening manifest values into chainparams.cpp."
    )
    parser.add_argument(
        "--manifest",
        type=Path,
        required=True,
        help="Path to JSON manifest from update_chain_hardening_manifest.py.",
    )
    parser.add_argument(
        "--chainparams",
        type=Path,
        default=Path("src/kernel/chainparams.cpp"),
        help="Path to chainparams.cpp (default: src/kernel/chainparams.cpp).",
    )
    parser.add_argument(
        "--chain",
        choices=("main", "testnet", "testnet4", "signet"),
        required=True,
        help="Chain block to update inside chainparams.cpp.",
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="Only check if chainparams already matches the manifest.",
    )
    return parser.parse_args()


def parse_hash(raw: Any, field: str) -> str:
    if not isinstance(raw, str):
        raise ManifestError(f"{field} must be a string")
    value = raw.strip().lower()
    if not HEX64_RE.fullmatch(value):
        raise ManifestError(f"{field} must be a 64-char lowercase hex hash")
    return value


def parse_chainwork(raw: Any) -> str:
    if not isinstance(raw, str):
        raise ManifestError("nMinimumChainWork must be a string")
    value = raw.strip().lower()
    if not re.fullmatch(r"[0-9a-f]+", value):
        raise ManifestError("nMinimumChainWork must be hex")
    if len(value) > 64:
        raise ManifestError("nMinimumChainWork must be <=64 hex chars")
    return value.rjust(64, "0")


def parse_manifest(path: Path) -> HardeningData:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ManifestError("manifest root must be a JSON object")

    chain = data.get("chain")
    if not isinstance(chain, str) or not chain:
        raise ManifestError("manifest field `chain` is required")

    genesis_hash = parse_hash(data.get("genesis_hash"), "genesis_hash")
    anchor_hash = parse_hash(data.get("anchor_hash"), "anchor_hash")
    minimum_chain_work = parse_chainwork(data.get("nMinimumChainWork"))

    anchor_height = data.get("anchor_height")
    if not isinstance(anchor_height, int) or anchor_height < 0:
        raise ManifestError("anchor_height must be a non-negative integer")

    chain_tx_data = data.get("chainTxData")
    if not isinstance(chain_tx_data, dict):
        raise ManifestError("chainTxData must be an object")

    n_time = chain_tx_data.get("nTime")
    tx_count = chain_tx_data.get("tx_count")
    d_tx_rate = chain_tx_data.get("dTxRate")
    if not isinstance(n_time, int) or n_time < 0:
        raise ManifestError("chainTxData.nTime must be a non-negative integer")
    if not isinstance(tx_count, int) or tx_count < 0:
        raise ManifestError("chainTxData.tx_count must be a non-negative integer")
    if not isinstance(d_tx_rate, (int, float)) or float(d_tx_rate) < 0:
        raise ManifestError("chainTxData.dTxRate must be a non-negative number")

    checkpoint = data.get("checkpoint")
    if isinstance(checkpoint, dict):
        checkpoint_height = checkpoint.get("height")
        checkpoint_hash = checkpoint.get("hash")
        if checkpoint_height != anchor_height:
            raise ManifestError("checkpoint.height does not match anchor_height")
        if checkpoint_hash is not None and parse_hash(checkpoint_hash, "checkpoint.hash") != anchor_hash:
            raise ManifestError("checkpoint.hash does not match anchor_hash")

    return HardeningData(
        chain=chain,
        genesis_hash=genesis_hash,
        anchor_height=anchor_height,
        anchor_hash=anchor_hash,
        minimum_chain_work=minimum_chain_work,
        chain_tx_time=n_time,
        chain_tx_count=tx_count,
        chain_tx_rate=float(d_tx_rate),
    )


def format_rate(value: float) -> str:
    rendered = f"{value:.12f}".rstrip("0").rstrip(".")
    return rendered if rendered else "0"


def class_name_for_chain(chain: str) -> str:
    mapping = {
        "main": "CMainParams",
        "testnet": "CTestNetParams",
        "testnet4": "CTestNet4Params",
        "signet": "SigNetParams",
    }
    return mapping[chain]


def update_once(block: str, pattern: str, replacement: str, field: str) -> str:
    updated, count = re.subn(pattern, replacement, block, count=1, flags=re.S)
    if count != 1:
        raise ManifestError(f"unable to locate {field} assignment in target class block")
    return updated


def update_class_block(block: str, hardening: HardeningData) -> str:
    genesis_assert_match = re.search(
        r'assert\(consensus\.hashGenesisBlock == uint256\{"([0-9a-f]{64})"\}\);',
        block,
    )
    if not genesis_assert_match:
        raise ManifestError("unable to find consensus.hashGenesisBlock assertion")
    chainparams_genesis = genesis_assert_match.group(1)
    if chainparams_genesis != hardening.genesis_hash:
        raise ManifestError(
            "manifest genesis hash does not match chainparams genesis "
            f"({hardening.genesis_hash} != {chainparams_genesis})"
        )

    block = update_once(
        block,
        r'        consensus\.nMinimumChainWork = uint256\{"[0-9a-f]{64}"\};',
        (
            "        consensus.nMinimumChainWork = uint256{"
            f"\"{hardening.minimum_chain_work}\""
            "};"
        ),
        "nMinimumChainWork",
    )
    block = update_once(
        block,
        r'        consensus\.defaultAssumeValid = uint256\{"[0-9a-f]{64}"\};',
        (
            "        consensus.defaultAssumeValid = uint256{"
            f"\"{hardening.anchor_hash}\""
            "};"
        ),
        "defaultAssumeValid",
    )

    checkpoint_by_height: dict[int, str] = {}
    for height, checkpoint_hash in (
        (0, hardening.genesis_hash),
        (hardening.anchor_height, hardening.anchor_hash),
    ):
        existing_hash = checkpoint_by_height.get(height)
        if existing_hash is not None and existing_hash != checkpoint_hash:
            raise ManifestError(
                "manifest yields conflicting checkpoint hashes at the same height "
                f"({height}: {existing_hash} vs {checkpoint_hash})"
            )
        checkpoint_by_height[height] = checkpoint_hash

    checkpoint_lines = "\n".join(
        f"                {{{height}, uint256{{\"{checkpoint_hash}\"}}}},"
        for height, checkpoint_hash in sorted(checkpoint_by_height.items())
    )
    checkpoint_block = (
        "        checkpointData = {\n"
        "            {\n"
        f"{checkpoint_lines}\n"
        "            }\n"
        "        };"
    )
    block = update_once(
        block,
        r"        checkpointData = \{.*?\n        \};",
        checkpoint_block,
        "checkpointData",
    )

    chain_tx_data_block = (
        "        chainTxData = ChainTxData{\n"
        f"            .nTime = {hardening.chain_tx_time},\n"
        f"            .tx_count = {hardening.chain_tx_count},\n"
        f"            .dTxRate = {format_rate(hardening.chain_tx_rate)},\n"
        "        };"
    )
    block = update_once(
        block,
        r"        chainTxData = ChainTxData\{.*?\n        \};",
        chain_tx_data_block,
        "chainTxData",
    )
    return block


def main() -> int:
    args = parse_args()
    try:
        hardening = parse_manifest(args.manifest)
        if hardening.chain != args.chain:
            raise ManifestError(
                f"manifest chain `{hardening.chain}` does not match --chain `{args.chain}`"
            )

        source = args.chainparams.read_text(encoding="utf-8")
        class_name = class_name_for_chain(args.chain)
        class_pattern = rf"class {class_name} : public CChainParams \{{.*?\n\}};\n"
        class_match = re.search(class_pattern, source, flags=re.S)
        if not class_match:
            raise ManifestError(f"unable to locate class block for {class_name}")

        original_block = class_match.group(0)
        updated_block = update_class_block(original_block, hardening)
        updated_source = source.replace(original_block, updated_block, 1)

        if args.check:
            if updated_source != source:
                print(
                    "error: chainparams does not match manifest for requested chain",
                    file=sys.stderr,
                )
                return 1
            print("chainparams hardening check: PASS")
            return 0

        if updated_source != source:
            args.chainparams.write_text(updated_source, encoding="utf-8")
        print(f"updated {args.chainparams} for chain {args.chain}")
        return 0
    except (ManifestError, OSError, json.JSONDecodeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
