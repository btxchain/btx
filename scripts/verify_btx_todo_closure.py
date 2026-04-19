#!/usr/bin/env python3
"""
Verify closure of the production-readiness TODO items called out for BTX launch.
"""

from __future__ import annotations

import re
import sys
import time
from pathlib import Path


def require(condition: bool, message: str, errors: list[str]) -> None:
    if not condition:
        errors.append(message)


def extract_class_block(source: str, class_name: str) -> str:
    match = re.search(rf"class {class_name}.*?\n}};\n", source, flags=re.S)
    return match.group(0) if match else ""


def extract_uint256_assignment(source: str, field_name: str) -> str | None:
    match = re.search(
        rf"{re.escape(field_name)}\s*=\s*uint256\{{(?:(?:\"([0-9a-f]{{64}})\")?)\}};",
        source,
    )
    if not match:
        return None
    return match.group(1) or ""


def main() -> int:
    repo_root = Path(__file__).resolve().parents[1]
    workspace_root = repo_root.parent

    chainparams_path = repo_root / "src/kernel/chainparams.cpp"
    chainparamsseeds_path = repo_root / "src/chainparamsseeds.h"
    rpc_mining_path = repo_root / "src/rpc/mining.cpp"
    node_readme_path = repo_root / "README.md"
    workspace_readme_path = workspace_root / "README.md"
    spec_path = repo_root / "doc/btx-matmul-pow-spec.md"
    m7_path = repo_root / "scripts/m7_miner_pool_e2e.py"

    chainparams_text = chainparams_path.read_text(encoding="utf-8")
    chainparamsseeds_text = chainparamsseeds_path.read_text(encoding="utf-8")
    rpc_mining_text = rpc_mining_path.read_text(encoding="utf-8")
    node_readme = node_readme_path.read_text(encoding="utf-8")
    workspace_readme = workspace_readme_path.read_text(encoding="utf-8") if workspace_readme_path.exists() else ""
    spec_text = spec_path.read_text(encoding="utf-8")

    errors: list[str] = []
    warnings_out: list[str] = []
    bootstrap_chainwork = "0000000000000000000000000000000000000000000000000000000100010001"
    launch_epoch = 1771726946  # 2026-02-22 02:22:26 UTC
    post_launch_grace_seconds = 30 * 24 * 60 * 60

    # Genesis script must no longer be the placeholder hash.
    require(
        "76a9141a2b3c4d5e6f708192a3b4c5d6e7f80910111288ac" not in chainparams_text,
        "placeholder genesis P2PKH script hash is still present",
        errors,
    )
    require(
        "5220afa45d6891836c7314dded4dbd0e7aacde3de0d7fa9a12aeac06e2296c794226" in chainparams_text,
        "launch genesis P2MR script commitment is missing",
        errors,
    )

    require(
        "node.btx.tools." in chainparams_text,
        "missing required live mainnet DNS seed: node.btx.tools.",
        errors,
    )
    for stale_seed in (
        "node.btxchain.org.",
        "node.btx.dev.",
    ):
        require(stale_seed not in chainparams_text, f"stale mainnet DNS seed still present: {stale_seed}", errors)
    require(
        "static const uint8_t chainparams_seed_main[] = {" in chainparamsseeds_text,
        "mainnet fixed seeds are still empty",
        errors,
    )

    # Testnet should mirror mainnet's all-active-from-genesis BIP policy.
    testnet_block = extract_class_block(chainparams_text, "CTestNetParams")
    require(bool(testnet_block), "unable to locate CTestNetParams block", errors)
    if testnet_block:
        for token in (
            "consensus.BIP34Height = 0;",
            "consensus.BIP65Height = 0;",
            "consensus.BIP66Height = 0;",
            "consensus.CSVHeight = 0;",
            "consensus.SegwitHeight = 0;",
            "consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].nStartTime = Consensus::BIP9Deployment::ALWAYS_ACTIVE;",
            "consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;",
        ):
            require(token in testnet_block, f"testnet activation mismatch: missing `{token}`", errors)

    # Fresh-chain bootstrap defaults should no longer be empty for main/test networks.
    main_block = extract_class_block(chainparams_text, "CMainParams")
    require(bool(main_block), "unable to locate CMainParams block", errors)
    if main_block:
        main_chainwork = extract_uint256_assignment(main_block, "consensus.nMinimumChainWork")
        require(
            main_chainwork not in (None, ""),
            "mainnet nMinimumChainWork assignment is missing",
            errors,
        )
        main_assumevalid = extract_uint256_assignment(main_block, "consensus.defaultAssumeValid")
        require(
            main_assumevalid not in (None, ""),
            "mainnet defaultAssumeValid is not set",
            errors,
        )
        if bootstrap_chainwork in main_block and time.time() >= launch_epoch + post_launch_grace_seconds:
            warnings_out.append("mainnet nMinimumChainWork still equals bootstrap floor >30 days after launch")
        checkpoint_section = re.search(r"checkpointData\s*=\s*\{.*?\};", main_block, flags=re.S)
        checkpoint_text = checkpoint_section.group(0) if checkpoint_section else ""
        checkpoint_entries = re.findall(r"\{\s*\d+\s*,", checkpoint_text)
        checkpoint_hashes = re.findall(r'uint256\{"([0-9a-f]{64})"\}', checkpoint_text)
        if main_assumevalid not in (None, "") and checkpoint_hashes:
            require(
                main_assumevalid == checkpoint_hashes[-1],
                "mainnet defaultAssumeValid does not match the anchored checkpoint hash",
                errors,
            )
        if len(checkpoint_entries) <= 1 and time.time() >= launch_epoch + post_launch_grace_seconds:
            warnings_out.append("mainnet checkpoints still genesis-only >30 days after launch")

    test_chainwork = extract_uint256_assignment(testnet_block, "consensus.nMinimumChainWork")
    require(
        test_chainwork is not None,
        "testnet nMinimumChainWork assignment is missing",
        errors,
    )
    test_assumevalid = extract_uint256_assignment(testnet_block, "consensus.defaultAssumeValid")
    require(
        test_assumevalid not in (None, ""),
        "testnet defaultAssumeValid is not set",
        errors,
    )

    # README/docs alignment: no KAWPOW references in top-level READMEs.
    require("MatMul" in node_readme, "btx-node README does not mention MatMul", errors)
    require(re.search(r"kawpow", node_readme, re.I) is None, "btx-node README still references KAWPOW", errors)
    if workspace_readme:
        require("MatMul" in workspace_readme, "workspace README does not mention MatMul", errors)
        require(re.search(r"kawpow", workspace_readme, re.I) is None, "workspace README still references KAWPOW", errors)

    # Block payload bandwidth note remains documented in the main spec.
    require(
        re.search(r"~?4\s*MB", spec_text) is not None,
        "MatMul payload size note (~4 MB) is missing from the spec",
        errors,
    )

    # External mining path remains GBT/submitblock, with pool E2E script coverage.
    require(
        "External miners should solve the MatMul proof using the provided seeds and submit via submitblock."
        in rpc_mining_text,
        "getblocktemplate mining guidance for external MatMul miners is missing",
        errors,
    )
    require(m7_path.exists(), "m7 miner/pool E2E script is missing", errors)

    if errors:
        for error in errors:
            print(f"[FAIL] {error}", file=sys.stderr)
        return 1

    for warning in warnings_out:
        print(f"[WARN] {warning}", file=sys.stderr)

    print("verify_btx_todo_closure: PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())
