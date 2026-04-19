#!/usr/bin/env python3
"""BTX M7 miner/pool readiness helper."""

from __future__ import annotations

import argparse
import json
import os
import pathlib
import socket
import subprocess
import tempfile
import time
from decimal import Decimal, ROUND_DOWN
from datetime import datetime, timezone
from typing import List, Optional


EXPECTED_NONCE_RANGE = "0000000000000000ffffffffffffffff"
DEFAULT_MATURITY_BLOCKS = 110
WALLET_NAME = "m7_pool"
DEFAULT_RPC_CLIENT_TIMEOUT_SECONDS = 120


def parse_args() -> argparse.Namespace:
    root_dir = pathlib.Path(__file__).resolve().parents[1]
    default_build = root_dir / "build-btx"

    parser = argparse.ArgumentParser(
        description="Validate BTX miner/pool readiness on regtest and collect artifacts.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "build_dir",
        nargs="?",
        default=str(default_build),
        help="BTX build directory containing bin/btxd and bin/btx-cli (legacy aliases accepted).",
    )
    parser.add_argument(
        "--artifact",
        help="Optional path where the readiness artifact JSON should be written.",
    )
    parser.add_argument(
        "--chain",
        choices=["regtest", "testnet"],
        default="regtest",
        help="Chain to exercise.",
    )
    parser.add_argument(
        "--template-only",
        action="store_true",
        help=(
            "Only validate getblocktemplate job fields. This is forced for "
            "non-regtest chains."
        ),
    )
    parser.add_argument(
        "--backend",
        choices=["cpu", "metal", "mlx", "cuda"],
        default="cpu",
        help=(
            "Requested external-miner backend profile. CUDA remains disabled by "
            "default and will report CPU fallback unless explicitly enabled in build."
        ),
    )
    return parser.parse_args()


def ensure_executable(path: pathlib.Path) -> pathlib.Path:
    if not path.is_file() or not os.access(path, os.X_OK):
        raise FileNotFoundError(f"missing executable: {path}")
    return path


def resolve_binary(bin_dir: pathlib.Path, canonical_name: str, legacy_name: str) -> pathlib.Path:
    canonical = bin_dir / canonical_name
    if canonical.is_file() and os.access(canonical, os.X_OK):
        return canonical
    return ensure_executable(bin_dir / legacy_name)


def run_cli(
    cli_path: pathlib.Path,
    datadir: pathlib.Path,
    chain: str,
    args: List[str],
    *,
    wallet: Optional[str] = None,
    named: bool = False,
    rpc_port: Optional[int] = None,
) -> str:
    timeout_raw = os.getenv(
        "BTX_M7_RPC_CLIENT_TIMEOUT_SECONDS",
        str(DEFAULT_RPC_CLIENT_TIMEOUT_SECONDS),
    )
    try:
        rpc_client_timeout = int(timeout_raw)
    except ValueError:
        rpc_client_timeout = DEFAULT_RPC_CLIENT_TIMEOUT_SECONDS
    if rpc_client_timeout < 1:
        rpc_client_timeout = DEFAULT_RPC_CLIENT_TIMEOUT_SECONDS

    if rpc_port is None:
        env_rpc_port = os.getenv("BTX_RPC_PORT")
        if env_rpc_port and env_rpc_port.isdigit():
            rpc_port = int(env_rpc_port)

    cmd: List[str] = [
        str(cli_path),
        f"-datadir={datadir}",
        f"-rpcclienttimeout={rpc_client_timeout}",
    ]
    if chain != "main":
        cmd.append(f"-{chain}")
    if rpc_port is not None:
        cmd.append(f"-rpcport={rpc_port}")
    if wallet:
        cmd.append(f"-rpcwallet={wallet}")
    if named:
        cmd.append("-named")
    cmd.extend(args)
    result = subprocess.run(cmd, check=True, capture_output=True, text=True)
    return result.stdout.strip()


def wait_for_rpc(
    cli_path: pathlib.Path,
    datadir: pathlib.Path,
    chain: str,
    daemon: Optional[subprocess.Popen[str]] = None,
) -> None:
    for _ in range(60):
        if daemon is not None and daemon.poll() is not None:
            raise RuntimeError("btxd exited before RPC became available")
        try:
            run_cli(cli_path, datadir, chain, ["getblockcount"])
            return
        except subprocess.CalledProcessError:
            time.sleep(1)
    raise RuntimeError("timed out waiting for btxd RPC availability")


def find_free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def rpc_error_output(err: subprocess.CalledProcessError) -> str:
    return f"{err.stdout}\n{err.stderr}".strip().lower()


def indicates_missing_method(output: str) -> bool:
    text = output.lower()
    return "unknown command" in text or "method not found" in text


def rpc_method_available(
    cli_path: pathlib.Path, datadir: pathlib.Path, chain: str, method: str
) -> bool:
    try:
        output = run_cli(cli_path, datadir, chain, ["help", method])
        return not indicates_missing_method(output)
    except subprocess.CalledProcessError as err:
        if indicates_missing_method(rpc_error_output(err)):
            return False
        raise


def resolve_template_only(chain: str, requested: bool) -> bool:
    if chain == "regtest":
        return requested
    return True


def query_backend_info(
    backend_info_bin: pathlib.Path, requested_backend: str
) -> dict:
    fallback = {
        "requested_input": requested_backend,
        "requested_known": requested_backend in {"cpu", "metal", "mlx", "cuda"},
        "requested_backend": requested_backend
        if requested_backend in {"cpu", "metal", "cuda"}
        else ("metal" if requested_backend == "mlx" else "cpu"),
        "active_backend": "cpu",
        "selection_reason": "backend_info_binary_missing_fallback_to_cpu",
        "capabilities": {
            "cpu": {
                "compiled": True,
                "available": True,
                "reason": "always_available",
            },
            "metal": {
                "compiled": False,
                "available": False,
                "reason": "unknown",
            },
            "cuda": {
                "compiled": False,
                "available": False,
                "reason": "disabled_by_build",
            },
        },
    }

    if not backend_info_bin.is_file():
        return fallback

    try:
        result = subprocess.run(
            [str(backend_info_bin), "--backend", requested_backend],
            check=True,
            capture_output=True,
            text=True,
        )
        payload = json.loads(result.stdout)
        if isinstance(payload, dict):
            return payload
    except (subprocess.CalledProcessError, json.JSONDecodeError):
        pass

    fallback["selection_reason"] = "backend_info_probe_failed_fallback_to_cpu"
    return fallback


def build_sendtoaddress_args(destination: str) -> List[str]:
    """Construct a stable sendtoaddress invocation for pool E2E checks."""
    return [
        "sendtoaddress",
        f"address={destination}",
        "amount=1",
        "subtractfeefromamount=false",
        "replaceable=true",
        "fee_rate=30",
        "verbose=false",
    ]


def build_raw_spend_fallback(
    cli_path: pathlib.Path,
    datadir: pathlib.Path,
    chain: str,
    *,
    wallet: str,
    destination: str,
    change_address: str,
    rpc_port: Optional[int],
) -> str:
    """Spend an explicit mature UTXO if sendtoaddress fails with insufficient funds."""
    unspent = json.loads(
        run_cli(
            cli_path,
            datadir,
            chain,
            ["listunspent", "1", "9999999", "[]", "true"],
            wallet=wallet,
            rpc_port=rpc_port,
        )
    )
    if not unspent:
        raise RuntimeError("fallback raw spend failed: wallet has no spendable UTXOs")

    selected = max(unspent, key=lambda entry: Decimal(str(entry.get("amount", "0"))))
    selected_amount = Decimal(str(selected["amount"]))
    send_amount = Decimal("1.0")
    fee_amount = Decimal("0.00010000")
    change_amount = (selected_amount - send_amount - fee_amount).quantize(
        Decimal("0.00000001"), rounding=ROUND_DOWN
    )
    if change_amount <= Decimal("0"):
        raise RuntimeError(
            "fallback raw spend failed: selected UTXO too small "
            f"(amount={selected_amount})"
        )

    inputs_json = json.dumps(
        [{"txid": selected["txid"], "vout": int(selected["vout"])}],
        separators=(",", ":"),
    )
    outputs = {destination: float(send_amount), change_address: float(change_amount)}
    outputs_json = json.dumps(outputs, separators=(",", ":"))

    raw_tx = run_cli(
        cli_path,
        datadir,
        chain,
        ["createrawtransaction", f"inputs={inputs_json}", f"outputs={outputs_json}"],
        wallet=wallet,
        named=True,
        rpc_port=rpc_port,
    )
    signed = json.loads(
        run_cli(
            cli_path,
            datadir,
            chain,
            ["signrawtransactionwithwallet", raw_tx],
            wallet=wallet,
            rpc_port=rpc_port,
        )
    )
    if not signed.get("complete"):
        raise RuntimeError("fallback raw spend failed: signing incomplete")
    return run_cli(
        cli_path,
        datadir,
        chain,
        ["sendrawtransaction", signed["hex"]],
        rpc_port=rpc_port,
    )


def build_direct_coinbase_spend(
    cli_path: pathlib.Path,
    datadir: pathlib.Path,
    chain: str,
    *,
    wallet: str,
    destination: str,
    change_address: str,
    rpc_port: Optional[int],
) -> str:
    """Spend block-1 coinbase directly for deterministic pool-E2E funding."""
    spend_block_hash = run_cli(
        cli_path, datadir, chain, ["getblockhash", "1"], rpc_port=rpc_port
    )
    spend_block = json.loads(
        run_cli(
            cli_path,
            datadir,
            chain,
            ["getblock", spend_block_hash, "2"],
            rpc_port=rpc_port,
        )
    )
    coinbase_tx = spend_block["tx"][0]
    selected_amount = Decimal(str(coinbase_tx["vout"][0]["value"]))
    send_amount = Decimal("1.0")
    fee_amount = Decimal("0.00010000")
    change_amount = (selected_amount - send_amount - fee_amount).quantize(
        Decimal("0.00000001"), rounding=ROUND_DOWN
    )
    if change_amount <= Decimal("0"):
        raise RuntimeError(
            "direct coinbase spend failed: selected coinbase output too small "
            f"(amount={selected_amount})"
        )

    inputs_json = json.dumps(
        [{"txid": coinbase_tx["txid"], "vout": 0}],
        separators=(",", ":"),
    )
    outputs = {destination: float(send_amount), change_address: float(change_amount)}
    outputs_json = json.dumps(outputs, separators=(",", ":"))

    raw_tx = run_cli(
        cli_path,
        datadir,
        chain,
        ["createrawtransaction", f"inputs={inputs_json}", f"outputs={outputs_json}"],
        named=True,
        rpc_port=rpc_port,
    )
    signed = json.loads(
        run_cli(
            cli_path,
            datadir,
            chain,
            ["signrawtransactionwithwallet", raw_tx],
            wallet=wallet,
            rpc_port=rpc_port,
        )
    )
    if not signed.get("complete"):
        raise RuntimeError("direct coinbase spend failed: signing incomplete")
    return run_cli(
        cli_path,
        datadir,
        chain,
        ["sendrawtransaction", signed["hex"]],
        rpc_port=rpc_port,
    )


def send_with_fallback(
    cli_path: pathlib.Path,
    datadir: pathlib.Path,
    chain: str,
    *,
    wallet: str,
    destination: str,
    change_address: str,
    rpc_port: Optional[int],
) -> str:
    """Prefer sendtoaddress, then fallback to explicit UTXO spend on known wallet edge-case."""
    try:
        return run_cli(
            cli_path,
            datadir,
            chain,
            build_sendtoaddress_args(destination),
            wallet=wallet,
            named=True,
            rpc_port=rpc_port,
        )
    except subprocess.CalledProcessError as err:
        err_text = rpc_error_output(err)
        if "insufficient funds" not in err_text:
            raise
        try:
            return build_raw_spend_fallback(
                cli_path,
                datadir,
                chain,
                wallet=wallet,
                destination=destination,
                change_address=change_address,
                rpc_port=rpc_port,
            )
        except RuntimeError:
            # Wallet trusted-balance can lag coinbase maturity accounting. Spend
            # the matured block-1 coinbase directly to exercise the real relay path.
            return build_direct_coinbase_spend(
                cli_path,
                datadir,
                chain,
                wallet=wallet,
                destination=destination,
                change_address=change_address,
                rpc_port=rpc_port,
            )


def main() -> int:
    args = parse_args()
    build_dir = pathlib.Path(args.build_dir).resolve()
    bitcoind = resolve_binary(build_dir / "bin", "btxd", "bitcoind")
    bitcoin_cli = resolve_binary(build_dir / "bin", "btx-cli", "bitcoin-cli")
    backend_info_bin = build_dir / "bin" / "btx-matmul-backend-info"

    rpc_port = find_free_port()
    previous_rpc_port = os.environ.get("BTX_RPC_PORT")
    os.environ["BTX_RPC_PORT"] = str(rpc_port)
    template_only = resolve_template_only(args.chain, args.template_only)
    backend_info = query_backend_info(backend_info_bin, args.backend)

    try:
        with tempfile.TemporaryDirectory(prefix="btx-m7-pool-") as datadir_raw:
            datadir = pathlib.Path(datadir_raw)
            daemon_cmd = [
                str(bitcoind),
                f"-datadir={datadir}",
                f"-{args.chain}",
                f"-rpcport={rpc_port}",
                "-autoshieldcoinbase=0",
                "-server=1",
                "-listen=0",
                "-fallbackfee=0.0001",
                "-printtoconsole=0",
            ]
            if args.chain == "regtest":
                daemon_cmd.append("-test=matmulstrict")
            else:
                # Avoid IBD gating for isolated local testnet template checks.
                daemon_cmd.append("-maxtipage=999999999")

            daemon = subprocess.Popen(
                daemon_cmd,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            try:
                wait_for_rpc(bitcoin_cli, datadir, args.chain, daemon)

                wallet_enabled = rpc_method_available(
                    bitcoin_cli, datadir, args.chain, "createwallet"
                )

                txid: Optional[str] = None
                mempool_entry: Optional[dict] = None
                wallet_tx: Optional[dict] = None
                payout_address: Optional[str] = None
                payout_descriptor = "raw(51)"
                selected_transactions = "[]"

                if template_only:
                    wallet_enabled = False
                elif wallet_enabled:
                    try:
                        run_cli(
                            bitcoin_cli,
                            datadir,
                            args.chain,
                            [
                                "createwallet",
                                f"wallet_name={WALLET_NAME}",
                                "descriptors=true",
                                "load_on_startup=false",
                                "blank=false",
                                "avoid_reuse=false",
                                "disable_private_keys=false",
                                "external_signer=false",
                            ],
                            named=True,
                        )
                    except subprocess.CalledProcessError as err:
                        if indicates_missing_method(rpc_error_output(err)):
                            wallet_enabled = False
                        else:
                            raise

                if wallet_enabled and not template_only:
                    payout_address = run_cli(
                        bitcoin_cli,
                        datadir,
                        args.chain,
                        ["getnewaddress", "pool-payout"],
                        wallet=WALLET_NAME,
                    )
                    payout_descriptor = f"addr({payout_address})"
                    run_cli(
                        bitcoin_cli,
                        datadir,
                        args.chain,
                        [
                            "generatetoaddress",
                            str(DEFAULT_MATURITY_BLOCKS),
                            payout_address,
                        ],
                    )

                    destination = run_cli(
                        bitcoin_cli,
                        datadir,
                        args.chain,
                        ["getnewaddress", "pool-target"],
                        wallet=WALLET_NAME,
                    )
                    txid = send_with_fallback(
                        bitcoin_cli,
                        datadir,
                        args.chain,
                        wallet=WALLET_NAME,
                        destination=destination,
                        change_address=payout_address,
                        rpc_port=rpc_port,
                    )

                    for _ in range(30):
                        mempool = json.loads(
                            run_cli(bitcoin_cli, datadir, args.chain, ["getrawmempool"])
                        )
                        if txid in mempool:
                            break
                        time.sleep(1)
                    else:
                        raise RuntimeError("transaction failed to reach mempool")

                    mempool_entry = json.loads(
                        run_cli(
                            bitcoin_cli, datadir, args.chain, ["getmempoolentry", txid]
                        )
                    )
                    wallet_tx = json.loads(
                        run_cli(
                            bitcoin_cli,
                            datadir,
                            args.chain,
                            ["gettransaction", txid],
                            wallet=WALLET_NAME,
                        )
                    )
                    selected_transactions = f'["{txid}"]'
                elif not template_only:
                    run_cli(
                        bitcoin_cli,
                        datadir,
                        args.chain,
                        ["generatetodescriptor", "3", payout_descriptor],
                    )

                gbt = json.loads(
                    run_cli(
                        bitcoin_cli,
                        datadir,
                        args.chain,
                        ["getblocktemplate", '{"rules":["segwit"]}'],
                    )
                )
                if gbt.get("noncerange") != EXPECTED_NONCE_RANGE:
                    raise RuntimeError(
                        f"unexpected noncerange {gbt.get('noncerange')} (expected {EXPECTED_NONCE_RANGE})"
                    )

                submission: Optional[dict] = None
                if not template_only:
                    block_obj = json.loads(
                        run_cli(
                            bitcoin_cli,
                            datadir,
                            args.chain,
                            [
                                "generateblock",
                                f"output={payout_descriptor}",
                                f"transactions={selected_transactions}",
                                "submit=false",
                            ],
                            named=True,
                        )
                    )
                    block_hash = block_obj["hash"]
                    block_hex = block_obj["hex"]
                    submit_result = run_cli(
                        bitcoin_cli, datadir, args.chain, ["submitblock", block_hex]
                    )
                    if submit_result not in ("", "null"):
                        raise RuntimeError(f"submitblock returned error: {submit_result}")

                    header = json.loads(
                        run_cli(
                            bitcoin_cli, datadir, args.chain, ["getblockheader", block_hash]
                        )
                    )
                    header_hex = run_cli(
                        bitcoin_cli,
                        datadir,
                        args.chain,
                        ["getblockheader", block_hash, "false"],
                    )
                    header_raw = bytes.fromhex(header_hex)
                    nonce64 = int.from_bytes(header_raw[76:84], byteorder="little")
                    matmul_digest = header_raw[84:116][::-1].hex()
                    block_json = json.loads(
                        run_cli(bitcoin_cli, datadir, args.chain, ["getblock", block_hash])
                    )

                    best_hash = run_cli(
                        bitcoin_cli, datadir, args.chain, ["getbestblockhash"]
                    )
                    if best_hash != block_hash:
                        raise RuntimeError("submitted block is not the chain tip")

                    if txid is not None:
                        mempool_after = json.loads(
                            run_cli(bitcoin_cli, datadir, args.chain, ["getrawmempool"])
                        )
                        if txid in mempool_after:
                            raise RuntimeError(
                                "transaction still in mempool after submission"
                            )

                    try:
                        hex_bytes = len(bytes.fromhex(block_hex))
                    except ValueError as exc:
                        raise RuntimeError(
                            "invalid block hex returned by generateblock"
                        ) from exc

                    submission = {
                        "block_hash": block_hash,
                        "height": block_json.get("height"),
                        "matmul_digest": matmul_digest,
                        "nonce": header.get("nonce"),
                        "nonce64": nonce64,
                        "hex_bytes": hex_bytes,
                        "tx": block_json.get("tx"),
                    }

                readiness = {
                    "generated_at": datetime.now(timezone.utc).isoformat().replace(
                        "+00:00", "Z"
                    ),
                    "chain": args.chain,
                    "requested_backend": args.backend,
                    "backend": backend_info,
                    "matmul_strict": args.chain == "regtest",
                    "template_only": template_only,
                    "wallet_enabled": wallet_enabled,
                    "payout_address": payout_address,
                    "payout_descriptor": payout_descriptor,
                    "stratum_job": {
                        "height": gbt["height"],
                        "previousblockhash": gbt["previousblockhash"],
                        "bits": gbt["bits"],
                        "target": gbt["target"],
                        "noncerange": gbt["noncerange"],
                        "coinbasevalue": gbt["coinbasevalue"],
                        "default_witness_commitment": gbt.get(
                            "default_witness_commitment"
                        ),
                        "transactions": [txid] if txid else [],
                    },
                    "mempool_entry": (
                        {
                            "txid": txid,
                            "wtxid": mempool_entry.get("wtxid"),
                            "vsize": mempool_entry.get("vsize"),
                            "weight": mempool_entry.get("weight"),
                            "fee": mempool_entry.get("fees", {}).get("base"),
                            "bip125-replaceable": mempool_entry.get(
                                "bip125-replaceable"
                            ),
                            "descendantcount": mempool_entry.get("descendantcount"),
                        }
                        if mempool_entry is not None
                        else None
                    ),
                    "wallet_transaction": (
                        {
                            "amount": wallet_tx.get("amount"),
                            "fee": wallet_tx.get("fee"),
                            "confirmations": wallet_tx.get("confirmations"),
                            "details": wallet_tx.get("details"),
                            "hex": wallet_tx.get("hex"),
                        }
                        if wallet_tx is not None
                        else None
                    ),
                    "submission": submission,
                }

                if args.artifact:
                    artifact_path = pathlib.Path(args.artifact)
                    artifact_path.parent.mkdir(parents=True, exist_ok=True)
                    with artifact_path.open("w", encoding="utf-8") as handle:
                        json.dump(readiness, handle, indent=2)
                        handle.write("\n")

                print("BTX miner/pool readiness checks passed:")
                print(
                    f"- Template height {gbt['height']} with noncerange {gbt['noncerange']}"
                )
                print(
                    f"- Backend selection requested={backend_info.get('requested_input')} "
                    f"active={backend_info.get('active_backend')} "
                    f"reason={backend_info.get('selection_reason')}"
                )
                if template_only:
                    print(
                        "- Template-only mode: validated testnet mining job fields "
                        "without local block submission"
                    )
                elif txid:
                    print(
                        f"- TX {txid} mined via generateblock submit=false / submitblock path"
                    )
                else:
                    print(
                        "- Wallet RPC not available; verified coinbase-only generateblock/submitblock path"
                    )
                if submission is not None:
                    print(f"- Accepted block {submission['block_hash']} now chain tip")
                if args.artifact:
                    print(f"- Artifact written to {args.artifact}")
            finally:
                try:
                    run_cli(bitcoin_cli, datadir, args.chain, ["stop"])
                except subprocess.CalledProcessError:
                    pass
                try:
                    daemon.wait(timeout=30)
                except subprocess.TimeoutExpired:
                    daemon.kill()
                    daemon.wait(timeout=10)
    finally:
        if previous_rpc_port is None:
            os.environ.pop("BTX_RPC_PORT", None)
        else:
            os.environ["BTX_RPC_PORT"] = previous_rpc_port

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
