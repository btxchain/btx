#!/usr/bin/env python3
"""Live regtest runtime validation for BTX production hardening.

Runs a real btxd node and validates:
- sustained mining and block header/difficulty observations
- transparent -> shielded -> transparent wallet flow
- 2-of-3 PQ multisig funding and spend via PSBT

Outputs a JSON artifact with concrete runtime evidence.
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import socket
import subprocess
import tempfile
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from decimal import Decimal
from pathlib import Path
from statistics import mean, median
from typing import Any, Callable


class RPCError(RuntimeError):
    pass


@dataclass
class RPCClient:
    rpc_port: int
    datadir: Path
    default_timeout_s: int = 60

    def _auth_header(self) -> str:
        cookie_path = self.datadir / "regtest" / ".cookie"
        cookie = cookie_path.read_text(encoding="utf-8").strip()
        token = base64.b64encode(cookie.encode("utf-8")).decode("ascii")
        return f"Basic {token}"

    def call(
        self,
        method: str,
        params: list[Any] | None = None,
        wallet: str | None = None,
        timeout_s: int | None = None,
    ) -> Any:
        params = params or []
        timeout_s = timeout_s if timeout_s is not None else self.default_timeout_s
        path = f"/wallet/{wallet}" if wallet else "/"
        body = json.dumps({"jsonrpc": "1.0", "id": "live", "method": method, "params": params}).encode("utf-8")
        req = urllib.request.Request(
            url=f"http://127.0.0.1:{self.rpc_port}{path}",
            data=body,
            headers={
                "Content-Type": "application/json",
                "Authorization": self._auth_header(),
            },
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=timeout_s) as resp:
                payload = json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as e:
            body = e.read().decode("utf-8", errors="replace")
            try:
                err_payload = json.loads(body)
                if err_payload.get("error") is not None:
                    raise RPCError(f"RPC error calling {method}: {err_payload['error']}") from e
            except json.JSONDecodeError:
                pass
            raise RPCError(f"RPC transport error calling {method}: HTTP {e.code} {e.reason}; body={body}") from e
        except TimeoutError as e:
            raise RPCError(f"RPC timeout calling {method} after {timeout_s}s: {e}") from e
        except socket.timeout as e:
            raise RPCError(f"RPC timeout calling {method} after {timeout_s}s: {e}") from e
        except urllib.error.URLError as e:
            raise RPCError(f"RPC transport error calling {method}: {e}") from e

        if payload.get("error") is not None:
            raise RPCError(f"RPC error calling {method}: {payload['error']}")
        return payload["result"]


def find_free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def wait_for_rpc(rpc: RPCClient, timeout_s: int = 120) -> None:
    deadline = time.time() + timeout_s
    last_err = None
    while time.time() < deadline:
        try:
            rpc.call("getblockcount")
            return
        except Exception as e:  # noqa: BLE001
            last_err = e
            time.sleep(0.25)
    raise RuntimeError(f"Timed out waiting for RPC: {last_err}")


def d(value: Any) -> Decimal:
    return Decimal(str(value))


def call_z_sendmany(
    rpc: RPCClient,
    wallet: str,
    outputs: list[dict[str, Any]],
    timeout_s: int | None = None,
) -> str:
    result = rpc.call("z_sendmany", [outputs], wallet=wallet, timeout_s=timeout_s)
    if isinstance(result, dict):
        return str(result["txid"])
    return str(result)


def ensure(cond: bool, msg: str) -> None:
    if not cond:
        raise RuntimeError(msg)


def mine_to_address(
    rpc: RPCClient,
    wallet: str,
    address: str,
    blocks: int,
    batch_size: int,
    mining_timeout_s: int,
    context: str = "mine",
) -> None:
    ensure(blocks >= 0, "blocks must be non-negative")
    ensure(batch_size > 0, "batch_size must be positive")
    remaining = blocks
    mined = 0
    while remaining > 0:
        chunk = min(remaining, batch_size)
        rpc.call(
            "generatetoaddress",
            [chunk, address],
            wallet=wallet,
            timeout_s=mining_timeout_s,
        )
        remaining -= chunk
        mined += chunk
        if blocks >= max(2 * batch_size, 20):
            print(f"[INFO] {context}: mined {mined}/{blocks}", flush=True)


def spend_mature_coinbase(
    rpc: RPCClient,
    *,
    next_height_provider: Callable[[], int],
    destination_addr: str,
    change_addr: str,
    amount: Decimal,
    fee: Decimal = Decimal("0.0001"),
    context: str = "coinbase_spend",
) -> str:
    chain_height = int(rpc.call("getblockcount"))
    max_mature_height = chain_height - 100
    if max_mature_height < 1:
        raise RuntimeError(f"{context}: no mature coinbase available (height={chain_height})")

    candidate = next_height_provider()
    while candidate <= max_mature_height:
        block_hash = str(rpc.call("getblockhash", [candidate]))
        block = rpc.call("getblock", [block_hash, 2])
        coinbase = block["tx"][0]
        prev_txid = str(coinbase["txid"])

        # Skip already-spent coinbase outputs.
        txout = rpc.call("gettxout", [prev_txid, 0])
        if txout is None:
            candidate += 1
            continue

        prev_value = d(txout["value"])
        change = (prev_value - amount - fee).quantize(Decimal("0.00000001"))
        if change <= Decimal("0"):
            candidate += 1
            continue

        raw = rpc.call(
            "createrawtransaction",
            [
                [{"txid": prev_txid, "vout": 0}],
                {destination_addr: float(amount), change_addr: float(change)},
            ],
        )
        signed = rpc.call("signrawtransactionwithwallet", [raw], wallet="miner")
        if not bool(signed.get("complete", False)):
            raise RuntimeError(f"{context}: incomplete signature at coinbase height {candidate}")
        return str(rpc.call("sendrawtransaction", [signed["hex"]]))

    raise RuntimeError(f"{context}: exhausted mature coinbase heights up to {max_mature_height}")


def split_mature_coinbase(
    rpc: RPCClient,
    *,
    next_height_provider: Callable[[], int],
    destination_amounts: dict[str, Decimal],
    change_addr: str,
    fee: Decimal = Decimal("0.0001"),
    context: str = "coinbase_split",
) -> str:
    if not destination_amounts:
        raise RuntimeError(f"{context}: destination set is empty")

    total_dest = Decimal("0")
    for amount in destination_amounts.values():
        if amount <= Decimal("0"):
            raise RuntimeError(f"{context}: destination amount must be positive")
        total_dest += amount

    chain_height = int(rpc.call("getblockcount"))
    max_mature_height = chain_height - 100
    if max_mature_height < 1:
        raise RuntimeError(f"{context}: no mature coinbase available (height={chain_height})")

    candidate = next_height_provider()
    while candidate <= max_mature_height:
        block_hash = str(rpc.call("getblockhash", [candidate]))
        block = rpc.call("getblock", [block_hash, 2])
        coinbase = block["tx"][0]
        prev_txid = str(coinbase["txid"])

        txout = rpc.call("gettxout", [prev_txid, 0])
        if txout is None:
            candidate += 1
            continue

        prev_value = d(txout["value"])
        change = (prev_value - total_dest - fee).quantize(Decimal("0.00000001"))
        if change <= Decimal("0"):
            candidate += 1
            continue

        outputs: dict[str, float] = {addr: float(amount) for addr, amount in destination_amounts.items()}
        outputs[change_addr] = float(change)

        raw = rpc.call(
            "createrawtransaction",
            [
                [{"txid": prev_txid, "vout": 0}],
                outputs,
            ],
        )
        signed = rpc.call("signrawtransactionwithwallet", [raw], wallet="miner")
        if not bool(signed.get("complete", False)):
            raise RuntimeError(f"{context}: incomplete signature at coinbase height {candidate}")
        return str(rpc.call("sendrawtransaction", [signed["hex"]]))

    raise RuntimeError(f"{context}: exhausted mature coinbase heights up to {max_mature_height}")


def wait_for_rpc_command_idle(rpc: RPCClient, method: str, timeout_s: int) -> None:
    """Wait until `method` no longer appears in active RPC commands."""
    deadline = time.time() + timeout_s
    while time.time() < deadline:
        try:
            active = rpc.call("getrpcinfo").get("active_commands", [])
        except Exception:
            return
        if all(str(cmd.get("method", "")) != method for cmd in active):
            return
        time.sleep(1)


def main() -> None:
    parser = argparse.ArgumentParser(description="Live regtest runtime validation")
    parser.add_argument("--build-dir", default="build-btx", help="Build dir containing btxd/btx-cli")
    parser.add_argument(
        "--artifact",
        default="/tmp/btx-live-regtest-runtime-validation.json",
        help="Artifact JSON output path",
    )
    parser.add_argument("--mine-blocks", type=int, default=430, help="Blocks to mine before runtime flows")
    parser.add_argument(
        "--mine-batch-size",
        type=int,
        default=200,
        help="Chunk size for generatetoaddress during long mining runs",
    )
    parser.add_argument(
        "--rpc-timeout-seconds",
        type=int,
        default=60,
        help="Default timeout for non-mining RPC calls",
    )
    parser.add_argument(
        "--mining-rpc-timeout-seconds",
        type=int,
        default=300,
        help="Timeout used for mining RPC calls",
    )
    parser.add_argument(
        "--shielded-rpc-timeout-seconds",
        type=int,
        default=600,
        help="Timeout used for shielded RPC calls (z_*)",
    )
    parser.add_argument(
        "--shielded-retry-attempts",
        type=int,
        default=6,
        help="Maximum retry attempts for shielded tx creation when mempool rejects transiently",
    )
    parser.add_argument(
        "--datadir",
        default="",
        help="Optional persistent datadir path. If omitted, a temporary datadir is used.",
    )
    parser.add_argument(
        "--keep-datadir",
        action="store_true",
        help="Preserve datadir after run (especially useful with --datadir).",
    )
    args = parser.parse_args()
    if args.mine_blocks < 1:
        raise RuntimeError("--mine-blocks must be >= 1")
    if args.mine_batch_size < 1:
        raise RuntimeError("--mine-batch-size must be >= 1")
    if args.rpc_timeout_seconds < 1:
        raise RuntimeError("--rpc-timeout-seconds must be >= 1")
    if args.mining_rpc_timeout_seconds < 1:
        raise RuntimeError("--mining-rpc-timeout-seconds must be >= 1")
    if args.shielded_rpc_timeout_seconds < 1:
        raise RuntimeError("--shielded-rpc-timeout-seconds must be >= 1")
    if args.shielded_retry_attempts < 1:
        raise RuntimeError("--shielded-retry-attempts must be >= 1")

    repo_root = Path(__file__).resolve().parents[1]
    build_dir = (repo_root / args.build_dir).resolve()
    btxd_bin = build_dir / "bin" / "btxd"
    if not btxd_bin.exists():
        legacy = build_dir / "bin" / "bitcoind"
        btxd_bin = legacy
    if not btxd_bin.exists():
        raise RuntimeError(f"Missing btxd/bitcoind in {build_dir / 'bin'}")

    if args.datadir:
        datadir = Path(args.datadir).resolve()
        datadir.mkdir(parents=True, exist_ok=True)
        datadir_is_temp = False
    else:
        datadir = Path(tempfile.mkdtemp(prefix="btx-live-runtime-"))
        datadir_is_temp = True
    rpc_port = find_free_port()
    p2p_port = find_free_port()

    node_stdout = datadir / "node.stdout.log"
    node_stderr = datadir / "node.stderr.log"
    stdout_fh = open(node_stdout, "ab")
    stderr_fh = open(node_stderr, "ab")

    node = subprocess.Popen(
        [
            str(btxd_bin),
            "-regtest",
            "-autoshieldcoinbase=0",
            "-server=1",
            "-listen=0",
            "-dnsseed=0",
            "-discover=0",
            "-fallbackfee=0.0001",
            f"-datadir={datadir}",
            f"-rpcport={rpc_port}",
            f"-port={p2p_port}",
            "-printtoconsole=0",
        ],
        stdout=stdout_fh,
        stderr=stderr_fh,
    )

    rpc = RPCClient(rpc_port=rpc_port, datadir=datadir, default_timeout_s=args.rpc_timeout_seconds)
    print(
        "[INFO] live runtime validation start "
        f"mine_blocks={args.mine_blocks} mine_batch_size={args.mine_batch_size} "
        f"rpc_timeout={args.rpc_timeout_seconds}s mining_timeout={args.mining_rpc_timeout_seconds}s "
        f"shielded_timeout={args.shielded_rpc_timeout_seconds}s",
        flush=True,
    )

    def cleanup() -> None:
        try:
            rpc.call("stop")
        except Exception:
            pass
        try:
            node.wait(timeout=30)
        except subprocess.TimeoutExpired:
            node.kill()
            node.wait(timeout=5)
        stdout_fh.close()
        stderr_fh.close()
        if datadir_is_temp and not args.keep_datadir:
            try:
                for root, dirs, files in os.walk(datadir, topdown=False):
                    for name in files:
                        Path(root, name).unlink(missing_ok=True)
                    for name in dirs:
                        Path(root, name).rmdir()
                datadir.rmdir()
            except Exception:
                pass

    try:
        wait_for_rpc(rpc)

        # Wallet setup
        rpc.call("createwallet", ["miner", False, False, "", False, True])
        rpc.call("createwallet", ["alice", False, False, "", False, True])
        rpc.call("createwallet", ["bob", False, False, "", False, True])
        rpc.call("createwallet", ["signer0", False, False, "", False, True])
        rpc.call("createwallet", ["signer1", False, False, "", False, True])
        rpc.call("createwallet", ["signer2", False, False, "", False, True])
        rpc.call("createwallet", ["msig_watch", True, True, "", False, True])

        miner_addr = rpc.call("getnewaddress", wallet="miner")
        # Warm up enough blocks for mature coinbase spends and shielded flow execution.
        # High-height shielding over thousands of UTXOs can be extremely slow; run the
        # shielded lifecycle first, then complete long-range mining for ASERT observations.
        warmup_blocks = min(args.mine_blocks, 430)
        mine_to_address(
            rpc,
            wallet="miner",
            address=miner_addr,
            blocks=warmup_blocks,
            batch_size=args.mine_batch_size,
            mining_timeout_s=args.mining_rpc_timeout_seconds,
            context="initial_mine",
        )
        ensure(int(rpc.call("getblockcount")) >= warmup_blocks, "Warmup mining did not reach requested height")

        next_coinbase_height = 1

        def next_height() -> int:
            nonlocal next_coinbase_height
            h = next_coinbase_height
            next_coinbase_height += 1
            return h

        def shield_with_retry(wallet: str, amount: float, zaddr: str, context: str) -> Any:
            last_error: Exception | None = None
            for attempt in range(1, args.shielded_retry_attempts + 1):
                try:
                    return rpc.call(
                        "z_shieldfunds",
                        [amount, zaddr],
                        wallet=wallet,
                        timeout_s=args.shielded_rpc_timeout_seconds,
                    )
                except RPCError as e:
                    msg = str(e)
                    last_error = e
                    # Under sustained shielding, transient mempool policy conflicts can occur.
                    # Mine one block and retry rather than failing the whole runtime harness.
                    is_transient = (
                        "rejected from mempool" in msg
                        or "Failed to create shielded transaction" in msg
                        or "RPC timeout calling z_shieldfunds" in msg
                    )
                    if is_transient:
                        print(
                            f"[WARN] {context}: shield attempt {attempt}/{args.shielded_retry_attempts} transient failure ({msg}); mining retry block",
                            flush=True,
                        )
                        wait_for_rpc_command_idle(
                            rpc,
                            "z_shieldfunds",
                            timeout_s=max(30, args.shielded_rpc_timeout_seconds),
                        )
                        mine_to_address(
                            rpc,
                            wallet="miner",
                            address=miner_addr,
                            blocks=1,
                            batch_size=1,
                            mining_timeout_s=args.mining_rpc_timeout_seconds,
                            context=f"{context}_retry_confirm",
                        )
                        continue
                    raise
            raise RuntimeError(f"{context}: exhausted shield retries ({args.shielded_retry_attempts}): {last_error}")

        # Fund Alice with many small transparent UTXOs so repeated z_shieldfunds
        # calls can seed enough commitment-tree entries for ring decoys.
        alice_taddrs: list[str] = [str(rpc.call("getnewaddress", wallet="alice")) for _ in range(40)]
        alice_funding_outputs = {addr: Decimal("0.25") for addr in alice_taddrs}
        fund_txid = split_mature_coinbase(
            rpc,
            next_height_provider=next_height,
            destination_amounts=alice_funding_outputs,
            change_addr=miner_addr,
            context="fund_alice_split",
        )
        mine_to_address(
            rpc,
            wallet="miner",
            address=miner_addr,
            blocks=1,
            batch_size=1,
            mining_timeout_s=args.mining_rpc_timeout_seconds,
            context="fund_alice_confirm",
        )

        # Seed commitment tree so ring-size decoy selection has enough diversity.
        alice_seed_zaddr = rpc.call("z_getnewaddress", wallet="alice", timeout_s=args.shielded_rpc_timeout_seconds)
        decoy_seed_txids: list[str] = []
        for _ in range(18):
            seed_tx = shield_with_retry("alice", 0.2, alice_seed_zaddr, context="decoy_seed")
            if isinstance(seed_tx, dict):
                decoy_seed_txids.append(str(seed_tx["txid"]))
            else:
                decoy_seed_txids.append(str(seed_tx))
            mine_to_address(
                rpc,
                wallet="miner",
                address=miner_addr,
                blocks=1,
                batch_size=1,
                mining_timeout_s=args.mining_rpc_timeout_seconds,
                context="decoy_seed_confirm",
            )

        # Transparent -> shielded -> transparent lifecycle using funded Alice wallet.
        zaddr = rpc.call("z_getnewaddress", wallet="alice", timeout_s=args.shielded_rpc_timeout_seconds)
        shield_tx_result = shield_with_retry("alice", 5.0, zaddr, context="alice_shield")
        shield_txid = str(shield_tx_result["txid"]) if isinstance(shield_tx_result, dict) else str(shield_tx_result)
        mine_to_address(
            rpc,
            wallet="miner",
            address=miner_addr,
            blocks=1,
            batch_size=1,
            mining_timeout_s=args.mining_rpc_timeout_seconds,
            context="shield_confirm",
        )
        z_balance_after_shield = d(
            rpc.call("z_getbalance", wallet="alice", timeout_s=args.shielded_rpc_timeout_seconds)["balance"]
        )
        ensure(z_balance_after_shield > Decimal("0"), "Shielded balance did not increase")

        bob_taddr = rpc.call("getnewaddress", wallet="bob")
        unshield_txid = call_z_sendmany(
            rpc,
            "alice",
            [{"address": bob_taddr, "amount": 1.0}],
            timeout_s=args.shielded_rpc_timeout_seconds,
        )
        mine_to_address(
            rpc,
            wallet="miner",
            address=miner_addr,
            blocks=1,
            batch_size=1,
            mining_timeout_s=args.mining_rpc_timeout_seconds,
            context="unshield_confirm",
        )
        bob_received = d(rpc.call("getreceivedbyaddress", [bob_taddr], wallet="bob"))
        ensure(bob_received >= Decimal("1.0"), "Bob did not receive expected unshielded funds")

        # PQ multisig lifecycle using mined funds.
        pq_keys: list[str] = []
        for w in ["signer0", "signer1", "signer2"]:
            src_addr = rpc.call("getnewaddress", wallet=w)
            exported = rpc.call("exportpqkey", [src_addr], wallet=w)
            ensure(exported["algorithm"] == "ml-dsa-44", f"Unexpected PQ algo for {w}")
            pq_keys.append(exported["key"])

        msig_info = rpc.call("addpqmultisigaddress", [2, pq_keys, "live-msig", True], wallet="msig_watch")
        msig_addr = msig_info["address"]

        fund_msig_txid = spend_mature_coinbase(
            rpc,
            next_height_provider=next_height,
            destination_addr=msig_addr,
            change_addr=miner_addr,
            amount=Decimal("3.0"),
            context="fund_multisig",
        )
        rpc.call("generatetoaddress", [1, miner_addr], wallet="miner")

        unspents = rpc.call("listunspent", [], wallet="msig_watch")
        msig_utxo = next(u for u in unspents if u.get("address") == msig_addr)
        dest = rpc.call("getnewaddress", wallet="signer2")
        created = rpc.call(
            "walletcreatefundedpsbt",
            [
                [{"txid": msig_utxo["txid"], "vout": msig_utxo["vout"]}],
                [{dest: 1.0}],
                0,
                {"add_inputs": False, "changeAddress": msig_addr, "fee_rate": 25},
            ],
            wallet="msig_watch",
        )
        psbt = rpc.call("walletprocesspsbt", [created["psbt"], False, "ALL", True, False], wallet="msig_watch")["psbt"]
        psbt_a = rpc.call("walletprocesspsbt", [psbt], wallet="signer0")["psbt"]
        psbt_b = rpc.call("walletprocesspsbt", [psbt], wallet="signer1")["psbt"]
        combined = rpc.call("combinepsbt", [[psbt_a, psbt_b]], wallet="signer0")
        finalized = rpc.call("finalizepsbt", [combined], wallet="signer0")
        ensure(bool(finalized["complete"]), "PQ multisig PSBT did not finalize")
        spend_msig_txid = rpc.call("sendrawtransaction", [finalized["hex"]], wallet="signer0")
        mine_to_address(
            rpc,
            wallet="miner",
            address=miner_addr,
            blocks=1,
            batch_size=1,
            mining_timeout_s=args.mining_rpc_timeout_seconds,
            context="multisig_confirm",
        )
        signer2_balance = d(rpc.call("getbalance", wallet="signer2"))
        ensure(signer2_balance >= Decimal("1.0"), "Signer2 did not receive multisig spend")

        chain_height = int(rpc.call("getblockcount"))
        if chain_height < args.mine_blocks:
            remaining_blocks = args.mine_blocks - chain_height
            mine_to_address(
                rpc,
                wallet="miner",
                address=miner_addr,
                blocks=remaining_blocks,
                batch_size=args.mine_batch_size,
                mining_timeout_s=args.mining_rpc_timeout_seconds,
                context="post_flow_mine",
            )
        chain_height = int(rpc.call("getblockcount"))
        ensure(chain_height >= args.mine_blocks, "Mining did not reach requested height")

        # Collect difficulty/header observations across the mined range.
        bits_changes: list[dict[str, Any]] = []
        prev_bits: str | None = None
        time_deltas: list[int] = []
        prev_time: int | None = None
        for h in range(1, chain_height + 1):
            bh = rpc.call("getblockhash", [h])
            header = rpc.call("getblockheader", [bh])
            bits = str(header["bits"])
            block_time = int(header["time"])
            if bits != prev_bits:
                bits_changes.append({"height": h, "bits": bits})
                prev_bits = bits
            if prev_time is not None:
                time_deltas.append(block_time - prev_time)
            prev_time = block_time

        final_height = int(rpc.call("getblockcount"))

        artifact = {
            "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "overall_status": "pass",
            "node": {
                "rpc_port": rpc_port,
                "p2p_port": p2p_port,
                "datadir": str(datadir),
                "stdout_log": str(node_stdout),
                "stderr_log": str(node_stderr),
                "final_height": final_height,
                "best_block": rpc.call("getbestblockhash"),
            },
            "mining_observations": {
                "initial_mined_blocks": args.mine_blocks,
                "bits_change_count": len(bits_changes),
                "bits_change_points": bits_changes[:30],
                "median_block_time_delta_s": median(time_deltas) if time_deltas else None,
                "mean_block_time_delta_s": float(mean(time_deltas)) if time_deltas else None,
                "time_delta_sample_size": len(time_deltas),
            },
            "shielded_flow": {
                "fund_txid": fund_txid,
                "funding_taddr_count": len(alice_taddrs),
                "shield_txid": shield_txid,
                "shield_tx_result": shield_tx_result,
                "unshield_txid": unshield_txid,
                "alice_z_balance_after_shield": str(z_balance_after_shield),
                "bob_received_unshielded": str(bob_received),
                "z_address": zaddr,
                "bob_taddr": bob_taddr,
                "decoy_seed_tx_count": len(decoy_seed_txids),
            },
            "pq_multisig_flow": {
                "msig_address": msig_addr,
                "fund_msig_txid": fund_msig_txid,
                "spend_msig_txid": spend_msig_txid,
                "signer2_balance": str(signer2_balance),
            },
        }

        artifact_path = Path(args.artifact)
        artifact_path.parent.mkdir(parents=True, exist_ok=True)
        artifact_path.write_text(json.dumps(artifact, indent=2), encoding="utf-8")
        print(f"Live runtime validation passed. Artifact: {artifact_path}")
    finally:
        cleanup()


if __name__ == "__main__":
    main()
