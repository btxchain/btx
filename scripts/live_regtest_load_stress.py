#!/usr/bin/env python3
"""Live single-node load stress harness for BTX regtest.

This script runs a real node and executes mixed transaction pressure:
- transparent sends from mined rewards
- transparent -> shielded moves
- shielded -> transparent spends
- repeated PQ multisig funding/spend cycles

It writes an artifact JSON with operational counters and txids.
"""

from __future__ import annotations

import argparse
import base64
import json
import random
import socket
import subprocess
import tempfile
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from decimal import Decimal
from pathlib import Path
from typing import Any, Callable


class RPCError(RuntimeError):
    pass


@dataclass
class RPCClient:
    rpc_port: int
    datadir: Path
    default_timeout_s: int = 90

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
        body = json.dumps({"jsonrpc": "1.0", "id": "load", "method": method, "params": params}).encode("utf-8")
        req = urllib.request.Request(
            url=f"http://127.0.0.1:{self.rpc_port}{path}",
            data=body,
            headers={"Content-Type": "application/json", "Authorization": self._auth_header()},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=timeout_s) as resp:
                payload = json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as e:
            body = e.read().decode("utf-8", errors="replace")
            raise RPCError(f"HTTP RPC error {method}: {e.code} {e.reason}; body={body}") from e
        except TimeoutError as e:
            raise RPCError(f"RPC timeout calling {method} after {timeout_s}s: {e}") from e
        except socket.timeout as e:
            raise RPCError(f"RPC timeout calling {method} after {timeout_s}s: {e}") from e
        except urllib.error.URLError as e:
            raise RPCError(f"Transport RPC error {method}: {e}") from e

        if payload.get("error") is not None:
            raise RPCError(f"RPC error {method}: {payload['error']}")
        return payload["result"]


@dataclass
class Counters:
    rounds: int = 0
    transparent_sent: int = 0
    shield_success: int = 0
    shield_skipped: int = 0
    unshield_success: int = 0
    unshield_skipped: int = 0
    multisig_success: int = 0
    multisig_skipped: int = 0
    mined_blocks: int = 0
    max_mempool_size: int = 0
    failures: list[str] = field(default_factory=list)


def find_free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def wait_for_rpc(rpc: RPCClient, timeout_s: int = 120) -> None:
    deadline = time.time() + timeout_s
    last_error: Exception | None = None
    while time.time() < deadline:
        try:
            rpc.call("getblockcount")
            return
        except Exception as e:  # noqa: BLE001
            last_error = e
            time.sleep(0.25)
    raise RuntimeError(f"Timed out waiting for RPC: {last_error}")


def d(value: Any) -> Decimal:
    return Decimal(str(value))


def random_amount(rng: random.Random, low: Decimal, high: Decimal) -> float:
    scaled = low + (high - low) * Decimal(str(rng.random()))
    return float(scaled.quantize(Decimal("0.00000001")))


def mine_blocks(
    rpc: RPCClient,
    wallet: str,
    address: str,
    blocks: int,
    batch_size: int,
    timeout_s: int,
    context: str = "mining",
) -> None:
    if blocks <= 0:
        return
    remaining = blocks
    mined = 0
    while remaining > 0:
        chunk = min(remaining, batch_size)
        rpc.call("generatetoaddress", [chunk, address], wallet=wallet, timeout_s=timeout_s)
        remaining -= chunk
        mined += chunk
        if blocks >= max(2 * batch_size, 20):
            print(f"[INFO] {context}: mined {mined}/{blocks} blocks", flush=True)


def try_shield(
    rpc: RPCClient,
    wallet: str,
    zaddr: str,
    rng: random.Random,
    timeout_s: int,
) -> tuple[bool, str]:
    tbal = d(rpc.call("getbalance", wallet=wallet))
    if tbal < Decimal("0.2"):
        return False, "insufficient_transparent_balance"
    amount = random_amount(rng, Decimal("0.10"), min(Decimal("1.50"), tbal - Decimal("0.01")))
    try:
        tx = rpc.call("z_shieldfunds", [amount, zaddr], wallet=wallet, timeout_s=timeout_s)
    except RPCError as e:
        msg = str(e)
        if "Failed to create shielded transaction" in msg:
            return False, "shielded_tx_construction_failed"
        if "Shielded transaction created but rejected from mempool" in msg:
            return False, "shielded_mempool_reject"
        if "rejected from mempool" in msg:
            return False, "shielded_mempool_reject"
        raise
    if isinstance(tx, dict):
        return True, str(tx["txid"])
    return True, str(tx)


def try_unshield(
    rpc: RPCClient,
    wallet: str,
    dest_taddr: str,
    rng: random.Random,
    timeout_s: int,
) -> tuple[bool, str]:
    zbal = d(rpc.call("z_getbalance", wallet=wallet, timeout_s=timeout_s)["balance"])
    if zbal < Decimal("0.2"):
        return False, "insufficient_shielded_balance"
    amount = random_amount(rng, Decimal("0.05"), min(Decimal("0.90"), zbal - Decimal("0.01")))
    try:
        result = rpc.call("z_sendmany", [[{"address": dest_taddr, "amount": amount}]], wallet=wallet, timeout_s=timeout_s)
    except RPCError as e:
        msg = str(e)
        if "Failed to create shielded transaction" in msg:
            return False, "shielded_tx_construction_failed"
        if "Shielded transaction created but rejected from mempool" in msg:
            # Under randomized load we can attempt two spends from the same note before
            # one is mined. Treat nullifier/mempool conflicts as expected skip paths.
            return False, "shielded_mempool_reject"
        raise
    if isinstance(result, dict):
        return True, str(result["txid"])
    return True, str(result)


def setup_multisig(rpc: RPCClient) -> str:
    pq_keys: list[str] = []
    for w in ["signer0", "signer1", "signer2"]:
        src_addr = rpc.call("getnewaddress", wallet=w)
        exported = rpc.call("exportpqkey", [src_addr], wallet=w)
        pq_keys.append(exported["key"])
    msig_info = rpc.call("addpqmultisigaddress", [2, pq_keys, "load-msig", True], wallet="msig_watch")
    return str(msig_info["address"])


def spend_mature_coinbase(
    rpc: RPCClient,
    *,
    wallet: str,
    coinbase_height: int,
    destination_addr: str,
    change_addr: str,
    amount: Decimal,
    fee: Decimal = Decimal("0.0001"),
) -> str:
    block_hash = str(rpc.call("getblockhash", [coinbase_height]))
    block = rpc.call("getblock", [block_hash, 2])
    coinbase = block["tx"][0]
    prev_txid = str(coinbase["txid"])
    prev_value = d(coinbase["vout"][0]["value"])
    change = (prev_value - amount - fee).quantize(Decimal("0.00000001"))
    if change <= Decimal("0"):
        raise RuntimeError(
            f"coinbase at height {coinbase_height} has insufficient value ({prev_value}) for amount={amount}"
        )

    raw = rpc.call(
        "createrawtransaction",
        [
            [{"txid": prev_txid, "vout": 0}],
            {destination_addr: float(amount), change_addr: float(change)},
        ],
    )
    signed = rpc.call("signrawtransactionwithwallet", [raw], wallet=wallet)
    if not bool(signed.get("complete", False)):
        raise RuntimeError(f"incomplete signature for coinbase spend at height {coinbase_height}")
    return str(rpc.call("sendrawtransaction", [signed["hex"]]))


def split_mature_coinbase(
    rpc: RPCClient,
    *,
    wallet: str,
    coinbase_height: int,
    destination_amounts: dict[str, Decimal],
    change_addr: str,
    fee: Decimal = Decimal("0.0001"),
) -> str:
    if not destination_amounts:
        raise RuntimeError("destination_amounts must be non-empty")

    total_dest = Decimal("0")
    for amount in destination_amounts.values():
        if amount <= Decimal("0"):
            raise RuntimeError("all destination amounts must be positive")
        total_dest += amount

    block_hash = str(rpc.call("getblockhash", [coinbase_height]))
    block = rpc.call("getblock", [block_hash, 2])
    coinbase = block["tx"][0]
    prev_txid = str(coinbase["txid"])
    prev_value = d(coinbase["vout"][0]["value"])
    change = (prev_value - total_dest - fee).quantize(Decimal("0.00000001"))
    if change <= Decimal("0"):
        raise RuntimeError(
            f"coinbase at height {coinbase_height} has insufficient value ({prev_value}) for split total={total_dest}"
        )

    outputs: dict[str, float] = {addr: float(amount) for addr, amount in destination_amounts.items()}
    outputs[change_addr] = float(change)

    raw = rpc.call(
        "createrawtransaction",
        [
            [{"txid": prev_txid, "vout": 0}],
            outputs,
        ],
    )
    signed = rpc.call("signrawtransactionwithwallet", [raw], wallet=wallet)
    if not bool(signed.get("complete", False)):
        raise RuntimeError(f"incomplete signature for split coinbase height {coinbase_height}")
    return str(rpc.call("sendrawtransaction", [signed["hex"]]))


def try_multisig_cycle(
    rpc: RPCClient,
    miner_addr: str,
    msig_addr: str,
    rng: random.Random,
    mining_timeout_s: int,
    mine_batch_size: int,
    fund_multisig: Callable[[Decimal], str],
) -> tuple[bool, str]:
    # Fund multisig from mined rewards, confirm, then spend with 2-of-3 signatures.
    fund_amount = d(random_amount(rng, Decimal("0.60"), Decimal("1.60")))
    fund_txid = fund_multisig(fund_amount)
    mine_blocks(
        rpc,
        wallet="miner",
        address=miner_addr,
        blocks=1,
        batch_size=mine_batch_size,
        timeout_s=mining_timeout_s,
    )
    unspents = rpc.call("listunspent", [1, 9999999, [msig_addr]], wallet="msig_watch")
    if not unspents:
        return False, f"no_multisig_utxo_after_fund:{fund_txid}"
    utxo = unspents[0]
    utxo_amount = Decimal(str(utxo["amount"]))
    spend_amount = min(Decimal("0.20"), utxo_amount - Decimal("0.15"))
    if spend_amount < Decimal("0.05"):
        return False, f"multisig_utxo_too_small:{utxo_amount}"
    dest = rpc.call("getnewaddress", wallet="signer2")
    try:
        created = rpc.call(
            "walletcreatefundedpsbt",
            [
                [{"txid": utxo["txid"], "vout": utxo["vout"]}],
                [{dest: float(spend_amount.quantize(Decimal("0.00000001")))}],
                0,
                {"add_inputs": False, "changeAddress": msig_addr, "fee_rate": 25},
            ],
            wallet="msig_watch",
        )
    except RPCError as e:
        msg = str(e)
        if "preselected coins total amount does not cover the transaction target" in msg:
            return False, "multisig_insufficient_preselected_amount"
        raise
    psbt = rpc.call("walletprocesspsbt", [created["psbt"], False, "ALL", True, False], wallet="msig_watch")["psbt"]
    psbt_a = rpc.call("walletprocesspsbt", [psbt], wallet="signer0")["psbt"]
    psbt_b = rpc.call("walletprocesspsbt", [psbt], wallet="signer1")["psbt"]
    combined = rpc.call("combinepsbt", [[psbt_a, psbt_b]], wallet="signer0")
    finalized = rpc.call("finalizepsbt", [combined], wallet="signer0")
    if not bool(finalized["complete"]):
        return False, "multisig_psbt_not_complete"
    spend_txid = str(rpc.call("sendrawtransaction", [finalized["hex"]], wallet="signer0"))
    return True, spend_txid


def main() -> None:
    parser = argparse.ArgumentParser(description="Live BTX load stress")
    parser.add_argument("--build-dir", default="build-btx")
    parser.add_argument("--artifact", default="/tmp/btx-live-load-stress.json")
    parser.add_argument("--rounds", type=int, default=160)
    parser.add_argument("--seed", type=int, default=2026030707)
    parser.add_argument("--initial-mine-blocks", type=int, default=450)
    parser.add_argument("--mine-every-rounds", type=int, default=4)
    parser.add_argument("--mine-batch-size", type=int, default=50)
    parser.add_argument("--rpc-timeout-seconds", type=int, default=90)
    parser.add_argument("--mining-rpc-timeout-seconds", type=int, default=300)
    parser.add_argument("--shielded-rpc-timeout-seconds", type=int, default=600)
    parser.add_argument("--max-runtime-seconds", type=int, default=0)
    parser.add_argument("--progress-every-rounds", type=int, default=20)
    args = parser.parse_args()
    if args.rounds < 1:
        raise RuntimeError("--rounds must be >= 1")
    if args.initial_mine_blocks < 1:
        raise RuntimeError("--initial-mine-blocks must be >= 1")
    if args.mine_every_rounds < 1:
        raise RuntimeError("--mine-every-rounds must be >= 1")
    if args.mine_batch_size < 1:
        raise RuntimeError("--mine-batch-size must be >= 1")
    if args.rpc_timeout_seconds < 1:
        raise RuntimeError("--rpc-timeout-seconds must be >= 1")
    if args.mining_rpc_timeout_seconds < 1:
        raise RuntimeError("--mining-rpc-timeout-seconds must be >= 1")
    if args.shielded_rpc_timeout_seconds < 1:
        raise RuntimeError("--shielded-rpc-timeout-seconds must be >= 1")
    if args.max_runtime_seconds < 0:
        raise RuntimeError("--max-runtime-seconds must be >= 0")
    if args.progress_every_rounds < 1:
        raise RuntimeError("--progress-every-rounds must be >= 1")

    rng = random.Random(args.seed)
    repo_root = Path(__file__).resolve().parents[1]
    build_dir = (repo_root / args.build_dir).resolve()
    btxd_bin = build_dir / "bin" / "btxd"
    if not btxd_bin.exists():
        btxd_bin = build_dir / "bin" / "bitcoind"
    if not btxd_bin.exists():
        raise RuntimeError(f"Missing node binary in {build_dir / 'bin'}")

    datadir = Path(tempfile.mkdtemp(prefix="btx-live-load-"))
    rpc_port = find_free_port()
    p2p_port = find_free_port()

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
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )

    rpc = RPCClient(rpc_port=rpc_port, datadir=datadir, default_timeout_s=args.rpc_timeout_seconds)
    counters = Counters()
    txids: dict[str, list[str]] = {"transparent": [], "shield": [], "unshield": [], "multisig": []}

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

    try:
        wait_for_rpc(rpc)
        print(
            "[INFO] live load stress start "
            f"seed={args.seed} rounds={args.rounds} initial_mine_blocks={args.initial_mine_blocks} "
            f"mine_every_rounds={args.mine_every_rounds} mine_batch_size={args.mine_batch_size} "
            f"shielded_timeout={args.shielded_rpc_timeout_seconds}s",
            flush=True,
        )

        # Wallet setup
        wallets = ["miner", "w0", "w1", "w2", "w3", "signer0", "signer1", "signer2"]
        for w in wallets:
            rpc.call("createwallet", [w, False, False, "", False, True])
        rpc.call("createwallet", ["msig_watch", True, True, "", False, True])

        miner_addr = rpc.call("getnewaddress", wallet="miner")
        mine_blocks(
            rpc,
            wallet="miner",
            address=miner_addr,
            blocks=args.initial_mine_blocks,
            batch_size=args.mine_batch_size,
            timeout_s=args.mining_rpc_timeout_seconds,
            context="initial_mine",
        )
        counters.mined_blocks += args.initial_mine_blocks

        print("[INFO] wallet setup complete", flush=True)
        t_wallets = ["w0", "w1", "w2", "w3"]
        t_addrs = {w: rpc.call("getnewaddress", wallet=w) for w in t_wallets}
        z_addrs = {w: rpc.call("z_getnewaddress", wallet=w, timeout_s=args.shielded_rpc_timeout_seconds) for w in t_wallets}

        print("[INFO] participant transparent addresses + shielded addresses initialized", flush=True)
        # Pre-fund transparent balances on participant wallets from matured
        # coinbase UTXOs using direct signed spends.
        for idx, w in enumerate(t_wallets, start=1):
            fund_txid = spend_mature_coinbase(
                rpc,
                wallet="miner",
                coinbase_height=idx,
                destination_addr=t_addrs[w],
                change_addr=miner_addr,
                amount=Decimal("4.0"),
            )
            txids["transparent"].append(fund_txid)
        # Create many miner-side small UTXOs from a matured coinbase so decoy
        # seeding via repeated z_shieldfunds remains deterministic.
        decoy_seed_taddrs = [str(rpc.call("getnewaddress", wallet="miner")) for _ in range(24)]
        decoy_split_txid = split_mature_coinbase(
            rpc,
            wallet="miner",
            coinbase_height=len(t_wallets) + 1,
            destination_amounts={addr: Decimal("0.25") for addr in decoy_seed_taddrs},
            change_addr=miner_addr,
        )
        txids["transparent"].append(decoy_split_txid)
        next_multisig_coinbase_height = len(t_wallets) + 2

        def fund_multisig_from_coinbase(amount: Decimal) -> str:
            nonlocal next_multisig_coinbase_height
            current_height = int(rpc.call("getblockcount"))
            max_mature_height = current_height - 100
            if next_multisig_coinbase_height > max_mature_height:
                raise RuntimeError(
                    f"no_mature_coinbase_for_multisig:{next_multisig_coinbase_height}>{max_mature_height}"
                )
            txid = spend_mature_coinbase(
                rpc,
                wallet="miner",
                coinbase_height=next_multisig_coinbase_height,
                destination_addr=msig_addr,
                change_addr=miner_addr,
                amount=amount,
            )
            next_multisig_coinbase_height += 1
            return txid
        mine_blocks(
            rpc,
            wallet="miner",
            address=miner_addr,
            blocks=2,
            batch_size=2,
            timeout_s=args.mining_rpc_timeout_seconds,
            context="prefund_confirm",
        )
        counters.mined_blocks += 2

        print("[INFO] participant prefund complete", flush=True)
        msig_addr = setup_multisig(rpc)
        print(f"[INFO] multisig setup complete: {msig_addr}", flush=True)

        # Seed shielded commitment diversity so ring-16 spends have sufficient decoys.
        miner_zaddr = rpc.call("z_getnewaddress", wallet="miner", timeout_s=args.shielded_rpc_timeout_seconds)
        for _ in range(18):
            try:
                seed_tx = rpc.call(
                    "z_shieldfunds",
                    [0.2, miner_zaddr],
                    wallet="miner",
                    timeout_s=args.shielded_rpc_timeout_seconds,
                )
                if isinstance(seed_tx, dict):
                    txids["shield"].append(str(seed_tx["txid"]))
                else:
                    txids["shield"].append(str(seed_tx))
                counters.shield_success += 1
            except RPCError:
                counters.shield_skipped += 1
            mine_blocks(
                rpc,
                wallet="miner",
                address=miner_addr,
                blocks=1,
                batch_size=1,
                timeout_s=args.mining_rpc_timeout_seconds,
                context="decoy_seed_confirm",
            )
            counters.mined_blocks += 1
        print("[INFO] decoy seed phase complete", flush=True)

        # Deterministic warm-up to guarantee coverage before randomized rounds.
        ok, out = try_shield(rpc, "w0", z_addrs["w0"], rng, timeout_s=args.shielded_rpc_timeout_seconds)
        if not ok:
            raise RuntimeError(f"Warm-up shield failed: {out}")
        txids["shield"].append(out)
        counters.shield_success += 1
        mine_blocks(
            rpc,
            wallet="miner",
            address=miner_addr,
            blocks=2,
            batch_size=1,
            timeout_s=args.mining_rpc_timeout_seconds,
            context="warmup_shield_confirm",
        )
        counters.mined_blocks += 2
        print("[INFO] warm-up shield complete", flush=True)

        warmup_unshield_ok = False
        warmup_unshield_out = "uninitialized"
        for _ in range(5):
            ok, out = try_unshield(rpc, "w0", t_addrs["w1"], rng, timeout_s=args.shielded_rpc_timeout_seconds)
            warmup_unshield_out = out
            if ok:
                warmup_unshield_ok = True
                warmup_unshield_out = out
                break
            mine_blocks(
                rpc,
                wallet="miner",
                address=miner_addr,
                blocks=2,
                batch_size=1,
                timeout_s=args.mining_rpc_timeout_seconds,
                context="warmup_unshield_retry_confirm",
            )
            counters.mined_blocks += 2
        if not warmup_unshield_ok:
            counters.unshield_skipped += 1
            counters.failures.append(f"warmup_unshield_skipped:{warmup_unshield_out}")
            print(f"[WARN] warm-up unshield skipped: {warmup_unshield_out}", flush=True)
        else:
            out = warmup_unshield_out
            txids["unshield"].append(out)
            counters.unshield_success += 1
            mine_blocks(
                rpc,
                wallet="miner",
                address=miner_addr,
                blocks=1,
                batch_size=1,
                timeout_s=args.mining_rpc_timeout_seconds,
                context="warmup_unshield_confirm",
            )
            counters.mined_blocks += 1
            print("[INFO] warm-up unshield complete", flush=True)

        ok, out = try_multisig_cycle(
            rpc,
            miner_addr=miner_addr,
            msig_addr=msig_addr,
            rng=rng,
            mining_timeout_s=args.mining_rpc_timeout_seconds,
            mine_batch_size=args.mine_batch_size,
            fund_multisig=fund_multisig_from_coinbase,
        )
        if not ok:
            raise RuntimeError(f"Warm-up multisig failed: {out}")
        txids["multisig"].append(out)
        counters.multisig_success += 1
        print("[INFO] warm-up multisig cycle complete", flush=True)

        start_epoch = time.time()
        completed = True
        termination_reason = "rounds_completed"
        for r in range(1, args.rounds + 1):
            if args.max_runtime_seconds > 0 and (time.time() - start_epoch) >= args.max_runtime_seconds:
                completed = False
                termination_reason = "max_runtime_seconds_exceeded"
                print(
                    f"[WARN] max runtime exceeded at round {r-1} ({args.max_runtime_seconds}s); writing partial artifact",
                    flush=True,
                )
                break
            counters.rounds = r
            action = rng.choices(
                ["transparent", "shield", "unshield", "multisig"],
                weights=[50, 20, 20, 10],
                k=1,
            )[0]
            try:
                if action == "transparent":
                    dest_wallet = rng.choice(t_wallets)
                    dest = rpc.call("getnewaddress", wallet=dest_wallet)
                    amount = random_amount(rng, Decimal("0.01"), Decimal("0.25"))
                    txid = str(rpc.call("sendtoaddress", [dest, amount], wallet="miner"))
                    txids["transparent"].append(txid)
                    counters.transparent_sent += 1
                elif action == "shield":
                    src_wallet = rng.choice(t_wallets)
                    ok, out = try_shield(rpc, src_wallet, z_addrs[src_wallet], rng, timeout_s=args.shielded_rpc_timeout_seconds)
                    if ok:
                        txids["shield"].append(out)
                        counters.shield_success += 1
                    else:
                        counters.shield_skipped += 1
                elif action == "unshield":
                    src_wallet = rng.choice(t_wallets)
                    dest_wallet = rng.choice(t_wallets)
                    ok, out = try_unshield(
                        rpc,
                        src_wallet,
                        t_addrs[dest_wallet],
                        rng,
                        timeout_s=args.shielded_rpc_timeout_seconds,
                    )
                    if ok:
                        txids["unshield"].append(out)
                        counters.unshield_success += 1
                    else:
                        counters.unshield_skipped += 1
                else:
                    ok, out = try_multisig_cycle(
                        rpc,
                        miner_addr=miner_addr,
                        msig_addr=msig_addr,
                        rng=rng,
                        mining_timeout_s=args.mining_rpc_timeout_seconds,
                        mine_batch_size=args.mine_batch_size,
                        fund_multisig=fund_multisig_from_coinbase,
                    )
                    if ok:
                        txids["multisig"].append(out)
                        counters.multisig_success += 1
                    else:
                        counters.multisig_skipped += 1
            except Exception as e:  # noqa: BLE001
                counters.failures.append(f"round={r} action={action} err={e}")

            if r % args.mine_every_rounds == 0:
                try:
                    mine_blocks(
                        rpc,
                        wallet="miner",
                        address=miner_addr,
                        blocks=1,
                        batch_size=1,
                        timeout_s=args.mining_rpc_timeout_seconds,
                        context="round_confirm",
                    )
                    counters.mined_blocks += 1
                except Exception as e:  # noqa: BLE001
                    completed = False
                    termination_reason = "round_confirm_mining_failed"
                    counters.failures.append(f"round={r} action=round_confirm_mining err={e}")
                    print(
                        f"[WARN] round confirm mining failed at round {r}: {e}; writing partial artifact",
                        flush=True,
                    )
                    break

            mempool_size = int(rpc.call("getmempoolinfo")["size"])
            counters.max_mempool_size = max(counters.max_mempool_size, mempool_size)
            if r % args.progress_every_rounds == 0:
                print(
                    "[INFO] round="
                    f"{r}/{args.rounds} tx={{t:{counters.transparent_sent},s:{counters.shield_success},u:{counters.unshield_success},m:{counters.multisig_success}}} "
                    f"mempool={mempool_size} failures={len(counters.failures)}",
                    flush=True,
                )

        # Final confirmation mining and health checks.
        try:
            mine_blocks(
                rpc,
                wallet="miner",
                address=miner_addr,
                blocks=15,
                batch_size=15,
                timeout_s=args.mining_rpc_timeout_seconds,
                context="final_confirm",
            )
            counters.mined_blocks += 15
        except Exception as e:  # noqa: BLE001
            completed = False
            if termination_reason == "rounds_completed":
                termination_reason = "final_confirm_mining_failed"
            counters.failures.append(f"action=final_confirm_mining err={e}")
            print(f"[WARN] final confirmation mining failed: {e}", flush=True)

        if counters.shield_success == 0:
            counters.failures.append("invariant:no_successful_shield_operations")
        if counters.unshield_success == 0:
            counters.failures.append("invariant:no_successful_unshield_operations")
        if counters.multisig_success == 0:
            counters.failures.append("invariant:no_successful_multisig_cycles")

        final_balances: dict[str, str] = {}
        final_z_balances: dict[str, str] = {}
        try:
            final_balances = {
                w: str(rpc.call("getbalance", wallet=w))
                for w in ["miner", "w0", "w1", "w2", "w3", "signer2"]
            }
        except Exception as e:  # noqa: BLE001
            counters.failures.append(f"final_balance_collection_failed:{e}")
        try:
            final_z_balances = {w: str(rpc.call("z_getbalance", wallet=w)["balance"]) for w in t_wallets}
        except Exception as e:  # noqa: BLE001
            counters.failures.append(f"final_z_balance_collection_failed:{e}")

        overall_status = "pass"
        if not completed and counters.failures:
            overall_status = "partial_with_failures"
        elif not completed:
            overall_status = "partial"
        elif counters.failures:
            overall_status = "pass_with_failures"

        artifact = {
            "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "overall_status": overall_status,
            "seed": args.seed,
            "completed": completed,
            "termination_reason": termination_reason,
            "node": {
                "rpc_port": rpc_port,
                "p2p_port": p2p_port,
                "final_height": int(rpc.call("getblockcount")),
                "best_block": rpc.call("getbestblockhash"),
            },
            "counters": counters.__dict__,
            "final_balances": final_balances,
            "final_z_balances": final_z_balances,
            "txid_samples": {k: v[:40] for k, v in txids.items()},
        }

        artifact_path = Path(args.artifact)
        artifact_path.parent.mkdir(parents=True, exist_ok=True)
        artifact_path.write_text(json.dumps(artifact, indent=2), encoding="utf-8")
        if not completed:
            print(f"Live load stress partial completion ({termination_reason}). Artifact: {artifact_path}", flush=True)
        else:
            print(f"Live load stress completed. Artifact: {artifact_path}", flush=True)
    finally:
        cleanup()


if __name__ == "__main__":
    main()
