#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""Focused lock-handling coverage for the shielded transfer builder."""

import json
import subprocess
import sys
from decimal import Decimal, ROUND_DOWN
from pathlib import Path
from urllib.parse import urlparse

from test_framework.shielded_utils import encrypt_and_unlock_wallet
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal


TOOL_PATH = Path(__file__).resolve().parents[2] / "contrib" / "shielded_transfer_builder.py"


def raw_send(node, wallet, from_addr, to_addrs_amounts, fee=Decimal("0.001")):
    candidates = [u for u in wallet.listunspent(1) if u.get("spendable", False)]

    total_needed = sum(to_addrs_amounts.values()) + fee
    selected = []
    selected_total = Decimal("0")
    for c in candidates:
        selected.append(c)
        selected_total += Decimal(str(c["amount"]))
        if selected_total >= total_needed:
            break
    assert selected_total >= total_needed, f"Insufficient UTXOs for {total_needed}"

    inputs = [{"txid": c["txid"], "vout": c["vout"]} for c in selected]
    outputs = {addr: float(amt) for addr, amt in to_addrs_amounts.items()}
    change = (selected_total - total_needed).quantize(
        Decimal("0.00000001"), rounding=ROUND_DOWN
    )
    if change > Decimal("0"):
        if from_addr in outputs:
            outputs[from_addr] = float(Decimal(str(outputs[from_addr])) + change)
        else:
            outputs[from_addr] = float(change)

    raw = node.createrawtransaction(inputs, outputs)
    signed = wallet.signrawtransactionwithwallet(raw)
    assert signed["complete"], f"Failed to sign raw tx: {signed.get('errors')}"
    return node.sendrawtransaction(signed["hex"])


def fund_same_address_many(node, wallet, from_addr, destination, amount, count):
    for _ in range(count):
        raw_send(node, wallet, from_addr, {destination: amount})


class WalletShieldedTransferBuilderLocksTest(BitcoinTestFramework):
    def add_options(self, parser):
        self.add_wallet_options(parser, legacy=False)

    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.extra_args = [["-noautoshieldcoinbase"]]
        self.rpc_timeout = 300

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()
        self.skip_if_no_sqlite()

    def run_tool(self, *args):
        completed = subprocess.run(
            [sys.executable, str(TOOL_PATH), *args],
            capture_output=True,
            text=True,
            check=True,
            cwd=Path(__file__).resolve().parents[1],
        )
        return json.loads(completed.stdout)

    def run_test(self):
        node = self.nodes[0]

        self.log.info("Create miner and signer wallets")
        node.createwallet(wallet_name="miner", descriptors=True)
        miner = node.get_wallet_rpc("miner")
        mine_addr = miner.getnewaddress()

        node.createwallet(wallet_name="signer1", descriptors=True)
        node.createwallet(wallet_name="signer2", descriptors=True)
        node.createwallet(wallet_name="signer3", descriptors=True)
        signer1 = encrypt_and_unlock_wallet(node, "signer1")
        signer2 = encrypt_and_unlock_wallet(node, "signer2")
        signer3 = encrypt_and_unlock_wallet(node, "signer3")

        self.generatetoaddress(node, 220, mine_addr, sync_fun=self.no_op)

        self.log.info("Fund signer wallets so they can export PQ keys")
        signer1_addr = signer1.getnewaddress()
        signer2_addr = signer2.getnewaddress()
        signer3_addr = signer3.getnewaddress()
        raw_send(node, miner, mine_addr, {
            signer1_addr: Decimal("1.0"),
            signer2_addr: Decimal("1.0"),
            signer3_addr: Decimal("1.0"),
        })
        self.generatetoaddress(node, 1, mine_addr, sync_fun=self.no_op)

        self.log.info("Create a shared 3-of-3 PQ multisig wallet view")
        pq_keys = [
            signer1.exportpqkey(signer1_addr)["key"],
            signer2.exportpqkey(signer2_addr)["key"],
            signer3.exportpqkey(signer3_addr)["key"],
        ]
        msig_info = signer1.addpqmultisigaddress(3, pq_keys, "lock-test-3of3", True)
        signer2.addpqmultisigaddress(3, pq_keys, "lock-test-3of3", True)
        signer3.addpqmultisigaddress(3, pq_keys, "lock-test-3of3", True)
        multisig_address = msig_info["address"]

        self.log.info("Fund the multisig wallet with multiple 20 BTX outputs")
        fund_same_address_many(node, miner, mine_addr, multisig_address, Decimal("20.0"), 6)
        self.generatetoaddress(node, 1, mine_addr, sync_fun=self.no_op)
        multisig_utxos = [u for u in signer1.listunspent() if u["address"] == multisig_address]
        assert_equal(len(multisig_utxos), 6)

        self.log.info("Pre-lock one UTXO and ensure no-lock planning excludes it")
        prelocked = {"txid": multisig_utxos[0]["txid"], "vout": multisig_utxos[0]["vout"]}
        assert_equal(signer1.lockunspent(False, [prelocked]), True)

        bundle_path = node.datadir_path / "builder-locks-bundle.json"
        z_dest = signer1.z_getnewaddress()
        datadir = str(node.datadir_path)
        rpcport = str(urlparse(node.url).port)

        plan = self.run_tool(
            "plan",
            f"--datadir={datadir}",
            "--chain=regtest",
            f"--rpcport={rpcport}",
            "--rpcwallet=signer1",
            "--signer-wallet=signer1",
            "--signer-wallet=signer2",
            "--signer-wallet=signer3",
            f"--destination={z_dest}=30.00000000",
            f"--bundle={bundle_path}",
            "--max-inputs-per-chunk=4",
            "--no-lock-inputs",
            "--unlock-on-failure",
        )
        assert_equal(plan["tx_count"], 1)

        bundle = json.loads(bundle_path.read_text(encoding="utf-8"))
        for tx in bundle["transactions"]:
            assert prelocked not in tx["selected_inputs"], tx["selected_inputs"]

        locked_after = signer1.listlockunspent()
        assert_equal(len(locked_after), 1)
        assert_equal(locked_after[0]["txid"], prelocked["txid"])
        assert_equal(locked_after[0]["vout"], prelocked["vout"])

        assert_equal(signer1.lockunspent(True, [prelocked]), True)


if __name__ == "__main__":
    WalletShieldedTransferBuilderLocksTest(__file__).main()
