#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""Functional coverage for the deterministic shielded transfer bundle tool."""

import json
import importlib.util
import subprocess
import sys
from decimal import Decimal, ROUND_DOWN
from pathlib import Path
from types import SimpleNamespace
from urllib.parse import urlparse

from test_framework.shielded_utils import encrypt_and_unlock_wallet
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_greater_than


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


class WalletShieldedTransferBuilderTest(BitcoinTestFramework):
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

        self.log.info("Import the same 3-of-3 PQ multisig descriptor into all signer wallets")
        pq_keys = [
            signer1.exportpqkey(signer1_addr)["key"],
            signer2.exportpqkey(signer2_addr)["key"],
            signer3.exportpqkey(signer3_addr)["key"],
        ]
        msig_info = signer1.addpqmultisigaddress(3, pq_keys, "builder-3of3", True)
        signer2_info = signer2.addpqmultisigaddress(3, pq_keys, "builder-3of3", True)
        signer3_info = signer3.addpqmultisigaddress(3, pq_keys, "builder-3of3", True)
        multisig = signer1
        multisig_address = msig_info["address"]
        assert_equal(signer2_info["address"], multisig_address)
        assert_equal(signer3_info["address"], multisig_address)
        assert "sortedmulti_pq(" in msig_info["descriptor"]

        self.log.info("Fund the multisig wallet with many 20 BTX outputs")
        fund_same_address_many(node, miner, mine_addr, multisig_address, Decimal("20.0"), 12)
        self.generatetoaddress(node, 1, mine_addr, sync_fun=self.no_op)
        multisig_utxos = [u for u in multisig.listunspent() if u["address"] == multisig_address]
        assert_equal(len(multisig_utxos), 12)

        z_dest_1 = signer1.z_getnewaddress()
        z_dest_2 = signer2.z_getnewaddress()
        datadir = str(node.datadir_path)
        rpcport = str(urlparse(node.url).port)
        bundle_path = node.datadir_path / "builder-bundle.json"
        no_lock_bundle_path = node.datadir_path / "builder-nolock-bundle.json"
        simulation_path = node.datadir_path / "builder-simulation.json"
        result_path = node.datadir_path / "builder-result.json"

        self.log.info("Builder config parser should accept btx.conf alongside bitcoin.conf")
        conf_dir = node.datadir_path / "builder-conf"
        conf_dir.mkdir()
        (conf_dir / "btx.conf").write_text(
            f"rpcport={rpcport}\nrpcuser=confuser\nrpcpassword=confpass\n",
            encoding="utf-8",
        )
        spec = importlib.util.spec_from_file_location("shielded_transfer_builder", TOOL_PATH)
        builder = importlib.util.module_from_spec(spec)
        assert spec.loader is not None
        spec.loader.exec_module(builder)
        assert_equal(builder.parse_bitcoin_conf(conf_dir, "main")["rpcport"], rpcport)
        conf_args = SimpleNamespace(
            rpcuser=None,
            rpcpassword=None,
            datadir=str(conf_dir),
            chain="main",
        )
        assert_equal(builder.rpc_auth_header(conf_args), "Basic Y29uZnVzZXI6Y29uZnBhc3M=")

        self.log.info("No-lock planning should honor pre-existing locks and release temporary plan locks")
        prelocked = {"txid": multisig_utxos[0]["txid"], "vout": multisig_utxos[0]["vout"]}
        assert_equal(multisig.lockunspent(False, [prelocked]), True)
        no_lock_plan = self.run_tool(
            "plan",
            f"--datadir={datadir}",
            "--chain=regtest",
            f"--rpcport={rpcport}",
            "--rpcwallet=signer1",
            "--signer-wallet=signer1",
            "--signer-wallet=signer2",
            "--signer-wallet=signer3",
            f"--destination={z_dest_1}=30.00000000",
            f"--bundle={no_lock_bundle_path}",
            "--max-inputs-per-chunk=4",
            "--no-lock-inputs",
            "--unlock-on-failure",
        )
        assert_equal(no_lock_plan["tx_count"], 1)
        no_lock_bundle = json.loads(no_lock_bundle_path.read_text(encoding="utf-8"))
        for tx in no_lock_bundle["transactions"]:
            assert prelocked not in tx["selected_inputs"], tx["selected_inputs"]
        locked_after_no_lock = multisig.listlockunspent()
        assert_equal(len(locked_after_no_lock), 1)
        assert_equal(locked_after_no_lock[0]["txid"], prelocked["txid"])
        assert_equal(locked_after_no_lock[0]["vout"], prelocked["vout"])
        assert_equal(multisig.lockunspent(True, [prelocked]), True)

        self.log.info("Plan a deterministic two-destination transfer bundle")
        plan = self.run_tool(
            "plan",
            f"--datadir={datadir}",
            "--chain=regtest",
            f"--rpcport={rpcport}",
            "--rpcwallet=signer1",
            "--signer-wallet=signer1",
            "--signer-wallet=signer2",
            "--signer-wallet=signer3",
            f"--destination={z_dest_1}=95.00000000",
            f"--destination={z_dest_2}=95.00000000",
            f"--bundle={bundle_path}",
            "--max-inputs-per-chunk=4",
            "--block-max-sigops=6000",
            "--unlock-on-failure",
        )
        assert_equal(plan["tx_count"], 4)
        assert_equal(plan["block_count"], 2)
        bundle = json.loads(bundle_path.read_text(encoding="utf-8"))
        assert_equal(bundle["format"], "btx-shielded-transfer-bundle/1")
        assert_equal(bundle["totals"]["tx_count"], 4)
        assert_equal(bundle["totals"]["block_count"], 2)
        assert_equal(len(bundle["transactions"]), 4)
        assert_equal(len(bundle["blocks"]), 2)
        assert_equal(bundle["destinations"][0]["address"], z_dest_1)
        assert_equal(bundle["destinations"][1]["address"], z_dest_2)
        locked = multisig.listlockunspent()
        assert_equal(len(locked), sum(len(tx["selected_inputs"]) for tx in bundle["transactions"]))

        self.log.info("Simulate the exact bundle and confirm mempool acceptance")
        simulation = self.run_tool(
            "simulate",
            f"--datadir={datadir}",
            "--chain=regtest",
            f"--rpcport={rpcport}",
            f"--bundle={bundle_path}",
            f"--simulation={simulation_path}",
        )
        assert_equal(simulation["tx_count"], 4)
        assert_equal(simulation["block_count"], 2)
        simulation_doc = json.loads(simulation_path.read_text(encoding="utf-8"))
        assert_equal(simulation_doc["format"], "btx-shielded-transfer-simulation/1")
        assert_equal(len(simulation_doc["transactions"]), 4)
        assert_equal(len(simulation_doc["blocks"]), 2)
        for tx in simulation_doc["transactions"]:
            assert_equal(tx["allowed"], True)
            assert tx["txid"]

        self.log.info("Execute the planned bundle and verify deterministic txids")
        result = self.run_tool(
            "execute",
            f"--datadir={datadir}",
            "--chain=regtest",
            f"--rpcport={rpcport}",
            f"--bundle={bundle_path}",
            f"--simulation={simulation_path}",
            f"--result={result_path}",
        )
        result_doc = json.loads(result_path.read_text(encoding="utf-8"))
        assert_equal(result_doc["format"], "btx-shielded-transfer-execution/1")
        assert_equal(len(result_doc["txids"]), 4)
        assert_equal(result_doc["txids"], [tx["txid"] for tx in simulation_doc["transactions"]])
        mempool = node.getrawmempool()
        for txid in result_doc["txids"]:
            assert txid in mempool, f"{txid} missing from mempool"
        assert_equal(multisig.listlockunspent(), [])

        self.log.info("Mine and confirm the executed transactions")
        self.generatetoaddress(node, 1, mine_addr, sync_fun=self.no_op)
        for txid in result_doc["txids"]:
            tx = multisig.gettransaction(txid)
            assert_greater_than(tx["confirmations"], 0)


if __name__ == "__main__":
    WalletShieldedTransferBuilderTest(__file__).main()
