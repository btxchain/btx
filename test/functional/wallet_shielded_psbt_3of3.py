#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""Regression and stress coverage for 3-of-3 PQ multisig shielded PSBTs."""

import base64
from decimal import Decimal, ROUND_DOWN

from test_framework.shielded_utils import encrypt_and_unlock_wallet
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_raises_rpc_error


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


class WalletShieldedPsbt3of3Test(BitcoinTestFramework):
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

    def run_test(self):
        node = self.nodes[0]

        self.log.info("Create three signer wallets and a miner wallet")
        node.createwallet(wallet_name="miner", descriptors=True)
        miner = node.get_wallet_rpc("miner")
        mine_addr = miner.getnewaddress()

        node.createwallet(wallet_name="signer1", descriptors=True)
        node.createwallet(wallet_name="signer2", descriptors=True)
        node.createwallet(wallet_name="signer3", descriptors=True)
        signer1 = encrypt_and_unlock_wallet(node, "signer1")
        signer2 = encrypt_and_unlock_wallet(node, "signer2")
        signer3 = encrypt_and_unlock_wallet(node, "signer3")

        self.generatetoaddress(node, 200, mine_addr, sync_fun=self.no_op)

        self.log.info("Fund signer wallets via raw transactions")
        signer1_addr = signer1.getnewaddress()
        signer2_addr = signer2.getnewaddress()
        signer3_addr = signer3.getnewaddress()
        raw_send(node, miner, mine_addr, {
            signer1_addr: Decimal("1.0"),
            signer2_addr: Decimal("1.0"),
            signer3_addr: Decimal("1.0"),
        })
        self.generatetoaddress(node, 1, mine_addr, sync_fun=self.no_op)

        self.log.info("Export PQ keys from each signer")
        key1_info = signer1.exportpqkey(signer1_addr)
        key2_info = signer2.exportpqkey(signer2_addr)
        key3_info = signer3.exportpqkey(signer3_addr)
        pq_keys = [key1_info["key"], key2_info["key"], key3_info["key"]]

        self.log.info("Create watch-only 3-of-3 PQ multisig wallet")
        node.createwallet(
            wallet_name="multisig_watch",
            blank=True,
            descriptors=True,
            disable_private_keys=True,
        )
        multisig_wallet = node.get_wallet_rpc("multisig_watch")
        msig_info = multisig_wallet.addpqmultisigaddress(3, pq_keys, "test-3of3", True)
        multisig_address = msig_info["address"]
        assert "sortedmulti_pq(" in msig_info["descriptor"]
        self.log.info("Multisig address: %s", multisig_address)

        self.log.info("Fund the multisig address")
        raw_send(node, miner, mine_addr, {multisig_address: Decimal("5.0")})
        self.generatetoaddress(node, 1, mine_addr, sync_fun=self.no_op)

        utxos = multisig_wallet.listunspent()
        multisig_utxos = [u for u in utxos if u["address"] == multisig_address]
        assert len(multisig_utxos) >= 1, f"Expected multisig UTXO, got {multisig_utxos}"

        self.log.info("Test z_fundpsbt: create unsigned shielded PSBT")
        shield_amount = Decimal("2.0")
        z_dest = signer1.z_getnewaddress()

        funded = multisig_wallet.z_fundpsbt(shield_amount, z_dest)
        assert funded["psbt"]
        assert_equal(funded["fee_authoritative"], True)
        assert funded["estimated_vsize"] > 0
        assert_equal(funded["estimated_sigop_cost"], 1050 * funded["transparent_inputs"])
        assert Decimal(str(funded["required_mempool_fee"])) <= Decimal(str(funded["fee"]))
        psbt = funded["psbt"]
        self.log.info("z_fundpsbt: %d inputs, %d shielded outputs",
                      funded["transparent_inputs"], funded["shielded_outputs"])

        self.log.info("walletprocesspsbt: signer1 partially signs")
        signed1 = signer1.walletprocesspsbt(psbt)
        assert_equal(signed1["complete"], False)

        self.log.info("walletprocesspsbt: signer2 partially signs")
        signed2 = signer2.walletprocesspsbt(signed1["psbt"])
        assert_equal(signed2["complete"], False)

        self.log.info("walletprocesspsbt: signer3 completes signing")
        signed3 = signer3.walletprocesspsbt(signed2["psbt"])
        assert_equal(signed3["complete"], True)
        psbt_fully_signed = signed3["psbt"]

        preview = multisig_wallet.z_finalizepsbt(psbt_fully_signed, False)
        assert_equal(preview["complete"], True)
        preview_decoded = node.decoderawtransaction(preview["hex"])
        assert_equal(preview_decoded["vsize"], funded["estimated_vsize"])

        self.log.info("z_finalizepsbt: finalize and broadcast (this crashes without fix)")
        finalized = multisig_wallet.z_finalizepsbt(psbt_fully_signed)
        assert_equal(finalized["complete"], True)
        assert "txid" in finalized
        txid = finalized["txid"]
        self.log.info("Finalized txid: %s", txid)

        mempool = node.getrawmempool()
        assert txid in mempool, f"txid {txid} not found in mempool"

        self.log.info("Mine a block and verify confirmation")
        self.generatetoaddress(node, 1, mine_addr, sync_fun=self.no_op)
        tip_hash = node.getbestblockhash()
        raw_tx = node.getrawtransaction(txid, True, tip_hash)
        assert_equal(raw_tx["in_active_chain"], True)
        assert raw_tx["confirmations"] >= 1

        # ── Stress scenario: many UTXOs, malformed PSBT rejection, dry-run finalize ──
        self.log.info("Create a second 3-of-3 multisig address for large-input stress")
        stress_signer1_addr = signer1.getnewaddress()
        stress_signer2_addr = signer2.getnewaddress()
        stress_signer3_addr = signer3.getnewaddress()
        stress_key1 = signer1.exportpqkey(stress_signer1_addr)
        stress_key2 = signer2.exportpqkey(stress_signer2_addr)
        stress_key3 = signer3.exportpqkey(stress_signer3_addr)
        stress_keys = [stress_key1["key"], stress_key2["key"], stress_key3["key"]]

        node.createwallet(
            wallet_name="multisig_stress",
            blank=True,
            descriptors=True,
            disable_private_keys=True,
        )
        multisig_stress = node.get_wallet_rpc("multisig_stress")
        stress_info = multisig_stress.addpqmultisigaddress(3, stress_keys, "stress-3of3", True)
        stress_address = stress_info["address"]
        assert "sortedmulti_pq(" in stress_info["descriptor"]

        stress_z_dest = signer1.z_getnewaddress()

        per_utxo = Decimal("0.12000000")
        fee = Decimal("0.00200000")
        stress_utxo_count = 26

        self.log.info(
            "Fund stress multisig with %d transparent UTXOs for the large-input finalize path",
            stress_utxo_count,
        )
        fund_same_address_many(node, miner, mine_addr, stress_address, per_utxo, stress_utxo_count)
        self.generatetoaddress(node, 1, mine_addr, sync_fun=self.no_op)

        stress_utxos = [u for u in multisig_stress.listunspent() if u["address"] == stress_address]
        assert len(stress_utxos) >= stress_utxo_count, f"Expected at least {stress_utxo_count} stress UTXOs"

        policy_preview = signer1.z_planshieldfunds(Decimal("0.1"), stress_z_dest)
        stress_target_inputs = min(24, int(policy_preview["policy"]["applied_max_inputs_per_chunk"]))
        assert stress_target_inputs >= 2
        request_amount = ((stress_target_inputs - 1) * per_utxo) + Decimal("0.00010000")

        stress_funded = multisig_stress.z_fundpsbt(
            request_amount,
            stress_z_dest,
            fee,
            {"max_inputs_per_chunk": stress_target_inputs},
        )
        assert_equal(stress_funded["fee_authoritative"], True)
        assert_equal(stress_funded["transparent_inputs"], stress_target_inputs)
        assert_equal(stress_funded["shielded_outputs"], 1)
        assert_equal(stress_funded["estimated_sigop_cost"], 1050 * stress_target_inputs)
        assert Decimal(str(stress_funded["required_mempool_fee"])) <= fee
        stress_psbt = stress_funded["psbt"]

        self.log.info("Sign the large-input PSBT with all three signers")
        stress_signed1 = signer1.walletprocesspsbt(stress_psbt)
        assert_equal(stress_signed1["complete"], False)
        stress_signed2 = signer2.walletprocesspsbt(stress_signed1["psbt"])
        assert_equal(stress_signed2["complete"], False)
        stress_signed3 = signer3.walletprocesspsbt(stress_signed2["psbt"])
        assert_equal(stress_signed3["complete"], True)
        stress_psbt_fully_signed = stress_signed3["psbt"]

        self.log.info("Low-fee large-input PSBTs should be detectable before broadcast")
        low_fee_funded = multisig_stress.z_fundpsbt(
            request_amount,
            stress_z_dest,
            Decimal("0.00005000"),
            {"max_inputs_per_chunk": stress_target_inputs},
        )
        assert_equal(low_fee_funded["fee_authoritative"], True)
        assert Decimal(str(low_fee_funded["required_mempool_fee"])) > Decimal("0.00005000")
        low_fee_signed1 = signer1.walletprocesspsbt(low_fee_funded["psbt"])
        assert_equal(low_fee_signed1["complete"], False)
        low_fee_signed2 = signer2.walletprocesspsbt(low_fee_signed1["psbt"])
        assert_equal(low_fee_signed2["complete"], False)
        low_fee_signed3 = signer3.walletprocesspsbt(low_fee_signed2["psbt"])
        assert_equal(low_fee_signed3["complete"], True)
        assert_raises_rpc_error(
            -26,
            "min relay fee not met",
            multisig_stress.z_finalizepsbt,
            low_fee_signed3["psbt"],
        )

        self.log.info("Malformed PSBT bytes should be rejected during decode")
        malformed_raw = base64.b64decode(stress_psbt_fully_signed)[:-1]
        assert_raises_rpc_error(
            -22,
            "TX decode failed",
            multisig_stress.z_finalizepsbt,
            base64.b64encode(malformed_raw).decode("utf8"),
            False,
        )

        self.log.info("broadcast=false should finalize but not submit to the mempool")
        mempool_before = sorted(node.getrawmempool())
        stress_dry_run = multisig_stress.z_finalizepsbt(stress_psbt_fully_signed, False)
        assert_equal(stress_dry_run["complete"], True)
        assert "txid" not in stress_dry_run
        assert len(stress_dry_run["hex"]) > 0
        assert_equal(sorted(node.getrawmempool()), mempool_before)

        self.log.info("Advance the chain before actual finalize to exercise wallet resync")
        self.generatetoaddress(node, 1, mine_addr, sync_fun=self.no_op)

        stress_finalized = multisig_stress.z_finalizepsbt(stress_psbt_fully_signed)
        assert_equal(stress_finalized["complete"], True)
        assert "txid" in stress_finalized
        assert_equal(stress_finalized["hex"], stress_dry_run["hex"])
        stress_txid = stress_finalized["txid"]
        assert stress_txid in node.getrawmempool(), f"stress txid {stress_txid} not found in mempool"

        self.generatetoaddress(node, 1, mine_addr, sync_fun=self.no_op)
        stress_tip = node.getbestblockhash()
        stress_raw_tx = node.getrawtransaction(stress_txid, True, stress_tip)
        assert_equal(stress_raw_tx["in_active_chain"], True)
        assert stress_raw_tx["confirmations"] >= 1

        # ── Large-input scenario: 50 compatible UTXOs into one shielded output ──
        self.log.info("Create a third 3-of-3 multisig address for the 50-input shielded PSBT scenario")
        large_signer1_addr = signer1.getnewaddress()
        large_signer2_addr = signer2.getnewaddress()
        large_signer3_addr = signer3.getnewaddress()
        large_key1 = signer1.exportpqkey(large_signer1_addr)
        large_key2 = signer2.exportpqkey(large_signer2_addr)
        large_key3 = signer3.exportpqkey(large_signer3_addr)
        large_keys = [large_key1["key"], large_key2["key"], large_key3["key"]]

        node.createwallet(
            wallet_name="multisig_50x20",
            blank=True,
            descriptors=True,
            disable_private_keys=True,
        )
        multisig_50x20 = node.get_wallet_rpc("multisig_50x20")
        large_info = multisig_50x20.addpqmultisigaddress(3, large_keys, "fifty-by-twenty", True)
        large_address = large_info["address"]
        large_z_dest = signer2.z_getnewaddress()

        large_utxo_count = 50
        large_utxo_value = Decimal("0.80000000")
        large_total_value = large_utxo_count * large_utxo_value
        low_fee = Decimal("0.00100000")
        accepted_fee = Decimal("0.00110000")
        accepted_amount = large_total_value - accepted_fee

        self.log.info("Fund the large-input multisig with %d x %s BTX UTXOs", large_utxo_count, large_utxo_value)
        for _ in range(large_utxo_count):
            raw_send(node, miner, mine_addr, {large_address: large_utxo_value})
            self.generatetoaddress(node, 1, mine_addr, sync_fun=self.no_op)

        underpriced = multisig_50x20.z_fundpsbt(
            large_total_value - low_fee,
            large_z_dest,
            low_fee,
            {"max_inputs_per_chunk": large_utxo_count},
        )
        assert_equal(underpriced["transparent_inputs"], large_utxo_count)
        underpriced_signed1 = signer1.walletprocesspsbt(underpriced["psbt"])
        assert_equal(underpriced_signed1["complete"], False)
        underpriced_signed2 = signer2.walletprocesspsbt(underpriced_signed1["psbt"])
        assert_equal(underpriced_signed2["complete"], False)
        underpriced_signed3 = signer3.walletprocesspsbt(underpriced_signed2["psbt"])
        assert_equal(underpriced_signed3["complete"], True)
        assert_raises_rpc_error(
            -26,
            "min relay fee not met",
            multisig_50x20.z_finalizepsbt,
            underpriced_signed3["psbt"],
        )

        large_funded = multisig_50x20.z_fundpsbt(
            accepted_amount,
            large_z_dest,
            accepted_fee,
            {"max_inputs_per_chunk": large_utxo_count},
        )
        assert_equal(large_funded["fee_authoritative"], True)
        assert_equal(large_funded["transparent_inputs"], large_utxo_count)
        assert_equal(large_funded["shielded_outputs"], 1)
        assert_equal(large_funded["shielded_amount"], accepted_amount)
        assert_equal(large_funded["estimated_sigop_cost"], 1050 * large_utxo_count)
        assert Decimal(str(large_funded["required_mempool_fee"])) <= accepted_fee

        large_signed1 = signer1.walletprocesspsbt(large_funded["psbt"])
        assert_equal(large_signed1["complete"], False)
        large_signed2 = signer2.walletprocesspsbt(large_signed1["psbt"])
        assert_equal(large_signed2["complete"], False)
        large_signed3 = signer3.walletprocesspsbt(large_signed2["psbt"])
        assert_equal(large_signed3["complete"], True)

        large_dry_run = multisig_50x20.z_finalizepsbt(large_signed3["psbt"], False)
        assert_equal(large_dry_run["complete"], True)
        large_decoded = node.decoderawtransaction(large_dry_run["hex"])
        assert_equal(
            large_funded["estimated_vsize"],
            max(large_decoded["vsize"], large_funded["estimated_sigop_cost"] * 20),
        )
        large_mempool_accept = node.testmempoolaccept([large_dry_run["hex"]])[0]
        assert_equal(large_mempool_accept["allowed"], True)

        large_finalized = multisig_50x20.z_finalizepsbt(large_signed3["psbt"])
        assert_equal(large_finalized["complete"], True)
        large_txid = large_finalized["txid"]
        assert large_txid in node.getrawmempool(), f"large txid {large_txid} not found in mempool"

        self.generatetoaddress(node, 1, mine_addr, sync_fun=self.no_op)
        large_tip = node.getbestblockhash()
        large_raw_tx = node.getrawtransaction(large_txid, True, large_tip)
        assert_equal(large_raw_tx["in_active_chain"], True)
        assert large_raw_tx["confirmations"] >= 1

        self.log.info("3-of-3 shielded PSBT regression and stress test passed")


if __name__ == "__main__":
    WalletShieldedPsbt3of3Test(__file__).main()
