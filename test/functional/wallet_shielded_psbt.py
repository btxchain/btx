#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""Functional test for z_fundpsbt and z_finalizepsbt shielded PSBT workflow.

Verifies the complete shielded PSBT lifecycle for a 2-of-2 PQ multisig wallet:
  1. z_fundpsbt creates an unsigned PSBT with a shielded bundle
  2. walletprocesspsbt adds partial signatures from each signer
  3. z_finalizepsbt finalizes and broadcasts the shielded transaction
  4. Error cases are handled gracefully
"""

from decimal import Decimal, ROUND_DOWN

from test_framework.shielded_utils import encrypt_and_unlock_wallet
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_raises_rpc_error


def raw_send(node, wallet, from_addr, to_addrs_amounts, fee=Decimal("0.001")):
    """Send funds via raw transaction to bypass PQ fee estimation issues.

    Selects a single mature UTXO from `from_addr`, creates outputs for each
    destination, and returns change to `from_addr`.
    """
    candidates = [u for u in wallet.listunspent(101) if u.get("spendable", False)]
    if not candidates:
        # Fallback: scan the chain for mature coinbase UTXOs
        tip = node.getblockcount()
        for h in range(1, tip + 1):
            bhash = node.getblockhash(h)
            blk = node.getblock(bhash, 2)
            cb_txid = blk["tx"][0]["txid"]
            txout = node.gettxout(cb_txid, 0, True)
            if txout is None:
                continue
            val = Decimal(str(txout["value"]))
            candidates.append({"txid": cb_txid, "vout": 0, "amount": val, "spendable": True})

    total_needed = sum(to_addrs_amounts.values()) + fee
    utxo = None
    for c in candidates:
        if Decimal(str(c["amount"])) >= total_needed:
            utxo = c
            break
    assert utxo is not None, f"No UTXO large enough for {total_needed}"

    inputs = [{"txid": utxo["txid"], "vout": utxo["vout"]}]
    outputs = {addr: float(amt) for addr, amt in to_addrs_amounts.items()}
    change = (Decimal(str(utxo["amount"])) - total_needed).quantize(
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


class WalletShieldedPsbtTest(BitcoinTestFramework):
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

        # ── Setup: create signer wallets and extract PQ keys ─────────
        self.log.info("Create two signer wallets and a miner wallet")
        node.createwallet(wallet_name="miner", descriptors=True)
        miner = node.get_wallet_rpc("miner")
        mine_addr = miner.getnewaddress()

        node.createwallet(wallet_name="signer1", descriptors=True)
        node.createwallet(wallet_name="signer2", descriptors=True)
        signer1 = encrypt_and_unlock_wallet(node, "signer1")
        signer2 = encrypt_and_unlock_wallet(node, "signer2")

        # Mine enough blocks for coinbase maturity.
        self.generatetoaddress(node, 130, mine_addr, sync_fun=self.no_op)

        # Fund each signer via raw transactions (bypasses PQ fee estimation)
        self.log.info("Fund signer wallets via raw transactions")
        signer1_addr = signer1.getnewaddress()
        signer2_addr = signer2.getnewaddress()
        raw_send(node, miner, mine_addr, {
            signer1_addr: Decimal("1.0"),
            signer2_addr: Decimal("1.0"),
        })
        self.generatetoaddress(node, 1, mine_addr, sync_fun=self.no_op)

        self.log.info("Export PQ keys from each signer")
        key1_info = signer1.exportpqkey(signer1_addr)
        key2_info = signer2.exportpqkey(signer2_addr)
        assert_equal(key1_info["algorithm"], "ml-dsa-44")
        assert_equal(key2_info["algorithm"], "ml-dsa-44")
        pq_keys = [key1_info["key"], key2_info["key"]]

        # ── Setup: create 2-of-2 watch-only multisig wallet ──────────
        self.log.info("Create watch-only 2-of-2 PQ multisig wallet")
        node.createwallet(
            wallet_name="multisig_watch",
            blank=True,
            descriptors=True,
            disable_private_keys=True,
        )
        multisig_wallet = node.get_wallet_rpc("multisig_watch")
        msig_info = multisig_wallet.addpqmultisigaddress(2, pq_keys, "test-2of2", True)
        multisig_address = msig_info["address"]
        assert "sortedmulti_pq(" in msig_info["descriptor"]
        self.log.info("Multisig address: %s", multisig_address)

        # Fund the multisig address via raw transaction
        self.log.info("Fund the multisig address")
        raw_send(node, miner, mine_addr, {multisig_address: Decimal("5.0")})
        self.generatetoaddress(node, 1, mine_addr, sync_fun=self.no_op)

        # Verify the multisig wallet sees the UTXO
        utxos = multisig_wallet.listunspent()
        multisig_utxos = [u for u in utxos if u["address"] == multisig_address]
        assert len(multisig_utxos) >= 1, f"Expected multisig UTXO, got {multisig_utxos}"

        # ── Test z_fundpsbt ──────────────────────────────────────────
        self.log.info("Test z_fundpsbt: create unsigned shielded PSBT")
        shield_amount = Decimal("2.0")
        z_dest = signer1.z_getnewaddress()

        funded = multisig_wallet.z_fundpsbt(shield_amount, z_dest)
        assert funded["psbt"], "PSBT should be non-empty"
        assert len(funded["psbt"]) > 10, "PSBT base64 should be substantial"
        assert Decimal(str(funded["fee"])) > Decimal("0")
        assert funded["transparent_inputs"] >= 1
        assert funded["shielded_outputs"] >= 1
        assert Decimal(str(funded["shielded_amount"])) > Decimal("0")
        assert_equal(funded["fee_authoritative"], True)
        assert funded["estimated_vsize"] > 0
        assert funded["estimated_sigop_cost"] > 0
        assert Decimal(str(funded["required_mempool_fee"])) <= Decimal(str(funded["fee"]))
        self.log.info(
            "z_fundpsbt result: %d inputs, %d shielded outputs, fee=%s",
            funded["transparent_inputs"],
            funded["shielded_outputs"],
            funded["fee"],
        )

        psbt = funded["psbt"]

        # ── Test walletprocesspsbt (signer 1) ────────────────────────
        self.log.info("Test walletprocesspsbt: signer1 partially signs")
        signed1 = signer1.walletprocesspsbt(psbt)
        assert_equal(signed1["complete"], False)
        psbt_after_sig1 = signed1["psbt"]
        self.log.info("Signer1 complete=%s", signed1["complete"])

        # ── Test walletprocesspsbt (signer 2) ────────────────────────
        self.log.info("Test walletprocesspsbt: signer2 completes signing")
        signed2 = signer2.walletprocesspsbt(psbt_after_sig1)
        assert_equal(signed2["complete"], True)
        psbt_fully_signed = signed2["psbt"]
        self.log.info("Signer2 complete=%s", signed2["complete"])

        # ── Test error: z_finalizepsbt with incomplete sigs ──────────
        self.log.info("Test error: z_finalizepsbt with only 1-of-2 signatures")
        incomplete_result = multisig_wallet.z_finalizepsbt(psbt_after_sig1, False)
        assert_equal(incomplete_result["complete"], False)

        dry_run = multisig_wallet.z_finalizepsbt(psbt_fully_signed, False)
        assert_equal(dry_run["complete"], True)
        decoded_dry = node.decoderawtransaction(dry_run["hex"])
        assert_equal(decoded_dry["vsize"], funded["estimated_vsize"])
        assert_equal(funded["estimated_sigop_cost"], 550 * funded["transparent_inputs"])

        # ── Test z_finalizepsbt ──────────────────────────────────────
        self.log.info("Test z_finalizepsbt: finalize and broadcast")
        finalized = multisig_wallet.z_finalizepsbt(psbt_fully_signed)
        assert_equal(finalized["complete"], True)
        assert "txid" in finalized, "Finalized result should include txid"
        txid = finalized["txid"]
        self.log.info("Finalized txid: %s", txid)

        # Verify the tx is in the mempool
        mempool = node.getrawmempool()
        assert txid in mempool, f"txid {txid} not found in mempool"

        # Mine a block and verify the tx is confirmed
        self.log.info("Mine a block and verify confirmation")
        self.generatetoaddress(node, 1, mine_addr, sync_fun=self.no_op)
        mempool_after = node.getrawmempool()
        assert txid not in mempool_after, "tx should no longer be in mempool after mining"
        # Use the tip block hash to look up the confirmed transaction
        tip_hash = node.getbestblockhash()
        raw_tx = node.getrawtransaction(txid, True, tip_hash)
        assert_equal(raw_tx["in_active_chain"], True)
        assert raw_tx["confirmations"] >= 1

        # ── Test error: z_fundpsbt with insufficient funds ───────────
        self.log.info("Test error: z_fundpsbt with insufficient funds")
        node.createwallet(wallet_name="empty_watch", blank=True, descriptors=True, disable_private_keys=True)
        empty_wallet = node.get_wallet_rpc("empty_watch")
        assert_raises_rpc_error(
            -6,
            "Insufficient transparent funds",
            empty_wallet.z_fundpsbt,
            Decimal("100.0"),
            z_dest,
        )

        self.log.info("All shielded PSBT tests passed")


if __name__ == "__main__":
    WalletShieldedPsbtTest(__file__).main()
