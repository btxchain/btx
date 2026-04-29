#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.

"""Historical SMILE v2 lifecycle coverage for the current v2_send path.

Tests the complete shielded transaction lifecycle on BTX, covering:
  1. PQ multisig wallet creation (2-of-2)
  2. Transparent funding and coinbase maturity
  3. Shielding via z_fundpsbt multisig PSBT workflow
  4. PSBT multi-party signing and broadcast
  5. Shielded-to-shielded v2 sends (z_sendtoaddress)
  6. v2 direct-spend verification (family=v2_send, bundle_type=v2)
  7. Change output detection by sender
  8. Chain of sequential shielded spends
  9. Multi-recipient mixed sendmany coverage
 10. Unshielding back to transparent
 11. Wallet backup, delete, restore, and balance verification
"""

import os
from decimal import Decimal, ROUND_DOWN

from test_framework.test_framework import BitcoinTestFramework
from test_framework.shielded_utils import (
    encrypt_and_unlock_wallet,
    ensure_ring_diversity,
    fund_trusted_transparent_balance,
    unlock_wallet,
)
from test_framework.util import assert_equal, assert_greater_than


def raw_send(node, wallet, from_addr, to_addrs_amounts, fee=Decimal("0.001")):
    """Send funds via raw transaction to bypass PQ fee estimation issues.

    Selects a single mature UTXO from `from_addr`, creates outputs for each
    destination, and returns change to `from_addr`.
    """
    candidates = [u for u in wallet.listunspent(101) if u.get("spendable", False)]
    if not candidates:
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


class WalletSmileV2FullLifecycleTest(BitcoinTestFramework):
    def add_options(self, parser):
        self.add_wallet_options(parser, legacy=False)

    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.extra_args = [["-noautoshieldcoinbase", "-txindex", "-regtestshieldedmatrictdisableheight=500"]]
        self.rpc_timeout = 600

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()
        self.skip_if_no_sqlite()

    def run_test(self):
        node = self.nodes[0]

        # ================================================================
        # Phase 1: Create wallets (miner, 2 signers, single-key receiver)
        # ================================================================
        self.log.info("Phase 1: Create miner, signer, and receiver wallets")

        node.createwallet(wallet_name="miner", descriptors=True)
        miner = node.get_wallet_rpc("miner")
        mine_addr = miner.getnewaddress()

        node.createwallet(wallet_name="signer1", descriptors=True)
        node.createwallet(wallet_name="signer2", descriptors=True)
        signer1 = encrypt_and_unlock_wallet(node, "signer1")
        signer2 = encrypt_and_unlock_wallet(node, "signer2")

        node.createwallet(wallet_name="receiver", descriptors=True)
        receiver = encrypt_and_unlock_wallet(node, "receiver")

        # ================================================================
        # Phase 2: Mine 130 blocks (100 maturity + 30 buffer)
        # ================================================================
        self.log.info("Phase 2: Mine blocks for coinbase maturity")
        self.generatetoaddress(node, 130, mine_addr, sync_fun=self.no_op)
        height = node.getblockcount()
        self.log.info("Chain height: %d", height)
        assert_greater_than(height, 109)

        # ================================================================
        # Phase 3: Create 2-of-2 PQ multisig wallet
        # ================================================================
        self.log.info("Phase 3: Create 2-of-2 PQ multisig wallet")

        # Fund signers so they have addresses with PQ keys
        signer1_addr = signer1.getnewaddress()
        signer2_addr = signer2.getnewaddress()
        raw_send(node, miner, mine_addr, {
            signer1_addr: Decimal("1.0"),
            signer2_addr: Decimal("1.0"),
        })
        self.generatetoaddress(node, 1, mine_addr, sync_fun=self.no_op)

        # Export PQ keys
        key1_info = signer1.exportpqkey(signer1_addr)
        key2_info = signer2.exportpqkey(signer2_addr)
        assert_equal(key1_info["algorithm"], "ml-dsa-44")
        assert_equal(key2_info["algorithm"], "ml-dsa-44")
        pq_keys = [key1_info["key"], key2_info["key"]]
        self.log.info("Exported PQ keys: algorithm=%s", key1_info["algorithm"])

        # Create watch-only multisig wallet
        node.createwallet(
            wallet_name="multisig_watch",
            blank=True,
            descriptors=True,
            disable_private_keys=True,
        )
        multisig = node.get_wallet_rpc("multisig_watch")
        msig_info = multisig.addpqmultisigaddress(2, pq_keys, "lifecycle-2of2", True)
        multisig_address = msig_info["address"]
        assert "sortedmulti_pq(" in msig_info["descriptor"]
        self.log.info("Multisig address: %s", multisig_address)

        # ================================================================
        # Phase 4: Fund multisig with transparent coins
        # ================================================================
        self.log.info("Phase 4: Send transparent funds to multisig")
        raw_send(node, miner, mine_addr, {multisig_address: Decimal("10.0")})
        self.generatetoaddress(node, 1, mine_addr, sync_fun=self.no_op)

        utxos = multisig.listunspent()
        ms_utxos = [u for u in utxos if u["address"] == multisig_address]
        assert len(ms_utxos) >= 1, f"Expected multisig UTXO, got {ms_utxos}"
        self.log.info("Multisig funded: %s BTX", ms_utxos[0]["amount"])

        # ================================================================
        # Phase 5: Shield funds from multisig via z_fundpsbt
        # ================================================================
        self.log.info("Phase 5: Shield funds from multisig via z_fundpsbt")
        z_signer1 = signer1.z_getnewaddress()
        shield_amount = Decimal("5.0")

        funded = multisig.z_fundpsbt(shield_amount, z_signer1)
        assert funded["psbt"], "PSBT should be non-empty"
        assert len(funded["psbt"]) > 10, "PSBT base64 should be substantial"
        assert Decimal(str(funded["fee"])) > Decimal("0")
        assert funded["transparent_inputs"] >= 1
        assert funded["shielded_outputs"] >= 1
        self.log.info(
            "z_fundpsbt: %d inputs, %d shielded outputs, fee=%s",
            funded["transparent_inputs"],
            funded["shielded_outputs"],
            funded["fee"],
        )

        # ================================================================
        # Phase 6: Sign PSBT with both signers
        # ================================================================
        self.log.info("Phase 6: Sign PSBT with both signers (2-of-2)")
        psbt = funded["psbt"]

        signed1 = signer1.walletprocesspsbt(psbt)
        assert_equal(signed1["complete"], False)
        self.log.info("Signer1 partial sign: complete=%s", signed1["complete"])

        signed2 = signer2.walletprocesspsbt(signed1["psbt"])
        assert_equal(signed2["complete"], True)
        self.log.info("Signer2 completes signing: complete=%s", signed2["complete"])

        # ================================================================
        # Phase 7: Finalize PSBT and broadcast
        # ================================================================
        self.log.info("Phase 7: z_finalizepsbt and broadcast")
        finalized = multisig.z_finalizepsbt(signed2["psbt"])
        assert_equal(finalized["complete"], True)
        assert "txid" in finalized
        shield_txid = finalized["txid"]
        self.log.info("Shield txid: %s", shield_txid)

        mempool = node.getrawmempool()
        assert shield_txid in mempool, f"Shield tx {shield_txid} not in mempool"

        # Mine and verify confirmation
        self.generatetoaddress(node, 1, mine_addr, sync_fun=self.no_op)
        mempool_after = node.getrawmempool()
        assert shield_txid not in mempool_after

        # ================================================================
        # Phase 8: Verify shielded balance and build ring diversity
        # ================================================================
        self.log.info("Phase 8: Verify shielded balance and build ring diversity")
        s1_balance = Decimal(signer1.z_getbalance()["balance"])
        self.log.info("Signer1 shielded balance: %s BTX", s1_balance)
        assert_greater_than(s1_balance, Decimal("0"))

        # Fund signer1 with transparent coins for ring diversity seeding.
        # ensure_ring_diversity calls z_shieldfunds which needs transparent
        # inputs, but signer1 only has shielded funds from the PSBT flow.
        s1_transparent_addr = signer1.getnewaddress()
        fund_trusted_transparent_balance(
            self, node, signer1, s1_transparent_addr, Decimal("15.0"),
            sync_fun=self.no_op,
        )

        ensure_ring_diversity(
            self, node, signer1, s1_transparent_addr, z_signer1,
            min_notes=20, topup_amount=Decimal("0.5")
        )

        # ================================================================
        # Phase 9: z_sendtoaddress shielded-to-shielded (v2_send)
        # ================================================================
        self.log.info("Phase 9: Shielded send via z_sendtoaddress (v2_send)")
        z_receiver = receiver.z_getnewaddress()

        send_result = signer1.z_sendtoaddress(
            z_receiver,
            Decimal("1.0"),
            "lifecycle test send",
            "receiver wallet",
            True,
            None,
            True,
        )
        send_txid = send_result["txid"]
        assert send_txid in node.getrawmempool()
        assert_equal(send_result["family"], "v2_send")
        assert_greater_than(send_result["spends"], 0)
        assert_greater_than(send_result["outputs"], 0)
        assert_greater_than(send_result["fee"], Decimal("0"))
        self.log.info(
            "v2_send: txid=%s family=%s spends=%d outputs=%d fee=%s",
            send_txid[:16], send_result["family"],
            send_result["spends"], send_result["outputs"], send_result["fee"],
        )

        # ================================================================
        # Phase 10: Verify v2 direct-spend proof properties
        # ================================================================
        self.log.info("Phase 10: Verify v2 direct-spend proof (family=v2_send, bundle_type=v2)")
        view = signer1.z_viewtransaction(send_txid)
        assert_equal(view["family"], "v2_send")
        self.log.info("z_viewtransaction family: %s", view["family"])

        # Check on-chain bundle type before mining
        raw_tx = node.getrawtransaction(send_txid, 2)
        shielded = raw_tx.get("shielded", {})
        bundle_type = shielded.get("bundle_type", "unknown")
        assert_equal(bundle_type, "v2")
        self.log.info("On-chain bundle_type: %s", bundle_type)

        # Pure shielded: no transparent inputs or outputs
        assert_equal(len(raw_tx["vin"]), 0)
        assert_equal(len(raw_tx["vout"]), 0)
        self.log.info("Confirmed: 0 transparent inputs, 0 transparent outputs")

        # ================================================================
        # Phase 11: Mine and verify receiver got funds
        # ================================================================
        self.log.info("Phase 11: Mine and verify receiver balance")
        self.generatetoaddress(node, 1, mine_addr, sync_fun=self.no_op)

        recv_balance = Decimal(receiver.z_getbalance()["balance"])
        self.log.info("Receiver shielded balance: %s BTX", recv_balance)
        # The receiver should have received the send amount minus fee
        # (z_sendtoaddress with subtractfeefromamount=True deducts fee)
        assert_greater_than(recv_balance, Decimal("0"))

        # Verify the receiver can see their output
        recv_view = receiver.z_viewtransaction(send_txid)
        receiver_sees_output = any(o["is_ours"] for o in recv_view["outputs"])
        receiver_no_spend = not any(s["is_ours"] for s in recv_view["spends"])
        assert receiver_sees_output, "Receiver should see their output"
        assert receiver_no_spend, "Receiver should not see sender's spend"
        self.log.info("Receiver view: sees output=%s, sees spend=%s",
                       receiver_sees_output, not receiver_no_spend)

        # ================================================================
        # Phase 12: Verify change output detected by sender
        # ================================================================
        self.log.info("Phase 12: Verify sender sees change output")
        sender_view = signer1.z_viewtransaction(send_txid)
        sender_sees_spend = any(s["is_ours"] for s in sender_view["spends"])
        sender_sees_change = any(
            o["is_ours"] and o["amount"] > 0 for o in sender_view["outputs"]
        )
        assert sender_sees_spend, "Sender should see their spend"
        assert sender_sees_change, "Sender should see change output"

        sender_balance_after = Decimal(signer1.z_getbalance()["balance"])
        self.log.info("Sender balance after send: %s BTX", sender_balance_after)
        assert_greater_than(sender_balance_after, Decimal("0"))
        sender_notes = signer1.z_listunspent()
        self.log.info("Sender note count: %d", len(sender_notes))

        # ================================================================
        # Phase 13: Chain of 3 more shielded sends
        # ================================================================
        self.log.info("Phase 13: Chain of 3 sequential shielded sends")
        chain_txids = []
        for i in range(3):
            chain_dest = receiver.z_getnewaddress()
            chain_send = signer1.z_sendmany([
                {"address": chain_dest, "amount": Decimal("0.1")}
            ])
            chain_txid = chain_send["txid"]
            assert chain_txid in node.getrawmempool()
            assert_greater_than(chain_send["spends"], 0)
            assert_greater_than(chain_send["outputs"], 0)
            chain_txids.append(chain_txid)
            self.log.info("  Chain send %d: txid=%s", i + 1, chain_txid[:16])

            # Mine each to confirm and make outputs spendable
            self.generatetoaddress(node, 1, mine_addr, sync_fun=self.no_op)

        # Verify all 3 confirmed
        for txid in chain_txids:
            tx_info = signer1.gettransaction(txid)
            assert_greater_than(tx_info["confirmations"], 0)
        self.log.info("All 3 chain sends confirmed")

        # Verify receiver accumulated the sends
        recv_balance_after_chain = Decimal(receiver.z_getbalance()["balance"])
        self.log.info("Receiver balance after chain: %s BTX", recv_balance_after_chain)
        assert_greater_than(recv_balance_after_chain, recv_balance)

        # ================================================================
        # Phase 14: Multi-recipient mixed sendmany
        # ================================================================
        self.log.info("Phase 14: Multi-recipient sendmany to shielded and transparent outputs")
        pre_multi_recv_balance = Decimal(receiver.z_getbalance()["balance"])
        multi_z_dest_a = receiver.z_getnewaddress()
        multi_z_dest_b = receiver.z_getnewaddress()
        multi_t_dest = receiver.getnewaddress()
        multi_send = signer1.z_sendmany([
            {"address": multi_z_dest_a, "amount": Decimal("0.15")},
            {"address": multi_z_dest_b, "amount": Decimal("0.05")},
            {"address": multi_t_dest, "amount": Decimal("0.07")},
        ])
        multi_txid = multi_send["txid"]
        assert multi_txid in node.getrawmempool()
        assert_greater_than(multi_send["outputs"], 0)
        self.generatetoaddress(node, 1, mine_addr, sync_fun=self.no_op)

        receiver_multi_view = receiver.z_viewtransaction(multi_txid)
        assert_equal(receiver_multi_view["family"], "v2_send")
        receiver_multi_outputs = [o for o in receiver_multi_view["outputs"] if o["is_ours"]]
        assert_equal(len(receiver_multi_outputs), 2)
        assert_equal(receiver.getreceivedbyaddress(multi_t_dest), Decimal("0.07"))
        post_multi_recv_balance = Decimal(receiver.z_getbalance()["balance"])
        assert_equal(post_multi_recv_balance - pre_multi_recv_balance, Decimal("0.20"))

        # ================================================================
        # Phase 15: Unshield back to transparent
        # ================================================================
        self.log.info("Phase 15: Unshield to transparent address")
        t_dest = signer1.getnewaddress()
        unshield_amount = Decimal("0.5")
        unshield_send = signer1.z_sendmany([
            {"address": t_dest, "amount": unshield_amount}
        ])
        unshield_txid = unshield_send["txid"]
        assert unshield_txid in node.getrawmempool()
        self.log.info("Unshield txid: %s", unshield_txid[:16])

        unshield_view = signer1.z_viewtransaction(unshield_txid)
        assert_equal(unshield_view["family"], "v2_send")
        unshield_raw = node.getrawtransaction(unshield_txid, 2)
        assert_equal(unshield_raw["shielded"]["bundle_type"], "v2")
        self.log.info(
            "Unshield runs on the v2 direct-send path: family=%s bundle_type=%s",
            unshield_view["family"],
            unshield_raw["shielded"]["bundle_type"],
        )

        self.generatetoaddress(node, 1, mine_addr, sync_fun=self.no_op)
        t_received = signer1.getreceivedbyaddress(t_dest)
        assert_equal(t_received, unshield_amount)
        self.log.info("Transparent received: %s BTX (expected %s)", t_received, unshield_amount)

        # ================================================================
        # Phase 16: Wallet backup, delete, restore, verify balances
        # ================================================================
        self.log.info("Phase 16: Wallet backup, delete, restore, verify")

        # Record balances before backup
        integrity = signer1.z_verifywalletintegrity()
        assert_equal(integrity["integrity_ok"], True)
        pre_backup_shielded = Decimal(signer1.z_getbalance()["balance"])
        pre_backup_notes = signer1.z_listunspent()
        pre_backup_note_count = len(pre_backup_notes)
        self.log.info(
            "Pre-backup: shielded=%s BTX, notes=%d",
            pre_backup_shielded, pre_backup_note_count,
        )

        # Backup
        backup_path = os.path.join(self.options.tmpdir, "signer1_backup.dat")
        signer1.backupwallet(backup_path)
        self.log.info("Wallet backed up to: %s", backup_path)
        assert os.path.exists(backup_path), "Backup file should exist"

        # Unload the wallet
        node.unloadwallet("signer1")
        self.log.info("Wallet unloaded")

        # Restore under a new name
        node.restorewallet("signer1_restored", backup_path)
        restored = unlock_wallet(node, "signer1_restored")
        self.log.info("Wallet restored as signer1_restored")

        # Verify balances match
        restored_integrity = restored.z_verifywalletintegrity()
        assert_equal(restored_integrity["integrity_ok"], True)
        post_restore_shielded = Decimal(restored.z_getbalance()["balance"])
        post_restore_notes = restored.z_listunspent()
        post_restore_note_count = len(post_restore_notes)
        self.log.info(
            "Post-restore: shielded=%s BTX, notes=%d",
            post_restore_shielded, post_restore_note_count,
        )

        assert_equal(post_restore_shielded, pre_backup_shielded)
        assert_equal(post_restore_note_count, pre_backup_note_count)
        self.log.info("Backup/restore verification passed: balances match")

        # ================================================================
        # Summary
        # ================================================================
        self.log.info("=" * 60)
        self.log.info("v2_send full lifecycle test PASSED")
        self.log.info("  Multisig: 2-of-2 PQ (ML-DSA-44)")
        self.log.info("  Shield: z_fundpsbt + PSBT signing + z_finalizepsbt")
        self.log.info("  Send: z_sendtoaddress (family=v2_send, bundle_type=v2)")
        self.log.info("  Chain: 3 sequential shielded sends verified")
        self.log.info("  Unshield: transparent output received correctly")
        self.log.info("  Backup/Restore: shielded balances preserved")
        self.log.info("=" * 60)


if __name__ == "__main__":
    WalletSmileV2FullLifecycleTest(__file__).main()
