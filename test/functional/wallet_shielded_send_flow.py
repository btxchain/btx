#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.

from decimal import Decimal

from test_framework.test_framework import BitcoinTestFramework
from test_framework.shielded_utils import (
    encrypt_and_unlock_wallet,
    ensure_ring_diversity,
    fund_trusted_transparent_balance,
)
from test_framework.util import assert_equal, assert_raises_rpc_error


LIVE_DIRECT_LIMIT = 8
STABLE_TEST_SEND_INPUTS = 2


class WalletShieldedSendFlowTest(BitcoinTestFramework):
    def add_options(self, parser):
        self.add_wallet_options(parser)

    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.extra_args = [["-autoshieldcoinbase=0"]]
        # The functional framework halves this value when creating the live RPC
        # connection, so use a larger headroom for the slowest debug-build
        # 8-input shielded send/unshield proofs.
        self.rpc_timeout = 1800

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def run_test(self):
        node = self.nodes[0]
        node.createwallet(wallet_name="shielded", descriptors=True)
        node.createwallet(wallet_name="receiver", descriptors=True)
        node.createwallet(wallet_name="unshielder", descriptors=True)
        node.createwallet(wallet_name="exactunshielder", descriptors=True)
        node.createwallet(wallet_name="funder", descriptors=True)
        wallet = encrypt_and_unlock_wallet(node, "shielded")
        receiver = encrypt_and_unlock_wallet(node, "receiver")
        unshielder = encrypt_and_unlock_wallet(node, "unshielder")
        exact_unshielder = encrypt_and_unlock_wallet(node, "exactunshielder")
        funder = encrypt_and_unlock_wallet(node, "funder")

        def compact_to_live_direct_spend_envelope(shielded_wallet):
            while shielded_wallet.z_getbalance()["note_count"] > STABLE_TEST_SEND_INPUTS:
                merge = shielded_wallet.z_mergenotes(LIVE_DIRECT_LIMIT)
                assert merge["txid"] in node.getrawmempool()
                assert merge["merged_notes"] >= 2
                assert merge["merged_notes"] <= LIVE_DIRECT_LIMIT
                assert_equal(shielded_wallet.z_viewtransaction(merge["txid"])["family"], "v2_send")
                self.generatetoaddress(node, 1, mine_addr, sync_fun=self.no_op)

        self.log.info("Mine transparent funds and shield into the pool")
        mine_addr = wallet.getnewaddress()
        fund_trusted_transparent_balance(
            self, node, wallet, mine_addr, Decimal("10.0"), sync_fun=self.no_op
        )
        fund_trusted_transparent_balance(
            self, node, funder, funder.getnewaddress(), Decimal("10.0"), sync_fun=self.no_op
        )

        z_from = wallet.z_getnewaddress()
        z_to = wallet.z_getnewaddress()
        wallet.z_shieldfunds(Decimal("2.0"), z_from)
        self.generatetoaddress(node, 1, mine_addr, sync_fun=self.no_op)
        ensure_ring_diversity(
            self, node, wallet, mine_addr, z_from, min_notes=16, topup_amount=Decimal("0.25")
        )

        shielded_balance = Decimal(wallet.z_getbalance()["balance"])
        assert shielded_balance > Decimal("0")
        assert len(wallet.z_listunspent(1, 9999999, False)) >= 1

        self.log.info("Send shielded->shielded twice and verify wallet avoids mempool nullifier conflicts")
        first_send = wallet.z_sendmany([{"address": z_to, "amount": Decimal("1.0")}])
        assert first_send["txid"] in node.getrawmempool()
        assert first_send["spends"] >= 1
        assert first_send["outputs"] >= 1
        first_view = wallet.z_viewtransaction(first_send["txid"])
        assert_equal(first_view["family"], "v2_send")
        second_send = wallet.z_sendmany([{"address": z_to, "amount": Decimal("0.1")}])
        assert second_send["txid"] in node.getrawmempool()
        assert second_send["txid"] != first_send["txid"]
        assert second_send["spends"] >= 1
        assert second_send["outputs"] >= 1
        self.generatetoaddress(node, 1, mine_addr, sync_fun=self.no_op)

        self.log.info("Force a multi-input shielded send on a receiver-only wallet")
        receiver_addr = receiver.z_getnewaddress()
        funder.z_sendmany([{"address": receiver_addr, "amount": Decimal("0.40")}])
        self.generatetoaddress(node, 1, mine_addr, sync_fun=self.no_op)
        funder.z_sendmany([{"address": receiver_addr, "amount": Decimal("0.60")}])
        self.generatetoaddress(node, 1, mine_addr, sync_fun=self.no_op)

        multi_input_dest = wallet.z_getnewaddress()
        multi_input_send = receiver.z_sendmany([{"address": multi_input_dest, "amount": Decimal("0.95")}])
        assert multi_input_send["txid"] in node.getrawmempool()
        assert_equal(multi_input_send["spends"], 2)
        assert_equal(receiver.z_viewtransaction(multi_input_send["txid"])["family"], "v2_send")
        self.generatetoaddress(node, 1, mine_addr, sync_fun=self.no_op)

        self.log.info("Surface a clear error once a direct shielded send would need more than the live input cap")
        overflow_addr = receiver.z_getnewaddress()
        for _ in range(LIVE_DIRECT_LIMIT + 1):
            funder.z_sendmany([{"address": overflow_addr, "amount": Decimal("0.05")}])
            self.generatetoaddress(node, 1, mine_addr, sync_fun=self.no_op)
        overflow_dest = wallet.z_getnewaddress()
        assert_raises_rpc_error(
            -4,
            "selected note count exceeds live direct shielded spend limit",
            receiver.z_sendmany,
            [{"address": overflow_dest, "amount": Decimal("0.44")}],
        )

        self.log.info("Iterated note merges recover the receiver wallet into the live direct-send envelope")
        compact_to_live_direct_spend_envelope(receiver)
        recovered_dest = wallet.z_getnewaddress()
        recovered_send = receiver.z_sendmany([{"address": recovered_dest, "amount": Decimal("0.30")}])
        assert recovered_send["txid"] in node.getrawmempool()
        assert recovered_send["spends"] <= STABLE_TEST_SEND_INPUTS
        assert_equal(receiver.z_viewtransaction(recovered_send["txid"])["family"], "v2_send")
        self.generatetoaddress(node, 1, mine_addr, sync_fun=self.no_op)

        self.log.info("Exercise an 8-note live merge on a fresh receiver-only wallet")
        node.createwallet(wallet_name="mergeprobe", descriptors=True)
        mergeprobe = encrypt_and_unlock_wallet(node, "mergeprobe")
        mergeprobe_addr = mergeprobe.z_getnewaddress()
        for _ in range(LIVE_DIRECT_LIMIT):
            funder.z_sendmany([{"address": mergeprobe_addr, "amount": Decimal("0.07")}])
            self.generatetoaddress(node, 1, mine_addr, sync_fun=self.no_op)
        assert_equal(mergeprobe.z_getbalance()["note_count"], LIVE_DIRECT_LIMIT)
        mergeprobe_merge = mergeprobe.z_mergenotes(LIVE_DIRECT_LIMIT)
        assert mergeprobe_merge["txid"] in node.getrawmempool()
        assert_equal(mergeprobe_merge["merged_notes"], LIVE_DIRECT_LIMIT)
        assert_equal(mergeprobe.z_viewtransaction(mergeprobe_merge["txid"])["family"], "v2_send")
        self.generatetoaddress(node, 1, mine_addr, sync_fun=self.no_op)
        assert_equal(mergeprobe.z_getbalance()["note_count"], 1)

        self.log.info("Canonical fee path: z_mergenotes rounds a non-bucket fee before computing the merged output")
        node.createwallet(wallet_name="mergecanonicalfee", descriptors=True)
        mergecanonicalfee = encrypt_and_unlock_wallet(node, "mergecanonicalfee")
        mergecanonicalfee_addr = mergecanonicalfee.z_getnewaddress()
        for _ in range(LIVE_DIRECT_LIMIT):
            funder.z_sendmany([{"address": mergecanonicalfee_addr, "amount": Decimal("0.07")}])
            self.generatetoaddress(node, 1, mine_addr, sync_fun=self.no_op)
        assert_equal(mergecanonicalfee.z_getbalance()["note_count"], LIVE_DIRECT_LIMIT)
        mergecanonicalfee_merge = mergecanonicalfee.z_mergenotes(
            LIVE_DIRECT_LIMIT,
            Decimal("0.00131619"),
        )
        assert mergecanonicalfee_merge["txid"] in node.getrawmempool()
        assert_equal(mergecanonicalfee_merge["merged_notes"], LIVE_DIRECT_LIMIT)
        assert_equal(mergecanonicalfee.z_viewtransaction(mergecanonicalfee_merge["txid"])["family"], "v2_send")
        self.generatetoaddress(node, 1, mine_addr, sync_fun=self.no_op)
        assert_equal(mergecanonicalfee.z_getbalance()["note_count"], 1)

        self.log.info("Stress supported multi-input sends on fresh receiver-only wallets")
        for iteration in range(2):
            wallet_name = f"receiverstress{iteration}"
            node.createwallet(wallet_name=wallet_name, descriptors=True)
            stress_receiver = encrypt_and_unlock_wallet(node, wallet_name)
            receiver_seed_addr = stress_receiver.z_getnewaddress()
            for amount in [Decimal("0.22"), Decimal("0.24")]:
                funder.z_sendmany([{"address": receiver_seed_addr, "amount": amount}])
                self.generatetoaddress(node, 1, mine_addr, sync_fun=self.no_op)

            stress_dest = wallet.z_getnewaddress()
            stress_send = stress_receiver.z_sendmany([{"address": stress_dest, "amount": Decimal("0.40")}])
            assert stress_send["txid"] in node.getrawmempool()
            assert stress_send["spends"] <= LIVE_DIRECT_LIMIT
            assert_equal(stress_receiver.z_viewtransaction(stress_send["txid"])["family"], "v2_send")
            self.generatetoaddress(node, 1, mine_addr, sync_fun=self.no_op)

        self.log.info("Force a multi-input unshield from a wallet that only owns two notes")
        unshield_addr = unshielder.z_getnewaddress()
        funder.z_sendmany([{"address": unshield_addr, "amount": Decimal("0.35")}])
        self.generatetoaddress(node, 1, mine_addr, sync_fun=self.no_op)
        funder.z_sendmany([{"address": unshield_addr, "amount": Decimal("0.40")}])
        self.generatetoaddress(node, 1, mine_addr, sync_fun=self.no_op)

        self.log.info("Unshield back to a transparent address")
        t_dest = unshielder.getnewaddress()
        unshield_send = unshielder.z_sendmany([{"address": t_dest, "amount": Decimal("0.68")}])
        assert unshield_send["txid"] in node.getrawmempool()
        assert_equal(unshield_send["spends"], 2)
        assert_equal(unshielder.z_viewtransaction(unshield_send["txid"])["family"], "v2_send")
        self.generatetoaddress(node, 1, mine_addr, sync_fun=self.no_op)
        assert_equal(unshielder.getreceivedbyaddress(t_dest), Decimal("0.68"))

        self.log.info("Stress supported multi-input unshields on fresh receiver-only wallets")
        for iteration in range(2):
            wallet_name = f"unshieldstress{iteration}"
            node.createwallet(wallet_name=wallet_name, descriptors=True)
            stress_unshielder = encrypt_and_unlock_wallet(node, wallet_name)
            unshield_seed_addr = stress_unshielder.z_getnewaddress()
            for amount in [Decimal("0.23"), Decimal("0.25")]:
                funder.z_sendmany([{"address": unshield_seed_addr, "amount": amount}])
                self.generatetoaddress(node, 1, mine_addr, sync_fun=self.no_op)

            stress_t_dest = stress_unshielder.getnewaddress()
            stress_unshield = stress_unshielder.z_sendmany([{"address": stress_t_dest, "amount": Decimal("0.35")}])
            assert stress_unshield["txid"] in node.getrawmempool()
            assert stress_unshield["spends"] <= LIVE_DIRECT_LIMIT
            assert_equal(stress_unshielder.z_viewtransaction(stress_unshield["txid"])["family"], "v2_send")
            self.generatetoaddress(node, 1, mine_addr, sync_fun=self.no_op)
            assert_equal(stress_unshielder.getreceivedbyaddress(stress_t_dest), Decimal("0.35"))

        self.log.info("Verify exact-balance unshield preserves the requested transparent amount")
        exact_amount = Decimal("0.50000001")
        # The migrated mixed v2_send path can land a little above the earlier
        # unshield fee floor once note/change selection changes. Keep the
        # exact-fee regression deterministic, but seed it above the current
        # live minimum instead of reusing a possibly smaller prior tx fee.
        exact_fee = max(Decimal(str(unshield_send["fee"])), Decimal("0.00012"))
        reserve = Decimal("0.00000001")
        seed_total = exact_amount + exact_fee + reserve

        exact_addr = exact_unshielder.z_getnewaddress()
        funder.z_sendmany([{"address": exact_addr, "amount": seed_total - reserve}])
        self.generatetoaddress(node, 1, mine_addr, sync_fun=self.no_op)
        funder.z_sendmany([{"address": exact_addr, "amount": reserve}])
        self.generatetoaddress(node, 1, mine_addr, sync_fun=self.no_op)

        exact_t_dest = exact_unshielder.getnewaddress()
        exact_unshield = exact_unshielder.z_sendmany(
            [{"address": exact_t_dest, "amount": exact_amount}],
            exact_fee,
        )
        assert exact_unshield["txid"] in node.getrawmempool()
        assert exact_unshield["spends"] >= 2
        assert_equal(Decimal(str(exact_unshield["fee"])), exact_fee)
        assert_equal(exact_unshielder.z_viewtransaction(exact_unshield["txid"])["family"], "v2_send")
        self.generatetoaddress(node, 1, mine_addr, sync_fun=self.no_op)
        assert_equal(exact_unshielder.getreceivedbyaddress(exact_t_dest), exact_amount)

        self.log.info("Run a small mined load loop of shielded sends")
        sent = 0
        for _ in range(3):
            loop_dest = wallet.z_getnewaddress()
            wallet.z_sendmany([{"address": loop_dest, "amount": Decimal("0.01")}])
            self.generatetoaddress(node, 1, mine_addr, sync_fun=self.no_op)
            sent += 1
        assert_equal(sent, 3)


if __name__ == "__main__":
    WalletShieldedSendFlowTest(__file__).main()
