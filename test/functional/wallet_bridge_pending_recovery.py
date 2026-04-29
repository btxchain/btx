#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""Persistence and recovery coverage for wallet-managed bridge batches."""

from decimal import Decimal

from test_framework.bridge_utils import (
    bridge_hex,
    create_bridge_wallet,
    find_output,
    mine_block,
    planout,
)
from test_framework.test_node import ErrorMatch
from test_framework.shielded_utils import unlock_wallet
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal


class WalletBridgePendingRecoveryTest(BitcoinTestFramework):
    def add_options(self, parser):
        self.add_wallet_options(parser, legacy=False)

    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.extra_args = [["-bridgependingconfirmdepth=2"]]

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()
        self.skip_if_no_sqlite()

    def run_test(self):
        node = self.nodes[0]
        wallet_name = "bridge_pending"
        wallet, mine_addr = create_bridge_wallet(self, node, wallet_name=wallet_name, amount=Decimal("12"))
        refund_fee = Decimal("0.00010000")

        self.log.info("Persist a pending bridge-out batch across restart and recover it manually")
        refund_lock_height = node.getblockcount() + 20
        payout_address = wallet.getnewaddress(address_type="p2mr")
        plan, _, _ = planout(
            wallet,
            payout_address,
            Decimal("2.0"),
            refund_lock_height,
            bridge_id=bridge_hex(0x710),
            operation_id=bridge_hex(0x711),
        )
        funding_txid = wallet.sendtoaddress(plan["bridge_address"], Decimal("2.0") + Decimal("0.00020000"))
        mine_block(self, node, mine_addr)
        vout, value = find_output(node, funding_txid, plan["bridge_address"], wallet)
        refund_destination = wallet.getnewaddress(address_type="p2mr")
        imported = wallet.bridge_importpending(
            plan["plan_hex"],
            funding_txid,
            vout,
            value,
            {
                "refund_destination": refund_destination,
                "refund_fee": refund_fee,
                "recover_now": False,
            },
        )
        assert_equal(imported["status"], "pending_settlement")
        assert_equal(imported["refund_destination"], refund_destination)

        self.restart_node(0)
        node = self.nodes[0]
        node.loadwallet(wallet_name)
        wallet = unlock_wallet(node, wallet_name)
        pending = wallet.bridge_listpending()
        assert_equal(len(pending), 1)
        assert_equal(pending[0]["status"], "pending_settlement")
        assert_equal(pending[0]["funding_txid"], funding_txid)
        assert_equal(pending[0]["funding_vout"], vout)

        recovery = wallet.bridge_recoverpending(funding_txid, vout, True)
        assert_equal(len(recovery), 1)
        assert_equal(recovery[0]["action"], "submitted_settlement")
        settlement_txid = recovery[0]["txid"]
        assert settlement_txid in node.getrawmempool()
        mine_block(self, node, mine_addr)
        pending = wallet.bridge_listpending()
        tracked = [entry for entry in pending if entry["funding_txid"] == funding_txid]
        assert_equal(len(tracked), 1)
        assert_equal(tracked[0]["status"], "settlement_confirming")
        assert_equal(tracked[0]["settlement_confirmations"], 1)
        assert_equal(tracked[0]["required_confirmations"], 2)
        assert_equal(wallet.bridge_listarchive({"funding_txid": funding_txid, "funding_vout": vout}), [])
        mine_block(self, node, mine_addr)
        assert_equal(wallet.bridge_listpending(), [])
        archive = wallet.bridge_listarchive({"funding_txid": funding_txid, "funding_vout": vout})
        assert_equal(len(archive), 1)
        assert_equal(archive[0]["status"], "archived_settlement")
        assert_equal(archive[0]["completion_kind"], "settlement")
        assert_equal(archive[0]["completion_txid"], settlement_txid)
        settlement_archive_block = node.getbestblockhash()

        self.log.info("A shallow reorg should restore the archived settlement journal entry and persist it across restart")
        node.invalidateblock(settlement_archive_block)
        self.wait_until(
            lambda: len(
                [
                    entry
                    for entry in wallet.bridge_listpending()
                    if entry["funding_txid"] == funding_txid and entry["funding_vout"] == vout
                ]
            ) == 1,
            timeout=60,
        )
        reactivated = [
            entry
            for entry in wallet.bridge_listpending()
            if entry["funding_txid"] == funding_txid and entry["funding_vout"] == vout
        ]
        assert_equal(len(reactivated), 1)
        assert_equal(reactivated[0]["status"], "settlement_confirming")
        assert_equal(reactivated[0]["settlement_confirmations"], 1)
        assert_equal(reactivated[0]["required_confirmations"], 2)
        assert_equal(wallet.bridge_listarchive({"funding_txid": funding_txid, "funding_vout": vout}), [])

        node.reconsiderblock(settlement_archive_block)
        self.wait_until(
            lambda: len(
                wallet.bridge_listarchive(
                    {"funding_txid": funding_txid, "funding_vout": vout}
                )
            )
            == 1,
            timeout=60,
        )
        assert_equal(
            [
                entry
                for entry in wallet.bridge_listpending()
                if entry["funding_txid"] == funding_txid and entry["funding_vout"] == vout
            ],
            [],
        )
        archive = wallet.bridge_listarchive({"funding_txid": funding_txid, "funding_vout": vout})
        assert_equal(len(archive), 1)
        assert_equal(archive[0]["status"], "archived_settlement")
        assert_equal(archive[0]["completion_txid"], settlement_txid)

        self.log.info("Auto-refund a persisted batch once timeout is reached if settlement remains impossible")
        refund_lock_height = node.getblockcount() + 6
        payout_address = wallet.getnewaddress(address_type="p2mr")
        stuck_plan, _, _ = planout(
            wallet,
            payout_address,
            Decimal("1.7"),
            refund_lock_height,
            bridge_id=bridge_hex(0x720),
            operation_id=bridge_hex(0x721),
        )
        stuck_funding_txid = wallet.sendtoaddress(stuck_plan["bridge_address"], Decimal("1.7"))
        mine_block(self, node, mine_addr)
        stuck_vout, stuck_value = find_output(node, stuck_funding_txid, stuck_plan["bridge_address"], wallet)
        stuck_refund_destination = wallet.getnewaddress(address_type="p2mr")
        wallet.bridge_importpending(
            stuck_plan["plan_hex"],
            stuck_funding_txid,
            stuck_vout,
            stuck_value,
            {
                "refund_destination": stuck_refund_destination,
                "refund_fee": refund_fee,
                "recover_now": False,
            },
        )

        blocks_until_timeout = refund_lock_height - node.getblockcount()
        assert blocks_until_timeout > 0
        mine_block(self, node, mine_addr, blocks_until_timeout)

        pending = wallet.bridge_listpending()
        auto_refund = [entry for entry in pending if entry["funding_txid"] == stuck_funding_txid]
        assert_equal(len(auto_refund), 1)
        assert_equal(auto_refund[0]["status"], "refund_in_mempool")
        refund_txid = auto_refund[0]["refund_txid"]
        assert refund_txid in node.getrawmempool()

        mine_block(self, node, mine_addr)
        pending = wallet.bridge_listpending()
        auto_refund = [entry for entry in pending if entry["funding_txid"] == stuck_funding_txid]
        assert_equal(len(auto_refund), 1)
        assert_equal(auto_refund[0]["status"], "refund_confirming")
        assert_equal(auto_refund[0]["refund_confirmations"], 1)
        assert_equal(auto_refund[0]["required_confirmations"], 2)
        assert_equal(wallet.bridge_listarchive({"funding_txid": stuck_funding_txid, "funding_vout": stuck_vout}), [])
        mine_block(self, node, mine_addr)
        assert_equal(wallet.bridge_listpending(), [])
        archive = wallet.bridge_listarchive({"funding_txid": stuck_funding_txid, "funding_vout": stuck_vout})
        assert_equal(len(archive), 1)
        assert_equal(archive[0]["status"], "archived_refund")
        assert_equal(archive[0]["completion_kind"], "refund")
        assert_equal(archive[0]["completion_txid"], refund_txid)
        assert_equal(
            Decimal(str(wallet.getreceivedbyaddress(stuck_refund_destination))),
            Decimal("1.7") - refund_fee,
        )

        self.log.info("Reject bridgependingconfirmdepth values that exceed signed confirmation accounting")
        self.stop_node(0)
        self.nodes[0].assert_start_raises_init_error(
            extra_args=["-bridgependingconfirmdepth=2147483648"],
            expected_msg=r".*Invalid -bridgependingconfirmdepth value 2147483648 \(must be between 1 and 2147483647\).*",
            match=ErrorMatch.FULL_REGEX,
        )


if __name__ == "__main__":
    WalletBridgePendingRecoveryTest(__file__).main()
