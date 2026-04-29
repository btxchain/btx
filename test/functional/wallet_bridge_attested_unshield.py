#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""End-to-end bridge-out settlement using the attested normal path."""

from decimal import Decimal

from test_framework.bridge_utils import (
    bridge_hex,
    create_bridge_wallet,
    find_output,
    mine_block,
    planout,
)
from test_framework.shielded_utils import encrypt_and_unlock_wallet
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal


class WalletBridgeAttestedUnshieldTest(BitcoinTestFramework):
    def add_options(self, parser):
        self.add_wallet_options(parser, legacy=False)

    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.extra_args = [["-test=matmulstrict", "-regtestshieldedmatrictdisableheight=1", "-bridgependingconfirmdepth=2"]]

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()
        self.skip_if_no_sqlite()

    def run_test(self):
        node = self.nodes[0]
        wallet, mine_addr = create_bridge_wallet(self, node, wallet_name="bridge_unshield")
        node.createwallet(wallet_name="bridge_operator", descriptors=True)
        operator_wallet = encrypt_and_unlock_wallet(node, "bridge_operator")
        fee_margin = Decimal("0.00100000")

        operator_address = operator_wallet.getnewaddress(address_type="p2mr")
        wallet.sendtoaddress(operator_address, Decimal("6.0"))
        mine_block(self, node, mine_addr)

        def settle_from_external_funding(*, bridge_id, operation_id, payout_amount, options=None):
            payout_address = wallet.getnewaddress(address_type="p2mr")
            refund_lock_height = node.getblockcount() + 20
            plan, _, _ = planout(
                wallet,
                payout_address,
                payout_amount,
                refund_lock_height,
                bridge_id=bridge_hex(bridge_id),
                operation_id=bridge_hex(operation_id),
            )

            funding_txid = operator_wallet.sendtoaddress(plan["bridge_address"], payout_amount + fee_margin)
            mine_block(self, node, mine_addr)
            vout, value = find_output(node, funding_txid, plan["bridge_address"], operator_wallet)

            built = wallet.bridge_buildunshieldtx(plan["plan_hex"], funding_txid, vout, value)
            assert_equal(built["p2mr_csfs_messages"][0]["message"], plan["attestation"]["bytes"])

            submitted = wallet.bridge_submitunshieldtx(
                plan["plan_hex"],
                funding_txid,
                vout,
                value,
                {} if options is None else options,
            )
            assert_equal(submitted["selected_path"], "normal")
            assert_equal(submitted["bridge_root"], plan["bridge_root"])
            assert_equal(submitted["ctv_hash"], plan["ctv_hash"])
            return payout_address, plan, funding_txid, vout, submitted["txid"]

        self.log.info("Externally funded tracked bridge-out settlements should broadcast and appear in the pending journal until confirmed")
        payout_address, _, funding_txid, vout, settlement_txid = settle_from_external_funding(
            bridge_id=60,
            operation_id=61,
            payout_amount=Decimal("2.75"),
        )
        pending = wallet.bridge_listpending()
        assert_equal(len(pending), 1)
        assert_equal(pending[0]["funding_txid"], funding_txid)
        assert_equal(pending[0]["funding_vout"], vout)
        assert_equal(pending[0]["settlement_txid"], settlement_txid)
        mine_block(self, node, mine_addr)
        pending = wallet.bridge_listpending()
        assert_equal(len(pending), 1)
        assert_equal(pending[0]["funding_txid"], funding_txid)
        assert_equal(pending[0]["funding_vout"], vout)
        assert_equal(pending[0]["status"], "settlement_confirming")
        assert_equal(pending[0]["settlement_confirmations"], 1)
        assert_equal(pending[0]["required_confirmations"], 2)
        assert_equal(wallet.bridge_listarchive({"funding_txid": funding_txid, "funding_vout": vout}), [])
        mine_block(self, node, mine_addr)
        assert_equal(wallet.bridge_listpending(), [])
        archive = wallet.bridge_listarchive({"funding_txid": funding_txid, "funding_vout": vout})
        assert_equal(len(archive), 1)
        assert_equal(archive[0]["status"], "archived_settlement")
        assert_equal(archive[0]["completion_kind"], "settlement")
        assert_equal(archive[0]["completion_txid"], settlement_txid)

        assert_equal(Decimal(str(wallet.getreceivedbyaddress(payout_address))), Decimal("2.75"))
        assert_equal(wallet.gettransaction(settlement_txid)["confirmations"] >= 1, True)

        self.log.info("Externally funded unshield submits should also work when track_pending is disabled")
        untracked_payout_address, _, _, _, untracked_txid = settle_from_external_funding(
            bridge_id=62,
            operation_id=63,
            payout_amount=Decimal("1.25"),
            options={"track_pending": False},
        )
        assert_equal(wallet.bridge_listpending(), [])
        mine_block(self, node, mine_addr)
        assert_equal(wallet.bridge_listpending(), [])
        assert_equal(Decimal(str(wallet.getreceivedbyaddress(untracked_payout_address))), Decimal("1.25"))
        assert_equal(wallet.gettransaction(untracked_txid)["confirmations"] >= 1, True)


if __name__ == "__main__":
    WalletBridgeAttestedUnshieldTest(__file__).main()
