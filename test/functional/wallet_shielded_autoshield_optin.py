#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""v0.32.0 fund-preservation: coinbase auto-shielding is opt-in (default off).

By default, mined rewards stay as post-quantum transparent (P2MR) outputs with no shielded-pool
exposure; only when the operator sets -autoshieldcoinbase=1 are mature coinbases swept into the
shielded pool. (On mainnet a height floor also defers auto-shield to the C-002 hardening height;
on regtest that floor defaults to 0, so this test exercises the on/off behavior directly.)
"""

from decimal import Decimal

from test_framework.shielded_utils import encrypt_and_unlock_wallet
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_greater_than


DISABLE_HEIGHT = 5


class WalletShieldedAutoshieldOptInTest(BitcoinTestFramework):
    def add_options(self, parser):
        self.add_wallet_options(parser)

    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        # No -autoshieldcoinbase: exercise the new DEFAULT (off).
        self.extra_args = [[f"-regtestshieldedmatrictdisableheight={DISABLE_HEIGHT}"]]
        self.rpc_timeout = 1200

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def run_test(self):
        node = self.nodes[0]
        node.createwallet(wallet_name="shielded", descriptors=True)
        wallet = encrypt_and_unlock_wallet(node, "shielded")
        mine_addr = wallet.getnewaddress()

        self.log.info("Default (auto-shield off): mine well past maturity; coinbase must stay transparent")
        self.generatetoaddress(node, 110, mine_addr, sync_fun=self.no_op)
        assert_equal(node.getblockcount(), 110)
        # The wallet must NOT have enqueued any shielding transaction, and the shielded balance is 0.
        assert_equal(node.getrawmempool(), [])
        balance = wallet.z_getbalance()
        assert_equal(Decimal(str(balance["balance"])), Decimal("0"))
        assert_equal(int(balance["note_count"]), 0)
        # Mature coinbase value is present in the wallet, just transparent (not swept into the pool).
        assert_greater_than(wallet.getbalance(), Decimal("0"))
        self.log.info("Confirmed: with the v0.32.0 default, mined coinbase stays transparent (no auto-shield)")
        # The opt-in path (-autoshieldcoinbase=1 -> coinbase swept into the pool) is covered by
        # wallet_shielded_postfork_coinbase_autoshield.py.


if __name__ == '__main__':
    WalletShieldedAutoshieldOptInTest(__file__).main()
