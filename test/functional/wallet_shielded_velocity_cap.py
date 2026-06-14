#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""v0.32.0 unshield velocity cap — consensus wiring under shield ops, restart, and reorg.

Activates the velocity cap from genesis on regtest and drives normal shielded activity. Because
self-serve z->t unshield is gated to the C-002 height (unreachable in regtest), this cannot produce
pool egress, so the cap never fires here -- the cap REJECTION logic is covered by the C++ unit tests
(shielded_unshield_velocity_tests). What this test covers is the consensus integration: per-block
net-egress recording, persistence across restart, and exact undo across a reorg, all with the rule
active -- i.e. that enabling the cap does not break normal shielded operation.
"""

from decimal import Decimal

from test_framework.messages import COIN
from test_framework.shielded_utils import encrypt_and_unlock_wallet
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_greater_than


DISABLE_HEIGHT = 5


class WalletShieldedVelocityCapTest(BitcoinTestFramework):
    def add_options(self, parser):
        self.add_wallet_options(parser)

    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.extra_args = [[
            f"-regtestshieldedmatrictdisableheight={DISABLE_HEIGHT}",
            # Activate the velocity cap from genesis so ConnectBlock/DisconnectBlock exercise it.
            "-regtestshieldedunshieldvelocityactivationheight=0",
            "-regtestshieldedunshieldvelocitymincapheight=0",
            "-regtestshieldedunshieldvelocitymincap=10000",
            "-autoshieldcoinbase=1",
            "-autoshieldcoinbaseminheight=0",
        ]]
        self.rpc_timeout = 1200

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def run_test(self):
        node = self.nodes[0]
        node.createwallet(wallet_name="shielded", descriptors=True)
        wallet = encrypt_and_unlock_wallet(node, "shielded")
        mine_addr = wallet.getnewaddress()

        self.log.info("Velocity cap active: mine + autoshield. Shielding (pool grows) must not be capped")
        self.generatetoaddress(node, 102, mine_addr, sync_fun=self.no_op)
        # Autoshield enqueues shield txs as coinbase matures; mine until they confirm into shielded
        # notes. Shields grow the pool (net egress 0), so the velocity cap must never reject them.
        def shielded_positive():
            self.generatetoaddress(node, 1, mine_addr, sync_fun=self.no_op)
            return Decimal(str(wallet.z_getbalance()["balance"])) > Decimal("0")
        self.wait_until(shielded_positive, timeout=300)
        balance = wallet.z_getbalance()
        assert_greater_than(Decimal(str(balance["balance"])), Decimal("0"))  # autoshield succeeded
        shielded_state = node.getshieldedstateinfo()
        assert_equal(shielded_state["velocity_min_cap_sat"], 10_000 * COIN)
        assert_equal(shielded_state["velocity_cap_amount_sat"], 10_000 * COIN)
        height_before = node.getblockcount()
        shielded_before = balance["balance"]

        self.log.info("Restart: the persisted velocity window must reload cleanly (node-level checks)")
        self.restart_node(0, extra_args=self.extra_args[0])
        # Node comes back up at the same tip -> the persisted velocity log (DB_UNSHIELD_VELOCITY)
        # loaded without corrupting the shielded state; verifychain re-validates blocks incl. the
        # velocity rule on each (no spurious "shielded-unshield-velocity-exceeded").
        assert_equal(node.getblockcount(), height_before)
        assert node.verifychain(4, 0)

        self.log.info("Reorg: invalidate the tip (DisconnectBlock undoes the velocity entry), then reconsider")
        tip = node.getbestblockhash()
        parent = node.getblockheader(tip)["previousblockhash"]
        node.invalidateblock(tip)
        assert_equal(node.getbestblockhash(), parent)  # disconnect succeeded (velocity undo ran)
        node.reconsiderblock(tip)
        assert_equal(node.getbestblockhash(), tip)      # reconnect succeeded (velocity re-recorded)
        assert_equal(node.getblockcount(), height_before)

        self.log.info("Mine past the reorg; chain keeps advancing with the velocity cap active")
        self.generatetoaddress(node, 3, mine_addr, sync_fun=self.no_op)
        assert_equal(node.getblockcount(), height_before + 3)
        assert node.verifychain(4, 0)


if __name__ == '__main__':
    WalletShieldedVelocityCapTest(__file__).main()
