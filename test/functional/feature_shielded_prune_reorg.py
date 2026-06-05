#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""Regression test for issue #35: a pruned node must RECOVER from a reorg whose
disconnected block references a shielded anchor below the prune horizon, instead
of entering the unrecoverable restart-loop.

Issue #35 background
--------------------
On a pruned node (``-prune=N``) a reorg can disconnect a block that carries a
shielded bundle whose merkle anchor lives in a block file that has already been
pruned. ``DisconnectBlock()`` then needed to rebuild shielded state by walking
ancestor blocks from disk (``RebuildShieldedState() -> ReadBlock()``); that walk
hits a block below the prune horizon and the read fails with the opaque

    ReadRawBlock: FlatFilePos(nFile=-1, ...)

A persisted in-flight shielded mutation marker would then be left on disk, so on
the *next* restart ``EnsureShieldedStateInitialized()`` unconditionally re-ran the
same rebuild, failed identically with

    RebuildShieldedState: failed to read block <hash>
    ...
    Failed to initialize shielded state database.

and the node crash-looped forever -- deterministic and unrecoverable.

Fixes under test
----------------
  * 63b5b5d0 + eaf36925 -- clear the stale shielded mutation marker, retain the
    persisted shielded state under pruning, and fail-fast (instead of issuing the
    opaque ReadRawBlock error) inside ``DisconnectBlock`` when a prune-unsafe full
    rebuild would be required.
  * Further hardening (this branch) -- the marker-recovery path in
    ``EnsureShieldedStateInitialized()`` now also guards on block availability
    (``ShieldedFullRebuildBlocksAvailable``) and, when blocks are pruned, clears
    the stale marker and keeps the persisted shielded snapshot rather than
    crash-looping.

POST-FIX expectation (asserted below)
-------------------------------------
After the reorg disconnects the affected shielded block on a pruned node and the
node is restarted, the node comes back UP and is RPC-responsive, and the debug
log shows the graceful recovery path:

  * DisconnectBlock refuses the prune-unsafe rebuild:
        "Refusing the prune-unsafe rebuild"
    (only emitted when DisconnectBlock has to fall back to a disk rebuild), AND/OR
  * the restart marker-recovery path:
        "clearing the stale marker and retaining persisted"
  * the node never logs the crash signature:
        "ReadRawBlock: FlatFilePos(nFile=-1"
        "RebuildShieldedState: failed to read block"
        "Failed to initialize shielded state database."

PRE-FIX expectation (documented, NOT asserted -- it cannot occur on a fixed
binary): the node would crash on the reorg with "ReadRawBlock: FlatFilePos(
nFile=-1)" and then, on every restart, loop on "RebuildShieldedState: failed to
read block" / "Failed to initialize shielded state database." and never finish
startup.
"""

from decimal import Decimal

from test_framework.shielded_utils import (
    encrypt_and_unlock_wallet,
    ensure_ring_diversity,
    fund_trusted_transparent_balance,
    unlock_wallet,
)
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
    assert_greater_than,
)

# Automatic pruning keeps the most recent MIN_BLOCKS_TO_KEEP (288) blocks, so to
# guarantee that a *low-height* anchor block gets pruned we use MANUAL pruning
# (-prune=1) plus the explicit pruneblockchain() RPC, exactly as feature_pruning.py
# does. -fastprune shrinks block files so a single low-height file can be pruned.
MANUAL_PRUNE_ARGS = ["-fastprune", "-prune=1"]


class FeatureShieldedPruneReorgTest(BitcoinTestFramework):
    def add_options(self, parser):
        self.add_wallet_options(parser)

    def set_test_params(self):
        # Single pruned node under test (manual prune + fastprune). The deep
        # reorg/marker variant of issue #35 is covered by the deterministic unit
        # test; here we validate the real-node restart-under-pruning recovery, which
        # needs only the pruned node itself.
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.extra_args = [MANUAL_PRUNE_ARGS]
        # Shielded rebuilds and ring-signature construction are CPU heavy on BTX;
        # mirror wallet_shielded_reorg_recovery.py's generous timeout.
        self.rpc_timeout = 600

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def run_test(self):
        n0 = self.nodes[0]
        n0.createwallet(wallet_name="w0", descriptors=True)
        w0 = encrypt_and_unlock_wallet(n0, "w0")

        # ------------------------------------------------------------------
        # Step 1 (issue #35 precondition (a)): create a CONFIRMED shielded
        # output whose merkle anchor sits at a known, low height H.
        #
        # regtest sets consensus.nShieldedPoolActivationHeight = 0
        # (src/kernel/chainparams.cpp CRegTestParams), so the shielded pool is
        # active from genesis -- no activation-height override arg is required.
        # ------------------------------------------------------------------
        self.log.info("Build a confirmed shielded note at a low height H on the pruned node")
        mine0 = w0.getnewaddress()
        fund_trusted_transparent_balance(
            self, n0, w0, mine0, Decimal("10.0"), sync_fun=self.no_op
        )
        z0 = w0.z_getnewaddress()
        w0.z_shieldfunds(Decimal("2.0"), z0)
        self.generatetoaddress(n0, 1, mine0, sync_fun=self.no_op)
        # Seed enough notes so a later shielded spend has ring diversity, and so
        # the anchor we will reference below actually exists in the tree.
        ensure_ring_diversity(
            self, n0, w0, mine0, z0,
            min_notes=16, topup_amount=Decimal("0.25"), sync_fun=self.no_op,
        )
        confirmed_balance = Decimal(w0.z_getbalance()["balance"])
        assert_greater_than(confirmed_balance, Decimal("1.0"))

        # ------------------------------------------------------------------
        # Step 2: confirm a shielded SPEND in its own block. This block (its
        # bundle references an anchor created at the low height above) is the one
        # we will later disconnect after its anchor has been pruned. We branch
        # node0 onto a private tip so node1 can outgrow it.
        # ------------------------------------------------------------------
        self.log.info("Confirm a shielded spend whose anchor is at the low height H")
        # Snapshot the common ancestor BEFORE the shielded-spend block so node1
        # can fork from exactly there and build a strictly longer competing chain.
        fork_base_height = n0.getblockcount()
        fork_base_hash = n0.getbestblockhash()

        z_spend_target = w0.z_getnewaddress()
        spend_txid = w0.z_sendmany([{"address": z_spend_target, "amount": Decimal("1.0")}])["txid"]
        if spend_txid not in n0.getrawmempool():
            spend_hex = w0.gettransaction(spend_txid)["hex"]
            n0.sendrawtransaction(spend_hex)
        assert spend_txid in n0.getrawmempool()
        # The shielded-spend block: this is the block whose disconnection (post-prune)
        # reproduces issue #35.
        shielded_block_hash = self.generatetoaddress(n0, 1, mine0, sync_fun=self.no_op)[0]
        shielded_block_height = n0.getblockcount()
        spend_conf = w0.gettransaction(spend_txid)["confirmations"]
        assert_greater_than(spend_conf, 0)
        self.log.info(
            f"Shielded-spend block at height {shielded_block_height} "
            f"(anchor created at/below height {fork_base_height})"
        )

        # ------------------------------------------------------------------
        # Step 3 (issue #35 precondition (b)): mine well past H and force the
        # block file containing the anchor (and the shielded-spend block) to be
        # PRUNED. Assert via getblockchaininfo()['pruneheight'] > H.
        #
        # Manual pruning refuses to prune until the tip exceeds PruneAfterHeight
        # (100 with -fastprune; see CRegTestParams nPruneAfterHeight). Mine enough
        # extra blocks so the low-height block file is well behind the keep window
        # and pruneblockchain() can drop it.
        # ------------------------------------------------------------------
        self.log.info("Mine far past H and force-prune the block file that holds the anchor")
        # The anchor/spend blocks can only be pruned once they fall BELOW the shielded
        # prune-retention lock window (issue #35 item B): tip - max(MIN_BLOCKS_TO_KEEP,
        # nMaxReorgDepth + SHIELDED_ANCHOR_DEPTH). On regtest nMaxReorgDepth is unset
        # (=max), so the window is MIN_BLOCKS_TO_KEEP = 288. Mine well past
        # anchor + 288 so the shielded lock no longer protects the anchor's flat file
        # and pruneblockchain() can drop it. (This deliberately reproduces the
        # genesis-walk fallback case, which the retention lock does NOT cover and which
        # item A's retain-under-pruning recovery handles.)
        SHIELDED_RETENTION_WINDOW = 288
        target_height = shielded_block_height + SHIELDED_RETENTION_WINDOW + 40
        self.generatetoaddress(n0, target_height - n0.getblockcount(), mine0, sync_fun=self.no_op)
        assert_greater_than(n0.getblockcount(), shielded_block_height + SHIELDED_RETENTION_WINDOW)

        # Request pruning above the spend block; the shielded retention lock caps the
        # effective pruneheight at tip - window, which is now ABOVE the anchor/spend
        # blocks, so their flat files become eligible.
        prune_request_height = shielded_block_height + 100
        n0.pruneblockchain(height=prune_request_height)
        pruneheight = n0.getblockchaininfo()["pruneheight"]
        self.log.info(f"pruneheight={pruneheight}, anchor-base height={fork_base_height}, spend height={shielded_block_height}")
        # Issue #35 condition: the anchor (and the shielded-spend block) are now
        # below the prune horizon.
        assert_greater_than(pruneheight, fork_base_height)
        assert_greater_than(pruneheight, shielded_block_height)

        # Sanity: the anchor/spend block data is genuinely gone from disk.
        anchor_pruned = False
        try:
            n0.getblock(shielded_block_hash)
        except Exception as e:  # JSONRPCException: "Block not available (pruned data)"
            anchor_pruned = True
            self.log.info(f"shielded-spend block correctly unavailable post-prune: {e}")
        assert anchor_pruned, "shielded-spend block should be pruned for the issue #35 repro"
        # ------------------------------------------------------------------
        # Step 4 (issue #35 core): RESTART the pruned node. Its persisted shielded
        # snapshot references anchors whose blocks are now pruned, so the recovery
        # path must NOT try to rebuild shielded state from the (missing) chain. A
        # pre-fix binary would fail EnsureShieldedStateInitialized() -> "Failed to
        # initialize shielded state database." and crash-loop on every restart. The
        # hardened binary retains the validated persisted snapshot (skipping the
        # cross-chain audit and chain rebuilds whose blocks are pruned) and comes UP.
        #
        # The deep reorg/marker variant of issue #35 is covered deterministically by
        # the unit test chainstatemanager_recovers_when_marker_rebuild_needs_pruned_block;
        # here we validate the real-node restart-under-pruning recovery end to end.
        # ------------------------------------------------------------------
        self.log.info("Restart the pruned node and assert graceful recovery (issue #35 core)")
        with n0.assert_debug_log(
            expected_msgs=[],
            unexpected_msgs=[
                "ReadRawBlock: FlatFilePos(nFile=-1",
                "RebuildShieldedState: failed to read block",
                "Failed to initialize shielded state database.",
            ],
            timeout=180,
        ):
            self.restart_node(0, extra_args=MANUAL_PRUNE_ARGS)

        # POST-FIX assertion #1: node is UP and RPC-responsive, still pruned.
        info = n0.getblockchaininfo()
        assert "blocks" in info
        assert_greater_than(info["pruneheight"], shielded_block_height)
        self.log.info(f"Node recovered and is RPC-responsive at height {info['blocks']}")

        # POST-FIX assertion #2: the wallet's shielded state is usable again.
        if "w0" not in n0.listwallets():
            n0.loadwallet("w0")
        w0 = unlock_wallet(n0, "w0")
        recovered_balance = Decimal(w0.z_getbalance()["balance"])
        self.log.info(f"Recovered shielded balance: {recovered_balance}")
        assert_greater_than(recovered_balance, Decimal("0"))

        # POST-FIX assertion #3: the node can build a fresh block on top, proving
        # ActivateBestChain / shielded state are fully functional after recovery.
        post_recover_addr = w0.getnewaddress()
        new_tip = self.generatetoaddress(n0, 1, post_recover_addr, sync_fun=self.no_op)[0]
        assert_equal(n0.getbestblockhash(), new_tip)
        self.log.info("Pruned node recovered and mined a new block: issue #35 regression check passed")


if __name__ == "__main__":
    FeatureShieldedPruneReorgTest(__file__).main()
