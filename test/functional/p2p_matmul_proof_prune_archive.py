#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""Prune / archive / restart-persistence of the segregated MatMul v4.2-D proof
(solver-evolution Stage 2c, design §3.5).

At ENC-BMX4C-D (segregated-proof) heights the ~32 MiB sketch travels out-of-band
(getmatmulproof/matmulproof) and is prunable. Stage 2c adds:

  * a rolling retention window (nMatMulProofPruneDepth): a DEFAULT node discards a
    proof once its block is buried below the window, but the block stays valid;
  * an ARCHIVE node (-matmulproofarchive) that retains ALL proofs and serves any
    historical block;
  * on-disk persistence so proofs survive a restart.

Driven on regtest with D activated at a low height via -regtestbmx4cdheight and a
TINY window via -regtestmatmulproofprunedepth (both regtest-only; D stays
INT32_MAX / disabled on every real network).

The chain is grown by extending the tip one D block at a time with the peers
connected, so each segregated block is relayed and its proof fetched over the
Stage-2b getmatmulproof/matmulproof path (the same tip-extension path the relay
test covers) — this test layers prune/archive/persistence on top rather than
re-testing cold IBD.

Asserts:
  (a) a pruned-proof node buries early D blocks below the window, DROPS their
      proofs (stops serving them) yet still tracks the SAME tip as the miner;
  (b) an ARCHIVE node still serves a historical proof the pruned node has dropped,
      and continues serving buried proofs to a second (pruned) peer;
  (c) an archive node still serves a historical proof after a restart (persisted).

n = 128 -> D tile b = 2 -> m = 64, so the per-nonce GEMM is trivial on a CPU
regtest miner and each proof is a few tens of KiB.
"""

import time

from test_framework.test_framework import BitcoinTestFramework
from test_framework.messages import msg_getmatmulproof
from test_framework.p2p import P2PInterface
from test_framework.util import assert_equal

V3_BINDING_HEIGHT = 2
H_C = 6          # unified v3 -> v4.2 / ENC-BMX4C activation
H_D = 8          # ENC-BMX4C-D segregated-proof activation (must be > H_C)
V4_DIMENSION = 128
PRUNE_DEPTH = 3  # tiny rolling window so a few D blocks bury the earliest


class ProofQueryPeer(P2PInterface):
    """A P2P peer that requests a proof (getmatmulproof) and records any
    matmulproof the node serves back."""

    def __init__(self):
        super().__init__()
        self.received_proofs = {}   # block_hash_int -> proof bytes

    def on_mmproof(self, message):
        self.received_proofs[message.block_hash] = message.proof


class BTXMatMulProofPruneArchive(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 3
        self.setup_clean_chain = True
        common = [
            "-test=matmuldgw",
            f"-regtestmatmulbindingheight={V3_BINDING_HEIGHT}",
            f"-regtestmatmulproductdigestheight={V3_BINDING_HEIGHT}",
            "-regtestmatmulrequireproductpayload=0",
            f"-regtestmatmulv4height={H_C}",
            f"-regtestmatmulv4dimension={V4_DIMENSION}",
            f"-regtestbmx4cheight={H_C}",
            f"-regtestbmx4cdheight={H_D}",
        ]
        archive = common + ["-matmulproofarchive"]
        pruned = common + [f"-regtestmatmulproofprunedepth={PRUNE_DEPTH}"]
        # node0: archive miner; node1 + node2: pruned-proof peers.
        self.extra_args = [archive, pruned, pruned]

    def setup_network(self):
        # node1 dials OUT to the archive miner node0 (connect_nodes(1, 0)) so node0
        # is a preferred download peer for it — in MatMul consensus mode an IBD node
        # only block-syncs from preferred (outbound) peers, so an inbound-only
        # archive peer would never be used as a sync source. node2 is left
        # DISCONNECTED; it joins later to exercise a genuine cold IBD from the
        # archive. Wiring the peers only to node0 guarantees buried proofs can only
        # be served by the archive.
        self.setup_nodes()
        self.connect_nodes(1, 0)

    def served(self, node, block_hash_hex, timeout=15):
        """True iff `node` serves the segregated proof for `block_hash_hex` over
        getmatmulproof. After the query we sync_with_ping, so the node has fully
        processed the request (and any reply) before we inspect."""
        peer = node.add_p2p_connection(ProofQueryPeer())
        try:
            h = int(block_hash_hex, 16)
            deadline = time.time() + timeout
            while time.time() < deadline:
                peer.send_message(msg_getmatmulproof(h))
                peer.sync_with_ping()
                if h in peer.received_proofs:
                    return True
                time.sleep(0.5)
            return False
        finally:
            peer.peer_disconnect()
            peer.wait_for_disconnect()

    def run_test(self):
        archive_node, pruned_node, fresh_node = self.nodes
        self.wait_until(
            lambda: archive_node.getconnectioncount() >= 1 and pruned_node.getconnectioncount() >= 1,
            timeout=120,
        )

        # node2 stays disconnected during chain build (cold-IBD candidate).
        sync_pair = [archive_node, pruned_node]

        self.log.info("Sync node0+node1 across v3 -> ENC-BMX4C (in-block), up to just below D")
        self.generate(archive_node, H_D - 1, sync_fun=self.no_op)
        self.sync_blocks(sync_pair, timeout=240)
        assert_equal(pruned_node.getblockcount(), H_D - 1)

        self.log.info("Extend the tip one segregated D block at a time; the pruned node fetches each proof")
        num_d_blocks = PRUNE_DEPTH + 3
        first_d_hash = None
        for i in range(num_d_blocks):
            self.generate(archive_node, 1, sync_fun=self.no_op)
            if first_d_hash is None:
                first_d_hash = archive_node.getblockhash(H_D)  # earliest D block
            # The pruned node catches up to this D block via the archive-served proof.
            self.sync_blocks(sync_pair, timeout=240)
        top_height = H_D - 1 + num_d_blocks
        tip_hash = archive_node.getbestblockhash()
        assert_equal(archive_node.getblockcount(), top_height)

        self.log.info("Pruned node reached the SAME D tip (block validity survives pruning) [test a]")
        assert_equal(pruned_node.getblockcount(), top_height)
        assert_equal(pruned_node.getbestblockhash(), tip_hash)
        assert_equal(pruned_node.getblock(tip_hash, 2)["matmul_dim"], V4_DIMENSION)

        # The earliest D block is buried by (top - H_D) = num_d_blocks - 1 > PRUNE_DEPTH.
        self.log.info("The pruned node DROPPED the buried proof but keeps the in-window tip proof [test a]")
        self.wait_until(lambda: not self.served(pruned_node, first_d_hash), timeout=90)
        assert not self.served(pruned_node, first_d_hash)
        assert self.served(pruned_node, tip_hash), "pruned node must serve in-window proofs"
        self.log.info("  pruned node: buried proof dropped, in-window proof retained")

        self.log.info("The archive node STILL serves the buried historical proof [test b]")
        assert self.served(archive_node, first_d_hash), "archive node must retain all proofs"
        assert self.served(archive_node, tip_hash)
        self.log.info("  archive serves both buried and in-window proofs")

        self.log.info("A fresh node cold-IBDs the D chain, fetching buried proofs from the archive [test b]")
        # node2 has never seen the chain. It dials OUT to the archive (preferred
        # download peer) and must fetch EVERY segregated proof — including the ones
        # buried below the pruned node's window, which only the archive still has —
        # running the §3.3 binding + Freivalds before crediting each block.
        self.connect_nodes(2, 0)
        self.wait_until(
            lambda: fresh_node.getblockcount() == top_height
            and fresh_node.getbestblockhash() == tip_hash,
            timeout=360,
        )
        assert_equal(fresh_node.getbestblockhash(), archive_node.getbestblockhash())
        self.log.info("  fresh node reached the D tip via archive-served proofs (cold IBD)")

        self.log.info("Proofs survive a restart of the archive node (on-disk persistence) [test c]")
        self.restart_node(0)
        archive_node = self.nodes[0]
        assert self.served(archive_node, first_d_hash), "archive proofs must persist across restart"
        assert self.served(archive_node, tip_hash)
        self.log.info("  archive node served historical + tip proofs after restart")

        self.log.info("Stage 2c prune/archive/persistence intact")


if __name__ == "__main__":
    BTXMatMulProofPruneArchive(__file__).main()
