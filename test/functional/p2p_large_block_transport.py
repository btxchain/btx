#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""Verify P2P relay/sync of a block LARGER than the ordinary-message ceiling.

Audit P1-1: ordinary P2P messages are capped at MAX_PROTOCOL_MESSAGE_LENGTH
(16 MB), but block-bearing messages (`block`, `blocktxn`) get the larger
MAX_BLOCK_MESSAGE_LENGTH (24 MB) so a consensus-valid block up to
MAX_BLOCK_SERIALIZED_SIZE (24 MB) stays relayable. A block in the 16-24 MB band
is the exact regression surface: it exceeds the ordinary ceiling, so it can
ONLY cross the wire over the block-bearing path. If that split were wrong (a
single 16 MB global limit, as before P1-1), such a block would be
consensus-valid but un-relayable -- a latent chain-split / eclipse vector.

This test builds a block strictly above 16 MB (and below the 24 MB max) and
proves a peer that holds NONE of the block's transactions downloads it in full
over P2P:
  * the block producer (node0) assembles the >16 MB block while the peer
    (node1) is DISCONNECTED, so the peer's mempool is empty (an unsynced
    baseline -- no loose-tx relay could have pre-populated it);
  * the peer is connected only afterwards and must obtain the whole chain,
    including the >16 MB block, through initial block download -- i.e. as a
    full `block` message that exceeds the 16 MB ordinary ceiling. With an empty
    mempool there is no compact-block-from-mempool shortcut; the full
    block-bearing message is forced onto the wire.
Success (the peer reaches the >16 MB tip) can only happen if the block-bearing
message ceiling (MAX_BLOCK_MESSAGE_LENGTH) admits it; under a 16 MB global
limit the peer would reject the oversized message header and stall below the
tip.
"""

from decimal import Decimal

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import create_lots_of_big_transactions
from test_framework.util import (
    assert_equal,
    assert_greater_than,
    gen_return_txouts,
)
from test_framework.wallet import MiniWallet

# The ordinary-message ceiling the block must exceed (net.h
# MAX_PROTOCOL_MESSAGE_LENGTH) and the block-bearing ceiling it must stay under
# (net.h MAX_BLOCK_MESSAGE_LENGTH == consensus MAX_BLOCK_SERIALIZED_SIZE).
ORDINARY_MESSAGE_CEILING = 16_000_000
BLOCK_MESSAGE_CEILING = 24_000_000


class P2PLargeBlockTransportTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 2
        self.setup_clean_chain = True
        # A >16 MB block over loopback is fast, but assembling >16 MB of mempool
        # (hundreds of fan-out txs) and mining it needs headroom.
        self.rpc_timeout = 600
        # node0 assembles the oversized block; node1 is a plain peer that will
        # pull the whole chain (including the >16 MB block) via IBD.
        self.extra_args = [
            ["-blockmaxweight=24000000", "-blockmaxtemplatetxs=0", "-acceptnonstdtxn=1"],
            [],
        ]

    def setup_network(self):
        # Deliberately do NOT connect the nodes here: node1 must stay off the
        # network while node0 builds and mines the oversized block, so node1's
        # mempool is empty and it is forced to download the full block later.
        self.setup_nodes()

    def run_test(self):
        node0, node1 = self.nodes

        wallet = MiniWallet(node0)
        self.log.info("Mature a deep coinbase set so hundreds of fan-out txs are fundable")
        # ~16 MB of block body at ~47 KB per 1500-output fan-out tx needs a few
        # hundred independent (mature) coinbase inputs; each fans out once, so
        # avoid deep in-mempool chains that would hit ancestor limits.
        self.generate(wallet, 750, sync_fun=self.no_op)
        wallet.rescan_utxos()

        fee = Decimal(str(node0.getnetworkinfo()["relayfee"])) * Decimal(100)
        txouts = gen_return_txouts()
        # Target a mempool above the 16 MB ordinary-message ceiling (with margin
        # for the block header/coinbase) so the assembled block lands in the
        # 16-24 MB band.
        target_mempool_bytes = 16_600_000
        for i in range(60):
            mp = node0.getmempoolinfo()["bytes"]
            if mp > target_mempool_bytes:
                break
            self.log.info(f"  building mempool: round {i}, {mp} bytes")
            create_lots_of_big_transactions(wallet, node0, fee, tx_batch_size=25, txouts=txouts)

        mempool_bytes = node0.getmempoolinfo()["bytes"]
        assert_greater_than(mempool_bytes, target_mempool_bytes)

        large_block_hash = self.generate(node0, 1, sync_fun=self.no_op)[0]
        block_size = len(node0.getblock(large_block_hash, 0)) // 2
        self.log.info(f"Assembled block is {block_size} bytes")
        # The whole point: the block exceeds the 16 MB ordinary-message ceiling
        # (so it can only cross the wire over the block-bearing path) yet stays
        # under the 24 MB block-message / consensus ceiling.
        assert_greater_than(block_size, ORDINARY_MESSAGE_CEILING)
        assert_greater_than(BLOCK_MESSAGE_CEILING, block_size)

        # node1 has been offline throughout: empty mempool, unsynced baseline.
        assert_equal(node1.getblockcount(), 0)
        assert_equal(node1.getmempoolinfo()["size"], 0)

        self.log.info("Connect the empty-mempool peer; it must pull the >16 MB block via IBD")
        # node1 must connect OUTBOUND to node0 (the chain source): a node does not
        # initial-header-sync a whole chain from an INBOUND-only peer (eclipse
        # protection), so connect_nodes(0, 1) -- node0 dialing node1 -- would leave
        # node1 stuck at genesis. node1 dialing node0 makes node0 an outbound peer
        # of node1, which node1 will initial-getheaders and then block-download.
        self.connect_nodes(1, 0)
        # IBD downloads every block as a full `block` message; the oversized one
        # is only deliverable if MAX_BLOCK_MESSAGE_LENGTH (not the 16 MB ordinary
        # limit) governs the `block` command.
        self.sync_blocks(timeout=240)

        assert_equal(node1.getbestblockhash(), large_block_hash)
        peer_block_size = len(node1.getblock(large_block_hash, 0)) // 2
        assert_equal(peer_block_size, block_size)
        assert_greater_than(peer_block_size, ORDINARY_MESSAGE_CEILING)
        self.log.info("Peer received the full >16 MB block over the block-bearing message path")


if __name__ == "__main__":
    P2PLargeBlockTransportTest(__file__).main()
