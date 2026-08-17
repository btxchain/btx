#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""Verify V2 P2P relay/sync of a block LARGER than one packet's ceiling.

V2/BIP324 packets are capped below 16.8 MB while consensus-valid blocks may be
as large as 24 MB. A block in that band is therefore relayable only through the
explicitly negotiated, whole-payload-hashed chunk encoding. Without it, a
V2-only network can permanently strand on a valid block.

This test builds a block strictly above 16 MB (and below the 24 MB max) and
proves a peer that holds NONE of the block's transactions downloads it in full
over P2P:
  * both nodes require V2, forcing the negotiated hashed chunk encoding;
  * the block producer (node0) assembles the >16 MB block while the peer
    (node1) is DISCONNECTED, so the peer's mempool is empty (an unsynced
    baseline -- no loose-tx relay could have pre-populated it);
  * the peer is connected only afterwards and must obtain the whole chain,
    including the >16 MB block, through initial block download. With an empty
    mempool there is no compact-block-from-mempool shortcut; negotiated full
    block chunks are forced onto the wire.
Success (the peer reaches the >16 MB tip) therefore proves manifest/chunk
negotiation, bounded reassembly, identity binding, and re-entry into ordinary
BLOCK admission all work over V2.
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

# The V2 long-message payload ceiling (24-bit contents length minus the type
# framing) the block must exceed, and the consensus/chunk transport ceiling it
# must stay under.
V2_SINGLE_PACKET_PAYLOAD_CEILING = (1 << 24) - 1 - 1 - 12
BLOCK_MESSAGE_CEILING = 24_000_000


class P2PLargeBlockTransportTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 2
        self.setup_clean_chain = True
        # A >16 MB block over loopback is fast, but assembling >16 MB of mempool
        # (hundreds of fan-out txs) and mining it needs headroom.
        self.rpc_timeout = 600
        # node0 assembles the oversized block; node1 is a plain peer that will
        # pull the whole chain (including the >16 MB block) via IBD. Disable
        # rcadmit generation on the source so this also proves that requested
        # historical catch-up crosses RC height 101 without an ephemeral
        # near-tip sidecar.
        self.extra_args = [
            ["-blockmaxweight=24000000", "-blockmaxtemplatetxs=0", "-acceptnonstdtxn=1", "-matmulrcadmission=0", "-v2transport=1", "-debug=net"],
            ["-v2transport=1", "-debug=net"],
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
        target_mempool_bytes = 17_200_000
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
        # The whole point: the block exceeds the V2 single-packet ceiling yet
        # stays under the 24 MB consensus/chunk-transport ceiling.
        assert_greater_than(block_size, V2_SINGLE_PACKET_PAYLOAD_CEILING)
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
        with node0.assert_debug_log(
                ["Queued block", "bounded chunk relay"], timeout=240), \
             node1.assert_debug_log(
                ["Accepted chunked block manifest"], timeout=240):
            self.connect_nodes(1, 0, peer_advertises_v2=True)
            self.wait_until(lambda: any(
                p["transport_protocol_type"] == "v2"
                for p in node1.getpeerinfo()))
            # IBD downloads every block as a full block; this oversized one must
            # use the negotiated manifest/chunk transport and then ordinary
            # BLOCK admission after bounded reassembly.
            self.sync_blocks(timeout=240)

        assert_equal(node1.getbestblockhash(), large_block_hash)
        peer_block_size = len(node1.getblock(large_block_hash, 0)) // 2
        assert_equal(peer_block_size, block_size)
        assert_greater_than(peer_block_size,
                            V2_SINGLE_PACKET_PAYLOAD_CEILING)
        self.log.info("Peer received the full >16 MB block over negotiated V2 chunks")


if __name__ == "__main__":
    P2PLargeBlockTransportTest(__file__).main()
