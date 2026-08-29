#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""End-to-end: jammed in-flight download slots self-heal without a restart.

Production (2026-08-12): peers accepted getdata and never delivered; slots stayed
occupied past BLOCK_REREQUEST_STALE_AFTER (180s); FindNextBlocksToDownload
reported only no_fetchable_in_window; restart was the only recovery.

This test:
  1. Mines a chain on an isolated source node
  2. Feeds headers to the target via a silent P2P peer that records getdata and
     never sends bodies (fills in-flight slots)
  3. Connects an honest peer that can serve the same bodies
  4. Advances mocktime past the hard-reclaim bound
  5. Asserts the target tip advances to the source tip WITHOUT a restart
"""

import time

from test_framework.messages import (
    CBlock,
    CBlockHeader,
    MSG_BLOCK,
    MSG_TYPE_MASK,
    from_hex,
    msg_headers,
)
from test_framework.p2p import P2PDataStore
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_greater_than


# Must match BLOCK_INFLIGHT_HARD_RECLAIM_AFTER / BLOCK_REREQUEST_STALE_AFTER.
RECLAIM_AFTER_SECONDS = 180
# Extra slack so SendMessages observes the aged requested_at stamps.
RECLAIM_SLACK_SECONDS = 20
NUM_BLOCKS = 32


class ChainPeer(P2PDataStore):
    def peer_connect_send_version(self, services):
        super().peer_connect_send_version(services)
        self.on_connection_send_msg.nStartingHeight = NUM_BLOCKS

    def on_getheaders(self, message):
        # This test supplies the complete header set explicitly after the
        # datastore is attached. Do not make the generic datastore walk raw
        # BTX payload wrappers during the outbound handshake.
        pass


class SilentStaller(ChainPeer):
    """Accepts getdata for blocks and never delivers bodies."""

    def on_getdata(self, message):
        for inv in message.inv:
            if (inv.type & MSG_TYPE_MASK) == MSG_BLOCK:
                self.getdata_requests.append(inv.hash)
            # Deliberately do not send msg_block.


class SerializedBlock:
    """Preserve BTX block payload fields unknown to the generic Python model."""

    def __init__(self, block_hex):
        self.raw = bytes.fromhex(block_hex)

    def serialize(self):
        return self.raw


class BlockDownloadSlotReclaimTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 2
        self.setup_clean_chain = True
        # Stay out of tip-age IBD gates; exercise the ordinary download window.
        self.extra_args = [
            ["-debug=net", "-maxtipage=999999999"],
            ["-debug=net", "-maxtipage=999999999"],
        ]

    def setup_network(self):
        # Nodes stay disconnected; the target only learns blocks via crafted peers.
        self.setup_nodes()

    def run_test(self):
        target = self.nodes[0]
        miner = self.nodes[1]

        self.log.info("Mine a source chain on node1")
        source_hashes = self.generate(miner, NUM_BLOCKS, sync_fun=self.no_op)
        blocks = []
        block_dict = {}
        for block_hash in source_hashes:
            block_hex = miner.getblock(block_hash, 0)
            block = from_hex(CBlock(), block_hex)
            block.rehash()
            blocks.append(block)
            block_dict[block.sha256] = SerializedBlock(block_hex)

        headers = msg_headers()
        headers.headers = [CBlockHeader(b) for b in blocks]

        self.mocktime = int(time.time()) + 1
        target.setmocktime(self.mocktime)

        self.log.info("Connect a silent peer that jams in-flight slots")
        staller = target.add_outbound_p2p_connection(
            SilentStaller(), p2p_idx=0, connection_type="outbound-full-relay")
        staller.block_store = block_dict
        staller.send_message(headers)

        self.wait_until(lambda: len(staller.getdata_requests) >= 1)
        # Fill as much of the per-peer transit window as the header set allows.
        self.wait_until(lambda: len(staller.getdata_requests) >= min(16, NUM_BLOCKS))
        jammed = len(staller.getdata_requests)
        self.log.info("Silent peer holds %d unanswered block requests", jammed)
        assert_greater_than(jammed, 0)
        assert_equal(target.getblockcount(), 0)
        staller.sync_with_ping()

        self.log.info(
            "Advance mocktime past hard-reclaim bound (%ds); slots must free "
            "without a restart",
            RECLAIM_AFTER_SECONDS,
        )
        with target.assert_debug_log(
            expected_msgs=["Block download slot reclaim"],
            timeout=60,
        ):
            self.mocktime += RECLAIM_AFTER_SECONDS + RECLAIM_SLACK_SECONDS
            target.setmocktime(self.mocktime)
            # Sole download peer: head-timeout disconnects it (slots freed via
            # FinalizeNode) and/or the hard-reclaim sweep logs. Either path is
            # the self-heal under test; do not require the staller to stay up.
            try:
                if staller.is_connected:
                    staller.sync_with_ping()
            except AssertionError:
                pass
            # Ensure the message handler runs even if the staller is gone.
            time.sleep(0.5)

        # Staller may be disconnected or paused after reclaim; connect a fresh
        # honest peer that can serve the same bodies. Connecting it before the
        # mocktime jump would stamp its in-flight requests as aged and time
        # them out before responses are processed.
        self.log.info("Connect an honest peer after reclaim and expect tip catch-up")
        honest = target.add_outbound_p2p_connection(
            ChainPeer(), p2p_idx=1, connection_type="outbound-full-relay")
        honest.block_store = block_dict
        honest.send_message(headers)

        self.wait_until(lambda: target.getblockcount() == NUM_BLOCKS, timeout=60)
        assert_equal(target.getbestblockhash(), source_hashes[-1])
        self.log.info(
            "Recovered to tip height %d without restart (honest delivered after reclaim)",
            NUM_BLOCKS,
        )


if __name__ == "__main__":
    BlockDownloadSlotReclaimTest(__file__).main()
