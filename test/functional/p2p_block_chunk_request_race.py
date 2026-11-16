#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""A chunked-block manifest that loses a benign request race is not misbehavior.

The node asks a chunk-capable peer for a block. Before that peer's manifest
arrives, another peer delivers the same block, and processing the new block
releases the in-flight request for every peer. The first peer's manifest was
solicited but no longer matches a live request. The node must end that stream
without classifying the honest peer as misbehaving (on a routable address that
would discourage it) and without punishing its following chunk.
"""

from test_framework.messages import (
    CBlock,
    CBlockHeader,
    from_hex,
    hash256,
    msg_blkchnkman,
    msg_blkchunk,
    msg_block,
    msg_headers,
    msg_sendblkchnk,
    uint256_from_str,
)
from test_framework.p2p import P2PInterface, p2p_lock
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal


CHUNK_SIZE = 1 << 20


class BlockServingPeer(P2PInterface):
    """Advertise a start height so the node downloads bodies from this peer."""
    def peer_connect_send_version(self, services):
        super().peer_connect_send_version(services)
        self.on_connection_send_msg.nStartingHeight = 100


class P2PBlockChunkRequestRaceTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 2
        self.setup_clean_chain = True
        # No noban permission on the receiver, so Misbehaving takes the real
        # punishment path. Loopback peers are disconnected but not discouraged
        # (MaybeDiscourageAndDisconnect), so the test asserts on the
        # Misbehaving classification itself; on a routable address the same
        # classification discourages the peer's address.
        self.extra_args = [["-debug=net"], ["-debug=net"]]

    @staticmethod
    def inflight(node, peer_id):
        for info in node.getpeerinfo():
            if info["id"] == peer_id:
                return info["inflight"]
        raise AssertionError(f"peer {peer_id} not connected")

    def run_test(self):
        source, receiver = self.nodes
        self.generate(source, 99)
        self.disconnect_nodes(0, 1)
        [block_hash] = self.generate(source, 1, sync_fun=self.no_op)
        block = from_hex(CBlock(), source.getblock(block_hash, 0))
        block.rehash()
        payload = block.serialize()
        manifest = msg_blkchnkman(
            block_hash=block.sha256,
            total_size=len(payload),
            chunk_size=CHUNK_SIZE,
            chunk_count=1 + (len(payload) - 1) // CHUNK_SIZE,
            payload_hash=uint256_from_str(hash256(payload)),
        )
        chunk = msg_blkchunk(block_hash=block.sha256, index=0, data=payload)

        self.log.info("The node asks a chunk-capable peer for the block")
        honest = receiver.add_p2p_connection(BlockServingPeer())
        honest.send_and_ping(msg_sendblkchnk())
        honest_id = max(p["id"] for p in receiver.getpeerinfo())
        with p2p_lock:
            honest.last_message.pop("getdata", None)
        honest.send_message(msg_headers(headers=[CBlockHeader(block)]))
        honest.wait_for_getdata([block.sha256], timeout=30)
        receiver.wait_until(
            lambda: self.inflight(receiver, honest_id) == [100], timeout=30)

        self.log.info("Another peer delivers the same block first")
        other = receiver.add_p2p_connection(BlockServingPeer())
        other.send_and_ping(msg_block(block))
        receiver.wait_until(
            lambda: receiver.getbestblockhash() == block_hash, timeout=60)
        # Processing the new block released the honest peer's request too.
        receiver.wait_until(
            lambda: self.inflight(receiver, honest_id) == [], timeout=30)

        self.log.info("The honest peer's solicited stream arrives after the release")
        with receiver.assert_debug_log(
                expected_msgs=["unsolicited blkchnkman"],
                unexpected_msgs=[f"Misbehaving: peer={honest_id}: "]):
            honest.send_message(manifest)
            honest.send_message(chunk)
            honest.wait_for_disconnect(timeout=30)

        self.log.info("The delivering peer and the tip are unaffected")
        other.sync_with_ping()
        assert_equal(receiver.getbestblockhash(), block_hash)
        assert_equal(receiver.getblockcount(), 100)


if __name__ == "__main__":
    P2PBlockChunkRequestRaceTest(__file__).main()
