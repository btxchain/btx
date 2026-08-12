#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""Exercise negotiated block-chunk rejection and request cleanup."""

from test_framework.messages import (
    CBlock,
    CBlockHeader,
    from_hex,
    hash256,
    msg_blkchnkman,
    msg_blkchunk,
    msg_block,
    msg_generic,
    msg_headers,
    msg_sendblkchnk,
    ser_compact_size,
    ser_uint256,
    uint256_from_str,
)
from test_framework.p2p import P2PInterface, p2p_lock
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal


CHUNK_SIZE = 1 << 20


class P2PBlockChunkTransportTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 2
        self.setup_clean_chain = True
        # Keep malformed-stream peers connected so each assertion exercises
        # the handler's own terminal ownership/reservation cleanup rather than
        # relying on FinalizeNode as a backstop. The explicit no-negotiation
        # disconnect below remains mandatory even for this NoBan peer.
        self.extra_args = [
            ["-debug=net"],
            ["-debug=net", "-whitelist=noban@127.0.0.1"],
        ]

    @staticmethod
    def manifest(block_hash, payload):
        return msg_blkchnkman(
            block_hash=block_hash,
            total_size=len(payload),
            chunk_size=CHUNK_SIZE,
            chunk_count=1 + (len(payload) - 1) // CHUNK_SIZE,
            payload_hash=uint256_from_str(hash256(payload)),
        )

    @staticmethod
    def request_block(peer, block):
        with p2p_lock:
            peer.last_message.pop("getdata", None)
        peer.send_message(msg_headers(headers=[CBlockHeader(block)]))
        peer.wait_for_getdata([block.sha256], timeout=30)

    @staticmethod
    def expect_re_request(peer, block):
        """Assert terminal stream cleanup makes the hash requestable again."""
        peer.wait_for_getdata([block.sha256], timeout=30)

    def run_test(self):
        source, receiver = self.nodes
        self.generate(source, 99)
        self.disconnect_nodes(0, 1)
        [block_hash] = self.generate(source, 1, sync_fun=self.no_op)
        block = from_hex(CBlock(), source.getblock(block_hash, 0))
        block.rehash()
        payload = block.serialize()
        manifest = self.manifest(block.sha256, payload)

        self.log.info("Reject chunk encoding without reciprocal negotiation")
        legacy_peer = receiver.add_p2p_connection(P2PInterface())
        self.request_block(legacy_peer, block)
        with receiver.assert_debug_log(["blkchnkman without negotiation"]):
            legacy_peer.send_message(manifest)
            legacy_peer.wait_for_disconnect(timeout=30)

        peer = receiver.add_p2p_connection(P2PInterface())
        peer.send_and_ping(msg_sendblkchnk())

        self.log.info("Reject an out-of-order chunk and release its request")
        self.request_block(peer, block)
        peer.send_message(manifest)
        with p2p_lock:
            peer.last_message.pop("getdata", None)
        with receiver.assert_debug_log(
                ["malformed or out-of-order blkchunk"]):
            peer.send_and_ping(msg_blkchunk(
                block_hash=block.sha256, index=1, data=b""))
        self.expect_re_request(peer, block)

        self.log.info("An interleaved manifest terminates the active stream")
        peer.send_message(manifest)
        with p2p_lock:
            peer.last_message.pop("getdata", None)
        with receiver.assert_debug_log(["interleaved blkchnkman"]):
            peer.send_and_ping(manifest)
        self.expect_re_request(peer, block)

        self.log.info("Reject an oversized declared vector before allocation")
        peer.send_message(manifest)
        with p2p_lock:
            peer.last_message.pop("getdata", None)
        oversized = (ser_uint256(block.sha256) +
                     (0).to_bytes(4, "little") +
                     ser_compact_size(CHUNK_SIZE + 1))
        with receiver.assert_debug_log(["oversized or truncated blkchunk"]):
            peer.send_and_ping(msg_generic(b"blkchunk", oversized))
        self.expect_re_request(peer, block)

        self.log.info("Bind the assembled payload's decoded block to request X")
        mismatched = CBlock(block)
        mismatched.nTime += 1
        mismatched.rehash()
        mismatched_payload = mismatched.serialize()
        peer.send_message(self.manifest(block.sha256, mismatched_payload))
        with p2p_lock:
            peer.last_message.pop("getdata", None)
        with receiver.assert_debug_log(["blkchunk payload identity mismatch"]):
            peer.send_and_ping(msg_blkchunk(
                block_hash=block.sha256,
                index=0,
                data=mismatched_payload))
        self.expect_re_request(peer, block)

        # Each terminal rejection above must have removed the expected hash's
        # in-flight ownership. Re-announcement therefore remains requestable,
        # and the ordinary BLOCK path can still advance the tip.
        peer.send_message(msg_block(block))
        receiver.wait_until(
            lambda: receiver.getbestblockhash() == block_hash, timeout=120)
        assert_equal(receiver.getblockcount(), 100)


if __name__ == "__main__":
    P2PBlockChunkTransportTest(__file__).main()
