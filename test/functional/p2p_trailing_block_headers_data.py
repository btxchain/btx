#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Reject tx/block/headers messages that carry trailing bytes."""

from test_framework.messages import (
    CBlock,
    CBlockHeader,
    from_hex,
    msg_generic,
    msg_getheaders,
    msg_headers,
    msg_ping,
)
from test_framework.p2p import P2PInterface
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal


class TrailingBlockHeadersDataTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True

    def run_test(self):
        node = self.nodes[0]

        self.log.info("Verify headers messages with trailing bytes are punished")
        headers_before = node.getblockchaininfo()["headers"]
        block_template = self.generateblock(node, output="raw(51)", transactions=[], submit=False, sync_fun=self.no_op)
        header = CBlockHeader(from_hex(CBlock(), block_template["hex"]))
        header.rehash()
        malformed_headers = msg_headers([header]).serialize() + b"\x00"

        peer = node.add_p2p_connection(P2PInterface())
        with node.assert_debug_log(expected_msgs=["Misbehaving", "trailing data after headers = 1 bytes"]):
            peer.send_message(msg_generic(b"headers", malformed_headers))
            peer.wait_for_disconnect(timeout=5)

        assert_equal(node.getblockchaininfo()["headers"], headers_before)

        self.log.info("Verify block messages with trailing bytes are punished")
        self.generate(node, 1)
        best_block_hex = node.getblock(node.getbestblockhash(), 0)
        malformed_block = bytes.fromhex(best_block_hex) + b"\x00"

        peer = node.add_p2p_connection(P2PInterface())
        with node.assert_debug_log(expected_msgs=["Misbehaving", "trailing data after block = 1 bytes"]):
            peer.send_message(msg_generic(b"block", malformed_block))
            peer.wait_for_disconnect(timeout=5)

        self.log.info("Verify tx messages with trailing bytes are punished")
        coinbase_hex = node.getblock(node.getbestblockhash(), 2)["tx"][0]["hex"]
        malformed_tx = bytes.fromhex(coinbase_hex) + b"\x00"

        peer = node.add_p2p_connection(P2PInterface())
        with node.assert_debug_log(expected_msgs=["Misbehaving", "trailing data after tx = 1 bytes"]):
            peer.send_message(msg_generic(b"tx", malformed_tx))
            peer.wait_for_disconnect(timeout=5)

        self.log.info("Verify ping messages with trailing bytes are punished")
        malformed_ping = msg_ping(nonce=123456789).serialize() + b"\x00"

        peer = node.add_p2p_connection(P2PInterface())
        with node.assert_debug_log(expected_msgs=["Misbehaving", "trailing data after ping = 1 bytes"]):
            peer.send_message(msg_generic(b"ping", malformed_ping))
            peer.wait_for_disconnect(timeout=5)

        self.log.info("Verify getheaders messages with trailing bytes are punished")
        malformed_getheaders = msg_getheaders().serialize() + b"\x00"

        peer = node.add_p2p_connection(P2PInterface())
        with node.assert_debug_log(expected_msgs=["Misbehaving", "trailing data after getheaders = 1 bytes"]):
            peer.send_message(msg_generic(b"getheaders", malformed_getheaders))
            peer.wait_for_disconnect(timeout=5)


if __name__ == "__main__":
    TrailingBlockHeadersDataTest(__file__).main()
