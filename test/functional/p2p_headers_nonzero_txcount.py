#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Reject headers messages with non-zero per-header transaction counts."""

from test_framework.messages import (
    CBlock,
    CBlockHeader,
    from_hex,
    ser_compact_size,
)
from test_framework.p2p import P2PInterface
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal


class msg_headers_with_tx_count:
    msgtype = b"headers"

    def __init__(self, *, header, tx_count):
        self.header = header
        self.tx_count = tx_count

    def serialize(self):
        payload = ser_compact_size(1)
        payload += CBlockHeader(self.header).serialize()
        payload += ser_compact_size(self.tx_count)
        return payload

    def __repr__(self):
        return f"{self.msgtype}(tx_count={self.tx_count})"


class HeadersNonzeroTxCountTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True

    def run_test(self):
        node = self.nodes[0]
        peer = node.add_p2p_connection(P2PInterface())

        headers_before = node.getblockchaininfo()["headers"]
        block_template = self.generateblock(node, output="raw(51)", transactions=[], submit=False, sync_fun=self.no_op)
        header = CBlockHeader(from_hex(CBlock(), block_template["hex"]))
        header.rehash()

        with node.assert_debug_log(expected_msgs=["Misbehaving", "nonzero headers tx count = 1"]):
            peer.send_message(msg_headers_with_tx_count(header=header, tx_count=1))
            peer.wait_for_disconnect(timeout=5)

        assert_equal(node.getblockchaininfo()["headers"], headers_before)


if __name__ == "__main__":
    HeadersNonzeroTxCountTest(__file__).main()
