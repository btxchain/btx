#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test that a getblocktxn with no transaction indexes disconnects the peer.

A getblocktxn is only needed when a compact block is missing at least one
transaction, so an empty one has no use and must not make the node read the
block from disk. Case from bitcoin/bitcoin#35832, in a test of its own so that
it does not depend on the rest of p2p_compactblocks.py.
"""

from test_framework.messages import BlockTransactionsRequest, msg_getblocktxn
from test_framework.p2p import P2PInterface
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal


class P2PGetBlockTxnEmptyTest(BitcoinTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 1

    def run_test(self):
        node = self.nodes[0]
        self.log.info("Test that a getblocktxn with no transaction indexes disconnects the peer")
        block_hash = int(node.getbestblockhash(), 16)
        peer = node.add_p2p_connection(P2PInterface())
        msg = msg_getblocktxn()
        msg.block_txn_request = BlockTransactionsRequest(blockhash=block_hash, indexes=[])
        with node.assert_debug_log(['getblocktxn received with no transaction indexes']):
            peer.send_message(msg)
            peer.wait_for_disconnect()
        assert_equal(node.getconnectioncount(), 0)


if __name__ == '__main__':
    P2PGetBlockTxnEmptyTest(__file__).main()
