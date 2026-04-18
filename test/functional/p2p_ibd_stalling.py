#!/usr/bin/env python3
# Copyright (c) 2022- The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""
Test stalling logic during IBD
"""

import time

from test_framework.messages import (
        CBlock,
        MSG_BLOCK,
        MSG_TYPE_MASK,
        from_hex,
)
from test_framework.p2p import (
        CBlockHeader,
        msg_block,
        msg_headers,
        P2PDataStore,
)
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
        assert_equal,
)


class P2PStaller(P2PDataStore):
    def __init__(self, stall_block):
        self.stall_block = stall_block
        super().__init__()

    def on_getdata(self, message):
        for inv in message.inv:
            self.getdata_requests.append(inv.hash)
            if (inv.type & MSG_TYPE_MASK) == MSG_BLOCK:
                if (inv.hash != self.stall_block):
                    self.send_message(msg_block(self.block_store[inv.hash]))

    def on_getheaders(self, message):
        pass


class P2PIBDStallingTest(BitcoinTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        # Keep node0 as the IBD/stalling target and mine source blocks on node1.
        self.num_nodes = 2

    def setup_network(self):
        # Intentionally do not connect the nodes; node0 should only learn blocks
        # from crafted P2P peers in this test.
        self.setup_nodes()

    def run_test(self):
        NUM_BLOCKS = 1025
        NUM_PEERS = 4
        node = self.nodes[0]
        miner = self.nodes[1]
        blocks = []
        self.log.info("Generate a valid source chain on node1 and prepare blocks for node0")
        source_hashes = self.generate(miner, NUM_BLOCKS, sync_fun=self.no_op)
        block_dict = {}
        for block_hash in source_hashes:
            block = from_hex(CBlock(), miner.getblock(block_hash, 0))
            block.rehash()
            blocks.append(block)
            block_dict[block.sha256] = block
        stall_block = blocks[0].sha256

        headers_message = msg_headers()
        headers_message.headers = [CBlockHeader(b) for b in blocks[:NUM_BLOCKS-1]]
        peers = []

        self.log.info("Check that a staller does not get disconnected if the 1024 block lookahead buffer is filled")
        self.mocktime = int(time.time()) + 1
        node.setmocktime(self.mocktime)
        for id in range(NUM_PEERS):
            peers.append(node.add_outbound_p2p_connection(P2PStaller(stall_block), p2p_idx=id, connection_type="outbound-full-relay"))
            peers[-1].block_store = block_dict
            peers[-1].send_message(headers_message)

        # Wait until node0 requested the withheld block and has issued getdata
        # for almost the entire 1024-header window. This replaces fragile fixed
        # byte-count assumptions that changed with BTX/KAWPOW headers.
        self.wait_until(lambda: self.is_block_requested(peers, stall_block))
        self.wait_until(lambda: self.total_getdata_requests(peers) >= NUM_BLOCKS - 2)

        self.all_sync_send_with_ping(peers)
        # If there was a peer marked for stalling, it would get disconnected
        self.mocktime += 3
        node.setmocktime(self.mocktime)
        self.all_sync_send_with_ping(peers)
        assert_equal(node.num_test_p2p_connections(), NUM_PEERS)

        self.log.info("Check that increasing the window beyond 1024 blocks triggers stalling logic")
        headers_message.headers = [CBlockHeader(b) for b in blocks]
        with node.assert_debug_log(expected_msgs=['Stall started']):
            for p in peers:
                p.send_message(headers_message)
            self.all_sync_send_with_ping(peers)

        self.log.info("Check that the stalling peer is disconnected after 2 seconds")
        self.mocktime += 3
        node.setmocktime(self.mocktime)
        peers[0].wait_for_disconnect()
        assert_equal(node.num_test_p2p_connections(), NUM_PEERS - 1)
        self.wait_until(lambda: self.is_block_requested(peers, stall_block))
        # Make sure that SendMessages() is invoked, which assigns the missing block
        # to another peer and starts the stalling logic for them
        self.all_sync_send_with_ping(peers)

        self.log.info("Check that the stalling timeout gets doubled to 4 seconds for the next staller")
        # No disconnect after just 3 seconds
        self.mocktime += 3
        node.setmocktime(self.mocktime)
        self.all_sync_send_with_ping(peers)
        assert_equal(node.num_test_p2p_connections(), NUM_PEERS - 1)

        self.mocktime += 2
        node.setmocktime(self.mocktime)
        self.wait_until(lambda: sum(x.is_connected for x in node.p2ps) == NUM_PEERS - 2)
        self.wait_until(lambda: self.is_block_requested(peers, stall_block))
        self.all_sync_send_with_ping(peers)

        self.log.info("Check that the stalling timeout gets doubled to 8 seconds for the next staller")
        # No disconnect after just 7 seconds
        self.mocktime += 7
        node.setmocktime(self.mocktime)
        self.all_sync_send_with_ping(peers)
        assert_equal(node.num_test_p2p_connections(), NUM_PEERS - 2)

        self.mocktime += 2
        node.setmocktime(self.mocktime)
        self.wait_until(lambda: sum(x.is_connected for x in node.p2ps) == NUM_PEERS - 3)
        self.wait_until(lambda: self.is_block_requested(peers, stall_block))
        self.all_sync_send_with_ping(peers)

        self.log.info("Provide the withheld block and check that stalling timeout gets reduced")
        with node.assert_debug_log(expected_msgs=['Decreased stalling timeout to']):
            for p in peers:
                if p.is_connected and (stall_block in p.getdata_requests):
                    p.send_message(msg_block(block_dict[stall_block]))

        self.log.info("Check that all outstanding blocks get connected")
        self.wait_until(lambda: node.getblockcount() == NUM_BLOCKS)

    def total_bytes_recv_for_blocks(self):
        total = 0
        for info in self.nodes[0].getpeerinfo():
            if ("block" in info["bytesrecv_per_msg"].keys()):
                total += info["bytesrecv_per_msg"]["block"]
        return total

    def total_getdata_requests(self, peers):
        return sum(len(p.getdata_requests) for p in peers)

    def all_sync_send_with_ping(self, peers):
        for p in peers:
            if p.is_connected:
                p.sync_with_ping()

    def is_block_requested(self, peers, hash):
        for p in peers:
            if p.is_connected and (hash in p.getdata_requests):
                return True
        return False


if __name__ == '__main__':
    P2PIBDStallingTest(__file__).main()
