#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""Canonical first-hole requests move to a new peer without a restart.

Production (2026-08-29): the same missing root was released and immediately
reassigned to an old owner. Each reassignment refreshed requested_at, so the
per-peer and hard timeouts never observed a continuously old request. Restart
only helped by changing peer-selection order.

This test gives the first-hole request to two silent peers, connects an honest
third peer, advances mock time past the catch-up timeout, and requires the stale
owners to be paused before the honest peer receives the root.
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
from test_framework.util import assert_equal


CATCHUP_TIMEOUT_SECONDS = 15
TIMEOUT_SLACK_SECONDS = 5
NUM_BLOCKS = 4


class ChainPeer(P2PDataStore):
    def __init__(self):
        super().__init__()
        self.chain_headers = None
        self.chain_tip = None

    def peer_connect_send_version(self, services):
        super().peer_connect_send_version(services)
        self.on_connection_send_msg.nStartingHeight = NUM_BLOCKS

    def on_getheaders(self, message):
        if self.chain_tip in message.locator.vHave:
            self.send_message(msg_headers())
        elif self.chain_headers is not None:
            self.send_message(self.chain_headers)


class SilentStaller(ChainPeer):
    def on_getdata(self, message):
        for inv in message.inv:
            if (inv.type & MSG_TYPE_MASK) == MSG_BLOCK:
                self.getdata_requests.append(inv.hash)
            # Deliberately do not deliver the requested body.


class SerializedBlock:
    """Preserve BTX block payload fields unknown to the generic model."""

    def __init__(self, block_hex):
        self.raw = bytes.fromhex(block_hex)

    def serialize(self):
        return self.raw


class BlockDownloadRootHandoffTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 2
        self.setup_clean_chain = True
        self.extra_args = [
            ["-debug=net", "-maxtipage=999999999"],
            ["-debug=net", "-maxtipage=999999999"],
        ]

    def setup_network(self):
        self.setup_nodes()

    def run_test(self):
        target = self.nodes[0]
        miner = self.nodes[1]

        source_hashes = self.generate(miner, NUM_BLOCKS, sync_fun=self.no_op)
        blocks = []
        block_store = {}
        for block_hash in source_hashes:
            block_hex = miner.getblock(block_hash, 0)
            block = from_hex(CBlock(), block_hex)
            block.rehash()
            blocks.append(block)
            block_store[block.sha256] = SerializedBlock(block_hex)

        headers = msg_headers()
        headers.headers = [CBlockHeader(block) for block in blocks]
        root_id = blocks[0].sha256

        self.mocktime = int(time.time()) + 1
        target.setmocktime(self.mocktime)

        first_peer = SilentStaller()
        first_peer.block_store = block_store
        first_peer.chain_headers = headers
        first_peer.chain_tip = blocks[-1].sha256
        first = target.add_outbound_p2p_connection(
            first_peer, p2p_idx=0,
            connection_type="outbound-full-relay")
        second_peer = SilentStaller()
        second_peer.block_store = block_store
        second_peer.chain_headers = headers
        second_peer.chain_tip = blocks[-1].sha256
        second = target.add_outbound_p2p_connection(
            second_peer, p2p_idx=1,
            connection_type="outbound-full-relay")
        first.send_message(headers)
        second.send_message(headers)

        self.wait_until(lambda: root_id in first.getdata_requests)
        self.wait_until(lambda: root_id in second.getdata_requests)
        assert_equal(target.getblockcount(), 0)

        honest_peer = ChainPeer()
        honest_peer.block_store = block_store
        honest_peer.chain_headers = headers
        honest_peer.chain_tip = blocks[-1].sha256
        honest = target.add_outbound_p2p_connection(
            honest_peer, p2p_idx=2,
            connection_type="outbound-full-relay")
        honest.send_message(headers)
        honest.sync_with_ping()
        assert root_id not in honest.getdata_requests

        recovery_log_offset = target.debug_log_size(encoding="utf-8")
        first_root_requests = first.getdata_requests.count(root_id)
        second_root_requests = second.getdata_requests.count(root_id)
        self.mocktime += CATCHUP_TIMEOUT_SECONDS + TIMEOUT_SLACK_SECONDS
        target.setmocktime(self.mocktime)
        # Exercise SendMessages on the stale owners. The first pass must
        # release and pause them rather than assigning the root back.
        for stale_peer in (first, second):
            try:
                if stale_peer.is_connected:
                    stale_peer.sync_with_ping()
            except AssertionError:
                # The ordinary head timeout may disconnect a silent owner;
                # disconnect is also a valid ownership handoff.
                pass

        honest.sync_with_ping()
        self.wait_until(lambda: root_id in honest.getdata_requests)
        self.wait_until(
            lambda: target.getblockcount() == NUM_BLOCKS, timeout=60)
        assert_equal(target.getbestblockhash(), source_hashes[-1])
        assert_equal(first.getdata_requests.count(root_id), first_root_requests)
        assert_equal(second.getdata_requests.count(root_id), second_root_requests)

        with open(target.debug_log_path, encoding="utf-8", errors="replace") as log_file:
            log_file.seek(recovery_log_offset)
            recovery_log = log_file.read()
        assert (
            "Block download root handoff" in recovery_log
            or "Block download slot reclaim" in recovery_log
        ), "No automatic stale-root recovery was logged"


if __name__ == "__main__":
    BlockDownloadRootHandoffTest(__file__).main()
