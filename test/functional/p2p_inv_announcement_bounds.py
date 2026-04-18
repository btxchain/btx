#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""Validate INV announcement caps under oversized batches."""

from test_framework.messages import (
    CInv,
    MSG_TX,
    MSG_TYPE_MASK,
    MSG_WTX,
    msg_inv,
)
from test_framework.p2p import (
    P2PInterface,
    p2p_lock,
)
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal


MAX_PEER_TX_ANNOUNCEMENTS = 5000


class CountingPeer(P2PInterface):
    def __init__(self):
        super().__init__()
        self.tx_getdata_count = 0

    def on_getdata(self, message):
        for inv in message.inv:
            if inv.type & MSG_TYPE_MASK == MSG_TX or inv.type & MSG_TYPE_MASK == MSG_WTX:
                self.tx_getdata_count += 1


class P2PInvAnnouncementBoundsTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True

    def assert_large_inv_batch(self, *, expected_getdata):
        node = self.nodes[0]
        peer = node.add_p2p_connection(CountingPeer())
        peer.send_message(
            msg_inv([CInv(t=MSG_WTX, h=wtxid) for wtxid in range(MAX_PEER_TX_ANNOUNCEMENTS + 1)])
        )
        peer.wait_until(lambda: peer.tx_getdata_count >= expected_getdata, timeout=20)
        with p2p_lock:
            assert_equal(peer.tx_getdata_count, expected_getdata)
        peer.sync_with_ping()

    def run_test(self):
        # Exit IBD; tx announcement handling is intentionally suppressed during IBD.
        self.generate(self.nodes[0], 1)

        self.log.info("Non-relay peers must be capped at MAX_PEER_TX_ANNOUNCEMENTS")
        self.assert_large_inv_batch(expected_getdata=MAX_PEER_TX_ANNOUNCEMENTS)

        self.log.info("Relay-permission peers may request the full oversized INV batch")
        self.restart_node(0, extra_args=["-whitelist=relay@127.0.0.1"])
        self.assert_large_inv_batch(expected_getdata=MAX_PEER_TX_ANNOUNCEMENTS + 1)


if __name__ == "__main__":
    P2PInvAnnouncementBoundsTest(__file__).main()
