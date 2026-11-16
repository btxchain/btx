#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""Outbound peers are not dropped for one benign unconnecting announcement.

A peer announces a block with a single HEADERS message whenever it believes we
already have the parent (BIP 130), which it records from the headers it sent
us. This node deliberately does not store some headers it is sent while keeping
the sender, e.g. headers of a competing branch beyond the unauthenticated-lead
cap. The sender's next ordinary announcement then does not connect. Such a peer
must not be disconnected for that, whatever its connection type, while the
MAX_UNCONNECTING_HEADERS flood bound still applies to every peer.

Scenario: the receiver sits on a short branch. An honest outbound peer serves
the heavier branch, the receiver stores it only up to the lead cap, and the
peer then announces its next block.
"""

from test_framework.messages import (
    CBlock,
    CBlockHeader,
    from_hex,
    msg_headers,
    msg_ping,
)
from test_framework.p2p import P2PInterface, p2p_lock
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_raises_rpc_error

# kernel::MAX_UNAUTHENTICATED_HEADER_LEAD and MAX_UNCONNECTING_HEADERS.
MAX_LEAD = 72
MAX_UNCONNECTING_HEADERS = 10

COMMON = 10
SHORT_BRANCH = 20
# Heavier branch: heights COMMON+1 .. COMMON+HEAVY_BRANCH (11 .. 131).
HEAVY_BRANCH = 121


class P2POutboundUnconnectingHeadersTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 2
        self.setup_clean_chain = True
        # No noban permission: the per-connection-type punishment applies.
        self.extra_args = [["-debug=net"], ["-debug=net"]]

    @staticmethod
    def headers_of(node, hashes):
        headers = []
        for block_hash in hashes:
            block = from_hex(CBlock(), node.getblock(block_hash, 0))
            block.rehash()
            headers.append(CBlockHeader(block))
        return headers

    def kept_after(self, peer, msgs):
        """Send msgs, then a ping. The node handles a peer's messages in order,
        so if processing msgs made it drop the peer, the ping is never
        answered and the connection closes instead."""
        # Outside the framework's own ping counter, whose handshake pong
        # (nonce 1) would otherwise satisfy this barrier immediately.
        self.nonce += 1
        nonce = 0x7e570000 + self.nonce
        with p2p_lock:
            peer.last_message.pop("pong", None)
        try:
            for msg in msgs:
                peer.send_message(msg)
            peer.send_message(msg_ping(nonce))
        except OSError:
            # The node closed the connection while we were still sending.
            peer.wait_for_disconnect(timeout=30)
            return False
        peer.wait_until(
            lambda: not peer.is_connected or (
                "pong" in peer.last_message and
                peer.last_message["pong"].nonce == nonce),
            timeout=30, check_connected=False)
        return peer.is_connected

    def run_test(self):
        self.nonce = 0
        source, receiver = self.nodes
        self.generate(source, COMMON)
        self.disconnect_nodes(0, 1)
        self.generate(receiver, SHORT_BRANCH, sync_fun=self.no_op)
        heavy = self.generate(source, HEAVY_BRANCH, sync_fun=self.no_op)
        tip_height = COMMON + SHORT_BRANCH
        assert_equal(receiver.getblockcount(), tip_height)
        served = self.headers_of(source, heavy[:-1])
        [announced] = self.headers_of(source, heavy[-1:])
        results = {}

        self.log.info("An honest outbound peer serves the heavier branch")
        majority = receiver.add_outbound_p2p_connection(
            P2PInterface(), p2p_idx=0, connection_type="outbound-full-relay")
        assert self.kept_after(majority, [msg_headers(headers=served)])
        # The receiver kept the peer but stored the branch only up to the cap.
        cap = tip_height + MAX_LEAD
        receiver.getblockheader(heavy[cap - COMMON - 1])
        assert_raises_rpc_error(-5, "Block not found",
                                receiver.getblockheader, heavy[cap - COMMON])

        self.log.info("The peer announces its next block, as BIP 130 tells it to")
        results["honest heavier-branch peer kept"] = self.kept_after(
            majority, [msg_headers(headers=[announced])])

        self.log.info("One unconnecting announcement from a block-relay-only peer")
        anchor = receiver.add_outbound_p2p_connection(
            P2PInterface(), p2p_idx=1, connection_type="block-relay-only")
        results["block-relay-only peer kept"] = self.kept_after(
            anchor, [msg_headers(headers=[announced])])

        self.log.info("The flood bound still applies to outbound peers")
        flooder = receiver.add_outbound_p2p_connection(
            P2PInterface(), p2p_idx=2, connection_type="outbound-full-relay")
        tolerated = self.kept_after(
            flooder, [msg_headers(headers=[announced])] * MAX_UNCONNECTING_HEADERS)
        results[f"{MAX_UNCONNECTING_HEADERS} announcements tolerated"] = tolerated
        if tolerated:
            with receiver.assert_debug_log(["(header flood / body-withhold)"]):
                results["dropped at the next one"] = not self.kept_after(
                    flooder, [msg_headers(headers=[announced])])

        for what, ok in results.items():
            self.log.info(f"{'ok  ' if ok else 'FAIL'} {what}")
        assert all(results.values()), (
            f"outbound peers dropped for benign unconnecting announcements: {results}")


if __name__ == "__main__":
    P2POutboundUnconnectingHeadersTest(__file__).main()
