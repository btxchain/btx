#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""SwapNet P2P frames stay inside the transport bounds.

Bounds pinned (src/swapnet/transport.{h,cpp}, src/net_processing.cpp,
src/swapnet/runtime.cpp, contrib/swapnet/swapnet/embedded.py):

- The node opens with swhello "2:<genesis hash>" and admits a peer only after
  the same frame comes back.
- A frame larger than 64 KiB is dropped before the SwapNet transport sees it.
- A frame the runtime cannot use is dropped: counted in packet_errors, or
  logged once as an ignored peer fault when it is not valid UTF-8.
- Each frame costs 1 + size/8192 tokens from a per-peer bucket of 16 that
  refills at 1 per second, so a flooding peer gets at most that many frames
  processed.
- The worker keeps serving RPC and the honest peer through all of it.
"""

import time

from test_framework.messages import (
    msg_swget,
    msg_swhello,
    msg_swprov,
    msg_swquote,
    msg_swreceipt,
    msg_swrfq,
    msg_swterms,
)
from test_framework.p2p import P2PInterface
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_greater_than

FAULT_LOG = "SwapNet: ignored peer fault during message"
MAX_FRAME = 65536
BUCKET = 16


class SwapNetFramesTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 2
        self.setup_clean_chain = True
        self.extra_args = [["-modelbind=off", "-swapnet=1"], ["-modelbind=off", "-swapnet=1"]]

    def admitted(self, node):
        return node.getswapbootstrapinfo()["admitted_peers"]

    def dropped(self):
        """Frames the runtime took and dropped: counted errors plus logged faults."""
        with open(self.nodes[0].debug_log_path, encoding="utf-8", errors="replace") as f:
            logged = f.read().count(FAULT_LOG)
        return self.nodes[0].getswapnetworkinfo()["packet_errors"] + logged

    def settle(self, peer, expected=None):
        """Wait until the worker has drained every queued frame of this peer."""
        peer.sync_with_ping()
        if expected is not None:
            self.wait_until(lambda: self.dropped() >= expected)
        last = self.dropped()
        # The worker takes 16 frames per 20 ms loop; 2 s without change means the queue is empty.
        stable_since = time.time()
        while time.time() - stable_since < 2:
            time.sleep(0.2)
            now = self.dropped()
            if now != last:
                last, stable_since = now, time.time()
        return last

    def refill(self):
        # The bucket runs on the steady clock, which mocktime does not move.
        time.sleep(BUCKET + 1)

    def run_test(self):
        node = self.nodes[0]
        assert_equal(node.getblockchaininfo()["chain"], "regtest")
        genesis = node.getblockhash(0).encode()
        self.wait_until(lambda: self.admitted(node) >= 1 and self.admitted(self.nodes[1]) >= 1)
        assert_equal(self.admitted(node), 1)

        self.log.info("The node opens with swhello 2:<genesis> and admits only that reply")
        peer = node.add_p2p_connection(P2PInterface())
        peer.wait_until(lambda: "swhello" in peer.last_message)
        assert_equal(peer.last_message["swhello"].payload, b"2:" + genesis)
        base = self.settle(peer)
        peer.send_message(msg_swprov(b"[]"))  # before the handshake
        peer.send_message(msg_swhello(b"2:" + b"0" * 64))
        peer.send_message(msg_swhello(b"1:" + genesis))
        peer.send_message(msg_swhello(b""))
        assert_equal(self.settle(peer), base)
        assert_equal(self.admitted(node), 1)
        peer.send_message(msg_swhello(b"2:" + genesis))
        self.wait_until(lambda: self.admitted(node) == 2)

        self.log.info("A frame over 64 KiB never reaches the transport")
        self.refill()
        base = self.settle(peer)
        for msg in (msg_swprov, msg_swget, msg_swterms):
            peer.send_message(msg(b"[" * (MAX_FRAME + 1)))
        assert_equal(self.settle(peer), base)
        peer.send_message(msg_swprov(b"[" * MAX_FRAME))  # at the bound: taken, then dropped
        assert_equal(self.settle(peer, base + 1), base + 1)

        self.log.info("Frames the runtime cannot use are dropped one by one")
        junk = [
            msg_swprov(b"[]"),
            msg_swget(b"{}"),
            msg_swget(b'{"after":0,"limit":0}'),
            msg_swrfq(b"null"),
            msg_swquote(b"{" * 64),
            msg_swterms(b'{"packet":{},"hops":9}'),
            msg_swreceipt(b"\x00"),
            msg_swprov(b"\xff\xfe"),  # not UTF-8
        ]
        self.refill()
        base = self.settle(peer)
        for msg in junk:
            peer.send_message(msg)
        assert_equal(self.settle(peer, base + len(junk)), base + len(junk))
        assert_equal(node.getswapnetworkinfo()["protocol"], 2)

        self.log.info("A flood is cut to the token bucket")
        base = self.settle(peer)
        start = time.time()
        sent = 400
        for _ in range(sent):
            peer.send_message(msg_swprov(b"[]"))
        processed = self.settle(peer) - base
        elapsed = time.time() - start
        self.log.info(f"{processed} of {sent} frames processed in {elapsed:.1f} s")
        assert_greater_than(processed, 0)
        assert processed <= BUCKET + int(elapsed) + 1, f"{processed} frames in {elapsed:.1f} s exceeds the bucket"

        self.log.info("The honest peer and RPC are unaffected")
        assert_equal(node.getswapnetworkinfo()["protocol"], 2)
        peer.peer_disconnect()
        peer.wait_for_disconnect()
        self.wait_until(lambda: self.admitted(node) == 1)
        assert_equal(self.admitted(self.nodes[1]), 1)
        assert_equal(len(node.getpeerinfo()), 1)


if __name__ == "__main__":
    SwapNetFramesTest(__file__).main()
