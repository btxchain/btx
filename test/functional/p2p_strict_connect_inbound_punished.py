#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""An inbound peer that misbehaves is disconnected under strict -connect.

With -connect=<addr> and an explicit -listen, CConnman skips SendMessages()
for inbound peers, and MaybeDiscourageAndDisconnect() used to run only there.
A misbehaving inbound peer then kept its connection with a score of 100.
"""

from test_framework.messages import msg_ping
from test_framework.p2p import P2PInterface
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import p2p_port

MATMUL_OFF = [
    "-regtestmatmulbindingheight=2147483647",
    "-regtestmatmulproductdigestheight=2147483647",
    "-regtestmatmulv4height=2147483647",
    "-regtestmatmulrequireproductpayload=0",
]


class msg_dandelionacc_trailing:
    """dandelionacc must be empty; a trailing byte is a Misbehaving() case."""
    __slots__ = ()
    msgtype = b"dandelionacc"

    def serialize(self):
        return b"\x00"

    def __repr__(self):
        return "msg_dandelionacc_trailing()"


class StrictConnectInboundPunishedTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        # Strict -connect to an address nobody listens on; -listen=1 keeps
        # inbound connections open.
        self.extra_args = [["-nomodelnet", "-listen=1",
                            f"-connect=127.0.0.1:{p2p_port(5)}", *MATMUL_OFF]]

    def run_test(self):
        node = self.nodes[0]
        peer = node.add_p2p_connection(P2PInterface())
        peer.send_message(msg_ping(nonce=1))
        peer.sync_with_ping()
        self.log.info("A misbehaving inbound peer is disconnected")
        with node.assert_debug_log(["trailing data after dandelionacc"]):
            peer.send_message(msg_dandelionacc_trailing())
            peer.wait_for_disconnect(timeout=20)


if __name__ == "__main__":
    StrictConnectInboundPunishedTest(__file__).main()
