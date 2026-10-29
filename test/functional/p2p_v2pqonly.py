#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""-v2pqonly leaves no unencrypted v1 connection open.

-v2pqonly is enforced inside V2Transport. Connections that start as v1 never
reach that check:
  - an outbound connection without v2 (for example to an address that does not
    advertise NODE_P2P_V2, or addconnection with v2transport=false),
  - every inbound connection when the node runs with -v2transport=0.

Checks that the node with -v2pqonly
  - still rejects a v1 peer that connects inbound (control),
  - opens an outbound v2 connection but no outbound v1 connection,
  - refuses to start with -v2transport=0.
Regtest only, loopback only.
"""

import socket

from test_framework.messages import MAGIC_BYTES
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, p2p_port


class V2PQOnlyTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.extra_args = [["-modelnet=0", "-modellandiscovery=0", "-debug=net",
                            "-v2transport=1", "-v2pqonly=1"]]

    def v1_peers(self, node):
        return [p for p in node.getpeerinfo() if p["transport_protocol_type"] == "v1"]

    def outbound_attempt(self, node, use_v2):
        """Return the first bytes the node sends to a local listener, or None if it never connects."""
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("127.0.0.1", 0))
        srv.listen(1)
        srv.settimeout(10)
        node.addconnection(f"127.0.0.1:{srv.getsockname()[1]}", "outbound-full-relay", use_v2)
        try:
            conn, _ = srv.accept()
        except socket.timeout:
            srv.close()
            return None
        conn.settimeout(5)
        data = conn.recv(64)
        conn.close()
        srv.close()
        return data

    def run_test(self):
        node = self.nodes[0]

        self.log.info("Control: an inbound v1 peer is rejected")
        with node.assert_debug_log(["rejecting v1 peer under -v2pqonly"], timeout=10):
            s = socket.create_connection(("127.0.0.1", p2p_port(0)), timeout=10)
            s.sendall(MAGIC_BYTES[self.chain] + b"version" + b"\x00" * 5 + b"\x00" * 8)
            try:
                data = s.recv(4096)
            except (ConnectionResetError, socket.timeout):
                data = b""
            s.close()
            assert_equal(data, b"")

        self.log.info("Outbound v2 is opened")
        data = self.outbound_attempt(node, use_v2=True)
        assert data is not None and len(data) > 0, "no outbound v2 connection"
        assert not data.startswith(MAGIC_BYTES[self.chain])

        self.log.info("Outbound v1 is not opened")
        with node.assert_debug_log(["not opening a v1 connection under -v2pqonly"], timeout=10):
            data = self.outbound_attempt(node, use_v2=False)
            assert data is None, f"outbound v1 connection opened, first bytes {data.hex()}"
        assert_equal(len(self.v1_peers(node)), 0)

        self.log.info("-v2pqonly with -v2transport=0 is refused at startup")
        self.stop_node(0)
        node.assert_start_raises_init_error(
            extra_args=["-modelnet=0", "-modellandiscovery=0", "-v2transport=0", "-v2pqonly=1"],
            expected_msg="Error: Cannot set -v2pqonly to true when v2transport is disabled.")


if __name__ == '__main__':
    V2PQOnlyTest(__file__).main()
