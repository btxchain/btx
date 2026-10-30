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
  - opens an automatic outbound connection as v2 to an address whose addrman
    entry does not advertise NODE_P2P_V2 (DNS-seed entries never do),
  - refuses to start with -v2transport=0.
Regtest only, loopback only: the automatic connection goes to a routable
address through a local SOCKS5 proxy that redirects it to a local listener.
"""

import socket

from test_framework.messages import MAGIC_BYTES
from test_framework.socks5 import Socks5Configuration, Socks5Server
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, p2p_port

# Routable, so addrman keeps it; the proxy redirects it to a local listener.
AUTO_ADDR = "1.2.3.4"
AUTO_PORT = 19444  # regtest default port: other ports are skipped at first


class V2PQOnlyTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.extra_args = [["-modelnet=0", "-modellandiscovery=0", "-debug=net",
                            "-v2transport=1", "-v2pqonly=1"]]
        # Automatic outbound connections are part of the test.
        self.disable_autoconnect = False

    def setup_nodes(self):
        # Every outbound connection goes through the proxy. Connections to the
        # local test listeners pass through unchanged; AUTO_ADDR goes to
        # auto_listener.
        self.auto_listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.auto_listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.auto_listener.bind(("127.0.0.1", 0))
        self.auto_listener.listen(4)
        conf = Socks5Configuration()
        conf.addr = ("127.0.0.1", p2p_port(self.num_nodes))
        conf.unauth = True
        conf.auth = True
        conf.destinations_factory = self.redirect
        self.proxy = Socks5Server(conf)
        self.proxy.start()
        self.extra_args[0].append(f"-proxy=127.0.0.1:{p2p_port(self.num_nodes)}")
        super().setup_nodes()

    def redirect(self, addr, port):
        if addr == AUTO_ADDR:
            return {"actual_to_addr": "127.0.0.1", "actual_to_port": self.auto_listener.getsockname()[1]}
        return {"actual_to_addr": addr, "actual_to_port": port}

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

        self.log.info("Automatic outbound to an entry without NODE_P2P_V2 is opened as v2")
        # addpeeraddress stores NODE_NETWORK | NODE_WITNESS, without NODE_P2P_V2.
        assert_equal(node.addpeeraddress(AUTO_ADDR, AUTO_PORT, True), {"success": True})
        self.auto_listener.settimeout(30)
        try:
            conn, _ = self.auto_listener.accept()
        except socket.timeout:
            raise AssertionError("no automatic outbound connection to an entry without NODE_P2P_V2")
        conn.settimeout(5)
        data = conn.recv(64)
        # Read the rest of what the node sent, so the close does not reset the
        # proxy's side of the connection.
        conn.settimeout(0.5)
        try:
            while conn.recv(4096):
                pass
        except socket.timeout:
            pass
        conn.close()
        assert len(data) > 0, "no bytes on the automatic outbound connection"
        assert not data.startswith(MAGIC_BYTES[self.chain]), f"automatic outbound sent v1, first bytes {data.hex()}"
        assert_equal(len(self.v1_peers(node)), 0)
        self.auto_listener.close()

        self.log.info("-v2pqonly with -v2transport=0 is refused at startup")
        self.stop_node(0)
        node.assert_start_raises_init_error(
            extra_args=["-modelnet=0", "-modellandiscovery=0", "-v2transport=0", "-v2pqonly=1"],
            expected_msg="Error: Cannot set -v2pqonly to true when v2transport is disabled.")


if __name__ == '__main__':
    V2PQOnlyTest(__file__).main()
