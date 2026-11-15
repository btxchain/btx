#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""The model helper reaches its peers by the node's -proxy, -onion and -onlynet.

btxd hands its proxies and -onlynet to the btx-modeld it starts, and the
helper dials like btxd dials its own peers: IPv4, IPv6, onion and named peers
through the proxy for their network (names are not resolved locally), with
fresh proxy credentials per connection unless -proxyrandomize=0. A local peer
is dialed directly, and an onion peer needs -proxy or -onion.

The proxy records each CONNECT and closes, so no PQ1 session is set up; only
the route of the helper's dials is checked. A plain TCP listener stands in
for a loopback peer and counts direct connections.
"""

import os
import socket
import threading
from pathlib import Path

from test_framework.socks5 import AddressType, Socks5Configuration, Socks5Server
from test_framework.test_framework import BitcoinTestFramework, SkipTest
from test_framework.util import assert_equal, p2p_port

MATMUL_OFF_ARGS = [
    "-regtestmatmulbindingheight=2147483647",
    "-regtestmatmulproductdigestheight=2147483647",
    "-regtestmatmulv4height=2147483647",
    "-regtestmatmulrequireproductpayload=0",
]
PEER_PORT = 29447
# Routable addresses in reserved space, so a direct dial from a broken build reaches nobody.
IPV4 = "240.0.0.1"
IPV6 = "1233:3432:2434:2343:3234:2345:6546:4534"
ONION = "pg6mmjiyjmcrsslvykfwnntlaru7p5svn6y2ymmju6nubxndf4pscryd.onion"
NAME = "modelpeer.invalid"


class DirectListener:
    """Counts TCP connections that reach the loopback peer."""

    def __init__(self, port):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("127.0.0.1", port))
        self.sock.listen(16)
        self.count = 0
        self.lock = threading.Lock()
        threading.Thread(target=self.run, daemon=True).start()

    def run(self):
        while True:
            try:
                conn, _ = self.sock.accept()
            except OSError:
                return
            with self.lock:
                self.count += 1
            conn.close()

    def connections(self):
        with self.lock:
            return self.count


class ModelNetProxyTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        # -proxy sets -listen=0, which refuses the harness's bind=127.0.0.1 line.
        self.bind_to_localhost_only = False
        self.extra_args = [["-modelnet=0", *MATMUL_OFF_ARGS]]

    def skip_test_if_missing_module(self):
        self.skip_if_platform_not_posix()
        exeext = self.config["environment"].get("EXEEXT", "")
        modeld = Path(self.config["environment"]["BUILDDIR"]) / "bin" / f"btx-modeld{exeext}"
        if not (modeld.is_file() and os.access(modeld, os.X_OK)):
            raise SkipTest("btx-modeld missing")

    def start_helper(self, case, extra):
        """Restart the node with its helper on a fresh model store and the given peers."""
        modeldir = self.nodes[0].datadir_path / f"modeldir-{case}"
        args = ["-modelnet=1", "-modelstorage=0", f"-modeldir={modeldir}", *MATMUL_OFF_ARGS, *extra]
        self.restart_node(0, extra_args=args)
        self.drain_proxy()
        self.direct_before = self.direct.connections()

    def drain_proxy(self):
        while not self.socks.queue.empty():
            self.socks.queue.get()

    def proxy_connects(self, want, timeout=60):
        """Collect proxy CONNECTs until each destination in `want` was seen twice (two dial rounds)."""
        seen = {}
        cmds = []

        def done():
            while not self.socks.queue.empty():
                cmd = self.socks.queue.get()
                assert not isinstance(cmd, Exception), cmd
                cmds.append(cmd)
                dest = (cmd.addr.decode(), cmd.port)
                seen[dest] = seen.get(dest, 0) + 1
            return all(seen.get(d, 0) >= 2 for d in want)

        self.wait_until(done, timeout=timeout)
        return cmds, seen

    def assert_launch(self, expected):
        """The helper launch line in debug.log carries the number of proxies and -onlynet."""
        lines = [line for line in self.nodes[0].debug_log_path.read_text(errors="replace").splitlines() if "model helper exe=" in line]
        assert expected in lines[-1], lines[-1]

    def run_test(self):
        node = self.nodes[0]
        # btxd puts the helper's unix socket under the datadir. A deep tmpdir
        # pushes it past sun_path, and without XDG_RUNTIME_DIR btxd has
        # nowhere shorter to put it.
        sock = node.chain_path / "modelnet" / "modeld.sock"
        if len(str(sock).encode()) >= 104 and not os.environ.get("XDG_RUNTIME_DIR"):
            raise SkipTest(f"tmpdir too deep for the helper's unix socket ({sock})")

        conf = Socks5Configuration()
        conf.addr = ("127.0.0.1", p2p_port(2))
        conf.unauth = True
        conf.auth = True
        self.socks = Socks5Server(conf)
        self.socks.start()
        proxy = f"127.0.0.1:{p2p_port(2)}"
        self.direct = DirectListener(p2p_port(3))
        local = f"-modelpeer=127.0.0.1:{p2p_port(3)}"
        ipv4, ipv6, onion, name = ((IPV4, PEER_PORT), (IPV6, PEER_PORT), (ONION, PEER_PORT), (NAME, PEER_PORT))
        ipv4_arg = f"-modelpeer={IPV4}:{PEER_PORT}"
        ipv6_arg = f"-modelpeer=[{IPV6}]:{PEER_PORT}"
        onion_arg = f"-modelpeer={ONION}:{PEER_PORT}"
        name_arg = f"-modelpeer={NAME}:{PEER_PORT}"

        self.log.info("No proxy: the helper dials a peer directly")
        self.start_helper("direct", [local])
        self.wait_until(lambda: self.direct.connections() > self.direct_before, timeout=60)

        self.log.info("-proxy: IPv4, IPv6, onion and named peers go through the proxy")
        self.start_helper("proxy", [f"-proxy={proxy}", local, ipv4_arg, ipv6_arg, onion_arg, name_arg])
        cmds, seen = self.proxy_connects([ipv4, ipv6, onion, name])
        assert_equal(set(seen), {ipv4, ipv6, onion, name})
        for cmd in cmds:
            # Every destination reaches the proxy as a name; the helper resolves nothing itself.
            assert_equal(cmd.atyp, AddressType.DOMAINNAME)
            # -proxyrandomize (default on): new credentials for every connection.
            assert cmd.username is not None
        assert_equal(len({cmd.username for cmd in cmds}), len(cmds))
        # A loopback peer is not handed to the proxy (btxd does the same for its own peers).
        self.wait_until(lambda: self.direct.connections() > self.direct_before, timeout=60)
        self.assert_launch("proxies=4 onlynet=all")

        self.log.info("-proxyrandomize=0: the helper sends no proxy credentials")
        self.start_helper("norandom", [f"-proxy={proxy}", "-proxyrandomize=0", onion_arg])
        cmds, _ = self.proxy_connects([onion])
        assert all(cmd.username is None for cmd in cmds)

        self.log.info("-proxy with -onlynet=onion: peers the operator named still go through the proxy")
        self.start_helper("proxyonion", [f"-proxy={proxy}", "-onlynet=onion", ipv4_arg, onion_arg, name_arg])
        _, seen = self.proxy_connects([ipv4, onion, name])
        assert_equal(set(seen), {ipv4, onion, name})
        self.assert_launch("proxies=4 onlynet=onion")

        self.log.info("-onion with -onlynet=onion: the onion peer goes through -onion")
        self.start_helper("onlyonion", [f"-onion={proxy}", "-onlynet=onion", onion_arg])
        _, seen = self.proxy_connects([onion])
        assert_equal(set(seen), {onion})
        self.assert_launch("proxies=1 onlynet=onion")

        self.log.info("A proxy for IPv4 only: the onion peer is not handed to it")
        self.start_helper("ipv4proxy", [f"-proxy={proxy}=ipv4", ipv4_arg, onion_arg])
        _, seen = self.proxy_connects([ipv4])
        assert_equal(set(seen), {ipv4})
        self.assert_launch("proxies=2 onlynet=all")

        self.stop_node(0)
        self.socks.stop()


if __name__ == '__main__':
    ModelNetProxyTest(__file__).main()
