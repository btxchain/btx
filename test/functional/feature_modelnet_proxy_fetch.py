#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""A model fetch runs end to end through a SOCKS5 proxy.

A host helper serves a model on loopback. A fetcher helper knows the host only
as an IPv4 address, an onion address or a name, and dials it through
-modelproxy; the test's SOCKS5 server forwards every CONNECT to the host. The
fetch must complete with the published bytes, and the fetcher keeps the host's
TLS pin under the endpoint it dialed. feature_modelnet_proxy.py checks that
btxd hands its proxies and -onlynet to the helper.
"""

import json

from feature_modelnet_retrieve_regressions import ModelNetRetrieveRegressionsTest
from test_framework.socks5 import Socks5Configuration, Socks5Server
from test_framework.util import p2p_port

PEER_PORT = 29447
# Without the proxy these reach nobody.
IPV4 = "240.0.0.1"
ONION = "pg6mmjiyjmcrsslvykfwnntlaru7p5svn6y2ymmju6nubxndf4pscryd.onion"
NAME = "modelpeer.invalid"
MODEL_BYTES = 9 << 20  # three pieces


class ModelNetProxyFetchTest(ModelNetRetrieveRegressionsTest):
    def add_options(self, parser):
        pass

    def set_test_params(self):
        super().set_test_params()

    def run_test(self):
        host_port = p2p_port(1)
        conf = Socks5Configuration()
        conf.addr = ("127.0.0.1", p2p_port(2))
        conf.unauth = True
        conf.auth = True
        conf.destinations_factory = lambda addr, port: {"actual_to_addr": "127.0.0.1", "actual_to_port": host_port}
        self.socks = Socks5Server(conf)
        self.socks.start()
        proxy = f"127.0.0.1:{p2p_port(2)}"

        self._host("host", host_port)
        uri = self._import("host", self._write_model("proxy", MODEL_BYTES))["uri"]

        cases = (
            ("IPv4 peer", [f"-modelproxy={proxy}=ipv4"], IPV4),
            ("onion peer", [f"-modelproxy={proxy}=onion"], ONION),
            ("named peer", [f"-modelproxy={proxy}=name"], NAME),
            # A Tor-only node: the IPv4 peer the operator named still goes through the proxy.
            ("IPv4 peer with -modelonlynet=onion",
             [f"-modelproxy={proxy}=ipv4", f"-modelproxy={proxy}=onion", "-modelonlynet=onion"], IPV4),
        )
        for i, (case, proxy_args, host) in enumerate(cases):
            endpoint = f"{host}:{PEER_PORT}"
            self.log.info("%s: fetch from %s through the proxy", case, endpoint)
            self.proxy_destinations()
            name = f"fetch{i}"
            self._start_helper(name, [*proxy_args, f"-modelpeer={endpoint}"])
            self._fetch(name, uri)
            self._assert_bytes_match(name, uri)
            assert (host, PEER_PORT) in self.proxy_destinations()
            pins = json.loads((self.helpers[name]["dir"] / "tls" / "pins.json").read_text())
            assert endpoint in pins, pins
            self._stop_helper(name)

        self.socks.stop()

    def proxy_destinations(self):
        """Empty the proxy's queue and return the destinations it was asked to CONNECT to."""
        dests = set()
        while not self.socks.queue.empty():
            cmd = self.socks.queue.get()
            # The forwarding thread reports a reset when a PQ1 session ends; only CONNECTs count.
            if not isinstance(cmd, Exception):
                dests.add((cmd.addr.decode(), cmd.port))
        return dests


if __name__ == '__main__':
    ModelNetProxyFetchTest(__file__).main()
