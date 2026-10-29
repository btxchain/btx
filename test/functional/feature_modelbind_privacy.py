#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""The model helper's PQ1 port stays closed on proxied, non-IP and loopback-bound nodes.

btxd passes -modelbind=0.0.0.0:29447 to the helper by default, and the helper
does not use -proxy. f19fd0d5 closes the port for -listen=0. An onion-service
operator runs -listen=1 with -proxy, -onlynet=onion or a loopback -bind; the
port must be closed there too, unless -modelbind is set explicitly.

btxd logs its helper launch config ("model helper exe=... bind=...") whether
or not a btx-modeld is packaged, so the decision is checked in debug.log.
"""

from test_framework.test_framework import BitcoinTestFramework

COMMON = [
    "-modelnet=1", "-modellandiscovery=0", "-natpmp=0", "-autoupdate=0", "-listenonion=0",
    "-regtestmatmulbindingheight=2147483647",
    "-regtestmatmulproductdigestheight=2147483647",
    "-regtestmatmulv4height=2147483647",
    "-regtestmatmulrequireproductpayload=0",
]


class ModelBindPrivacyTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True

    def setup_network(self):
        self.add_nodes(self.num_nodes)
        # The framework config pins modelbind=0; drop it to see the default.
        # It keeps bind=127.0.0.1, so P2P stays on loopback in every case.
        conf = self.nodes[0].datadir_path / "btx.conf"
        if not conf.exists():
            conf = self.nodes[0].datadir_path / "bitcoin.conf"
        lines = [line for line in conf.read_text().splitlines() if not line.startswith("modelbind=")]
        conf.write_text("\n".join(lines) + "\n")

    def check(self, extra, expected):
        with self.nodes[0].assert_debug_log(expected_msgs=expected):
            self.start_node(0, extra_args=COMMON + extra)
        self.stop_node(0)

    def run_test(self):
        self.log.info("-proxy with -listen=1 closes the model port")
        self.check(["-proxy=127.0.0.1:9", "-listen=1"],
                   ["parameter interaction: -proxy set -> setting -modelbind=off", " bind= host="])
        self.log.info("-onlynet=onion with -listen=1 closes the model port")
        self.check(["-onion=127.0.0.1:9", "-onlynet=onion", "-listen=1"],
                   ["parameter interaction: -onlynet without ipv4/ipv6 -> setting -modelbind=off", " bind= host="])
        self.log.info("a loopback-only -bind with -listen=1 closes the model port")
        self.check(["-listen=1"],
                   ["parameter interaction: -bind on loopback only -> setting -modelbind=off", " bind= host="])
        self.log.info("an explicit -modelbind is kept")
        self.check(["-proxy=127.0.0.1:9", "-listen=1", "-modelbind=127.0.0.1:29447"],
                   [" bind=127.0.0.1:29447 host="])


if __name__ == "__main__":
    ModelBindPrivacyTest(__file__).main()
