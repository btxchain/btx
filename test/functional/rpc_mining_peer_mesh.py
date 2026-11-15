#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""addminingpeermeshnode is idempotent, also while the peer is connected."""

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, p2p_port


class MiningPeerMeshTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 2
        self.extra_args = [["-nomodelnet"], ["-nomodelnet"]]

    def setup_network(self):
        self.setup_nodes()

    def run_test(self):
        node = self.nodes[0]
        peer = "127.0.0.1:{}".format(p2p_port(1))

        self.log.info("The first call adds the peer and connects")
        first = node.addminingpeermeshnode(peer)
        assert_equal(first["added"], True)
        assert_equal(first["already_added"], False)
        self.wait_until(lambda: any(i["addednode"] == peer and i["connected"] for i in node.getaddednodeinfo()))

        self.log.info("A second call while connected reports the peer as already added")
        second = node.addminingpeermeshnode(peer)
        assert_equal(second["already_added"], True)
        assert_equal(second["added"], False)
        assert_equal(len([i for i in node.getaddednodeinfo() if i["addednode"] == peer]), 1)


if __name__ == "__main__":
    MiningPeerMeshTest(__file__).main()
