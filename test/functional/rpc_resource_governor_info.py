#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""Test getresourcegovernorinfo under -rpcdoccheck.

The test framework starts every node with -rpcdoccheck=1, as a debug build
does by default. The call must answer instead of failing the result-doc check.
"""

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal


class ResourceGovernorInfoTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.extra_args = [["-nomodelnet", "-modellandiscovery=0"]]

    def run_test(self):
        node = self.nodes[0]

        self.log.info("getresourcegovernorinfo answers under -rpcdoccheck")
        info = node.getresourcegovernorinfo()
        assert_equal(info["schema_version"], 1)
        assert_equal(info["mode"], "AUTO")
        assert_equal(info["enabled"], True)

        self.log.info("The documented fields follow the mode")
        node.setresourcegovernormode("OFF")
        info = node.getresourcegovernorinfo()
        assert_equal(info["mode"], "OFF")
        assert_equal(info["enabled"], False)


if __name__ == '__main__':
    ResourceGovernorInfoTest(__file__).main()
