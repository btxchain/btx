#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test a scan object whose range ends at the largest descriptor index.

EvalDescriptorStringOrObject() counted the range in an int, so a range ending
at 2^31-1 overflowed after the last index: undefined behaviour, which
terminates a node built with -ftrapv. Case from bitcoin/bitcoin#35872, in a
test of its own so that it does not depend on the rest of rpc_scantxoutset.py.
"""

from test_framework.descriptors import descsum_create
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal

XPUB = "tpubD6NzVbkrYhZ4YNXVQbNhMK1WqguFsUXceaVJKbmno2aZ3B6QfbMeraaYvnBSGpV3vxLyTTK9DYT1yoEck4XUScMzXoQ2U2oSmE2JyMedq3H"


class ScanTxOutSetRangeEndTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True

    def run_test(self):
        node = self.nodes[0]
        desc = descsum_create(f"wpkh({XPUB}/*)")
        range_end = 2**31 - 1

        self.log.info("A scan of exactly [2^31-1, 2^31-1] returns")
        res = node.scantxoutset("start", [{"desc": desc, "range": [range_end, range_end]}])
        assert_equal(res["success"], True)
        assert_equal(res["unspents"], [])

        self.log.info("So does a range that ends there")
        res = node.scantxoutset("start", [{"desc": desc, "range": [range_end - 1, range_end]}])
        assert_equal(res["success"], True)


if __name__ == '__main__':
    ScanTxOutSetRangeEndTest(__file__).main()
