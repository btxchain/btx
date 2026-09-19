#!/usr/bin/env python3
# Copyright (c) 2014-2022 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test that sweepprivkeys is disabled (legacy ECDSA)."""

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_raises_rpc_error

SWEEPPRIVKEYS_DISABLED_ERROR = (
    "BTX PQ policy: sweepprivkeys is disabled (legacy ECDSA); use wallet P2MR descriptors"
)


class SweepPrivKeysTest(BitcoinTestFramework):
    def add_options(self, parser):
        self.add_wallet_options(parser)

    def set_test_params(self):
        self.num_nodes = 1

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def run_test(self):
        self.log.info("sweepprivkeys is disabled (legacy ECDSA)")
        assert_raises_rpc_error(
            -8,
            SWEEPPRIVKEYS_DISABLED_ERROR,
            self.nodes[0].sweepprivkeys,
            {'privkeys': ('92YkaycAxLPUqbbV78V9nNngKLnyVd9T8uZuZAzQnc26dJSP4fm',), 'label': 'test 1'},
        )


if __name__ == '__main__':
    SweepPrivKeysTest(__file__).main()
