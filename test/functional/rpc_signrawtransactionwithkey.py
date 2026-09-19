#!/usr/bin/env python3
# Copyright (c) 2015-2022 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test that signrawtransactionwithkey is disabled (legacy ECDSA)."""

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_raises_rpc_error

SIGNRAWTRANSACTIONWITHKEY_DISABLED_ERROR = (
    "BTX PQ policy: signrawtransactionwithkey is disabled (legacy ECDSA); use wallet signrawtransactionwithwallet with a P2MR address"
)

INPUTS = [
    {'txid': '9b907ef1e3c26fc71fe4a4b3580bc75264112f95050014157059c736f0202e71', 'vout': 0,
     'scriptPubKey': '76a91460baa0f494b38ce3c940dea67f3804dc52d1fb9488ac'},
]
OUTPUTS = {'mpLQjfK79b7CCV4VMJWEWAj5Mpx8Up5zxB': 0.1}
PRIVKEYS = ['cUeKHd5orzT3mz8P9pxyREHfsWtVfgsfDjiZZBcjUBAaGk1BTj7N']


class SignRawTransactionWithKeyTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1

    def run_test(self):
        raw_tx = self.nodes[0].createrawtransaction(INPUTS, OUTPUTS)
        self.log.info("signrawtransactionwithkey is disabled (legacy ECDSA)")
        assert_raises_rpc_error(
            -8,
            SIGNRAWTRANSACTIONWITHKEY_DISABLED_ERROR,
            self.nodes[0].signrawtransactionwithkey,
            raw_tx,
            PRIVKEYS,
            INPUTS,
        )
        assert_raises_rpc_error(
            -8,
            SIGNRAWTRANSACTIONWITHKEY_DISABLED_ERROR,
            self.nodes[0].signrawtransactionwithkey,
            raw_tx,
            [],
            [],
        )


if __name__ == '__main__':
    SignRawTransactionWithKeyTest(__file__).main()
