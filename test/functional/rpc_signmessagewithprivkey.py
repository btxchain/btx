#!/usr/bin/env python3
# Copyright (c) 2016-2022 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test that signmessagewithprivkey is disabled and classical verify fails."""

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_raises_rpc_error,
)


class SignMessagesWithPrivTest(BitcoinTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 1

    def run_test(self):
        message = 'This is just a test message'
        priv_key = 'cUeKHd5orzT3mz8P9pxyREHfsWtVfgsfDjiZZBcjUBAaGk1BTj7N'
        classical_sig = 'INbVnW4e6PeRmsv2Qgu8NuopvrVjkcxob+sX8OcZG0SALhWybUjzMLPdAsXI46YZGb0KQTRii+wWIQzRpG/U+S0='

        self.log.info('signmessagewithprivkey is disabled (legacy ECDSA)')
        assert_raises_rpc_error(-8, "signmessagewithprivkey is disabled", self.nodes[0].signmessagewithprivkey, priv_key, message)

        self.log.info('verifymessage refuses classical P2PKH compact ECDSA')
        assert not self.nodes[0].verifymessage('mpLQjfK79b7CCV4VMJWEWAj5Mpx8Up5zxB', classical_sig, message)

        self.log.info('test parameter validity and error codes')
        for num_params in [0, 1, 3, 4, 5]:
            param_list = ["dummy"] * num_params
            assert_raises_rpc_error(-1, "signmessagewithprivkey", self.nodes[0].signmessagewithprivkey, *param_list)
        for num_params in [0, 1, 2, 4, 5]:
            param_list = ["dummy"] * num_params
            assert_raises_rpc_error(-1, "verifymessage", self.nodes[0].verifymessage, *param_list)
        assert_raises_rpc_error(-5, "Invalid address", self.nodes[0].verifymessage, "invalid_addr", classical_sig, message)
        assert_raises_rpc_error(-3, "Malformed base64 encoding", self.nodes[0].verifymessage, 'mpLQjfK79b7CCV4VMJWEWAj5Mpx8Up5zxB', "invalid_sig", message)


if __name__ == '__main__':
    SignMessagesWithPrivTest(__file__).main()
