#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""exportmatmulattestations and importmatmulattestations are the documented
aliases of getmatmulattestations and submitmatmulattestations
(doc/btx-matmul-trusted-rpc-mirrors.md) and must reach the same handlers."""

from test_framework.authproxy import JSONRPCException
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal


def rpc_error(fun, *args):
    try:
        fun(*args)
    except JSONRPCException as e:
        return e.error
    raise AssertionError("No exception raised")


class MatMulAttestationAliasesTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True

    def run_test(self):
        node = self.nodes[0]
        genesis = node.getbestblockhash()

        self.log.info("exportmatmulattestations is getmatmulattestations")
        for args in ([genesis], ["00"]):
            assert_equal(
                rpc_error(node.exportmatmulattestations, *args),
                rpc_error(node.getmatmulattestations, *args),
            )

        self.log.info("importmatmulattestations is submitmatmulattestations")
        for args in ([[]], [["00"]]):
            assert_equal(
                rpc_error(node.importmatmulattestations, *args),
                rpc_error(node.submitmatmulattestations, *args),
            )


if __name__ == "__main__":
    MatMulAttestationAliasesTest(__file__).main()
