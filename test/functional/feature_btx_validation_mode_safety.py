#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""Validation-mode safety warnings and RPC visibility checks."""

from test_framework.test_framework import BitcoinTestFramework
from test_framework.test_node import ErrorMatch
from test_framework.util import assert_equal


class BTXValidationModeSafetyTest(BitcoinTestFramework):
    def add_options(self, parser):
        parser.add_argument(
            "--descriptors",
            action="store_true",
            default=True,
            help="Run with descriptor wallet support (default on for BTX).",
        )

    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.extra_args = [[]]

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def run_test(self):
        node = self.nodes[0]

        info = node.getblockchaininfo()
        assert_equal(info["matmulvalidationmode"], "consensus")

        with node.assert_debug_log(
            expected_msgs=[
                "Running in SPV mode: Phase 2 MatMul validation is disabled.",
                "SPV mode active: this node cannot fully validate MatMul consensus.",
            ]
        ):
            self.restart_node(0, extra_args=["-matmulvalidation=spv", "-disablewallet=1"])
        assert_equal(node.getblockchaininfo()["matmulvalidationmode"], "spv")

        self.stop_node(
            0,
            expected_stderr="Warning: SPV mode active: this node cannot fully validate MatMul consensus.",
        )
        node.assert_start_raises_init_error(
            extra_args=["-matmulvalidation=spv"],
            expected_msg=r"Error: SPV mode requires -disablewallet=1 .*",
            match=ErrorMatch.PARTIAL_REGEX,
        )

        with node.assert_debug_log(
            expected_msgs=[
                "Using -reindex-chainstate on MatMul chains does not rerun all contextual Phase 2 checks",
                "Using -reindex-chainstate with non-consensus MatMul validation mode can preserve previously unverified Phase 2 history",
            ]
        ):
            self.start_node(0, extra_args=["-matmulvalidation=economic", "-disablewallet=1", "-reindex-chainstate"])
        assert_equal(node.getblockchaininfo()["matmulvalidationmode"], "economic")
        self.stop_node(
            0,
            expected_stderr=(
                "Warning: Using -reindex-chainstate on MatMul chains does not rerun all contextual Phase 2 checks. "
                "Use -reindex for full historical re-validation.\n"
                "Warning: Using -reindex-chainstate with non-consensus MatMul validation mode can preserve previously unverified Phase 2 history."
            ),
        )


if __name__ == "__main__":
    BTXValidationModeSafetyTest(__file__).main()
