#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""btx-cli must send preparereorg's max_disconnect as a JSON number.

preparereorg declares max_disconnect as RPCArg::Type::NUM, so it has to be
listed in the client conversion table (src/rpc/client.cpp). Without the entry
btx-cli passes the digits as a JSON string, positional or -named, and the
server rejects the call with "Wrong type passed".
"""

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
    assert_raises_rpc_error,
)


class PrepareReorgCliTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True

    def skip_test_if_missing_module(self):
        self.skip_if_no_cli()

    def run_test(self):
        node = self.nodes[0]
        tip = node.getbestblockhash()

        self.log.info("JSON-RPC reference result")
        plan = node.preparereorg(tip, 1)

        self.log.info("btx-cli positional arguments")
        assert_equal(node.cli.preparereorg(tip, 1), plan)

        self.log.info("btx-cli -named arguments")
        assert_equal(node.cli("-named", "preparereorg", f"target_hash={tip}", "max_disconnect=1").send_cli(), plan)

        self.log.info("max_disconnect reaches the server range check as a number")
        assert_raises_rpc_error(-8, "max_disconnect must be positive", node.cli.preparereorg, tip, 0)


if __name__ == '__main__':
    PrepareReorgCliTest(__file__).main()
