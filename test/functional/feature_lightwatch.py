#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""Bind persisted lightwatch balances to the active regtest chain after reorgs."""

import json
import subprocess
from pathlib import Path

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal


class LightWatchTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.extra_args = [[
            "-disablewallet", "-modelnet=0", "-blockfilterindex=1",
            "-regtestmatmulbindingheight=2147483647",
            "-regtestmatmulproductdigestheight=2147483647",
            "-regtestmatmulv4height=2147483647",
            "-regtestmatmulrequireproductpayload=0",
        ]]

    def run_test(self):
        node = self.nodes[0]
        watchdir = Path(self.options.tmpdir) / "lightwatch"

        def watch(*args, ready=True):
            result = subprocess.run([
                node.cli.binary, f"-datadir={node.datadir_path}",
                f"-conf={node.cli.bitcoinconf}", f"-lightwatchdir={watchdir}",
                "lightwatch", *map(str, args),
            ], capture_output=True, text=True, timeout=30)
            if not ready:
                assert result.returncode != 0, result.stdout
                assert "BTX_BALANCE_NOT_READY" in result.stdout + result.stderr, result.stderr
                assert '"amount"' not in result.stdout + result.stderr
                return None
            assert_equal(result.returncode, 0)
            return json.loads(result.stdout)

        def filters_ready():
            self.wait_until(lambda: node.getindexinfo()["basic block filter index"]["best_block_height"] == node.getblockcount())

        blocks = self.generatetodescriptor(node, 3, "raw(51)")
        filters_ready()
        watch("init", "raw(51)", 0)
        watch("balanceat", 3, ready=False)
        assert watch("sync")["ready"]
        assert_equal(watch("balanceat", 3)["immature"], 60)

        # Same-height replacement: matching heights alone cannot prove readiness.
        node.invalidateblock(blocks[-1])
        self.generatetodescriptor(node, 1, "raw(52)")
        filters_ready()
        assert not watch("status")["ready"]
        watch("balance", ready=False)
        watch("balanceat", 3, ready=False)
        assert_equal(watch("balanceat", 2)["immature"], 40)
        self.restart_node(0)
        assert not watch("status")["ready"]
        watch("balanceat", 3, ready=False)
        assert watch("sync")["ready"]
        assert_equal(watch("balance")["immature"], 40)

        # A shorter tip must reject the orphan height before sync and rewind
        # successfully without querying an out-of-range active-chain hash.
        node.invalidateblock(node.getbestblockhash())
        assert_equal(node.getblockcount(), 2)
        watch("balanceat", 3, ready=False)
        assert_equal(watch("balanceat", 2)["immature"], 40)
        assert watch("sync")["ready"]
        assert_equal(watch("status")["wallet_height"], 2)
        watch("balanceat", 3, ready=False)
        self.restart_node(0)
        assert_equal(watch("balance")["immature"], 40)

        # Extending the chain does not invalidate a verified historical prefix.
        self.generatetodescriptor(node, 1, "raw(51)")
        filters_ready()
        assert_equal(watch("balanceat", 2)["immature"], 40)
        watch("balance", ready=False)
        assert watch("sync")["ready"]
        assert_equal(watch("balance")["immature"], 60)
        self.stop_node(0)
        result = subprocess.run([
            node.cli.binary, f"-datadir={node.datadir_path}",
            f"-conf={node.cli.bitcoinconf}", f"-lightwatchdir={watchdir}",
            "-rpcclienttimeout=1", "lightwatch", "balanceat", "2",
        ], capture_output=True, text=True, timeout=10)
        assert result.returncode != 0
        assert '"amount"' not in result.stdout + result.stderr


if __name__ == "__main__":
    LightWatchTest(__file__).main()
