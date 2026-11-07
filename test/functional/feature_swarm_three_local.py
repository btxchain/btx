#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""Three regtest nodes on one host.

The framework connects them. This is a local count, not a public model
family. automatic_spend_atoms stays 0. No second GPU is claimed, and the
nodes share no scheduler object.
"""

from pathlib import Path

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal


class SwarmThreeLocalTest(BitcoinTestFramework):
    def add_options(self, parser):
        self.add_wallet_options(parser)

    def set_test_params(self):
        self.num_nodes = 3
        self.setup_clean_chain = True
        self.rpc_timeout = 180

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def setup_nodes(self):
        self.extra_args = []
        for index in range(self.num_nodes):
            modeldir = Path(self.options.tmpdir) / f"three-local-models-{index}"
            modeldir.mkdir(parents=True)
            self.extra_args.append([
                "-modelnet=1",
                "-modelnetrequired=0",
                "-modelbind=off",
                "-modelstorage=0",
                f"-modeldir={modeldir}",
                f"-modelhelper={modeldir / 'absent-helper'}",
                # Keep regtest block production off the matmul path so a coinbase can mature.
                "-regtestmatmulbindingheight=2147483647",
                "-regtestmatmulproductdigestheight=2147483647",
                "-regtestmatmulv4height=2147483647",
                "-regtestmatmulrequireproductpayload=0",
            ])
        super().setup_nodes()

    def run_test(self):
        assert_equal(self.num_nodes, 3)
        assert_equal(len(self.nodes), 3)
        for node in self.nodes:
            info = node.getmodelnetworkinfo()
            assert_equal(info["automatic_spend_atoms"], 0)
            # The framework chain is already up. Do not print peer records.
            assert node.getconnectioncount() >= 1


if __name__ == "__main__":
    SwarmThreeLocalTest(__file__).main()
