#!/usr/bin/env python3
# Copyright (c) 2022 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test logic for setting -maxtipage on command line.

Nodes don't consider themselves out of "initial block download" as long as
their best known block header time is more than -maxtipage in the past.

Do not use DEFAULT_MAX_TIP_AGE as a mining timestamp offset. Generating
blocks 30 days (or even 1–2 hours) in the past and waiting for P2P
sync_all() does not converge on this chain (ASERT / EncDr nTime). The
compiled default is verified by `btxd -help-debug` reporting
`default: 2592000`. Stay-in-IBD / leave-IBD is exercised with explicit
1- and 2-hour -maxtipage values by mining on node0 and delivering the
block to node1 via submitblock, not via header sync.
"""

import re
import subprocess
import time

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal


# Compiled DEFAULT_MAX_TIP_AGE{30 * 24h}. Do not pass this into setmocktime.
COMPILED_DEFAULT_MAX_TIP_AGE = 30 * 24 * 60 * 60


class MaxTipAgeTest(BitcoinTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 2

    def setup_network(self):
        # Isolated nodes: P2P sync of mocktime-offset blocks times out.
        self.setup_nodes()

    def assert_compiled_default(self):
        help_text = subprocess.run(
            [self.options.bitcoind, "-help-debug"],
            check=True,
            capture_output=True,
            text=True,
            timeout=30,
        ).stdout
        match = re.search(
            r"-maxtipage=<n>.*?default:\s*(\d+)",
            help_text,
            flags=re.DOTALL,
        )
        assert match is not None, "-maxtipage missing from -help-debug"
        assert_equal(int(match.group(1)), COMPILED_DEFAULT_MAX_TIP_AGE)

    def deliver_block(self, miner, ibd, blockhash):
        """Copy a mined block onto the IBD node without P2P header sync."""
        raw = miner.getblock(blockhash, 0)
        result = ibd.submitblock(raw)
        assert result is None or result == "duplicate", (
            f"submitblock({blockhash}) returned {result!r}"
        )
        assert_equal(ibd.getbestblockhash(), blockhash)

    def test_maxtipage(self, maxtipage, set_parameter=True, test_deltas=True):
        node_miner = self.nodes[0]
        node_ibd = self.nodes[1]

        self.restart_node(1, [f'-maxtipage={maxtipage}'] if set_parameter else None)
        cur_time = int(time.time())

        if test_deltas:
            # tips older than maximum age -> stay in IBD
            node_ibd.setmocktime(cur_time)
            for delta in [5, 4, 3, 2, 1]:
                node_miner.setmocktime(cur_time - maxtipage - delta)
                blockhash = self.generate(node_miner, 1, sync_fun=self.no_op)[0]
                self.deliver_block(node_miner, node_ibd, blockhash)
                assert_equal(node_ibd.getblockchaininfo()['initialblockdownload'], True)

        # tip within maximum age -> leave IBD
        node_miner.setmocktime(max(cur_time - maxtipage, 0))
        blockhash = self.generate(node_miner, 1, sync_fun=self.no_op)[0]
        self.deliver_block(node_miner, node_ibd, blockhash)
        assert_equal(node_ibd.getblockchaininfo()['initialblockdownload'], False)

        # reset time to system time so we don't have a time offset with the ibd node the next
        # time we connect to it, ensuring TimeOffsets::WarnIfOutOfSync() doesn't output to stderr
        node_miner.setmocktime(0)
        node_ibd.setmocktime(0)

    def run_test(self):
        self.log.info("Compiled -maxtipage default is 2592000 (30 days), from -help-debug.")
        self.assert_compiled_default()

        for hours in [2, 1]:
            maxtipage = hours * 60 * 60
            self.log.info(f"Test IBD with maximum tip age of {hours} hours (-maxtipage={maxtipage}) via submitblock.")
            self.test_maxtipage(maxtipage)


if __name__ == '__main__':
    MaxTipAgeTest(__file__).main()
