#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""Two node paths that ran into their own lock assertions.

- invalidateblock delivers ActiveTipChange after InvalidateBlock has
  released cs_main.
- GETMMATTEST for a block a serving node does not know is logged from
  inside the handler's LOCK(cs_main) scope.

A DEBUG_LOCKORDER build used to abort on both. Every build must answer
and keep running.
"""

from test_framework.messages import msg_getmmattest
from test_framework.p2p import P2PInterface
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal
from test_framework.wallet_util import generate_keypair

INLINE_SIGNER_WARNING = (
    "Warning: -matmulattestationsignerkey exposes an online signing key "
    "through process/config surfaces; use a permission-restricted "
    "-matmulattestationsignerkeyfile."
)


class LockAssertionPathsTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        signer_wif, signer_pub = generate_keypair(wif=True)
        self.extra_args = [[
            f"-matmultrustedpubkey={signer_pub.hex()}",
            "-matmultrustedthreshold=1",
            f"-matmulattestationsignerkey={signer_wif}",
            "-matmulattestationserve=1",
            "-matmulvalidation=consensus",
            "-debug=net",
        ]]

    def run_test(self):
        node = self.nodes[0]
        self.generate(node, 3)
        tip = node.getbestblockhash()

        self.log.info("invalidateblock and reconsiderblock the tip")
        node.invalidateblock(tip)
        assert_equal(node.getblockcount(), 2)
        node.reconsiderblock(tip)
        assert_equal(node.getbestblockhash(), tip)

        self.log.info("Ask the serving node for a block it does not know")
        peer = node.add_p2p_connection(P2PInterface())
        with node.assert_debug_log(["reason=no_such_block"]):
            peer.send_message(msg_getmmattest(block_hash=0x1d2 << 200))
            peer.sync_with_ping()
        assert_equal(node.getblockcount(), 3)
        assert peer.is_connected

        self.stop_node(0, expected_stderr=INLINE_SIGNER_WARNING)


if __name__ == '__main__':
    LockAssertionPathsTest(__file__).main()
