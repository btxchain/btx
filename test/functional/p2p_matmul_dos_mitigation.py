#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""MatMul invalid-block DoS mitigation smoke test."""

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal


class BTXMatMulDosMitigationTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 2
        self.setup_clean_chain = True
        self.extra_args = [
            ["-test=matmulstrict"],
            ["-test=matmulstrict"],
        ]

    def _tampered_candidate(self, node):
        candidate = node.generateblock("raw(51)", [], False, called_by_framework=True)
        bad_hex = candidate["hex"]
        # Overwrite the entire matmul_digest with an unmistakably over-target
        # value (all 0xff) so the header fails the phase1 target check and is
        # rejected "high-hash". A single-nibble flip would leave the digest
        # under the (easy regtest) target but break its binding to the product
        # payload, which the node rejects as "invalid-product-payload" instead.
        digest_start = (4 + 32 + 32 + 4 + 4 + 8) * 2
        digest_end = digest_start + 64
        return bad_hex[:digest_start] + ("f" * 64) + bad_hex[digest_end:]

    def run_test(self):
        node0, node1 = self.nodes

        self.generate(node0, 10)
        self.sync_blocks()
        tip_hash = node0.getbestblockhash()

        # Repeated invalid headers should be rejected and chain tip should remain stable.
        saw_high_hash = False
        for _ in range(12):
            reject = node1.submitblock(self._tampered_candidate(node0))
            assert reject in {"high-hash", "duplicate-invalid"}
            saw_high_hash = saw_high_hash or (reject == "high-hash")
            assert_equal(node1.getbestblockhash(), tip_hash)
        assert saw_high_hash

        # Regtest remains in soft-fail mode (no persistent bans).
        assert_equal(node0.listbanned(), [])
        assert_equal(node1.listbanned(), [])
        assert node0.getconnectioncount() > 0
        assert node1.getconnectioncount() > 0


if __name__ == "__main__":
    BTXMatMulDosMitigationTest(__file__).main()
