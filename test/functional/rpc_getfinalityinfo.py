#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""getfinalityinfo returns only keys its RPCResult documents.

The framework starts nodes with -rpcdoccheck=1, so an undocumented key
makes the call fail. trusted_pq_signer_pubkeys must list the configured
ML-DSA-44 pin, as getmatmultrustedstatus does."""

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal

# -matmultrustedpqpubkey only checks the 1312-byte ML-DSA-44 size.
PQ_PUBKEY = bytes(i % 256 for i in range(1312)).hex()


class GetFinalityInfoTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True

    def run_test(self):
        node = self.nodes[0]

        self.log.info("No pin: every returned key is documented")
        info = node.getfinalityinfo()
        assert_equal(info["trusted_signer_pubkeys"], [])
        assert_equal(info["trusted_pq_signer_pubkeys"], [])

        self.log.info("ML-DSA-44 pin member is listed")
        self.restart_node(0, extra_args=[
            f"-matmultrustedpqpubkey={PQ_PUBKEY}",
            "-matmultrustedthreshold=1",
        ])
        info = node.getfinalityinfo()
        assert_equal(info["trusted_pq_signer_pubkeys"], [PQ_PUBKEY])
        assert_equal(
            info["trusted_pq_signer_pubkeys"],
            node.getmatmultrustedstatus()["trusted_pq_signer_pubkeys"])


if __name__ == "__main__":
    GetFinalityInfoTest(__file__).main()
