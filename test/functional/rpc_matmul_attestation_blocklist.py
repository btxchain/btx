#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""The attestation blocklist covers ML-DSA-44 pin members.

-matmulattestationblocklist and addmatmulattestationblocklist take an
ML-DSA-44 (-matmultrustedpqpubkey) pin member as well as a compressed
secp256k1 key. listmatmulattestationblocklist and
addmatmulattestationblocklist report it under blocked_pq_pubkeys. A startup
block lasts while the flag is set; a runtime block persists across restart,
and a persisted block that leaves fewer than M unblocked pin members
refuses start. The framework runs every node with -rpcdoccheck=1, so the
results are also checked against the RPC result documentation."""

from test_framework.test_framework import BitcoinTestFramework
from test_framework.test_node import ErrorMatch
from test_framework.util import assert_equal, assert_raises_rpc_error
from test_framework.wallet_util import generate_keypair

# -matmultrustedpqpubkey only checks the 1312-byte ML-DSA-44 size.
PQ_PUBKEY = bytes(i % 256 for i in range(1312)).hex()


class MatMulAttestationBlocklistTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True

    def run_test(self):
        node = self.nodes[0]
        _, pub_a = generate_keypair(wif=True)
        _, pub_b = generate_keypair(wif=True)
        pub_a, pub_b = pub_a.hex(), pub_b.hex()

        def pin(threshold=2):
            # 2 secp256k1 + 1 ML-DSA-44 pin members, M of 3.
            return [
                "-matmulvalidation=consensus",
                "-matmulattestationserve=0",
                f"-matmultrustedpubkey={pub_a}",
                f"-matmultrustedpubkey={pub_b}",
                f"-matmultrustedpqpubkey={PQ_PUBKEY}",
                f"-matmultrustedthreshold={threshold}",
            ]

        self.log.info("-matmulattestationblocklist takes an ML-DSA-44 pin member")
        self.restart_node(0, extra_args=pin() + [
            f"-matmulattestationblocklist={PQ_PUBKEY}"])
        listed = node.listmatmulattestationblocklist()
        assert_equal(listed["blocked_pubkeys"], [])
        assert_equal(listed["blocked_pq_pubkeys"], [PQ_PUBKEY])
        assert_equal(listed["unblocked_pin_members"], 2)
        assert_equal(listed["threshold"], 2)
        assert_equal(listed["pin_quorum_reachable"], True)
        assert_equal(node.getmatmultrustedstatus()["unblocked_pin_members"], 2)

        self.log.info("A startup block ends when the flag is removed")
        self.restart_node(0, extra_args=pin())
        listed = node.listmatmulattestationblocklist()
        assert_equal(listed["blocked_pq_pubkeys"], [])
        assert_equal(listed["unblocked_pin_members"], 3)

        self.log.info("addmatmulattestationblocklist blocks an ML-DSA-44 pin member")
        added = node.addmatmulattestationblocklist(PQ_PUBKEY)
        assert_equal(added["added"], True)
        assert_equal(added["result"], "blocked")
        assert_equal(added["blocked_pubkeys"], [])
        assert_equal(added["blocked_pq_pubkeys"], [PQ_PUBKEY])
        assert_equal(added["unblocked_pin_members"], 2)
        assert_equal(added["persisted"], True)
        assert "persist_error" not in added
        assert_equal(node.addmatmulattestationblocklist(PQ_PUBKEY)["result"],
                     "duplicate")
        assert_raises_rpc_error(-8, "would-disable-pin-quorum",
                                node.addmatmulattestationblocklist, pub_a)
        assert_raises_rpc_error(-5, "ML-DSA-44",
                                node.addmatmulattestationblocklist,
                                PQ_PUBKEY[:-2])

        self.log.info("A runtime block persists across restart")
        self.restart_node(0, extra_args=pin())
        listed = node.listmatmulattestationblocklist()
        assert_equal(listed["blocked_pq_pubkeys"], [PQ_PUBKEY])
        assert_equal(listed["unblocked_pin_members"], 2)
        assert_equal(listed["persisted"], True)

        self.log.info("A persisted block that leaves fewer than M unblocked members refuses start")
        self.stop_node(0)
        node.assert_start_raises_init_error(
            extra_args=pin(threshold=3),
            expected_msg=r"Error: .*persisted attestation PQ blocklist leaves fewer than M",
            match=ErrorMatch.PARTIAL_REGEX)
        self.start_node(0, extra_args=pin())
        assert_equal(node.listmatmulattestationblocklist()["blocked_pq_pubkeys"],
                     [PQ_PUBKEY])


if __name__ == "__main__":
    MatMulAttestationBlocklistTest(__file__).main()
