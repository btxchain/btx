#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""Regtest rehearsal for the BTX MatMul v4 hard-fork boundary.

Mines across the height-gated v4 activation (design spec section G.1) and
asserts:
  * pre-fork blocks validate under the v3 rules (transcript/full-C path,
    v3 dimension) on an independently-validating peer;
  * post-fork blocks validate under the v4 rules (sketch-committed digest,
    v4 dimension) on the same peer;
  * a v4 block whose sketch payload bytes are corrupted is rejected and
    does not move the tip, while the uncorrupted original is accepted.

Node configuration relies on the v4 regtest override args following the
established ``-regtestmatmul*`` convention in src/chainparamsbase.cpp:
  -regtestmatmulv4height=<n>     v4 activation height (spec G.2, regtest 100)
  -regtestmatmulv4dimension=<n>  v4 matrix dimension n (regtest default 256)
This test lowers the activation height so both fork sides are exercised,
and selects a distinct v4 dimension so the fork boundary is observable in
block RPC output (matmul_dim changes at the boundary).
"""

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal

# Heights/dimensions chosen for CI speed: v3 regtest dimension is 64; the
# v4 dimension is set to 128 (b = 4 -> m = 128/4 = 32, sketch payload 8 KiB)
# so the per-nonce GEMM stays trivial on CPU regtest miners (which now run
# the v4.1 batched-sketch solve loop, spec §K.2b).
V4_ACTIVATION_HEIGHT = 8
V3_DIMENSION = 64
V4_DIMENSION = 128
V3_BINDING_HEIGHT = 3

# Hex complement table used to corrupt payload bytes deterministically.
HEX_COMPLEMENT = str.maketrans("0123456789abcdef", "fedcba9876543210")


class BTXMatMulV4Activation(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 2
        self.setup_clean_chain = True
        common = [
            "-test=matmuldgw",
            f"-regtestmatmulbindingheight={V3_BINDING_HEIGHT}",
            f"-regtestmatmulproductdigestheight={V3_BINDING_HEIGHT}",
            "-regtestmatmulrequireproductpayload=0",
            f"-regtestmatmulv4height={V4_ACTIVATION_HEIGHT}",
            f"-regtestmatmulv4dimension={V4_DIMENSION}",
        ]
        self.extra_args = [common, common]

    def run_test(self):
        node0, node1 = self.nodes

        # Make sure the pair is connected before relying on sync waits
        # (mirrors feature_btx_matmul_consensus.py under parallel CI load).
        self.connect_nodes(0, 1)
        self.wait_until(
            lambda: node0.getconnectioncount() >= 1 and node1.getconnectioncount() >= 1,
            timeout=120,
        )

        self.log.info("Mine the pre-fork (v3) segment and sync the peer")
        pre_fork_height = V4_ACTIVATION_HEIGHT - 1
        self.generate(node0, pre_fork_height, sync_fun=self.no_op)
        self.wait_until(
            lambda: node1.getblockcount() == pre_fork_height
            and node1.getbestblockhash() == node0.getbestblockhash(),
            timeout=180,
        )

        self.log.info("Pre-fork blocks carry v3 semantics")
        for height in range(1, pre_fork_height + 1):
            block = node1.getblock(node1.getblockhash(height), 2)
            assert_equal(block["height"], height)
            # v3 dimension throughout the pre-fork segment.
            assert_equal(block["matmul_dim"], V3_DIMENSION)
            if height < V3_BINDING_HEIGHT:
                # Before the v3 transcript-binding height no product payload
                # is required on this permissive-regtest configuration.
                assert "matrix_c_words" not in block
            else:
                # Bound v3 blocks ship the full product matrix: n*n words.
                assert_equal(block["matrix_c_words"], V3_DIMENSION * V3_DIMENSION)

        tip_hash = node1.getbestblockhash()

        self.log.info("Build the first v4 block without submitting it")
        candidate = node0.generateblock("raw(51)", [], False, called_by_framework=True)
        good_hex = candidate["hex"]

        self.log.info("A v4 block with a corrupted sketch payload is rejected")
        # The MatMul proof payload is the trailing serialized region of a
        # BTX block; complementing the final bytes corrupts sketch payload
        # words without touching the 182-byte header or the transactions.
        tail = 16
        bad_hex = good_hex[:-tail] + good_hex[-tail:].translate(HEX_COMPLEMENT)
        assert bad_hex != good_hex
        result = node1.submitblock(bad_hex)
        assert result is not None, "corrupted v4 sketch payload must be rejected"
        self.log.info(f"corrupted-payload reject reason: {result}")
        assert_equal(node1.getbestblockhash(), tip_hash)
        assert_equal(node1.getblockcount(), pre_fork_height)

        self.log.info("The same block with its honest sketch payload is accepted")
        assert_equal(node1.submitblock(good_hex), None)
        self.wait_until(
            lambda: node0.getbestblockhash() == node1.getbestblockhash(),
            timeout=180,
        )
        assert_equal(node1.getblockcount(), V4_ACTIVATION_HEIGHT)

        self.log.info("The activation block validates under v4 rules")
        v4_block = node1.getblock(node1.getbestblockhash(), 2)
        assert_equal(v4_block["height"], V4_ACTIVATION_HEIGHT)
        assert_equal(v4_block["matmul_dim"], V4_DIMENSION)
        if "matrix_c_words" in v4_block:
            # v4 ships the compressed sketch, never the full n*n product
            # (spec sections 0.7-(3) and E.1).
            assert v4_block["matrix_c_words"] != V4_DIMENSION * V4_DIMENSION

        self.log.info("Post-fork blocks continue to validate under v4 on both nodes")
        self.generate(node0, 2, sync_fun=self.no_op)
        self.wait_until(
            lambda: node1.getblockcount() == V4_ACTIVATION_HEIGHT + 2
            and node1.getbestblockhash() == node0.getbestblockhash(),
            timeout=180,
        )
        for height in range(V4_ACTIVATION_HEIGHT, V4_ACTIVATION_HEIGHT + 3):
            block = node1.getblock(node1.getblockhash(height), 2)
            assert_equal(block["matmul_dim"], V4_DIMENSION)

        self.log.info("Pre-fork history remains v3 after activation")
        boundary_parent = node1.getblock(node1.getblockhash(pre_fork_height), 2)
        assert_equal(boundary_parent["matmul_dim"], V3_DIMENSION)


if __name__ == "__main__":
    BTXMatMulV4Activation(__file__).main()
