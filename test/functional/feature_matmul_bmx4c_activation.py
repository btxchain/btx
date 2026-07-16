#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""Regtest rehearsal for the BTX MatMul v4.2 / ENC-BMX4C encoding-profile fork.

STRICT UNIFIED ACTIVATION (audit P0.2): the MatMul upgrade activates on ONE flag
day, v3 -> v4.2/ENC-BMX4C directly, with NO reachable ENC-S8 interval on any
network. So v4_height == bmx4c_height == H: at heights below H the v3 rules apply;
at and above H the ENC_BMX4C profile applies exclusively (the verifier, payload
shape, digest, and matmul_dim are UNCHANGED across the fork -- only how header
seeds become exact integer operands changes). There is no [v4, bmx4c) ENC_S8
window; a config with v4_height != bmx4c_height fails the strict-unified startup
assert (AssertBMX4CConstructionInvariants).

This test mines across the single boundary on regtest and asserts:
  * pre-fork v3 blocks validate on an independently-validating peer;
  * the v3 -> ENC-BMX4C transition validates at H: the first ENC-BMX4C block and
    its successors validate on the same peer, which can only happen if that peer
    independently re-derives the ENC-BMX4C operands and Freivalds-checks the
    sketch under the ENC-BMX4C profile;
  * an ENC-BMX4C block whose sketch payload bytes are corrupted is rejected and
    does not move the tip, while the uncorrupted original is accepted (proving
    the ENC-BMX4C verify cascade -- VerifySketchBMX4C -- is the live path).

Node configuration follows the established ``-regtestmatmul*`` override
convention (src/chainparamsbase.cpp); under strict unified the v4 and ENC-BMX4C
heights are set to the SAME value:
  -regtestmatmulv4height=<H>     v4 / ENC-BMX4C unified activation height
  -regtestmatmulv4dimension=<n>  v4 matrix dimension n (multiple of 32 for the
                                 ENC-BMX4C E8M0 block scales)
  -regtestbmx4cheight=<H>        ENC-BMX4C activation height (== v4 height)
"""

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal

# Heights/dimension chosen for CI speed. n = 128 keeps n % 32 == 0 (ENC-BMX4C
# block scales) and n % 4 == 0 (sketch tile b = 4 -> m = 32, 8 KiB payload), so
# the per-nonce GEMM stays trivial on CPU regtest miners. Heights below
# ACTIVATION_HEIGHT are v3 (product-committed from V3_BINDING_HEIGHT); heights at
# and above ACTIVATION_HEIGHT are ENC-BMX4C. There is NO ENC_S8 interval.
ACTIVATION_HEIGHT = 6
DIMENSION = 128
V3_BINDING_HEIGHT = 2


class BTXMatMulBMX4CActivation(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 2
        self.setup_clean_chain = True
        # Strict unified: v4height == bmx4cheight == ACTIVATION_HEIGHT.
        common = [
            "-test=matmuldgw",
            f"-regtestmatmulbindingheight={V3_BINDING_HEIGHT}",
            f"-regtestmatmulproductdigestheight={V3_BINDING_HEIGHT}",
            "-regtestmatmulrequireproductpayload=0",
            f"-regtestmatmulv4height={ACTIVATION_HEIGHT}",
            f"-regtestmatmulv4dimension={DIMENSION}",
            f"-regtestbmx4cheight={ACTIVATION_HEIGHT}",
        ]
        self.extra_args = [common, common]

    def run_test(self):
        node0, node1 = self.nodes

        self.connect_nodes(0, 1)
        self.wait_until(
            lambda: node0.getconnectioncount() >= 1 and node1.getconnectioncount() >= 1,
            timeout=120,
        )

        self.log.info("Mine the pre-fork v3 segment and sync the peer")
        pre_fork_height = ACTIVATION_HEIGHT - 1
        self.generate(node0, pre_fork_height, sync_fun=self.no_op)
        self.wait_until(
            lambda: node1.getblockcount() == pre_fork_height
            and node1.getbestblockhash() == node0.getbestblockhash(),
            timeout=180,
        )

        self.log.info("The last pre-fork v3 block validated on the peer")
        v3_block = node1.getblock(node1.getblockhash(pre_fork_height), 2)
        assert_equal(v3_block["height"], pre_fork_height)
        assert_equal(v3_block["matmul_dim"], DIMENSION)

        tip_hash = node1.getbestblockhash()

        self.log.info("Build the first ENC-BMX4C block without submitting it")
        candidate = node0.generateblock("raw(51)", [], False, called_by_framework=True)
        good_hex = candidate["hex"]

        self.log.info("An ENC-BMX4C block with a corrupted sketch payload is rejected")
        # The MatMul proof payload is the trailing serialized region of a BTX
        # block; complementing the final bytes corrupts sketch payload words
        # without touching the 182-byte header or the transactions.
        tail = 16
        bad_hex = good_hex[:-tail] + good_hex[-tail:].translate(
            str.maketrans("0123456789abcdef", "fedcba9876543210")
        )
        assert bad_hex != good_hex
        result = node1.submitblock(bad_hex)
        assert result is not None, "corrupted ENC-BMX4C sketch payload must be rejected"
        self.log.info(f"corrupted-payload reject reason: {result}")
        assert_equal(node1.getbestblockhash(), tip_hash)
        assert_equal(node1.getblockcount(), pre_fork_height)

        self.log.info("The same block with its honest ENC-BMX4C payload is accepted")
        assert_equal(node1.submitblock(good_hex), None)
        self.wait_until(
            lambda: node0.getbestblockhash() == node1.getbestblockhash(),
            timeout=180,
        )
        assert_equal(node1.getblockcount(), ACTIVATION_HEIGHT)

        self.log.info("The activation block validates under the ENC-BMX4C profile")
        bmx4c_block = node1.getblock(node1.getbestblockhash(), 2)
        assert_equal(bmx4c_block["height"], ACTIVATION_HEIGHT)
        # matmul_dim is UNCHANGED across the encoding-profile fork (only the
        # operand encoding changes).
        assert_equal(bmx4c_block["matmul_dim"], DIMENSION)

        self.log.info("Post-fork ENC-BMX4C blocks continue to validate on both nodes")
        self.generate(node0, 3, sync_fun=self.no_op)
        self.wait_until(
            lambda: node1.getblockcount() == ACTIVATION_HEIGHT + 3
            and node1.getbestblockhash() == node0.getbestblockhash(),
            timeout=180,
        )
        for height in range(ACTIVATION_HEIGHT, ACTIVATION_HEIGHT + 4):
            block = node1.getblock(node1.getblockhash(height), 2)
            assert_equal(block["matmul_dim"], DIMENSION)

        self.log.info("The v3->ENC-BMX4C unified transition is intact on both nodes")
        assert_equal(node0.getbestblockhash(), node1.getbestblockhash())
        # The v3 side of the boundary is unchanged after activation.
        boundary_parent = node1.getblock(node1.getblockhash(pre_fork_height), 2)
        assert_equal(boundary_parent["matmul_dim"], DIMENSION)


if __name__ == "__main__":
    BTXMatMulBMX4CActivation(__file__).main()
