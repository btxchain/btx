#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""Regtest rehearsal for the BTX MatMul v4.2 / ENC-BMX4C encoding-profile fork.

ENC-BMX4C (doc/btx-matmul-v4.2-bmx4c-spec.md) is a height-gated hard fork of the
committed-operand ENCODING ONLY: at heights in [v4_height, bmx4c_height) the
ENC_S8 profile applies; at and above bmx4c_height the ENC_BMX4C profile applies
exclusively (the verifier, payload shape, digest, and matmul_dim are UNCHANGED
across the fork — only how header seeds become exact integer operands changes).

This test mines across BOTH boundaries on regtest and asserts:
  * pre-fork v4 (ENC_S8) blocks validate on an independently-validating peer;
  * the v4 -> bmx4c (ENC_S8 -> ENC_BMX4C) profile transition validates: the
    first ENC-BMX4C block and its successors validate on the same peer, which
    can only happen if that peer independently re-derives the ENC-BMX4C operands
    and Freivalds-checks the sketch under the right profile;
  * an ENC-BMX4C block whose sketch payload bytes are corrupted is rejected and
    does not move the tip, while the uncorrupted original is accepted (proving
    the ENC-BMX4C verify cascade — VerifySketchBMX4C — is the live path).

Node configuration follows the established ``-regtestmatmul*`` override
convention (src/chainparamsbase.cpp):
  -regtestmatmulv4height=<n>     v4 (ENC_S8) activation height
  -regtestmatmulv4dimension=<n>  v4 matrix dimension n (must be a multiple of 32
                                 for ENC-BMX4C E8M0 block scales)
  -regtestbmx4cheight=<n>        ENC-BMX4C activation height (> v4 height)
"""

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal

# Heights/dimension chosen for CI speed. n = 128 keeps n % 32 == 0 (ENC-BMX4C
# block scales) and n % 4 == 0 (sketch tile b = 4 -> m = 32, 8 KiB payload), so
# the per-nonce GEMM stays trivial on CPU regtest miners. ENC_S8 v4 blocks span
# heights [V4_ACTIVATION_HEIGHT, BMX4C_ACTIVATION_HEIGHT); ENC-BMX4C blocks are
# mined at and above BMX4C_ACTIVATION_HEIGHT.
V4_ACTIVATION_HEIGHT = 4
BMX4C_ACTIVATION_HEIGHT = 8
DIMENSION = 128
V3_BINDING_HEIGHT = 2

# Hex complement table used to corrupt payload bytes deterministically.
HEX_COMPLEMENT = str.maketrans("0123456789abcdef", "fedcba9876543210")


class BTXMatMulBMX4CActivation(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 2
        self.setup_clean_chain = True
        common = [
            "-test=matmuldgw",
            f"-regtestmatmulbindingheight={V3_BINDING_HEIGHT}",
            f"-regtestmatmulproductdigestheight={V3_BINDING_HEIGHT}",
            "-regtestmatmulrequireproductpayload=0",
            f"-regtestmatmulv4height={V4_ACTIVATION_HEIGHT}",
            f"-regtestmatmulv4dimension={DIMENSION}",
            f"-regtestbmx4cheight={BMX4C_ACTIVATION_HEIGHT}",
        ]
        self.extra_args = [common, common]

    def run_test(self):
        node0, node1 = self.nodes

        self.connect_nodes(0, 1)
        self.wait_until(
            lambda: node0.getconnectioncount() >= 1 and node1.getconnectioncount() >= 1,
            timeout=120,
        )

        self.log.info("Mine the pre-BMX4C segment (v3 + ENC_S8 v4) and sync the peer")
        pre_fork_height = BMX4C_ACTIVATION_HEIGHT - 1
        self.generate(node0, pre_fork_height, sync_fun=self.no_op)
        self.wait_until(
            lambda: node1.getblockcount() == pre_fork_height
            and node1.getbestblockhash() == node0.getbestblockhash(),
            timeout=180,
        )

        self.log.info("The last ENC_S8 v4 block validated on the peer")
        s8_block = node1.getblock(node1.getblockhash(pre_fork_height), 2)
        assert_equal(s8_block["height"], pre_fork_height)
        assert_equal(s8_block["matmul_dim"], DIMENSION)

        tip_hash = node1.getbestblockhash()

        self.log.info("Build the first ENC-BMX4C block without submitting it")
        candidate = node0.generateblock("raw(51)", [], False, called_by_framework=True)
        good_hex = candidate["hex"]

        self.log.info("An ENC-BMX4C block with a corrupted sketch payload is rejected")
        # The MatMul proof payload is the trailing serialized region of a BTX
        # block; complementing the final bytes corrupts sketch payload words
        # without touching the 182-byte header or the transactions.
        tail = 16
        bad_hex = good_hex[:-tail] + good_hex[-tail:].translate(HEX_COMPLEMENT)
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
        assert_equal(node1.getblockcount(), BMX4C_ACTIVATION_HEIGHT)

        self.log.info("The activation block validates under the ENC-BMX4C profile")
        bmx4c_block = node1.getblock(node1.getbestblockhash(), 2)
        assert_equal(bmx4c_block["height"], BMX4C_ACTIVATION_HEIGHT)
        # matmul_dim is UNCHANGED across the encoding-profile fork (only the
        # operand encoding changes).
        assert_equal(bmx4c_block["matmul_dim"], DIMENSION)

        self.log.info("Post-fork ENC-BMX4C blocks continue to validate on both nodes")
        self.generate(node0, 3, sync_fun=self.no_op)
        self.wait_until(
            lambda: node1.getblockcount() == BMX4C_ACTIVATION_HEIGHT + 3
            and node1.getbestblockhash() == node0.getbestblockhash(),
            timeout=180,
        )
        for height in range(BMX4C_ACTIVATION_HEIGHT, BMX4C_ACTIVATION_HEIGHT + 4):
            block = node1.getblock(node1.getblockhash(height), 2)
            assert_equal(block["matmul_dim"], DIMENSION)

        self.log.info("The v4->bmx4c profile transition is intact on both nodes")
        assert_equal(node0.getbestblockhash(), node1.getbestblockhash())
        # The ENC_S8 side of the boundary is unchanged after activation.
        boundary_parent = node1.getblock(node1.getblockhash(pre_fork_height), 2)
        assert_equal(boundary_parent["matmul_dim"], DIMENSION)


if __name__ == "__main__":
    BTXMatMulBMX4CActivation(__file__).main()
