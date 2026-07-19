#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""Regtest rehearsal for the BTX MatMul v4.4-LT Rank-1 / ENC-DR-LT encoding-profile fork.

LT is a further deepening staged strictly AT OR AFTER the v4.2 ENC-BMX4C fork.
It remains inert on public networks until an activation height is selected;
regtest deliberately activates it by default for coverage, and this rehearsal
overrides that height and selects Phase A to exercise both sides of the profile
boundary without turning the activation test into a Q*-seal workload test
(Consensus::Params::IsDRLTActive requires IsBMX4CActive;
AssertBMX4CConstructionInvariants enforces nMatMulDRLTHeight >=
nMatMulBMX4CHeight whenever DRLT is configured live). This test stages the two
forks at DIFFERENT heights (unlike the unified v3->ENC-BMX4C flag day) so the
[bmx4c_height, drlt_height) window exercises ENC-BMX4C and [drlt_height, inf)
exercises ENC-BMX4C-LT, both on the SAME v4 dimension (LT changes the operand
encoding/tile/commitment shape only -- deep-m under ENC-DR is a storage-free
parameter retarget, not a dimension or carriage change on the wire).

This test mines across both boundaries on regtest and asserts:
  * before the ENC-BMX4C fork, getmatmulchallenge advertises no encoding_profile
    (the field only appears once v4 is active);
  * in [bmx4c_height, drlt_height), getmatmulchallenge advertises "ENC-BMX4C";
  * at and above drlt_height, getmatmulchallenge advertises "ENC-BMX4C-LT" and
    mined blocks validate on an independently-validating peer -- which can only
    happen if that peer independently re-derives the Rank-1 MatExpand/deep-m
    operands and recomputes the ENC-DR digest under the LT profile (pow.cpp's
    ENC_BMX4C_LT dispatch to the LT digest reference);
  * every LT block still carries the ENC-DR digest-only carriage (empty
    matrix_c_data / no matrix_c_words), exactly like ENC-BMX4C's DIGEST_RECOMPUTE
    default -- LT never reintroduces an in-block sketch payload;
  * mining continues to make progress (tip advances, both nodes agree) after
    activation.

Node configuration follows the established ``-regtestmatmul*`` override
convention (src/chainparamsbase.cpp):
  -regtestmatmulv4height=<H>      v4 / ENC-BMX4C unified activation height
  -regtestmatmulv4dimension=<n>   v4 matrix dimension n
  -regtestbmx4cheight=<H>         ENC-BMX4C activation height (== v4 height)
  -regtestdrltheight=<H2>         ENC-DR-LT activation height (H2 >= H)
  -regtestmatmulltsealaspow=0     keep this profile-transition test in Phase A

If a future refactor ever removes the -regtestdrltheight override, this test
skips outright rather than failing, since LT staying permanently unreachable
without a regtest knob is a valid (if less testable) scaffolding state.
"""

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal

# n=128 keeps n % 32 == 0 (ENC-BMX4C E8M0 block scales), n % 4 == 0 (ENC-BMX4C
# tile b=4 -> m=32), and n % 2 == 0 (ENC-DR-LT deep-m tile b=2 -> m=64), so the
# per-nonce GEMM stays trivial on CPU regtest miners under either profile.
V4_DIMENSION = 128
V3_BINDING_HEIGHT = 2
BMX4C_HEIGHT = 6
# Staged strictly after BMX4C so [BMX4C_HEIGHT, DRLT_HEIGHT) exercises
# ENC-BMX4C on its own before LT supersedes it.
DRLT_HEIGHT = BMX4C_HEIGHT + 3


class BTXMatMulDRLTActivation(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 2
        self.setup_clean_chain = True
        common = [
            # Do not let regtest's default fSkipMatMulValidation turn this into
            # a version/profile-only sync test. The receiving peer must execute
            # the same strict header/dimension/digest checks as production.
            "-test=matmulstrict",
            "-test=matmuldgw",
            f"-regtestmatmulbindingheight={V3_BINDING_HEIGHT}",
            f"-regtestmatmulproductdigestheight={V3_BINDING_HEIGHT}",
            "-regtestmatmulrequireproductpayload=0",
            f"-regtestmatmulv4height={BMX4C_HEIGHT}",
            f"-regtestmatmulv4dimension={V4_DIMENSION}",
            f"-regtestbmx4cheight={BMX4C_HEIGHT}",
            f"-regtestdrltheight={DRLT_HEIGHT}",
            "-regtestmatmulltsealaspow=0",
        ]
        self.extra_args = [common, common]

    def run_test(self):
        node0, node1 = self.nodes

        joined = " ".join(self.extra_args[0])
        if "-regtestdrltheight" not in joined or "-test=matmulstrict" not in joined:
            raise AssertionError("test setup error: strict DRLT rehearsal flags missing")

        self.connect_nodes(0, 1)
        self.wait_until(
            lambda: node0.getconnectioncount() >= 1 and node1.getconnectioncount() >= 1,
            timeout=120,
        )

        self.log.info("Pre-fork: getmatmulchallenge advertises no v4 encoding_profile yet")
        challenge = node0.getmatmulchallenge()
        assert "encoding_profile" not in challenge["matmul"]

        self.log.info(f"Mine up to the ENC-BMX4C activation height {BMX4C_HEIGHT}")
        self.generate(node0, BMX4C_HEIGHT, sync_fun=self.no_op)
        self.wait_until(
            lambda: node1.getblockcount() == BMX4C_HEIGHT
            and node1.getbestblockhash() == node0.getbestblockhash(),
            timeout=180,
        )

        self.log.info("Between the BMX4C and DRLT forks, the profile is ENC-BMX4C")
        challenge = node0.getmatmulchallenge()
        assert_equal(challenge["height"], BMX4C_HEIGHT + 1)
        assert_equal(challenge["matmul"]["encoding_profile"], "ENC-BMX4C")
        bmx4c_block = node1.getblock(node1.getbestblockhash(), 2)
        assert_equal(bmx4c_block["height"], BMX4C_HEIGHT)
        assert_equal(bmx4c_block["matmul_dim"], V4_DIMENSION)

        self.log.info(f"Mine up to one block short of the ENC-DR-LT activation height {DRLT_HEIGHT}")
        self.generate(node0, DRLT_HEIGHT - 2 - BMX4C_HEIGHT, sync_fun=self.no_op)
        self.wait_until(
            lambda: node1.getblockcount() == DRLT_HEIGHT - 2
            and node1.getbestblockhash() == node0.getbestblockhash(),
            timeout=180,
        )
        challenge = node0.getmatmulchallenge()
        assert_equal(challenge["height"], DRLT_HEIGHT - 1)
        assert_equal(challenge["matmul"]["encoding_profile"], "ENC-BMX4C")

        self.log.info(f"Mine the last pre-LT ENC-BMX4C block {DRLT_HEIGHT - 1}")
        self.generate(node0, 1, sync_fun=self.no_op)
        self.wait_until(
            lambda: node1.getblockcount() == DRLT_HEIGHT - 1
            and node1.getbestblockhash() == node0.getbestblockhash(),
            timeout=180,
        )
        pre_lt_block = node1.getblock(node1.getbestblockhash(), 2)
        assert_equal(pre_lt_block["height"], DRLT_HEIGHT - 1)
        assert_equal(pre_lt_block["matmul_dim"], V4_DIMENSION)
        challenge = node0.getmatmulchallenge()
        assert_equal(challenge["height"], DRLT_HEIGHT)
        assert_equal(challenge["matmul"]["encoding_profile"], "ENC-BMX4C-LT")
        assert_equal(challenge["matmul"]["b"], 2)
        assert_equal(challenge["matmul"]["consensus_q_star"], 256)
        assert_equal(challenge["matmul"]["lt_transcript_block_size"], 2)

        self.log.info(f"Mine the ENC-DR-LT activation block {DRLT_HEIGHT} and sync the peer")
        self.generate(node0, 1, sync_fun=self.no_op)
        self.wait_until(
            lambda: node1.getblockcount() == DRLT_HEIGHT
            and node1.getbestblockhash() == node0.getbestblockhash(),
            timeout=180,
        )

        self.log.info("The activation block validates on the peer under the ENC-BMX4C-LT profile")
        drlt_block = node1.getblock(node1.getbestblockhash(), 2)
        assert_equal(drlt_block["height"], DRLT_HEIGHT)
        assert_equal(drlt_block["matmul_dim"], V4_DIMENSION)
        # v4.4 ENC-DR digest-only carriage: LT never reintroduces an in-block
        # sketch payload (matrix_c_data stays empty; matrix_c_words is omitted).
        assert "matrix_c_words" not in drlt_block
        challenge = node1.getmatmulchallenge()
        assert_equal(challenge["matmul"]["encoding_profile"], "ENC-BMX4C-LT")

        self.log.info("Post-fork: ENC-BMX4C-LT blocks continue to validate on both nodes (mining still works)")
        self.generate(node0, 3, sync_fun=self.no_op)
        self.wait_until(
            lambda: node1.getblockcount() == DRLT_HEIGHT + 3
            and node1.getbestblockhash() == node0.getbestblockhash(),
            timeout=180,
        )
        for height in range(DRLT_HEIGHT, DRLT_HEIGHT + 4):
            block = node1.getblock(node1.getblockhash(height), 2)
            assert_equal(block["matmul_dim"], V4_DIMENSION)
            assert "matrix_c_words" not in block

        self.log.info("The BMX4C -> ENC-DR-LT staged transition is intact on both nodes")
        assert_equal(node0.getbestblockhash(), node1.getbestblockhash())
        # The ENC-BMX4C side of the boundary is unchanged after LT activation.
        boundary_block = node1.getblock(node1.getblockhash(DRLT_HEIGHT - 1), 2)
        assert_equal(boundary_block["matmul_dim"], V4_DIMENSION)


if __name__ == "__main__":
    BTXMatMulDRLTActivation(__file__).main()
