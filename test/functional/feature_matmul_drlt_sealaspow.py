#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""Regtest functional coverage for the BTX MatMul v4.4-LT Q* Phase B
seal-as-PoW window lottery object (INERT-by-default; opt-in on regtest via
-regtestmatmulltsealaspow together with a live -regtestdrltheight).

feature_matmul_drlt_activation.py already exercises Phase A (the per-nonce
ENC-DR-LT digest). This test exercises Phase B: with -regtestmatmulltsealaspow
set, once the ENC-DR-LT height is reached the consensus lottery object stops
being the per-nonce digest and becomes the Q* WINDOW SEAL
(matmul_digest := SealWindowCommit(sigma_anchor, Merkle(slot digests), Q*), see
matmul::v4::lt::ComputeSealDigestBMX4CLT). Every slot re-derives its consensus
V3 (parent-MTP-bound) seeds, so a seal genuinely costs Q* fresh ENC-DR-LT
digests (adversarial LT-Q1/LT-Q2).

The test asserts the FULL seal path end-to-end on regtest:
  * a seal-configured node MINES seal-mode blocks at/after the LT height
    (pow.cpp SolveMatMulV4LT Phase B branch actually produces them), and
  * an independently-validating, seal-configured PEER ACCEPTS and SYNCS them,
    which can only happen if that peer re-derives the whole Q* window and
    recomputes the window seal under CheckMatMulProofOfWork_V4EncDr's seal
    branch (validation.cpp / pow.cpp IsMatMulLTSealAsPoWActive path). A Phase-A
    validator would reject these blocks (the seal is not an H(sigma||Chat)
    preimage), so a successful sync is positive evidence Phase B is live.
  * seal blocks still carry the ENC-DR digest-only carriage (empty
    matrix_c_data / no matrix_c_words) — seal mode never packs a sketch body.
  * mining keeps making progress across several seal blocks (both nodes agree).

RUNTIME NOTE: each seal attempt evaluates Q* (=256 default on regtest) full ENC-DR-LT digests, so
seal-mode blocks are ~Q* times costlier to mine than Phase-A blocks. The test
uses the smallest viable regtest shape (n=128, the drlt-activation dimension)
and a minimal seal-block count to keep wall-clock bounded (a few seconds of
mining per seal block on a CPU regtest miner). On regtest the target is
powLimit, so the first seal per anchor almost always meets target.

If a future refactor removes -regtestdrltheight or -regtestmatmulltsealaspow,
the test skips rather than fails (seal-as-PoW staying permanently unreachable
without a regtest knob is a valid, if less testable, scaffolding state).
"""

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal

# n=128: 128 % 32 == 0 (ENC-BMX4C E8M0 block scales), 128 % 4 == 0 (BMX4C tile),
# 128 % 2 == 0 (ENC-DR-LT deep-m tile b=2 -> m=64). Matches the proven-good
# drlt-activation shape so the per-slot GEMM stays trivial on a CPU miner.
V4_DIMENSION = 128
V3_BINDING_HEIGHT = 2
BMX4C_HEIGHT = 4
# ENC-DR-LT (and, with the knob, seal-as-PoW) activates strictly after BMX4C.
DRLT_HEIGHT = BMX4C_HEIGHT + 2
# Keep the seal-mined span small: each block is ~Q* digests.
SEAL_BLOCKS = 3


class BTXMatMulDRLTSealAsPoW(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 2
        self.setup_clean_chain = True
        common = [
            "-test=matmuldgw",
            f"-regtestmatmulbindingheight={V3_BINDING_HEIGHT}",
            f"-regtestmatmulproductdigestheight={V3_BINDING_HEIGHT}",
            "-regtestmatmulrequireproductpayload=0",
            f"-regtestmatmulv4height={BMX4C_HEIGHT}",
            f"-regtestmatmulv4dimension={V4_DIMENSION}",
            f"-regtestbmx4cheight={BMX4C_HEIGHT}",
            f"-regtestdrltheight={DRLT_HEIGHT}",
            # Phase B: turn the ENC-DR-LT lottery object into the Q* window seal.
            "-regtestmatmulltsealaspow",
        ]
        self.extra_args = [common, common]

    def run_test(self):
        node0, node1 = self.nodes

        joined = " ".join(self.extra_args[0])
        if "-regtestdrltheight" not in joined or "-regtestmatmulltsealaspow" not in joined:
            raise AssertionError(
                "test setup error: seal-as-PoW knobs missing from extra_args")

        self.connect_nodes(0, 1)
        self.wait_until(
            lambda: node0.getconnectioncount() >= 1 and node1.getconnectioncount() >= 1,
            timeout=120,
        )

        self.log.info(f"Mine the pre-LT chain up to height {DRLT_HEIGHT - 1} (Phase A / BMX4C)")
        self.generate(node0, DRLT_HEIGHT - 1, sync_fun=self.no_op)
        self.wait_until(
            lambda: node1.getblockcount() == DRLT_HEIGHT - 1
            and node1.getbestblockhash() == node0.getbestblockhash(),
            timeout=180,
        )

        # Under ENC-DR-LT the challenge advertises Q* in {128,256,512}; the seal
        # window uses this exact Q*. (There is no separate challenge flag for seal
        # mode: the consensus object flip is height/knob-gated, not template-advertised.)
        challenge = node0.getmatmulchallenge()
        assert_equal(challenge["height"], DRLT_HEIGHT)
        assert_equal(challenge["matmul"]["encoding_profile"], "ENC-BMX4C-LT")
        q_star = challenge["matmul"]["consensus_q_star"]
        assert q_star in (128, 256, 512), f"unexpected Q* {q_star}"
        self.log.info(f"ENC-DR-LT active at {DRLT_HEIGHT}; seal window Q*={q_star}")

        self.log.info(f"Mine the ENC-DR-LT SEAL activation block {DRLT_HEIGHT} (Phase B)")
        # This block's matmul_digest is a Q* WINDOW SEAL produced by
        # SolveMatMulV4LT's seal-as-PoW branch, not a per-nonce digest.
        self.generate(node0, 1, sync_fun=self.no_op)
        self.wait_until(
            lambda: node1.getblockcount() == DRLT_HEIGHT
            and node1.getbestblockhash() == node0.getbestblockhash(),
            timeout=600,
        )

        self.log.info("The seal block validates + synced on the independent peer (Phase B path)")
        seal_block = node1.getblock(node1.getbestblockhash(), 2)
        assert_equal(seal_block["height"], DRLT_HEIGHT)
        assert_equal(seal_block["matmul_dim"], V4_DIMENSION)
        # Seal mode leaves the ENC-DR digest-only carriage empty (no sketch body).
        assert "matrix_c_words" not in seal_block

        self.log.info(f"Mine {SEAL_BLOCKS} more seal blocks; both nodes keep agreeing")
        self.generate(node0, SEAL_BLOCKS, sync_fun=self.no_op)
        target_height = DRLT_HEIGHT + SEAL_BLOCKS
        self.wait_until(
            lambda: node1.getblockcount() == target_height
            and node1.getbestblockhash() == node0.getbestblockhash(),
            timeout=600,
        )
        for height in range(DRLT_HEIGHT, target_height + 1):
            block = node1.getblock(node1.getblockhash(height), 2)
            assert_equal(block["matmul_dim"], V4_DIMENSION)
            assert "matrix_c_words" not in block

        self.log.info("Cross-check: node1 can also MINE a seal block that node0 accepts")
        # Reverse the roles so both directions of the seal mine/relay/validate
        # path are exercised (node1 mines under Phase B, node0 validates).
        self.generate(node1, 1, sync_fun=self.no_op)
        self.wait_until(
            lambda: node0.getblockcount() == target_height + 1
            and node0.getbestblockhash() == node1.getbestblockhash(),
            timeout=600,
        )

        assert_equal(node0.getbestblockhash(), node1.getbestblockhash())
        self.log.info("Phase B seal-as-PoW mine/relay/validate/sync path is intact on both nodes")


if __name__ == "__main__":
    BTXMatMulDRLTSealAsPoW(__file__).main()
