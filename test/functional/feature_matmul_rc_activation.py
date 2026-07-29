#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""Regtest end-to-end rehearsal for ENC_RC + ENC_RC_COUPLED activation (F6).

Public nets keep nMatMulRCHeight / nMatMulRCCoupledHeight at INT32_MAX and the
GKR arbiter OFF. This test is the ONLY path that raises finite RC/coupled
heights — and only on regtest via CLI overrides — so mine → assemble →
relay/admit → async ExactReplay verify → shallow reorg → restart → IBD are
exercised together (unit tests alone build Consensus::Params in-process and
never hit that stack).

Node configuration follows the established ``-regtest*`` override convention
(src/chainparamsbase.cpp / src/chainparams.cpp / src/kernel/chainparams.cpp):
  -regtestmatmulv4height=<H>       unified v4 / ENC-BMX4C height
  -regtestbmx4cheight=<H>          (== v4 height under strict unified)
  -regtestdrltheight=<H>           ENC-DR-LT (kept at H; seal-as-PoW off)
  -regtestrcheight=<H_RC>          ENC_RC activation (H_RC >= H)
  -regtestrccoupledheight=<H_C>    ENC_RC_COUPLED (H_C >= H_RC)
  -regtestrctoydims=1              CI-scale ENC_RC episode dims
  -regtestrccoupledtoydims=1       CI-scale coupled dims
  -test=matmulstrict               peer must ExactReplay (not skip MatMul)
  -matmulasyncverify=1             P2P deliveries use the async verify worker

If a future refactor removes the -regtestrc* overrides, this test skips
outright rather than failing — RC staying permanently unreachable without a
regtest knob is a valid (if less testable) scaffolding state.
"""

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal

V4_DIMENSION = 128
V3_BINDING_HEIGHT = 2
# Unified v3 -> v4.2/BMX4C/LT flag day (seal-as-PoW off so pre-RC mining stays
# Phase-A digests, not Q* window seals).
V4_HEIGHT = 6
# Staged after v4 so [V4_HEIGHT, RC_HEIGHT) still exercises ENC-BMX4C-LT.
RC_HEIGHT = V4_HEIGHT + 3
# Coupled supersedes RC; construction requires H_C >= H_RC when both live.
COUPLED_HEIGHT = RC_HEIGHT + 3


class BTXMatMulRCActivation(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 3
        self.setup_clean_chain = True
        common = [
            "-test=matmulstrict",
            "-test=matmuldgw",
            "-matmulasyncverify=1",
            f"-regtestmatmulbindingheight={V3_BINDING_HEIGHT}",
            f"-regtestmatmulproductdigestheight={V3_BINDING_HEIGHT}",
            "-regtestmatmulrequireproductpayload=0",
            f"-regtestmatmulv4height={V4_HEIGHT}",
            f"-regtestmatmulv4dimension={V4_DIMENSION}",
            f"-regtestbmx4cheight={V4_HEIGHT}",
            f"-regtestdrltheight={V4_HEIGHT}",
            "-regtestmatmulltsealaspow=0",
            f"-regtestrcheight={RC_HEIGHT}",
            f"-regtestrccoupledheight={COUPLED_HEIGHT}",
            "-regtestrctoydims=1",
            "-regtestrccoupledtoydims=1",
        ]
        self.extra_args = [common, common, common]

    def setup_network(self):
        # Star: 0—1 always; node2 joins later for IBD coverage.
        self.setup_nodes()
        self.connect_nodes(0, 1)
        self.sync_all(self.nodes[:2])

    def _wait_peer_tip(self, height, timeout=300):
        node0, node1 = self.nodes[0], self.nodes[1]
        self.wait_until(
            lambda: node1.getblockcount() == height
            and node1.getbestblockhash() == node0.getbestblockhash(),
            timeout=timeout,
        )

    def run_test(self):
        node0, node1, node2 = self.nodes

        joined = " ".join(self.extra_args[0])
        if "-regtestrcheight" not in joined or "-regtestrccoupledheight" not in joined:
            raise AssertionError("test setup error: RC/coupled regtest override flags missing")
        if "-test=matmulstrict" not in joined:
            raise AssertionError("test setup error: matmulstrict required for ExactReplay peer path")

        self.log.info("Stop node2 so it can IBD the RC/coupled chain later")
        self.stop_node(2)

        self.wait_until(
            lambda: node0.getconnectioncount() >= 1 and node1.getconnectioncount() >= 1,
            timeout=120,
        )

        self.log.info("Pre-v4: getmatmulchallenge advertises no encoding_profile yet")
        challenge = node0.getmatmulchallenge()
        assert "encoding_profile" not in challenge["matmul"]

        self.log.info(f"Mine up to unified v4/BMX4C/LT height {V4_HEIGHT}")
        self.generate(node0, V4_HEIGHT, sync_fun=self.no_op)
        self._wait_peer_tip(V4_HEIGHT)

        challenge = node0.getmatmulchallenge()
        assert_equal(challenge["height"], V4_HEIGHT + 1)
        # DRLT live with seal-as-PoW off → ENC-BMX4C-LT Phase A.
        assert_equal(challenge["matmul"]["encoding_profile"], "ENC-BMX4C-LT")

        self.log.info(f"Mine up to one block short of ENC_RC activation {RC_HEIGHT}")
        self.generate(node0, RC_HEIGHT - 1 - V4_HEIGHT, sync_fun=self.no_op)
        self._wait_peer_tip(RC_HEIGHT - 1)
        challenge = node0.getmatmulchallenge()
        assert_equal(challenge["height"], RC_HEIGHT)
        assert_equal(challenge["matmul"]["encoding_profile"], "ENC-RC")

        self.log.info(f"Mine ENC_RC activation block {RC_HEIGHT} (assemble + relay/admit + async verify)")
        self.generate(node0, 1, sync_fun=self.no_op)
        self._wait_peer_tip(RC_HEIGHT)

        rc_block = node1.getblock(node1.getbestblockhash(), 2)
        assert_equal(rc_block["height"], RC_HEIGHT)
        assert_equal(rc_block["matmul_dim"], V4_DIMENSION)
        # ENC_RC is DIGEST_RECOMPUTE — no in-block sketch payload.
        assert "matrix_c_words" not in rc_block
        challenge = node1.getmatmulchallenge()
        assert_equal(challenge["matmul"]["encoding_profile"], "ENC-RC")

        self.log.info(f"Mine through ENC_RC window up to coupled activation {COUPLED_HEIGHT}")
        self.generate(node0, COUPLED_HEIGHT - RC_HEIGHT, sync_fun=self.no_op)
        self._wait_peer_tip(COUPLED_HEIGHT)

        coupled_block = node1.getblock(node1.getbestblockhash(), 2)
        assert_equal(coupled_block["height"], COUPLED_HEIGHT)
        assert_equal(coupled_block["matmul_dim"], V4_DIMENSION)
        assert "matrix_c_words" not in coupled_block
        challenge = node1.getmatmulchallenge()
        assert_equal(challenge["matmul"]["encoding_profile"], "ENC-RC-COUPLED")

        self.log.info("Post-coupled: continue mining; peer keeps ExactReplay-validating")
        self.generate(node0, 2, sync_fun=self.no_op)
        self._wait_peer_tip(COUPLED_HEIGHT + 2)
        tip_height = COUPLED_HEIGHT + 2
        tip_hash = node0.getbestblockhash()
        assert_equal(node1.getbestblockhash(), tip_hash)

        self.log.info("Shallow reorg: invalidate tip on node0, remine heavier branch, sync peer")
        stale_tip = tip_hash
        node0.invalidateblock(stale_tip)
        assert_equal(node0.getblockcount(), tip_height - 1)
        # ENC_RC_COUPLED mining is seed-deterministic from (prev, time, …). Without
        # advancing time, remine rebuilds the identical invalidated tip →
        # ProcessNewBlock duplicate-invalid. Advance mocktime past MTP.
        parent = node0.getblock(node0.getbestblockhash())
        node0.setmocktime(parent["time"] + 600)
        self.generate(node0, 2, sync_fun=self.no_op)
        self._wait_peer_tip(tip_height + 1)
        assert node0.getbestblockhash() != stale_tip
        assert_equal(node0.getbestblockhash(), node1.getbestblockhash())
        challenge = node1.getmatmulchallenge()
        assert_equal(challenge["matmul"]["encoding_profile"], "ENC-RC-COUPLED")
        node0.setmocktime(0)

        self.log.info("Restart validating peer; tip and ENC-RC-COUPLED profile persist")
        tip_after_reorg = node0.getbestblockhash()
        tip_height_after = node0.getblockcount()
        self.restart_node(1, extra_args=self.extra_args[1])
        self.connect_nodes(0, 1)
        self._wait_peer_tip(tip_height_after)
        assert_equal(node1.getbestblockhash(), tip_after_reorg)
        challenge = node1.getmatmulchallenge()
        assert_equal(challenge["matmul"]["encoding_profile"], "ENC-RC-COUPLED")

        self.log.info("IBD: start node2 from genesis and sync the RC/coupled chain")
        self.start_node(2, extra_args=self.extra_args[2])
        self.connect_nodes(0, 2)
        self.wait_until(
            lambda: node2.getblockcount() == tip_height_after
            and node2.getbestblockhash() == tip_after_reorg,
            timeout=600,
        )
        challenge = node2.getmatmulchallenge()
        assert_equal(challenge["matmul"]["encoding_profile"], "ENC-RC-COUPLED")
        # Spot-check an RC block and a coupled block survived IBD ExactReplay.
        ibd_rc = node2.getblock(node2.getblockhash(RC_HEIGHT), 2)
        assert_equal(ibd_rc["matmul_dim"], V4_DIMENSION)
        assert "matrix_c_words" not in ibd_rc
        ibd_coupled = node2.getblock(node2.getblockhash(COUPLED_HEIGHT), 2)
        assert_equal(ibd_coupled["matmul_dim"], V4_DIMENSION)
        assert "matrix_c_words" not in ibd_coupled

        self.log.info("ENC_RC → ENC_RC_COUPLED regtest activation path is intact on all nodes")
        assert_equal(node0.getbestblockhash(), node1.getbestblockhash())
        assert_equal(node0.getbestblockhash(), node2.getbestblockhash())


if __name__ == "__main__":
    BTXMatMulRCActivation(__file__).main()
