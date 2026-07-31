#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""Direct MatMul v4.7 Epoch-A activation rehearsal.

This regtest pins the launch shape that a later, narrow activation patch must
use: v4 == BMX4C == RC at one height, Profile 1 ExactReplay, DRLT/coupled off,
HeaderPoW off, and no in-block matrix payload. It complements the historical
staged RC/coupled regression without treating that staging path as the public
activation model.
"""

from test_framework.messages import CBlock, from_hex, msg_block
from test_framework.p2p import P2PInterface
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal


ACTIVATION_HEIGHT = 6
DISABLED_HEIGHT = 2_147_483_647
V4_DIMENSION = 128
V3_BINDING_HEIGHT = 2
FIXED_HEADER_BYTES = 182


class BTXMatMulV47EpochAActivation(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 2
        self.setup_clean_chain = True
        common = [
            "-test=matmulstrict",
            "-test=matmuldgw",
            "-matmulasyncverify=1",
            f"-regtestmatmulbindingheight={V3_BINDING_HEIGHT}",
            f"-regtestmatmulproductdigestheight={V3_BINDING_HEIGHT}",
            "-regtestmatmulrequireproductpayload=0",
            f"-regtestmatmulv4height={ACTIVATION_HEIGHT}",
            f"-regtestbmx4cheight={ACTIVATION_HEIGHT}",
            f"-regtestdrltheight={DISABLED_HEIGHT}",
            f"-regtestrcheight={ACTIVATION_HEIGHT}",
            f"-regtestrccoupledheight={DISABLED_HEIGHT}",
            "-regtestrcprofile=1",
            "-regtestrctoydims=1",
            "-regtestrccoupledtoydims=0",
            "-regtestmatmulltsealaspow=0",
            f"-regtestmatmulv4dimension={V4_DIMENSION}",
        ]
        self.extra_args = [common, common]

    def run_test(self):
        node0, node1 = self.nodes

        self.log.info("Mine to the parent of the atomic Epoch-A height")
        self.generate(node0, ACTIVATION_HEIGHT - 1)
        self.sync_all()
        challenge = node1.getmatmulchallenge()
        assert_equal(challenge["height"], ACTIVATION_HEIGHT)
        assert_equal(challenge["matmul"]["encoding_profile"], "ENC-RC")

        self.log.info("Mine and relay the direct Profile-1 ExactReplay block")
        self.generate(node0, 1, sync_fun=self.no_op)
        self.wait_until(
            lambda: node1.getblockcount() == ACTIVATION_HEIGHT
            and node1.getbestblockhash() == node0.getbestblockhash(),
            timeout=300,
        )

        activation_hash = node1.getbestblockhash()
        activation_block = node1.getblock(activation_hash, 2)
        assert_equal(activation_block["height"], ACTIVATION_HEIGHT)
        assert_equal(activation_block["matmul_dim"], V4_DIMENSION)
        assert "matrix_c_words" not in activation_block
        assert_equal(
            len(bytes.fromhex(node1.getblockheader(activation_hash, False))),
            FIXED_HEADER_BYTES,
        )
        scheduler = node1.getmininginfo()["backend_runtime"]["rc_accelerator_scheduler"]
        assert_equal(scheduler["authenticated_relay_samples"], 1)
        assert scheduler["last_authenticated_relay_s"] >= 0
        assert scheduler["max_authenticated_relay_s"] >= scheduler["last_authenticated_relay_s"]
        assert_equal(
            scheduler["complete_lifecycle_readiness"]["authenticated_relay_measured"],
            True,
        )

        self.log.info("A redundant full-block delivery cannot double-count relay telemetry")
        duplicate = from_hex(CBlock(), node0.getblock(activation_hash, 0))
        duplicate.rehash()
        duplicate_peer = node1.add_p2p_connection(P2PInterface())
        duplicate_peer.send_and_ping(msg_block(duplicate))
        duplicate_peer.peer_disconnect()
        scheduler_after_duplicate = node1.getmininginfo()["backend_runtime"][
            "rc_accelerator_scheduler"
        ]
        assert_equal(scheduler_after_duplicate["authenticated_relay_samples"], 1)

        self.log.info("Continue beyond Epoch A; the peer remains on ENC-RC")
        self.generate(node0, 2, sync_fun=self.no_op)
        self.sync_all()
        challenge = node1.getmatmulchallenge()
        assert_equal(challenge["matmul"]["encoding_profile"], "ENC-RC")
        assert_equal(node1.getbestblockhash(), node0.getbestblockhash())


if __name__ == "__main__":
    BTXMatMulV47EpochAActivation(__file__).main()
