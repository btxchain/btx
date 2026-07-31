#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""One GPU-authority archive serving two trusted Profile-1 RPC mirrors."""

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal
from test_framework.wallet_util import generate_keypair


ACTIVATION_HEIGHT = 6
DISABLED_HEIGHT = 2_147_483_647


class MatMulTrustedMirrorsTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 3
        self.setup_clean_chain = True
        signer_wif, signer_pub = generate_keypair(wif=True)
        _, unavailable_pub = generate_keypair(wif=True)
        self.signer_pub = signer_pub.hex()
        self.unavailable_pub = unavailable_pub.hex()
        common = [
            "-test=matmulstrict",
            "-test=matmuldgw",
            "-matmulasyncverify=1",
            "-regtestmatmulbindingheight=2",
            "-regtestmatmulproductdigestheight=2",
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
            "-regtestmatmulv4dimension=128",
            f"-matmultrustedpubkey={self.signer_pub}",
            "-matmultrustedthreshold=1",
            "-matmultrustedwaitms=30000",
        ]
        archive = common + [
            "-matmulvalidation=consensus",
            f"-matmulattestationsignerkey={signer_wif}",
            "-matmulattestationserve=1",
        ]
        mirror = common + [
            "-matmulvalidation=trusted",
            "-matmulattestationserve=0",
        ]
        self.mirror_args = mirror
        self.insufficient_quorum_args = [
            arg for arg in mirror
            if not arg.startswith("-matmultrustedthreshold=")
            and not arg.startswith("-matmultrustedwaitms=")
        ] + [
            f"-matmultrustedpubkey={self.unavailable_pub}",
            "-matmultrustedthreshold=2",
            "-matmultrustedwaitms=1000",
        ]
        self.extra_args = [archive, mirror, mirror]

    def run_test(self):
        archive, mirror_a, mirror_b = self.nodes
        self.connect_nodes(0, 2)

        archive_services = archive.getnetworkinfo()["localservicesnames"]
        assert "MATMUL_ATTESTATION_ARCHIVE" in archive_services
        assert "MATMUL_CONSENSUS" in archive_services
        for mirror in (mirror_a, mirror_b):
            services = mirror.getnetworkinfo()["localservicesnames"]
            assert "MATMUL_TRUSTED_MIRROR" in services
            assert "MATMUL_CONSENSUS" not in services
            status = mirror.getmatmultrustedstatus()
            assert_equal(status["trusted_mirror"], True)
            assert_equal(status["local_signer"], False)
            assert_equal(status["threshold"], 1)

        self.log.info("Mine through the toy Profile-1 activation")
        self.generate(archive, ACTIVATION_HEIGHT + 2, sync_fun=self.no_op)
        self.wait_until(
            lambda: all(
                node.getbestblockhash() == archive.getbestblockhash()
                for node in (mirror_a, mirror_b)
            ),
            timeout=300,
        )

        for mirror in (mirror_a, mirror_b):
            status = mirror.getmatmultrustedstatus()
            assert status["accepted"] >= 1
            assert status["blocks_with_quorum"] >= 1
            assert_equal(mirror.getblockcount(), ACTIVATION_HEIGHT + 2)
            assert_equal(
                mirror.getblockchaininfo()["matmulvalidationmode"],
                "trusted",
            )

        self.log.info("Archive export imports idempotently on both mirrors")
        activation_hash = archive.getblockhash(ACTIVATION_HEIGHT)
        exported = archive.getmatmulattestations(activation_hash)
        assert_equal(len(exported), 1)
        for mirror in (mirror_a, mirror_b):
            imported = mirror.submitmatmulattestations(exported)
            assert_equal(imported[0]["result"], "duplicate")
            assert_equal(imported[0]["quorum"], True)

        self.log.info("Insufficient quorum is retryable and non-punitive")
        old_height = mirror_b.getblockcount()
        self.restart_node(2, self.insufficient_quorum_args)
        self.connect_nodes(0, 2)
        self.generate(archive, 1, sync_fun=self.no_op)
        self.wait_until(
            lambda: mirror_a.getblockcount() == old_height + 1,
            timeout=120,
        )
        self.wait_until(
            lambda: mirror_b.getmatmultrustedstatus()["wait_timeouts"] >= 1,
            timeout=120,
        )
        assert_equal(mirror_b.getblockcount(), old_height)
        assert_equal(mirror_b.listbanned(), [])

        self.log.info("Restoring a satisfiable quorum retries the same block")
        self.restart_node(2, self.mirror_args)
        self.connect_nodes(0, 2)
        self.wait_until(
            lambda: mirror_b.getbestblockhash()
            == archive.getbestblockhash(),
            timeout=180,
        )


if __name__ == "__main__":
    MatMulTrustedMirrorsTest(__file__).main()
