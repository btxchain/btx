#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""One GPU-authority archive serving two trusted Profile-1 RPC mirrors,
plus a late-joining consensus verifier with no local signer."""

from test_framework.test_framework import BitcoinTestFramework
from test_framework.messages import msg_generic, ser_compact_size
from test_framework.p2p import P2PInterface
from test_framework.util import (
    assert_equal,
    assert_greater_than,
    assert_greater_than_or_equal,
)
from test_framework.wallet_util import generate_keypair


ACTIVATION_HEIGHT = 6
DISABLED_HEIGHT = 2_147_483_647
TRUST_WARNING = (
    "Warning: TRUSTED MATMUL MIRROR ACTIVE: this node delegates Profile-1 "
    "ExactReplay to a configured threshold of {} signer(s). It validates "
    "block bodies and scripts but is not an independent full consensus "
    "validator."
)
INLINE_SIGNER_WARNING = (
    "Warning: -matmulattestationsignerkey exposes an online signing key "
    "through process/config surfaces; use a permission-restricted "
    "-matmulattestationsignerkeyfile."
)


class MatMulTrustedMirrorsTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 4
        self.setup_clean_chain = True
        signer_wif, signer_pub = generate_keypair(wif=True)
        _, unavailable_pub = generate_keypair(wif=True)
        self.signer_wif = signer_wif
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
        # Consensus IBD without a local signer: same trusted pubkey/threshold
        # as the archive/mirrors, but no signing key and no attestation serve.
        consensus_verifier = common + [
            "-matmulvalidation=consensus",
            "-matmulattestationserve=0",
        ]
        self.mirror_args = mirror
        self.consensus_verifier_args = consensus_verifier
        self.insufficient_quorum_args = [
            arg for arg in mirror
            if not arg.startswith("-matmultrustedthreshold=")
            and not arg.startswith("-matmultrustedwaitms=")
        ] + [
            f"-matmultrustedpubkey={self.unavailable_pub}",
            "-matmultrustedthreshold=2",
            "-matmultrustedwaitms=1000",
        ]
        self.extra_args = [archive, mirror, mirror, consensus_verifier]

    def setup_network(self):
        # Start archive + mirrors only. The consensus verifier joins from a
        # clean height-0 datadir after the archive tip is past Profile-1
        # activation (PR 105: Authority stuck at 0 while archive tip advanced).
        self.add_nodes(self.num_nodes, self.extra_args)
        for i in range(3):
            self.start_node(i)
        if self._requires_wallet:
            for i in range(3):
                self.init_wallet(node=i)
        for i in range(2):
            self.connect_nodes(i + 1, i)
        self.sync_all(self.nodes[:3])

    def run_test(self):
        archive, mirror_a, mirror_b, verifier = self.nodes

        self.log.info("Trusted mirrors fail closed if configured to sign")
        self.stop_node(2, expected_stderr=TRUST_WARNING.format(1))
        mirror_b.assert_start_raises_init_error(
            extra_args=self.mirror_args + [
                f"-matmulattestationsignerkey={self.signer_wif}",
            ],
            expected_msg=(
                INLINE_SIGNER_WARNING
                + "\nError: Only an independent MatMul consensus validator can load an attestation signing key; remove -matmulattestationsignerkeyfile/-matmulattestationsignerkey from non-consensus nodes."
            ),
        )
        # Cache-and-forward GETMMATTEST is the archive role. Serving must not
        # require a local signing key (live: signer GETMMATTEST fan-in wedged
        # signing while mirrors returned empty).
        serving_mirror_args = [
            arg for arg in self.mirror_args
            if not arg.startswith("-matmulattestationserve=")
        ] + ["-matmulattestationserve=1"]
        self.start_node(2, extra_args=serving_mirror_args)
        serving_services = mirror_b.getnetworkinfo()["localservicesnames"]
        assert "MATMUL_TRUSTED_MIRROR" in serving_services
        assert "MATMUL_ATTESTATION_ARCHIVE" in serving_services
        assert "MATMUL_CONSENSUS" not in serving_services
        assert_equal(mirror_b.getmatmultrustedstatus()["serves_attestations"], True)
        self.stop_node(2, expected_stderr=TRUST_WARNING.format(1))
        mirror_b.assert_start_raises_init_error(
            extra_args=[
                arg for arg in self.mirror_args
                if not arg.startswith("-regtestrcprofile=")
            ] + ["-regtestrcprofile=2"],
            expected_msg="Error: Trusted MatMul mirrors support only RC Profile 1 ExactReplay attestations; the configured network selects a different RC profile.",
        )
        # A repeated key would otherwise inflate N and satisfy any M-of-N
        # minimum while the quorum still rests on one private key. Rejected on
        # every chain, and before daemonization so the operator sees why.
        mirror_b.assert_start_raises_init_error(
            extra_args=[
                arg for arg in self.mirror_args
                if not arg.startswith("-matmultrustedthreshold=")
            ] + [
                f"-matmultrustedpubkey={self.signer_pub}",
                "-matmultrustedthreshold=2",
            ],
            expected_msg=(
                f"Error: Duplicate -matmultrustedpubkey: {self.signer_pub}. "
                "Every trusted signer must be a distinct key; a repeated key "
                "raises N without adding an independent attestation authority."
            ),
        )
        # This rehearsal intentionally uses supported 1-of-1 trusted mode.
        # Mainnet warns for this topology but does not impose a 2-of-2 floor.
        self.start_node(2, self.mirror_args)

        self.connect_nodes(0, 2)

        archive_services = archive.getnetworkinfo()["localservicesnames"]
        assert "MATMUL_ATTESTATION_ARCHIVE" in archive_services
        assert "MATMUL_CONSENSUS" in archive_services
        archive_status = archive.getmatmultrustedstatus()
        assert_equal(archive_status["attestation_version"], 2)
        assert_equal(len(archive_status["replay_authority_context"]), 64)
        for mirror in (mirror_a, mirror_b):
            services = mirror.getnetworkinfo()["localservicesnames"]
            assert "MATMUL_TRUSTED_MIRROR" in services
            assert "MATMUL_CONSENSUS" not in services
            status = mirror.getmatmultrustedstatus()
            assert_equal(status["attestation_version"], 2)
            assert_equal(
                status["replay_authority_context"],
                archive_status["replay_authority_context"],
            )
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

        def peer_msg_bytes(node, sent, msg):
            key = "bytessent_per_msg" if sent else "bytesrecv_per_msg"
            return sum(
                (peer.get(key) or {}).get(msg, 0) for peer in node.getpeerinfo()
            )

        self.log.info(
            "Trusted mirrors request attestations for deferred Profile-1 blocks"
        )
        for mirror in (mirror_a, mirror_b):
            assert_greater_than(peer_msg_bytes(mirror, True, "getmmattest"), 0)
            assert_greater_than(peer_msg_bytes(mirror, False, "mmattest"), 0)
            status = mirror.getmatmultrustedstatus()
            assert status["accepted"] >= 1
            assert status["blocks_with_quorum"] >= 1
            attested = mirror.getmatmulattestedtip()
            assert "signed_frontier" in attested, attested
            frontier = attested["signed_frontier"]
            assert frontier["on_active_chain"] is True
            assert_equal(frontier["blocks_behind"], 0)
            assert_equal(mirror.getblockcount(), ACTIVATION_HEIGHT + 2)
            assert_equal(
                mirror.getblockchaininfo()["matmulvalidationmode"],
                "trusted",
            )

        self.log.info(
            "Frontier follows two newly produced P2P-attested blocks"
        )
        before_heights = [
            mirror.getmatmulattestedtip()["signed_frontier"]["height"]
            for mirror in (mirror_a, mirror_b)
        ]
        self.generate(archive, 2, sync_fun=self.no_op)
        self.wait_until(
            lambda: all(
                node.getbestblockhash() == archive.getbestblockhash()
                for node in (mirror_a, mirror_b)
            ),
            timeout=300,
        )
        for mirror, before in zip((mirror_a, mirror_b), before_heights):
            attested = mirror.getmatmulattestedtip()
            frontier = attested["signed_frontier"]
            assert frontier["on_active_chain"] is True
            assert_equal(frontier["blocks_behind"], 0)
            assert_greater_than(frontier["height"], before)
            assert_equal(mirror.getblockcount(), archive.getblockcount())

        self.log.info(
            "Consensus verifier without local signer syncs Profile-1 tip "
            "from the archive (PR 105 qualifier)"
        )
        assert_equal(archive.getblockcount(), ACTIVATION_HEIGHT + 4)
        self.start_node(3, self.consensus_verifier_args)
        assert_equal(verifier.getblockcount(), 0)
        self.connect_nodes(3, 0)
        self.wait_until(
            lambda: verifier.getbestblockhash()
            == archive.getbestblockhash(),
            timeout=300,
        )
        assert_equal(verifier.getblockcount(), archive.getblockcount())
        verifier_services = verifier.getnetworkinfo()["localservicesnames"]
        assert "MATMUL_CONSENSUS" in verifier_services
        assert "MATMUL_TRUSTED_MIRROR" not in verifier_services
        verifier_status = verifier.getmatmultrustedstatus()
        assert_equal(verifier_status["trusted_mirror"], False)
        assert_equal(verifier_status["local_signer"], False)
        assert_equal(
            verifier.getblockchaininfo()["matmulvalidationmode"],
            "consensus",
        )
        self.generate(archive, 2, sync_fun=self.no_op)
        self.wait_until(
            lambda: all(
                node.getbestblockhash() == archive.getbestblockhash()
                for node in (mirror_a, mirror_b, verifier)
            ),
            timeout=300,
        )
        assert_equal(verifier.getblockcount(), archive.getblockcount())

        self.log.info("Archive export imports idempotently on both mirrors")
        activation_hash = archive.getblockhash(ACTIVATION_HEIGHT)
        exported = archive.getmatmulattestations(activation_hash)
        assert_equal(len(exported), 1)
        raw_attestation = bytes.fromhex(exported[0])
        for mirror in (mirror_a, mirror_b):
            imported = mirror.submitmatmulattestations(exported)
            assert_equal(imported[0]["result"], "duplicate")
            assert_equal(imported[0]["quorum"], True)

        self.log.info("Attestations are bound to the replay authority context")
        wrong_context = bytearray(raw_attestation)
        # V2 appends replay_authority_context after the legacy statement
        # fields. The legacy block-hash field remains at bytes [33:65].
        wrong_context[71:103] = b"\xff" * 32
        rejected = mirror_a.submitmatmulattestations(
            [wrong_context.hex()]
        )
        assert_equal(
            rejected[0]["result"],
            "wrong-replay-authority-context",
        )
        assert_equal(rejected[0]["quorum"], True)

        legacy_version = bytearray(raw_attestation)
        legacy_version[0] = 1
        del legacy_version[71:103]
        rejected = mirror_a.submitmatmulattestations(
            [legacy_version.hex()]
        )
        assert_equal(rejected[0]["result"], "unsupported-version")
        assert_equal(rejected[0]["quorum"], True)

        self.log.info("Insufficient quorum is retryable and non-punitive")
        old_height = mirror_b.getblockcount()
        self.stop_node(2, expected_stderr=TRUST_WARNING.format(1))
        self.start_node(2, self.insufficient_quorum_args)
        self.connect_nodes(0, 2)
        self.generate(archive, 1, sync_fun=self.no_op)
        self.wait_until(
            lambda: mirror_a.getblockcount() == old_height + 1,
            timeout=120,
        )
        # ConnectTip defers unattested Profile-1 without blocking the message
        # thread on WaitForQuorum, so wait_timeouts may stay 0. The observable
        # is headers-ahead / blocks-pinned and no ban.
        self.wait_until(
            lambda: mirror_b.getblockchaininfo()["headers"] >= old_height + 1,
            timeout=60,
        )
        info = mirror_b.getblockchaininfo()
        assert_greater_than_or_equal(info["headers"], old_height + 1)
        assert_equal(info["blocks"], old_height)
        assert_equal(mirror_b.listbanned(), [])

        self.log.info("Restoring a satisfiable quorum retries the same block")
        self.stop_node(2, expected_stderr=TRUST_WARNING.format(2))
        self.start_node(2, self.mirror_args)
        self.connect_nodes(0, 2)
        self.wait_until(
            lambda: mirror_b.getbestblockhash()
            == archive.getbestblockhash(),
            timeout=180,
        )

        self.log.info("Malformed and source-amplified attestation relay fails closed")
        with mirror_a.assert_debug_log(["mmattest payload=16385 exceeds bound"]):
            peer = mirror_a.add_p2p_connection(P2PInterface())
            peer.send_message(
                msg_generic(b"mmattest", bytes(16 * 1024 + 1))
            )
        if peer.is_connected:
            peer.peer_disconnect()
        with mirror_a.assert_debug_log(["mmattest count=17 exceeds bound"]):
            peer = mirror_a.add_p2p_connection(P2PInterface())
            peer.send_message(
                msg_generic(b"mmattest", ser_compact_size(17))
            )
        if peer.is_connected:
            peer.peer_disconnect()
        with mirror_a.assert_debug_log(["mmattest trailing data"]):
            peer = mirror_a.add_p2p_connection(P2PInterface())
            peer.send_message(
                msg_generic(
                    b"mmattest",
                    ser_compact_size(1) + raw_attestation + b"\x00",
                )
            )
        if peer.is_connected:
            peer.peer_disconnect()

        unknown_attestation = bytearray(raw_attestation)
        # V2 preserves the legacy version || chain_id || block_hash prefix.
        unknown_attestation[33:65] = b"\xff" * 32
        with mirror_a.assert_debug_log(["mmattest for unknown"]):
            peer = mirror_a.add_p2p_connection(P2PInterface())
            peer.send_message(
                msg_generic(
                    b"mmattest",
                    ser_compact_size(1) + bytes(unknown_attestation),
                )
            )
        if peer.is_connected:
            peer.peer_disconnect()

        sixteen_attestations = (
            ser_compact_size(16) + raw_attestation * 16
        )
        # Replaying a valid public attestation must not drain the shared relay
        # budget: duplicates do not amplify into outbound messages. They still
        # consume the retained keyed-netgroup signature-verification budget,
        # so rotating peer IDs cannot obtain unbounded verification work.
        with mirror_a.assert_debug_log(
            ["mmattest over source verify budget"]
        ):
            # Sixteen full messages exactly consume the 256-signature source
            # burst and can never prove the rejection path. The seventeenth
            # must exceed the bucket even after the small elapsed-time refill.
            for _ in range(17):
                peer = mirror_a.add_p2p_connection(P2PInterface())
                peer.send_and_ping(
                    msg_generic(b"mmattest", sixteen_attestations)
                )
                peer.peer_disconnect()

        self.stop_node(0, expected_stderr=INLINE_SIGNER_WARNING)
        self.stop_node(1, expected_stderr=TRUST_WARNING.format(1))
        self.stop_node(2, expected_stderr=TRUST_WARNING.format(1))
        self.stop_node(3)


if __name__ == "__main__":
    MatMulTrustedMirrorsTest(__file__).main()
