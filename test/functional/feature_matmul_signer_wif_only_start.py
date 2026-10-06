#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""A local secp signer WIF seeds the pin and counts as an unblocked member.

-matmulattestationsignerkeyfile (and -matmulattestationsignerkey) add the
signer's public key to the configured signer set in FinalizeConfiguration,
and the init threshold check already counts that seeded key. The init
blocklist check must count it too, so a consensus node whose only secp pin
member is its own WIF starts, and a WIF can complete a pin that is below M.

A real blocklist must still fail closed: fewer than M unblocked pin members,
including a seeded key that is itself blocked, refuses start."""

from test_framework.test_framework import BitcoinTestFramework
from test_framework.test_node import ErrorMatch
from test_framework.util import assert_equal
from test_framework.wallet_util import generate_keypair

# -matmultrustedpqpubkey only checks the 1312-byte ML-DSA-44 size.
PQ_PUBKEY = bytes(i % 256 for i in range(1312)).hex()
INLINE_SIGNER_WARNING = (
    "Warning: -matmulattestationsignerkey exposes an online signing key "
    "through process/config surfaces; use a permission-restricted "
    "-matmulattestationsignerkeyfile."
)
BLOCKLIST_REFUSAL = r"Error: .*blocklist leaves"


class MatMulSignerWifOnlyStartTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True

    def check_start(self, label, args, expected_stderr, *, secp_pin, pq_pin,
                    threshold, unblocked):
        self.log.info(label)
        self.start_node(0, extra_args=args)
        status = self.nodes[0].getmatmultrustedstatus()
        assert_equal(status["configured"], True)
        assert_equal(status["local_signer"], True)
        assert_equal(sorted(status["trusted_signer_pubkeys"]), sorted(secp_pin))
        assert_equal(status["trusted_pq_signer_pubkeys"], pq_pin)
        assert_equal(status["threshold"], threshold)
        assert_equal(status["unblocked_pin_members"], unblocked)
        assert_equal(status["pin_quorum_reachable"], True)
        self.stop_node(0, expected_stderr=expected_stderr)

    def check_refused(self, label, args, expected_msg, match):
        self.log.info(label)
        self.nodes[0].assert_start_raises_init_error(
            extra_args=args, expected_msg=expected_msg, match=match)

    def run_test(self):
        signer_wif, signer_pub = generate_keypair(wif=True)
        _, pub_a = generate_keypair(wif=True)
        _, pub_b = generate_keypair(wif=True)
        signer_pub, pub_a, pub_b = signer_pub.hex(), pub_a.hex(), pub_b.hex()
        keyfile = self.nodes[0].chain_path / "matmul-attestor.wif"
        keyfile.write_text(signer_wif + "\n", encoding="utf8")
        consensus = [
            "-matmulvalidation=consensus",
            "-matmulattestationserve=0",
        ]
        inline_signer = consensus + [f"-matmulattestationsignerkey={signer_wif}"]
        file_signer = consensus + [f"-matmulattestationsignerkeyfile={keyfile}"]

        self.stop_node(0)

        self.log.info("A blocklist that leaves fewer than M unblocked members still refuses start")
        self.check_refused(
            "Pin A + B, A blocked, M=2, no local signer",
            consensus + [
                f"-matmultrustedpubkey={pub_a}",
                f"-matmultrustedpubkey={pub_b}",
                f"-matmulattestationblocklist={pub_a}",
                "-matmultrustedthreshold=2",
            ],
            "Error: -matmulattestationblocklist leaves 1 unblocked pin "
            "member(s), below -matmultrustedthreshold=2. Fail-closed: add "
            "another independent signer or remove a blocked key before start.",
            ErrorMatch.FULL_TEXT)
        self.check_refused(
            "Local signer only, its own key blocked, M=1",
            file_signer + [
                f"-matmulattestationblocklist={signer_pub}",
                "-matmultrustedthreshold=1",
            ],
            BLOCKLIST_REFUSAL, ErrorMatch.PARTIAL_REGEX)
        self.check_refused(
            "Pin signer + B, signer blocked, local signer, M=2",
            file_signer + [
                f"-matmultrustedpubkey={signer_pub}",
                f"-matmultrustedpubkey={pub_b}",
                f"-matmulattestationblocklist={signer_pub}",
                "-matmultrustedthreshold=2",
            ],
            BLOCKLIST_REFUSAL, ErrorMatch.PARTIAL_REGEX)
        self.check_refused(
            "Pin A, A blocked, unpinned local signer, M=2",
            file_signer + [
                f"-matmultrustedpubkey={pub_a}",
                f"-matmulattestationblocklist={pub_a}",
                "-matmultrustedthreshold=2",
            ],
            BLOCKLIST_REFUSAL, ErrorMatch.PARTIAL_REGEX)
        # The init count cannot see that the WIF is already pinned, so it
        # counts that key twice; the finalized pin must still refuse.
        self.check_refused(
            "Pin signer + A, A blocked, local signer, M=2",
            file_signer + [
                f"-matmultrustedpubkey={signer_pub}",
                f"-matmultrustedpubkey={pub_a}",
                f"-matmulattestationblocklist={pub_a}",
                "-matmultrustedthreshold=2",
            ],
            BLOCKLIST_REFUSAL, ErrorMatch.PARTIAL_REGEX)
        self.check_refused(
            "Pin signer only, local signer, M=2",
            file_signer + [
                f"-matmultrustedpubkey={signer_pub}",
                "-matmultrustedthreshold=2",
            ],
            r"Error: .*(blocklist leaves|threshold must be between)",
            ErrorMatch.PARTIAL_REGEX)

        self.check_start(
            "Local signer with its own key pinned, M=1 (control)",
            inline_signer + [
                f"-matmultrustedpubkey={signer_pub}",
                "-matmultrustedthreshold=1",
            ],
            INLINE_SIGNER_WARNING,
            secp_pin=[signer_pub], pq_pin=[], threshold=1, unblocked=1)

        self.log.info("A local signer WIF seeds or completes the pin")
        self.check_start(
            "Inline WIF only, no -matmultrustedpubkey, M=1",
            inline_signer + ["-matmultrustedthreshold=1"],
            INLINE_SIGNER_WARNING,
            secp_pin=[signer_pub], pq_pin=[], threshold=1, unblocked=1)
        self.check_start(
            "WIF keyfile only, no -matmultrustedpubkey, default M",
            file_signer,
            "",
            secp_pin=[signer_pub], pq_pin=[], threshold=1, unblocked=1)
        self.check_start(
            "WIF keyfile completes a 1-key secp pin, M=2",
            file_signer + [
                f"-matmultrustedpubkey={pub_a}",
                "-matmultrustedthreshold=2",
            ],
            "",
            secp_pin=[pub_a, signer_pub], pq_pin=[], threshold=2, unblocked=2)
        self.check_start(
            "WIF keyfile completes a 1-key ML-DSA-44 pin, M=2",
            file_signer + [
                f"-matmultrustedpqpubkey={PQ_PUBKEY}",
                "-matmultrustedthreshold=2",
            ],
            "",
            secp_pin=[signer_pub], pq_pin=[PQ_PUBKEY], threshold=2, unblocked=2)
        self.check_start(
            "Pin A + B, A blocked, unpinned local signer, M=2",
            file_signer + [
                f"-matmultrustedpubkey={pub_a}",
                f"-matmultrustedpubkey={pub_b}",
                f"-matmulattestationblocklist={pub_a}",
                "-matmultrustedthreshold=2",
            ],
            "",
            secp_pin=[pub_a, pub_b, signer_pub], pq_pin=[], threshold=2,
            unblocked=2)

        self.start_node(0)


if __name__ == "__main__":
    MatMulSignerWifOnlyStartTest(__file__).main()
