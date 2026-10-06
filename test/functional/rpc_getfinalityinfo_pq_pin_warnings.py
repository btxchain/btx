#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""getfinalityinfo warnings agree with its pin booleans for mixed pins.

ML-DSA-44 pin members (-matmultrustedpqpubkey) count toward N for the
pin quorum, the init threshold check, and the single_key_trusted_authority
and collocated_signer_pin fields of getfinalityinfo and
getmatmultrustedstatus. The matching getfinalityinfo warnings entries and
the getmatmultrustedstatus warning string must use the same N, so a
1 secp + 1 ML-DSA-44 pin at M=2 is not reported as single-key."""

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal
from test_framework.wallet_util import generate_keypair

# -matmultrustedpqpubkey only checks the 1312-byte ML-DSA-44 size.
PQ_PUBKEY_A = bytes(i % 256 for i in range(1312)).hex()
PQ_PUBKEY_B = bytes((i * 7 + 1) % 256 for i in range(1312)).hex()
PIN_FLAGS = ("single_key_trusted_authority", "collocated_signer_pin")
SINGLE_KEY_STATUS_WARNING = "Single-key trusted mirror:"
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


class GetFinalityInfoPqPinWarningsTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True

    def check_pin(self, label, args, expected_stderr, *, single_key, collocated):
        self.log.info(label)
        self.stop_node(0, expected_stderr=self.running_stderr)
        self.start_node(0, extra_args=args)
        self.running_stderr = expected_stderr
        node = self.nodes[0]

        info = node.getfinalityinfo()
        assert_equal(info["single_key_trusted_authority"], single_key)
        assert_equal(info["collocated_signer_pin"], collocated)
        assert_equal(
            [w for w in info["warnings"] if w in PIN_FLAGS],
            [f for f in PIN_FLAGS if info[f]])

        status = node.getmatmultrustedstatus()
        assert_equal(status["single_key_trusted_authority"], single_key)
        assert_equal(status["collocated_signer_pin"], collocated)
        assert_equal(
            status["warning"].startswith(SINGLE_KEY_STATUS_WARNING),
            single_key)

    def run_test(self):
        self.running_stderr = ""
        _, secp_a = generate_keypair(wif=True)
        _, secp_b = generate_keypair(wif=True)
        signer_wif, signer_pub = generate_keypair(wif=True)
        secp_a, secp_b, signer_pub = secp_a.hex(), secp_b.hex(), signer_pub.hex()
        mirror = ["-matmulvalidation=trusted", "-matmulattestationserve=0"]
        consensus_signer = [
            "-matmulvalidation=consensus",
            "-matmulattestationserve=0",
            f"-matmulattestationsignerkey={signer_wif}",
            f"-matmultrustedpubkey={signer_pub}",
        ]

        self.check_pin(
            "Trusted mirror, 1 secp + 1 ML-DSA-44 at M=2: not single-key",
            mirror + [
                f"-matmultrustedpubkey={secp_a}",
                f"-matmultrustedpqpubkey={PQ_PUBKEY_A}",
                "-matmultrustedthreshold=2",
            ],
            TRUST_WARNING.format(2),
            single_key=False, collocated=False)

        self.check_pin(
            "Trusted mirror, 2 ML-DSA-44 at M=2: not single-key",
            mirror + [
                f"-matmultrustedpqpubkey={PQ_PUBKEY_A}",
                f"-matmultrustedpqpubkey={PQ_PUBKEY_B}",
                "-matmultrustedthreshold=2",
            ],
            TRUST_WARNING.format(2),
            single_key=False, collocated=False)

        self.check_pin(
            "Trusted mirror, 2 secp at M=2: not single-key",
            mirror + [
                f"-matmultrustedpubkey={secp_a}",
                f"-matmultrustedpubkey={secp_b}",
                "-matmultrustedthreshold=2",
            ],
            TRUST_WARNING.format(2),
            single_key=False, collocated=False)

        self.check_pin(
            "Trusted mirror, 1 secp + 1 ML-DSA-44 at M=1: single-key",
            mirror + [
                f"-matmultrustedpubkey={secp_a}",
                f"-matmultrustedpqpubkey={PQ_PUBKEY_A}",
                "-matmultrustedthreshold=1",
            ],
            TRUST_WARNING.format(1),
            single_key=True, collocated=False)

        self.check_pin(
            "Trusted mirror, 1 ML-DSA-44 at M=1: single-key",
            mirror + [
                f"-matmultrustedpqpubkey={PQ_PUBKEY_A}",
                "-matmultrustedthreshold=1",
            ],
            TRUST_WARNING.format(1),
            single_key=True, collocated=False)

        self.check_pin(
            "Consensus signer pinned beside 1 ML-DSA-44 at M=2: not collocated",
            consensus_signer + [
                f"-matmultrustedpqpubkey={PQ_PUBKEY_A}",
                "-matmultrustedthreshold=2",
            ],
            INLINE_SIGNER_WARNING,
            single_key=False, collocated=False)

        self.check_pin(
            "Consensus signer pinned beside 1 ML-DSA-44 at M=1: collocated",
            consensus_signer + [
                f"-matmultrustedpqpubkey={PQ_PUBKEY_A}",
                "-matmultrustedthreshold=1",
            ],
            INLINE_SIGNER_WARNING,
            single_key=False, collocated=True)

        self.stop_node(0, expected_stderr=self.running_stderr)
        self.start_node(0)


if __name__ == "__main__":
    GetFinalityInfoPqPinWarningsTest(__file__).main()
