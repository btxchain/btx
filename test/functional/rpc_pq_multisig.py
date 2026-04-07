#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""RPC coverage for PQ multisig address construction and validation."""

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_raises_rpc_error


LEGACY_MULTISIG_DISABLED_ERROR = (
    "BTX PQ policy: legacy multisig RPCs are disabled; use P2MR descriptors"
)


class RPCPQMultisigTest(BitcoinTestFramework):
    def add_options(self, parser):
        self.add_wallet_options(parser)

    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.extra_args = [[]]

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def run_test(self):
        node = self.nodes[0]
        node.createwallet(wallet_name="pq_multisig_rpc", descriptors=True)
        wallet = node.get_wallet_rpc("pq_multisig_rpc")

        mldsa_a = "11" * 1312
        mldsa_b = "22" * 1312
        slh = "33" * 32
        pq_keys = [mldsa_a, mldsa_b, f"pk_slh({slh})"]

        self.log.info("createmultisig returns a P2MR address/redeemScript/descriptor for PQ keys")
        created = node.createmultisig(2, pq_keys, {"address_type": "p2mr", "sort": True})
        assert "address" in created
        assert "redeemScript" in created
        assert "descriptor" in created
        assert "sortedmulti_pq(" in created["descriptor"]

        self.log.info("decodescript exposes PQ multisig metadata")
        decoded = node.decodescript(created["redeemScript"])
        assert "OP_CHECKSIGADD_MLDSA" in decoded["asm"]
        assert "OP_CHECKSIGADD_SLHDSA" in decoded["asm"]
        assert "pq_multisig" in decoded
        assert_equal(decoded["pq_multisig"]["threshold"], 2)
        assert_equal(decoded["pq_multisig"]["keys"], 3)
        assert_equal(decoded["pq_multisig"]["algorithms"], ["ml-dsa-44", "ml-dsa-44", "slh-dsa-shake-128s"])

        self.log.info("invalid thresholds are rejected")
        assert_raises_rpc_error(
            -8,
            "nrequired must be at least 1",
            node.createmultisig,
            0,
            pq_keys,
        )
        assert_raises_rpc_error(
            -8,
            "nrequired cannot exceed number of keys",
            node.createmultisig,
            4,
            pq_keys,
        )
        assert_raises_rpc_error(
            -8,
            "multisig requires at least 2 keys",
            node.createmultisig,
            1,
            [mldsa_a],
        )
        assert_raises_rpc_error(
            -8,
            "Unable to build PQ multisig leaf script",
            node.createmultisig,
            2,
            [mldsa_a, mldsa_a, f"pk_slh({slh})"],
        )

        self.log.info("non-P2MR address types remain rejected")
        assert_raises_rpc_error(
            -8,
            "Only address type 'p2mr' is supported for PQ multisig",
            node.createmultisig,
            2,
            pq_keys,
            {"address_type": "bech32"},
        )

        self.log.info("legacy/secp key forms remain blocked")
        assert_raises_rpc_error(
            -8,
            LEGACY_MULTISIG_DISABLED_ERROR,
            node.createmultisig,
            2,
            [
                "03789ed0bb717d88f7d321a368d905e7430207ebbd82bd342cf11ae157a7ace5fd",
                "03dbc6764b8884a92e871274b87583e6d5c2a58819473e17e107ef3f6aa5a61626",
            ],
        )

        self.log.info("policy key-count cap is enforced")
        too_many_slh_keys = [f"{i:064x}" for i in range(1, 11)]
        assert_raises_rpc_error(
            -8,
            "Unable to build PQ multisig leaf script",
            node.createmultisig,
            2,
            too_many_slh_keys,
        )

        self.log.info("wallet RPC addpqmultisigaddress mirrors createmultisig behavior")
        added = wallet.addpqmultisigaddress(2, pq_keys, "pq-msig", True)
        assert "address" in added
        assert "redeemScript" in added
        assert "descriptor" in added
        assert "sortedmulti_pq(" in added["descriptor"]
        assert_raises_rpc_error(
            -8,
            "multisig requires at least 2 keys",
            wallet.addpqmultisigaddress,
            1,
            [mldsa_a],
            "single-key-invalid",
            False,
        )
        assert_raises_rpc_error(
            -8,
            "Unable to build PQ multisig script with provided keys",
            wallet.addpqmultisigaddress,
            2,
            [mldsa_a, mldsa_a, f"pk_slh({slh})"],
            "duplicate-key-invalid",
            False,
        )


if __name__ == "__main__":
    RPCPQMultisigTest(__file__).main()
