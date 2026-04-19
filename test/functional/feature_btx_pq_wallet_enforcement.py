#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""BTX PQ wallet policy enforcement checks."""

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_raises_rpc_error


LEGACY_WALLET_DISABLED_ERROR = (
    "BTX PQ policy: only descriptor wallets are supported (descriptors=true)"
)
LEGACY_MULTISIG_DISABLED_ERROR = (
    "BTX PQ policy: legacy multisig RPCs are disabled; use P2MR descriptors"
)


class BTXPQWalletEnforcementTest(BitcoinTestFramework):
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

        assert_raises_rpc_error(
            -8,
            LEGACY_WALLET_DISABLED_ERROR,
            node.createwallet,
            wallet_name="legacy_forbidden",
            descriptors=False,
        )

        node.createwallet(wallet_name="pq_enforced", descriptors=True)
        wallet = node.get_wallet_rpc("pq_enforced")

        pubkeys = [
            "03789ed0bb717d88f7d321a368d905e7430207ebbd82bd342cf11ae157a7ace5fd",
            "03dbc6764b8884a92e871274b87583e6d5c2a58819473e17e107ef3f6aa5a61626",
        ]

        assert_raises_rpc_error(
            -8,
            LEGACY_MULTISIG_DISABLED_ERROR,
            node.createmultisig,
            2,
            pubkeys,
        )
        assert_raises_rpc_error(
            -8,
            LEGACY_MULTISIG_DISABLED_ERROR,
            wallet.addmultisigaddress,
            2,
            pubkeys,
        )

        mldsa_a = "11" * 1312
        mldsa_b = "22" * 1312
        slh = "33" * 32
        pq_keys = [mldsa_a, mldsa_b, f"pk_slh({slh})"]

        created = node.createmultisig(2, pq_keys)
        assert "address" in created
        assert "redeemScript" in created
        assert "descriptor" in created
        assert "multi_pq(" in created["descriptor"]

        imported = wallet.addpqmultisigaddress(2, pq_keys, "pq-msig", True)
        assert "address" in imported
        assert "redeemScript" in imported
        assert "descriptor" in imported
        assert "sortedmulti_pq(" in imported["descriptor"]

        info = node.validateaddress(imported["address"])
        assert_equal(info["isvalid"], True)
        assert_equal(info["iswitness"], True)
        assert_equal(info["witness_version"], 2)

        assert_raises_rpc_error(
            -8,
            "Only address type 'p2mr' is supported",
            wallet.createwalletdescriptor,
            "bech32",
        )


if __name__ == "__main__":
    BTXPQWalletEnforcementTest(__file__).main()
