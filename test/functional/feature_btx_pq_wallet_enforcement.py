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
SIGNRAWTRANSACTIONWITHKEY_DISABLED_ERROR = (
    "BTX PQ policy: signrawtransactionwithkey is disabled (legacy ECDSA); use wallet signrawtransactionwithwallet with a P2MR address"
)
SWEEPPRIVKEYS_DISABLED_ERROR = (
    "BTX PQ policy: sweepprivkeys is disabled (legacy ECDSA); use wallet P2MR descriptors"
)
IMPORTPRIVKEY_DISABLED_ERROR = (
    "BTX PQ policy: importprivkey is disabled (legacy ECDSA); use importdescriptors with P2MR"
)
IMPORTPUBKEY_DISABLED_ERROR = (
    "BTX PQ policy: importpubkey is disabled (legacy secp256k1); use importdescriptors with P2MR"
)
IMPORTADDRESS_SECP_DISABLED_ERROR = (
    "BTX PQ policy: importaddress is disabled for secp256k1; use importdescriptors with P2MR"
)
IMPORTWALLET_DISABLED_ERROR = (
    "BTX PQ policy: importwallet is disabled (legacy WIF); use importdescriptors with P2MR"
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

        raw_tx = node.createrawtransaction(
            [{"txid": "00" * 32, "vout": 0}],
            [{imported["address"]: 0.1}],
        )
        assert_raises_rpc_error(
            -8,
            SIGNRAWTRANSACTIONWITHKEY_DISABLED_ERROR,
            node.signrawtransactionwithkey,
            raw_tx,
            ["cUeKHd5orzT3mz8P9pxyREHfsWtVfgsfDjiZZBcjUBAaGk1BTj7N"],
        )
        assert_raises_rpc_error(
            -8,
            SWEEPPRIVKEYS_DISABLED_ERROR,
            node.sweepprivkeys,
            {"privkeys": ["cUeKHd5orzT3mz8P9pxyREHfsWtVfgsfDjiZZBcjUBAaGk1BTj7N"]},
        )
        assert_raises_rpc_error(
            -8,
            IMPORTPRIVKEY_DISABLED_ERROR,
            wallet.rpc.importprivkey,
            "cUeKHd5orzT3mz8P9pxyREHfsWtVfgsfDjiZZBcjUBAaGk1BTj7N",
        )
        assert_raises_rpc_error(
            -8,
            IMPORTPUBKEY_DISABLED_ERROR,
            wallet.rpc.importpubkey,
            "03789ed0bb717d88f7d321a368d905e7430207ebbd82bd342cf11ae157a7ace5fd",
        )
        assert_raises_rpc_error(
            -8,
            IMPORTADDRESS_SECP_DISABLED_ERROR,
            wallet.rpc.importaddress,
            "mpLQjfK79b7CCV4VMJWEWAj5Mpx8Up5zxB",
        )
        assert_raises_rpc_error(
            -8,
            IMPORTWALLET_DISABLED_ERROR,
            wallet.rpc.importwallet,
            "wallet.dump",
        )


if __name__ == "__main__":
    BTXPQWalletEnforcementTest(__file__).main()
