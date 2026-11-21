#!/usr/bin/env python3
# Copyright (c) 2014-2016 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

# Exercise the createmultisig API

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
    assert_raises_rpc_error,
)

# BTX createmultisig builds P2MR multisig from post-quantum keys, and "sort"
# orders them by public key bytes (src/rpc/output_script.cpp); secp256k1 keys
# are refused. The sorting checks therefore use synthetic ML-DSA-44 keys (as in
# rpc_pq_multisig.py) whose sorted order is pub3, pub1, pub2, like upstream's.
PQ_PUB1 = "22" * 1312
PQ_PUB2 = "33" * 1312
PQ_PUB3 = "11" * 1312

LEGACY_MULTISIG_DISABLED_ERROR = (
    "BTX PQ policy: legacy multisig RPCs are disabled; use P2MR descriptors"
)

class SortMultisigTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.extra_args = [[]]
        self.setup_clean_chain = True

    def assert_key_order(self, ms, keys):
        positions = [ms["redeemScript"].index(key) for key in keys]
        assert_equal(positions, sorted(positions))

    def run_simple_test(self):
        pub1, pub2, pub3 = PQ_PUB1, PQ_PUB2, PQ_PUB3

        pubs = [pub1,pub2,pub3]

        default = self.nodes[0].createmultisig(2, pubs)
        unsorted_ms = self.nodes[0].createmultisig(2, pubs, {"sort": False})
        assert_equal(unsorted_ms, self.nodes[0].createmultisig(2, pubs, options={"sort": False}))
        assert_equal(unsorted_ms, self.nodes[0].createmultisig(2, pubs, sort=False))

        assert unsorted_ms["descriptor"].startswith("mr(multi_pq(2,")
        self.assert_key_order(unsorted_ms, [pub1, pub2, pub3])
        assert_equal(default["address"], unsorted_ms["address"])
        assert_equal(default["redeemScript"], unsorted_ms["redeemScript"])

        sorted_ms = self.nodes[0].createmultisig(2, pubs, {"sort": True})
        assert_equal(sorted_ms, self.nodes[0].createmultisig(2, pubs, options={"sort": True}))
        assert_equal(sorted_ms, self.nodes[0].createmultisig(2, pubs, sort=True))
        assert sorted_ms["descriptor"].startswith("mr(sortedmulti_pq(2,")
        self.assert_key_order(sorted_ms, [pub3, pub1, pub2])
        assert sorted_ms["address"] != unsorted_ms["address"]

    def run_demonstrate_sorting(self):
        pub1, pub2, pub3 = PQ_PUB1, PQ_PUB2, PQ_PUB3

        sorted_ms = self.nodes[0].createmultisig(2, [pub3,pub1,pub2,])

        self.test_if_result_matches(2, [pub1,pub2,pub3], True, sorted_ms["address"])
        self.test_if_result_matches(2, [pub1,pub3,pub2], True, sorted_ms["address"])
        self.test_if_result_matches(2, [pub2,pub3,pub1], True, sorted_ms["address"])
        self.test_if_result_matches(2, [pub2,pub1,pub3], True, sorted_ms["address"])
        self.test_if_result_matches(2, [pub3,pub1,pub2], True, sorted_ms["address"])
        self.test_if_result_matches(2, [pub3,pub2,pub1], True, sorted_ms["address"])

        self.test_if_result_matches(2, [pub1,pub2,pub3], False, sorted_ms["address"])
        self.test_if_result_matches(2, [pub1,pub3,pub2], False, sorted_ms["address"])
        self.test_if_result_matches(2, [pub2,pub3,pub1], False, sorted_ms["address"])
        self.test_if_result_matches(2, [pub2,pub1,pub3], False, sorted_ms["address"])
        self.test_if_result_matches(2, [pub3,pub2,pub1], False, sorted_ms["address"])

    def test_if_result_matches(self, m, keys, sort, against):
        result = self.nodes[0].createmultisig(m, keys, {"sort": sort})
        assert_equal(sort, result["address"] == against)

    def test_legacy_keys_refused(self):
        # BIP67's compressed-key rule is secp256k1-only; on BTX the upstream
        # fixtures' keys are refused outright, sorted or not.
        compressed = ["022df8750480ad5b26950b25c7ba79d3e37d75f640f8e5d9bcd5b150a0f85014da",
                      "03e3818b65bcc73a7d64064106a859cc1a5a728c4345ff0b641209fba0d90de6e9",
                      "021f2f6e1e50cb6a953935c3601284925decd3fd21bc445712576873fb8c6ebc18"]
        uncompressed = ["02fdf7e1b65a477a7815effde996a03a7d94cbc46f7d14c05ef38425156fc92e22",
                        "04823336da95f0b4cf745839dff26992cef239ad2f08f494e5b57c209e4f3602d5526bc251d480e3284d129f736441560e17f3a7eb7ed665fdf0158f44550b926c"]
        for pubs in (compressed, uncompressed):
            assert_raises_rpc_error(-8, LEGACY_MULTISIG_DISABLED_ERROR, self.nodes[0].createmultisig, 2, pubs)
            for sort in (False, True):
                assert_raises_rpc_error(-8, LEGACY_MULTISIG_DISABLED_ERROR, self.nodes[0].createmultisig, 2, pubs, {"sort": sort})

    def run_test(self):
        self.run_simple_test()
        self.run_demonstrate_sorting()
        self.test_legacy_keys_refused()

if __name__ == '__main__':
    SortMultisigTest(__file__).main()

