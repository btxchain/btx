#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test descriptor ranges whose exclusive end does not fit in int32_t.

WalletDescriptor stores the range end in int32_t, exclusive. An import whose
end is past INT32_MAX used to be truncated to a negative range and abort the
node during keypool top-up. Cases from bitcoin/bitcoin#35989, in a test that
runs with BTX's P2MR-only wallet defaults.
"""

from test_framework.descriptors import descsum_create
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_raises_rpc_error

XPUB = "tpubD6NzVbkrYhZ4YNXVQbNhMK1WqguFsUXceaVJKbmno2aZ3B6QfbMeraaYvnBSGpV3vxLyTTK9DYT1yoEck4XUScMzXoQ2U2oSmE2JyMedq3H"


class WalletDescriptorRangeBoundsTest(BitcoinTestFramework):
    def add_options(self, parser):
        self.add_wallet_options(parser, legacy=False)

    def set_test_params(self):
        self.num_nodes = 1
        self.extra_args = [["-keypool=5"]]
        self.setup_clean_chain = True
        # No default wallet: the -keypool=3000000000 restart must not top one up.
        self.wallet_names = []

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()
        self.skip_if_no_sqlite()

    def import_one(self, wallet, request):
        result = wallet.importdescriptors([request])
        assert_equal(len(result), 1)
        return result[0]

    def run_test(self):
        node = self.nodes[0]

        self.log.info("Control: a ranged watch-only import inside the int32_t bound succeeds")
        node.createwallet(wallet_name="w", disable_private_keys=True, blank=True)
        w = node.get_wallet_rpc("w")
        res = self.import_one(w, {"desc": descsum_create(f"wpkh({XPUB}/0/*)"), "timestamp": "now", "range": [0, 2]})
        assert_equal(res["success"], True)

        self.log.info("An inclusive range end of 2^31-1 has no representable exclusive end and is rejected")
        res = self.import_one(w, {"desc": descsum_create(f"wpkh({XPUB}/1/*)"), "timestamp": "now", "range": [2**31 - 1, 2**31 - 1]})
        assert_equal(res["success"], False)
        assert_equal(res["error"]["code"], -8)
        assert_equal(res["error"]["message"], "End of range is too high")
        assert_equal(len(w.listdescriptors()["descriptors"]), 1)
        node.getblockcount()  # the node is still up
        w.unloadwallet()

        self.log.info("Without a range the import falls back to -keypool, which is bounded the same way")
        self.restart_node(0, extra_args=["-keypool=3000000000"])
        node.createwallet(wallet_name="keypool_bound", disable_private_keys=True, blank=True)
        wk = node.get_wallet_rpc("keypool_bound")
        res = self.import_one(wk, {"desc": descsum_create(f"wpkh({XPUB}/2/*)"), "timestamp": "now"})
        assert_equal(res["success"], False)
        assert_equal(res["error"]["code"], -8)
        assert_equal(res["error"]["message"], "End of range is too high")
        assert_equal(res["warnings"], ["Range not given, using default keypool range"])
        assert_equal(wk.listdescriptors()["descriptors"], [])
        wk.unloadwallet()

        self.log.info("keypoolrefill 2^31-1 on an advanced descriptor leaves the range unchanged")
        self.restart_node(0, extra_args=["-keypool=5"])
        node.createwallet(wallet_name="refill")
        wr = node.get_wallet_rpc("refill")
        wr.getnewaddress()
        wr.getrawchangeaddress()
        descriptors_before = wr.listdescriptors()["descriptors"]
        assert_equal(sorted({d["next_index"] for d in descriptors_before if d["active"]}), [1])
        # Without the bound this addition is undefined behaviour (UBSan); a normal
        # build wraps and reports the same error.
        assert_raises_rpc_error(-4, "Error refreshing keypool.", wr.keypoolrefill, 2**31 - 1)
        assert_equal(wr.listdescriptors()["descriptors"], descriptors_before)


if __name__ == '__main__':
    WalletDescriptorRangeBoundsTest(__file__).main()
