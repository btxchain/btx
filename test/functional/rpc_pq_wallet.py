#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.

from decimal import Decimal

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_raises_rpc_error


class RPCPQWalletTest(BitcoinTestFramework):
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
        node.createwallet(wallet_name="pqwallet", descriptors=True)
        wallet = node.get_wallet_rpc("pqwallet")

        self.log.info("check getdescriptorinfo accepts mr() descriptors with key origin info")
        descs = wallet.listdescriptors()["descriptors"]
        assert len(descs) >= 1
        mr_desc = descs[0]["desc"]
        info = node.getdescriptorinfo(mr_desc)
        assert_equal(info["descriptor"].startswith("mr("), True)
        assert_equal(info["isrange"], True)
        assert_equal(info["issolvable"], True)
        # Public wallet descriptors contain xpubs, not private keys.
        assert_equal(info["hasprivatekeys"], False)

        self.log.info("check tr() raw OP_SUCCESS is rejected by default and requires explicit override")
        tapscript_opsuccess_desc = "tr(79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798,raw(bd))"
        assert_raises_rpc_error(
            -5,
            "allow_op_success",
            node.getdescriptorinfo,
            tapscript_opsuccess_desc,
        )
        info_opsuccess = node.getdescriptorinfo(tapscript_opsuccess_desc, {"allow_op_success": True})
        assert_equal(info_opsuccess["descriptor"].startswith("tr("), True)

        self.log.info("check getnewaddress with explicit p2mr type")
        explicit = wallet.getnewaddress(address_type="p2mr")
        assert explicit.startswith("btxrt1z")

        self.log.info("check getnewaddress default is p2mr")
        default_addr = wallet.getnewaddress()
        assert default_addr.startswith("btxrt1z")

        self.log.info("check getnewaddress rejects legacy address types")
        assert_raises_rpc_error(
            -8,
            "Only address type 'p2mr' is supported",
            wallet.getnewaddress,
            address_type="bech32",
        )

        self.log.info("check validateaddress fields for p2mr")
        valid = wallet.validateaddress(default_addr)
        assert_equal(valid["isvalid"], True)
        assert_equal(valid["iswitness"], True)
        assert_equal(valid["isscript"], True)
        assert_equal(valid["witness_version"], 2)

        self.log.info("check validateaddress rejects malformed p2mr strings")
        malformed = default_addr[:-1] + ("q" if default_addr[-1] != "q" else "p")
        invalid = wallet.validateaddress(malformed)
        assert_equal(invalid["isvalid"], False)

        self.log.info("check sendtoaddress round-trip on p2mr outputs")
        mining_address = wallet.getnewaddress()
        self.generatetoaddress(node, 101, mining_address, sync_fun=self.no_op)
        recipient = wallet.getnewaddress()
        txid = wallet.sendtoaddress(recipient, Decimal("1.0"))
        self.generatetoaddress(node, 1, mining_address, sync_fun=self.no_op)
        tx = wallet.gettransaction(txid)
        assert tx["confirmations"] >= 1

        self.log.info("check getblocktemplate exposes PQ metadata and 24 MWU capacity")
        tmpl = node.getblocktemplate({"rules": ["segwit"]})
        assert_equal(tmpl["block_capacity"]["max_block_weight"], 24_000_000)
        assert "pq_info" in tmpl
        assert_equal(tmpl["pq_info"]["pq_algorithm"], "ml-dsa-44")
        assert_equal(tmpl["pq_info"]["pq_backup_algorithm"], "slh-dsa-shake-128s")
        assert_equal(tmpl["pq_info"]["pq_pubkey_size"], 1312)
        assert_equal(tmpl["pq_info"]["pq_signature_size"], 2420)

        self.log.info("check decodescript identifies witness_v2_p2mr outputs")
        script_hex = wallet.getaddressinfo(default_addr)["scriptPubKey"]
        decoded = node.decodescript(script_hex)
        assert_equal(decoded["type"], "witness_v2_p2mr")


if __name__ == "__main__":
    RPCPQWalletTest(__file__).main()
