#!/usr/bin/env python3
# Copyright (c) 2014-2022 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test importmulti against pre-existing legacy wallets."""

from test_framework.descriptors import descsum_create
from test_framework.script import CScript, OP_NOP
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
    assert_raises_rpc_error,
)
from test_framework.wallet_util import (
    create_legacy_wallet_with_tool,
    get_generate_key,
    test_address,
)


class ImportMultiTest(BitcoinTestFramework):
    def add_options(self, parser):
        self.add_wallet_options(parser, descriptors=False)

    def set_test_params(self):
        self.num_nodes = 2
        self.setup_clean_chain = True
        self.wallet_names = []

    def skip_test_if_missing_module(self):
        if not self.is_wallet_compiled():
            self.skip_if_no_wallet()
        self.enable_wallet_if_possible()
        if not self.is_bdb_compiled():
            self.skip_if_no_sqlite()
        self.skip_if_no_wallet_tool()

    def setup_network(self):
        self.add_nodes(self.num_nodes, extra_args=[["-nowallet"]] * self.num_nodes)
        create_legacy_wallet_with_tool(self, self.nodes[1], self.default_wallet_name)
        create_legacy_wallet_with_tool(
            self,
            self.nodes[1],
            "noprivkeys",
            blank=True,
            disable_private_keys=True,
        )
        create_legacy_wallet_with_tool(self, self.nodes[1], "encrypted", blank=True)
        self.start_nodes()
        self.nodes[1].loadwallet(self.default_wallet_name)
        self.connect_nodes(1, 0)

    def import_one(self, request, *, success=True, error_code=None, error_message=None):
        result = self.nodes[1].importmulti([request])[0]
        assert_equal(result["success"], success)
        if error_code is not None:
            assert_equal(result["error"]["code"], error_code)
            assert_equal(result["error"]["message"], error_message)
        return result

    def run_test(self):
        self.generate(self.nodes[0], 1)
        timestamp = self.nodes[1].getblock(self.nodes[1].getbestblockhash())["mediantime"]

        self.log.info("Import a pre-existing address as watch-only")
        address_key = get_generate_key()
        self.import_one({
            "scriptPubKey": {"address": address_key.p2pkh_addr},
            "timestamp": "now",
            "label": "watch address",
            "watchonly": True,
        })
        test_address(
            self.nodes[1],
            address_key.p2pkh_addr,
            iswatchonly=True,
            ismine=False,
            timestamp=timestamp,
            ischange=False,
            labels=["watch address"],
        )

        self.log.info("Import public and private key material")
        public_key = get_generate_key()
        public_result = self.import_one({
            "scriptPubKey": {"address": public_key.p2pkh_addr},
            "pubkeys": [public_key.pubkey],
            "timestamp": "now",
            "watchonly": True,
        })
        assert "warnings" not in public_result
        assert self.nodes[1].getaddressinfo(public_key.p2pkh_addr)["solvable"]

        private_key = get_generate_key()
        self.import_one({
            "scriptPubKey": {"address": private_key.p2pkh_addr},
            "keys": [private_key.privkey],
            "timestamp": "now",
        })
        private_info = self.nodes[1].getaddressinfo(private_key.p2pkh_addr)
        assert private_info["ismine"]
        assert not private_info["iswatchonly"]

        self.log.info("Reject malformed and contradictory import requests")
        self.import_one(
            {"scriptPubKey": {"address": "not valid address"}, "timestamp": "now"},
            success=False,
            error_code=-5,
            error_message='Invalid address "not valid address"',
        )
        nonstandard = private_key.p2pkh_script + CScript([OP_NOP]).hex()
        self.import_one(
            {"scriptPubKey": nonstandard, "timestamp": "now"},
            success=False,
            error_code=-8,
            error_message="Internal must be set to true for nonstandard scriptPubKey imports.",
        )
        self.import_one(
            {
                "scriptPubKey": private_key.p2pkh_script,
                "timestamp": "now",
                "internal": True,
                "label": "not allowed",
            },
            success=False,
            error_code=-8,
            error_message="Internal addresses should not have a label",
        )

        self.log.info("Legacy imports reject Taproot destinations and descriptors")
        taproot_address = "bcrt1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqc8gma6"
        self.import_one(
            {"scriptPubKey": {"address": taproot_address}, "timestamp": "now"},
            success=False,
            error_code=-5,
            error_message=f'Invalid address "{taproot_address}"',
        )
        self.import_one(
            {"desc": descsum_create(f"tr({public_key.pubkey})"), "timestamp": "now"},
            success=False,
            error_code=-5,
            error_message="Bech32m descriptors cannot be imported into legacy wallets",
        )

        self.log.info("Import public keypool data into an existing no-private-keys wallet")
        self.nodes[1].loadwallet("noprivkeys")
        nopriv = self.nodes[1].get_wallet_rpc("noprivkeys")
        keypool_key = get_generate_key()
        result = nopriv.importmulti([{
            "desc": descsum_create(f"wpkh({keypool_key.pubkey})"),
            "keypool": True,
            "timestamp": "now",
        }])
        assert result[0]["success"]
        assert_equal(nopriv.getwalletinfo()["keypoolsize"], 1)

        self.log.info("Locked legacy wallets still allow explicit watch-only imports")
        self.nodes[1].loadwallet("encrypted")
        encrypted = self.nodes[1].get_wallet_rpc("encrypted")
        encrypted.encryptwallet("pass")
        encrypted_key = get_generate_key()
        assert_raises_rpc_error(
            -13,
            "Please enter the wallet passphrase",
            encrypted.importmulti,
            [{"desc": descsum_create(f"wpkh({encrypted_key.pubkey})"), "timestamp": "now"}],
        )
        watch_result = encrypted.importmulti([{
            "desc": descsum_create(f"wpkh({encrypted_key.pubkey})"),
            "timestamp": "now",
            "watchonly": True,
        }])
        assert watch_result[0]["success"]

        self.restart_node(1)
        self.nodes[1].loadwallet(self.default_wallet_name)
        default_wallet = self.nodes[1].get_wallet_rpc(self.default_wallet_name)
        assert default_wallet.getaddressinfo(private_key.p2pkh_addr)["ismine"]
        assert default_wallet.getaddressinfo(address_key.p2pkh_addr)["iswatchonly"]


if __name__ == '__main__':
    ImportMultiTest(__file__).main()
