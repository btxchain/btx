#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Verify shieldedv2dev uses an isolated datadir, wallet namespace, and HRP."""

from pathlib import Path

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal


class ShieldedV2DevDatadirIsolationTest(BitcoinTestFramework):
    def set_test_params(self):
        self.chain = "shieldedv2dev"
        self.num_nodes = 1
        self.setup_clean_chain = True

    def add_options(self, parser):
        self.add_wallet_options(parser)

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def _switch_chain(self, old_chain: str, new_chain: str) -> None:
        self.nodes[0].replace_in_config([
            (f"{old_chain}=1", f"{new_chain}=1"),
            (f"[{old_chain}]", f"[{new_chain}]"),
        ])
        self.nodes[0].chain = new_chain

    def _wallet_names(self):
        return sorted(entry["name"] for entry in self.nodes[0].listwalletdir()["wallets"])

    def run_test(self):
        node = self.nodes[0]
        shared_datadir = node.datadir_path

        assert_equal(node.getblockchaininfo()["chain"], "shieldedv2dev")
        shielded_wallet = "shieldedv2dev-wallet"
        node.createwallet(shielded_wallet)
        shielded_rpc = node.get_wallet_rpc(shielded_wallet)
        shielded_addr = shielded_rpc.getnewaddress(address_type="p2mr")
        assert shielded_addr.startswith("btxv2"), shielded_addr
        shielded_wallet_path = Path(shared_datadir) / "shieldedv2dev" / "wallets" / shielded_wallet
        assert shielded_wallet_path.exists(), shielded_wallet_path

        self.stop_node(0)
        self._switch_chain("shieldedv2dev", "regtest")
        self.start_node(0)

        node = self.nodes[0]
        assert_equal(node.getblockchaininfo()["chain"], "regtest")
        assert shielded_wallet not in self._wallet_names()

        regtest_wallet = "regtest-wallet"
        node.createwallet(regtest_wallet)
        regtest_rpc = node.get_wallet_rpc(regtest_wallet)
        regtest_addr = regtest_rpc.getnewaddress(address_type="p2mr")
        assert regtest_addr.startswith("btxrt"), regtest_addr
        regtest_wallet_path = Path(shared_datadir) / "regtest" / "wallets" / regtest_wallet
        assert regtest_wallet_path.exists(), regtest_wallet_path
        assert shielded_wallet_path.exists(), shielded_wallet_path

        self.stop_node(0)
        self._switch_chain("regtest", "shieldedv2dev")
        self.start_node(0)

        assert_equal(self.nodes[0].getblockchaininfo()["chain"], "shieldedv2dev")
        assert shielded_wallet in self._wallet_names()
        assert regtest_wallet not in self._wallet_names()
        assert regtest_wallet_path.exists(), regtest_wallet_path


if __name__ == "__main__":
    ShieldedV2DevDatadirIsolationTest(__file__).main()
