#!/usr/bin/env python3
# Copyright (c) 2014-2022 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test rescans when importing pre-existing data into loaded legacy wallets."""

import time

from test_framework.authproxy import JSONRPCException
from test_framework.blocktools import (
    REGTEST_GENERIC_P2P_MATMUL_ARGS,
    create_block,
    create_coinbase,
)
from test_framework.script import CScript
from test_framework.test_framework import BitcoinTestFramework
from test_framework.wallet_util import (
    create_legacy_wallet_with_tool,
    get_generate_key,
)


class ImportRescanTest(BitcoinTestFramework):
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
        self.add_nodes(
            self.num_nodes,
            extra_args=[["-nowallet", *REGTEST_GENERIC_P2P_MATMUL_ARGS]] * self.num_nodes,
        )
        for node in self.nodes:
            create_legacy_wallet_with_tool(self, node, self.default_wallet_name)
        self.start_nodes()
        for node in self.nodes:
            node.loadwallet(self.default_wallet_name)
        self.connect_nodes(1, 0)

    def mine_coinbase_to_key(self, key):
        tip = self.nodes[0].getblockheader(self.nodes[0].getbestblockhash())
        coinbase = create_coinbase(
            tip["height"] + 1,
            script_pubkey=CScript(bytes.fromhex(key.p2pkh_script)),
        )
        self.block_time = max(getattr(self, "block_time", 0) + 1, tip["time"] + 1, int(time.time()))
        block = create_block(
            int(tip["hash"], 16),
            coinbase,
            self.block_time,
        )
        block.solve()
        block_hex = block.serialize().hex()
        self.nodes[0].submitblock(block_hex)
        self.nodes[1].submitblock(block_hex)
        self.sync_blocks()
        for node in self.nodes:
            node.syncwithvalidationinterfacequeue()
        return coinbase.hash

    def run_test(self):
        # Legacy destination generation and relay are intentionally disabled on
        # BTX. Handcrafted coinbases let this test retain the supported and
        # security-relevant behavior: rescanning historical chain data for a
        # pre-existing imported key.
        key = get_generate_key()
        historical_txid = self.mine_coinbase_to_key(key)

        self.nodes[0].importprivkey(key.privkey, "rescanned", True)
        assert self.nodes[0].gettransaction(historical_txid)["confirmations"] == 1

        self.nodes[1].importprivkey(key.privkey, "no rescan", False)
        try:
            self.nodes[1].gettransaction(historical_txid)
            raise AssertionError("rescan-disabled import unexpectedly found historical transaction")
        except JSONRPCException as error:
            assert error.error["code"] == -5

        live_txid = self.mine_coinbase_to_key(key)
        assert self.nodes[0].gettransaction(live_txid)["confirmations"] == 1
        assert self.nodes[1].gettransaction(live_txid)["confirmations"] == 1

        watch_key = get_generate_key()
        self.nodes[1].importaddress(watch_key.p2pkh_addr, "watch only", False)
        watch_txid = self.mine_coinbase_to_key(watch_key)
        watch_tx = self.nodes[1].gettransaction(watch_txid, True)
        assert watch_tx["confirmations"] == 1

        self.restart_node(0)
        self.restart_node(1)
        self.nodes[0].loadwallet(self.default_wallet_name)
        self.nodes[1].loadwallet(self.default_wallet_name)
        assert self.nodes[0].gettransaction(historical_txid)["confirmations"] == 3
        assert self.nodes[1].gettransaction(watch_txid)["confirmations"] == 1


if __name__ == '__main__':
    ImportRescanTest(__file__).main()
