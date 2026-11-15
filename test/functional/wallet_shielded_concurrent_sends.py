#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""Two shielded sends from one wallet at the same time pick different notes.

z_sendmany reserves the notes it selected until its transaction reaches the
mempool. A second z_sendmany that selects while the first one is still being
built or committed must not take those notes again.
"""
import threading
from decimal import Decimal

from test_framework.authproxy import JSONRPCException
from test_framework.blocktools import REGTEST_GENERIC_P2P_MATMUL_ARGS
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, get_rpc_proxy

PASSPHRASE = "concurrent sends"
ROUNDS = 3


class WalletShieldedConcurrentSendsTest(BitcoinTestFramework):
    def add_options(self, parser):
        self.add_wallet_options(parser, legacy=False)

    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.extra_args = [list(REGTEST_GENERIC_P2P_MATMUL_ARGS) + ["-autoshieldcoinbase=0", "-nomodelnet"]]
        self.rpc_timeout = 600

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def send_at_once(self, zaddr, amounts):
        node = self.nodes[0]
        results = {}

        def send(key, amount):
            proxy = get_rpc_proxy(node.url + "/wallet/shielded", 0, timeout=600, coveragedir=node.coverage_dir)
            try:
                results[key] = proxy.z_sendmany([{"address": zaddr, "amount": amount}])["txid"]
            except JSONRPCException as e:
                results[key] = e.error

        threads = [threading.Thread(target=send, args=(i, amount)) for i, amount in enumerate(amounts)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        return [results[i] for i in range(len(amounts))]

    def run_test(self):
        node = self.nodes[0]
        node.createwallet("miner")
        miner = node.get_wallet_rpc("miner")
        node.createwallet(wallet_name="shielded", passphrase=PASSPHRASE)
        wallet = node.get_wallet_rpc("shielded")
        wallet.walletpassphrase(PASSPHRASE, 600)
        zaddr = wallet.z_getnewaddress()
        other_zaddr = wallet.z_getnewaddress()
        self.generatetoaddress(node, 20, wallet.getnewaddress())
        self.generatetoaddress(node, 101, miner.getnewaddress())
        # Shielded sends need at least 16 shielded outputs on chain; one note
        # per coinbase leaves enough notes for every round.
        for _ in range(19):
            wallet.z_shieldcoinbase(zaddr, None, 1)
        self.generatetoaddress(node, 2, miner.getnewaddress())
        assert len(wallet.z_listunspent(1, 9999999, False, True)) >= 2 * ROUNDS

        for round_number in range(ROUNDS):
            self.log.info(f"Round {round_number}: two z_sendmany calls at the same time")
            txids = self.send_at_once(other_zaddr, [Decimal("2"), Decimal("3")])
            for txid in txids:
                assert isinstance(txid, str), f"a concurrent z_sendmany failed: {txid}"
            assert txids[0] != txids[1]
            mempool = node.getrawmempool()
            for txid in txids:
                assert txid in mempool
            assert_equal(len(mempool), 2)
            self.generatetoaddress(node, 1, miner.getnewaddress())


if __name__ == "__main__":
    WalletShieldedConcurrentSendsTest(__file__).main()
