#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""Shielded wallet calls must survive an active chain that gets shorter meanwhile.

The shielded wallet reads the chain height and then looks up the block at
that height, once (the birth time of a new address) or for each height up to
it (the rebuild and catch-up loops). If blocks are disconnected in between (a
reorg, invalidateblock), the chain no longer reaches that height. The node
must keep running.

One thread makes new shielded addresses while another one disconnects and
reconnects blocks below the tip.
"""
import threading

from test_framework.authproxy import AuthServiceProxy
from test_framework.blocktools import REGTEST_GENERIC_P2P_MATMUL_ARGS
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal

BLOCKS = 600
ROUNDS = 60
DEPTH = 25
PASSPHRASE = "pass"


class WalletShieldedRebuildChainShrinkTest(BitcoinTestFramework):
    def add_options(self, parser):
        self.add_wallet_options(parser, legacy=False)

    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.extra_args = [["-autoshieldcoinbase=0", "-modelnet=0", "-rpcthreads=8"] + REGTEST_GENERIC_P2P_MATMUL_ARGS]
        self.rpc_timeout = 600

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def proxy(self, path=""):
        return AuthServiceProxy(self.nodes[0].url + path, timeout=600)

    def run_test(self):
        node = self.nodes[0]
        node.createwallet(wallet_name="miner", descriptors=True)
        miner = node.get_wallet_rpc("miner")
        self.generatetoaddress(node, BLOCKS, miner.getnewaddress(), sync_fun=self.no_op)

        node.createwallet(wallet_name="z", descriptors=True)
        z = node.get_wallet_rpc("z")
        z.encryptwallet(PASSPHRASE)
        z.walletpassphrase(PASSPHRASE, 99999)
        zaddr = z.z_getnewaddress()

        node.createwallet(wallet_name="w", descriptors=True)
        w = node.get_wallet_rpc("w")
        w.encryptwallet(PASSPHRASE)
        w.walletpassphrase(PASSPHRASE, 99999)
        assert w.z_validateaddress(zaddr)["isvalid"]
        w.z_getnewaddress()

        self.log.info("New shielded addresses while blocks below the tip are disconnected and reconnected")
        errors = []
        done = threading.Event()

        def rebuild_loop():
            rpc = self.proxy("/wallet/w")
            try:
                while not done.is_set():
                    rpc.z_getnewaddress()
            except Exception as e:
                errors.append(f"z_getnewaddress: {type(e).__name__}: {e}")

        def reorg_loop():
            rpc = self.proxy()
            try:
                for _ in range(ROUNDS):
                    block = rpc.getblockhash(BLOCKS - DEPTH)
                    rpc.invalidateblock(block)
                    rpc.reconsiderblock(block)
            except Exception as e:
                errors.append(f"invalidateblock: {type(e).__name__}: {e}")
            finally:
                done.set()

        threads = [threading.Thread(target=rebuild_loop), threading.Thread(target=reorg_loop)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        assert_equal(errors, [])

        self.log.info("The node runs and the wallets are on the active chain")
        assert_equal(node.getblockcount(), BLOCKS)
        assert w.z_validateaddress(zaddr)["isvalid"]
        w.z_getnewaddress()
        assert_equal(w.z_getbalance()["balance"], 0)
        assert_equal(z.z_getbalance()["balance"], 0)


if __name__ == "__main__":
    WalletShieldedRebuildChainShrinkTest(__file__).main()
