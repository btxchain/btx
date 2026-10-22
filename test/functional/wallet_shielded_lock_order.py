#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""Shielded wallet RPCs must take cs_wallet before cs_shielded.

rescanblockchain, the wallet bundle RPCs given a passphrase on a locked
wallet, and z_sendtoaddress / z_sendmany with conflict_txid used to lock
cs_shielded first and then cs_wallet (IsLocked(), GetMasterSeed(),
GetConflictSpendSelection()), the reverse of every other shielded path.

- A DEBUG_LOCKORDER build aborts on the first such call.
- Any build can deadlock the wallet when another RPC holds cs_wallet and
  waits for cs_shielded, so each path also runs while other threads poll
  getwalletinfo.
"""

import threading

from test_framework.authproxy import JSONRPCException
from test_framework.shielded_utils import SHIELDED_WALLET_PASSPHRASE, encrypt_and_unlock_wallet
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_raises_rpc_error, get_rpc_proxy

POLLERS = 2
ROUNDS = 10
MISSING_TXID = "11" * 32


class WalletShieldedLockOrderTest(BitcoinTestFramework):
    def add_options(self, parser):
        self.add_wallet_options(parser, legacy=False)

    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.rpc_timeout = 120

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()
        self.skip_if_no_sqlite()

    def wallet_proxy(self):
        # A deadlocked wallet never answers: fail after a minute, not after the full RPC timeout.
        return get_rpc_proxy(self.nodes[0].url + "/wallet/w", 0, timeout=int(60 * self.options.timeout_factor))

    def run_paths(self, wallet, zaddr, tag):
        wallet.rescanblockchain()
        assert_raises_rpc_error(-8, None, wallet.z_sendtoaddress, address=zaddr, amount=0.1, conflict_txid=MISSING_TXID)
        assert_raises_rpc_error(-8, None, wallet.z_sendmany, amounts=[{"address": zaddr, "amount": 0.1}], conflict_txid=MISSING_TXID)
        wallet.walletlock()
        wallet.backupwalletbundle(self.nodes[0].datadir_path / f"bundle-{tag}", SHIELDED_WALLET_PASSPHRASE)
        wallet.walletpassphrase(SHIELDED_WALLET_PASSPHRASE, 999000)

    def run_test(self):
        node = self.nodes[0]
        node.createwallet(wallet_name="w", descriptors=True)
        wallet = encrypt_and_unlock_wallet(node, "w")
        zaddr = wallet.z_getnewaddress()
        self.generatetoaddress(node, 10, wallet.getnewaddress(), sync_fun=self.no_op)

        self.log.info("Take cs_wallet then cs_shielded once, then run each path")
        wallet.getwalletinfo()
        self.run_paths(wallet, zaddr, "single")

        self.log.info("Run each path while other RPCs hold cs_wallet and wait for cs_shielded")
        stop = threading.Event()
        errors = []

        def poll():
            proxy = self.wallet_proxy()
            while not stop.is_set():
                try:
                    proxy.getwalletinfo()
                except JSONRPCException as e:
                    errors.append(e)
                    return

        pollers = [threading.Thread(target=poll) for _ in range(POLLERS)]
        for t in pollers:
            t.start()
        caller = self.wallet_proxy()
        try:
            for i in range(ROUNDS):
                self.run_paths(caller, zaddr, f"round-{i}")
        finally:
            stop.set()
            for t in pollers:
                t.join()
        assert not errors, errors
        wallet.getwalletinfo()


if __name__ == "__main__":
    WalletShieldedLockOrderTest(__file__).main()
