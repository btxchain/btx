#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test that unlocking a wallet whose cached PQ pubkeys do not match its seed relocks.

CWallet::Unlock() runs UpgradeDescriptorCache() after the master key is already
in memory. When a cached PQ pubkey did not match what the wallet seed derives,
DescriptorCache::MergeAndDiff() threw there and the exception escaped Unlock():
walletpassphrase returned an error without scheduling the relock and
exportwalletbundle skipped its relock, so the wallet stayed unlocked with no
timeout while getwalletinfo reported unlocked_until=0.

The test builds such a wallet from an encrypted descriptor wallet on disk: it
clears WALLET_FLAG_LAST_HARDENED_XPUB_CACHED, so the upgrade runs again on
unlock, and changes one byte of each cached index-0 ML-DSA pubkey.
"""

import struct

try:
    import sqlite3
except ImportError:
    pass

from test_framework.authproxy import JSONRPCException
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
    assert_greater_than,
    assert_raises_rpc_error,
)

WALLET_FLAG_LAST_HARDENED_XPUB_CACHED = 1 << 2
PQ_ALGO_ML_DSA_44 = 0


def db_key_prefix(record_type):
    # Record types are serialized with a one-byte compact size length prefix.
    name = record_type.encode()
    assert len(name) < 253
    return bytes([len(name)]) + name


class WalletUnlockCacheUpgradeTest(BitcoinTestFramework):
    def add_options(self, parser):
        self.add_wallet_options(parser, legacy=False)

    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 1
        self.extra_args = [["-keypool=3"]]

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()
        self.skip_if_no_sqlite()
        self.skip_if_no_py_sqlite3()

    def make_cache_mismatch(self, wallet_name):
        """Clear the last-hardened-xpub-cached flag and change the cached index-0 ML-DSA pubkeys."""
        db_path = self.nodes[0].wallets_path / wallet_name / self.wallet_data_filename
        flags_key = db_key_prefix("flags")
        cache_prefix = db_key_prefix("walletdescriptorpqcache")
        changed = 0
        conn = sqlite3.connect(db_path)
        with conn:
            (flags_value,) = conn.execute("SELECT value FROM main WHERE key = ?", (flags_key,)).fetchone()
            flags = struct.unpack("<Q", flags_value)[0]
            assert flags & WALLET_FLAG_LAST_HARDENED_XPUB_CACHED
            conn.execute("UPDATE main SET value = ? WHERE key = ?",
                         (struct.pack("<Q", flags & ~WALLET_FLAG_LAST_HARDENED_XPUB_CACHED), flags_key))
            for key, value in conn.execute("SELECT key, value FROM main").fetchall():
                if not key.startswith(cache_prefix):
                    continue
                # desc_id (32 bytes) | algo (uint8) | key_exp_index (uint32 LE) | der_index (uint32 LE)
                rest = key[len(cache_prefix):]
                algo = rest[32]
                der_index = struct.unpack("<I", rest[37:41])[0]
                if algo == PQ_ALGO_ML_DSA_44 and der_index == 0:
                    conn.execute("UPDATE main SET value = ? WHERE key = ?", (value[:-1] + bytes([value[-1] ^ 0x01]), key))
                    changed += 1
        conn.close()
        assert_greater_than(changed, 0)

    def is_locked(self, wallet):
        try:
            wallet.listdescriptors(True)
        except JSONRPCException as e:
            if e.error["code"] == -13:
                return True
            raise
        return False

    def run_test(self):
        node = self.nodes[0]
        passphrase = "WalletPassphrase"

        self.log.info("Create an encrypted wallet whose cached index-0 ML-DSA pubkeys no longer match its seed")
        node.createwallet(wallet_name="mismatch", passphrase=passphrase)
        node.unloadwallet("mismatch")
        self.make_cache_mismatch("mismatch")
        node.loadwallet("mismatch")
        wallet = node.get_wallet_rpc("mismatch")
        assert self.is_locked(wallet)

        self.log.info("walletpassphrase unlocks and the relock timer still fires")
        wallet.walletpassphrase(passphrase, 5)
        assert_greater_than(wallet.getwalletinfo()["unlocked_until"], 0)
        assert not self.is_locked(wallet)
        self.wait_until(lambda: self.is_locked(wallet), timeout=30)
        assert_equal(wallet.getwalletinfo()["unlocked_until"], 0)

        self.log.info("A second unlock works too, and walletlock locks")
        wallet.walletpassphrase(passphrase, 600)
        assert not self.is_locked(wallet)
        wallet.walletlock()
        assert self.is_locked(wallet)

        self.log.info("A wrong passphrase is still rejected")
        assert_raises_rpc_error(-14, "The wallet passphrase entered was incorrect", wallet.walletpassphrase, passphrase + "wrong", 10)
        assert self.is_locked(wallet)

        self.log.info("exportwalletbundle undoes its temporary unlock")
        bundle_path = node.datadir_path / "mismatch.btxwallet.json"
        result = wallet.exportwalletbundle(str(bundle_path), passphrase)
        assert result["unlocked_by_rpc"]
        assert self.is_locked(wallet)
        bundle_path.unlink()


if __name__ == '__main__':
    WalletUnlockCacheUpgradeTest(__file__).main()
