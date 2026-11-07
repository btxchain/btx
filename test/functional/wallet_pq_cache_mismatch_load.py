#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""Load a wallet whose cached PQ pubkeys are not the ones its seed derives.

The first unlocked load of a descriptor wallet runs the one-time
last-hardened-xpub cache upgrade. That upgrade expands index 0 again without
the cache, so it re-derives the PQ pubkeys at index 0. It used to throw when a
re-derived pubkey differed from the cached one. On load the exception became
"Wallet corrupted"; the flag that skips the upgrade is only set after it
succeeds, so the wallet failed every load and btxd exited when the wallet was
set to load at startup. On unlock the exception reached walletpassphrase after
the wallet was already unlocked, so no relock was scheduled.

The test builds such wallets by replacing the cached ML-DSA pubkeys of a wallet
that has not run the upgrade yet with valid ML-DSA pubkeys of another wallet.
The seed no longer derives them, while the SLH-DSA backup leaf still matches
the seed. The wallets must load over RPC and at startup, unlock with a relock
timer, log the mismatch, keep the cached pubkeys (their scripts are built from
them), and spend coins received after the load through the SLH-DSA leaf.
"""
from pathlib import Path
import sqlite3
import struct

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_greater_than

PQ_CACHE_PREFIX = bytes([len(b"walletdescriptorpqcache")]) + b"walletdescriptorpqcache"
FLAGS_KEY = bytes([len(b"flags")]) + b"flags"
WALLET_FLAG_LAST_HARDENED_XPUB_CACHED = 1 << 2
ML_DSA_44 = 0
ML_DSA_44_PUBKEY_SIZE = 1312
OP_CHECKSIG_SLHDSA = 0xbc
MISMATCH_LOG = "is not the key this wallet's seed derives"


class WalletPQCacheMismatchLoadTest(BitcoinTestFramework):
    def add_options(self, parser):
        self.add_wallet_options(parser, legacy=False)

    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.extra_args = [[
            "-autoshieldcoinbase=0",
            *self.modelnet_off_args(),
            # Regtest-only MatMul knobs that keep block generation fast.
            "-regtestmatmulbindingheight=2147483647",
            "-regtestmatmulproductdigestheight=2147483647",
            "-regtestmatmulv4height=2147483647",
            "-regtestmatmulrequireproductpayload=0",
        ]]

    def modelnet_off_args(self):
        """Keep the model helper off on builds that have it.

        A -DWITH_MODELNET=OFF build does not register -modelnet or -modelbind
        and refuses to start with them. It does not build btx-modeld either;
        the model network tests skip on the same check.
        """
        exeext = self.config["environment"].get("EXEEXT", "")
        builddir = self.config["environment"].get("BUILDDIR", "")
        if Path(builddir, "bin", f"btx-modeld{exeext}").is_file():
            return ["-modelnet=0", "-modelbind=off"]
        return []

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()
        self.skip_if_no_py_sqlite3()

    def wallet_db(self, name):
        return self.nodes[0].wallets_path / name / self.wallet_data_filename

    def read_flags(self, name):
        conn = sqlite3.connect(self.wallet_db(name))
        (value,) = conn.execute("SELECT value FROM main WHERE key = ?", (FLAGS_KEY,)).fetchone()
        conn.close()
        return struct.unpack("<Q", value)[0]

    def write_flags(self, name, flags):
        conn = sqlite3.connect(self.wallet_db(name))
        with conn:
            conn.execute("UPDATE main SET value = ? WHERE key = ?", (struct.pack("<Q", flags), FLAGS_KEY))
        conn.close()

    def ml_dsa_cache_records(self, name):
        """Cached ML-DSA pubkeys, keyed by (prefix, descriptor id, algo, key expression, index)."""
        conn = sqlite3.connect(self.wallet_db(name))
        rows = conn.execute("SELECT key, value FROM main").fetchall()
        conn.close()
        records = {}
        for key, value in rows:
            key = bytes(key)
            if not key.startswith(PQ_CACHE_PREFIX):
                continue
            assert_equal(len(key), len(PQ_CACHE_PREFIX) + 32 + 1 + 4 + 4)
            if key[len(PQ_CACHE_PREFIX) + 32] != ML_DSA_44:
                continue
            assert_equal(len(value), 3 + ML_DSA_44_PUBKEY_SIZE)  # compact size + pubkey
            records[key] = bytes(value)
        return records

    def replace_ml_dsa_pubkeys(self, name, donor):
        """Give wallet `name` the cached ML-DSA pubkeys of wallet `donor`."""
        target = sorted(self.ml_dsa_cache_records(name).items())
        replacements = sorted(self.ml_dsa_cache_records(donor).values())
        assert target
        assert len(replacements) >= len(target)
        conn = sqlite3.connect(self.wallet_db(name))
        with conn:
            for (key, old_value), new_value in zip(target, replacements):
                assert old_value != new_value
                conn.execute("UPDATE main SET value = ? WHERE key = ?", (new_value, key))
        conn.close()

    def assert_upgrade_pending(self, name):
        assert_equal(self.read_flags(name) & WALLET_FLAG_LAST_HARDENED_XPUB_CACHED, 0)

    def assert_upgrade_done(self, name):
        assert self.read_flags(name) & WALLET_FLAG_LAST_HARDENED_XPUB_CACHED

    def run_test(self):
        node = self.nodes[0]
        node.createwallet(wallet_name="funder", descriptors=True)
        self.funder = node.get_wallet_rpc("funder")
        self.generatetoaddress(node, 110, self.funder.getnewaddress(), sync_fun=self.no_op)
        node.createwallet(wallet_name="donor", descriptors=True)
        node.unloadwallet("donor")

        self.test_loadwallet()
        self.test_walletpassphrase()
        self.test_startup()

    def test_loadwallet(self):
        node = self.nodes[0]
        self.log.info("loadwallet: a wallet created without a passphrase runs the upgrade on its first load")
        node.createwallet(wallet_name="control", descriptors=True)
        node.unloadwallet("control")
        self.assert_upgrade_pending("control")
        with node.assert_debug_log(expected_msgs=[], unexpected_msgs=[MISMATCH_LOG]):
            node.loadwallet("control")
        node.unloadwallet("control")
        self.assert_upgrade_done("control")

        self.log.info("loadwallet: the same with cached ML-DSA pubkeys the seed does not derive")
        node.createwallet(wallet_name="mismatch", descriptors=True)
        node.unloadwallet("mismatch")
        self.assert_upgrade_pending("mismatch")
        self.replace_ml_dsa_pubkeys("mismatch", "donor")
        with node.assert_debug_log(expected_msgs=[MISMATCH_LOG]):
            node.loadwallet("mismatch")
        wallet = node.get_wallet_rpc("mismatch")

        self.log.info("Coins received after the load are spent through the SLH-DSA leaf")
        self.funder.sendtoaddress(wallet.getnewaddress(), 10)
        self.generatetoaddress(node, 1, self.funder.getnewaddress(), sync_fun=self.no_op)
        assert_equal(wallet.getbalance(), 10)
        txid = wallet.sendtoaddress(self.funder.getnewaddress(), 4)
        tx = node.getrawtransaction(txid, True)
        assert tx["vin"]
        for txin in tx["vin"]:
            leaf_script = bytes.fromhex(txin["txinwitness"][-2])
            assert_equal(leaf_script[-1], OP_CHECKSIG_SLHDSA)
        self.generatetoaddress(node, 1, self.funder.getnewaddress(), sync_fun=self.no_op)
        assert_equal(wallet.gettransaction(txid)["confirmations"], 1)

        self.log.info("The upgrade completed, so the wallet reloads with its funds")
        balance = wallet.getbalance()
        node.unloadwallet("mismatch")
        self.assert_upgrade_done("mismatch")
        node.loadwallet("mismatch")
        assert_equal(node.get_wallet_rpc("mismatch").getbalance(), balance)
        node.unloadwallet("mismatch")

    def test_walletpassphrase(self):
        node = self.nodes[0]
        self.log.info("walletpassphrase: an encrypted wallet that has not run the upgrade runs it on unlock")
        node.createwallet(wallet_name="mismatch_encrypted", descriptors=True, passphrase="pass")
        node.unloadwallet("mismatch_encrypted")
        # A wallet created with a passphrase ran the upgrade while it was blank.
        # Clear the flag to get the state an interrupted encryptwallet leaves.
        self.assert_upgrade_done("mismatch_encrypted")
        self.write_flags("mismatch_encrypted", self.read_flags("mismatch_encrypted") & ~WALLET_FLAG_LAST_HARDENED_XPUB_CACHED)
        self.replace_ml_dsa_pubkeys("mismatch_encrypted", "donor")
        node.loadwallet("mismatch_encrypted")  # locked: the upgrade waits for the unlock
        wallet = node.get_wallet_rpc("mismatch_encrypted")
        with node.assert_debug_log(expected_msgs=[MISMATCH_LOG]):
            wallet.walletpassphrase("pass", 600)
        assert_greater_than(wallet.getwalletinfo()["unlocked_until"], 0)
        wallet.walletlock()
        assert_equal(wallet.getwalletinfo()["unlocked_until"], 0)
        node.unloadwallet("mismatch_encrypted")
        self.assert_upgrade_done("mismatch_encrypted")

    def test_startup(self):
        node = self.nodes[0]
        self.log.info("btxd starts with such a wallet set to load at startup")
        node.createwallet(wallet_name="mismatch_startup", descriptors=True)
        node.unloadwallet("mismatch_startup")
        self.assert_upgrade_pending("mismatch_startup")
        self.replace_ml_dsa_pubkeys("mismatch_startup", "donor")
        with node.assert_debug_log(expected_msgs=[MISMATCH_LOG]):
            self.restart_node(0, extra_args=self.extra_args[0] + ["-wallet=mismatch_startup"])
        assert "mismatch_startup" in node.listwallets()


if __name__ == "__main__":
    WalletPQCacheMismatchLoadTest(__file__).main()
