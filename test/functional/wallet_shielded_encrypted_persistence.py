#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.

from decimal import Decimal
import sqlite3

from test_framework.shielded_utils import (
    encrypt_and_unlock_wallet,
    ensure_ring_diversity,
    fund_trusted_transparent_balance,
)
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_greater_than, assert_raises_rpc_error


class WalletShieldedEncryptedPersistenceTest(BitcoinTestFramework):
    def add_options(self, parser):
        self.add_wallet_options(parser)

    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.rpc_timeout = 600
        self.extra_args = [[]]

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()
        self.skip_if_no_py_sqlite3()

    @staticmethod
    def _serialized_key_hex(key_name: str) -> str:
        key_bytes = key_name.encode()
        assert len(key_bytes) < 253
        return (bytes([len(key_bytes)]) + key_bytes).hex().upper()

    def _wallet_db_has_key(self, wallet_db_path, key_name: str) -> bool:
        query_key = self._serialized_key_hex(key_name)
        conn = sqlite3.connect(wallet_db_path)
        with conn:
            row = conn.execute(
                "SELECT 1 FROM main WHERE hex(key) = ?",
                (query_key,),
            ).fetchone()
        conn.close()
        return row is not None

    def run_test(self):
        node = self.nodes[0]
        node.createwallet(wallet_name="shielded", descriptors=True)
        wallet = encrypt_and_unlock_wallet(node, "shielded")

        self.log.info("Create confirmed shielded balance")
        mine_addr = wallet.getnewaddress()
        fund_trusted_transparent_balance(
            self, node, wallet, mine_addr, Decimal("4.0"), sync_fun=self.no_op
        )
        assert_greater_than(Decimal(wallet.getbalance()), Decimal("2.0"))
        zaddr = wallet.z_getnewaddress()
        viewing_key = wallet.z_exportviewingkey(zaddr)
        wallet.z_shieldfunds(Decimal("2.0"), zaddr)
        self.generatetoaddress(node, 1, mine_addr, sync_fun=self.no_op)
        ensure_ring_diversity(self, node, wallet, mine_addr, zaddr)
        balance_before = Decimal(wallet.z_getbalance()["balance"])
        assert balance_before > Decimal("0")

        self.log.info("Partial shielded rescans must fail once the wallet has existing scan state")
        assert_raises_rpc_error(
            -8,
            "Partial shielded rescans are only supported before a wallet has existing shielded scan state",
            wallet.rescanblockchain,
            1,
        )

        self.log.info("Lock encrypted wallet and verify shielded secret persistence policy")
        wallet.walletlock()
        assert_raises_rpc_error(
            -13,
            "Shielded key import requires an unlocked encrypted wallet",
            wallet.z_importviewingkey,
            viewing_key["viewing_key"],
            viewing_key["kem_public_key"],
            viewing_key["address"],
            False,
            0,
        )
        wallet.walletpassphrase("pass", 120)
        import_result = wallet.z_importviewingkey(
            viewing_key["viewing_key"],
            viewing_key["kem_public_key"],
            viewing_key["address"],
            False,
            0,
        )
        assert_equal(import_result["success"], True)
        assert_equal(import_result["address"], viewing_key["address"])
        wallet.z_getnewaddress()
        wallet.walletlock()
        assert_raises_rpc_error(
            -13,
            "Please enter the wallet passphrase with walletpassphrase first",
            wallet.z_sendmany,
            [{"address": zaddr, "amount": Decimal("0.01")}],
        )
        node.unloadwallet("shielded")

        wallet_db = node.wallets_path / "shielded" / self.wallet_data_filename
        assert self._wallet_db_has_key(wallet_db, "pqmasterseedcrypt")
        assert self._wallet_db_has_key(wallet_db, "shieldedstatecrypt")
        assert not self._wallet_db_has_key(wallet_db, "pqmasterseed")
        assert not self._wallet_db_has_key(wallet_db, "shieldedstate")

        self.log.info("Reload encrypted wallet and verify shielded spending still works after unlock")
        load_result = node.loadwallet("shielded")
        assert_equal(load_result["name"], "shielded")
        assert any("Unlock it after load" in warning for warning in load_result["warnings"])
        wallet = node.get_wallet_rpc("shielded")
        locked_balance = wallet.z_getbalance()
        assert_equal(locked_balance["locked_state_incomplete"], True)
        locked_total = wallet.z_gettotalbalance()
        assert_equal(locked_total["locked_state_incomplete"], True)
        wallet.walletpassphrase("pass", 120)
        wallet.z_getnewaddress()
        assert_equal(Decimal(wallet.z_getbalance()["balance"]), balance_before)
        wallet.walletlock()
        relocked_balance = wallet.z_getbalance()
        assert "locked_state_incomplete" not in relocked_balance
        assert_equal(Decimal(relocked_balance["balance"]), balance_before)
        relocked_total = wallet.z_gettotalbalance()
        assert "locked_state_incomplete" not in relocked_total
        assert_equal(Decimal(relocked_total["shielded"]), balance_before)
        wallet.walletpassphrase("pass", 120)

        self.log.info("Partial viewing-key rescans must also fail on wallets with existing shielded scan state")
        node.createwallet(wallet_name="importer", descriptors=True)
        importer = encrypt_and_unlock_wallet(node, "importer")
        importer_mine_addr = importer.getnewaddress()
        fund_trusted_transparent_balance(
            self, node, importer, importer_mine_addr, Decimal("2.0"), sync_fun=self.no_op
        )
        importer_zaddr = importer.z_getnewaddress()
        importer.z_shieldfunds(Decimal("1.0"), importer_zaddr)
        self.generatetoaddress(node, 1, importer_mine_addr, sync_fun=self.no_op)
        ensure_ring_diversity(self, node, importer, importer_mine_addr, importer_zaddr)
        assert_raises_rpc_error(
            -8,
            "Partial shielded rescans are only supported before a wallet has existing shielded scan state",
            importer.z_importviewingkey,
            viewing_key["viewing_key"],
            viewing_key["kem_public_key"],
            viewing_key["address"],
            True,
            1,
        )

        zdest = wallet.z_getnewaddress()
        txid = wallet.z_sendmany([{"address": zdest, "amount": Decimal("0.1")}])["txid"]
        assert txid in node.getrawmempool()


if __name__ == "__main__":
    WalletShieldedEncryptedPersistenceTest(__file__).main()
