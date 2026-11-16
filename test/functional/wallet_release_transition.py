#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""Open an old used encrypted PQ database and restore its old safe backup.

Requires an explicitly supplied, independently verified previous BTX executable.
For test_runner, supply BTX_PREVIOUS_DAEMON (and BTX_PREVIOUS_MODELNET=1
only for an old ModelNet build) in the environment. Custom CLI options are for
direct invocation; the runner forwards CLI options to its cache helper too.
The two forward consumers run sequentially on copies of the same baseline chain.
"""
from decimal import Decimal
from pathlib import Path
import hashlib
import os
import shutil

from test_framework.shielded_utils import (
    SHIELDED_WALLET_PASSPHRASE as PASSPHRASE,
    ensure_ring_diversity,
    fund_trusted_transparent_balance,
)
from test_framework.test_framework import BitcoinTestFramework, SkipTest
from test_framework.util import assert_equal, find_vout_for_address


def notes(wallet):
    rows = wallet.z_listunspent(1, 9999999, False, True)
    result = sorted((r["commitment"], Decimal(r["amount"]), r["block_hash"]) for r in rows)
    assert_equal(len(rows), len({r[0] for r in result}))
    return result


def public_identity(wallet):
    return sorted((r["desc"], r.get("internal", False), r.get("active", False))
                  for r in wallet.listdescriptors()["descriptors"])


def transparent(wallet):
    rows = wallet.listunspent(1)
    result = sorted((r["txid"], r["vout"], Decimal(r["amount"]), r["address"]) for r in rows)
    assert_equal(len(result), len({(r[0], r[1]) for r in result}))
    return result


class WalletReleaseTransitionTest(BitcoinTestFramework):
    def add_options(self, parser):
        self.add_wallet_options(parser, legacy=False)
        parser.add_argument("--previous-btxd", default=os.getenv("BTX_PREVIOUS_DAEMON"),
                            help="Verified old BTX executable/launcher; no automatic download")

        parser.add_argument("--previous-modelnet", action="store_true",
                            default=os.getenv("BTX_PREVIOUS_MODELNET") == "1",
                            help="Old build has ModelNet support; explicitly disable it")

    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.wallet_names = []
        self.extra_args = [["-autoshieldcoinbase=0", "-regtestshieldedmatrictdisableheight=500"]]
        self.rpc_timeout = 600

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()
        self.skip_if_no_sqlite()
        if not self.options.previous_btxd:
            raise SkipTest("Supply --previous-btxd=<verified old BTX path>")
        assert not self.options.valgrind, "Executable switching does not support valgrind"

    def setup_nodes(self):
        self.current_binary = self.options.bitcoind
        self.add_nodes(1, self.extra_args, binary=[self.options.previous_btxd])
        if self.options.previous_modelnet:
            self.nodes[0].extra_args.append("-nomodelnet")
        self.start_nodes()

    def mine(self):
        self.generatetoaddress(self.nodes[0], 1, self.mining, sync_fun=self.no_op)
        self.nodes[0].syncwithvalidationinterfacequeue()

    def confirmed(self, wallet, txid):
        result = wallet.gettransaction(txid)
        assert result["confirmations"] > 0
        assert self.nodes[0].getblockheader(result["blockhash"])["confirmations"] > 0
        return result

    def unlock(self, wallet):
        wallet.walletpassphrase(PASSPHRASE, 999000)

    def snapshot(self, wallet):
        return dict(transparent=transparent(wallet), notes=notes(wallet),
                    balance=Decimal(wallet.z_getbalance()["balance"]),
                    descriptors=public_identity(wallet), addresses=wallet.z_listaddresses())

    def check(self, wallet, expected):
        assert_equal(wallet.getwalletinfo()["private_keys_enabled"], True)
        assert_equal(wallet.getwalletinfo()["descriptors"], True)
        assert_equal(self.snapshot(wallet), expected)
        assert_equal(wallet.getaddressinfo(self.receive)["ismine"], True)
        assert self.spent_transparent not in {(r[0], r[1]) for r in transparent(wallet)}
        assert not self.spent_notes & {r["commitment"] for r in wallet.z_listunspent(0, 9999999, False, True)}

    def run_test(self):
        assert_equal(self.chain, "regtest")
        node = self.nodes[0]
        for name in ("payer", "original"):
            node.createwallet(name, descriptors=True, load_on_startup=False)
            node.get_wallet_rpc(name).encryptwallet(PASSPHRASE)
            assert_equal(node.get_wallet_rpc(name).getwalletinfo()["unlocked_until"], 0)
            self.unlock(node.get_wallet_rpc(name))
        payer = node.get_wallet_rpc("payer")
        original = node.get_wallet_rpc("original")
        self.mining = payer.getnewaddress()
        # The helper spends one 20-BTX coinbase; leave room for its fee.
        fund_trusted_transparent_balance(self, node, payer, self.mining, Decimal("18"), sync_fun=self.no_op)
        ensure_ring_diversity(self, node, payer, self.mining, payer.z_getnewaddress(), sync_fun=self.no_op)
        self.receive = original.getnewaddress(address_type="p2mr")
        assert original.getaddressinfo(self.receive)["scriptPubKey"].startswith("5220")
        self.zreceive = original.z_getnewaddress()
        funding = payer.sendtoaddress(self.receive, Decimal("6"))
        self.spent_transparent = (funding, find_vout_for_address(node, funding, self.receive))
        shielding = payer.z_shieldfunds(Decimal("1"), self.zreceive)["txid"]
        self.mine()
        assert_equal(Decimal(original.z_getbalance()["balance"]), Decimal("1"))
        assert_equal(sum(r[2] for r in transparent(original)), Decimal("6"))
        self.confirmed(original, funding)
        self.confirmed(payer, shielding)
        self.spent_notes = {r[0] for r in notes(original)}
        old_send = original.sendtoaddress(self.mining, Decimal("1"))
        payer_before = Decimal(payer.z_getbalance()["balance"])
        old_zresult = original.z_sendmany([{"address": payer.z_getnewaddress(), "amount": Decimal("0.2")}])
        old_shielded = old_zresult["txid"]
        self.mine()
        sent = self.confirmed(original, old_send)
        self.confirmed(original, old_shielded)
        assert_equal(Decimal(original.z_getbalance()["balance"]), Decimal("0.8") - Decimal(old_zresult["fee"]))
        assert_equal(Decimal(payer.z_getbalance()["balance"]), payer_before + Decimal("0.2"))
        assert_equal(sum(r[2] for r in transparent(original)), Decimal("5") + Decimal(sent["fee"]))
        assert_equal(node.gettxout(*self.spent_transparent), None)
        expected = self.snapshot(original)
        self.check(original, expected)
        self.log.info("Transition checkpoint: old-baseline-confirmed")
        baseline_tip = node.getbestblockhash()
        backup = Path(self.options.tmpdir) / "old-safe-backup.dat"
        original.backupwallet(backup)
        original.walletlock()
        assert_equal(original.getwalletinfo()["unlocked_until"], 0)
        self.stop_node(0)
        baseline = Path(self.options.tmpdir) / "immutable-old-baseline"
        shutil.copytree(node.datadir_path, baseline)
        backup_hash = hashlib.sha256(backup.read_bytes()).hexdigest()
        old_database_hash = hashlib.sha256((baseline / "regtest/wallets/original/wallet.dat").read_bytes()).hexdigest()
        # Reopen on the old executable as a healthy baseline control.
        self.start_node(0)
        node.loadwallet("original", False)
        control = node.get_wallet_rpc("original")
        assert_equal(control.getwalletinfo()["unlocked_until"], 0)
        self.unlock(control)
        self.check(control, expected)
        self.stop_node(0)
        self.log.info("Transition checkpoint: old-reopen-passed")
        # No candidate writes reach baseline/backup. Never run two signer copies.
        for restore in (False, True):
            self.log.info("Candidate consumer: %s", "old backup restore" if restore else "existing database")
            shutil.rmtree(node.datadir_path)
            shutil.copytree(baseline, node.datadir_path)
            if restore:
                shutil.rmtree(node.wallets_path / "original")
            node.extra_args = [a for a in node.extra_args if a != "-nomodelnet"]
            if self.config["components"].getboolean("ENABLE_MODELNET", fallback=False):
                node.extra_args.append("-nomodelnet")
            node.binary = self.current_binary
            node.args[0] = self.current_binary
            self.start_node(0)
            assert_equal(node.getbestblockhash(), baseline_tip)
            node.loadwallet("payer", False)
            payer = node.get_wallet_rpc("payer")
            self.unlock(payer)
            if restore:
                node.restorewallet("restored", backup, False)
                name = "restored"
            else:
                node.loadwallet("original", False)
                name = "original"
            assert_equal(set(node.listwallets()), {"payer", name})
            wallet = node.get_wallet_rpc(name)
            assert_equal(wallet.getwalletinfo()["unlocked_until"], 0)
            self.unlock(wallet)
            self.check(wallet, expected)
            new_transparent = payer.sendtoaddress(self.receive, Decimal("0.5"))
            new_shielding = payer.z_shieldfunds(Decimal("0.1"), self.zreceive)["txid"]
            self.mine()
            self.confirmed(wallet, new_transparent)
            self.confirmed(payer, new_shielding)
            assert_equal(sum(r[2] for r in transparent(wallet)), sum(r[2] for r in expected["transparent"]) + Decimal("0.5"))
            assert_equal(Decimal(wallet.z_getbalance()["balance"]), expected["balance"] + Decimal("0.1"))
            before_transparent = sum(r[2] for r in transparent(wallet))
            new_send = wallet.sendtoaddress(self.mining, Decimal("0.25"))
            before_z = Decimal(wallet.z_getbalance()["balance"])
            payer_before = Decimal(payer.z_getbalance()["balance"])
            zresult = wallet.z_sendmany([{"address": payer.z_getnewaddress(), "amount": Decimal("0.1")}])
            new_zsend = zresult["txid"]
            self.mine()
            sent = self.confirmed(wallet, new_send)
            self.confirmed(wallet, new_zsend)
            assert_equal(Decimal(wallet.z_getbalance()["balance"]), before_z - Decimal("0.1") - Decimal(zresult["fee"]))
            assert_equal(Decimal(payer.z_getbalance()["balance"]), payer_before + Decimal("0.1"))
            assert_equal(sum(r[2] for r in transparent(wallet)), before_transparent - Decimal("0.25") + Decimal(sent["fee"]))
            continued = self.snapshot(wallet)
            wallet.walletlock()
            assert_equal(wallet.getwalletinfo()["unlocked_until"], 0)
            self.restart_node(0)
            if name not in node.listwallets():
                node.loadwallet(name, False)
            wallet = node.get_wallet_rpc(name)
            assert_equal(wallet.getwalletinfo()["unlocked_until"], 0)
            self.unlock(wallet)
            self.check(wallet, continued)
            wallet.walletlock()
            self.stop_node(0)
            assert_equal(hashlib.sha256(backup.read_bytes()).hexdigest(), backup_hash)
            assert_equal(hashlib.sha256((baseline / "regtest/wallets/original/wallet.dat").read_bytes()).hexdigest(), old_database_hash)
            self.log.info("Transition checkpoint: %s-passed", "backup-restore" if restore else "existing-open")


if __name__ == '__main__':
    WalletReleaseTransitionTest(__file__).main()
