#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""importwalletbundle must keep shielded keys consistent when it replaces the PQ seed.

importwalletbundle installs the bundle's PQ master seed as the wallet seed. Shielded spending
keys are derived from that seed, so:

(a) into a wallet with no shielded keys of its own (only a finished empty-gap search from the old
    seed), the imported seed's shielded notes were never searched and stayed invisible. The fix
    forgets the empty-gap result and derives/scans for the new seed, so the note appears at once.
(b) into a wallet that already holds its own shielded keys/notes, replacing the seed made those
    notes unspendable. The fix refuses the import before the overwrite, so the own note survives.
(same seed) re-importing the wallet's own bundle is unchanged: it is accepted and keeps the note.
"""
from decimal import Decimal

from test_framework.shielded_utils import (
    SHIELDED_WALLET_PASSPHRASE,
    encrypt_and_unlock_wallet,
    ensure_ring_diversity,
    fund_trusted_transparent_balance,
)
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_raises_rpc_error


class WalletImportBundleShieldedTest(BitcoinTestFramework):
    def add_options(self, parser):
        self.add_wallet_options(parser)

    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.extra_args = [["-autoshieldcoinbase=0", "-regtestshieldedmatrictdisableheight=500"]]
        self.rpc_timeout = 600

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def zbal(self, w):
        return Decimal(w.z_getbalance()["balance"])

    def make_funded_bundle(self, node, fund, fmine, name, amount):
        """A wallet 'name' that received one shielded note of 'amount'; returns its bundle path."""
        node.createwallet(wallet_name=name, descriptors=True)
        w = encrypt_and_unlock_wallet(node, name)
        z = w.z_getnewaddress()
        fund.z_shieldfunds(amount, z)
        self.generatetoaddress(node, 1, fmine, sync_fun=self.no_op)
        assert_equal(self.zbal(w), amount)
        path = str(node.datadir_path / f"{name}.btxwallet.json")
        w.exportwalletbundle(path, None, 1)
        return w, path

    def run_test(self):
        node = self.nodes[0]
        node.createwallet(wallet_name="fund", descriptors=True)
        fund = encrypt_and_unlock_wallet(node, "fund")
        fmine = fund.getnewaddress()
        fund_trusted_transparent_balance(self, node, fund, fmine, Decimal("10.0"), sync_fun=self.no_op)
        ensure_ring_diversity(self, node, fund, fmine, fund.z_getnewaddress())

        src, src_path = self.make_funded_bundle(node, fund, fmine, "src", Decimal("1.0"))

        self.log.info("(a) import into a wallet with no shielded keys: the note appears without a restart")
        node.createwallet(wallet_name="dst", descriptors=True)
        dst = encrypt_and_unlock_wallet(node, "dst")
        dst.importwalletbundle(src_path, True)
        assert_equal(self.zbal(dst), Decimal("1.0"))  # found immediately, no restart

        self.restart_node(0)
        # Re-acquire wallet handles: the restart rotates the RPC cookie, so the
        # pre-restart proxies (dst, fund) would be rejected.
        for name in ("dst", "fund"):
            if name not in node.listwallets():
                node.loadwallet(name)
        dst = node.get_wallet_rpc("dst")
        dst.walletpassphrase(SHIELDED_WALLET_PASSPHRASE, 999000)
        fund = node.get_wallet_rpc("fund")
        fund.walletpassphrase(SHIELDED_WALLET_PASSPHRASE, 999000)
        assert_equal(self.zbal(dst), Decimal("1.0"))  # still there after restart

        self.log.info("(same seed) re-importing the wallet's own bundle is refused too, with the same message")
        own_path = str(node.datadir_path / "dst_own.btxwallet.json")
        dst.exportwalletbundle(own_path, None, 1)
        # dst now holds shielded keys, so the guard fires for its own bundle too.
        # The message does not claim "another seed", so it is correct here as well.
        assert_raises_rpc_error(-4, "already has shielded keys or notes", dst.importwalletbundle, own_path, True)
        assert_equal(self.zbal(dst), Decimal("1.0"))  # the own note is untouched

        self.log.info("(b) import into a wallet with its own shielded note is refused; the own note survives")
        node.createwallet(wallet_name="dst2", descriptors=True)
        dst2 = encrypt_and_unlock_wallet(node, "dst2")
        dst2_z = dst2.z_getnewaddress()
        fund.z_shieldfunds(Decimal("2.0"), dst2_z)
        self.generatetoaddress(node, 1, fmine, sync_fun=self.no_op)
        assert_equal(self.zbal(dst2), Decimal("2.0"))
        assert_raises_rpc_error(-4, "already has shielded keys or notes", dst2.importwalletbundle, src_path, True)
        # The own note is untouched and still spendable.
        assert_equal(self.zbal(dst2), Decimal("2.0"))
        dst2.z_sendmany([{"address": dst2.getnewaddress(), "amount": Decimal("0.5")}])
        self.generatetoaddress(node, 1, fmine, sync_fun=self.no_op)
        assert self.zbal(dst2) > 0


if __name__ == "__main__":
    WalletImportBundleShieldedTest(__file__).main()
