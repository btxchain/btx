#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Warn on locked encrypted-backup restore and verify explicit receipt recovery."""

from decimal import Decimal

from test_framework.authproxy import JSONRPCException
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_raises_rpc_error


RECOVERY_WARNING = (
    "This encrypted wallet was restored while locked. Payments to addresses used "
    "after this backup may be missing. Unlock the wallet, refill its keypool with "
    "keypoolrefill, then use rescanblockchain to scan the available history. "
    "Unlocking alone does not recover those payments. If addresses remain outside "
    "the derived range or required blocks are unavailable, recovery is incomplete."
)


class EncryptedBackupRecoveryTest(BitcoinTestFramework):
    def add_options(self, parser):
        self.add_wallet_options(parser, legacy=False)

    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        # Wallet-only fixture: explicitly avoid the independent default-consensus
        # block-100 setup problem. These policies do not qualify consensus.
        self.extra_args = [[
            "-keypool=4", "-modelnet=0", "-autoshieldcoinbase=0",
            "-connect=0", "-dnsseed=0", "-matmulvalidation=economic",
            "-matmulrcexecution=cpu-diagnostic",
        ]]

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()
        self.skip_if_no_sqlite()

    def run_test(self):
        node = self.nodes[0]
        passphrase = "disposable-regtest-only"
        receipt_txids = []

        def receipts(wallet, addresses):
            # Check recognition, not AvailableCoins/locked signing capability.
            rows = []
            for txid in receipt_txids:
                try:
                    tx = wallet.gettransaction(txid)
                except JSONRPCException as error:
                    if error.error["code"] == -5:
                        continue
                    raise
                assert tx["confirmations"] >= 1
                rows.extend(
                    (f"{txid}:{detail['vout']}", detail["amount"])
                    for detail in tx["details"]
                    if detail["category"] == "receive" and detail.get("address") in addresses
                )
            return sorted(outpoint for outpoint, _ in rows), sum((amount for _, amount in rows), Decimal(0))

        node.createwallet(wallet_name="funder", descriptors=True)
        funder = node.get_wallet_rpc("funder")
        mining_address = funder.getnewaddress()
        self.generatetoaddress(node, 101, mining_address, sync_fun=self.no_op)

        cases = {}
        for name, encrypted in [("encrypted", True), ("plain", False)]:
            node.createwallet(wallet_name=name, descriptors=True, **({"passphrase": passphrase} if encrypted else {}))
            wallet = node.get_wallet_rpc(name)
            if encrypted:
                wallet.walletpassphrase(passphrase, 600)
            known_address = wallet.getnewaddress()
            remaining = wallet.getwalletinfo()["keypoolsize"]
            assert 0 < remaining <= 32
            backup = node.datadir_path / f"{name}-stale.bak"
            wallet.backupwallet(str(backup))
            # A genuinely issued address just beyond the backup's cached range.
            for _ in range(remaining + 1):
                later_address = wallet.getnewaddress()
            assert later_address != known_address
            if encrypted:
                wallet.walletlock()
            cases[name] = {"wallet": wallet, "addresses": [known_address, later_address], "backup": backup}

        # Separate blocks let the unencrypted restore extend its range when it
        # encounters the earlier known script, before the later payment.
        for position in (0, 1):
            destinations = {case["addresses"][position]: Decimal(position + 1) for case in cases.values()}
            receipt_txids.append(funder.sendmany("", destinations))
            self.generatetoaddress(node, 1, mining_address, sync_fun=self.no_op)

        for name, case in cases.items():
            expected, total = receipts(case["wallet"], case["addresses"])
            assert_equal(len(expected), 2)
            assert_equal(total, Decimal(3))
            case["expected"] = expected
            node.unloadwallet(name)
        self.log.info("CONTROL: original locked encrypted wallet recognizes both receipts")

        assert_raises_rpc_error(-8, "Backup file does not exist", node.restorewallet,
                                "missing-backup", str(node.datadir_path / "does-not-exist.bak"))
        assert "missing-backup" not in node.listwallets()

        plain = cases["plain"]
        plain_result = node.restorewallet("plain-restored", str(plain["backup"]))
        assert RECOVERY_WARNING not in plain_result.get("warnings", [])
        assert_equal(receipts(node.get_wallet_rpc("plain-restored"), plain["addresses"]), (plain["expected"], Decimal(3)))
        self.log.info("CONTROL: plain backup recovers both receipts without encrypted recovery warning")

        case = cases["encrypted"]
        restored = node.restorewallet("encrypted-restored", str(case["backup"]))
        wallet = node.get_wallet_rpc("encrypted-restored")
        warnings = restored.get("warnings", [])
        assert any("contains shielded state" in warning for warning in warnings)
        assert_equal(wallet.getwalletinfo()["unlocked_until"], 0)
        before_receipts, _ = receipts(wallet, case["addresses"])
        assert_equal(len(before_receipts), 1)
        assert_raises_rpc_error(-13, "walletpassphrase", wallet.keypoolrefill)
        assert_raises_rpc_error(-14, "incorrect", wallet.walletpassphrase, "wrong-disposable-passphrase", 600)
        assert_equal(wallet.getwalletinfo()["unlocked_until"], 0)
        assert_equal(receipts(wallet, case["addresses"])[0], before_receipts)

        tip = node.getbestblockhash()
        wallet.walletpassphrase(passphrase, 600)
        wallet.keypoolrefill()
        assert wallet.getaddressinfo(case["addresses"][1])["ismine"]
        assert_equal(receipts(wallet, case["addresses"])[0], before_receipts)
        scan = wallet.rescanblockchain(0)
        assert_equal(scan["start_height"], 0)
        assert_equal(scan["stop_height"], node.getblockcount())
        assert_equal(receipts(wallet, case["addresses"]), (case["expected"], Decimal(3)))
        assert_equal(node.getbestblockhash(), tip)
        wallet.walletlock()
        assert_equal(wallet.getwalletinfo()["unlocked_until"], 0)
        self.log.info("RECOVERY: explicit refill/rescan restores exact receipts at same tip; relock succeeds")

        # Last so the baseline must reach and satisfy the same recovery controls
        # before failing specifically on the missing guidance contract.
        assert_equal(warnings.count(RECOVERY_WARNING), 1)


if __name__ == "__main__":
    EncryptedBackupRecoveryTest(__file__).main()
