#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Compare native Qt recovery on a disposable encrypted stale backup."""

from decimal import Decimal
import os
import subprocess
import time
from pathlib import Path
try:
    import pyatspi
except ImportError:
    pyatspi = None

from test_framework.authproxy import JSONRPCException
from test_framework.test_framework import BitcoinTestFramework, SkipTest
from test_framework.util import assert_equal, assert_raises_rpc_error


def shown_text(text):
    found = False
    def visit(node, depth=0):
        nonlocal found
        if found or depth > 25:
            return
        try:
            if text in node.name and node.getState().contains(pyatspi.STATE_SHOWING):
                found = True
            for child in node:
                if child is not None:
                    visit(child, depth+1)
        except (RuntimeError, AttributeError):
            pass
    visit(pyatspi.Registry.getDesktop(0))
    return found

def shown_buttons(prefix):
    matches = []
    def visit(node, depth=0):
        if depth > 25:
            return
        try:
            if node.getRoleName() == "push button" and node.name.lstrip("&").startswith(prefix):
                if node.getState().contains(pyatspi.STATE_SHOWING):
                    matches.append(node)
            for child in node:
                if child is not None:
                    visit(child, depth+1)
        except (RuntimeError, AttributeError):
            pass
    visit(pyatspi.Registry.getDesktop(0))
    return matches

def wait_for(predicate, seconds=25):
    until = time.monotonic() + seconds
    while time.monotonic() < until:
        result = predicate()
        if result:
            return result
        time.sleep(0.15)
    raise AssertionError("Expected native Qt observation unavailable")

def xdotool(*args):
    subprocess.run(["xdotool", *map(str, args)], check=True, timeout=6)

def click(label):
    (button,) = wait_for(lambda: shown_buttons(label))
    action = button.queryAction()
    assert action.nActions and action.doAction(0), label

def window(title):
    def match():
        query = subprocess.run(["xdotool", "search", "--onlyvisible", "--name", title],
                               capture_output=True, text=True, timeout=5)
        return query.stdout.split()
    try:
        (window_id,) = wait_for(match)
    except AssertionError:
        root = Path(os.environ["RECOVERY_RECORDS"])
        windows = subprocess.run(["wmctrl", "-l"], capture_output=True, text=True, timeout=5)
        (root/"observed-windows.txt").write_text(windows.stdout)
        subprocess.run(["scrot", str(root/"last-window.png")], check=False, timeout=5)
        raise
    xdotool("windowactivate", "--sync", window_id)

class EncryptedBackupRecoveryTest(BitcoinTestFramework):
    def add_options(self, parser):
        self.add_wallet_options(parser, legacy=False)
        parser.add_argument("--qt-binary", help="Native btx-qt binary; requires a Linux X11 session")
        parser.add_argument("--qt-records", help="Directory for native Qt test observations")
        parser.add_argument("--expect-action-absent", action="store_true",
                            help="Record the pre-change absence control instead of testing recovery")

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
        if pyatspi is None or not os.environ.get("DISPLAY") or not self.options.qt_binary:
            raise SkipTest("Requires --qt-binary, X11, pyatspi and the native Qt test tools")
        binary = Path(self.options.qt_binary)
        if not binary.is_file() or not os.access(binary, os.X_OK):
            raise AssertionError("Requested Qt executable is unavailable")

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
        genesis = node.getblockhash(0)
        root = Path(self.options.qt_records) if self.options.qt_records else node.datadir_path/"qt-records"
        root.mkdir(mode=0o700, parents=True, exist_ok=True)
        os.environ["RECOVERY_RECORDS"] = str(root)
        library = root/"scan-delay.so"
        subprocess.run(["cc", "-Wall", "-Wextra", "-Werror", "-fPIC", "-shared",
                        str(Path(__file__).with_name("qt_recovery_delay.c")),
                        "-o", str(library), "-ldl"], check=True, timeout=30)
        gate, observed = root/"delay.gate", root/"delay.observed"
        qt = str(Path(self.options.qt_binary).resolve())
        profile = node.datadir_path / "isolated-qt"
        profile.mkdir(mode=0o700)
        for name in ("runtime", "config", "data"):
            (profile/name).mkdir(mode=0o700)
        # The framework creates a default wallet and loads it on startup.
        # Remove other disposable wallets from startup before testing selection.
        for name in node.listwallets():
            if name != "encrypted-restored":
                node.unloadwallet(name, False)
        self.stop_node(0)
        node.args[0] = qt
        self.start_node(0, extra_args=node.extra_args + [
            "-server=1", "-splash=0", "-wallet=encrypted-restored"
        ], env={"QT_LINUX_ACCESSIBILITY_ALWAYS_ON": "1", "QT_QPA_PLATFORM": "xcb",
                "XDG_RUNTIME_DIR": str(profile/"runtime"),
                "XDG_CONFIG_HOME": str(profile/"config"),
                "XDG_DATA_HOME": str(profile/"data"),
                "LC_ALL": "C.UTF-8",
                "LD_PRELOAD": str(library),
                "BTX_RECOVERY_DELAY_GATE": str(gate),
                "BTX_RECOVERY_DELAY_OBSERVED": str(observed),
                "BTX_RECOVERY_SCAN_LOG": str(node.datadir_path/"regtest/debug.log"),
                "BTX_RECOVERY_SCAN_MARKER": "[encrypted-restored] Rescan started from block " + genesis})
        assert_equal(node.listwallets(), ["encrypted-restored"])
        wallet = node.get_wallet_rpc("encrypted-restored")
        assert_equal(receipts(wallet, case["addresses"])[0], before_receipts)
        assert_raises_rpc_error(-13, "walletpassphrase", wallet.keypoolrefill)
        # On the ordinary Transactions tab, establish that the window and
        # accessibility are working before interpreting a missing control.
        wait_for(lambda: subprocess.run(["xdotool", "search", "--onlyvisible", "--name", "regtest"],
                    capture_output=True, timeout=5).returncode == 0)
        ids = subprocess.check_output(["xdotool", "search", "--onlyvisible", "--name", "regtest"],
                                      text=True, timeout=5).split()
        assert len(ids) == 1, ids
        xdotool("windowactivate", "--sync", ids[0])
        xdotool("key", "alt+4")
        wait_for(lambda: shown_buttons("Export"))
        if self.options.expect_action_absent:
            assert not shown_buttons("Recover missing payments")
            self.log.info("BASELINE: Transactions tab renders and has no recovery action")
            return

        def begin(unlock=True, cancel_unlock=False):
            click("Recover missing payments")
            window("Recover missing payments")
            xdotool("key", "Return")  # Accept the displayed finite default of 20.
            click("Yes")
            if not unlock:
                return
            window("Unlock wallet")
            if cancel_unlock:
                xdotool("key", "Escape")
                return
            xdotool("type", "--clearmodifiers", "--", passphrase)
            xdotool("key", "Return")

        begin(cancel_unlock=True)
        wait_for(lambda: wallet.getwalletinfo()["scanning"] is False)
        assert_raises_rpc_error(-13, "walletpassphrase", wallet.keypoolrefill)
        self.log.info("CONTROL: cancelled unlock released recovery reservation and stayed locked")

        def arm_delay():
            observed.unlink(missing_ok=True)
            gate.write_text(str((node.datadir_path/"regtest/debug.log").stat().st_size))

        arm_delay()
        try:
            begin()
            wait_for(observed.is_file)
            assert_raises_rpc_error(-4, "currently rescanning", wallet.rescanblockchain, 0)
            try:
                click("Cancel")
            except AssertionError:
                windows = subprocess.run(["wmctrl", "-l"], capture_output=True, text=True, timeout=5)
                (root/"observed-windows.txt").write_text(windows.stdout)
                subprocess.run(["scrot", str(root/"cancel-window.png")], check=False, timeout=5)
                raise
        finally:
            gate.unlink(missing_ok=True)
        window("Recovery incomplete")
        wait_for(lambda: shown_text("Rescan aborted."))
        xdotool("key", "Return")
        wait_for(lambda: wallet.getwalletinfo()["scanning"] is False)
        assert_raises_rpc_error(-13, "walletpassphrase", wallet.keypoolrefill)
        assert_equal(receipts(wallet, case["addresses"])[0], before_receipts)
        self.log.info("CANDIDATE: active scan cancelled, reservation released, wallet relocked")
        begin()
        window("Recovery complete")
        subprocess.run(["scrot", str(root/"recovery-complete.png")], check=True, timeout=5)
        xdotool("key", "Return")
        assert_equal(receipts(wallet, case["addresses"]), (case["expected"], Decimal(3)))
        assert_equal(node.getbestblockhash(), tip)
        assert_raises_rpc_error(-13, "walletpassphrase", wallet.keypoolrefill)
        assert wallet.getwalletinfo()["scanning"] is False
        self.log.info("CANDIDATE: retry recovered both exact outpoints at the same tip and relocked")
        wallet.walletpassphrase(passphrase, 600)
        begin(unlock=False)
        window("Recovery complete")
        xdotool("key", "Return")
        wallet.keypoolrefill(1)  # An already-unlocked wallet is not relocked by the action.
        rpc_scan = wallet.rescanblockchain(0)
        assert_equal(rpc_scan["stop_height"], node.getblockcount())
        assert_equal(receipts(wallet, case["addresses"]), (case["expected"], Decimal(3)))
        wallet.walletlock()
        self.log.info("CONTROL: direct RPC rescan still reaches the same tip and preserves both receipts")
        self.log.info("CONTROL: action preserved an existing unlock and its RPC relock policy")

        # Hold a real scan read, then extend the chain and grant a newer RPC
        # unlock. The GUI operation must complete its original range and leave
        # the newer unlock under its own timer.
        arm_delay()
        try:
            begin()
            wait_for(observed.is_file)
            wallet.walletpassphrase(passphrase, 600)
            before_height = node.getblockcount()
            self.generatetoaddress(node, 1, mining_address, sync_fun=self.no_op)
            assert_equal(node.getblockcount(), before_height + 1)
        finally:
            gate.unlink(missing_ok=True)
        window("Recovery complete")
        xdotool("key", "Return")
        assert_equal(receipts(wallet, case["addresses"]), (case["expected"], Decimal(3)))
        wallet.keypoolrefill(1)
        wallet.walletlock()
        self.log.info("CONTROL: new block and newer RPC unlock survived the recovery completion")



if __name__ == "__main__":
    EncryptedBackupRecoveryTest(__file__).main()
