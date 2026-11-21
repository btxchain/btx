#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see COPYING.
"""W3: seed restore with missing history, then same-database full-history recovery.

Reuses JPP's #703 restore control, repch1c's #717/#741 recovery fixes,
and the existing manual-pruning setup. Disposable regtest wallets only.
"""
from decimal import Decimal
from pathlib import Path
import hashlib
import json
import os
import shutil
import sys

from test_framework.shielded_utils import (
    SHIELDED_WALLET_PASSPHRASE as PASSPHRASE,
    encrypt_and_unlock_wallet,
    ensure_ring_diversity,
    fund_trusted_transparent_balance,
)
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_greater_than, assert_raises_rpc_error

COMMON = ["-autoshieldcoinbase=0", "-regtestshieldedmatrictdisableheight=500", "-daemon=0"]
PRUNED = COMMON + ["-prune=1", "-fastprune"]
MAX_PRUNE_HEIGHT = 488  # Reserve headroom below the inherited height-500 boundary.


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def note_set(wallet):
    # These are disposable notes. Do not record nullifiers or any seed material.
    rows = wallet.z_listunspent(1, 9999999, False, True)
    notes = sorted((row["commitment"], str(Decimal(row["amount"])), row["block_hash"])
                   for row in rows)
    assert_equal(len(notes), len({note[0] for note in notes}))
    return notes


def descriptor_identity(wallet):
    # Keypool ranges can legitimately refresh at unlock; compare public authority identity.
    return sorted((row["desc"], row.get("internal", False), row.get("active", False))
                  for row in wallet.listdescriptors()["descriptors"])


class WalletSeedPrunedRecovery(BitcoinTestFramework):
    def add_options(self, parser):
        self.add_wallet_options(parser)

    def set_test_params(self):
        self.num_nodes = 2
        self.setup_clean_chain = True
        self.extra_args = [COMMON, PRUNED]
        self.rpc_timeout = 600

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()
        self.skip_if_no_sqlite()

    def event(self, stage, **data):
        self.events.append({"stage": stage, **data})
        self.write_record()

    def write_record(self):
        if self.record_path is None:
            return
        self.record_path.write_text(json.dumps({"status": self.outcome, "events": self.events,
                                               "setup": self.setup_diagnostics},
                                              indent=2, default=str) + "\n")

    def mine(self, blocks, address):
        assert blocks >= 0
        assert self.nodes[0].getblockcount() + blocks < 495, "Fixture crosses proof-profile boundary"
        if blocks:
            self.generatetoaddress(self.nodes[0], blocks, address, sync_fun=self.no_op)
        self.sync_blocks()

    def block_location(self, node, block_hash):
        """Read this disposable node's files only; never modify storage or expose XOR bytes."""
        payload = bytes.fromhex(node.getblock(block_hash, 0))
        directory = node.blocks_path
        key = node.read_xor_key()
        assert_equal(len(key), 8)  # Pinned InitBlocksdirXorKey std::array format.
        matches = []
        total = 0
        for path in sorted(directory.glob("blk*.dat")):
            size = path.stat().st_size
            total += size
            assert size <= 8 * 1024 * 1024 and total <= 64 * 1024 * 1024, "SETUP: block-file diagnostic budget"
            encoded = path.read_bytes()
            decoded = bytes(value ^ key[index % 8] for index, value in enumerate(encoded))
            offset = decoded.find(payload)
            if offset >= 0:
                assert decoded.find(payload, offset + 1) < 0
                matches.append({"file": path.name, "file_number": int(path.stem[3:]),
                                "payload_offset": offset, "allocated_bytes": size})
        assert_equal(len(matches), 1)
        return matches[0]

    def close_receipt_file(self, payer, mining, receipt_hash):
        # A normal payer self-send (as in the existing prune/reorg fixture), not
        # padding spam or a custom block/consensus bypass. Its measured block size
        # is an explicit prerequisite for the pinned fastprune rollover rule.
        b = self.nodes[1]
        receipt_file = self.block_location(b, receipt_hash)
        self.setup_diagnostics["receipt_file"] = receipt_file
        self.write_record()
        delimiter = payer.z_sendmany([{"address": payer.z_getnewaddress(), "amount": Decimal("1.0")}])
        assert delimiter["txid"] in self.nodes[0].getrawmempool()
        self.mine(1, mining)
        delimiter_hash = self.nodes[0].getbestblockhash()
        delimiter_block = self.nodes[0].getblock(delimiter_hash)
        delimiter_file = self.block_location(b, delimiter_hash)
        self.setup_diagnostics.update(delimiter_block=delimiter_hash,
                                      delimiter_height=delimiter_block["height"],
                                      delimiter_bytes=delimiter_block["size"],
                                      delimiter_file=delimiter_file)
        self.write_record()
        assert delimiter_block["size"] >= 65536, "SETUP: ordinary self-send did not create a fastprune boundary block"
        assert_greater_than(delimiter_file["file_number"], receipt_file["file_number"])
        # A following small block forces a new file after an oversized delimiter.
        self.mine(1, mining)
        following_hash = self.nodes[0].getbestblockhash()
        following_file = self.block_location(b, following_hash)
        self.setup_diagnostics["following_file"] = following_file
        self.write_record()
        assert_greater_than(following_file["file_number"], delimiter_file["file_number"])
        assert_equal(self.block_location(b, receipt_hash)["file"], receipt_file["file"])
        # No future block existed when the delimiter was synced: the receipt file
        # is now sealed with last height <= H, below H+328-288-10-1.

    def complete(self, wallet):
        report = wallet.z_verifywalletintegrity()
        assert_equal(report["scan_incomplete"], False)
        assert_equal(report["master_seed_available"], True)
        assert_equal(report["integrity_ok"], True)
        return report

    def incomplete(self, wallet):
        # Assert a public current-state diagnostic after unlock, not serialized schema.
        report = wallet.z_verifywalletintegrity()
        assert_equal(report["master_seed_available"], True)
        assert_equal(report["scan_incomplete"], True)
        assert_equal(report["integrity_ok"], False)
        assert_equal(wallet.z_getbalance().get("scan_incomplete", False), True)
        return report

    def run_test(self):
        assert_equal(self.chain, "regtest")
        record_path = os.getenv("BTX_TEST_WALLET_RECOVERY_RECORDS")
        self.record_path = Path(record_path) if record_path else None
        if self.record_path:
            self.record_path.parent.mkdir(parents=True, exist_ok=True)
        self.events = []
        self.setup_diagnostics = {}
        self.outcome = "IN_PROGRESS"
        self.secret_paths = []
        try:
            self.scenario()
            self.outcome = "PASS"
        except BaseException:
            self.outcome = "FAIL"
            raise
        finally:
            # Default framework intentionally leaves nodes up on failure; this fixture doesn't.
            active_error = sys.exc_info()[0] is not None
            try:
                self.stop_nodes()
            except Exception as error:
                self.outcome = "FAIL"
                self.events.append({"stage": "CLEANUP_FAILURE", "type": type(error).__name__})
                if not active_error:
                    raise
            finally:
                for path in self.secret_paths:
                    path.unlink(missing_ok=True)
                self.write_record()

    def scenario(self):
        a, b = self.nodes
        a.createwallet(wallet_name="payer", descriptors=True)
        payer = encrypt_and_unlock_wallet(a, "payer")
        mining = payer.getnewaddress()
        # Helpers from the pinned framework; do not duplicate their funding/proof logic.
        fund_trusted_transparent_balance(self, a, payer, mining, Decimal("10"), sync_fun=self.no_op)
        self.sync_blocks()
        ensure_ring_diversity(self, a, payer, mining, payer.z_getnewaddress(), sync_fun=self.no_op)
        self.sync_blocks()
        a.createwallet(wallet_name="original", descriptors=True)
        original = encrypt_and_unlock_wallet(a, "original")
        original_address = original.z_getnewaddress()
        funding = payer.z_shieldfunds(Decimal("1"), original_address)
        self.sync_mempools()
        self.mine(1, mining)
        block_hash = a.getbestblockhash()
        height = a.getblockcount()
        expected_notes = note_set(original)
        assert_equal(len(expected_notes), 1)
        assert_equal(Decimal(expected_notes[0][1]), Decimal("1"))
        assert_equal(expected_notes[0][2], block_hash)
        assert_equal(Decimal(original.z_getbalance()["balance"]), Decimal("1"))
        seed_a = a.datadir_path / "disposable-w3.btxwallet.json"
        seed_b = b.datadir_path / "disposable-w3.btxwallet.json"
        self.secret_paths.extend([seed_a, seed_b])
        exported = original.exportwalletbundle(str(seed_a), None, 1)
        assert_equal(exported["success"], True)
        assert_equal(json.loads(seed_a.read_text())["birthday"], 1)
        shutil.copy2(seed_a, seed_b)
        assert_equal(digest(seed_a), digest(seed_b))
        # Capture public identities only; never log/export JSON seed bytes.
        control = a.restorewalletbundle("healthy", str(seed_a), None, True, PASSPHRASE)
        healthy = a.get_wallet_rpc("healthy")
        healthy.walletpassphrase(PASSPHRASE, 999000)
        assert_equal(note_set(healthy), expected_notes)
        self.complete(healthy)
        identity = control["first_receive_address"]
        assert_equal(identity, exported["first_receive_address"])
        a.unloadwallet("healthy", False)
        a.unloadwallet("original", False)
        self.event("HEALTHY_CONTROL", original_note=expected_notes, block=block_hash,
                   height=height, bundle_sha256=digest(seed_a), first_receive=identity,
                   funding_txid=funding["txid"])

        self.close_receipt_file(payer, mining, block_hash)
        target = height + 288 + 40
        assert target <= MAX_PRUNE_HEIGHT, "Fixture setup left insufficient pruning headroom"
        self.mine(target - a.getblockcount(), mining)
        while True:
            returned = b.pruneblockchain(height + 100)
            prune_height = b.getblockchaininfo()["pruneheight"]
            self.setup_diagnostics.setdefault("prune_attempts", []).append(
                {"tip": a.getblockcount(), "requested": height + 100, "returned": returned,
                 "pruneheight": prune_height, "buffered_retention_ceiling": a.getblockcount() - 288 - 10 - 1,
                 "initialblockdownload": b.getblockchaininfo()["initialblockdownload"],
                 "receipt_file_present": (b.blocks_path / self.setup_diagnostics["receipt_file"]["file"]).exists(),
                 "block_files": [{"file": path.name, "allocated_bytes": path.stat().st_size}
                                 for path in sorted(b.blocks_path.glob("blk*.dat"))]})
            self.write_record()
            if prune_height > height:
                break
            remaining = MAX_PRUNE_HEIGHT - a.getblockcount()
            assert remaining > 0, "SETUP: note block not actually pruned within bounded profile"
            self.mine(min(8, remaining), mining)
        assert_equal(a.getbestblockhash(), b.getbestblockhash())
        assert_raises_rpc_error(-1, "pruned data", b.getblock, block_hash)
        assert_equal(a.getblock(block_hash)["hash"], block_hash)
        self.event("PRUNE_ADMITTED", pruneheight=b.getblockchaininfo()["pruneheight"],
                   tip=a.getblockcount(), original_block_missing=True)
        # Creation precedes the history preflight; a failed destination may remain.
        assert_raises_rpc_error(-4, "Pruned blocks", b.restorewalletbundle,
                                "refused", str(seed_b), None, True, PASSPHRASE)
        if "refused" in b.listwallets():
            b.unloadwallet("refused", False)
        imported = b.restorewalletbundle("deferred", str(seed_b), None, False, PASSPHRASE)
        assert_equal(imported["success"], True)
        assert_equal(imported["rescan"], False)
        assert_equal(imported["first_receive_address"], identity)
        deferred = b.get_wallet_rpc("deferred")
        deferred.walletpassphrase(PASSPHRASE, 999000)
        self.incomplete(deferred)
        before = descriptor_identity(deferred)
        assert_raises_rpc_error(-1, "pruned data", deferred.rescanblockchain, 0)
        assert_equal(descriptor_identity(deferred), before)
        self.incomplete(deferred)
        self.event("INCOMPLETE_RECOVERY", first_receive=identity, failed_full_scan=True)

        deferred.walletlock()
        self.restart_node(1, extra_args=PRUNED)
        self.connect_nodes(1, 0)
        self.sync_blocks()
        if "deferred" not in b.listwallets():
            b.loadwallet("deferred")
        deferred = b.get_wallet_rpc("deferred")
        deferred.walletpassphrase(PASSPHRASE, 999000)
        self.incomplete(deferred)
        assert_equal(descriptor_identity(deferred), before)
        backup_b = b.datadir_path / "disposable-w3.backup.dat"
        backup_a = a.datadir_path / "disposable-w3.backup.dat"
        self.secret_paths.extend([backup_a, backup_b])
        deferred.walletlock()
        deferred.backupwallet(str(backup_b))
        b.unloadwallet("deferred", False)
        shutil.copy2(backup_b, backup_a)
        assert_equal(digest(backup_b), digest(backup_a))
        self.event("DURABLE_DATABASE", backup_sha256=digest(backup_a), first_receive=identity)

        a.restorewallet("recovered", str(backup_a))
        recovered = a.get_wallet_rpc("recovered")
        recovered.walletpassphrase(PASSPHRASE, 999000)
        assert_equal(descriptor_identity(recovered), before)
        recovered.rescanblockchain(0)
        self.complete(recovered)
        assert_equal(note_set(recovered), expected_notes)
        assert_equal(Decimal(recovered.z_getbalance()["balance"]), Decimal("1"))
        # No original/control wallet is allowed to supply authority at this stage.
        assert "original" not in a.listwallets() and "healthy" not in a.listwallets()
        a.createwallet(wallet_name="recipient", descriptors=True)
        recipient = encrypt_and_unlock_wallet(a, "recipient")
        amount = Decimal("0.25")
        sent = recovered.z_sendmany([{"address": recipient.z_getnewaddress(), "amount": amount}])
        txid = sent["txid"]
        assert txid in a.getrawmempool(), "Real broadcast required, not just a returned txid"
        fee = Decimal(sent["fee"])
        assert fee >= 0
        self.mine(1, mining)
        assert_greater_than(recovered.gettransaction(txid)["confirmations"], 0)
        assert_equal(Decimal(recipient.z_getbalance()["balance"]), amount)
        expected_change = Decimal("1") - amount - fee
        assert_greater_than(expected_change, 0)
        assert_equal(Decimal(recovered.z_getbalance()["balance"]), expected_change)
        after_spend = note_set(recovered)
        assert not any(n[0] == expected_notes[0][0] for n in after_spend)
        self.restart_node(0, extra_args=COMMON)
        self.connect_nodes(1, 0)
        self.sync_blocks()
        for name in ["payer", "recovered", "recipient"]:
            if name not in a.listwallets():
                a.loadwallet(name)
        assert "original" not in a.listwallets() and "healthy" not in a.listwallets()
        recovered = a.get_wallet_rpc("recovered")
        recipient = a.get_wallet_rpc("recipient")
        payer = a.get_wallet_rpc("payer")
        for wallet in [recovered, recipient, payer]:
            wallet.walletpassphrase(PASSPHRASE, 999000)
        self.complete(recovered)
        assert_equal(note_set(recovered), after_spend)
        assert_equal(Decimal(recipient.z_getbalance()["balance"]), amount)
        assert_greater_than(recovered.gettransaction(txid)["confirmations"], 0)
        # Fresh receive capability, without importing the original seed again.
        second = payer.z_sendmany([{"address": recovered.z_getnewaddress(), "amount": Decimal("0.1")}])
        assert second["txid"] in a.getrawmempool()
        self.mine(1, mining)
        assert_equal(Decimal(recovered.z_getbalance()["balance"]), expected_change + Decimal("0.1"))
        self.event("CONFIRMED_CONTINUED_USE", spend_txid=txid, fee=fee,
                   sender_change=expected_change, recipient_received=amount,
                   later_receive_txid=second["txid"], final_height=a.getblockcount())


if __name__ == "__main__":
    WalletSeedPrunedRecovery(__file__).main()
