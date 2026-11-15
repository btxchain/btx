#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""Check what backupwalletbundle and backupwalletbundlearchive say about an encrypted wallet's seeds.

Both exports write listdescriptors_private.json, which holds the private
descriptors with their PQ seeds in plaintext. A wallet that imports only that
file can sign for the encrypted wallet's addresses without its passphrase, so
the exports must not report that the wallet passphrase is required to spend.
"""

import json
from pathlib import Path
import re

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_raises_rpc_error

PASSPHRASE = "pass"
ARCHIVE_PASSPHRASE = "archive-pass"
PRIVATE_PQHD = re.compile(r"pqhd\(([0-9a-f]{64,})/")


class WalletBackupBundlePrivateDescriptorsTest(BitcoinTestFramework):
    def add_options(self, parser):
        self.add_wallet_options(parser, legacy=False)

    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.extra_args = [[]]

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()
        self.skip_if_no_sqlite()

    def run_test(self):
        node = self.nodes[0]
        node.createwallet(wallet_name="source", descriptors=True, passphrase=PASSPHRASE)
        source = node.get_wallet_rpc("source")
        source_addr = source.getnewaddress()
        source.walletlock()
        assert_raises_rpc_error(-13, "walletpassphrase first", source.listdescriptors, True)

        self.log.info("The directory bundle of an encrypted wallet holds its PQ seeds in plaintext")
        bundle = source.backupwalletbundle(node.datadir_path / "source.bundle", PASSPHRASE)
        assert_equal(bundle["wallet_encrypted"], True)
        bundle_path = Path(bundle["bundle_dir"])
        private_path = bundle_path / "listdescriptors_private.json"
        assert str(private_path) in bundle["files"]
        descriptors = json.loads(private_path.read_text(encoding="utf-8"))["descriptors"]
        assert len(descriptors) > 0
        for entry in descriptors:
            assert PRIVATE_PQHD.search(entry["desc"]), entry["desc"]

        self.log.info("A new unencrypted wallet that imports only that file signs for the source wallet's address")
        node.createwallet(wallet_name="imported", descriptors=True, blank=True)
        imported = node.get_wallet_rpc("imported")
        requests = []
        for entry in descriptors:
            request = {"desc": entry["desc"], "timestamp": 0, "active": entry["active"], "internal": entry.get("internal", False)}
            if "range" in entry:
                request["range"] = entry["range"]
            if "next_index" in entry:
                request["next_index"] = entry["next_index"]
            requests.append(request)
        assert all(result["success"] for result in imported.importdescriptors(requests))
        assert "unlocked_until" not in imported.getwalletinfo()
        info = imported.getaddressinfo(source_addr)
        assert_equal(info["ismine"], True)
        prevout = {"txid": "11" * 32, "vout": 0}
        raw = node.createrawtransaction([prevout], [{imported.getnewaddress(): 0.999}])
        signed = imported.signrawtransactionwithwallet(raw, [{**prevout, "scriptPubKey": info["scriptPubKey"], "amount": 1}])
        assert_equal(signed["complete"], True)

        self.log.info("So the bundle must not claim that the wallet passphrase is needed to spend, and must say why")
        assert_equal(bundle["wallet_passphrase_required_to_spend"], False)
        manifest = json.loads((bundle_path / "manifest.json").read_text(encoding="utf-8"))
        assert_equal(manifest["private_descriptors_exported"], True)
        assert_equal(manifest["wallet_encrypted"], True)
        assert_equal(manifest["wallet_passphrase_required_to_spend"], False)
        export_log = (bundle_path / "export_warnings.log").read_text(encoding="utf-8")
        for warnings in (bundle["warnings"], manifest["warnings"], export_log.splitlines()):
            assert any("Wallet passphrase is not stored" in warning for warning in warnings)
            assert any(
                "listdescriptors_private.json in this bundle" in warning and "without the wallet passphrase" in warning
                for warning in warnings
            ), warnings

        self.log.info("The archive holds the same file, protected only by the archive passphrase")
        archive = source.backupwalletbundlearchive(node.datadir_path / "source.bundle.btx", ARCHIVE_PASSPHRASE, PASSPHRASE)
        assert "listdescriptors_private.json" in archive["bundle_files"]
        assert_equal(archive["wallet_encrypted"], True)
        assert_equal(archive["wallet_passphrase_required_to_spend"], False)
        assert any(
            "listdescriptors_private.json in this archive" in warning and "archive passphrase" in warning
            for warning in archive["warnings"]
        ), archive["warnings"]

        self.log.info("Restoring the archive still gives an encrypted wallet that needs its passphrase")
        restore = node.restorewalletbundlearchive("restored", archive["archive_file"], ARCHIVE_PASSPHRASE)
        assert_equal(restore["bundled_manifest"]["private_descriptors_exported"], True)
        assert_equal(restore["bundled_manifest"]["wallet_passphrase_required_to_spend"], False)
        assert any("archive passphrase only decrypted" in warning for warning in restore["warnings"])
        restored = node.get_wallet_rpc("restored")
        assert_equal(restored.getwalletinfo()["unlocked_until"], 0)
        assert_raises_rpc_error(-13, "walletpassphrase first", restored.listdescriptors, True)


if __name__ == "__main__":
    WalletBackupBundlePrivateDescriptorsTest(__file__).main()
