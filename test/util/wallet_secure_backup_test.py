#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.

from io import StringIO
from pathlib import Path
import importlib.util
import sys
import tempfile
import unittest


MODULE_PATH = Path(__file__).resolve().parents[2] / "scripts" / "wallet_secure_backup.py"
SPEC = importlib.util.spec_from_file_location("wallet_secure_backup", MODULE_PATH)
wallet_secure_backup = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
sys.modules[SPEC.name] = wallet_secure_backup
SPEC.loader.exec_module(wallet_secure_backup)


class FakeCLIContext:
    def __init__(self):
        self.calls = []

    def run_json(self, method, *args, **kwargs):
        self.calls.append((method, args, kwargs))
        if method == "getwalletinfo":
            return {"private_keys_enabled": True, "unlocked_until": 1}
        if method == "backupwalletbundlearchive":
            return {
                "archive_file": str(args[0]),
                "archive_sha256": "00" * 32,
                "bundle_name": "wallet.bundle",
                "bundle_files": ["manifest.json", "getbalances.json"],
                "warnings": [],
                "integrity": {"integrity_ok": True},
            }
        raise AssertionError(f"unexpected method {method}")

    def run_text(self, method, *args, **kwargs):
        raise AssertionError(f"unexpected text RPC {method}")


class WalletSecureBackupTest(unittest.TestCase):
    def test_plaintext_export_writes_wallet_balances_snapshot(self):
        class PlaintextFakeCLIContext:
            def __init__(self):
                self.calls = []

            def run_json(self, method, *args, **kwargs):
                self.calls.append((method, args, kwargs))
                if method == "getwalletinfo":
                    return {"private_keys_enabled": True, "unlocked_until": 1}
                if method == "getbalances":
                    return {"mine": {"trusted": "3.5", "untrusted_pending": "0", "immature": "0"}}
                if method == "z_gettotalbalance":
                    return {"transparent": "3.5", "shielded": "0", "total": "3.5"}
                if method == "z_verifywalletintegrity":
                    return {"integrity_ok": True, "warnings": ["rehydrate after unlock"]}
                if method == "listdescriptors":
                    return {"descriptors": []}
                if method == "z_listaddresses":
                    return []
                raise AssertionError(f"unexpected method {method}")

            def run_text(self, method, *args, **kwargs):
                self.calls.append((method, args, kwargs))
                if method == "backupwallet":
                    return ""
                raise AssertionError(f"unexpected text RPC {method}")

        ctx = PlaintextFakeCLIContext()
        warnings_handle = StringIO()
        with tempfile.TemporaryDirectory() as tempdir:
            wallet_dir = Path(tempdir) / "wallet"
            result = wallet_secure_backup.export_wallet(
                ctx,
                "wallet",
                wallet_dir,
                unlock_timeout=30,
                skip_viewing_keys=False,
                warnings_handle=warnings_handle,
            )

            self.assertEqual(result["backup_file"], str(wallet_dir / "wallet.backup.dat"))
            self.assertTrue(result["integrity_ok"])
            self.assertEqual(result["integrity_warnings"], ["rehydrate after unlock"])
            self.assertTrue((wallet_dir / "getbalances.json").is_file())
            balances = (wallet_dir / "getbalances.json").read_text(encoding="utf-8")
            self.assertIn('"trusted": "3.5"', balances)
            integrity = (wallet_dir / "z_verifywalletintegrity.json").read_text(encoding="utf-8")
            self.assertIn('"integrity_ok": true', integrity)
            backup_index = next(i for i, call in enumerate(ctx.calls) if call[0] == "backupwallet")
            integrity_index = next(i for i, call in enumerate(ctx.calls) if call[0] == "z_verifywalletintegrity")
            self.assertLess(integrity_index, backup_index)
            self.assertIn("rehydrate after unlock", warnings_handle.getvalue())

    def test_archive_export_passes_placeholder_wallet_passphrase_and_bool(self):
        ctx = FakeCLIContext()
        warnings_handle = StringIO()
        with tempfile.TemporaryDirectory() as tempdir:
            archive_path = Path(tempdir) / "wallet.bundle.btx"
            result = wallet_secure_backup.export_wallet_archive(
                ctx,
                "wallet",
                archive_path,
                unlock_timeout=30,
                skip_viewing_keys=True,
                archive_passphrase="archive-pass",
                warnings_handle=warnings_handle,
            )

        self.assertEqual(result["bundle_files"], ["manifest.json", "getbalances.json"])
        backup_call = next(call for call in ctx.calls if call[0] == "backupwalletbundlearchive")
        self.assertEqual(backup_call[1], (str(archive_path), "", "false"))
        self.assertEqual(backup_call[2]["input_text"], "archive-pass\n")
        self.assertEqual(backup_call[2]["extra_cli_args"], ["-stdinbundlepassphrase"])

    def test_archive_export_uses_rpc_default_viewing_key_policy(self):
        ctx = FakeCLIContext()
        warnings_handle = StringIO()
        with tempfile.TemporaryDirectory() as tempdir:
            archive_path = Path(tempdir) / "wallet.bundle.btx"
            wallet_secure_backup.export_wallet_archive(
                ctx,
                "wallet",
                archive_path,
                unlock_timeout=30,
                skip_viewing_keys=False,
                archive_passphrase="archive-pass",
                warnings_handle=warnings_handle,
            )

        backup_call = next(call for call in ctx.calls if call[0] == "backupwalletbundlearchive")
        self.assertEqual(backup_call[1], (str(archive_path), ""))
        self.assertEqual(backup_call[2]["input_text"], "archive-pass\n")
        self.assertEqual(backup_call[2]["extra_cli_args"], ["-stdinbundlepassphrase"])

    def test_archive_export_records_integrity_warnings(self):
        class IntegrityWarningCLIContext(FakeCLIContext):
            def run_json(self, method, *args, **kwargs):
                self.calls.append((method, args, kwargs))
                if method == "getwalletinfo":
                    return {"private_keys_enabled": True, "unlocked_until": 1}
                if method == "backupwalletbundlearchive":
                    return {
                        "archive_file": str(args[0]),
                        "archive_sha256": "00" * 32,
                        "bundle_name": "wallet.bundle",
                        "bundle_files": ["manifest.json", "getbalances.json"],
                        "warnings": [],
                        "integrity": {
                            "integrity_ok": False,
                            "warnings": ["shielded scan is incomplete"],
                        },
                    }
                raise AssertionError(f"unexpected method {method}")

        ctx = IntegrityWarningCLIContext()
        warnings_handle = StringIO()
        with tempfile.TemporaryDirectory() as tempdir:
            archive_path = Path(tempdir) / "wallet.bundle.btx"
            result = wallet_secure_backup.export_wallet_archive(
                ctx,
                "wallet",
                archive_path,
                unlock_timeout=30,
                skip_viewing_keys=False,
                archive_passphrase="archive-pass",
                warnings_handle=warnings_handle,
            )

        self.assertEqual(result["integrity_ok"], False)
        self.assertEqual(result["integrity_warnings"], ["shielded scan is incomplete"])
        self.assertIn("wallet\tintegrity\tshielded scan is incomplete", warnings_handle.getvalue())

    def test_plaintext_export_surfaces_generic_integrity_failure(self):
        class IntegrityFailureCLIContext:
            def __init__(self):
                self.calls = []

            def run_json(self, method, *args, **kwargs):
                self.calls.append((method, args, kwargs))
                if method == "getwalletinfo":
                    return {"private_keys_enabled": True, "unlocked_until": 1}
                if method == "getbalances":
                    return {"mine": {"trusted": "3.5", "untrusted_pending": "0", "immature": "0"}}
                if method == "z_gettotalbalance":
                    return {"transparent": "3.5", "shielded": "0", "total": "3.5"}
                if method == "z_verifywalletintegrity":
                    return {"integrity_ok": False, "warnings": []}
                if method == "listdescriptors":
                    return {"descriptors": []}
                if method == "z_listaddresses":
                    return []
                raise AssertionError(f"unexpected method {method}")

            def run_text(self, method, *args, **kwargs):
                self.calls.append((method, args, kwargs))
                if method == "backupwallet":
                    return ""
                raise AssertionError(f"unexpected text RPC {method}")

        ctx = IntegrityFailureCLIContext()
        warnings_handle = StringIO()
        with tempfile.TemporaryDirectory() as tempdir:
            wallet_dir = Path(tempdir) / "wallet"
            result = wallet_secure_backup.export_wallet(
                ctx,
                "wallet",
                wallet_dir,
                unlock_timeout=30,
                skip_viewing_keys=False,
                warnings_handle=warnings_handle,
            )

        self.assertEqual(result["integrity_ok"], False)
        self.assertIn("integrity verification failed without a detailed warning", warnings_handle.getvalue())


if __name__ == "__main__":
    unittest.main()
