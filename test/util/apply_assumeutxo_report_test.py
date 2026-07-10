#!/usr/bin/env python3
"""Unit coverage for scripts/apply_assumeutxo_report.py."""

from __future__ import annotations

import importlib.util
import json
import pathlib
import subprocess
import sys
import tempfile
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[2]
SCRIPT_PATH = ROOT / "scripts" / "apply_assumeutxo_report.py"


def load_module():
    spec = importlib.util.spec_from_file_location("apply_assumeutxo_report", SCRIPT_PATH)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


BASE_SOURCE = """class CMainParams : public CChainParams {
public:
    CMainParams() {
        m_assumeutxo_data = {
            {
                // main assumeutxo snapshot at height 55'000
                .height = 55'000,
                .hash_serialized = AssumeutxoHash{uint256{"3fdff3b95b68ae2d40ef949e41d9e39fe68591f7fcc4cbfbc46c04f58030dda5"}},
                .m_chain_tx_count = 56'457,
                .blockhash = consteval_ctor(uint256{"db5e6530e55606be66aa78fe3f711e9dc4406ee4b26dde2ed819103c37d97d63"}),
            },
        };
    }
};
"""

VERSIONED_SOURCE = """class CMainParams : public CChainParams {
public:
    CMainParams() {
        m_assumeutxo_data = {
            {
                // main assumeutxo snapshot at height 155'700 (snapshot v9)
                .height = 155'700,
                .hash_serialized = AssumeutxoHash{uint256{"177c88216b700618cee432a3ca4f7c30c79fa3733666553484c5a22e283b777f"}},
                .m_chain_tx_count = 213'654,
                .blockhash = consteval_ctor(uint256{"b5ea1fb02d12e1cfa4bbc5ccc4946ca026ad4a5f270b99a0816aa95853306c3d"}),
                .shielded_state_commitment = uint256{"d8abf2d33319a2030c34c68dd50cfda10ececdd95f5a85bdbe05d44b334fbe9d"},
            },
        };
    }
};
"""


class ApplyAssumeutxoReportTest(unittest.TestCase):
    def setUp(self):
        self.module = load_module()

    def snapshot(
        self,
        height: int,
        txoutset_hash: str,
        blockhash: str,
        nchaintx: int,
        shielded_state_pin: str | None = None,
        snapshot_file_version: int | None = None,
    ):
        return self.module.AssumeutxoSnapshot(
            chain="main",
            height=height,
            txoutset_hash=txoutset_hash,
            nchaintx=nchaintx,
            blockhash=blockhash,
            shielded_state_pin=shielded_state_pin,
            snapshot_file_version=snapshot_file_version,
        )

    def test_replace_assumeutxo_block_appends_new_height(self):
        updated = self.module.replace_assumeutxo_block(
            BASE_SOURCE,
            "main",
            self.snapshot(
                60760,
                "1111111111111111111111111111111111111111111111111111111111111111",
                "2222222222222222222222222222222222222222222222222222222222222222",
                66221,
            ),
            replace_existing=False,
        )

        self.assertIn(".height = 55'000,", updated)
        self.assertIn(".height = 60'760,", updated)
        self.assertLess(updated.index(".height = 55'000,"), updated.index(".height = 60'760,"))

    def test_replace_assumeutxo_block_appends_shielded_state_pin(self):
        shielded_state_pin = "44" * 32
        updated = self.module.replace_assumeutxo_block(
            BASE_SOURCE,
            "main",
            self.snapshot(
                60760,
                "1111111111111111111111111111111111111111111111111111111111111111",
                "2222222222222222222222222222222222222222222222222222222222222222",
                66221,
                shielded_state_pin,
                9,
            ),
            replace_existing=False,
        )

        self.assertIn(f".shielded_state_commitment = uint256{{\"{shielded_state_pin}\"}}", updated)
        self.assertIn("snapshot v9", updated)

    def test_versioned_existing_entry_round_trips_exactly(self):
        snapshot = self.snapshot(
            155700,
            "177c88216b700618cee432a3ca4f7c30c79fa3733666553484c5a22e283b777f",
            "b5ea1fb02d12e1cfa4bbc5ccc4946ca026ad4a5f270b99a0816aa95853306c3d",
            213654,
            "d8abf2d33319a2030c34c68dd50cfda10ececdd95f5a85bdbe05d44b334fbe9d",
            9,
        )

        updated = self.module.replace_assumeutxo_block(
            VERSIONED_SOURCE,
            "main",
            snapshot,
            replace_existing=True,
        )

        self.assertEqual(updated, VERSIONED_SOURCE)

        parsed = self.module.parse_existing_assumeutxo_entries(
            VERSIONED_SOURCE,
            "main",
        )
        self.assertEqual(parsed[0].snapshot_file_version, 9)
        with self.assertRaisesRegex(
            self.module.AssumeutxoApplyError,
            "already has assumeutxo metadata",
        ):
            self.module.merge_assumeutxo_entries(
                "main",
                parsed,
                self.snapshot(
                    155700,
                    snapshot.txoutset_hash,
                    snapshot.blockhash,
                    snapshot.nchaintx,
                    snapshot.shielded_state_pin,
                    10,
                ),
                replace_existing=False,
            )

    def test_check_accepts_matching_versioned_entry(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            chainparams_path = pathlib.Path(tmpdir) / "chainparams.cpp"
            report_path = pathlib.Path(tmpdir) / "snapshot.report.json"
            chainparams_path.write_text(VERSIONED_SOURCE, encoding="utf-8")
            report_path.write_text(
                json.dumps(
                    {
                        "chain": "main",
                        "snapshot": {
                            "height": 155700,
                            "txoutset_hash": "177c88216b700618cee432a3ca4f7c30c79fa3733666553484c5a22e283b777f",
                            "nchaintx": 213654,
                            "blockhash": "b5ea1fb02d12e1cfa4bbc5ccc4946ca026ad4a5f270b99a0816aa95853306c3d",
                            "shielded_state_pin": "d8abf2d33319a2030c34c68dd50cfda10ececdd95f5a85bdbe05d44b334fbe9d",
                            "file_version": 9,
                        },
                    }
                ),
                encoding="utf-8",
            )

            result = subprocess.run(
                [
                    sys.executable,
                    str(SCRIPT_PATH),
                    "--report",
                    str(report_path),
                    "--chainparams",
                    str(chainparams_path),
                    "--check",
                ],
                check=False,
                capture_output=True,
                text=True,
            )

            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("assumeutxo apply check: PASS", result.stdout)
            self.assertEqual(chainparams_path.read_text(encoding="utf-8"), VERSIONED_SOURCE)

    def test_parse_report_reads_shielded_state_pin(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            report_path = pathlib.Path(tmpdir) / "snapshot.report.json"
            report_path.write_text(
                json.dumps(
                    {
                        "chain": "main",
                        "snapshot": {
                            "height": 60760,
                            "txoutset_hash": "11" * 32,
                            "nchaintx": 66221,
                            "blockhash": "22" * 32,
                            "shielded_state_pin": "44" * 32,
                            "file_version": 9,
                        },
                    }
                ),
                encoding="utf-8",
            )

            snapshot, chain = self.module.parse_report(report_path)

            self.assertEqual(chain, "main")
            self.assertEqual(snapshot.shielded_state_pin, "44" * 32)
            self.assertEqual(snapshot.snapshot_file_version, 9)

    def test_parse_report_reads_snapshot_file_version_from_manifest(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            report_path = pathlib.Path(tmpdir) / "snapshot.report.json"
            report_path.write_text(
                json.dumps(
                    {
                        "chain": "main",
                        "snapshot": {
                            "height": 60760,
                            "txoutset_hash": "11" * 32,
                            "nchaintx": 66221,
                            "blockhash": "22" * 32,
                            "shielded_state_pin": "44" * 32,
                        },
                        "release_asset_manifest": {
                            "snapshot_file_version": 9,
                        },
                    }
                ),
                encoding="utf-8",
            )

            snapshot, _ = self.module.parse_report(report_path)

            self.assertEqual(snapshot.snapshot_file_version, 9)

    def test_parse_report_rejects_shielded_snapshot_before_v9(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            report_path = pathlib.Path(tmpdir) / "snapshot.report.json"
            report_path.write_text(
                json.dumps(
                    {
                        "chain": "main",
                        "snapshot": {
                            "height": 60760,
                            "txoutset_hash": "11" * 32,
                            "nchaintx": 66221,
                            "blockhash": "22" * 32,
                            "shielded_state_pin": "44" * 32,
                            "file_version": 8,
                        },
                    }
                ),
                encoding="utf-8",
            )

            with self.assertRaisesRegex(self.module.AssumeutxoApplyError, "unshield velocity state"):
                self.module.parse_report(report_path)

    def test_parse_report_rejects_shielded_snapshot_without_file_version(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            report_path = pathlib.Path(tmpdir) / "snapshot.report.json"
            report_path.write_text(
                json.dumps(
                    {
                        "chain": "main",
                        "snapshot": {
                            "height": 60760,
                            "txoutset_hash": "11" * 32,
                            "nchaintx": 66221,
                            "blockhash": "22" * 32,
                            "shielded_state_pin": "44" * 32,
                        },
                    }
                ),
                encoding="utf-8",
            )

            with self.assertRaisesRegex(self.module.AssumeutxoApplyError, "snapshot.file_version"):
                self.module.parse_report(report_path)

    def test_replace_assumeutxo_block_rejects_conflicting_height_without_replace(self):
        with self.assertRaises(self.module.AssumeutxoApplyError):
            self.module.replace_assumeutxo_block(
                BASE_SOURCE,
                "main",
                self.snapshot(
                    55000,
                    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                    "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                    99999,
                ),
                replace_existing=False,
            )

    def test_replace_assumeutxo_block_replaces_conflicting_height_when_allowed(self):
        updated = self.module.replace_assumeutxo_block(
            BASE_SOURCE,
            "main",
            self.snapshot(
                55000,
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                99999,
            ),
            replace_existing=True,
        )

        self.assertIn("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", updated)
        self.assertIn("99'999", updated)
        self.assertNotIn("3fdff3b95b68ae2d40ef949e41d9e39fe68591f7fcc4cbfbc46c04f58030dda5", updated)


if __name__ == "__main__":
    unittest.main()
