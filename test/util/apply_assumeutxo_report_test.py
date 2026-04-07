#!/usr/bin/env python3
"""Unit coverage for scripts/apply_assumeutxo_report.py."""

from __future__ import annotations

import importlib.util
import pathlib
import sys
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


class ApplyAssumeutxoReportTest(unittest.TestCase):
    def setUp(self):
        self.module = load_module()

    def snapshot(self, height: int, txoutset_hash: str, blockhash: str, nchaintx: int):
        return self.module.AssumeutxoSnapshot(
            chain="main",
            height=height,
            txoutset_hash=txoutset_hash,
            nchaintx=nchaintx,
            blockhash=blockhash,
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
