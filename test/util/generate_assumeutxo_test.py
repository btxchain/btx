#!/usr/bin/env python3
"""Unit coverage for contrib/devtools/generate_assumeutxo.py."""

from __future__ import annotations

import importlib.util
import pathlib
import sys
import tempfile
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[2]
SCRIPT_PATH = ROOT / "contrib" / "devtools" / "generate_assumeutxo.py"


def load_module():
    spec = importlib.util.spec_from_file_location("generate_assumeutxo", SCRIPT_PATH)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class GenerateAssumeutxoTest(unittest.TestCase):
    def setUp(self):
        self.module = load_module()

    def test_build_chainparams_entry_formats_cpp_snippet(self):
        metadata = self.module.AssumeutxoSnapshot(
            height=50000,
            txoutset_hash="0123456789abcdef" * 4,
            nchaintx=777,
            blockhash="abcdef0123456789" * 4,
            path="/tmp/utxo.dat",
            snapshot_sha256="f0" * 32,
        )

        snippet = self.module.build_chainparams_entry(metadata, comment="mainnet snapshot")

        self.assertIn(".height = 50'000", snippet)
        self.assertIn(".hash_serialized = AssumeutxoHash{uint256{\"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\"}}", snippet)
        self.assertIn(".m_chain_tx_count = 777", snippet)
        self.assertIn(".blockhash = consteval_ctor(uint256{\"abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789\"})", snippet)
        self.assertIn("// mainnet snapshot", snippet)

    def test_build_report_includes_release_asset_hint(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            snapshot_path = pathlib.Path(tmpdir) / "utxo.dat"
            snapshot_path.write_bytes(b"snapshot")
            metadata = self.module.AssumeutxoSnapshot(
                height=50000,
                txoutset_hash="11" * 32,
                nchaintx=888,
                blockhash="22" * 32,
                path=str(snapshot_path),
                snapshot_sha256="33" * 32,
            )

            report = self.module.build_report(
                metadata,
                chain="main",
                cli_path="/opt/btx/bin/btx-cli",
                rpc_args=["-rpcconnect=127.0.0.1", "-rpcport=19334"],
                snapshot_type="rollback",
                asset_url="https://node.btxchain.org/releases/utxo.dat",
            )

            self.assertEqual(report["chain"], "main")
            self.assertEqual(report["snapshot"]["height"], 50000)
            self.assertEqual(report["snapshot"]["sha256"], "33" * 32)
            self.assertIn("m_assumeutxo_data", report["chainparams_snippet"])
            self.assertEqual(report["asset"]["url"], "https://node.btxchain.org/releases/utxo.dat")
            self.assertEqual(report["asset"]["sha256"], "33" * 32)


if __name__ == "__main__":
    unittest.main()
