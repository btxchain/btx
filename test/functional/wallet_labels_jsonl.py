#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""BIP329 JSONL exportlabels/importlabels for P2MR address labels."""

import json

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
    assert_raises_rpc_error,
)

# Known-valid regtest secp P2WPKH (witness v0) — must be rejected on import.
SECP_P2WPKH = "btxrt1qthmht0k2qnh3wy7336z05lu2km7emzfp3p2wxm"


class WalletLabelsJSONLTest(BitcoinTestFramework):
    def add_options(self, parser):
        self.add_wallet_options(parser, descriptors=True, legacy=False)

    def set_test_params(self):
        self.num_nodes = 1

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def run_test(self):
        node = self.nodes[0]
        src = node.get_wallet_rpc(self.default_wallet_name)

        tabby = src.getnewaddress("tabby", "p2mr")
        mittens = src.getnewaddress("mittens", "p2mr")

        export_path = node.datadir_path / "labels.jsonl"
        exported = src.exportlabels(str(export_path))
        assert_equal(exported["filename"], str(export_path))
        assert exported["labels"] >= 2

        with open(export_path, encoding="utf8") as fh:
            records = [json.loads(line) for line in fh if line.strip()]
        by_ref = {rec["ref"]: rec for rec in records}
        assert_equal(by_ref[tabby]["type"], "addr")
        assert_equal(by_ref[tabby]["label"], "tabby")
        assert_equal(by_ref[mittens]["label"], "mittens")
        for rec in records:
            assert rec["type"] == "addr"
            assert "bitcoin:" not in rec["ref"]
            if "origin" in rec:
                assert rec["origin"].startswith("[")

        assert_raises_rpc_error(-8, "already exists", src.exportlabels, str(export_path))
        assert_raises_rpc_error(-8, "parent-directory", src.exportlabels, str(node.datadir_path / ".." / "labels-evil.jsonl"))
        assert_raises_rpc_error(-8, "parent-directory", src.importlabels, str(node.datadir_path / ".." / "labels.jsonl"))

        node.createwallet("dest")
        dest = node.get_wallet_rpc("dest")

        bitcoin_path = node.datadir_path / "labels-bitcoin.jsonl"
        bitcoin_path.write_text(json.dumps({"type": "addr", "ref": "bitcoin:" + tabby, "label": "nope"}) + "\n", encoding="utf8")
        assert_raises_rpc_error(-5, "bitcoin:", dest.importlabels, str(bitcoin_path))

        secp_path = node.datadir_path / "labels-secp.jsonl"
        secp_path.write_text(json.dumps({"type": "addr", "ref": SECP_P2WPKH, "label": "secp"}) + "\n", encoding="utf8")
        assert_raises_rpc_error(-5, "P2MR", dest.importlabels, str(secp_path))

        mixed_path = node.datadir_path / "labels-mixed.jsonl"
        mixed_path.write_text(
            json.dumps({"type": "addr", "ref": tabby, "label": "tabby"}) + "\n"
            + json.dumps({"type": "addr", "ref": "bitcoin:" + mittens, "label": "bad"}) + "\n",
            encoding="utf8",
        )
        assert_raises_rpc_error(-5, "bitcoin:", dest.importlabels, str(mixed_path))
        assert_raises_rpc_error(-11, "No addresses with label", dest.getaddressesbylabel, "tabby")

        imported = dest.importlabels(str(export_path))
        assert imported["imported"] >= 2
        assert_equal(dest.getaddressesbylabel("tabby")[tabby]["purpose"], "send")
        assert_equal(dest.getaddressesbylabel("mittens")[mittens]["purpose"], "send")

        # Labels are not keys: export from a locked encrypted wallet must succeed.
        node.createwallet(wallet_name="locked_labels", passphrase="secret")
        locked = node.get_wallet_rpc("locked_labels")
        locked.walletpassphrase("secret", 60)
        locked_addr = locked.getnewaddress("cinnamon", "p2mr")
        locked.walletlock()
        locked_path = node.datadir_path / "labels-locked.jsonl"
        locked_export = locked.exportlabels(str(locked_path))
        assert locked_export["labels"] >= 1
        with open(locked_path, encoding="utf8") as fh:
            locked_records = [json.loads(line) for line in fh if line.strip()]
        assert any(rec.get("ref") == locked_addr and rec.get("label") == "cinnamon" for rec in locked_records)


if __name__ == "__main__":
    WalletLabelsJSONLTest(__file__).main()
