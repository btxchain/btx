#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""Release cards, helper refusals, and read-only compute receipt checks.

A structured helper refusal is the helper's code and message. "model helper
unavailable" stays reserved for a helper that is down or a reply that is not
JSON (covered when modelnet is off by feature_modelnet_compute_economy.py).
"""

import hashlib
import json
import os
import struct

from test_framework.authproxy import JSONRPCException
from test_framework.test_framework import BitcoinTestFramework, SkipTest
from test_framework.util import assert_equal

MATMUL_OFF = [
    "-regtestmatmulbindingheight=2147483647",
    "-regtestmatmulproductdigestheight=2147483647",
    "-regtestmatmulv4height=2147483647",
    "-regtestmatmulrequireproductpayload=0",
]


def assert_refusal(fn, code):
    try:
        fn()
    except JSONRPCException as exc:
        message = exc.error["message"]
        if exc.error["code"] != -8 or not message.startswith(code + ":"):
            raise AssertionError(message) from exc
        if "model helper unavailable" in message:
            raise AssertionError(message) from exc
        return
    raise AssertionError(f"expected {code}")


def write_safetensors(path):
    hdr = json.dumps({
        "__metadata__": {"format": "pt"},
        "w": {"dtype": "F32", "shape": [1], "data_offsets": [0, 4]},
    }).encode()
    with open(path, "wb") as f:
        f.write(struct.pack("<Q", len(hdr)) + hdr + b"\0\0\0\0")


def find_card(res, release_id):
    for item in res.get("results") or res.get("items") or []:
        if release_id in json.dumps(item):
            return item
    return None


class ModelnetReleaseCardsTest(BitcoinTestFramework):
    def add_options(self, parser):
        self.add_wallet_options(parser, legacy=False)

    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.extra_args = [[
            "-modelnet=1",
            "-modelbind=off",
            "-modelstorage=8MiB",
            *MATMUL_OFF,
        ]]

    def skip_test_if_missing_module(self):
        self.skip_if_platform_not_posix()
        self.skip_if_no_wallet()
        self.skip_if_no_sqlite()
        exeext = self.config["environment"].get("EXEEXT", "")
        builddir = self.config["environment"].get("BUILDDIR")
        if not builddir or not os.path.isfile(os.path.join(builddir, "bin", f"btx-modeld{exeext}")):
            if not os.environ.get("BTXMODELD"):
                raise SkipTest("btx-modeld not found")

    def run_test(self):
        node = self.nodes[0]
        self.wait_until(lambda: node.getmodelnetworkinfo().get("helper_ready"), timeout=30)

        assert_refusal(lambda: node.importcomputereceipt({"envelope": {"junk": 1}}), "COMPUTE_RECORD_INVALID")
        assert_refusal(lambda: node.hostmodel(os.path.join(node.datadir_path, "missing.safetensors")), "IMPORT_FAILED")
        assert_refusal(lambda: node.verifycomputereceipt({"envelope": {"junk": 1}}), "COMPUTE_RECORD_INVALID")
        assert_equal(node.listcomputereceipts()["records"], [])

        model_dir = os.path.join(node.datadir_path, "model")
        os.makedirs(model_dir, exist_ok=True)
        path = os.path.join(model_dir, "toy.safetensors")
        write_safetensors(path)
        size = os.path.getsize(path)
        node.createwallet("pub")
        wallet = node.get_wallet_rpc("pub")
        mine = wallet.getnewaddress()
        self.generatetoaddress(node, 110, mine)
        hosted = node.hostmodel(path)
        height = node.getblockcount()
        rel = node.createmodelrelease({
            "uri": hosted["uri"],
            "secret32_hex": hashlib.sha256(b"release-key").hexdigest(),
            "refund_height": height + 50,
            "target_atoms": 5_000_000,
            "display_name": "Pretty Beta",
            "short_description": "kept description",
            "searchable_metadata": {"family": "toy", "format": "safetensors", "tags": ["license:mit"]},
        })
        rid = rel["release_id"]
        assert_equal(rel["publish_state"], "published")

        for method in ("getrecentreleases", "getfundablemodels"):
            card = find_card(getattr(node, method)({"scope": "LOCAL", "limit": 10}), rid)
            assert card is not None
            assert_equal(card["name"], "Pretty Beta")
            assert card["size_bytes"] == size or card["entry"]["model"]["size_bytes"] == size
            assert card["size_bytes"] != 0
            assert "id" in card["publisher"]
            assert card["publisher"]["id"] != "0" * 96
            assert_equal(card["entry"]["model"]["description"], "kept description")

        claimant = wallet.exportpqkey(wallet.getnewaddress())["pubkey"]
        refund_pk = wallet.exportpqkey(wallet.getnewaddress())["pubkey"]
        amount = 2_000_000
        plan = node.preparefundmodelrelease(rid, {
            "amount_atoms": amount,
            "claimant": claimant,
            "refund_pubkey": refund_pk,
        })
        frozen = wallet.preparemodelfunding({
            "key_hash": plan["key_hash"],
            "claimant": claimant,
            "refund_pubkey": refund_pk,
            "refund_height": int(plan["refund_height"]),
            "amount_atoms": amount,
            "auto_pay": False,
            "assurance": "KEY_RELEASE_ONLY",
        })
        signed = wallet.signmodelfunding(frozen["unsigned_hex"], frozen)
        wallet.submitmodelfunding(signed["hex"], frozen)
        self.generatetoaddress(node, 2, mine)

        econ = node.getmodelreleaseeconomics(rid)
        assert_equal(econ["value_known"], True)
        assert_equal(econ["confirmed_funded_atoms"], amount)

        node.createwallet("second")
        econ2 = node.getmodelreleaseeconomics(rid)
        assert_equal(econ2["value_known"], True)
        assert_equal(econ2["confirmed_funded_atoms"], amount)
        card = find_card(node.getfundablemodels({"limit": 10}), rid)
        assert card is not None
        assert_equal(card["release"]["value_known"], True)
        assert_equal(card["release"]["confirmed_funded_atoms"], amount)
        assert_equal(card["fundable_now"], True)


if __name__ == "__main__":
    ModelnetReleaseCardsTest(__file__).main()
