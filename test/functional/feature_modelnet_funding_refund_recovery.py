#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""submitmodelfunding must persist the HTLC refund terms.

A funder who funds a model release and keeps only release_id/txid (the common
case: prepare -> sign -> submit passes the JSON through, and the result note
does not say to save it) must still be able to recover the refund descriptor
from the node after a restart. Before the fix the descriptor lived only in the
preparemodelfunding JSON, so exportmodelrecovery(release_id) returned
"no public recovery material" and a failed campaign could not be refunded.

Both submit paths are covered: the broadcast path (CommitTransaction) and the
duplicate path (the transaction is already in the wallet/mempool, so only
remember_funding runs and must persist the terms with an explicit WriteTx).
"""
import hashlib
import json
import os
import struct

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal

MATMUL_OFF = ["-regtestmatmulbindingheight=2147483647", "-regtestmatmulproductdigestheight=2147483647",
              "-regtestmatmulv4height=2147483647", "-regtestmatmulrequireproductpayload=0"]


def write_safetensors(path):
    hdr = json.dumps({"__metadata__": {"format": "pt"},
                      "w": {"dtype": "F32", "shape": [1], "data_offsets": [0, 4]}}).encode()
    with open(path, "wb") as f:
        f.write(struct.pack("<Q", len(hdr)) + hdr + b"\0\0\0\0")


class ModelnetFundingRefundRecoveryTest(BitcoinTestFramework):
    def add_options(self, parser):
        self.add_wallet_options(parser, legacy=False)

    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.extra_args = [["-modelnet=1", "-modelbind=off", "-modelstorage=8MiB", *MATMUL_OFF]]
        self.rpc_timeout = 600

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def host_release(self, node, w, tag, refund_height):
        model_dir = os.path.join(node.datadir_path, "model")
        os.makedirs(model_dir, exist_ok=True)
        mp = os.path.join(model_dir, f"{tag}.safetensors")
        write_safetensors(mp)
        hosted = node.hostmodel(mp)
        secret = hashlib.sha256(tag.encode()).digest()
        rel = node.createmodelrelease({"uri": hosted["uri"], "secret32_hex": secret.hex(),
                                       "refund_height": refund_height, "target_atoms": 5_000_000,
                                       "display_name": tag})
        rid = rel["release_id"]
        key_hash = rel.get("key_hash") or hashlib.sha256(secret).hexdigest()
        return rid, key_hash

    def freeze_sign(self, node, w, rid, key_hash, refund_height):
        claimant = w.exportpqkey(w.getnewaddress())["pubkey"]
        # No refund_pubkey: the wallet mints the refund key (the documented default).
        frozen = w.preparemodelfunding(rid, {"key_hash": key_hash, "claimant": claimant,
                                             "refund_height": refund_height, "amount_atoms": "2000000",
                                             "fee_cap_atoms": "1000000", "auto_pay": False,
                                             "automatic_spend_atoms": "0"})
        signed = w.signmodelfunding(frozen["unsigned_hex"], frozen)
        return frozen, signed

    def run_test(self):
        node = self.nodes[0]
        self.wait_until(lambda: node.getmodelnetworkinfo().get("helper_ready"), timeout=60)
        node.createwallet("w")
        w = node.get_wallet_rpc("w")
        mine = w.getnewaddress()
        self.generatetoaddress(node, 110, mine, sync_fun=self.no_op)
        h = node.getblockcount()

        # Release A, broadcast path: submitmodelfunding broadcasts and commits.
        rid_a, kh_a = self.host_release(node, w, "relA", h + 40)
        frozen_a, signed_a = self.freeze_sign(node, w, rid_a, kh_a, h + 40)
        want_desc_a, want_script_a = frozen_a["descriptor"], frozen_a["output_script"]
        sub_a = w.submitmodelfunding(signed_a["hex"], frozen_a)
        assert_equal(sub_a["submitted"], True)
        assert_equal(sub_a["duplicate"], False)

        # Release B, duplicate path: the transaction is broadcast first, so
        # submitmodelfunding sees it already present and only remember_funding runs.
        rid_b, kh_b = self.host_release(node, w, "relB", h + 40)
        frozen_b, signed_b = self.freeze_sign(node, w, rid_b, kh_b, h + 40)
        want_desc_b, want_script_b = frozen_b["descriptor"], frozen_b["output_script"]
        node.sendrawtransaction(signed_b["hex"])
        sub_b = w.submitmodelfunding(signed_b["hex"], frozen_b)
        assert_equal(sub_b["duplicate"], True)

        # Deliberately do NOT mine the funding transactions before restarting: a
        # confirming block re-persists the wallet tx (and with it the in-memory
        # mapValue), which would mask whether submitmodelfunding itself persisted
        # the terms. The funder keeps only release_id/txid; the JSON is gone.
        del frozen_a, signed_a, frozen_b, signed_b
        self.restart_node(0)
        self.wait_until(lambda: node.getmodelnetworkinfo().get("helper_ready"), timeout=60)
        if "w" not in node.listwallets():
            node.loadwallet("w")
        w = node.get_wallet_rpc("w")

        for tag, rid, want_desc, want_script in (("broadcast", rid_a, want_desc_a, want_script_a),
                                                 ("duplicate", rid_b, want_desc_b, want_script_b)):
            rec = node.exportmodelrecovery(rid)
            assert "error" not in rec, f"{tag}: exportmodelrecovery reports no recovery material: {rec.get('error')}"
            assert rec.get("descriptor"), f"{tag}: exportmodelrecovery returned no descriptor"
            assert_equal(rec["descriptor"], want_desc)
            assert_equal(rec.get("output_script"), want_script)
            self.log.info(f"{tag} path: recovered refund descriptor from persisted funding tx after restart")

        # Ambiguity: fund relA a second time. With no refund_pubkey the wallet
        # mints a fresh refund key, so the second funding carries a different
        # descriptor for the same release_id. exportmodelrecovery must then refuse
        # to guess and say so, while an explicitly supplied descriptor still works.
        frozen_a2, signed_a2 = self.freeze_sign(node, w, rid_a, kh_a, h + 40)
        assert frozen_a2["descriptor"] != want_desc_a, "second funding should yield a different descriptor"
        assert_equal(w.submitmodelfunding(signed_a2["hex"], frozen_a2)["submitted"], True)

        rec_amb = node.exportmodelrecovery(rid_a)
        assert not rec_amb.get("descriptor"), f"exportmodelrecovery guessed a descriptor for an ambiguous release_id: {rec_amb.get('descriptor')}"
        assert "several descriptors" in rec_amb.get("error", ""), f"missing ambiguity message: {rec_amb.get('error')}"
        # An explicit descriptor still resolves.
        rec_explicit = node.exportmodelrecovery(rid_a, {"descriptor": want_desc_a})
        assert_equal(rec_explicit.get("descriptor"), want_desc_a)
        self.log.info("ambiguous release_id: exportmodelrecovery refused to guess and resolved with an explicit descriptor")


if __name__ == "__main__":
    ModelnetFundingRefundRecoveryTest(__file__).main()
