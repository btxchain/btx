#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""Opt-in presign of an htlc_sha256 claim leaf (walletprocesspsbt htlc_presign).

A buyer in an atomic swap wants to hand a watchtower a claim that is already
signed, before the secret is public. The claim-leaf signature does not commit
to the preimage, so the wallet can sign now and anyone who later learns the
secret can complete the witness.

Flow:
  1. The claimer wallet signs the selected claim leaf without the preimage
     (htlc_presign=true). The PSBT stays incomplete and carries no preimage.
  2. A party without the wallet (the watchtower) adds the real preimage as
     BIP174 PSBT_IN_SHA256 and calls finalizepsbt. The claim is accepted and
     confirms, and the witness reveals the preimage.

Negative controls:
  - without htlc_presign the wallet still refuses to sign the claim leaf
    without the preimage;
  - htlc_presign needs sign=true and a selected leaf;
  - htlc_presign needs sighashtype DEFAULT or ALL (NONE, SINGLE and
    ANYONECANPAY would let the holder redirect the claim or take fee);
  - a wallet without the claimer key gets an error that says so;
  - an htlc_sha256_legacy claim leaf is not presigned;
  - a presigned PSBT does not finalize without the preimage;
  - a wrong preimage is still rejected when the PSBT is read (BIP174);
  - the presignature commits to the transaction: a changed output does not
    finalize even with the real preimage;
  - as with buildhtlcclaim, no presign against a funding output that is
    unconfirmed, unknown or below min_confirmations, and none once the refund
    path is final, unless allow_unconfirmed_funding / allow_late_claim is set;
  - the refund leaf of a funding that is not broadcast yet can still be signed.
"""

import hashlib
from decimal import Decimal

from test_framework.key import TaggedHash
from test_framework.messages import CTxOut, ser_string, tx_from_hex
from test_framework.psbt import PSBT, PSBT_IN_SHA256, PSBT_IN_WITNESS_UTXO
from test_framework.segwit_addr import encode_segwit_address
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_raises_rpc_error
from test_framework.bridge_utils import create_bridge_wallet, find_output, mine_block

FEE_SAT = 1000
P2MR_LEAF_VERSION = 0xc2


def with_preimage(psbt_b64, preimage, digest=None):
    """Add a BIP174 PSBT_IN_SHA256 entry to input 0, as a watchtower would."""
    psbt = PSBT.from_base64(psbt_b64)
    digest = digest or hashlib.sha256(preimage).digest()
    psbt.i[0].map[bytes([PSBT_IN_SHA256]) + digest] = preimage
    return psbt.to_base64()


def leaf_hash(script):
    return TaggedHash("P2MRLeaf", bytes([P2MR_LEAF_VERSION]) + ser_string(script))


def branch(a, b):
    lo, hi = (a, b) if a < b else (b, a)
    return TaggedHash("P2MRBranch", lo + hi)


class WalletHtlcPresignTest(BitcoinTestFramework):
    def add_options(self, parser):
        self.add_wallet_options(parser, legacy=False)

    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.extra_args = [["-autoshieldcoinbase=0",
                            "-modelbind=off",
                            "-regtestmatmulbindingheight=2147483647",
                            "-regtestmatmulproductdigestheight=2147483647",
                            "-regtestmatmulv4height=2147483647",
                            "-regtestmatmulrequireproductpayload=0"]]

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()
        self.skip_if_no_sqlite()

    def checksummed(self, desc):
        return f"{desc}#{self.nodes[0].getdescriptorinfo(desc)['checksum']}"

    def first_key(self, wallet):
        """The wallet's first P2MR pubkey and the private key expression that derives it."""
        pubkey = wallet.exportpqkey(wallet.getnewaddress(address_type="p2mr"))["pubkey"]
        body = next(d["desc"] for d in wallet.listdescriptors(True)["descriptors"]
                    if d["desc"].startswith("mr(pqhd(") and not d["internal"]).split("#")[0]
        return pubkey, body[body.index("pqhd("):body.index("/*)") + 3]

    def import_lock(self, wallet, desc_priv):
        res = wallet.importdescriptors([{"desc": desc_priv, "range": [0, 0], "timestamp": 0, "active": False}])
        assert res[0]["success"], res

    def fund(self, address, amount=Decimal("1")):
        txid = self.maker.sendtoaddress(address, amount)
        mine_block(self, self.nodes[0], self.mine_addr)
        vout, value = find_output(self.nodes[0], txid, address, self.maker)
        return txid, vout, value

    def claim_psbt(self, txid, vout, value, dest):
        amount = value - Decimal(FEE_SAT) / Decimal(100_000_000)
        return self.nodes[0].createpsbt([{"txid": txid, "vout": vout}], [{dest: amount}], 0, True), amount

    def run_test(self):
        node = self.nodes[0]
        self.maker, self.mine_addr = create_bridge_wallet(self, node, wallet_name="maker", amount=Decimal("8"))
        maker = self.maker
        node.createwallet(wallet_name="claimer", descriptors=True)
        claimer = node.get_wallet_rpc("claimer")

        # The claim leaf uses the claimer's first P2MR key. The claimer imports the HTLC
        # descriptor with the private form of that key so its wallet can sign the leaf.
        claimer_pk, claimer_key = self.first_key(claimer)
        refund_pk = maker.exportpqkey(maker.getnewaddress(address_type="p2mr"))["pubkey"]

        secret = bytes.fromhex("5a" * 32)
        hashlock = hashlib.sha256(secret).hexdigest()
        lock = node.getblockcount() + 100
        desc_pub = self.checksummed(f"mr(htlc_sha256({hashlock},{claimer_pk}),refund({lock},{refund_pk}))")
        desc_priv = self.checksummed(f"mr(htlc_sha256({hashlock},{claimer_key}),refund({lock},{refund_pk}))")
        self.import_lock(claimer, desc_priv)
        htlc_addr = node.deriveaddresses(desc_pub)[0]

        txid, vout, value = self.fund(htlc_addr, Decimal("2"))
        dest = claimer.getnewaddress(address_type="p2mr")
        psbt, amount = self.claim_psbt(txid, vout, value, dest)
        claim_leaf = {f"{txid}:{vout}": 0}

        self.log.info("Without htlc_presign the claim leaf is not signed without the preimage")
        assert_raises_rpc_error(None, "requires the 32-byte preimage",
                                claimer.walletprocesspsbt, psbt, {"p2mr_leaf": claim_leaf})

        self.log.info("htlc_presign needs sign=true and a selected leaf")
        assert_raises_rpc_error(-8, "htlc_presign requires sign=true",
                                claimer.walletprocesspsbt, psbt, {"sign": False, "htlc_presign": True})
        assert_raises_rpc_error(None, "no leaf selected",
                                claimer.walletprocesspsbt, psbt, {"htlc_presign": True})

        self.log.info("htlc_presign needs sighashtype DEFAULT or ALL")
        for sighash in ("NONE", "SINGLE", "ALL|ANYONECANPAY", "NONE|ANYONECANPAY", "SINGLE|ANYONECANPAY"):
            assert_raises_rpc_error(-8, "htlc_presign requires sighashtype DEFAULT or ALL",
                                    claimer.walletprocesspsbt, psbt,
                                    {"htlc_presign": True, "p2mr_leaf": claim_leaf, "sighashtype": sighash})
        with_all = claimer.walletprocesspsbt(psbt, {"htlc_presign": True, "p2mr_leaf": claim_leaf, "sighashtype": "ALL"})
        assert_equal(with_all["complete"], False)
        assert_equal(len(node.decodepsbt(with_all["psbt"])["inputs"][0].get("p2mr_partial_signatures", [])), 1)

        self.log.info("Presign the claim leaf; the PSBT stays incomplete and holds no preimage")
        presigned = claimer.walletprocesspsbt(psbt, {"htlc_presign": True, "p2mr_leaf": claim_leaf})
        assert_equal(presigned["complete"], False)
        assert "hex" not in presigned
        decoded = node.decodepsbt(presigned["psbt"])["inputs"][0]
        sigs = [s for s in decoded.get("p2mr_partial_signatures", []) if s.get("pubkey") == claimer_pk]
        assert_equal(len(sigs), 1)
        assert "sha256_preimages" not in decoded
        assert_equal(node.finalizepsbt(presigned["psbt"])["complete"], False)

        self.log.info("A wrong preimage is still rejected when the PSBT is read")
        wrong = with_preimage(presigned["psbt"], bytes(32), digest=bytes.fromhex(hashlock))
        assert_raises_rpc_error(-22, "SHA256 preimage does not match the key", node.finalizepsbt, wrong)

        self.log.info("The presignature commits to the transaction: a changed output does not finalize")
        tampered = PSBT.from_base64(presigned["psbt"])
        tampered.tx.vout[0].nValue -= 1000
        tampered.g.map[0x00] = tampered.tx.serialize()
        tampered_b64 = with_preimage(tampered.to_base64(), secret)
        assert_equal(node.finalizepsbt(tampered_b64)["complete"], False)

        self.log.info("A wallet without the claimer key gets an error that says so")
        node.createwallet(wallet_name="nokey", descriptors=True)
        nokey = node.get_wallet_rpc("nokey")
        nokey_pk, nokey_key = self.first_key(nokey)
        self.import_lock(nokey, self.checksummed(f"mr(htlc_sha256({hashlock},{claimer_pk}),refund({lock},{nokey_key}))"))
        nk_addr = node.deriveaddresses(self.checksummed(f"mr(htlc_sha256({hashlock},{claimer_pk}),refund({lock},{nokey_pk}))"))[0]
        nk_txid, nk_vout, nk_value = self.fund(nk_addr)
        nk_psbt, _ = self.claim_psbt(nk_txid, nk_vout, nk_value, dest)
        assert_raises_rpc_error(None, "htlc_presign: this wallet has no key for the selected htlc_sha256 claim leaf",
                                nokey.walletprocesspsbt, nk_psbt,
                                {"htlc_presign": True, "p2mr_leaf": {f"{nk_txid}:{nk_vout}": 0}})

        self.log.info("An htlc_sha256_legacy claim leaf is not presigned")
        # Legacy leaf: OP_SHA256 <h> OP_EQUALVERIFY <claimer key> OP_CHECKSIG, i.e. the current leaf
        # without its OP_SIZE 32 OP_EQUALVERIFY prefix. Its sibling is the same refund leaf, whose hash
        # is the second half of the current lock's control block. deriveaddresses refuses legacy leaves.
        current_leaf = bytes.fromhex(decoded["p2mr_leaf_script"])
        control = bytes.fromhex(decoded["p2mr_control_block"])
        assert_equal(len(control), 33)
        legacy_secret = bytes.fromhex("6b" * 32)
        legacy_hash = hashlib.sha256(legacy_secret).digest()
        legacy_leaf = bytes([0xa8, 0x20]) + legacy_hash + bytes([0x88]) + current_leaf[4 + 35:]
        legacy_addr = encode_segwit_address("btxrt", 2, branch(leaf_hash(legacy_leaf), control[1:]))
        self.import_lock(claimer, self.checksummed(f"mr(htlc_sha256_legacy({legacy_hash.hex()},{claimer_key}),refund({lock},{refund_pk}))"))
        l_txid, l_vout, l_value = self.fund(legacy_addr)
        l_psbt, _ = self.claim_psbt(l_txid, l_vout, l_value, dest)
        assert_raises_rpc_error(None, "htlc_presign signs only the htlc_sha256 claim leaf, not htlc_sha256_legacy",
                                claimer.walletprocesspsbt, l_psbt,
                                {"htlc_presign": True, "p2mr_leaf": {f"{l_txid}:{l_vout}": legacy_leaf.hex()}})

        self.log.info("The funding and refund options apply only with htlc_presign")
        assert_raises_rpc_error(-8, "apply only with htlc_presign",
                                claimer.walletprocesspsbt, psbt, {"p2mr_leaf": claim_leaf, "allow_late_claim": True})
        assert_raises_rpc_error(-8, "min_confirmations must be at least 1",
                                claimer.walletprocesspsbt, psbt, {"htlc_presign": True, "p2mr_leaf": claim_leaf, "min_confirmations": 0})
        assert_raises_rpc_error(-8, "allow_unconfirmed_funding cannot be combined with min_confirmations",
                                claimer.walletprocesspsbt, psbt,
                                {"htlc_presign": True, "p2mr_leaf": claim_leaf, "allow_unconfirmed_funding": True, "min_confirmations": 2})

        self.log.info("No presign against funding that is unconfirmed or not known, unless allow_unconfirmed_funding is set")
        u_txid = maker.sendtoaddress(htlc_addr, Decimal("1"))
        u_vout, u_value = find_output(node, u_txid, htlc_addr, maker)
        u_psbt, _ = self.claim_psbt(u_txid, u_vout, u_value, dest)
        u_leaf = {f"{u_txid}:{u_vout}": 0}
        assert_raises_rpc_error(None, "is unconfirmed: the funder can still replace it",
                                claimer.walletprocesspsbt, u_psbt, {"htlc_presign": True, "p2mr_leaf": u_leaf})
        unconfirmed = claimer.walletprocesspsbt(u_psbt, {"htlc_presign": True, "p2mr_leaf": u_leaf, "allow_unconfirmed_funding": True})
        assert_equal(unconfirmed["complete"], False)
        assert_equal(len(node.decodepsbt(unconfirmed["psbt"])["inputs"][0].get("p2mr_partial_signatures", [])), 1)
        unknown = PSBT.from_base64(node.createpsbt([{"txid": "11" * 32, "vout": 0}], [{dest: Decimal("0.5")}], 0, True))
        unknown.i[0].map[bytes([PSBT_IN_WITNESS_UTXO])] = CTxOut(50_100_000, bytes.fromhex(node.validateaddress(htlc_addr)["scriptPubKey"])).serialize()
        assert_raises_rpc_error(None, "is not in the UTXO set",
                                claimer.walletprocesspsbt, unknown.to_base64(), {"htlc_presign": True, "p2mr_leaf": {f"{'11' * 32}:0": 0}})

        self.log.info("min_confirmations is checked against the funding depth")
        mine_block(self, node, self.mine_addr)
        assert_raises_rpc_error(None, "has 1 confirmations but min_confirmations is 2",
                                claimer.walletprocesspsbt, u_psbt, {"htlc_presign": True, "p2mr_leaf": u_leaf, "min_confirmations": 2})
        mine_block(self, node, self.mine_addr)
        deep = claimer.walletprocesspsbt(u_psbt, {"htlc_presign": True, "p2mr_leaf": u_leaf, "min_confirmations": 2})
        assert_equal(deep["complete"], False)

        self.log.info("No presign once the refund path is final, unless allow_late_claim is set")
        late_lock = node.getblockcount() + 2
        late_pub = self.checksummed(f"mr(htlc_sha256({hashlock},{claimer_pk}),refund({late_lock},{refund_pk}))")
        self.import_lock(claimer, self.checksummed(f"mr(htlc_sha256({hashlock},{claimer_key}),refund({late_lock},{refund_pk}))"))
        late_addr = node.deriveaddresses(late_pub)[0]
        lt_txid, lt_vout, lt_value = self.fund(late_addr)
        lt_psbt, _ = self.claim_psbt(lt_txid, lt_vout, lt_value, dest)
        lt_leaf = {f"{lt_txid}:{lt_vout}": 0}
        assert_equal(node.getblockcount(), late_lock - 1)
        assert_equal(claimer.walletprocesspsbt(lt_psbt, {"htlc_presign": True, "p2mr_leaf": lt_leaf})["complete"], False)
        mine_block(self, node, self.mine_addr)
        assert_raises_rpc_error(None, f"the refund path of {lt_txid}:{lt_vout} is already final (refund locktime {late_lock}, tip height {late_lock})",
                                claimer.walletprocesspsbt, lt_psbt, {"htlc_presign": True, "p2mr_leaf": lt_leaf})
        late = claimer.walletprocesspsbt(lt_psbt, {"htlc_presign": True, "p2mr_leaf": lt_leaf, "allow_late_claim": True})
        assert_equal(late["complete"], False)

        self.log.info("The refund leaf of a funding that is not broadcast yet can still be signed")
        # The sender signs its refund before it sends the funding. That signing has no
        # htlc_presign, so none of the checks above apply. nokey holds the refund key of nk_addr.
        r_psbt = PSBT.from_base64(node.createpsbt([{"txid": "22" * 32, "vout": 0}], [{dest: Decimal("0.5")}], lock, True))
        r_psbt.i[0].map[bytes([PSBT_IN_WITNESS_UTXO])] = CTxOut(50_100_000, bytes.fromhex(node.validateaddress(nk_addr)["scriptPubKey"])).serialize()
        refund = nokey.walletprocesspsbt(r_psbt.to_base64(), {"p2mr_leaf": {f"{'22' * 32}:0": 1}, "finalize": False})
        r_sigs = node.decodepsbt(refund["psbt"])["inputs"][0].get("p2mr_partial_signatures", [])
        assert_equal([s["pubkey"] for s in r_sigs], [nokey_pk])

        self.log.info("Watchtower: add the real preimage, finalize without the wallet, broadcast")
        final = node.finalizepsbt(with_preimage(presigned["psbt"], secret))
        assert_equal(final["complete"], True)
        assert_equal(node.testmempoolaccept([final["hex"]])[0]["allowed"], True)
        claim_txid = node.sendrawtransaction(final["hex"])
        mine_block(self, node, self.mine_addr)
        assert_equal(claimer.gettransaction(claim_txid)["confirmations"], 1)
        witness = tx_from_hex(final["hex"]).wit.vtxinwit[0].scriptWitness.stack
        assert secret in witness
        assert_equal(claimer.getreceivedbyaddress(dest), amount)


if __name__ == "__main__":
    WalletHtlcPresignTest(__file__).main()
