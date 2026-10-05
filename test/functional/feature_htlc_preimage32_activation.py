#!/usr/bin/env python3
# HTLC hardening review (second pass): F1 fix, activation of the 32-byte preimage rule.
# Local review only. Uses only coins and keys created on a private regtest chain.
"""SCRIPT_VERIFY_P2MR_HTLC_PREIMAGE32 is policy at once and consensus from its height.

Below -regtesthtlcpreimage32height a block may contain a legacy SHA-256 HTLC claim
with a 33-byte preimage (as v0.34.12 allows); from that height such a block is
rejected. The spend is non-standard throughout. A 32-byte claim is valid on both
sides of the height.

Requires htlc-fixes.patch (the option and htlc_sha256_legacy() do not exist in v0.34.13).
"""

import hashlib
from decimal import Decimal

import test_framework.util as tf_util
from test_framework.key import TaggedHash
from test_framework.messages import ser_string, tx_from_hex, CTxInWitness
from test_framework.psbt import PSBT, PSBT_IN_SHA256
from test_framework.segwit_addr import encode_segwit_address
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal
from test_framework.bridge_utils import create_bridge_wallet, find_output, mine_block

tf_util.PORT_RANGE = 20

P2MR_LEAF_VERSION = 0xc2
FEE = 1000
ACTIVATION = 130


def sha256(b):
    return hashlib.sha256(b).digest()


def leaf_hash(script):
    return TaggedHash("P2MRLeaf", bytes([P2MR_LEAF_VERSION]) + ser_string(script))


def branch(a, b):
    lo, hi = (a, b) if a < b else (b, a)
    return TaggedHash("P2MRBranch", lo + hi)


class HtlcPreimage32ActivationTest(BitcoinTestFramework):
    def add_options(self, parser):
        self.add_wallet_options(parser, legacy=False)

    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.bind_to_localhost_only = False
        self.extra_args = [["-listen=0", "-dnsseed=0", "-autoshieldcoinbase=0", "-modelbind=off", "-modelnet=0",
                            "-regtestmatmulbindingheight=2147483647",
                            "-regtestmatmulproductdigestheight=2147483647",
                            "-regtestmatmulv4height=2147483647",
                            "-regtestmatmulrequireproductpayload=0",
                            f"-regtesthtlcpreimage32height={ACTIVATION}"]]

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()
        self.skip_if_no_sqlite()

    def desc(self, body):
        return f"{body}#{self.node.getdescriptorinfo(body)['checksum']}"

    def try_block(self, tx_hex):
        """Return (accepted, error). Judged by the tip, and by generateblock's error."""
        h0, n0 = self.node.getbestblockhash(), self.node.getblockcount()
        err = None
        try:
            self.generateblock(self.node, self.mine_addr, [tx_hex], sync_fun=self.no_op)
        except Exception as e:  # noqa: BLE001
            err = str(e)
        accepted = self.node.getblockcount() == n0 + 1 and self.node.getbestblockhash() != h0
        return accepted, err

    def run_test(self):
        self.node = node = self.nodes[0]
        self.sender, self.mine_addr = create_bridge_wallet(self, node, wallet_name="act_sender", amount=Decimal("12"))
        sender = self.sender
        node.createwallet(wallet_name="act_claimer", descriptors=True)
        claimer = node.get_wallet_rpc("act_claimer")
        cpk = claimer.exportpqkey(claimer.getnewaddress(address_type="p2mr"))["pubkey"]  # index 0
        priv = [x["desc"] for x in claimer.listdescriptors(True)["descriptors"]
                if x["desc"].startswith("mr(pqhd(") and not x["internal"]]
        body = priv[0].split("#")[0]
        K = body[body.index("pqhd("):body.index("/*)") + 3]
        spk = sender.exportpqkey(sender.getnewaddress(address_type="p2mr"))["pubkey"]
        dest_c = claimer.getnewaddress(address_type="p2mr")
        L = 400
        assert node.getblockcount() < ACTIVATION - 10, node.getblockcount()

        # Learn the claimer's pubkey push + CHECKSIG opcode and the refund leaf
        # from a throwaway current-format lock with the same keys and timeout.
        p0 = bytes([0x01]) * 32
        d0 = self.desc(f"mr(htlc_sha256({sha256(p0).hex()},{cpk}),refund({L},{spk}))")
        a0 = node.deriveaddresses(d0)[0]
        t0 = sender.sendtoaddress(a0, Decimal("0.1"))
        mine_block(self, node, self.mine_addr)
        v0, _ = find_output(node, t0, a0, sender)
        new_leaf = bytes.fromhex(claimer.buildhtlcclaim(d0, {"txid": t0, "vout": v0}, p0.hex(), dest_c, FEE)["leaf_script"])
        refund_leaf = bytes.fromhex(sender.buildhtlcrefund(d0, {"txid": t0, "vout": v0}, dest_c, L, FEE)["leaf_script"])
        key_and_checksig = new_leaf[4 + 35:]

        def legacy_lock(secret, amount):
            h = sha256(secret)
            leaf = bytes([0xa8, 0x20]) + h + bytes([0x88]) + key_and_checksig
            addr = encode_segwit_address("btxrt", 2, branch(leaf_hash(leaf), leaf_hash(refund_leaf)))
            d = self.desc(f"mr(htlc_sha256_legacy({h.hex()},{K}),refund({L},{spk}))")
            res = claimer.importdescriptors([{"desc": d, "range": [0, 0], "timestamp": 0, "active": False}])[0]
            assert res["success"], res
            txid = sender.sendtoaddress(addr, amount)
            return h, leaf, addr, txid

        def sign_claim(h, leaf, addr, txid, secret):
            vout, value = find_output(node, txid, addr, sender)
            out_amt = value - Decimal(FEE) / Decimal(100000000)
            psbt = PSBT.from_base64(node.createpsbt([{"txid": txid, "vout": vout}], [{dest_c: out_amt}], 0))
            psbt.i[0].map[bytes([PSBT_IN_SHA256]) + h] = secret
            processed = claimer.walletprocesspsbt(psbt.to_base64(), True, "DEFAULT", True, False)
            dec = node.decodepsbt(processed["psbt"])["inputs"][0]
            sigs = [s for s in dec.get("p2mr_partial_signatures", []) if s["pubkey"] == cpk]
            assert sigs, f"no claimer signature in the PSBT: {dec.keys()}"
            control = bytes([P2MR_LEAF_VERSION]) + leaf_hash(refund_leaf)
            tx = tx_from_hex(dec_tx_hex(processed["psbt"]))
            tx.wit.vtxinwit = [CTxInWitness()]
            tx.wit.vtxinwit[0].scriptWitness.stack = [bytes.fromhex(sigs[0]["signature"]), secret, leaf, control]
            return tx.serialize().hex()

        def dec_tx_hex(psbt_b64):
            return PSBT.from_base64(psbt_b64).tx.serialize().hex()

        sa, sb, sc = bytes([0xa1]) * 33, bytes([0xb2]) * 33, bytes([0xc3]) * 32
        la = legacy_lock(sa, Decimal("1"))
        lb = legacy_lock(sb, Decimal("1"))
        lc = legacy_lock(sc, Decimal("1"))
        mine_block(self, node, self.mine_addr)
        claim_a = sign_claim(*la, sa)
        claim_b = sign_claim(*lb, sb)
        claim_c = sign_claim(*lc, sc)

        results = []
        r = node.testmempoolaccept([claim_a])[0]
        results.append(("A1 before activation: 33-byte legacy claim is non-standard", not r["allowed"], r.get("reject-reason")))
        height_a = node.getblockcount() + 1
        ok, err = self.try_block(claim_a)
        results.append((f"A2 before activation (block {height_a} < {ACTIVATION}): the block is valid, as in v0.34.12", ok, err or ""))

        mine_block(self, node, self.mine_addr, ACTIVATION - 1 - node.getblockcount())
        assert_equal(node.getblockcount(), ACTIVATION - 1)
        ok, err = self.try_block(claim_b)
        results.append((f"A3 at activation (block {ACTIVATION}): a block with a 33-byte legacy claim is rejected",
                        not ok and err is not None, (err or "accepted")[:110]))
        ok, err = self.try_block(claim_c)
        results.append((f"A4 at activation (block {ACTIVATION}): a 32-byte legacy claim is valid", ok, err or ""))

        for name, ok, detail in results:
            self.log.info(f"{'PASS' if ok else 'FAIL'} {name} :: {detail}")
        assert all(ok for _, ok, _ in results)


if __name__ == "__main__":
    HtlcPreimage32ActivationTest(__file__).main()
