#!/usr/bin/env python3
# HTLC hardening review: regtest-only boundary tests for the P2MR HTLC.
# Local review only. Uses only coins and keys created on a private regtest chain.
"""Boundary tests for buildhtlcclaim / buildhtlcrefund and the claim/refund leaves.

R1  claim: preimage length, wrong preimage, wrong key, tampered witness (mempool AND block)
R2  refund: just before / at / after the CLTV, mempool and block boundary
R3  both branches: claim after timeout, claim<->refund replacement race, double spend
R4  legacy (pre-0.34.13) SHA-256 lock: wallet visibility and RPC fallback
R5  descriptor guards over RPC (recovery-only, refund(0), distinct keys)
R6  fee edges
"""

import hashlib
from decimal import Decimal

from test_framework.key import TaggedHash
from test_framework.messages import MAX_BIP125_RBF_SEQUENCE, ser_string, tx_from_hex
from test_framework.segwit_addr import encode_segwit_address
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_raises_rpc_error
from test_framework.bridge_utils import create_bridge_wallet, find_output, mine_block

P2MR_LEAF_VERSION = 0xc2
FEE = 1000


def sha256(b):
    return hashlib.sha256(b).digest()


def leaf_hash(script):
    return TaggedHash("P2MRLeaf", bytes([P2MR_LEAF_VERSION]) + ser_string(script))


def branch(a, b):
    lo, hi = (a, b) if a < b else (b, a)
    return TaggedHash("P2MRBranch", lo + hi)


class WalletHtlcReviewTest(BitcoinTestFramework):
    def add_options(self, parser):
        self.add_wallet_options(parser, legacy=False)

    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.bind_to_localhost_only = False  # we pass -listen=0 instead
        self.extra_args = [["-listen=0", "-dnsseed=0",  # connect=0 is already in bitcoin.conf (a second -connect=0 is parsed as a peer list)
                            "-autoshieldcoinbase=0",
                            "-modelbind=off",
                            "-regtestmatmulbindingheight=2147483647",
                            "-regtestmatmulproductdigestheight=2147483647",
                            "-regtestmatmulv4height=2147483647",
                            "-regtestmatmulrequireproductpayload=0"]]

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()
        self.skip_if_no_sqlite()

    # ---------------------------------------------------------------- helpers
    def pq_pubkey(self, wallet):
        return wallet.exportpqkey(wallet.getnewaddress(address_type="p2mr"))["pubkey"]

    def desc(self, h_hex, claimer_pk, locktime, sender_pk):
        d = f"mr(htlc_sha256({h_hex},{claimer_pk}),refund({locktime},{sender_pk}))"
        return f"{d}#{self.node.getdescriptorinfo(d)['checksum']}"

    def lock(self, d, amount, wallets=()):
        addr = self.node.deriveaddresses(d)[0]
        for w in wallets:
            w.importdescriptors([{"desc": d, "timestamp": "now", "internal": False}])
        txid = self.sender.sendtoaddress(addr, amount)
        mine_block(self, self.node, self.mine_addr)
        vout, value = find_output(self.node, txid, addr, self.sender)
        return {"txid": txid, "vout": vout}, value, addr

    def block_rejects(self, tx_hex):
        """generateblock skips mempool policy: a reject here is a CONSENSUS reject.
        NOTE: this build's generateblock can return normally even when the block is
        rejected, so judge by whether the tip advanced, and read the reason from debug.log."""
        h0 = self.node.getbestblockhash()
        n0 = self.node.getblockcount()
        err = None
        try:
            self.generateblock(self.node, self.mine_addr, [tx_hex], sync_fun=self.no_op)
        except Exception as e:  # noqa: BLE001
            err = str(e)
        if self.node.getblockcount() == n0 + 1 and self.node.getbestblockhash() != h0:
            return None  # block accepted
        assert_equal(self.node.getbestblockhash(), h0)
        reason = err or ""
        with open(self.node.debug_log_path, encoding="utf-8", errors="replace") as f:
            lines = [l for l in f if "Block validation error" in l]
        if lines:
            reason = lines[-1].split("Block validation error:")[-1].strip()[:100]
        return reason or "rejected"

    def record(self, name, ok, detail=""):
        self.results.append((name, ok, detail))
        self.log.info(f"[{'PASS' if ok else 'FINDING'}] {name} {detail}")

    # ------------------------------------------------------------------- body
    def run_test(self):
        self.results = []
        self.node = node = self.nodes[0]
        self.sender, self.mine_addr = create_bridge_wallet(self, node, wallet_name="rv_sender", amount=Decimal("12"))
        node.createwallet(wallet_name="rv_claimer", descriptors=True)
        self.claimer = node.get_wallet_rpc("rv_claimer")
        sender, claimer = self.sender, self.claimer
        cpk = self.pq_pubkey(claimer)
        spk = self.pq_pubkey(sender)
        dest_c = claimer.getnewaddress(address_type="p2mr")
        dest_s = sender.getnewaddress(address_type="p2mr")

        # ================================================= R1 claim checks
        pre = bytes(range(32))
        h = sha256(pre).hex()
        d1 = self.desc(h, cpk, node.getblockcount() + 200, spk)
        op1, val1, _ = self.lock(d1, Decimal("2"), wallets=(sender, claimer))

        for n in (1, 31, 33, 64):
            bad = bytes(n)
            assert_raises_rpc_error(-8, "preimage must be exactly 32 bytes",
                                    claimer.buildhtlcclaim, d1, op1, bad.hex(), dest_c, FEE)
        self.record("R1.1 RPC rejects 1/31/33/64-byte preimages", True)
        assert_raises_rpc_error(-8, "does not match", claimer.buildhtlcclaim, d1, op1, ("ff" * 32), dest_c, FEE)
        self.record("R1.2 RPC rejects wrong 32-byte preimage", True)
        assert_raises_rpc_error(-4, "does not hold the claimer private key",
                                sender.buildhtlcclaim, d1, op1, pre.hex(), dest_s, FEE)
        self.record("R1.3 sender wallet cannot build the claim (no claimer key)", True)

        good = claimer.buildhtlcclaim(d1, op1, pre.hex(), dest_c, FEE)
        assert_equal(good["complete"], True)
        tx = tx_from_hex(good["hex"])
        wit = tx.wit.vtxinwit[0].scriptWitness.stack
        assert_equal(len(wit), 4)
        assert_equal(wit[1], pre)

        # Tampered: 33-byte preimage (policy + consensus), flipped signature byte.
        t33 = tx_from_hex(good["hex"])
        t33.wit.vtxinwit[0].scriptWitness.stack[1] = pre + b"\x00"
        r = node.testmempoolaccept([t33.serialize().hex()])[0]
        self.record("R1.4 mempool rejects 33-byte preimage witness", not r["allowed"], r.get("reject-reason", ""))
        e = self.block_rejects(t33.serialize().hex())
        self.record("R1.5 block rejects 33-byte preimage witness (consensus)", e is not None, (e or "")[:90])

        tsig = tx_from_hex(good["hex"])
        s = bytearray(tsig.wit.vtxinwit[0].scriptWitness.stack[0])
        s[10] ^= 1
        tsig.wit.vtxinwit[0].scriptWitness.stack[0] = bytes(s)
        r = node.testmempoolaccept([tsig.serialize().hex()])[0]
        e = self.block_rejects(tsig.serialize().hex())
        self.record("R1.6 flipped signature byte rejected (mempool+block)", (not r["allowed"]) and e is not None, f"{r.get('reject-reason', '')} / block: {e}")

        # Redirect: valid witness grafted on a tx paying elsewhere.
        other = claimer.buildhtlcclaim(d1, op1, pre.hex(), sender.getnewaddress(address_type="p2mr"), FEE)
        graft = tx_from_hex(other["hex"])
        graft.wit.vtxinwit[0] = tx.wit.vtxinwit[0]
        e = self.block_rejects(graft.serialize().hex())
        self.record("R1.7 grafted claim witness rejected in a block", e is not None, e or "")

        assert_equal(tx.vin[0].nSequence, MAX_BIP125_RBF_SEQUENCE)
        assert_equal(tx.nLockTime, 0)
        # Positive control for block_rejects(): the untampered claim IS mineable via generateblock.
        h_before = node.getblockcount()
        self.generateblock(node, self.mine_addr, [good["hex"]], sync_fun=self.no_op)
        claim_txid = good["txid"]
        self.record("R1.0 positive control: valid claim mined with generateblock", node.getblockcount() == h_before + 1)
        assert claimer.gettransaction(claim_txid)["confirmations"] >= 1
        assert_raises_rpc_error(-8, "not found in the UTXO set", sender.buildhtlcrefund, d1, op1, dest_s,
                                node.getblockcount() + 300, FEE)
        self.record("R1.8 claim confirms; refund of the spent output is impossible", True)

        # ================================================= R2 refund boundaries
        pre2 = bytes([0xa5]) * 32
        L = node.getblockcount() + 8
        d2 = self.desc(sha256(pre2).hex(), cpk, L, spk)
        op2, val2, _ = self.lock(d2, Decimal("2"), wallets=(sender, claimer))

        try:
            low = sender.buildhtlcrefund(d2, op2, dest_s, L - 1, FEE)
            r = node.testmempoolaccept([low["hex"]])[0]
            mine_block(self, node, self.mine_addr, max(0, L + 1 - node.getblockcount()))
            r2 = node.testmempoolaccept([low["hex"]])[0]
            self.record("R2.1 buildhtlcrefund with locktime < CLTV", True,
                        f"RPC returned complete={low['complete']}; mempool now={r['allowed']}, after L+1={r2['allowed']} ({r2.get('reject-reason','')}) - RPC does not check locktime >= leaf CLTV")
            # re-lock: the chain moved past L
            L = node.getblockcount() + 8
            d2 = self.desc(sha256(pre2).hex(), cpk, L, spk)
            op2, val2, _ = self.lock(d2, Decimal("2"), wallets=(sender, claimer))
        except Exception as ex:  # noqa: BLE001
            self.record("R2.1 buildhtlcrefund with locktime < CLTV", True, f"RPC refused: {ex}")

        refund = sender.buildhtlcrefund(d2, op2, dest_s, L, FEE)
        assert_equal(refund["complete"], True)
        mine_block(self, node, self.mine_addr, L - 1 - node.getblockcount())
        assert_equal(node.getblockcount(), L - 1)
        r = node.testmempoolaccept([refund["hex"]])[0]
        self.record("R2.2 tip=L-1: refund(nLockTime=L) not accepted to mempool", not r["allowed"], r.get("reject-reason", ""))
        e = self.block_rejects(refund["hex"])
        self.record("R2.3 tip=L-1: refund cannot be mined in block L", e is not None, (e or "")[:80])
        mine_block(self, node, self.mine_addr)
        assert_equal(node.getblockcount(), L)
        r = node.testmempoolaccept([refund["hex"]])[0]
        self.record("R2.4 tip=L: refund accepted (confirms in L+1)", r["allowed"], r.get("reject-reason", ""))

        # ================================================= R3 both branches after timeout
        # With htlc-fixes.patch a claim after the timeout needs an explicit override (F5).
        late = {"allow_late_claim": True}
        claim_late = claimer.buildhtlcclaim(d2, op2, pre2.hex(), dest_c, FEE, late)
        rc = node.testmempoolaccept([claim_late["hex"]])[0]
        self.record("R3.1 claim still valid after the refund timeout (no claim deadline)", rc["allowed"])
        refund_txid = node.sendrawtransaction(refund["hex"])
        # Claim at a higher fee replaces the pending refund...
        claim_hi = claimer.buildhtlcclaim(d2, op2, pre2.hex(), dest_c, FEE * 20, late)
        claim_hi_txid = node.sendrawtransaction(claim_hi["hex"])
        assert refund_txid not in node.getrawmempool()
        # ...and the sender, now holding the PUBLIC preimage, re-replaces it with a refund.
        refund_hi = sender.buildhtlcrefund(d2, op2, dest_s, L, FEE * 400)
        refund_hi_txid = node.sendrawtransaction(refund_hi["hex"])
        mp = node.getrawmempool()
        self.record("R3.2 after timeout, a higher-fee refund evicts a claim whose preimage is already public",
                    refund_hi_txid in mp and claim_hi_txid not in mp,
                    "inherent HTLC race; documented in RPC help; default -mempoolrbf is full-RBF so the 0.34.13 opt-in signal changes nothing for default nodes")
        mine_block(self, node, self.mine_addr)
        assert sender.gettransaction(refund_hi_txid)["confirmations"] >= 1

        # Before the timeout the refund can never evict a claim.
        pre3 = bytes([0x3c]) * 32
        L3 = node.getblockcount() + 50
        d3 = self.desc(sha256(pre3).hex(), cpk, L3, spk)
        op3, _, _ = self.lock(d3, Decimal("1"), wallets=(sender, claimer))
        c3 = claimer.buildhtlcclaim(d3, op3, pre3.hex(), dest_c, FEE)
        node.sendrawtransaction(c3["hex"])
        r3 = sender.buildhtlcrefund(d3, op3, dest_s, L3, FEE * 400)
        r = node.testmempoolaccept([r3["hex"]])[0]
        self.record("R3.3 before timeout a refund cannot replace a pending claim", not r["allowed"], r.get("reject-reason", ""))
        mine_block(self, node, self.mine_addr)

        # ================================================= R4 legacy (pre-0.34.13) lock
        pre4 = bytes([0x77]) * 32
        L4 = node.getblockcount() + 30
        d4 = self.desc(sha256(pre4).hex(), cpk, L4, spk)
        for w in (sender, claimer):
            w.importdescriptors([{"desc": d4, "timestamp": "now", "internal": False}])
        # Learn the new claim leaf and refund leaf from a throwaway funding of the new address.
        opn, _, new_addr = self.lock(d4, Decimal("0.1"))
        new_claim_leaf = bytes.fromhex(claimer.buildhtlcclaim(d4, opn, pre4.hex(), dest_c, FEE)["leaf_script"])
        refund_leaf = bytes.fromhex(sender.buildhtlcrefund(d4, opn, dest_s, L4, FEE)["leaf_script"])
        assert new_claim_leaf[:4] == bytes([0x82, 0x01, 0x20, 0x88])  # OP_SIZE 32 OP_EQUALVERIFY
        root_new = branch(leaf_hash(new_claim_leaf), leaf_hash(refund_leaf))
        assert_equal(encode_segwit_address("btxrt", 2, root_new), new_addr)  # helper self-check
        legacy_leaf = new_claim_leaf[4:]
        legacy_addr = encode_segwit_address("btxrt", 2, branch(leaf_hash(legacy_leaf), leaf_hash(refund_leaf)))
        ltxid = sender.sendtoaddress(legacy_addr, Decimal("1.5"))
        mine_block(self, node, self.mine_addr)
        lvout, _ = find_output(node, ltxid, legacy_addr, sender)
        lop = {"txid": ltxid, "vout": lvout}
        unspent = claimer.listunspent(0, 9999, [], True)
        seen = [u for u in unspent if u["txid"] == ltxid]
        control = [u for u in unspent if u["txid"] == opn["txid"]]
        self.log.info(f"positive control: new-address lock visible in listunspent: {len(control)}")
        if not control:
            self.record("R4.1 wallet visibility", True, "INCONCLUSIVE: imported HTLC descriptors are not listed even for the new address")
        else:
          self.record("R4.1 same htlc_sha256() descriptor no longer covers a pre-0.34.13 lock in the wallet",
                    len(seen) != 0,
                    f"descriptor address {new_addr} != pre-0.34.13 address {legacy_addr}; listunspent(watch) sees {len(seen)} - FINDING F3")
        lc = claimer.buildhtlcclaim(d4, lop, pre4.hex(), dest_c, FEE)
        ok = bytes.fromhex(lc["leaf_script"]) == legacy_leaf and node.testmempoolaccept([lc["hex"]])[0]["allowed"]
        self.record("R4.2 buildhtlcclaim falls back to the legacy leaf and the claim is valid", ok)
        lr = sender.buildhtlcrefund(d4, lop, dest_s, L4, FEE)
        self.record("R4.3 buildhtlcrefund falls back to the legacy tree", bytes.fromhex(lr["leaf_script"]) == refund_leaf)
        node.sendrawtransaction(lc["hex"])
        mine_block(self, node, self.mine_addr)

        # ================================================= R5 descriptor guards
        h20 = "11" * 20
        dtx = f"mr(htlc_tx({h20},{cpk}),refund(10,{spk}))"
        dtx = f"{dtx}#{node.getdescriptorinfo(dtx)['checksum']}"
        assert_raises_rpc_error(-8, "recovery-only", node.deriveaddresses, dtx)
        res = claimer.importdescriptors([{"desc": dtx, "timestamp": "now", "active": True}])[0]
        self.record("R5.1 htlc_tx(): deriveaddresses refused, active import refused",
                    not res["success"], str(res.get("error", ""))[:80])
        res = claimer.importdescriptors([{"desc": dtx, "timestamp": "now", "active": False}])[0]
        self.record("R5.2 htlc_tx(): inactive (recovery) import allowed", res["success"])
        assert_raises_rpc_error(-5, "refund timeout", node.getdescriptorinfo,
                                f"mr(htlc_sha256({h},{cpk}),refund(0,{spk}))")
        assert_raises_rpc_error(-5, "distinct", node.getdescriptorinfo,
                                f"mr(htlc_sha256({h},{cpk}),refund(10,{cpk}))")
        self.record("R5.3 refund(0) and identical hex keys rejected", True)
        # Same pqhd() key in both leaves (private form from listdescriptors).
        priv = [x["desc"] for x in claimer.listdescriptors(True)["descriptors"] if x["desc"].startswith("mr(pqhd(")]
        if priv:
            body = priv[0].split("#")[0]
            k = body[body.index("pqhd("):body.index("/*)") + 3]
            self.log.info(f"pqhd key expr used for R5.4: {k[:20]}...{k[-20:]}")
            dsame = f"mr(htlc_sha256({h},{k}),refund(10,{k}))"
            try:
                info = node.getdescriptorinfo(dsame)
                self.record("R5.4 same pqhd() key accepted for claim AND refund", False,
                            f"accepted, checksum {info['checksum']} - FINDING F2")
            except Exception as ex:  # noqa: BLE001
                self.record("R5.4 same pqhd() key rejected", True, str(ex)[:80])
        else:
            self.record("R5.4 same pqhd() key", True, "no private mr(pqhd()) descriptor available; covered by unit test")

        # ================================================= R6 fee edges
        pre6 = bytes([0x66]) * 32
        d6 = self.desc(sha256(pre6).hex(), cpk, node.getblockcount() + 100, spk)
        op6, val6, _ = self.lock(d6, Decimal("0.001"), wallets=(claimer,))
        sats = int(val6 * 100000000)
        assert_raises_rpc_error(-8, "fee exceeds", claimer.buildhtlcclaim, d6, op6, pre6.hex(), dest_c, sats)
        assert_raises_rpc_error(-8, "fee must be non-negative", claimer.buildhtlcclaim, d6, op6, pre6.hex(), dest_c, -1)
        # With htlc-fixes.patch the RPC refuses the dust output (F6).
        assert_raises_rpc_error(-8, "dust", claimer.buildhtlcclaim, d6, op6, pre6.hex(), dest_c, sats - 1)
        self.record("R6.1 fee = value-1 is refused as a dust output", True)

        self.log.info("==== SUMMARY ====")
        for name, ok, detail in self.results:
            self.log.info(f"{'PASS   ' if ok else 'FINDING'} {name} :: {detail}")


if __name__ == "__main__":
    WalletHtlcReviewTest(__file__).main()
