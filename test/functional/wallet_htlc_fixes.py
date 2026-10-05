#!/usr/bin/env python3
# HTLC hardening review (second pass): regression tests for the proposed fixes.
# Local review only. Uses only coins and keys created on a private regtest chain.
"""Each check records PASS when the fixed behaviour is present, FAIL otherwise.

On an unpatched v0.34.13 build the F*/N* checks FAIL (that is the reproduction);
with htlc-fixes.patch applied every check PASSES. O* checks are observations
that hold on both builds.

F2  claim/refund distinct-key rule: same pqhd() key, every claim/refund pair,
    expanded keys in buildhtlcclaim
F3  htlc_sha256_legacy(): a wallet can watch and claim a pre-0.34.13 lock
F5  buildhtlcclaim refuses a claim once the refund is already final
F6  buildhtlcclaim / buildhtlcrefund refuse dust outputs and fees above -maxtxfee
F7  generateblock reports a block that fails validation
N2  buildhtlcclaim refuses to reveal the preimage against an unconfirmed funding output
N3  bridge refund_lock_height must be a block height (< 500000000)
O1  time-based (MTP) refund lock on chain
O2  a reorg that removes a confirmed claim after the timeout lets the refund win
"""

import hashlib
import time
from decimal import Decimal

import test_framework.util as tf_util
from test_framework.key import TaggedHash
from test_framework.messages import ser_string, tx_from_hex, COIN
from test_framework.segwit_addr import encode_segwit_address
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal
from test_framework.bridge_utils import bridge_hex, create_bridge_wallet, find_output, mine_block, planout

# Keep p2p, rpc and tor ports in 28443-28499.
tf_util.PORT_RANGE = 20

P2MR_LEAF_VERSION = 0xc2
FEE = 1000


def sha256(b):
    return hashlib.sha256(b).digest()


def leaf_hash(script):
    return TaggedHash("P2MRLeaf", bytes([P2MR_LEAF_VERSION]) + ser_string(script))


def branch(a, b):
    lo, hi = (a, b) if a < b else (b, a)
    return TaggedHash("P2MRBranch", lo + hi)


class WalletHtlcFixesTest(BitcoinTestFramework):
    def add_options(self, parser):
        self.add_wallet_options(parser, legacy=False)

    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.bind_to_localhost_only = False  # -listen=0 instead: no p2p socket at all
        self.extra_args = [["-listen=0", "-dnsseed=0",
                            "-autoshieldcoinbase=0",
                            "-modelbind=off", "-modelnet=0",
                            "-regtestmatmulbindingheight=2147483647",
                            "-regtestmatmulproductdigestheight=2147483647",
                            "-regtestmatmulv4height=2147483647",
                            "-regtestmatmulrequireproductpayload=0"]]

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()
        self.skip_if_no_sqlite()

    # ---------------------------------------------------------------- helpers
    def record(self, name, ok, detail=""):
        self.results.append((name, ok, detail))
        self.log.info(f"[{'PASS' if ok else 'FAIL'}] {name} {detail}")

    def rpc_error(self, fn, *args):
        """Return the RPC error message, or None if the call succeeded."""
        try:
            fn(*args)
        except Exception as e:  # noqa: BLE001
            return str(e)
        return None

    def pq_pubkey(self, wallet):
        return wallet.exportpqkey(wallet.getnewaddress(address_type="p2mr"))["pubkey"]

    def desc(self, body):
        return f"{body}#{self.node.getdescriptorinfo(body)['checksum']}"

    def lock(self, d, amount, wallets=(), confirm=True):
        addr = self.node.deriveaddresses(d)[0]
        for w in wallets:
            w.importdescriptors([{"desc": d, "timestamp": "now", "internal": False}])
        txid = self.sender.sendtoaddress(addr, amount)
        if confirm:
            mine_block(self, self.node, self.mine_addr)
        vout, value = find_output(self.node, txid, addr, self.sender)
        return {"txid": txid, "vout": vout}, value, addr

    def mine_to(self, height):
        n = height - self.node.getblockcount()
        if n > 0:
            mine_block(self, self.node, self.mine_addr, n)
        assert_equal(self.node.getblockcount(), height)

    # ------------------------------------------------------------------- body
    def run_test(self):
        self.results = []
        self.node = node = self.nodes[0]
        self.sender, self.mine_addr = create_bridge_wallet(self, node, wallet_name="fx_sender", amount=Decimal("12"))
        node.createwallet(wallet_name="fx_claimer", descriptors=True)
        self.claimer = node.get_wallet_rpc("fx_claimer")
        sender, claimer = self.sender, self.claimer
        cpk_addr = claimer.getnewaddress(address_type="p2mr")  # index 0
        cpk = claimer.exportpqkey(cpk_addr)["pubkey"]
        spk = self.pq_pubkey(sender)
        dest_c = claimer.getnewaddress(address_type="p2mr")
        dest_s = sender.getnewaddress(address_type="p2mr")
        priv = [x["desc"] for x in claimer.listdescriptors(True)["descriptors"]
                if x["desc"].startswith("mr(pqhd(") and not x["internal"]]
        body = priv[0].split("#")[0]
        K = body[body.index("pqhd("):body.index("/*)") + 3]

        # ================================================= F2 distinct keys
        h = sha256(b"f2").hex()
        e = self.rpc_error(node.getdescriptorinfo, f"mr(htlc_sha256({h},{K}),refund(10,{K}))")
        self.record("F2.1 same pqhd() key in claim and refund rejected", e is not None and "distinct" in e, (e or "accepted")[:90])
        e = self.rpc_error(node.getdescriptorinfo, f"mr(htlc_sha256({h},{cpk}),{{refund(10,{cpk}),refund(20,{spk})}})")
        self.record("F2.2 every claim/refund pair is compared, not only the last", e is not None and "distinct" in e, (e or "accepted")[:90])
        dummy = {"txid": "11" * 32, "vout": 0}
        mixed = f"mr(htlc_sha256({sha256(bytes(32)).hex()},{K}),refund(10,{cpk}))"
        e = self.rpc_error(claimer.buildhtlcclaim, mixed, dummy, bytes(32).hex(), dest_c, FEE)
        self.record("F2.3 buildhtlcclaim compares the EXPANDED keys (pqhd vs the same key in hex)",
                    e is not None and "distinct" in e, (e or "accepted")[:90])

        # ================================================= N5 mr() with a backup tree round-trips
        h5 = sha256(b"n5").hex()
        d5b = f"mr(htlc_sha256({h5},{cpk}),{{refund(700,{spk}),{self.pq_pubkey(sender)}}})"
        canon = node.getdescriptorinfo(d5b)["descriptor"]
        e = self.rpc_error(node.getdescriptorinfo, canon)
        self.record("N5.1 getdescriptorinfo output for a 3-leaf mr() parses again", e is None, (e or "ok")[:90])
        node.createwallet(wallet_name="fx_tree", disable_private_keys=True, descriptors=True)
        wt = node.get_wallet_rpc("fx_tree")
        r = wt.importdescriptors([{"desc": self.desc(d5b), "timestamp": "now"}])[0]
        node.unloadwallet("fx_tree")
        e = self.rpc_error(node.loadwallet, "fx_tree")
        self.record("N5.2 a wallet that imported a 3-leaf mr() descriptor loads again", r["success"] and e is None,
                    f"import={r['success']}; reload: {(e or 'ok')[:100]}")

        # ================================================= F3 legacy lock visible + claimable
        pre3 = bytes([0x77]) * 32
        L3 = node.getblockcount() + 300
        d3 = self.desc(f"mr(htlc_sha256({sha256(pre3).hex()},{cpk}),refund({L3},{spk}))")
        opn, _, new_addr = self.lock(d3, Decimal("0.1"))
        new_claim_leaf = bytes.fromhex(claimer.buildhtlcclaim(d3, opn, pre3.hex(), dest_c, FEE)["leaf_script"])
        refund_leaf = bytes.fromhex(sender.buildhtlcrefund(d3, opn, dest_s, L3, FEE)["leaf_script"])
        legacy_leaf = new_claim_leaf[4:]
        legacy_addr = encode_segwit_address("btxrt", 2, branch(leaf_hash(legacy_leaf), leaf_hash(refund_leaf)))
        ltxid = sender.sendtoaddress(legacy_addr, Decimal("1.5"))
        mine_block(self, node, self.mine_addr)
        lvout, _ = find_output(node, ltxid, legacy_addr, sender)
        lop = {"txid": ltxid, "vout": lvout}
        dleg_body = f"mr(htlc_sha256_legacy({sha256(pre3).hex()},{cpk}),refund({L3},{spk}))"
        e = self.rpc_error(node.getdescriptorinfo, dleg_body)
        if e is None:
            dleg = self.desc(dleg_body)
            res = claimer.importdescriptors([{"desc": dleg, "timestamp": 0, "internal": False}])[0]
            seen = [u for u in claimer.listunspent(0, 9999, [], True) if u["txid"] == ltxid]
            self.record("F3.1 htlc_sha256_legacy() import makes the pre-0.34.13 lock visible", res["success"] and len(seen) == 1,
                        f"import={res['success']} listunspent={len(seen)}")
            lc = claimer.buildhtlcclaim(dleg, lop, pre3.hex(), dest_c, FEE)
            ok = bytes.fromhex(lc["leaf_script"]) == legacy_leaf and node.testmempoolaccept([lc["hex"]])[0]["allowed"]
            self.record("F3.2 buildhtlcclaim accepts the htlc_sha256_legacy() descriptor directly", ok)
            e2 = self.rpc_error(node.deriveaddresses, dleg)
            self.record("F3.3 htlc_sha256_legacy() is recovery-only (no new address)", e2 is not None and "recovery-only" in e2, (e2 or "derived")[:80])
            node.sendrawtransaction(lc["hex"])
            mine_block(self, node, self.mine_addr)
        else:
            self.record("F3.1 htlc_sha256_legacy() import makes the pre-0.34.13 lock visible", False, e[:90])
            self.record("F3.2 buildhtlcclaim accepts the htlc_sha256_legacy() descriptor directly", False, "descriptor not supported")
            self.record("F3.3 htlc_sha256_legacy() is recovery-only (no new address)", False, "descriptor not supported")

        # ================================================= F6 dust / max fee
        pre6 = bytes([0x66]) * 32
        L6 = node.getblockcount() + 200
        d6 = self.desc(f"mr(htlc_sha256({sha256(pre6).hex()},{cpk}),refund({L6},{spk}))")
        op6, val6, _ = self.lock(d6, Decimal("2"))
        sats = int(val6 * COIN)
        e = self.rpc_error(claimer.buildhtlcclaim, d6, op6, pre6.hex(), dest_c, sats - 1)
        self.record("F6.1 buildhtlcclaim refuses a dust output", e is not None and "dust" in e, (e or "built")[:80])
        e = self.rpc_error(claimer.buildhtlcclaim, d6, op6, pre6.hex(), dest_c, sats // 2)
        self.record("F6.2 buildhtlcclaim refuses a fee above -maxtxfee", e is not None and "maxtxfee" in e, (e or "built")[:80])
        e = self.rpc_error(sender.buildhtlcrefund, d6, op6, dest_s, L6, sats - 1)
        self.record("F6.3 buildhtlcrefund refuses a dust output", e is not None and "dust" in e, (e or "built")[:80])
        e = self.rpc_error(claimer.buildhtlcclaim, d6, op6, pre6.hex(), dest_c, FEE, {"min_confirmations": 0})
        self.record("F8.1 min_confirmations of 0 is rejected", e is not None and "at least 1" in e, (e or "built")[:90])
        e = self.rpc_error(claimer.buildhtlcclaim, d6, op6, pre6.hex(), dest_c, FEE, {"min_confirmations": 2})
        self.record("F8.2 min_confirmations waits for the caller-chosen depth", e is not None and "will not be revealed yet" in e, (e or "built")[:90])
        e = self.rpc_error(claimer.buildhtlcclaim, d6, op6, pre6.hex(), dest_c, FEE, {"min_confirmations": 100000})
        self.record("F8.3 a confirmation wait that reaches the refund height is refused", e is not None and "would make the refund path final" in e, (e or "built")[:90])
        e = self.rpc_error(claimer.buildhtlcclaim, d6, op6, pre6.hex(), dest_c, FEE, {"allow_unconfirmed_funding": True, "min_confirmations": 1})
        self.record("F8.4 allow_unconfirmed_funding cannot be combined with min_confirmations", e is not None and "cannot be combined" in e, (e or "built")[:90])
        past = self.desc(f"mr(htlc_sha256({sha256(pre6).hex()},{cpk}),refund(500000000,{spk}))")
        e = self.rpc_error(node.deriveaddresses, past)
        self.record("F9.1 deriveaddresses refuses a refund timestamp that is already past", e is not None and "already in the past" in e, (e or "derived")[:90])
        watched = claimer.importdescriptors([{"desc": past, "timestamp": "now", "active": False}])[0]
        self.record("F9.2 a watch-only import of a matured refund timestamp still succeeds", watched.get("success") is True, str(watched)[:90])
        active = claimer.importdescriptors([{"desc": past, "timestamp": "now", "active": True}])[0]
        self.record("F9.3 an active import of a past refund timestamp is refused", active.get("success") is False and "already in the past" in active.get("error", {}).get("message", ""), str(active)[:120])
        future = self.desc(f"mr(htlc_sha256({sha256(pre6).hex()},{cpk}),refund(2000000000,{spk}))")
        self.record("F9.4 a future refund timestamp still derives an address", len(node.deriveaddresses(future)) == 1)

        # ================================================= F7 generateblock on an invalid block
        good6 = claimer.buildhtlcclaim(d6, op6, pre6.hex(), dest_c, FEE)
        bad = tx_from_hex(good6["hex"])
        bad.wit.vtxinwit[0].scriptWitness.stack[1] = pre6 + b"\x00"  # new leaf: OP_SIZE fails
        h0 = node.getbestblockhash()
        e = self.rpc_error(lambda: self.generateblock(node, self.mine_addr, [bad.serialize().hex()], sync_fun=self.no_op))
        self.record("F7.1 generateblock raises when the block fails validation",
                    e is not None and node.getbestblockhash() == h0, (e or "returned a hash")[:100])
        assert_equal(node.getbestblockhash(), h0)

        # ================================================= N2 zero-conf funding
        pre2 = bytes([0x2b]) * 32
        L2 = node.getblockcount() + 200
        d2 = self.desc(f"mr(htlc_sha256({sha256(pre2).hex()},{cpk}),refund({L2},{spk}))")
        op2, val2, _ = self.lock(d2, Decimal("1"), confirm=False)
        e = self.rpc_error(claimer.buildhtlcclaim, d2, op2, pre2.hex(), dest_c, FEE)
        self.record("N2.1 buildhtlcclaim refuses to reveal the preimage against an unconfirmed funding output",
                    e is not None and "unconfirmed" in e, (e or "built a claim against a mempool-only funding tx")[:90])
        # Demonstrate why: with the override (or on v0.34.13), the funder can replace the funding tx.
        args = (d2, op2, pre2.hex(), dest_c, FEE) + (({"allow_unconfirmed_funding": True},) if e is not None else ())
        claim2 = claimer.buildhtlcclaim(*args)
        claim2_txid = node.sendrawtransaction(claim2["hex"])
        ftx = node.decoderawtransaction(sender.gettransaction(op2["txid"])["hex"])
        fee_old = -sender.gettransaction(op2["txid"])["fee"]
        ins, in_sum = [], Decimal(0)
        for vin in ftx["vin"]:
            prev = node.decoderawtransaction(sender.gettransaction(vin["txid"])["hex"])
            in_sum += Decimal(str(prev["vout"][vin["vout"]]["value"]))
            ins.append({"txid": vin["txid"], "vout": vin["vout"]})
        steal = sender.createrawtransaction(ins, [{dest_s: in_sum - fee_old - Decimal("0.001")}])
        steal = sender.signrawtransactionwithwallet(steal)["hex"]
        node.sendrawtransaction(steal)
        mp = node.getrawmempool()
        revealed = tx_from_hex(claim2["hex"]).wit.vtxinwit[0].scriptWitness.stack[1] == pre2
        self.record("O-N2 a funder can double-spend an unconfirmed lock after seeing the claim's preimage",
                    claim2_txid not in mp and op2["txid"] not in mp and revealed,
                    "claim and funding evicted by a full-RBF double spend; the preimage was already broadcast")
        mine_block(self, node, self.mine_addr)

        # ================================================= F5 late claim
        pre5 = bytes([0x55]) * 32
        L5 = node.getblockcount() + 4
        d5 = self.desc(f"mr(htlc_sha256({sha256(pre5).hex()},{cpk}),refund({L5},{spk}))")
        op5, _, _ = self.lock(d5, Decimal("1"))
        self.mine_to(L5)
        e = self.rpc_error(claimer.buildhtlcclaim, d5, op5, pre5.hex(), dest_c, FEE)
        self.record("F5.1 buildhtlcclaim refuses once the refund is already final", e is not None and "allow_late_claim" in e, (e or "built")[:90])
        if e is not None:
            late = claimer.buildhtlcclaim(d5, op5, pre5.hex(), dest_c, FEE, {"allow_late_claim": True})
            self.record("F5.2 allow_late_claim=true still builds the claim", node.testmempoolaccept([late["hex"]])[0]["allowed"])
        else:
            self.record("F5.2 allow_late_claim=true still builds the claim", False, "option not present")
        mine_block(self, node, self.mine_addr)

        # ================================================= N3 bridge refund lock that is really a time
        plan_err = None
        try:
            plan, _, _ = planout(sender, sender.getnewaddress(address_type="p2mr"), Decimal("1"), 500000001,
                                 bridge_id=bridge_hex(40), operation_id=bridge_hex(41))
        except Exception as ex:  # noqa: BLE001
            plan_err = str(ex)
        if plan_err is None:
            ftxid = sender.sendtoaddress(plan["bridge_address"], Decimal("1"))
            mine_block(self, node, self.mine_addr)
            vout, value = find_output(node, ftxid, plan["bridge_address"], sender)
            rf = sender.bridge_buildrefund(plan["plan_hex"], ftxid, vout, value, dest_s, Decimal("0.0001"), False)
            signed = sender.walletprocesspsbt(rf["psbt"])
            hexr = signed["hex"] if signed["complete"] else sender.finalizepsbt(signed["psbt"])["hex"]
            acc = node.testmempoolaccept([hexr])[0]
            self.record("N3.1 bridge planout refuses refund_lock_height >= 500000000 (a time, not a height)", False,
                        f"plan accepted; refund at height {node.getblockcount()} mempool allowed={acc['allowed']} (lock 'height' 500000001 is a 1985 timestamp)")
            if acc["allowed"]:
                node.sendrawtransaction(hexr)
                mine_block(self, node, self.mine_addr)
        else:
            self.record("N3.1 bridge planout refuses refund_lock_height >= 500000000 (a time, not a height)",
                        "500000000" in plan_err, plan_err[:100])

        # ================================================= O1 MTP time lock
        mtp = node.getblockchaininfo()["mediantime"]
        T = mtp + 1200
        pre_t = bytes([0x7e]) * 32
        dt = self.desc(f"mr(htlc_sha256({sha256(pre_t).hex()},{cpk}),refund({T},{spk}))")
        opt, _, _ = self.lock(dt, Decimal("1"))
        e = self.rpc_error(sender.buildhtlcrefund, dt, opt, dest_s, node.getblockcount() + 10, FEE)
        self.record("O1.1 buildhtlcrefund refuses a height nLockTime for a time CLTV", e is not None, (e or "built")[:80])
        rt = sender.buildhtlcrefund(dt, opt, dest_s, T, FEE)
        now = int(time.time())
        mock = max(now, mtp) + 1
        accepted_at = None
        rejected_while_mtp_le_T = True
        for _ in range(40):
            cur_mtp = node.getblockchaininfo()["mediantime"]
            ok = node.testmempoolaccept([rt["hex"]])[0]["allowed"]
            if ok:
                accepted_at = cur_mtp
                break
            if cur_mtp > T:
                rejected_while_mtp_le_T = False
            mock += 300
            node.setmocktime(mock)
            mine_block(self, node, self.mine_addr)
        self.record("O1.2 time-locked refund enters the mempool exactly when tip MTP > locktime",
                    accepted_at is not None and accepted_at > T and rejected_while_mtp_le_T,
                    f"locktime {T}, first accepted at MTP {accepted_at}")
        late_t = claimer.buildhtlcclaim(dt, opt, pre_t.hex(), dest_c, FEE, {"allow_late_claim": True}) if \
            self.rpc_error(claimer.buildhtlcclaim, dt, opt, pre_t.hex(), dest_c, FEE) else None
        self.record("O1.3 a time-locked lock past its MTP timeout is also treated as a late claim (F5)",
                    late_t is not None, "refused without allow_late_claim" if late_t else "claim built without warning")
        node.sendrawtransaction(rt["hex"])
        mine_block(self, node, self.mine_addr)
        node.setmocktime(0)

        # ================================================= O2 reorg removes a claim after the timeout
        pre_r = bytes([0x4f]) * 32
        Lr = node.getblockcount() + 6
        dr = self.desc(f"mr(htlc_sha256({sha256(pre_r).hex()},{cpk}),refund({Lr},{spk}))")
        opr, _, _ = self.lock(dr, Decimal("1"))
        self.mine_to(Lr - 2)
        cr = claimer.buildhtlcclaim(dr, opr, pre_r.hex(), dest_c, FEE)
        node.sendrawtransaction(cr["hex"])
        mine_block(self, node, self.mine_addr)          # claim confirmed in block Lr-1
        claim_block = node.getbestblockhash()
        assert cr["txid"] in node.getblock(claim_block)["tx"]
        mine_block(self, node, self.mine_addr, 2)       # tip Lr+1: refund would now be final
        node.invalidateblock(claim_block)               # a 3-block reorg removes the claim
        for _ in range(3):                              # replacement branch mined without the claim
            self.generateblock(node, self.mine_addr, [], sync_fun=self.no_op)
        assert node.getblockcount() >= Lr
        rr = sender.buildhtlcrefund(dr, opr, dest_s, Lr, FEE * 50)
        node.sendrawtransaction(rr["hex"])
        mine_block(self, node, self.mine_addr)
        self.record("O2.1 a reorg deeper than (timeout - claim height) lets the refund replace a confirmed claim",
                    rr["txid"] in node.getblock(node.getbestblockhash())["tx"],
                    "claim confirmed 1 block before the timeout; 3-block reorg; refund mined instead")
        node.reconsiderblock(claim_block)

        self.log.info("==== SUMMARY ====")
        for name, ok, detail in self.results:
            self.log.info(f"{'PASS' if ok else 'FAIL'} {name} :: {detail}")
        failed = [n for n, ok, _ in self.results if not ok]
        assert not failed, f"{len(failed)} check(s) failed: {failed}"


if __name__ == "__main__":
    WalletHtlcFixesTest(__file__).main()
