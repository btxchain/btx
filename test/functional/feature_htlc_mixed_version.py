#!/usr/bin/env python3
# HTLC hardening review (second pass): mixed-version regtest checks.
# Local review only. Two private regtest nodes connected only to each other on 127.0.0.1.
"""Mixed-version checks between a v0.34.12 node (node0) and a v0.34.13 node (node1).

X1 (F1)  node0 mines a block with a legacy SHA-256 HTLC claim that reveals a 33-byte
         preimage. node1 rejects the block and the two chains split. The split ends
         only when the node1 side has more work.
X2 (F3)  the same htlc_sha256() descriptor derives different addresses on the two
         versions, and a v0.34.12 claimer cannot claim a lock funded at the v0.34.13
         address.
X3 (N1)  a claim of a v0.34.13 (OP_SIZE) lock is non-standard on v0.34.12: it is not
         accepted to node0's mempool, is not relayed to it, and node0 does not mine it.
         node0 still accepts a block that contains it.

Run (ports stay inside 28443-28499):
  TEST_RUNNER_PORT_MIN=28443 python3 build/test/functional/feature_htlc_mixed_version.py \
      --portseed=0 --oldbtxd=/path/to/btx-0.34.12/bin/btxd
(or set BTX_OLD_BTXD). The test is skipped when no v0.34.12 binary is given.
"""

import hashlib
import os
import shutil
import time
from decimal import Decimal

import test_framework.util as tf_util
from test_framework.psbt import PSBT, PSBT_IN_SHA256
from test_framework.test_framework import BitcoinTestFramework, SkipTest
from test_framework.util import assert_equal, assert_raises_rpc_error
from test_framework.bridge_utils import create_bridge_wallet, find_output

# Keep p2p, rpc and tor ports in 28443-28499 (p2p 28443+n, rpc 28463+n, tor 28483+n).
tf_util.PORT_RANGE = 20

FEE = 1000
OLD_BTXD = os.environ.get("BTX_OLD_BTXD", "")
COMMON_ARGS = [
    "-dnsseed=0",
    "-autoshieldcoinbase=0",
    "-modelbind=off",
    "-modelnet=0",
    "-regtestmatmulbindingheight=2147483647",
    "-regtestmatmulproductdigestheight=2147483647",
    "-regtestmatmulv4height=2147483647",
    "-regtestmatmulrequireproductpayload=0",
]


def sha256(b):
    return hashlib.sha256(b).digest()


class HtlcMixedVersionTest(BitcoinTestFramework):
    def add_options(self, parser):
        self.add_wallet_options(parser, legacy=False)
        parser.add_argument("--oldbtxd", dest="oldbtxd", default=OLD_BTXD,
                            help="path to a v0.34.12 btxd binary")

    def set_test_params(self):
        self.num_nodes = 2
        self.setup_clean_chain = True
        # bind_to_localhost_only (default) keeps both nodes on 127.0.0.1.
        self.extra_args = [list(COMMON_ARGS), list(COMMON_ARGS)]

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()
        self.skip_if_no_sqlite()
        if not self.options.oldbtxd or not os.path.isfile(self.options.oldbtxd):
            raise SkipTest("needs a v0.34.12 btxd: pass --oldbtxd or set BTX_OLD_BTXD")

    def setup_nodes(self):
        old_cli = str(self.options.oldbtxd).rsplit("/", 1)[0] + "/btx-cli"
        self.add_nodes(self.num_nodes, self.extra_args,
                       binary=[self.options.oldbtxd, self.options.bitcoind],
                       binary_cli=[old_cli, self.options.bitcoincli])
        self.start_nodes()

    def setup_network(self):
        # Connected in run_test after the initial chain is mined: during a fast
        # bulk generation 0.34.13 disconnects 0.34.12 for "unconnecting headers".
        self.setup_nodes()

    # ------------------------------------------------------------ helpers
    def record(self, name, ok, detail=""):
        self.results.append((name, ok, detail))
        self.log.info(f"[{'PASS' if ok else 'FINDING'}] {name} {detail}")

    def wait_same_tip(self, timeout=60):
        self.wait_until(lambda: self.nodes[0].getbestblockhash() == self.nodes[1].getbestblockhash(), timeout=timeout)

    def mine(self, node, n, addr, sync=False):
        hashes = []
        for _ in range(n):
            hashes += self.generatetoaddress(node, 1, addr, sync_fun=self.no_op)
            if sync:
                self.wait_same_tip()
        return hashes

    def pq_pubkey(self, w):
        return w.exportpqkey(w.getnewaddress(address_type="p2mr"))["pubkey"]

    def desc(self, node, body):
        return f"{body}#{node.getdescriptorinfo(body)['checksum']}"

    # ------------------------------------------------------------ body
    def run_test(self):
        self.results = []
        old, new = self.nodes
        self.log.info(f"node0 version {old.getnetworkinfo()['subversion']}, node1 version {new.getnetworkinfo()['subversion']}")
        assert "0.34.12" in old.getnetworkinfo()["subversion"]
        assert "0.34.13" in new.getnetworkinfo()["subversion"]

        ow, omine = create_bridge_wallet(self, old, wallet_name="old_w", amount=Decimal("12"))
        # node1 (0.34.13) makes the outbound connection: it does not download
        # blocks from the inbound 0.34.12 peer during initial sync.
        self.connect_nodes(1, 0)
        self.wait_same_tip(timeout=300)
        nw_addr = None
        new.createwallet(wallet_name="new_w", descriptors=True)
        nw = new.get_wallet_rpc("new_w")
        nw_addr = nw.getnewaddress(address_type="p2mr")
        ow.sendtoaddress(nw_addr, Decimal("4"))
        self.mine(old, 1, omine)
        self.wait_same_tip()

        # A dedicated old-version claimer wallet whose first p2mr key is index 0.
        old.createwallet(wallet_name="old_claimer", descriptors=True)
        oc = old.get_wallet_rpc("old_claimer")
        oc_addr0 = oc.getnewaddress(address_type="p2mr")
        cpk_old = oc.exportpqkey(oc_addr0)["pubkey"]
        priv = [d["desc"] for d in oc.listdescriptors(True)["descriptors"]
                if d["desc"].startswith("mr(pqhd(") and not d["internal"]]
        assert priv, "no external mr(pqhd()) descriptor in the old claimer wallet"
        body = priv[0].split("#")[0]
        claimer_key_expr = body[body.index("pqhd("):body.index("/*)") + 3]
        spk_old = self.pq_pubkey(ow)

        # ============================================ X1: F1 chain split
        secret33 = bytes([0x42]) * 33
        h33 = sha256(secret33).hex()
        L = old.getblockcount() + 500
        d_pub = self.desc(old, f"mr(htlc_sha256({h33},{cpk_old}),refund({L},{spk_old}))")
        legacy_addr = old.deriveaddresses(d_pub)[0]
        new_addr_same_desc = new.deriveaddresses(d_pub)[0]
        self.log.info(f"same descriptor: 0.34.12 address {legacy_addr}, 0.34.13 address {new_addr_same_desc}")
        self.record("X2.1 the same htlc_sha256() descriptor derives different addresses on 0.34.12 and 0.34.13",
                    legacy_addr != new_addr_same_desc, "FINDING F3 confirmed across versions" if legacy_addr != new_addr_same_desc else "")

        # Import the claim descriptor with the claimer's PRIVATE ranged key so walletprocesspsbt can sign.
        d_priv = self.desc(old, f"mr(htlc_sha256({h33},{claimer_key_expr}),refund({L},{spk_old}))")
        res = oc.importdescriptors([{"desc": d_priv, "range": [0, 0], "timestamp": 0, "active": False}])[0]
        assert res["success"], res
        assert_equal(oc.deriveaddresses(d_priv, [0, 0])[0], legacy_addr)

        ftxid = ow.sendtoaddress(legacy_addr, Decimal("2"))
        self.mine(old, 1, omine)
        self.wait_same_tip()
        vout, value = find_output(old, ftxid, legacy_addr, ow)
        dest = oc.getnewaddress(address_type="p2mr")
        out_amt = value - Decimal(FEE) / Decimal(100000000)
        psbt_b64 = old.createpsbt([{"txid": ftxid, "vout": vout}], [{dest: out_amt}], 0)
        psbt = PSBT.from_base64(psbt_b64)
        psbt.i[0].map[bytes([PSBT_IN_SHA256]) + bytes.fromhex(h33)] = secret33
        signed = oc.walletprocesspsbt(psbt.to_base64())
        assert signed["complete"], signed
        claim_hex = signed["hex"]
        wit = old.decoderawtransaction(claim_hex)["vin"][0]["txinwitness"]
        assert_equal(len(bytes.fromhex(wit[1])), 33)
        self.log.info("0.34.12 signed a legacy-leaf claim revealing a 33-byte preimage")

        r_old = old.testmempoolaccept([claim_hex])[0]
        r_new = new.testmempoolaccept([claim_hex])[0]
        self.record("X1.1 both mempools refuse the 33-byte claim (policy)",
                    not r_old["allowed"] and not r_new["allowed"],
                    f"0.34.12: {r_old.get('reject-reason')}; 0.34.13: {r_new.get('reject-reason')}")

        base_h = old.getblockcount()
        base_hash = old.getbestblockhash()
        # generateblock bypasses mempool policy; a miner can include a non-standard spend.
        self.generateblock(old, omine, [claim_hex], sync_fun=self.no_op)
        split_hash = old.getbestblockhash()
        self.record("X1.2 0.34.12 accepts and connects the block containing the spend",
                    old.getblockcount() == base_h + 1 and split_hash != base_hash, f"block {split_hash[:16]}..")

        def new_marked_invalid():
            for tip in new.getchaintips():
                if tip["hash"] == split_hash and tip["status"] == "invalid":
                    return True
            return False
        self.wait_until(new_marked_invalid, timeout=60)
        with open(new.debug_log_path, encoding="utf-8", errors="replace") as f:
            reasons = [l.strip() for l in f if split_hash[:16] in l or "Invalid HTLC preimage size" in l]
        self.record("X1.3 0.34.13 rejects the same block as invalid",
                    new.getbestblockhash() == base_hash and new_marked_invalid(),
                    (reasons[-1][-140:] if reasons else ""))

        self.mine(old, 2, omine)
        time.sleep(3)
        self.record("X1.4 chains split: 0.34.12 builds on its block, 0.34.13 stays behind",
                    old.getblockcount() == base_h + 3 and new.getblockcount() == base_h
                    and new.getbestblockhash() == base_hash,
                    f"0.34.12 tip h={old.getblockcount()}, 0.34.13 tip h={new.getblockcount()}")

        # The 0.34.13 side now mines more blocks than the 0.34.12 side has.
        new_mine = nw.getnewaddress(address_type="p2mr")
        for _ in range(5):
            self.mine(new, 1, new_mine)
            time.sleep(1)
        # 0.34.12 got the first header of this branch while it was shorter and
        # then stopped asking for more (getheaders is rate-limited and the
        # later blocks were only inv-announced). A fresh connection resyncs.
        self.disconnect_nodes(1, 0)
        self.connect_nodes(1, 0)
        # getheaders is rate-limited per peer (2 min), so allow a few minutes.
        self.wait_until(lambda: old.getbestblockhash() == new.getbestblockhash(), timeout=420)
        in_chain = old.getblockheader(split_hash)["confirmations"]
        self.record("X1.5 the split ends only when the enforcing side has more work: 0.34.12 reorgs onto it",
                    in_chain == -1, f"0.34.12 tip h={old.getblockcount()}, split block confirmations={in_chain}")

        # ============================================ X2: F3 cross-version claim
        pre32 = bytes([0x5c]) * 32
        h32 = sha256(pre32).hex()
        nspk = self.pq_pubkey(nw)
        L2 = new.getblockcount() + 400
        d2 = self.desc(new, f"mr(htlc_sha256({h32},{cpk_old}),refund({L2},{nspk}))")
        new_fmt_addr = new.deriveaddresses(d2)[0]
        f2 = nw.sendtoaddress(new_fmt_addr, Decimal("1"))
        self.mine(new, 1, new_mine)
        self.wait_same_tip()
        v2, _ = find_output(new, f2, new_fmt_addr, nw)
        assert_raises_rpc_error(-8, "does not match", oc.buildhtlcclaim, d2, {"txid": f2, "vout": v2},
                                pre32.hex(), oc.getnewaddress(address_type="p2mr"), FEE)
        self.record("X2.2 a 0.34.12 claimer cannot claim a lock funded at the 0.34.13 address",
                    True, "buildhtlcclaim: Outpoint scriptPubKey does not match the descriptor")

        # ============================================ X3: N1 new-leaf claim is non-standard on 0.34.12
        pre3 = bytes([0x3d]) * 32
        h3 = sha256(pre3).hex()
        ncpk = self.pq_pubkey(nw)
        L3 = new.getblockcount() + 400
        d3 = self.desc(new, f"mr(htlc_sha256({h3},{ncpk}),refund({L3},{spk_old}))")
        a3 = new.deriveaddresses(d3)[0]
        f3 = nw.sendtoaddress(a3, Decimal("1"))
        self.mine(new, 1, new_mine)
        self.wait_same_tip()
        v3, _ = find_output(new, f3, a3, nw)
        claim3 = nw.buildhtlcclaim(d3, {"txid": f3, "vout": v3}, pre3.hex(), nw.getnewaddress(address_type="p2mr"), FEE)
        r_new = new.testmempoolaccept([claim3["hex"]])[0]
        r_old = old.testmempoolaccept([claim3["hex"]])[0]
        self.record("X3.1 a claim of a 0.34.13 lock is standard on 0.34.13 but NOT on 0.34.12",
                    r_new["allowed"] and not r_old["allowed"],
                    f"0.34.13 allowed={r_new['allowed']}; 0.34.12: {r_old.get('reject-reason')}")
        txid3 = new.sendrawtransaction(claim3["hex"])
        time.sleep(5)
        self.record("X3.2 the claim is not relayed into the 0.34.12 mempool",
                    txid3 in new.getrawmempool() and txid3 not in old.getrawmempool())
        self.mine(old, 1, omine)
        self.wait_same_tip()
        blk = old.getblock(old.getbestblockhash())
        self.record("X3.3 a 0.34.12 miner leaves the claim out of its block",
                    txid3 not in blk["tx"], f"0.34.12 block has {len(blk['tx'])} tx")
        self.mine(new, 1, new_mine)
        self.wait_same_tip()
        blk = new.getblock(new.getbestblockhash())
        self.record("X3.4 a 0.34.13 miner includes it and 0.34.12 accepts that block",
                    txid3 in blk["tx"] and old.getbestblockhash() == new.getbestblockhash())

        # ============================================ X4: wallet written by 0.34.12, loaded by 0.34.13
        # 0.34.12 accepts refund(0) and the same key in the claim and refund leaves. 0.34.13
        # rejects both descriptors at parse time, including when it loads them from a wallet file.
        hx = sha256(b"x4").hex()
        k1 = self.pq_pubkey(ow)
        k2 = self.pq_pubkey(ow)
        cases = {
            "x4_refund0": f"mr(htlc_sha256({hx},{k1}),refund(0,{k2}))",
            "x4_samekey": f"mr(htlc_sha256({hx},{k1}),refund(10,{k1}))",
        }
        for wname, body4 in cases.items():
            old.createwallet(wallet_name=wname, descriptors=True, disable_private_keys=True)
            w4 = old.get_wallet_rpc(wname)
            r4 = w4.importdescriptors([{"desc": self.desc(old, body4), "timestamp": "now"}])[0]
            assert r4["success"], r4
            old.unloadwallet(wname)
            src = old.chain_path / "wallets" / wname
            dst = new.chain_path / "wallets" / wname
            shutil.copytree(src, dst)
            try:
                new.loadwallet(wname)
                loaded, err4 = True, ""
                new.unloadwallet(wname)
            except Exception as e:  # noqa: BLE001
                loaded, err4 = False, str(e)[:160]
            self.record(f"X4 0.34.13 loads a 0.34.12 wallet that imported {wname[3:]} HTLC descriptor",
                        loaded, err4 or "loaded")

        self.log.info("==== SUMMARY ====")
        for name, ok, detail in self.results:
            self.log.info(f"{'PASS   ' if ok else 'FINDING'} {name} :: {detail}")


if __name__ == "__main__":
    HtlcMixedVersionTest(__file__).main()
