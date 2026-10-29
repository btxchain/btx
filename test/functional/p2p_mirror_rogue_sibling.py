#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""A trusted mirror announces an honest tip child after an unattestable sibling.

  P  consensus miner, no signer key; enforces the empty-block subsidy penalty.
  M  trusted Profile-1 mirror pinning KS at threshold 1; dials P.
  S  consensus signer KS (serving); its only link is to M (S dials M).
  Q  isolated miner without the subsidy penalty; follows P by submitblock.

Q mines R, an empty block with the full subsidy on the common tip. R has a
valid header and MatMul proof but fails ConnectBlock (bad-cb-amount) on P, M
and S. M gets R first (submitblock), stores it before quorum and waits for S
to attest it, which S never does. P then mines the honest sibling H at the
same height and one block on top of it.

NewPoWValidBlock fast-announces only the first block at each height. If M
keeps that rule while it waits for attestation, H never reaches S, S never
attests H, and M and S stay on the parent of H.

Asserts that M and S reach P's tip, that R never becomes active and that M and
S keep their outbound links. Regtest only, loopback only.
"""

import time

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, p2p_port
from test_framework.wallet_util import generate_keypair

ACTIVATION_HEIGHT = 6
DISABLED_HEIGHT = 2_147_483_647


class MirrorRogueSiblingTest(BitcoinTestFramework):
    def add_options(self, parser):
        parser.add_argument("--wait", dest="wait", type=int, default=60)

    def set_test_params(self):
        self.num_nodes = 4
        self.setup_clean_chain = True
        ks_wif, ks_pub = generate_keypair(wif=True)
        self.ks = ks_pub.hex()
        common = [
            "-test=matmulstrict",
            "-test=matmuldgw",
            "-matmulasyncverify=1",
            "-regtestmatmulbindingheight=2",
            f"-regtestmatmulproductdigestheight={DISABLED_HEIGHT}",
            "-regtestmatmulrequireproductpayload=0",
            f"-regtestmatmulv4height={ACTIVATION_HEIGHT}",
            f"-regtestbmx4cheight={ACTIVATION_HEIGHT}",
            f"-regtestdrltheight={DISABLED_HEIGHT}",
            f"-regtestrcheight={ACTIVATION_HEIGHT}",
            f"-regtestrccoupledheight={DISABLED_HEIGHT}",
            "-regtestrcprofile=1",
            "-regtestrctoydims=1",
            "-regtestrccoupledtoydims=0",
            "-regtestmatmulltsealaspow=0",
            "-regtestmatmulv4dimension=128",
            "-matmultrustedwaitms=30000",
            "-modelnet=0",
            "-debug=net",
        ]
        penalty = ["-regtestemptyblocksubsidypenaltyheight=1"]
        producer = common + penalty + [
            "-matmulvalidation=consensus",
        ]
        mirror = common + penalty + [
            "-matmulvalidation=trusted",
            "-matmulattestationserve=0",
            f"-matmultrustedpubkey={self.ks}",
            "-matmultrustedthreshold=1",
        ]
        signer = common + penalty + [
            "-matmulvalidation=consensus",
            f"-matmulattestationsignerkey={ks_wif}",
            "-matmulattestationserve=1",
            f"-matmultrustedpubkey={self.ks}",
            "-matmultrustedthreshold=1",
        ]
        isolated = common + [
            "-matmulvalidation=consensus",
        ]
        self.extra_args = [producer, mirror, signer, isolated]

    def setup_network(self):
        self.add_nodes(self.num_nodes, self.extra_args)
        for i in range(self.num_nodes):
            self.start_node(i)
        # Outbound full-relay links, so a punished honest peer would be dropped.
        self.dial(1, 0)  # M dials P
        self.dial(2, 1)  # S dials M (S's only link)

    def dial(self, a, b):
        self.nodes[a].addconnection(f"127.0.0.1:{p2p_port(b)}", "outbound-full-relay", False)
        self.wait_until(lambda: self.outbound_count(a) == 1, timeout=15)

    def outbound_count(self, i):
        return sum(1 for p in self.nodes[i].getpeerinfo()
                   if p["connection_type"] == "outbound-full-relay")

    def tip_status(self, node, block_hash):
        for t in node.getchaintips():
            if t["hash"] == block_hash:
                return t["status"]
        return "unseen"

    def mine_and_sync(self, label):
        p, m, s, _ = self.nodes
        t0 = time.time()
        tip = self.generate(p, 1, sync_fun=self.no_op)[0]
        height = p.getblockcount()
        try:
            self.wait_until(lambda: m.getbestblockhash() == tip and s.getbestblockhash() == tip,
                            timeout=self.options.wait)
        except AssertionError:
            self.log.info(f"RESULT {label} height={height} STALLED after {time.time() - t0:.0f}s: "
                          f"M={m.getblockcount()} S={s.getblockcount()} "
                          f"M.status={self.tip_status(m, tip)} S.status={self.tip_status(s, tip)}")
            return height
        self.log.info(f"RESULT {label} height={height} synced_in={time.time() - t0:.1f}s")
        return None

    def run_test(self):
        p, m, s, q = self.nodes
        self.log.info("Pre-activation and two Profile-1 blocks")
        for i in range(ACTIVATION_HEIGHT + 1):
            assert self.mine_and_sync("warmup") is None, "warm-up did not sync"

        self.log.info("Q follows P, then mines R (full subsidy, empty) on the common tip")
        for h in range(1, p.getblockcount() + 1):
            assert_equal(q.submitblock(p.getblock(p.getblockhash(h), 0)), None)
        assert_equal(q.getbestblockhash(), p.getbestblockhash())
        r_hash = self.generate(q, 1, sync_fun=self.no_op)[0]
        m.submitblock(q.getblock(r_hash, 0))
        self.wait_until(lambda: self.tip_status(s, r_hash) == "invalid", timeout=30)
        self.log.info(f"R={r_hash} invalid at S; M status {self.tip_status(m, r_hash)}")

        self.log.info("P mines the honest sibling H and one block on top of it")
        stalled = None
        for label in ("sibling", "child"):
            stalled = self.mine_and_sync(label)
            if stalled is not None:
                break

        for node in (p, m, s):
            assert node.getbestblockhash() != r_hash
        assert_equal(self.outbound_count(1), 1)  # M -> P
        assert_equal(self.outbound_count(2), 1)  # S -> M

        # Trusted-mirror and inline-signer startup warnings go to stderr.
        for i in (1, 2):
            self.nodes[i].stderr.seek(0)
            err = self.nodes[i].stderr.read().decode("utf-8", "replace").strip()
            self.stop_node(i, expected_stderr=err)
        assert stalled is None, f"mirror/signer stalled at height {stalled}"


if __name__ == "__main__":
    MirrorRogueSiblingTest(__file__).main()
