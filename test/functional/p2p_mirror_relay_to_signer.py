#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""A trusted mirror relays a tip child to a signer that depends on it.

  P  consensus miner, no signer key.
  M  trusted Profile-1 mirror pinning KS at threshold 1; dials P.
  S  consensus signer KS (serving); its only link is to M (S dials M).

After Profile-1 activation M persists each new block before quorum and needs
S's attestation to connect it. BlockRequestAllowed serves such a body so a
consensus signer peered only with this mirror can ExactReplay and attest. If M
announced nothing until the block connects, S would never see the block and
the attestation M waits for would never come.

Asserts that M and S reach P's tip after activation within a timeout, and
logs the time each block took. Taken from the harness in Jpp-matata's review
of #288. Regtest only, loopback only.
"""

import time

from test_framework.test_framework import BitcoinTestFramework
from test_framework.wallet_util import generate_keypair

ACTIVATION_HEIGHT = 6
DISABLED_HEIGHT = 2_147_483_647


class MirrorRelayToSignerTest(BitcoinTestFramework):
    def add_options(self, parser):
        parser.add_argument("--blocks", dest="blocks", type=int, default=4)
        parser.add_argument("--wait", dest="wait", type=int, default=90)

    def set_test_params(self):
        self.num_nodes = 3
        self.setup_clean_chain = True
        ks_wif, ks_pub = generate_keypair(wif=True)
        self.ks = ks_pub.hex()
        common = [
            "-test=matmulstrict",
            "-test=matmuldgw",
            "-matmulasyncverify=1",
            "-regtestmatmulbindingheight=2",
            "-regtestmatmulproductdigestheight=2",
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
        producer = common + [
            "-matmulvalidation=consensus",
        ]
        mirror = common + [
            "-matmulvalidation=trusted",
            "-matmulattestationserve=0",
            f"-matmultrustedpubkey={self.ks}",
            "-matmultrustedthreshold=1",
        ]
        signer = common + [
            "-matmulvalidation=consensus",
            f"-matmulattestationsignerkey={ks_wif}",
            "-matmulattestationserve=1",
            f"-matmultrustedpubkey={self.ks}",
            "-matmultrustedthreshold=1",
        ]
        self.extra_args = [producer, mirror, signer]

    def setup_network(self):
        self.add_nodes(self.num_nodes, self.extra_args)
        for i in range(self.num_nodes):
            self.start_node(i)
        self.connect_nodes(1, 0)  # M dials P
        self.connect_nodes(2, 1)  # S dials M (S's only link)

    def run_test(self):
        p, m, s = self.nodes
        self.log.info("Pre-activation blocks (no quorum needed)")
        for _ in range(ACTIVATION_HEIGHT - 1):
            self.generate(p, 1, sync_fun=self.no_op)
            tip = p.getbestblockhash()
            self.wait_until(lambda: m.getbestblockhash() == tip and s.getbestblockhash() == tip, timeout=60)
        self.log.info(f"synced to height {p.getblockcount()}")

        self.log.info("Profile-1 blocks: M needs S's attestation, S's only source is M")
        stalled = None
        for _ in range(self.options.blocks):
            t0 = time.time()
            self.generate(p, 1, sync_fun=self.no_op)
            tip = p.getbestblockhash()
            h = p.getblockcount()
            try:
                self.wait_until(lambda: m.getbestblockhash() == tip and s.getbestblockhash() == tip,
                                timeout=self.options.wait)
                self.log.info(f"RESULT height={h} synced_in={time.time() - t0:.1f}s")
            except AssertionError:
                stalled = h
                self.log.info(f"RESULT height={h} STALLED after {self.options.wait}s: "
                              f"P={p.getblockcount()} M={m.getblockcount()} S={s.getblockcount()} "
                              f"M.headers={m.getblockchaininfo()['headers']} "
                              f"S.headers={s.getblockchaininfo()['headers']}")
                for t in m.getchaintips():
                    if t["hash"] == tip:
                        self.log.info(f"  M chaintip for {tip}: {t['status']}")
                for t in s.getchaintips():
                    if t["hash"] == tip:
                        self.log.info(f"  S chaintip for {tip}: {t['status']}")
                st = m.getmatmultrustedstatus()
                self.log.info(f"  M trusted status: accepted={st.get('accepted')} "
                              f"blocks_with_quorum={st.get('blocks_with_quorum')}")
                break
        # Trusted-mirror and inline-signer startup warnings go to stderr.
        for i in (1, 2):
            self.nodes[i].stderr.seek(0)
            err = self.nodes[i].stderr.read().decode("utf-8", "replace").strip()
            self.stop_node(i, expected_stderr=err)
        assert stalled is None, f"mirror/signer stalled at height {stalled}"


if __name__ == "__main__":
    MirrorRelayToSignerTest(__file__).main()
