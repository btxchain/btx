#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""A node that handshakes below the Dandelion++ activation height is not punished for stems.

DANDELIONACC is sent once, at VERACK. Until this change a node sent it only when
it was already past the activation height, while the receiver of a DLTX
punished any peer that never sent one. A node that handshakes during IBD and
later relays a stem (its own transaction or a forwarded one) was disconnected
by its peer.

Topology: node1 (B) and node2 (C) connect outbound to node0 (A) while B and C
are at height 0, below the activation height H=110, and A is at 120.

Phase 1: B broadcasts a transaction after syncing. A must not punish B.
Phase 2: B reconnects above H and broadcasts again. A accepts the stem.
Phase 3: a P2P peer of C stems a transaction to C, which forwards it to A.
  A must not punish C.
"""

import time

import test_framework.p2p as p2pmod
from test_framework.blocktools import REGTEST_GENERIC_P2P_MATMUL_ARGS
from test_framework.messages import msg_dandelionacc, msg_tx
from test_framework.p2p import P2PInterface
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import p2p_port
from test_framework.wallet import MiniWallet

H = 110


class msg_dltx(msg_tx):
    msgtype = b"dltx"


p2pmod.MESSAGEMAP[b"dltx"] = msg_dltx


class DlPeer(P2PInterface):
    def __init__(self):
        super().__init__()
        self.dltx_received = 0

    def on_dltx(self, message):
        self.dltx_received += 1


class DandelionAccBelowActivationTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 3
        self.setup_clean_chain = True
        common = [
            *REGTEST_GENERIC_P2P_MATMUL_ARGS,
            f"-regtestshieldedmatrictdisableheight={H}",
            "-debug=net",
            "-debug=dandelion",
            "-nomodelnet",
            "-acceptnonstdtxn=1",
        ]
        self.extra_args = [common] * self.num_nodes

    def setup_network(self):
        # v0.34.15 skips SendMessages (and MaybeDiscourageAndDisconnect) for
        # fully-connected inbound peers whenever automatic outbound is off,
        # which the framework's connect=0 triggers (fixed later by 55c5e569,
        # not in v0.34.15). Drop connect=0 so the node behaves like a default
        # mainnet node. dnsseed=0, fixedseeds=0 and an empty addrman keep every
        # node on loopback (checked with lsof in the run notes).
        self.add_nodes(self.num_nodes, self.extra_args)
        for n in self.nodes:
            conf = n.datadir_path / "bitcoin.conf"
            lines = [l for l in conf.read_text().splitlines() if l.strip() != "connect=0"]
            conf.write_text("\n".join(lines) + "\n")
        self.start_nodes()
        # Each node picks stem or fluff per epoch (STEM_PROBABILITY 0.9, at
        # least 60 s per epoch). A fluff epoch on A or C sends the stem down
        # the fluff path, which neither shows nor tests the punishment.
        # Restart until every node starts in a stem epoch.
        for i in range(self.num_nodes):
            self.start_in_stem_epoch(i)

    def start_in_stem_epoch(self, i):
        for _ in range(20):
            self.wait_until(lambda: len(self.log_lines(i, "stem_mode=")) > 0, timeout=30)
            lines = self.log_lines(i, "stem_mode=")
            if lines[-1].endswith("stem_mode=1"):
                return
            self.log.info(f"node{i} started in a fluff epoch; restarting it")
            self.restart_node(i)
            self.wait_until(lambda: len(self.log_lines(i, "stem_mode=")) > len(lines), timeout=30)
        raise AssertionError(f"node{i} never started in a stem epoch")

    def outbound_to(self, a, b):
        port = p2p_port(b)
        self.nodes[a].addconnection(f"127.0.0.1:{port}", "outbound-full-relay", False)
        self.wait_until(lambda: len(self.links_to(a, b)) == 1)
        time.sleep(1)

    def links_to(self, a, b):
        port = p2p_port(b)
        return [p for p in self.nodes[a].getpeerinfo()
                if p["connection_type"] == "outbound-full-relay" and p["addr"].endswith(f":{port}")
                and p.get("version", 0) != 0]

    def log_lines(self, i, needle):
        with open(self.nodes[i].debug_log_path, encoding="utf-8", errors="replace") as f:
            return [l.strip() for l in f if needle in l]

    def nmis(self):
        return len(self.log_lines(0, "dltx from non-dandelion peer"))

    def run_test(self):
        A, B, C = self.nodes
        wallet = MiniWallet(A)
        self.log.info("A mines 120 blocks (block by block) while B and C are unconnected")
        for _ in range(120):
            self.generate(wallet, 1, sync_fun=self.no_op)
        assert A.getblockcount() == 120 and B.getblockcount() == 0 and C.getblockcount() == 0

        def newtx():
            return wallet.create_self_transfer(utxo_to_spend=wallet.get_utxo(confirmed_only=True))

        # ---------------- Phase 1 ----------------
        self.log.info("Phase 1: B connects to A while B is below activation height")
        self.outbound_to(1, 0)
        self.wait_until(lambda: B.getbestblockhash() == A.getbestblockhash(), timeout=120)
        time.sleep(2)
        base = self.nmis()
        tx1 = newtx()
        self.log.info(f"B (height {B.getblockcount()}) broadcasts tx1 {tx1['txid']} via sendrawtransaction")
        B.sendrawtransaction(tx1["hex"])
        self.wait_until(lambda: len(self.log_lines(0, f"accepted stem tx {tx1['txid'][:12]}")) > 0
                        or self.nmis() > base, timeout=30)
        time.sleep(2)
        p1_mis = self.nmis() - base
        p1_links = len(self.links_to(1, 0))
        self.log.info(f"RESULT phase1 A_misbehaving_dltx={p1_mis} B_outbound_to_A_after={p1_links}")

        # ---------------- Phase 2 (control) ----------------
        self.log.info("Phase 2: B reconnects to A while B is above activation height")
        for _ in self.links_to(1, 0):
            B.disconnectnode(nodeid=self.links_to(1, 0)[0]["id"])
            self.wait_until(lambda: len(self.links_to(1, 0)) == 0, timeout=30)
        self.outbound_to(1, 0)
        time.sleep(2)
        base = self.nmis()
        tx2 = newtx()
        self.log.info(f"B broadcasts tx2 {tx2['txid']} via sendrawtransaction")
        B.sendrawtransaction(tx2["hex"])
        self.wait_until(lambda: len(self.log_lines(0, f"accepted stem tx {tx2['txid'][:12]}")) > 0
                        or self.nmis() > base, timeout=30)
        time.sleep(2)
        p2_mis = self.nmis() - base
        p2_links = len(self.links_to(1, 0))
        p2_stem = len(self.log_lines(0, f"accepted stem tx {tx2['txid'][:12]}"))
        self.log.info(f"RESULT phase2 A_misbehaving_dltx={p2_mis} B_outbound_to_A_after={p2_links} "
                      f"A_accepted_stem_tx2={p2_stem}")

        # ---------------- Phase 3 (forwarding variant) ----------------
        self.log.info("Phase 3: C connects to A while C is below activation; C later forwards P's DLTX")
        self.outbound_to(2, 0)
        self.wait_until(lambda: C.getbestblockhash() == A.getbestblockhash(), timeout=120)
        time.sleep(2)
        base = self.nmis()
        tx3 = None
        p3_routed_back = 0
        for attempt in range(3):
            p = C.add_p2p_connection(DlPeer())
            p.send_message(msg_dandelionacc())
            p.sync_with_ping()
            tx3 = newtx()
            p.send_message(msg_dltx(tx3["tx"]))
            accepted = lambda: len(self.log_lines(0, f"accepted stem tx {tx3['txid'][:12]}")) > 0
            self.wait_until(lambda: self.nmis() > base or p.dltx_received > 0 or accepted(), timeout=30)
            if self.nmis() > base or accepted():
                break
            # C picked P itself as its (only, same-netgroup) relay. Disconnect P so
            # C reseats its relay set to the remaining candidate (A) and retry.
            p3_routed_back += 1
            self.log.info(f"attempt {attempt}: C routed the stem back to P; retrying with a fresh P")
            p.peer_disconnect()
            p.wait_for_disconnect()
            time.sleep(1)
        time.sleep(2)
        p3_mis = self.nmis() - base
        p3_links = len(self.links_to(2, 0))
        c_stem = len(self.log_lines(2, f"accepted stem tx {tx3['txid'][:12]}"))
        self.log.info(f"RESULT phase3 C_accepted_stem_from_P={c_stem} routed_back_retries={p3_routed_back} "
                      f"A_misbehaving_dltx={p3_mis} C_outbound_to_A_after={p3_links}")

        for line in self.log_lines(0, "dltx from non-dandelion peer"):
            self.log.info(f"A LOG: {line[-110:]}")
        for line in self.log_lines(0, "disconnecting but not discouraging"):
            self.log.info(f"A LOG: {line[-110:]}")

        assert p1_mis == 0 and p1_links == 1, "phase1: honest B was punished for its stem"
        assert p2_mis == 0 and p2_links == 1 and p2_stem >= 1, "phase2: stem above the activation height failed"
        assert c_stem >= 1 and p3_mis == 0 and p3_links == 1, "phase3: forwarding C was punished"


if __name__ == "__main__":
    DandelionAccBelowActivationTest(__file__).main()
