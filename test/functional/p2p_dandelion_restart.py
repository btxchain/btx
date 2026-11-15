#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""Test that a locally stemmed Dandelion++ transaction is announced after a restart.

The stempool and its embargo timer live only in memory. A transaction that
this node submitted and stemmed must therefore reach mempool.dat as pending
initial broadcast (unbroadcast). Otherwise a restart before the embargo fires
leaves it in the mempool with nothing that ever announces it.

While the node runs, nothing may change: during the stem phase, and after the
embargo has fluffed the transaction, a peer that completes its handshake must
not be announced it.
"""
import time

from test_framework.messages import (
    MSG_TX,
    MSG_TYPE_MASK,
    MSG_WTX,
    msg_dandelionacc,
)
from test_framework.p2p import (
    P2PInterface,
    P2PTxInvStore,
    p2p_lock,
)
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal
from test_framework.wallet import MiniWallet

# Dandelion::EMBARGO_MIN and EMBARGO_MAX in src/dandelion.h.
EMBARGO_MIN = 5
EMBARGO_MAX = 180


class StemObserver(P2PInterface):
    """Records the dltx and tx-inv messages it receives.

    It never requests an announced transaction, so it does not take a
    transaction out of the node's unbroadcast set.
    """

    def __init__(self):
        super().__init__()
        self.dltx_wtxids = set()
        self.tx_invs = set()

    def on_dltx(self, message):
        self.dltx_wtxids.add(message.tx.getwtxid())

    def on_inv(self, message):
        for inv in message.inv:
            if inv.type & MSG_TYPE_MASK in (MSG_TX, MSG_WTX):
                self.tx_invs.add(inv.hash)

    def got_inv(self, wtxid):
        with p2p_lock:
            return int(wtxid, 16) in self.tx_invs


class DandelionRestartTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.extra_args = [[
            # MiniWallet's default output is nonstandard under BTX policy.
            "-acceptnonstdtxn=1",
            # No model helper: it is not needed here, and its fixed PQ1 port
            # would collide with other tests running in parallel.
            "-modelnet=0",
        ]]

    def add_stem_relay(self, p2p_idx):
        relay = self.nodes[0].add_outbound_p2p_connection(StemObserver(), p2p_idx=p2p_idx)
        relay.send_and_ping(msg_dandelionacc())
        return relay

    def stem_tx(self, relay):
        tx = self.wallet.create_self_transfer()
        self.nodes[0].sendrawtransaction(tx["hex"])
        relay.wait_until(lambda: tx["wtxid"] in relay.dltx_wtxids)
        return tx

    def run_test(self):
        self.wallet = MiniWallet(self.nodes[0])

        self.test_announced_after_restart()
        self.test_embargo_still_fluffs()

    def test_announced_after_restart(self):
        node = self.nodes[0]

        self.log.info("Stem a local transaction with mocktime frozen")
        now = int(time.time())
        node.setmocktime(now)
        relay = self.add_stem_relay(p2p_idx=0)
        tx = self.stem_tx(relay)
        # The embargo deadline is at least now + EMBARGO_MIN.

        self.log.info("Peers that connect during the stem phase are not announced it")
        late_peers = [node.add_outbound_p2p_connection(StemObserver(), p2p_idx=i) for i in range(1, 5)]
        for t in range(1, EMBARGO_MIN):
            node.setmocktime(now + t)
            for peer in late_peers:
                peer.sync_with_ping()
        for peer in late_peers:
            peer.sync_with_ping()
            assert not peer.got_inv(tx["wtxid"])
        assert tx["txid"] in node.getrawmempool()

        self.log.info("Restart before the embargo expires")
        self.restart_node(0)
        self.wait_until(lambda: node.getmempoolinfo()["loaded"])
        node.syncwithvalidationinterfacequeue()
        assert tx["txid"] in node.getrawmempool()

        self.log.info("A peer that connects after the restart is announced the transaction")
        peer = node.add_outbound_p2p_connection(P2PTxInvStore(), p2p_idx=5)
        peer.wait_for_broadcast([tx["wtxid"]])
        self.wait_until(lambda: node.getmempoolinfo()["unbroadcastcount"] == 0)
        assert_equal(node.getmempoolentry(tx["txid"])["unbroadcast"], False)

        node.disconnect_p2ps()
        self.wait_until(lambda: len(node.getpeerinfo()) == 0)

    def test_embargo_still_fluffs(self):
        node = self.nodes[0]

        self.log.info("Without a restart, the embargo fluffs a stemmed transaction")
        now = int(time.time())
        node.setmocktime(now)
        relay = self.add_stem_relay(p2p_idx=6)
        tx = self.stem_tx(relay)
        # Connected after the stem, and never requests the transaction.
        peer = node.add_outbound_p2p_connection(StemObserver(), p2p_idx=7)

        with node.assert_debug_log([f"embargo expired for tx {tx['txid'][:12]}"], timeout=30):
            node.setmocktime(now + EMBARGO_MAX + 1)

        # Step mocktime so the peer's next inventory trickle comes after the
        # fluff was queued.
        def announced():
            node.bumpmocktime(1)
            peer.sync_with_ping()
            return peer.got_inv(tx["wtxid"])
        self.wait_until(announced)

        self.log.info("Peers that connect after the fluff are not announced it")
        late_peers = [node.add_outbound_p2p_connection(StemObserver(), p2p_idx=i) for i in range(8, 10)]
        for _ in range(20):
            node.bumpmocktime(1)
            for late in late_peers:
                late.sync_with_ping()
        for late in late_peers:
            late.sync_with_ping()
            assert not late.got_inv(tx["wtxid"])
        assert_equal(node.getmempoolentry(tx["txid"])["unbroadcast"], False)

        node.setmocktime(0)
        node.disconnect_p2ps()


if __name__ == '__main__':
    DandelionRestartTest(__file__).main()
