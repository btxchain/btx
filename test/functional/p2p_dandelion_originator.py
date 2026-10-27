#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""Test that a Dandelion++ originator keeps its own stem transaction private.

BroadcastTransaction adds a local transaction to the mempool and sends it on
the stem as DLTX to one relay. Until the node's embargo for that transaction
expires, the node must not announce it to its peers (not even when a
forcerelay peer sends it back), serve it to a GETDATA, or list it in a BIP35
MEMPOOL reply. Once the embargo has expired, it announces the transaction
normally.

node0 makes two outbound full-relay connections:
  stem: sends DANDELIONACC, so it is the only possible stem relay.
  spy:  does not, so it can never be a stem relay.
Both get noban (node0 then sends them inventory on every SendMessages pass
instead of on the randomized trickle timer, so an announcement would arrive at
once), mempool permission (BIP35) and forcerelay. Mock time stays frozen while
the stem phase is checked. The embargo lasts at least EMBARGO_MIN (5 s) of mock
time, so it cannot expire before the test moves the clock.
"""

from test_framework.messages import (
    CInv,
    MSG_TX,
    MSG_TYPE_MASK,
    MSG_WTX,
    msg_dandelionacc,
    msg_getdata,
    msg_mempool,
    msg_tx,
)
from test_framework.p2p import (
    P2PInterface,
    p2p_lock,
)
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
    assert_raises_rpc_error,
)
from test_framework.wallet import MiniWallet

# Dandelion::EMBARGO_MAX (src/dandelion.h)
EMBARGO_MAX = 180


class TxObserver(P2PInterface):
    """Records transaction announcements and DLTX messages. Requests nothing.

    The query helpers read state shared with the network thread: call them
    under p2p_lock, or from wait_until (which holds it)."""

    def __init__(self):
        super().__init__()
        self.inv_msgs = []
        self.dltx_wtxids = []

    def on_inv(self, message):
        hashes = [inv.hash for inv in message.inv if (inv.type & MSG_TYPE_MASK) in (MSG_TX, MSG_WTX)]
        if hashes:
            self.inv_msgs.append(hashes)

    def on_dltx(self, message):
        self.dltx_wtxids.append(message.tx.getwtxid())

    def announced(self, tx):
        ids = (int(tx["txid"], 16), int(tx["wtxid"], 16))
        return any(h in ids for msg in self.inv_msgs for h in msg)

    def got_dltx(self, tx):
        return tx["wtxid"] in self.dltx_wtxids


class DandelionOriginatorTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.extra_args = [[
            "-dandelion=1",
            "-whitelist=noban,mempool,forcerelay,out@127.0.0.1",
            # MiniWallet's anyone-can-spend output is not standard on this chain.
            "-acceptnonstdtxn=1",
            # The model subsystem plays no part in transaction relay.
            "-modelnet=0",
        ]]

    def run_test(self):
        node = self.nodes[0]
        wallet = MiniWallet(node)

        self.log.info("Connect the stem peer first, so it is the only Dandelion++ relay candidate")
        stem = node.add_outbound_p2p_connection(TxObserver(), p2p_idx=0, connection_type="outbound-full-relay")
        stem.send_and_ping(msg_dandelionacc())
        spy = node.add_outbound_p2p_connection(TxObserver(), p2p_idx=1, connection_type="outbound-full-relay")
        spy.sync_with_ping()
        for peer in node.getpeerinfo():
            for permission in ("noban", "mempool", "forcerelay"):
                assert permission in peer["permissions"], peer

        mock_time = int(node.getblockheader(node.getbestblockhash())["time"]) + 1
        node.setmocktime(mock_time)

        self.log.info("A transaction from the spy is relayed normally (control for the BIP35 reply)")
        control = wallet.create_self_transfer()
        spy.send_and_ping(msg_tx(control["tx"]))
        assert control["txid"] in node.getrawmempool()

        self.log.info("A local transaction goes on the stem as DLTX to the stem peer")
        local = wallet.send_self_transfer(from_node=node)
        stem.wait_until(lambda: stem.got_dltx(local))
        with p2p_lock:
            assert not spy.got_dltx(local)

        self.log.info("During the embargo the originator does not announce it")
        # node0 runs SendMessages for a peer right after handling its ping, and
        # whatever it announces then reaches the peer before the next pong, so a
        # few round trips flush anything queued for announcement.
        for _ in range(3):
            spy.sync_with_ping()
            stem.sync_with_ping()
        with p2p_lock:
            assert not spy.announced(local), "originator announced its stem transaction"
            assert not stem.announced(local), "originator announced its stem transaction to the stem relay"

        self.log.info("During the embargo the originator does not serve it")
        want = msg_getdata([CInv(t=MSG_WTX, h=int(local["wtxid"], 16))])
        with p2p_lock:
            spy.last_message.pop("notfound", None)
            spy.last_message.pop("tx", None)
        spy.send_and_ping(want)
        with p2p_lock:
            assert "tx" not in spy.last_message, "originator served its stem transaction"
            assert_equal(spy.last_message["notfound"].vec, want.inv)

        self.log.info("During the embargo the originator does not list it in a BIP35 mempool reply")
        with p2p_lock:
            spy.inv_msgs.clear()
        spy.send_and_ping(msg_mempool())
        spy.wait_until(lambda: any(int(control["wtxid"], 16) in msg for msg in spy.inv_msgs))
        spy.sync_with_ping()
        with p2p_lock:
            assert not spy.announced(local), "originator listed its stem transaction in a mempool reply"

        self.log.info("During the embargo a forcerelay peer sending it back does not make the originator announce it")
        stem.send_and_ping(msg_tx(local["tx"]))
        for _ in range(3):
            spy.sync_with_ping()
            stem.sync_with_ping()
        with p2p_lock:
            assert not spy.announced(local), "originator announced its stem transaction after a forcerelay echo"

        self.log.info("A transaction retried after a rejected submission still goes on the stem")
        parent = wallet.create_self_transfer()
        child = wallet.create_self_transfer(utxo_to_spend=parent["new_utxo"])
        assert_raises_rpc_error(-25, "bad-txns-inputs-missingorspent", node.sendrawtransaction, hexstring=child["hex"], maxfeerate=0)
        wallet.sendrawtransaction(from_node=node, tx_hex=parent["hex"])
        node.sendrawtransaction(hexstring=child["hex"], maxfeerate=0)
        for _ in range(3):
            spy.sync_with_ping()
            stem.sync_with_ping()
        with p2p_lock:
            assert stem.got_dltx(parent) and stem.got_dltx(child), "retried transaction was not stemmed"
            assert not spy.announced(child), "originator announced a retried stem transaction"

        self.log.info("After the embargo the originator announces it and serves it")
        node.setmocktime(mock_time + EMBARGO_MAX + 1)
        spy.wait_until(lambda: spy.announced(local))
        with p2p_lock:
            spy.last_message.pop("tx", None)
        spy.send_and_ping(want)
        with p2p_lock:
            assert_equal(spy.last_message["tx"].tx.getwtxid(), local["wtxid"])
        assert local["txid"] in node.getrawmempool()


if __name__ == '__main__':
    DandelionOriginatorTest(__file__).main()
