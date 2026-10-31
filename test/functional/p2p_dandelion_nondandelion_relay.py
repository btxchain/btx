#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""Test a stem transaction whose relay peer does not support Dandelion++.

When no outbound peer has sent DANDELIONACC, SelectNewRelays falls back to an
outbound peer that has not. A DLTX that is then routed to that peer must be
taken out of the stempool and fluffed: added to the mempool and announced.

That fallback used to run inside the CConnman::ForNode callback, so it took
the Dandelion++ mutex and cs_main while holding m_nodes_mutex. Route selection
takes m_nodes_mutex while holding the Dandelion++ mutex (and cs_main on the
sendrawtransaction path), so this was a lock-order inversion. A build with
DEBUG_LOCKORDER aborts on it with "POTENTIAL DEADLOCK DETECTED".

node0 has two peers:
  fallback: outbound full relay, never sends DANDELIONACC.
  sender:   inbound. It sends DANDELIONACC only after the epoch has picked
            its relays, so the fallback peer is the only relay.
"""

from test_framework.messages import (
    MSG_TX,
    MSG_TYPE_MASK,
    MSG_WTX,
    msg_dandelionacc,
    msg_dltx,
)
from test_framework.p2p import (
    P2PInterface,
    p2p_lock,
)
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal
from test_framework.wallet import MiniWallet

# Below the 20 minute inactivity timeout, so the peers stay connected while
# the clock moves past the epoch deadline.
CLOCK_STEP = 1000


class TxObserver(P2PInterface):
    def __init__(self):
        super().__init__()
        self.tx_invs = set()

    def on_inv(self, message):
        for inv in message.inv:
            if inv.type & MSG_TYPE_MASK in (MSG_TX, MSG_WTX):
                self.tx_invs.add(inv.hash)


class DandelionNonDandelionRelayTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.extra_args = [[
            "-dandelion=1",
            "-debug=dandelion",
            # Announce at once instead of on the trickle timer.
            "-whitelist=noban,in,out@127.0.0.1",
            # MiniWallet's anyone-can-spend output is not standard on this chain.
            "-acceptnonstdtxn=1",
            # The model subsystem plays no part in transaction relay.
            "-modelnet=0",
        ]]

    def read_log_from(self, offset):
        with open(self.nodes[0].debug_log_path, encoding="utf-8", errors="replace") as f:
            f.seek(offset)
            return f.read()

    def log_size(self):
        with open(self.nodes[0].debug_log_path, "rb") as f:
            f.seek(0, 2)
            return f.tell()

    def run_test(self):
        node = self.nodes[0]
        wallet = MiniWallet(node)
        tx = wallet.create_self_transfer()

        mock_time = int(node.getblockheader(node.getbestblockhash())["time"]) + 1
        node.setmocktime(mock_time)

        self.log.info("Connect an outbound peer without Dandelion++ and an inbound sender")
        fallback = node.add_outbound_p2p_connection(TxObserver(), p2p_idx=0, connection_type="outbound-full-relay")
        fallback.sync_with_ping()
        sender = node.add_p2p_connection(P2PInterface())
        fallback_id = next(p["id"] for p in node.getpeerinfo() if p["connection_type"] == "outbound-full-relay")

        self.log.info("Start a stem epoch whose only relay is the fallback peer")
        for _ in range(40):
            offset = self.log_size()
            mock_time += CLOCK_STEP
            node.setmocktime(mock_time)
            fallback.sync_with_ping()
            sender.sync_with_ping()
            node.mockscheduler(5)
            try:
                self.wait_until(lambda: "Dandelion++: new epoch" in self.read_log_from(offset), timeout=3)
            except AssertionError:
                continue  # the epoch deadline has not passed yet
            log = self.read_log_from(offset)
            if "selected 1 relay destination(s)" in log and "new epoch, stem_mode=1" in log:
                break
        else:
            raise AssertionError("no stem epoch with the fallback peer as its only relay")

        sender.send_and_ping(msg_dandelionacc())

        self.log.info("A DLTX routed to the fallback peer is fluffed, without a lock-order inversion")
        offset = self.log_size()
        sender.send_and_ping(msg_dltx(tx["tx"]))
        log = self.read_log_from(offset)
        assert f"relay to {fallback_id}," in log, log
        assert "POTENTIAL DEADLOCK DETECTED" not in log
        assert tx["txid"] in node.getrawmempool()
        fallback.wait_until(lambda: int(tx["wtxid"], 16) in fallback.tx_invs)
        with p2p_lock:
            assert_equal(len(fallback.tx_invs), 1)


if __name__ == '__main__':
    DandelionNonDandelionRelayTest(__file__).main()
