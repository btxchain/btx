#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""The shielded anchor window describes the active tip after a block disconnect.

ConnectBlock keeps the last SHIELDED_ANCHOR_DEPTH + 1 tree roots. If a block
disconnect only drops the newest root, the window misses the oldest root that
is still valid for the new tip, while a node that synced the same chain
without the reorg has it.

  1. S is a shielded spend built at tip H (anchor = root(H)), not broadcast.
  2. Block H+1 shields a new note, 100 empty blocks follow: tip T = H+101,
     where root(H) is outside the window (S is correctly rejected, both by
     the mempool and in a block).
  3. invalidateblock(T): tip H+100, where root(H) is the oldest valid root.
     S must now be accepted by the mempool and in a block.

Regtest only, loopback only.
"""

from decimal import Decimal

from test_framework.authproxy import JSONRPCException
from test_framework.blocktools import REGTEST_GENERIC_P2P_MATMUL_ARGS
from test_framework.shielded_utils import encrypt_and_unlock_wallet, ensure_ring_diversity
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal


class ShieldedAnchorWindowReorgTest(BitcoinTestFramework):
    def add_options(self, parser):
        self.add_wallet_options(parser)

    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.extra_args = [[
            "-walletbroadcast=0",
            "-autoshieldcoinbase=0",
            "-regtestshieldedmatrictdisableheight=500",
            "-modelnet=0",
            "-modellandiscovery=0",
        ] + REGTEST_GENERIC_P2P_MATMUL_ARGS]
        self.rpc_timeout = 900

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def gen(self, txs):
        return self.generateblock(self.nodes[0], self.mine_addr, txs, sync_fun=self.no_op)["hash"]

    def run_test(self):
        node = self.nodes[0]
        for name in ("a", "b"):
            node.createwallet(wallet_name=name, descriptors=True)
        wa = encrypt_and_unlock_wallet(node, "a")
        wb = encrypt_and_unlock_wallet(node, "b")
        self.mine_addr = wa.getnewaddress()
        self.generatetoaddress(node, 130, self.mine_addr, sync_fun=self.no_op)
        fund = wa.sendtoaddress(wb.getnewaddress(), Decimal("3.0"))
        node.sendrawtransaction(wa.gettransaction(fund)["hex"])
        self.generatetoaddress(node, 1, self.mine_addr, sync_fun=self.no_op)
        za = wa.z_getnewaddress()
        shield = wa.z_shieldfunds(Decimal("2.0"), za)["txid"]
        node.sendrawtransaction(wa.gettransaction(shield)["hex"])
        self.generatetoaddress(node, 1, self.mine_addr, sync_fun=self.no_op)
        ensure_ring_diversity(self, node, wa, self.mine_addr, za)

        self.log.info("Build S at tip H and keep it local")
        h = node.getblockcount()
        s_txid = wa.z_sendmany([{"address": wa.z_getnewaddress(), "amount": Decimal("0.1")}])["txid"]
        s_hex = wa.gettransaction(s_txid)["hex"]

        self.log.info("Block H+1 changes the tree, then 100 empty blocks")
        churn = wb.z_shieldfunds(Decimal("1.0"), wb.z_getnewaddress())["txid"]
        self.gen([wb.gettransaction(churn)["hex"]])
        for _ in range(100):
            self.gen([])
        tip_t = node.getbestblockhash()
        assert_equal(node.getblockcount(), h + 101)

        self.log.info("At T = H+101, root(H) is outside the window: S is rejected")
        res = node.testmempoolaccept([s_hex])[0]
        assert not res["allowed"] and "anchor" in res["reject-reason"], res
        try:
            self.gen([s_hex])
            raise AssertionError("block with S on T was accepted")
        except JSONRPCException:
            pass

        self.log.info("invalidateblock(T): at H+100, root(H) is the oldest valid root")
        node.invalidateblock(tip_t)
        assert_equal(node.getblockcount(), h + 100)
        res = node.testmempoolaccept([s_hex])[0]
        try:
            block = self.gen([s_hex])
            block_error = None
        except JSONRPCException as e:
            block, block_error = None, e.error.get("message", "")
        self.log.info(f"after the reorg: mempool allowed={res['allowed']} "
                      f"reason={res.get('reject-reason')}; block error={block_error}")
        assert res["allowed"] and block_error is None, \
            "S rejected after a one-block reorg (mempool and/or block)"
        assert_equal(node.getbestblockhash(), block)


if __name__ == "__main__":
    ShieldedAnchorWindowReorgTest(__file__).main()
