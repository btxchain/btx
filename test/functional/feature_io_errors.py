#!/usr/bin/env python3
# Copyright (c) The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""Test that transaction lookups distinguish missing data from I/O errors."""

from decimal import Decimal

from test_framework.blocktools import COINBASE_MATURITY
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_raises_rpc_error


class IOErrorTest(BitcoinTestFramework):
    def add_options(self, parser):
        self.add_wallet_options(parser)

    def set_test_params(self):
        self.num_nodes = 1

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def run_test(self):
        self.log.info("Test transaction RPCs report block-file I/O errors")

        node = self.nodes[0]
        self.restart_node(0, ["-txindex"])
        self.wait_until(lambda: node.getindexinfo()["txindex"]["synced"])
        wallet = node.get_wallet_rpc(self.default_wallet_name)

        # Spend an explicitly mined P2MR coinbase so the parent transaction is
        # no longer in the UTXO set. This forces its lookup through txindex,
        # while avoiding MiniWallet scripts rejected by BTX's P2MR-only policy.
        mine_address = wallet.getnewaddress(address_type="p2mr")
        mined = self.generatetoaddress(node, COINBASE_MATURITY + 1, mine_address)
        coinbase = node.getblock(mined[0], 3)["tx"][0]
        prevout = {
            "txid": coinbase["txid"],
            "vout": 0,
            "scriptPubKey": coinbase["vout"][0]["scriptPubKey"]["hex"],
            "amount": coinbase["vout"][0]["value"],
        }
        destination = wallet.getnewaddress(address_type="p2mr")
        raw = node.createrawtransaction(
            [prevout],
            [{destination: coinbase["vout"][0]["value"] - Decimal("0.001")}],
        )
        signed = wallet.signrawtransactionwithwallet(raw, [prevout])
        txid = node.sendrawtransaction(signed["hex"], maxfeerate=0)

        destination2 = wallet.getnewaddress(address_type="p2mr")
        decoded = node.decoderawtransaction(signed["hex"])
        prevout2 = {
            "txid": txid,
            "vout": 0,
            "scriptPubKey": decoded["vout"][0]["scriptPubKey"]["hex"],
            "amount": decoded["vout"][0]["value"],
        }
        raw2 = node.createrawtransaction(
            [prevout2],
            [{destination2: decoded["vout"][0]["value"] - Decimal("0.001")}],
        )
        signed2 = wallet.signrawtransactionwithwallet(raw2, [prevout2])
        txid2 = node.sendrawtransaction(signed2["hex"], maxfeerate=0)
        block = self.generate(node, 1)[0]
        psbt = node.createpsbt(inputs=[{"txid": txid, "vout": 0}], outputs=[])

        blk_dat = node.blocks_path / "blk00000.dat"
        blk_dat_moved = node.blocks_path / "blk00000.dat.moved"
        blk_dat.rename(blk_dat_moved)

        txindex_msg = "I/O error while opening block file via txindex"
        assert_raises_rpc_error(-32603, txindex_msg, node.gettxoutproof, [txid])
        assert_raises_rpc_error(-32603, txindex_msg, node.getrawtransaction, txid)
        assert_raises_rpc_error(-32603, txindex_msg, node.utxoupdatepsbt, psbt)
        assert_raises_rpc_error(-32603, "I/O error reading block data", node.getrawtransaction, "a" * 64, blockhash=block)
        assert_raises_rpc_error(-32603, "Can't read block from disk", node.gettxoutproof, [txid2])

        blk_dat_moved.rename(blk_dat)


if __name__ == "__main__":
    IOErrorTest(__file__).main()
