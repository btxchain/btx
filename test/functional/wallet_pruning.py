#!/usr/bin/env python3
# Copyright (c) 2022 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test importing pre-existing legacy wallet dumps on a pruned node."""

from test_framework.blocktools import (
    COINBASE_MATURITY,
    REGTEST_GENERIC_P2P_MATMUL_ARGS,
    create_block,
    create_coinbase,
)
from test_framework.messages import CTxOut
from test_framework.script import CScript, OP_RETURN, OP_TRUE
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_raises_rpc_error
from test_framework.wallet_util import (
    create_legacy_wallet_with_tool,
    get_generate_key,
)


class WalletPruningTest(BitcoinTestFramework):
    def add_options(self, parser):
        self.add_wallet_options(parser, descriptors=False)

    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 2
        self.wallet_names = []
        self.extra_args = [
            ["-nowallet", *REGTEST_GENERIC_P2P_MATMUL_ARGS],
            ["-nowallet", "-prune=550", *REGTEST_GENERIC_P2P_MATMUL_ARGS],
        ]

    def skip_test_if_missing_module(self):
        if not self.is_wallet_compiled():
            self.skip_if_no_wallet()
        self.enable_wallet_if_possible()
        if not self.is_bdb_compiled():
            self.skip_if_no_sqlite()
        self.skip_if_no_wallet_tool()

    def setup_nodes(self):
        self.add_nodes(self.num_nodes, self.extra_args)
        create_legacy_wallet_with_tool(self, self.nodes[1], "wallet_pruned")
        self.start_nodes()
        self.nodes[1].loadwallet("wallet_pruned")
        self.connect_nodes(1, 0)

    def mine_large_blocks(self, n):
        best = self.nodes[0].getblockheader(self.nodes[0].getbestblockhash())
        height = best["height"] + 1
        block_time = max(getattr(self, "block_time", 0), best["time"]) + 1
        previous = int(best["hash"], 16)
        filler_script = CScript([OP_RETURN, bytes(80)])
        for node in self.nodes:
            node.setmocktime(block_time + 600 * n)
        for _ in range(n):
            coinbase = create_coinbase(height, script_pubkey=CScript([OP_TRUE]))
            coinbase.vout.extend(CTxOut(0, filler_script) for _ in range(10300))
            coinbase.rehash()
            block = create_block(
                hashprev=previous,
                ntime=block_time,
                coinbase=coinbase,
            )
            block.solve()
            block_hex = block.serialize().hex()
            assert self.nodes[0].submitblock(block_hex) is None
            assert self.nodes[1].submitblock(block_hex) in (None, "duplicate")
            previous = block.sha256
            height += 1
            block_time += 600
        self.block_time = block_time
        self.sync_blocks()

    def has_block(self, block_index):
        return (self.nodes[1].blocks_path / f"blk{block_index:05}.dat").is_file()

    def create_wallet_dump(self, wallet_name):
        self.stop_node(0)
        create_legacy_wallet_with_tool(self, self.nodes[0], wallet_name, blank=True)
        self.start_node(0, extra_args=[*self.extra_args[0], f"-mocktime={self.block_time}"])
        self.connect_nodes(0, 1)
        self.nodes[0].setmocktime(self.block_time)
        self.nodes[0].loadwallet(wallet_name)

        key = get_generate_key()
        wallet = self.nodes[0].get_wallet_rpc(wallet_name)
        result = wallet.importmulti([{
            "scriptPubKey": {"address": key.p2pkh_addr},
            "timestamp": "now",
            "keys": [key.privkey],
            "label": "runtime fixture",
        }], {"rescan": False})
        assert result[0]["success"]
        dump_path = self.nodes[0].datadir_path / f"{wallet_name}.dump"
        wallet.dumpwallet(dump_path)
        wallet.unloadwallet()
        return dump_path, key

    @staticmethod
    def dump_birthheight(dump_path):
        with open(dump_path, encoding="utf8") as dump_file:
            for line in dump_file:
                if line.startswith("# * Best block at time of backup"):
                    return int(line.split(" ")[9])
        raise AssertionError("wallet dump did not contain a best-block height")

    def run_test(self):
        self.log.info("Generating enough large blocks to exercise pruning")
        initial_hashes = self.generate(self.nodes[0], 250, sync_fun=self.no_op)
        for block_hash in initial_hashes:
            self.nodes[1].submitblock(self.nodes[0].getblock(block_hash, 0))
        self.sync_blocks()
        self.mine_large_blocks(50)
        assert not self.has_block(1)
        old_dump, _ = self.create_wallet_dump("old_wallet")

        self.mine_large_blocks(600)
        recent_dump, recent_key = self.create_wallet_dump("recent_wallet")

        # Regtest only begins pruning after height 1,000. Preserve the original
        # test's 101-block post-dump advance so the five final ~948 kB blocks
        # cross that threshold and trigger pruning without moving the recent
        # wallet's birth block outside the retained window.
        self.generate(self.nodes[0], COINBASE_MATURITY + 1)
        self.mine_large_blocks(5)
        assert not self.has_block(0)

        recent_birthheight = self.dump_birthheight(recent_dump)
        self.nodes[1].getblock(self.nodes[1].getblockhash(recent_birthheight))
        self.nodes[1].importwallet(recent_dump)
        assert self.nodes[1].getaddressinfo(recent_key.p2pkh_addr)["ismine"]

        old_birthheight = self.dump_birthheight(old_dump)
        assert_raises_rpc_error(
            -1,
            "Block not available (pruned data)",
            self.nodes[1].getblock,
            self.nodes[1].getblockhash(old_birthheight),
        )
        assert_raises_rpc_error(
            -4,
            "Pruned blocks",
            self.nodes[1].importwallet,
            old_dump,
        )


if __name__ == '__main__':
    WalletPruningTest(__file__).main()
