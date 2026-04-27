#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""Exercise spend-path recovery block disconnect/reconnect behavior."""

from test_framework.blocktools import COINBASE_MATURITY
from test_framework.bridge_utils import build_spend_path_recovery_fixture
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal


LATTICE_RING_SIZE = 8
REGTEST_MATRICT_DISABLE_HEIGHT = 132


class SpendPathRecoveryReorgTest(BitcoinTestFramework):
    def add_options(self, parser):
        self.add_wallet_options(parser)

    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.rpc_timeout = 600
        self.extra_args = [[
            "-autoshieldcoinbase=0",
            "-dandelion=0",
            f"-regtestshieldedmatrictdisableheight={REGTEST_MATRICT_DISABLE_HEIGHT}",
            "-regtestshieldedspendpathrecoveryactivationheight=1",
        ]]

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def run_test(self):
        node = self.nodes[0]

        node.createwallet(wallet_name="miner", descriptors=True)
        miner = node.get_wallet_rpc("miner")
        mine_addr = miner.getnewaddress(address_type="p2mr")

        self.log.info("Mine enough mature outputs below the MatRiCT disable height")
        self.generatetoaddress(node, COINBASE_MATURITY + LATTICE_RING_SIZE, mine_addr, sync_fun=self.no_op)

        funding_utxos = sorted(
            miner.listunspent(COINBASE_MATURITY),
            key=lambda utxo: (utxo["txid"], utxo["vout"]),
        )[:LATTICE_RING_SIZE]
        assert_equal(len(funding_utxos), LATTICE_RING_SIZE)

        self.log.info("Build a deterministic spend-path recovery fixture at the next height")
        fixture = build_spend_path_recovery_fixture(
            self,
            funding_utxos,
            validation_height=node.getblockcount() + 1,
            matrict_disable_height=REGTEST_MATRICT_DISABLE_HEIGHT,
            legacy_fee_sats=20_000,
            recovery_fee_sats=100_000,
        )
        assert_equal(len(fixture["legacy_txs"]), LATTICE_RING_SIZE)

        self.log.info("Mine the deterministic legacy funding chain")
        for legacy_tx in fixture["legacy_txs"]:
            signed = miner.signrawtransactionwithwallet(legacy_tx["tx_hex"])
            assert_equal(signed["complete"], True)
            legacy_accept = node.testmempoolaccept(rawtxs=[signed["hex"]], maxfeerate=0)[0]
            assert legacy_accept["allowed"], legacy_accept
            node.sendrawtransaction(signed["hex"])
            self.generatetoaddress(node, 1, mine_addr, sync_fun=self.no_op)

        recovery_tx_hex = fixture["recovery_tx_hex"]
        recovery_accept = node.testmempoolaccept(rawtxs=[recovery_tx_hex], maxfeerate=0)[0]
        assert recovery_accept["allowed"], recovery_accept

        self.log.info("Mine a recovery block, invalidate it, then reconnect it")
        recovery_txid = node.sendrawtransaction(recovery_tx_hex)
        recovery_block = self.generatetoaddress(node, 1, mine_addr, sync_fun=self.no_op)[0]

        mined_recovery = node.getrawtransaction(recovery_txid, True, recovery_block)
        assert_equal(mined_recovery["shielded"]["bundle_type"], "v2")
        assert_equal(mined_recovery["shielded"]["family"], "v2_spend_path_recovery")
        assert recovery_txid not in node.getrawmempool()

        node.invalidateblock(recovery_block)
        self.wait_until(lambda: recovery_txid in node.getrawmempool(), timeout=60)
        assert node.getbestblockhash() != recovery_block

        node.reconsiderblock(recovery_block)
        self.wait_until(lambda: node.getbestblockhash() == recovery_block, timeout=60)
        self.wait_until(lambda: recovery_txid not in node.getrawmempool(), timeout=60)

        reconnected_recovery = node.getrawtransaction(recovery_txid, True, recovery_block)
        assert_equal(reconnected_recovery["txid"], recovery_txid)
        assert_equal(reconnected_recovery["confirmations"], 1)
        assert_equal(reconnected_recovery["shielded"]["family"], "v2_spend_path_recovery")


if __name__ == "__main__":
    SpendPathRecoveryReorgTest(__file__).main()
