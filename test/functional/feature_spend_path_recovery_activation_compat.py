#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""Exercise spend-path recovery compatibility across activation boundaries."""

import os
from pathlib import Path

from test_framework.authproxy import JSONRPCException
from test_framework.blocktools import COINBASE_MATURITY
from test_framework.bridge_utils import build_spend_path_recovery_fixture
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal


LATTICE_RING_SIZE = 8
REGTEST_MATRICT_DISABLE_HEIGHT = 132


class SpendPathRecoveryActivationCompatTest(BitcoinTestFramework):
    def add_options(self, parser):
        self.add_wallet_options(parser)

    def set_test_params(self):
        self.num_nodes = 2
        self.setup_clean_chain = True
        self.rpc_timeout = 600
        self._baseline_bitcoind = os.getenv("BTX_BASELINE_BITCOIND")
        self._baseline_bitcoincli = os.getenv("BTX_BASELINE_BITCOINCLI")
        self.extra_args = [
            [
                "-autoshieldcoinbase=0",
                "-dandelion=0",
                f"-regtestshieldedmatrictdisableheight={REGTEST_MATRICT_DISABLE_HEIGHT}",
                "-regtestshieldedspendpathrecoveryactivationheight=1",
            ],
            [
                "-autoshieldcoinbase=0",
                "-dandelion=0",
                f"-regtestshieldedmatrictdisableheight={REGTEST_MATRICT_DISABLE_HEIGHT}",
            ],
        ]

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def setup_nodes(self):
        if bool(self._baseline_bitcoind) != bool(self._baseline_bitcoincli):
            raise AssertionError(
                "BTX_BASELINE_BITCOIND and BTX_BASELINE_BITCOINCLI must be provided together"
            )

        if self._baseline_bitcoind is None:
            self.add_nodes(self.num_nodes, self.extra_args)
        else:
            baseline_bitcoind = Path(self._baseline_bitcoind)
            baseline_bitcoincli = Path(self._baseline_bitcoincli)
            if not baseline_bitcoind.is_file():
                raise AssertionError(f"Baseline daemon not found: {baseline_bitcoind}")
            if not baseline_bitcoincli.is_file():
                raise AssertionError(f"Baseline CLI not found: {baseline_bitcoincli}")

            self.add_nodes(
                self.num_nodes,
                extra_args=self.extra_args,
                binary=[self.options.bitcoind, str(baseline_bitcoind)],
                binary_cli=[self.options.bitcoincli, str(baseline_bitcoincli)],
            )
        self.start_nodes()

    def mine_and_sync(self, node, address, blocks=1):
        hashes = self.generatetoaddress(node, blocks, address, sync_fun=self.no_op)
        self.sync_blocks(self.nodes)
        return hashes

    def run_test(self):
        upgraded_node, feature_off_node = self.nodes
        self.connect_nodes(0, 1)
        if self._baseline_bitcoind is not None:
            self.log.info("Running strict patched-binary vs baseline-binary compatibility coverage")
        else:
            self.log.info("Running activation-split coverage with the same binary on both nodes")

        upgraded_node.createwallet(wallet_name="miner", descriptors=True)
        miner = upgraded_node.get_wallet_rpc("miner")
        mine_addr = miner.getnewaddress(address_type="p2mr")

        self.log.info("Mine enough mature wallet-owned outputs while staying below the MatRiCT disable height")
        self.mine_and_sync(upgraded_node, mine_addr, COINBASE_MATURITY + LATTICE_RING_SIZE)

        funding_utxos = sorted(
            miner.listunspent(COINBASE_MATURITY),
            key=lambda utxo: (utxo["txid"], utxo["vout"]),
        )[:LATTICE_RING_SIZE]
        assert_equal(len(funding_utxos), LATTICE_RING_SIZE)

        self.log.info("Build a deterministic spend-path recovery fixture against the next validation height")
        fixture = build_spend_path_recovery_fixture(
            self,
            funding_utxos,
            validation_height=upgraded_node.getblockcount() + 1,
            matrict_disable_height=REGTEST_MATRICT_DISABLE_HEIGHT,
            legacy_fee_sats=20_000,
            recovery_fee_sats=100_000,
        )
        assert_equal(len(fixture["legacy_txs"]), LATTICE_RING_SIZE)

        self.log.info("Sign and mine the legacy shield-only funding transactions in deterministic tree order")
        for legacy_tx in fixture["legacy_txs"]:
            signed = miner.signrawtransactionwithwallet(legacy_tx["tx_hex"])
            assert_equal(signed["complete"], True)
            legacy_accept = feature_off_node.testmempoolaccept(rawtxs=[signed["hex"]], maxfeerate=0)[0]
            assert legacy_accept["allowed"], legacy_accept
            upgraded_node.sendrawtransaction(signed["hex"])
            self.mine_and_sync(upgraded_node, mine_addr, 1)

        self.log.info("The upgraded node should accept the recovery tx while the feature-off node rejects it")
        recovery_tx_hex = fixture["recovery_tx_hex"]
        upgraded_accept = upgraded_node.testmempoolaccept(rawtxs=[recovery_tx_hex], maxfeerate=0)[0]
        assert upgraded_accept["allowed"], upgraded_accept

        try:
            feature_off_accept = feature_off_node.testmempoolaccept(rawtxs=[recovery_tx_hex], maxfeerate=0)[0]
            assert not feature_off_accept["allowed"], feature_off_accept
            assert "spend-path-recovery-disabled" in feature_off_accept["reject-reason"]
        except JSONRPCException as exc:
            if self._baseline_bitcoind is None:
                raise
            assert "TX decode failed" in exc.error["message"], exc.error

        recovery_txid = upgraded_node.sendrawtransaction(recovery_tx_hex)
        self.wait_until(lambda: recovery_txid in upgraded_node.getrawmempool(), timeout=60)

        self.log.info("Mine the recovery tx on the upgraded node and confirm the feature-off peer falls behind")
        recovery_block = self.generatetoaddress(upgraded_node, 1, mine_addr, sync_fun=self.no_op)[0]
        self.wait_until(
            lambda: feature_off_node.getblockcount() == upgraded_node.getblockcount() - 1,
            timeout=60,
        )
        assert feature_off_node.getbestblockhash() != upgraded_node.getbestblockhash()

        mined_recovery = upgraded_node.getrawtransaction(recovery_txid, True, recovery_block)
        assert_equal(mined_recovery["txid"], recovery_txid)
        assert_equal(mined_recovery["shielded"]["bundle_type"], "v2")
        assert_equal(mined_recovery["shielded"]["family"], "v2_spend_path_recovery")


if __name__ == "__main__":
    SpendPathRecoveryActivationCompatTest(__file__).main()
