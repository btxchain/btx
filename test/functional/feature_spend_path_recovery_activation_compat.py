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
from test_framework.shielded_utils import encrypt_and_unlock_wallet
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal


LEGACY_FIXTURE_INPUT_COUNT = 3
REGTEST_MATRICT_DISABLE_HEIGHT = 132
REGTEST_RECOVERY_DISABLED_HEIGHT = 2_147_483_647


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
                f"-regtestshieldedspendpathrecoveryactivationheight={REGTEST_RECOVERY_DISABLED_HEIGHT}",
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
        miner = encrypt_and_unlock_wallet(upgraded_node, "miner")
        mine_addr = miner.getnewaddress(address_type="p2mr")
        stranded_addr = miner.z_getnewaddress()
        stranded_addr_info = miner.z_validateaddress(stranded_addr)
        assert stranded_addr_info["isvalid"], stranded_addr_info
        assert stranded_addr_info["ismine"], stranded_addr_info
        recovery_recipient = {
            "pk_hash": stranded_addr_info["pk_hash"],
            "kem_public_key": stranded_addr_info["kem_public_key"],
        }

        self.log.info("Mine enough mature wallet-owned outputs while staying below the MatRiCT disable height")
        self.mine_and_sync(upgraded_node, mine_addr, COINBASE_MATURITY + LEGACY_FIXTURE_INPUT_COUNT)

        funding_utxos = sorted(
            miner.listunspent(COINBASE_MATURITY),
            key=lambda utxo: (utxo["txid"], utxo["vout"]),
        )[:LEGACY_FIXTURE_INPUT_COUNT]
        assert_equal(len(funding_utxos), LEGACY_FIXTURE_INPUT_COUNT)

        self.log.info("Build a deterministic spend-path recovery fixture for post-disable recovery")
        fixture = build_spend_path_recovery_fixture(
            self,
            funding_utxos,
            validation_height=REGTEST_MATRICT_DISABLE_HEIGHT + 1,
            matrict_disable_height=REGTEST_MATRICT_DISABLE_HEIGHT,
            legacy_fee_sats=20_000,
            recovery_fee_sats=100_000,
            recovery_recipient=recovery_recipient,
        )
        assert_equal(len(fixture["legacy_txs"]), LEGACY_FIXTURE_INPUT_COUNT)

        self.log.info("Sign and mine the legacy shield-only funding transactions in deterministic tree order")
        for legacy_tx in fixture["legacy_txs"]:
            signed = miner.signrawtransactionwithwallet(legacy_tx["tx_hex"])
            assert_equal(signed["complete"], True)
            legacy_accept = feature_off_node.testmempoolaccept(rawtxs=[signed["hex"]], maxfeerate=0)[0]
            assert legacy_accept["allowed"], legacy_accept
            upgraded_node.sendrawtransaction(signed["hex"])
            self.mine_and_sync(upgraded_node, mine_addr, 1)

        self.log.info("Advance both nodes past the MatRiCT disable height before attempting recovery")
        blocks_to_disable = REGTEST_MATRICT_DISABLE_HEIGHT - upgraded_node.getblockcount()
        if blocks_to_disable > 0:
            self.mine_and_sync(upgraded_node, mine_addr, blocks_to_disable)
        assert upgraded_node.getblockcount() >= REGTEST_MATRICT_DISABLE_HEIGHT
        self.wait_until(
            lambda: any(
                note["commitment"] == fixture["recovery_input_note_commitment"]
                for note in miner.z_listunspent(1, 9999999, False, True)
            ),
            timeout=60,
        )

        self.log.info("Build the recovery tx on the upgraded wallet and confirm the feature-off node rejects it")
        recovery_result = miner.z_recoverstrandednote(fixture["recovery_input_note_commitment"])
        recovery_txid = recovery_result["txid"]
        recovery_tx_hex = upgraded_node.getrawtransaction(recovery_txid)
        self.wait_until(lambda: recovery_txid in upgraded_node.getrawmempool(), timeout=60)

        try:
            feature_off_accept = feature_off_node.testmempoolaccept(rawtxs=[recovery_tx_hex], maxfeerate=0)[0]
            assert not feature_off_accept["allowed"], feature_off_accept
            reject_reason = feature_off_accept["reject-reason"]
            assert (
                "shielded-v2-spend-path-recovery-disabled" in reject_reason
                or "shielded-matrict-disabled" in reject_reason
            ), feature_off_accept
        except JSONRPCException as exc:
            assert "TX decode failed" in exc.error["message"], exc.error

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
