#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""Exercise spend-path recovery block disconnect/reconnect behavior."""

from test_framework.blocktools import COINBASE_MATURITY
from test_framework.bridge_utils import build_spend_path_recovery_fixture
from test_framework.shielded_utils import encrypt_and_unlock_wallet
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal


LEGACY_FIXTURE_INPUT_COUNT = 3
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
        miner = encrypt_and_unlock_wallet(node, "miner")
        mine_addr = miner.getnewaddress(address_type="p2mr")
        stranded_addr = miner.z_getnewaddress()
        stranded_addr_info = miner.z_validateaddress(stranded_addr)
        assert stranded_addr_info["isvalid"], stranded_addr_info
        assert stranded_addr_info["ismine"], stranded_addr_info
        recovery_recipient = {
            "pk_hash": stranded_addr_info["pk_hash"],
            "kem_public_key": stranded_addr_info["kem_public_key"],
        }

        self.log.info("Mine enough mature outputs below the MatRiCT disable height")
        self.generatetoaddress(node, COINBASE_MATURITY + LEGACY_FIXTURE_INPUT_COUNT, mine_addr, sync_fun=self.no_op)

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

        self.log.info("Mine the deterministic legacy funding chain")
        for legacy_tx in fixture["legacy_txs"]:
            signed = miner.signrawtransactionwithwallet(legacy_tx["tx_hex"])
            assert_equal(signed["complete"], True)
            legacy_accept = node.testmempoolaccept(rawtxs=[signed["hex"]], maxfeerate=0)[0]
            assert legacy_accept["allowed"], legacy_accept
            node.sendrawtransaction(signed["hex"])
            self.generatetoaddress(node, 1, mine_addr, sync_fun=self.no_op)

        self.log.info("Advance the node past the MatRiCT disable height before attempting recovery")
        blocks_to_disable = REGTEST_MATRICT_DISABLE_HEIGHT - node.getblockcount()
        if blocks_to_disable > 0:
            self.generatetoaddress(node, blocks_to_disable, mine_addr, sync_fun=self.no_op)
        assert node.getblockcount() >= REGTEST_MATRICT_DISABLE_HEIGHT
        self.wait_until(
            lambda: any(
                note["commitment"] == fixture["recovery_input_note_commitment"]
                for note in miner.z_listunspent(1, 9999999, False, True)
            ),
            timeout=60,
        )

        recovery_result = miner.z_recoverstrandednote(fixture["recovery_input_note_commitment"])
        recovery_txid = recovery_result["txid"]
        recovery_tx_hex = node.getrawtransaction(recovery_txid)
        self.wait_until(lambda: recovery_txid in node.getrawmempool(), timeout=60)

        self.log.info("Mine a recovery block, invalidate it, then reconnect it")
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
