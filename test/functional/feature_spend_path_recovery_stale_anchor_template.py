#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""A spend-path recovery whose note anchor ages out of the
SHIELDED_ANCHOR_DEPTH window must not break block templates.

V2_SPEND_PATH_RECOVERY has no account-registry reference, so the block
assembler's registry-anchor check does not skip it once its note anchor is
stale; TestBlockValidity then fails and CreateNewBlock falls back to an
empty template.

1. Recovery R is admitted to the mempool while its anchor is valid.
2. One block without R changes the tree, then 101 empty blocks without R.
3. An unrelated transparent transaction T is broadcast.
4. getblocktemplate and the next mined block must include T, and leave out
   R without evicting it: R stays in the mempool.

Regtest only, loopback only.
"""

from decimal import Decimal

from test_framework.blocktools import COINBASE_MATURITY, REGTEST_GENERIC_P2P_MATMUL_ARGS
from test_framework.bridge_utils import build_spend_path_recovery_fixture
from test_framework.shielded_utils import encrypt_and_unlock_wallet
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal

LEGACY_FIXTURE_INPUT_COUNT = 3
REGTEST_MATRICT_DISABLE_HEIGHT = 132


class SpendPathRecoveryStaleAnchorTemplateTest(BitcoinTestFramework):
    def add_options(self, parser):
        self.add_wallet_options(parser)

    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.rpc_timeout = 600
        self.extra_args = [[
            "-autoshieldcoinbase=0",
            "-dandelion=0",
            "-nomodelnet",
            "-modellandiscovery=0",
            f"-regtestshieldedmatrictdisableheight={REGTEST_MATRICT_DISABLE_HEIGHT}",
            "-regtestshieldedspendpathrecoveryactivationheight=1",
        ] + REGTEST_GENERIC_P2P_MATMUL_ARGS]

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def run_test(self):
        node = self.nodes[0]
        node.createwallet(wallet_name="miner", descriptors=True)
        node.createwallet(wallet_name="churn", descriptors=True)
        miner = encrypt_and_unlock_wallet(node, "miner")
        churn = encrypt_and_unlock_wallet(node, "churn")
        mine_addr = miner.getnewaddress(address_type="p2mr")
        stranded_addr = miner.z_getnewaddress()
        info = miner.z_validateaddress(stranded_addr)
        recipient = {"pk_hash": info["pk_hash"], "kem_public_key": info["kem_public_key"]}

        self.generatetoaddress(node, COINBASE_MATURITY + LEGACY_FIXTURE_INPUT_COUNT, mine_addr, sync_fun=self.no_op)
        funding = sorted(miner.listunspent(COINBASE_MATURITY),
                         key=lambda u: (u["txid"], u["vout"]))[:LEGACY_FIXTURE_INPUT_COUNT]
        fixture = build_spend_path_recovery_fixture(
            self, funding,
            validation_height=REGTEST_MATRICT_DISABLE_HEIGHT + 1,
            matrict_disable_height=REGTEST_MATRICT_DISABLE_HEIGHT,
            legacy_fee_sats=20_000, recovery_fee_sats=100_000,
            recovery_recipient=recipient)
        for legacy_tx in fixture["legacy_txs"]:
            signed = miner.signrawtransactionwithwallet(legacy_tx["tx_hex"])
            node.sendrawtransaction(signed["hex"])
            self.generatetoaddress(node, 1, mine_addr, sync_fun=self.no_op)

        self.log.info("Fund the churn wallet")
        churn_fund = miner.sendtoaddress(churn.getnewaddress(), Decimal("3.0"))
        self.generatetoaddress(node, 1, mine_addr, sync_fun=self.no_op)
        assert churn_fund not in node.getrawmempool()
        if node.getblockcount() < REGTEST_MATRICT_DISABLE_HEIGHT:
            self.generatetoaddress(node, REGTEST_MATRICT_DISABLE_HEIGHT - node.getblockcount(),
                                   mine_addr, sync_fun=self.no_op)
        self.wait_until(lambda: any(n["commitment"] == fixture["recovery_input_note_commitment"]
                                    for n in miner.z_listunspent(1, 9999999, False, True)), timeout=60)

        self.log.info("Admit recovery R while its anchor is valid")
        r_txid = miner.z_recoverstrandednote(fixture["recovery_input_note_commitment"])["txid"]
        self.wait_until(lambda: r_txid in node.getrawmempool(), timeout=60)
        r_family = node.getrawtransaction(r_txid, True)["shielded"]["family"]
        assert_equal(r_family, "v2_spend_path_recovery")

        self.log.info("Change the tree root with a block that does not include R")
        # After the MatRiCT disable height only mature coinbase may be shielded.
        churn_txid = miner.z_shieldfunds(Decimal("1.0"), churn.z_getnewaddress())["txid"]
        churn_hex = miner.gettransaction(churn_txid)["hex"]
        self.generateblock(node, mine_addr, [churn_hex], sync_fun=self.no_op)
        assert r_txid in node.getrawmempool()

        self.log.info("Connect 101 more blocks without R (anchor leaves the window)")
        for _ in range(101):
            self.generateblock(node, mine_addr, [], sync_fun=self.no_op)
        r_in_mempool = r_txid in node.getrawmempool()
        self.log.info(f"R still in mempool after anchor expiry: {r_in_mempool}")

        self.log.info("Broadcast unrelated transparent transaction T")
        t_txid = miner.sendtoaddress(churn.getnewaddress(), Decimal("0.5"))
        assert t_txid in node.getrawmempool()

        template = node.getblocktemplate({"rules": ["segwit"]})
        template_txids = [e["txid"] for e in template["transactions"]]
        self.log.info(f"template tx count={len(template_txids)} contains_T={t_txid in template_txids} "
                      f"contains_R={r_txid in template_txids}")
        block = node.getblock(self.generatetoaddress(node, 1, mine_addr, sync_fun=self.no_op)[0])
        mined_t = t_txid in block["tx"]
        self.log.info(f"next block tx count={len(block['tx'])} mined_T={mined_t} "
                      f"R_in_mempool={r_txid in node.getrawmempool()}")

        assert t_txid in template_txids, "block template dropped every mempool transaction (empty fallback)"
        assert mined_t, "unrelated transaction T was not mined while R (stale anchor) sits in the mempool"
        # R is skipped, not evicted: after a disconnect brings its anchor back
        # into the window it can still be mined.
        assert r_in_mempool, "R was evicted when its anchor left the window"
        assert r_txid not in template_txids, "R (stale anchor) is in the block template"
        assert r_txid not in block["tx"], "R (stale anchor) was mined"
        assert r_txid in node.getrawmempool(), "R left the mempool when the next block was mined"


if __name__ == "__main__":
    SpendPathRecoveryStaleAnchorTemplateTest(__file__).main()
