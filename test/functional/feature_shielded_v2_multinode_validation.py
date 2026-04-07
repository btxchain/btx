#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.

from decimal import Decimal

from test_framework.bridge_utils import (
    bridge_hex,
    build_signed_shielded_relay_fixture_tx,
    build_unsigned_shielded_relay_fixture_tx,
    build_ingress_batch_tx,
    build_ingress_statement,
    build_proof_policy,
    build_proof_profile,
    build_proof_receipt,
)
from test_framework.shielded_utils import (
    encrypt_and_unlock_wallet,
    ensure_ring_diversity,
    fund_trusted_transparent_balance,
)
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal


HIGH_SHIELDED_FEE_DELTA = 100_000_000


class ShieldedV2MultinodeValidationTest(BitcoinTestFramework):
    def add_options(self, parser):
        self.add_wallet_options(parser)

    def set_test_params(self):
        self.num_nodes = 4
        self.setup_clean_chain = True
        self.rpc_timeout = 600
        self.extra_args = [
            ["-autoshieldcoinbase=0", "-dandelion=0"],
            ["-autoshieldcoinbase=0", "-dandelion=0"],
            ["-autoshieldcoinbase=0", "-dandelion=0"],
            ["-autoshieldcoinbase=0", "-dandelion=0"],
        ]

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def sync_connected(self):
        self.sync_blocks(self.nodes[:3])
        self.sync_mempools(self.nodes[:3])

    def connect_connected_mesh(self):
        for a, b in ((0, 1), (0, 2), (1, 2)):
            try:
                self.connect_nodes(a, b)
            except Exception:
                pass
        self.wait_until(lambda: all(len(node.getpeerinfo()) >= 2 for node in self.nodes[:3]), timeout=60)
        self.sync_connected()

    def isolate_late_joiner(self):
        for peer in range(3):
            try:
                self.disconnect_nodes(3, peer)
            except Exception:
                pass
        self.wait_until(lambda: len(self.nodes[3].getpeerinfo()) == 0, timeout=60)

    def build_v2_ingress_batch_tx(self, node, source_wallet, mine_addr, ingress_wallet_name, seed):
        node.createwallet(wallet_name=ingress_wallet_name, descriptors=True)
        ingress_wallet = encrypt_and_unlock_wallet(node, ingress_wallet_name)
        ingress_taddr = ingress_wallet.getnewaddress()
        source_wallet.sendtoaddress(ingress_taddr, Decimal("1.0"))
        self.generatetoaddress(node, 1, mine_addr, sync_fun=self.no_op)
        self.sync_connected()

        ingress_funding_addr = ingress_wallet.z_getnewaddress()
        ingress_shield = ingress_wallet.z_shieldfunds(Decimal("0.40"), ingress_funding_addr)
        assert ingress_shield["txid"] in node.getrawmempool()
        self.generatetoaddress(node, 1, mine_addr, sync_fun=self.no_op)
        self.sync_connected()

        proof_profile = build_proof_profile(
            ingress_wallet,
            family="shieldedegress",
            proof_type="receipt",
            claim_system="settlement",
        )
        descriptor = {
            "proof_system_id": proof_profile["proof_system_id"],
            "verifier_key_hash": bridge_hex(seed + 0x01),
        }
        proof_policy = build_proof_policy(ingress_wallet, [descriptor], required_receipts=1, targets=[descriptor])
        intents = [
            {
                "wallet_id": bridge_hex(seed + 0x02),
                "destination_id": bridge_hex(seed + 0x03),
                "amount": Decimal("0.19"),
                "authorization_hash": bridge_hex(seed + 0x04),
                "l2_id": bridge_hex(seed + 0x05),
                "fee": Decimal("0.01"),
            },
        ]
        reserve_outputs = [{"address": ingress_wallet.z_getnewaddress(), "amount": Decimal("0.20")}]
        statement = build_ingress_statement(
            ingress_wallet,
            intents,
            bridge_id=bridge_hex(seed + 0x06),
            operation_id=bridge_hex(seed + 0x07),
            domain_id=bridge_hex(seed + 0x08),
            source_epoch=22,
            data_root=bridge_hex(seed + 0x09),
            proof_policy=proof_policy["proof_policy"],
        )
        proof_receipt = build_proof_receipt(
            ingress_wallet,
            statement["statement_hex"],
            proof_profile_hex=proof_profile["profile_hex"],
            verifier_key_hash=descriptor["verifier_key_hash"],
            public_values_hash=bridge_hex(seed + 0x0A),
            proof_commitment=bridge_hex(seed + 0x0B),
        )
        proof_receipt_policy = {
            "min_receipts": 1,
            "required_proof_system_ids": [descriptor["proof_system_id"]],
            "required_verifier_key_hashes": [descriptor["verifier_key_hash"]],
            "descriptor_proofs": [proof_policy["proofs"][0]["proof_hex"]],
        }
        return build_ingress_batch_tx(
            ingress_wallet,
            statement["statement_hex"],
            intents,
            reserve_outputs,
            {
                "proof_receipts": [proof_receipt["proof_receipt_hex"]],
                "proof_receipt_policy": proof_receipt_policy,
            },
        )

    def wait_for_mempool(self, txids, nodes=None):
        if nodes is None:
            nodes = self.nodes[:3]
        wanted = set(txids)
        self.wait_until(
            lambda: all(wanted.issubset(set(node.getrawmempool())) for node in nodes),
            timeout=120,
        )
        if len(nodes) > 1:
            self.sync_mempools(nodes)

    def mine_connected(self, miner_node, mine_addr):
        block_hash = self.generatetoaddress(miner_node, 1, mine_addr, sync_fun=self.no_op)[0]
        self.sync_connected()
        return block_hash

    def assert_block_family(self, node, txid, block_hash, family):
        tx = node.getrawtransaction(txid, True, block_hash)
        assert_equal(tx["shielded"]["bundle_type"], "v2")
        assert_equal(tx["shielded"]["family"], family)
        return tx

    def assert_default_retention_surface(self, node, expected_height):
        blockchaininfo = node.getblockchaininfo()
        assert_equal(blockchaininfo["blocks"], expected_height)
        assert_equal(blockchaininfo["headers"], expected_height)
        assert_equal(blockchaininfo["shielded_retention"]["profile"], "externalized")
        assert_equal(blockchaininfo["shielded_retention"]["retain_shielded_commitment_index"], False)
        assert_equal(blockchaininfo["snapshot_sync"]["active"], False)
        assert_equal(blockchaininfo["snapshot_sync"]["background_validation_in_progress"], False)

    def run_validation_scenario(self):
        node0, node1, node2, node3 = self.nodes

        self.log.info("Keep node3 isolated as a late joiner while nodes 0-2 carry the live shielded workload")
        self.isolate_late_joiner()
        self.connect_connected_mesh()

        node0.createwallet(wallet_name="miner", descriptors=True)
        node1.createwallet(wallet_name="user", descriptors=True)
        node2.createwallet(wallet_name="operator", descriptors=True)
        miner_wallet = encrypt_and_unlock_wallet(node0, "miner")
        user_wallet = encrypt_and_unlock_wallet(node1, "user")
        operator_wallet = encrypt_and_unlock_wallet(node2, "operator")

        miner_mine_addr = miner_wallet.getnewaddress(address_type="p2mr")
        user_mine_addr = user_wallet.getnewaddress(address_type="p2mr")
        operator_mine_addr = operator_wallet.getnewaddress(address_type="p2mr")

        self.log.info("Fund trusted transparent balances for miner, user, and operator wallets on the active mesh")
        fund_trusted_transparent_balance(
            self,
            node0,
            miner_wallet,
            miner_mine_addr,
            Decimal("12.0"),
            sync_fun=self.sync_connected,
        )
        fund_trusted_transparent_balance(
            self,
            node1,
            user_wallet,
            user_mine_addr,
            Decimal("6.0"),
            sync_fun=self.sync_connected,
        )
        fund_trusted_transparent_balance(
            self,
            node2,
            operator_wallet,
            operator_mine_addr,
            Decimal("6.0"),
            sync_fun=self.sync_connected,
        )

        self.log.info("Seed shielded liquidity and build a live mixed v2_send + v2_ingress_batch mempool on the active mesh")
        user_zaddr = user_wallet.z_getnewaddress()
        recipient_zaddr = miner_wallet.z_getnewaddress()
        user_wallet.z_shieldfunds(Decimal("2.0"), user_zaddr)
        self.mine_connected(node1, user_mine_addr)
        ensure_ring_diversity(
            self,
            node1,
            user_wallet,
            user_mine_addr,
            user_zaddr,
            min_notes=16,
            topup_amount=Decimal("0.5"),
            sync_fun=self.sync_connected,
        )
        seeded_balance = user_wallet.z_getbalance()
        assert int(seeded_balance["note_count"]) >= 16, seeded_balance

        ingress_tx = self.build_v2_ingress_batch_tx(node1, user_wallet, user_mine_addr, "dist_ingress", 0x310)
        assert_equal(ingress_tx["family"], "v2_ingress_batch")
        v2_send = user_wallet.z_sendmany([{"address": recipient_zaddr, "amount": Decimal("0.25")}])
        assert v2_send["txid"] in node1.getrawmempool()
        assert_equal(user_wallet.z_viewtransaction(v2_send["txid"])["family"], "v2_send")
        assert_equal(node1.sendrawtransaction(ingress_tx["tx_hex"]), ingress_tx["txid"])
        self.wait_for_mempool([v2_send["txid"], ingress_tx["txid"]], nodes=[node1])

        user_block = self.mine_connected(node1, user_mine_addr)
        self.assert_block_family(node2, v2_send["txid"], user_block, "v2_send")
        self.assert_block_family(node2, ingress_tx["txid"], user_block, "v2_ingress_batch")
        assert_equal(node0.getrawmempool(), [])
        assert_equal(node1.getrawmempool(), [])
        assert_equal(node2.getrawmempool(), [])

        self.log.info("Publish wallet-signed v2_rebalance and reserve-bound v2_settlement_anchor across the active mesh")
        relay_utxos = [
            utxo
            for utxo in operator_wallet.listunspent(101)
            if utxo.get("spendable", False) and Decimal(str(utxo["amount"])) > Decimal("0.001")
        ]
        assert len(relay_utxos) >= 2, relay_utxos
        rebalance_fixture = build_signed_shielded_relay_fixture_tx(
            self, node2, operator_wallet, "rebalance", relay_utxos[0], require_mempool_accept=True
        )
        settlement_fixture = build_signed_shielded_relay_fixture_tx(
            self, node2, operator_wallet, "settlement_anchor_receipt", relay_utxos[1]
        )
        assert_equal(rebalance_fixture["netting_manifest_id"], settlement_fixture["netting_manifest_id"])

        assert_equal(
            node2.sendrawtransaction(hexstring=rebalance_fixture["signed_tx_hex"], maxfeerate=0),
            rebalance_fixture["txid"],
        )
        self.wait_for_mempool([rebalance_fixture["txid"]], nodes=[node2])
        rebalance_block = self.mine_connected(node2, operator_mine_addr)
        rebalance_tx = self.assert_block_family(node1, rebalance_fixture["txid"], rebalance_block, "v2_rebalance")
        assert_equal(
            rebalance_tx["shielded"]["payload"]["netting_manifest"]["manifest_id"],
            rebalance_fixture["netting_manifest_id"],
        )

        assert_equal(
            node2.sendrawtransaction(hexstring=settlement_fixture["signed_tx_hex"], maxfeerate=0),
            settlement_fixture["txid"],
        )
        self.wait_for_mempool([settlement_fixture["txid"]], nodes=[node2])
        settlement_block = self.mine_connected(node2, operator_mine_addr)
        settlement_tx = self.assert_block_family(
            node1, settlement_fixture["txid"], settlement_block, "v2_settlement_anchor"
        )
        assert_equal(
            settlement_tx["shielded"]["payload"]["anchored_netting_manifest_id"],
            settlement_fixture["netting_manifest_id"],
        )

        self.log.info("Prioritise and mine a bare v2_egress_batch against the active settlement anchor on all active nodes")
        egress_fixture = build_unsigned_shielded_relay_fixture_tx(
            self, node2, "egress_receipt"
        )
        assert_equal(egress_fixture["family"], "v2_egress_batch")
        assert_equal(egress_fixture["settlement_anchor_digest"], settlement_fixture["settlement_anchor_digest"])
        for node in (node0, node1, node2):
            node.prioritisetransaction(txid=egress_fixture["txid"], fee_delta=HIGH_SHIELDED_FEE_DELTA)
        assert_equal(node2.sendrawtransaction(hexstring=egress_fixture["tx_hex"], maxfeerate=0), egress_fixture["txid"])
        self.wait_for_mempool([egress_fixture["txid"]], nodes=[node2])
        egress_block = self.mine_connected(node2, operator_mine_addr)
        egress_tx = self.assert_block_family(node1, egress_fixture["txid"], egress_block, "v2_egress_batch")
        assert_equal(
            egress_tx["shielded"]["payload"]["settlement_anchor"],
            egress_fixture["settlement_anchor_digest"],
        )

        self.log.info("Late joiner node3 should sync the historical mixed shielded_v2 chain and decode every mined family")
        for peer in (0, 1, 2):
            try:
                self.connect_nodes(3, peer)
            except Exception:
                pass
        self.sync_blocks(self.nodes)
        expected_height = node0.getblockcount()
        self.assert_default_retention_surface(node3, expected_height)
        self.assert_block_family(node3, v2_send["txid"], user_block, "v2_send")
        self.assert_block_family(node3, ingress_tx["txid"], user_block, "v2_ingress_batch")
        late_rebalance = self.assert_block_family(node3, rebalance_fixture["txid"], rebalance_block, "v2_rebalance")
        late_settlement = self.assert_block_family(node3, settlement_fixture["txid"], settlement_block, "v2_settlement_anchor")
        late_egress = self.assert_block_family(node3, egress_fixture["txid"], egress_block, "v2_egress_batch")
        assert_equal(
            late_rebalance["shielded"]["payload"]["netting_manifest"]["manifest_id"],
            settlement_fixture["netting_manifest_id"],
        )
        assert_equal(
            late_settlement["shielded"]["payload"]["anchored_netting_manifest_id"],
            settlement_fixture["netting_manifest_id"],
        )
        assert_equal(
            late_egress["shielded"]["payload"]["settlement_anchor"],
            settlement_fixture["settlement_anchor_digest"],
        )

        self.log.info("Restart node3 and verify the late-joiner recovery surface stays consistent after resync")
        self.restart_node(3)
        for peer in (0, 1, 2):
            try:
                self.connect_nodes(3, peer)
            except Exception:
                pass
        self.sync_blocks(self.nodes)
        self.assert_default_retention_surface(node3, expected_height)
        self.assert_block_family(node3, rebalance_fixture["txid"], rebalance_block, "v2_rebalance")
        self.assert_block_family(node3, settlement_fixture["txid"], settlement_block, "v2_settlement_anchor")
        self.assert_block_family(node3, egress_fixture["txid"], egress_block, "v2_egress_batch")

        for node in self.nodes:
            assert_equal(node.getbestblockhash(), node0.getbestblockhash())
            assert_equal(node.getrawmempool(), [])

        return {
            "wallets": {
                "miner": "miner",
                "user": "user",
                "operator": "operator",
                "miner_mine_addr": miner_mine_addr,
                "user_mine_addr": user_mine_addr,
                "operator_mine_addr": operator_mine_addr,
                "user_zaddr": user_zaddr,
                "recipient_zaddr": recipient_zaddr,
            },
            "txids": {
                "v2_send": v2_send["txid"],
                "v2_ingress_batch": ingress_tx["txid"],
                "v2_rebalance": rebalance_fixture["txid"],
                "v2_settlement_anchor": settlement_fixture["txid"],
                "v2_egress_batch": egress_fixture["txid"],
            },
            "blocks": {
                "v2_send_and_ingress_batch": user_block,
                "v2_rebalance": rebalance_block,
                "v2_settlement_anchor": settlement_block,
                "v2_egress_batch": egress_block,
            },
            "expected_height": expected_height,
            "netting_manifest_id": settlement_fixture["netting_manifest_id"],
            "settlement_anchor_digest": settlement_fixture["settlement_anchor_digest"],
            "retention_surface": node3.getblockchaininfo()["shielded_retention"],
        }

    def run_test(self):
        self.run_validation_scenario()


if __name__ == "__main__":
    ShieldedV2MultinodeValidationTest(__file__).main()
