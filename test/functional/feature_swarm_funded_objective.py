#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""Native funded objective: exact HTLC fund, claim, reorg and presigned refund.

A missing helper or signable plan is a failure. This test exercises the wallet
path with an intentionally absent model helper; no model peer holds wallet keys.
This is one isolated regtest node with two wallets, not a multi-host deployment,
a production L2 qualification, or evidence for every advertised payment mode.
"""
import hashlib
import importlib.util
import json
from decimal import Decimal
from pathlib import Path

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_raises_rpc_error

WATCHTOWER_PATH = Path(__file__).resolve().parents[2] / "contrib/swarm/native_payments/watchtower.py"
spec = importlib.util.spec_from_file_location("native_payment_watchtower", WATCHTOWER_PATH)
watchtower = importlib.util.module_from_spec(spec)
spec.loader.exec_module(watchtower)


class WalletRPCAdapter:
    def __init__(self, wallet):
        self.wallet = wallet

    def call(self, method, *params):
        return getattr(self.wallet, method)(*params)


class SwarmFundedObjectiveTest(BitcoinTestFramework):
    def add_options(self, parser):
        self.add_wallet_options(parser, legacy=False)

    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.supports_cli = False
        self.rpc_timeout = 180

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()
        self.skip_if_no_sqlite()

    def setup_nodes(self):
        self.modeldir = Path(self.options.tmpdir) / "funded-objective-models"
        self.modeldir.mkdir(parents=True)
        self.extra_args = [[
            "-autoshieldcoinbase=0", "-modelnet=1", "-modelnetrequired=0", "-modelbind=off", "-modelstorage=0",
            f"-modeldir={self.modeldir}", f"-modelhelper={self.modeldir / 'absent-helper'}",
            "-regtestmatmulbindingheight=2147483647", "-regtestmatmulproductdigestheight=2147483647",
            "-regtestmatmulv4height=2147483647", "-regtestmatmulrequireproductpayload=0",
        ]]
        super().setup_nodes()

    def run_test(self):
        node = self.nodes[0]
        assert_equal(node.getblockchaininfo()["chain"], "regtest")
        funder = node.get_wallet_rpc(self.default_wallet_name)
        mining_address = funder.getnewaddress()
        self.generatetoaddress(node, 102, mining_address)
        node.createwallet(wallet_name="objective_worker")
        worker = node.get_wallet_rpc("objective_worker")
        claimant = worker.exportpqkey(worker.getnewaddress())["pubkey"]
        refund_key = funder.exportpqkey(funder.getnewaddress())["pubkey"]
        amount, settlement_fee = 10_000_000, 1_000_000
        receipts = []

        def mine(count=1):
            self.generatetoaddress(node, count, mining_address)
            return node.getbestblockhash()

        def terms(secret, expiry):
            return {
                "key_hash": hashlib.sha256(secret).hexdigest(), "claimant": claimant,
                "refund_pubkey": refund_key, "refund_height": expiry,
                "amount_atoms": str(amount), "fee_cap_atoms": "1000000", "auto_pay": False,
                "automatic_spend_atoms": "0",
            }

        def fund(objective, options):
            count = funder.getwalletinfo()["txcount"]
            prepared = funder.preparefundmodelrelease(objective, options)
            assert_equal(prepared["plan_stage"], "WALLET_PREPARED")
            assert_equal(prepared["automatic_spend_atoms"], "0")
            assert_equal(prepared["amount_atoms"], str(amount))
            assert isinstance(prepared["fee_atoms"], str)
            assert isinstance(prepared["fee_cap_atoms"], str)
            assert_equal(funder.getwalletinfo()["txcount"], count)
            assert prepared["unsigned_hex"]
            assert_raises_rpc_error(-4, "fee_cap_atoms", funder.signmodelfunding,
                                    prepared["unsigned_hex"], dict(prepared, fee_cap_atoms="0"))
            signed = funder.signmodelfunding(prepared["unsigned_hex"], prepared)
            assert signed["complete"], signed
            assert_raises_rpc_error(-8, "fee_cap_atoms", funder.submitmodelfunding,
                                    signed["hex"], dict(prepared, fee_cap_atoms="0"))
            submitted = funder.submitmodelfunding(signed["hex"], prepared)
            txid = submitted["txid"]
            assert txid in node.getrawmempool()
            unconfirmed = funder.getmodelfundingsettlement(txid, prepared)
            assert_equal(unconfirmed["funded"], False)
            assert_equal(unconfirmed["settled"], False)
            prepared["funding_blockhash"] = mine()
            receipt = funder.getmodelfundingsettlement(txid, prepared)
            assert_equal(receipt["state"], "FUNDED")
            assert_equal(receipt["principal_atoms"], str(amount))
            assert_equal(receipt["settled"], False)
            duplicate = funder.submitmodelfunding(signed["hex"], prepared)
            assert_equal(duplicate["duplicate"], True)
            assert_equal(duplicate["submitted"], False)
            return txid, receipt["funding_vout"], prepared

        # Rejected aliases, malformed atoms and foreign refund ownership must
        # never be reclassified as a successful no-op funded objective.
        base = terms(bytes.fromhex("42" * 32), node.getblockcount() + 100)
        for extra in ({"automatic_spend_atoms": "1"}, {"auto_pay": "true"}, {"autopay": True}):
            assert_raises_rpc_error(-8, "automatic BTX spend is zero", funder.preparefundmodelrelease, "aa" * 48, dict(base, **extra))
        assert_raises_rpc_error(-8, "canonical", funder.preparefundmodelrelease, "aa" * 48, dict(base, amount_atoms="01"))
        assert_raises_rpc_error(-4, "refund pubkey", funder.preparefundmodelrelease, "aa" * 48, dict(base, refund_pubkey=claimant))
        assert_raises_rpc_error(-4, "exceeds fee_cap_atoms", funder.preparefundmodelrelease,
                                "aa" * 48, dict(base, fee_cap_atoms="0"))
        assert_raises_rpc_error(-4, "already expired", funder.preparefundmodelrelease,
                                "aa" * 48, dict(base, refund_height=node.getblockcount()))

        secret = bytes.fromhex("42" * 32)
        txid, vout, prepared = fund("aa" * 48, base)
        destination = worker.getnewaddress()
        claimed = worker.buildhtlcclaim(prepared["descriptor"], {"txid": txid, "vout": vout}, secret.hex(), destination, settlement_fee)
        assert_equal(claimed["complete"], True)
        claim_txid = node.sendrawtransaction(claimed["hex"])
        expectation = dict(prepared, destination=destination, max_settlement_fee_atoms=str(settlement_fee))
        pending = funder.getmodelfundingsettlement(txid, expectation, claim_txid)
        assert_equal(pending["settled"], False)
        assert_equal(pending["paid_atoms"], "0")
        expectation["settlement_blockhash"] = mine()
        receipt = funder.getmodelfundingsettlement(txid, expectation, claim_txid)
        assert_equal(receipt["state"], "CLAIMED")
        assert_equal(receipt["settled"], True)
        assert_equal(receipt["paid_atoms"], str(amount - settlement_fee))
        assert_equal(receipt["fee_atoms"], str(settlement_fee))
        assert_equal(Decimal(str(worker.getreceivedbyaddress(destination))), Decimal(amount - settlement_fee) / 100_000_000)
        assert_equal(receipt["release_qualified"], False)
        receipts.append(receipt)
        assert_raises_rpc_error(-8, "SETTLEMENT_MISMATCH", funder.getmodelfundingsettlement, txid,
                                dict(expectation, destination=funder.getnewaddress()), claim_txid)
        assert_raises_rpc_error(-8, "FEE_CAP", funder.getmodelfundingsettlement, txid,
                                dict(expectation, max_settlement_fee_atoms=str(settlement_fee - 1)), claim_txid)

        # A confirmed receipt is never permanently latched across a reorg.
        claim_block = expectation["settlement_blockhash"]
        node.invalidateblock(claim_block)
        orphan = funder.getmodelfundingsettlement(txid, expectation, claim_txid)
        assert_equal(orphan["settled"], False)
        assert_equal(orphan["paid_atoms"], "0")
        node.reconsiderblock(claim_block)
        assert_equal(funder.getmodelfundingsettlement(txid, expectation, claim_txid)["settled"], True)

        # A previously valid unsigned quote cannot mint a new signature after
        # its refund height passes while the owner is reviewing it.
        expired = funder.preparefundmodelrelease("cc" * 48,
            terms(bytes.fromhex("ca" * 32), node.getblockcount() + 1))
        mine()
        assert_raises_rpc_error(-4, "already expired", funder.signmodelfunding,
                                expired["unsigned_hex"], expired)

        # A second, separately funded work objective has a unilateral owner
        # refund. Recovery receives a complete presigned transaction, never a
        # key or permission to sign arbitrary future spends.
        refund_height = node.getblockcount() + 6
        rtxid, rvout, refund_quote = fund("bb" * 48, terms(bytes.fromhex("a5" * 32), refund_height))
        refund_destination = funder.getnewaddress()
        refund = funder.buildhtlcrefund(refund_quote["descriptor"], {"txid": rtxid, "vout": rvout},
                                       refund_destination, refund_height, settlement_fee)
        assert refund["complete"], refund
        early = node.testmempoolaccept([refund["hex"]])
        assert_equal(early[0]["allowed"], False)
        assert_raises_rpc_error(-26, None, node.sendrawtransaction, refund["hex"])
        database = Path(self.options.tmpdir) / "native-refund-watch.sqlite3"
        tower = watchtower.RefundWatchtower(database, WalletRPCAdapter(funder))
        try:
            tower.register(rtxid, refund_quote, refund_destination, refund["hex"], str(settlement_fee), 1)
            assert_equal(tower.poll()[0]["state"], "WAITING")
            tower.close()
            tower = watchtower.RefundWatchtower(database, WalletRPCAdapter(funder))
            assert_equal(tower.poll()[0]["state"], "WAITING")
            while node.getblockcount() < refund_height:
                mine()
            assert_equal(tower.poll()[0]["state"], "SUBMITTED")
            assert_equal(tower.poll()[0]["state"], "SUBMITTED")
            mine()
            assert_equal(tower.poll()[0]["state"], "CONFIRMED")
            refund_txid = node.decoderawtransaction(refund["hex"])["txid"]
            refund_receipt = funder.getmodelfundingsettlement(rtxid,
                dict(refund_quote, destination=refund_destination, max_settlement_fee_atoms=str(settlement_fee)), refund_txid)
            assert_equal(refund_receipt["state"], "REFUNDED")
            assert_equal(refund_receipt["paid_atoms"], str(amount - settlement_fee))
            assert_equal(Decimal(str(funder.getreceivedbyaddress(refund_destination))), Decimal(amount - settlement_fee) / 100_000_000)
            receipts.append(refund_receipt)
        finally:
            tower.close()
        assert_equal(node.getmodelnetworkinfo()["automatic_spend_atoms"], 0)
        (Path(self.options.tmpdir) / "native-payment-evidence.json").write_text(json.dumps({
            "profile": "isolated-regtest-sha256-htlc", "physical_hosts": 1,
            "funding_and_claim": "PASS", "funding_and_refund": "PASS", "reorg_revocation": "PASS",
            "native_fee_caps_and_expiry": "PASS",
            "presigned_refund_restart": "PASS", "generic_l2_watchtower": "NOT_RUN",
            "release_qualified": False, "receipts": receipts,
        }, indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    SwarmFundedObjectiveTest(__file__).main()
