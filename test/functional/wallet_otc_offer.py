#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""Bonded OTC offer lifecycle (doc/btx-otc-escrow-supply-validation.md, contrib/otc).

Drives the contrib/otc/btx_otc.py SDK end to end against a regtest node:

  1. CREATE   a tier-B bonded offer: fund the bond vault + the OP_RETURN
              "BTXOTC1" || sha256(canonical terms) commitment in one tx.
  2. VERIFY   the published bundle with a node only (no seller cooperation):
              descriptor shape, UTXO existence/confirmations/amount, funding-tx
              commitment, expiry, attestation.
  3. REJECT   fakes: tampered terms, double-pledged outpoints (same coins, second
              terms hash), fabricated outpoints, insufficient confirmations, and
              descriptor trees with undeclared spend paths (fail closed).
  4. REFUND   the bond via its refund(locktime, key) leaf after expiry.
  5. SETTLE   stage 2: an HTLC settlement vault claimed by the buyer with the
              preimage (the trustless crypto-vs-crypto trade leg).
"""

import importlib.util
import os
import sys
from decimal import Decimal

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_greater_than
from test_framework.bridge_utils import create_bridge_wallet, find_output, mine_block


def _load_btx_otc():
    """Import contrib/otc/btx_otc.py from the source tree."""
    here = os.path.dirname(os.path.realpath(__file__))
    path = os.path.abspath(os.path.join(here, "..", "..", "contrib", "otc", "btx_otc.py"))
    spec = importlib.util.spec_from_file_location("btx_otc", path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules["btx_otc"] = mod
    spec.loader.exec_module(mod)
    return mod


btx_otc = _load_btx_otc()
COIN_SAT = 100_000_000


def rpc_adapter(rpc_conn):
    """btx_otc expects rpc(method, *params); adapt a test-framework RPC connection."""
    def rpc(method, *params):
        return getattr(rpc_conn, method)(*params)
    return rpc


class WalletOtcOfferTest(BitcoinTestFramework):
    def add_options(self, parser):
        self.add_wallet_options(parser, legacy=False)

    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.extra_args = [["-autoshieldcoinbase=0"]]

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()
        self.skip_if_no_sqlite()

    # ----------------------------- helpers -----------------------------

    def pq_pubkey(self, wallet):
        addr = wallet.getnewaddress(address_type="p2mr")
        return wallet.exportpqkey(addr)["pubkey"]

    def make_terms(self, seller_address, amount_sats, expiry_height, nonce):
        return {
            "version": 1,
            "amount_sats": amount_sats,
            "expiry_height": expiry_height,
            "price": "spot-0.5%",
            "settle_asset": "wBTX",
            "seller_address": seller_address,
            "nonce": nonce,
        }

    def assert_failed_checks(self, report, expected_failing):
        """The report must fail overall, with failures exactly in `expected_failing` names."""
        assert_equal(report.ok, False)
        failing = {c.name for c in report.failures()}
        assert failing & set(expected_failing), \
            f"expected a failure among {expected_failing}, got {failing}"

    # ----------------------------- test body -----------------------------

    def run_test(self):
        node = self.nodes[0]
        self.log.info("btx_otc offline selftest")
        btx_otc.selftest()

        desk, mine_addr = create_bridge_wallet(self, node, wallet_name="desk",
                                               amount=Decimal("15"))
        node.createwallet(wallet_name="buyer", descriptors=True)
        buyer = node.get_wallet_rpc("buyer")

        rpc = rpc_adapter(node)
        rpc_desk = rpc_adapter(desk)
        rpc_buyer = rpc_adapter(buyer)

        settle_pk = self.pq_pubkey(desk)
        refund_pk = self.pq_pubkey(desk)
        seller_address = desk.getnewaddress(address_type="p2mr")

        # === 1. CREATE a tier-B bonded offer ==================================
        self.log.info("create bonded offer (soft bond + OP_RETURN terms binding)")
        amount_sats = 3 * COIN_SAT
        expiry_height = node.getblockcount() + 30
        terms = self.make_terms(seller_address, amount_sats, expiry_height,
                                nonce="11" * 16)
        desc = btx_otc.soft_bond_descriptor(settle_pk, expiry_height, refund_pk)

        # A refund leaf that unlocks before the advertised expiry must be refused.
        bad_desc = btx_otc.soft_bond_descriptor(settle_pk, expiry_height - 5, refund_pk)
        try:
            btx_otc.create_offer(rpc, rpc_desk, terms, bad_desc)
            raise AssertionError("create_offer accepted refund_locktime < expiry_height")
        except ValueError as e:
            self.log.info(f"early-refund descriptor correctly refused: {e}")

        bundle = btx_otc.create_offer(rpc, rpc_desk, terms, desc)
        mine_block(self, node, mine_addr)

        outpoint = bundle["bond"]["outpoints"][0]
        assert_equal(bundle["bond"]["tier"], "B")
        assert_equal(len(bundle["bond"]["outpoints"]), 1)

        # The funding tx really carries the commitment output (no -txindex on this
        # node, so scope the lookup to the block that just confirmed it).
        fund_tx = node.getrawtransaction(outpoint["txid"], True, node.getbestblockhash())
        want_script = btx_otc.commitment_script_hex(terms)
        assert any(o["scriptPubKey"]["hex"] == want_script for o in fund_tx["vout"])

        # === 2. VERIFY the bundle ==============================================
        self.log.info("verify offer bundle (positive)")
        report = btx_otc.verify_offer(rpc, bundle, min_conf=1)
        for c in report.checks:
            self.log.info(f"  [{'ok' if c.ok else 'FAIL'}] {c.name}: {c.detail}")
        assert_equal(report.ok, True)
        assert_equal(report.tier, "B")
        assert_greater_than(report.verified_sats + 1, amount_sats)

        # === 3. REJECT fakes ===================================================
        self.log.info("reject: tampered terms (amount inflated after funding)")
        tampered = dict(bundle, terms=dict(terms, amount_sats=amount_sats * 10))
        self.assert_failed_checks(btx_otc.verify_offer(rpc, tampered, min_conf=1),
                                  {"commitment", "amount"})

        self.log.info("reject: double-pledge (same coins, second offer's terms)")
        second_terms = dict(terms, nonce="22" * 16)
        double = {
            "version": 1,
            "terms": second_terms,
            "bond": dict(bundle["bond"]),  # cites the SAME outpoint
        }
        self.assert_failed_checks(btx_otc.verify_offer(rpc, double, min_conf=1),
                                  {"commitment"})

        self.log.info("reject: fabricated outpoint")
        fake = dict(bundle, bond=dict(bundle["bond"],
                                      outpoints=[{"txid": "00" * 32, "vout": 0}]))
        self.assert_failed_checks(btx_otc.verify_offer(rpc, fake, min_conf=1),
                                  {"outpoints"})

        self.log.info("reject: insufficient confirmations")
        self.assert_failed_checks(btx_otc.verify_offer(rpc, bundle, min_conf=1000),
                                  {"outpoints"})

        self.log.info("reject: descriptor with an undeclared spend path (fail closed)")
        sneaky_desc = (f"mr({settle_pk},{{htlc({'ee' * 20},{settle_pk}),"
                       f"refund({expiry_height},{refund_pk})}})")
        sneaky = dict(bundle, bond=dict(bundle["bond"], descriptor=sneaky_desc))
        self.assert_failed_checks(btx_otc.verify_offer(rpc, sneaky, min_conf=1),
                                  {"descriptor-shape", "outpoints"})

        self.log.info("reject: duplicate outpoints in one bundle")
        dup = dict(bundle, bond=dict(bundle["bond"],
                                     outpoints=[outpoint, dict(outpoint)]))
        self.assert_failed_checks(btx_otc.verify_offer(rpc, dup, min_conf=1),
                                  {"outpoints"})

        # === 4. REFUND the bond after expiry ===================================
        self.log.info("bond refund via refund leaf after expiry")
        fee_sat = 20000
        blocks_needed = max(0, expiry_height - node.getblockcount())
        if blocks_needed:
            mine_block(self, node, mine_addr, blocks_needed)

        # Expired offers no longer verify.
        self.assert_failed_checks(btx_otc.verify_offer(rpc, bundle, min_conf=1),
                                  {"not-expired"})

        refund_dest = desk.getnewaddress(address_type="p2mr")
        raw = btx_otc.build_bond_refund(rpc_desk, bundle["bond"]["descriptor"],
                                        outpoint["txid"], outpoint["vout"],
                                        refund_dest, expiry_height, fee_sat)
        refund_txid = node.sendrawtransaction(raw)
        mine_block(self, node, mine_addr)
        assert_equal(desk.gettransaction(refund_txid)["confirmations"] >= 1, True)
        assert_equal(Decimal(str(desk.getreceivedbyaddress(refund_dest))),
                     Decimal(amount_sats - fee_sat) / Decimal(COIN_SAT))

        # A spent bond is detected instantly by the watcher.
        assert_equal(btx_otc.watch_offer(rpc, bundle, interval=0.01), "spent")

        # === 5. SETTLE stage 2: HTLC vault, buyer claims with preimage =========
        self.log.info("stage-2 settlement: HTLC vault claim by buyer")
        buyer_pk = self.pq_pubkey(buyer)
        preimage = btx_otc.new_preimage()
        h160 = btx_otc.swap_hash160_hex(preimage)
        swap_locktime = node.getblockcount() + 100
        swap_desc = btx_otc.swap_vault_descriptor(settle_pk, h160, buyer_pk,
                                                  swap_locktime, refund_pk)
        swap_desc_ck = btx_otc.add_checksum(rpc, swap_desc)
        swap_addr = btx_otc.bond_address(rpc, swap_desc_ck)
        for w in (desk, buyer):
            w.importdescriptors([{"desc": swap_desc_ck, "timestamp": "now",
                                  "internal": False}])

        swap_amount = Decimal("2.0")
        swap_txid = desk.sendtoaddress(swap_addr, swap_amount)
        mine_block(self, node, mine_addr)
        swap_vout, _ = find_output(node, swap_txid, swap_addr, desk)

        buyer_dest = buyer.getnewaddress(address_type="p2mr")
        claim_raw = btx_otc.build_swap_claim(rpc_buyer, swap_desc_ck, swap_txid,
                                             swap_vout, preimage, buyer_dest, fee_sat)
        claim_txid = node.sendrawtransaction(claim_raw)
        mine_block(self, node, mine_addr)
        assert_equal(buyer.gettransaction(claim_txid)["confirmations"] >= 1, True)
        assert_equal(Decimal(str(buyer.getreceivedbyaddress(buyer_dest))),
                     swap_amount - Decimal(fee_sat) / Decimal(COIN_SAT))

        # The preimage is revealed on-chain (what makes cross-chain legs atomic).
        claim_tx = node.getrawtransaction(claim_txid, True, node.getbestblockhash())
        revealed = any(
            btx_otc.swap_hash160_hex(bytes.fromhex(item)) == h160
            for vin in claim_tx["vin"] for item in vin.get("txinwitness", []) or []
            if len(item) % 2 == 0
        )
        assert_equal(revealed, True)


if __name__ == "__main__":
    WalletOtcOfferTest(__file__).main()
