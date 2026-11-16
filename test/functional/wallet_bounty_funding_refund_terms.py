#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""submitbountyfunding keeps the escrow refund terms with the wallet transaction.

After refund_height the funder refunds the escrow with the descriptor and the
refund key. preparebountyfunding creates that key when the plan has none, so
before this only the prepare/sign JSON held the terms: lose it and the escrow
cannot be refunded from the wallet.

  public  council escrow, wallet-made refund key, submitted with the sign result
  staged  htlc escrow, wallet-made refund key, submitted with the sign result
  dup     already mined, then submitbountyfunding with the sign result
  hex     submitted with the hex only: no terms, as before
All terms survive a restart.
"""

import hashlib

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal

MATMUL_OFF = [
    "-regtestmatmulbindingheight=2147483647",
    "-regtestmatmulproductdigestheight=2147483647",
    "-regtestmatmulv4height=2147483647",
    "-regtestmatmulrequireproductpayload=0",
]
PRINCIPAL = 100_000_000
FEE_RESERVE = 10_000_000


class WalletBountyFundingRefundTermsTest(BitcoinTestFramework):
    def add_options(self, parser):
        self.add_wallet_options(parser, legacy=False)

    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.supports_cli = False
        self.extra_args = [["-autoshieldcoinbase=0", "-nomodelnet", "-modellandiscovery=0", *MATMUL_OFF]]

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def pq_pubkey(self, wallet):
        return wallet.exportpqkey(wallet.getnewaddress())["pubkey"]

    def signed(self, funder, plan):
        # No refund_key in the plan: the wallet makes one.
        assert "refund_key" not in plan
        prep = funder.preparebountyfunding(plan)
        assert prep["refund_key"]
        bound = {**plan, "output_script": prep["output_script"], "descriptor": prep["descriptor"],
                 "refund_key": prep["refund_key"], "plan_id": prep["plan_id"]}
        res = funder.signbountyfunding({**bound, "unsigned_hex": prep["unsigned_hex"], "hex": prep["unsigned_hex"]})
        assert_equal(res["descriptor"], prep["descriptor"])
        return prep, res

    def check_terms(self, funder, txid, prep, plan):
        tx = funder.gettransaction(txid)
        assert_equal(tx.get("bounty_descriptor"), prep["descriptor"])
        assert_equal(tx.get("bounty_refund_pubkey"), prep["refund_key"])
        assert_equal(tx.get("bounty_refund_height"), str(plan["refund_height"]))
        raw = funder.decoderawtransaction(tx["hex"])
        assert_equal(raw["vout"][int(tx["bounty_output_vout"])]["scriptPubKey"]["hex"], prep["output_script"])
        if plan.get("mode") == "STAGED_RELEASE":
            assert_equal(tx.get("bounty_hashlock"), plan["hashlock_hex"])
            assert_equal(tx.get("bounty_claimant"), plan["claimant_key"])
        else:
            assert_equal(tx.get("bounty_award_height"), str(plan["award_height"]))
            assert_equal(tx.get("bounty_threshold"), str(plan["threshold"]))
            assert_equal(tx.get("bounty_council_keys"), ",".join(plan["council_keys"]))

    def run_test(self):
        node = self.nodes[0]
        funder = node.get_wallet_rpc(self.default_wallet_name)
        node.createwallet(wallet_name="council")
        council = node.get_wallet_rpc("council")
        addr = funder.getnewaddress()
        self.generatetoaddress(node, 115, addr, sync_fun=self.no_op)
        h = node.getblockcount()
        public = {
            "principal_atoms": str(PRINCIPAL),
            "fee_reserve_atoms": str(FEE_RESERVE),
            "council_keys": [self.pq_pubkey(council), self.pq_pubkey(council)],
            "threshold": 2,
            "award_height": h + 6,
            "refund_height": h + 20,
        }
        staged = {
            "principal_atoms": str(PRINCIPAL),
            "fee_reserve_atoms": str(FEE_RESERVE),
            "claimant_key": self.pq_pubkey(council),
            "hashlock_hex": hashlib.sha256(b"r20 staged refund terms").hexdigest(),
            "refund_height": h + 30,
            "mode": "STAGED_RELEASE",
        }

        self.log.info("public: the sign result given to submitbountyfunding leaves the terms on the wallet transaction")
        prep_p, res_p = self.signed(funder, public)
        sub_p = funder.submitbountyfunding(res_p)
        assert sub_p["submitted"], sub_p
        self.check_terms(funder, sub_p["txid"], prep_p, public)

        self.log.info("staged: the htlc terms are kept the same way")
        prep_s, res_s = self.signed(funder, staged)
        sub_s = funder.submitbountyfunding(res_s)
        assert sub_s["submitted"], sub_s
        self.check_terms(funder, sub_s["txid"], prep_s, staged)

        self.log.info("dup: a funding already mined and then submitted keeps the terms too")
        dup_plan = {**public, "refund_height": h + 40}
        prep_d, res_d = self.signed(funder, dup_plan)
        txid_d = node.sendrawtransaction(res_d["hex"])
        self.generatetoaddress(node, 1, addr, sync_fun=self.no_op)
        assert "bounty_descriptor" not in funder.gettransaction(txid_d)
        sub_d = funder.submitbountyfunding(res_d)
        assert_equal(sub_d["txid"], txid_d)
        assert sub_d["duplicate"], sub_d
        self.check_terms(funder, txid_d, prep_d, dup_plan)

        self.log.info("hex: without the plan nothing is added, as before")
        hex_plan = {**public, "refund_height": h + 50}
        _, res_h = self.signed(funder, hex_plan)
        sub_h = funder.submitbountyfunding({"hex": res_h["hex"]})
        assert sub_h["submitted"], sub_h
        assert "bounty_descriptor" not in funder.gettransaction(sub_h["txid"])

        self.log.info("The terms survive a restart")
        self.restart_node(0)
        funder = node.get_wallet_rpc(self.default_wallet_name)
        self.check_terms(funder, sub_p["txid"], prep_p, public)
        self.check_terms(funder, sub_s["txid"], prep_s, staged)
        self.check_terms(funder, txid_d, prep_d, dup_plan)


if __name__ == '__main__':
    WalletBountyFundingRefundTermsTest(__file__).main()
