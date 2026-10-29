#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""signbountyfunding bounds the fee of the transaction it signs.

The plan that reaches signbountyfunding is
caller JSON (agent, GUI, relay). The transaction fingerprint is checked
against the caller's own unsigned_hex, so a plan with a lowered change output
or an extra wallet input still matches itself. The wallet must still refuse to
sign a fee above the plan's fee_reserve_atoms or its own -maxtxfee:

  honest  prepared transaction unchanged          -> signed and submitted
  A       change output lowered by 5 BTX           -> refused
  B       extra wallet input, same outputs         -> refused
  D       change lowered to 3.5x fee_reserve_atoms -> refused
  E       fee_reserve_atoms "0.5", "-5", "12abc", "1e6", wrapping heights and
          a sloppy outpoint vout                     -> refused at parse time
"""

from decimal import Decimal

from test_framework.messages import COIN, tx_from_hex
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_raises_rpc_error

MATMUL_OFF = [
    "-regtestmatmulbindingheight=2147483647",
    "-regtestmatmulproductdigestheight=2147483647",
    "-regtestmatmulv4height=2147483647",
    "-regtestmatmulrequireproductpayload=0",
]
PRINCIPAL = 100_000_000
FEE_RESERVE = 10_000_000
CUT = 5 * COIN


class WalletBountyFundingFeeBoundTest(BitcoinTestFramework):
    def add_options(self, parser):
        self.add_wallet_options(parser, legacy=False)

    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.supports_cli = False
        self.extra_args = [["-autoshieldcoinbase=0", "-txindex=1", "-nomodelnet", *MATMUL_OFF]]

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def pq_pubkey(self, wallet):
        return wallet.exportpqkey(wallet.getnewaddress())["pubkey"]

    def prepared(self, funder, plan):
        prep = funder.preparebountyfunding(plan)
        bound = {**plan, "output_script": prep["output_script"], "descriptor": prep["descriptor"],
                 "refund_key": prep.get("refund_key", plan["refund_key"]), "plan_id": prep["plan_id"]}
        return prep, bound

    @staticmethod
    def change_index(tx, script):
        idx = [i for i, o in enumerate(tx.vout) if o.scriptPubKey != script]
        assert_equal(len(idx), 1)
        return idx[0]

    def run_test(self):
        node = self.nodes[0]
        funder = node.get_wallet_rpc(self.default_wallet_name)
        node.createwallet(wallet_name="council")
        council = node.get_wallet_rpc("council")
        addr = funder.getnewaddress()
        self.generatetoaddress(node, 115, addr, sync_fun=self.no_op)
        h = node.getblockcount()
        plan = {
            "principal_atoms": str(PRINCIPAL),
            "refund_key": self.pq_pubkey(funder),
            "fee_reserve_atoms": str(FEE_RESERVE),
            "council_keys": [self.pq_pubkey(council), self.pq_pubkey(council)],
            "threshold": 2,
            "award_height": h + 6,
            "refund_height": h + 20,
        }

        self.log.info("A: lowered change output is refused")
        prep, bound = self.prepared(funder, plan)
        esc = bytes.fromhex(prep["output_script"])
        tx = tx_from_hex(prep["unsigned_hex"])
        tx.vout[self.change_index(tx, esc)].nValue -= CUT
        hex_a = tx.serialize().hex()
        assert_raises_rpc_error(-4, "funding fee exceeds fee_reserve_atoms",
                                funder.signbountyfunding, {**bound, "unsigned_hex": hex_a, "hex": hex_a})

        self.log.info("B: extra wallet input is refused")
        used = {(f"{i.prevout.hash:064x}", i.prevout.n) for i in tx_from_hex(prep["unsigned_hex"]).vin}
        extra = next(u for u in funder.listunspent() if (u["txid"], u["vout"]) not in used and u["spendable"])
        tx = tx_from_hex(prep["unsigned_hex"])
        tx.vin.append(tx_from_hex(funder.createrawtransaction([{"txid": extra["txid"], "vout": extra["vout"]}], [])).vin[0])
        hex_b = tx.serialize().hex()
        assert_raises_rpc_error(-4, "funding fee exceeds fee_reserve_atoms",
                                funder.signbountyfunding, {**bound, "unsigned_hex": hex_b, "hex": hex_b})

        self.log.info("D: fee of 3.5x fee_reserve_atoms is refused")
        tx = tx_from_hex(prep["unsigned_hex"])
        tx.vout[self.change_index(tx, esc)].nValue -= int(3.5 * FEE_RESERVE)
        hex_d = tx.serialize().hex()
        assert_raises_rpc_error(-4, "funding fee exceeds fee_reserve_atoms",
                                funder.signbountyfunding, {**bound, "unsigned_hex": hex_d, "hex": hex_d})

        self.log.info("E: a non-canonical fee_reserve_atoms does not switch the cap off")
        for bad in ["0.5", "0.0001", "-5", "12abc", "1e6", " 1"]:
            assert_raises_rpc_error(-8, "fee_reserve_atoms: canonical non-negative atoms required",
                                    funder.signbountyfunding, {**bound, "fee_reserve_atoms": bad,
                                                               "unsigned_hex": hex_a, "hex": hex_a})
            assert_raises_rpc_error(-8, "fee_reserve_atoms: canonical non-negative atoms required",
                                    funder.preparebountyfunding, {**plan, "fee_reserve_atoms": bad})
        assert_raises_rpc_error(-8, "fee_reserve_atoms: canonical non-negative atoms required",
                                funder.signbountyfunding, {**bound, "fee_reserve_atoms": -5,
                                                           "unsigned_hex": hex_a, "hex": hex_a})
        assert_raises_rpc_error(-8, "fee_atoms: canonical non-negative atoms required",
                                funder.signbountyfunding, {**bound, "fee_atoms": "3.9",
                                                           "unsigned_hex": hex_a, "hex": hex_a})
        assert_raises_rpc_error(-8, "award_height out of range",
                                funder.preparebountyfunding, {**plan, "award_height": 2**32 + h + 6})
        assert_raises_rpc_error(-8, "refund_height out of range",
                                funder.preparebountyfunding, {**plan, "refund_height": -1})
        assert_raises_rpc_error(-8, "refund_height out of range",
                                funder.preparebountyfunding, {**plan, "refund_height": 500_000_000})
        prev = tx_from_hex(prep["unsigned_hex"]).vin[0].prevout
        assert_raises_rpc_error(-8, "outpoint", funder.signbountyfunding,
                                {**bound, "outpoint": f"{prev.hash:064x}:{prev.n}x",
                                 "unsigned_hex": hex_a, "hex": hex_a})
        assert_raises_rpc_error(-8, "prev_vout", funder.signbountyfunding,
                                {**bound, "prev_vout": -1, "unsigned_hex": hex_a, "hex": hex_a})

        self.log.info("Without a fee reserve, -maxtxfee still bounds the fee")
        no_reserve = {k: v for k, v in bound.items() if k != "fee_reserve_atoms"}
        assert_raises_rpc_error(-4, "funding fee exceeds -maxtxfee",
                                funder.signbountyfunding, {**no_reserve, "unsigned_hex": hex_a, "hex": hex_a})

        self.log.info("The honest prepared transaction is signed and submitted")
        res = funder.signbountyfunding({**bound, "unsigned_hex": prep["unsigned_hex"], "hex": prep["unsigned_hex"]})
        sub = funder.submitbountyfunding({"hex": res["hex"]})
        assert sub["submitted"], sub
        self.generatetoaddress(node, 1, addr, sync_fun=self.no_op)
        assert funder.gettransaction(sub["txid"])["confirmations"] >= 1


if __name__ == "__main__":
    WalletBountyFundingFeeBoundTest(__file__).main()
