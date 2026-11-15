#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""Test that wallet fee sizing covers the sigop-adjusted vsize of P2MR spends.

Relay policy charges a transaction max(weight, sigop cost * -bytespersigop).
One SLH-DSA checksig is 500 sigops (10,000 vbytes at the default 20) and a
2-of-3 ML-DSA multisig leaf is 1,050 sigops (21,000 vbytes), both more than
the input's weight. The node runs with -corepolicy=0 so that the release
relay floor of 1 sat/vB applies, as on mainnet.
"""
from decimal import Decimal

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_greater_than_or_equal


class WalletPQSigopFeeTest(BitcoinTestFramework):
    def add_options(self, parser):
        self.add_wallet_options(parser)

    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        # -fallbackfee=0.00001 is the release default (1 sat/vB). Keep coinbase
        # outputs transparent and regtest mining cheap.
        self.extra_args = [[
            "-corepolicy=0", "-fallbackfee=0.00001", "-autoshieldcoinbase=0",
            "-modelnet=0", "-modelbind=off",
            "-regtestmatmulbindingheight=2147483647", "-regtestmatmulproductdigestheight=2147483647",
            "-regtestmatmulv4height=2147483647", "-regtestmatmulrequireproductpayload=0",
        ]]

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def check_rate(self, txid, rate):
        """The tx is in the mempool and pays the requested rate on the mempool's vsize."""
        entry = self.nodes[0].getmempoolentry(txid)
        paid = Decimal(entry["fees"]["base"]) * 100_000_000 / entry["vsize"]
        self.log.info(f"  vsize {entry['vsize']}, paid {paid:.3f} sat/vB, asked {rate}")
        assert_greater_than_or_equal(paid, Decimal(rate))
        assert paid < Decimal(rate) * Decimal("1.02"), f"overpaid: {paid}"

    def import_wallet(self, name, ext, internal):
        node = self.nodes[0]
        node.createwallet(wallet_name=name, blank=True)
        wallet = node.get_wallet_rpc(name)
        requests = []
        for desc, is_internal in ((ext, False), (internal, True)):
            desc += "#" + node.getdescriptorinfo(desc)["checksum"]
            requests.append({"desc": desc, "active": True, "internal": is_internal, "timestamp": "now", "range": [0, 20]})
        assert all(r["success"] for r in wallet.importdescriptors(requests))
        return wallet

    def mine(self):
        self.generatetoaddress(self.nodes[0], 1, self.funder.getnewaddress(), sync_fun=self.no_op)

    def fund(self, wallet, count):
        self.funder.send(outputs=[{wallet.getnewaddress(): 1} for _ in range(count)], options={"fee_rate": 5})
        self.mine()

    def run_test(self):
        node = self.nodes[0]
        node.createwallet(wallet_name="funder")
        node.createwallet(wallet_name="receiver")
        self.funder = node.get_wallet_rpc("funder")
        receiver = node.get_wallet_rpc("receiver")
        self.generatetoaddress(node, 120, self.funder.getnewaddress(), sync_fun=self.no_op)

        desc = [d for d in self.funder.listdescriptors(True)["descriptors"] if d["active"] and not d["internal"]][0]["desc"]
        assert desc.startswith("mr(pqhd(")
        seed = desc[len("mr(pqhd("):].split("/")[0]

        self.log.info("Control: a default ML-DSA spend is sized by weight")
        txid = self.funder.send(outputs=[{receiver.getnewaddress(): 1}], options={"fee_rate": 5})["txid"]
        self.check_rate(txid, 5)
        self.mine()

        self.log.info("SLH-DSA single-key wallet: 500 sigops per input")
        slh = self.import_wallet("slh", f"mr(pk_slh(pqhd({seed}/1h/0h/0/*)))", f"mr(pk_slh(pqhd({seed}/1h/0h/1/*)))")
        self.fund(slh, 4)
        self.log.info("- send at the 1 sat/vB relay floor relays")
        txid = slh.send(outputs=[{receiver.getnewaddress(): Decimal("0.3")}], options={"fee_rate": 1})["txid"]
        self.check_rate(txid, 1)
        self.mine()
        self.log.info("- sendtoaddress with the default fallback fee relays")
        txid = slh.sendtoaddress(receiver.getnewaddress(), Decimal("0.25"))
        self.check_rate(txid, 1)
        self.mine()
        self.log.info("- sendall pays the requested rate")
        txid = slh.sendall(recipients=[receiver.getnewaddress()], options={"fee_rate": 5})["txid"]
        self.check_rate(txid, 5)
        self.mine()

        self.log.info("2-of-3 ML-DSA multisig wallet: 1,050 sigops per input")
        ml_multi = self.import_wallet(
            "ml_2of3",
            f"mr(multi_pq(2,pqhd({seed}/1h/1h/0/*),pqhd({seed}/1h/2h/0/*),pqhd({seed}/1h/3h/0/*)))",
            f"mr(multi_pq(2,pqhd({seed}/1h/1h/1/*),pqhd({seed}/1h/2h/1/*),pqhd({seed}/1h/3h/1/*)))")
        self.fund(ml_multi, 3)
        txid = ml_multi.sendtoaddress(receiver.getnewaddress(), Decimal("0.25"))
        self.check_rate(txid, 1)
        self.mine()
        txid = ml_multi.sendall(recipients=[receiver.getnewaddress()], options={"fee_rate": 5})["txid"]
        self.check_rate(txid, 5)
        self.mine()

        self.log.info("2-of-2 SLH-DSA multisig wallet: 5,500 sigops per input")
        slh_multi = self.import_wallet(
            "slh_2of2",
            f"mr(multi_pq(2,pk_slh(pqhd({seed}/1h/4h/0/*)),pk_slh(pqhd({seed}/1h/5h/0/*))))",
            f"mr(multi_pq(2,pk_slh(pqhd({seed}/1h/4h/1/*)),pk_slh(pqhd({seed}/1h/5h/1/*))))")
        self.fund(slh_multi, 3)
        txid = slh_multi.sendall(recipients=[receiver.getnewaddress()], options={"fee_rate": 5})["txid"]
        self.check_rate(txid, 5)


if __name__ == "__main__":
    WalletPQSigopFeeTest(__file__).main()
