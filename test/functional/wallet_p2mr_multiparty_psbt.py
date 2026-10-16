#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""Multi-party PSBT with multi-leaf P2MR inputs.

A P2MR signature commits to every spent output, so no input can be signed
while another input's UTXO is missing from the PSBT. A party that processes
the PSBT at that point (walletprocesspsbt, send with an external input,
descriptorprocesspsbt) must get it back with complete=false, not the error
"multi-leaf P2MR input: no leaf selected". Once every spent output is known,
an unsigned multi-leaf input with no selected leaf keeps that error.
"""
from decimal import Decimal

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
    assert_raises_rpc_error,
)

# An outpoint this node has never seen, standing in for another party's coin
# that is not yet confirmed or relayed.
UNKNOWN_OUTPOINT = {"txid": "ab" * 32, "vout": 0}


class WalletP2MRMultipartyPSBTTest(BitcoinTestFramework):
    def add_options(self, parser):
        self.add_wallet_options(parser, legacy=False)

    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.extra_args = [[
            "-autoshieldcoinbase=0",
            "-modelnet=0",
            "-modelbind=off",
            # Regtest-only MatMul knobs that keep block generation fast.
            "-regtestmatmulbindingheight=2147483647",
            "-regtestmatmulproductdigestheight=2147483647",
            "-regtestmatmulv4height=2147483647",
            "-regtestmatmulrequireproductpayload=0",
        ]]

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def run_test(self):
        node = self.nodes[0]
        node.createwallet(wallet_name="funder", descriptors=True)
        self.funder = node.get_wallet_rpc("funder")
        node.createwallet(wallet_name="burn", descriptors=True)
        self.burn_addr = node.get_wallet_rpc("burn").getnewaddress()
        # One coinbase per address, so the funder never reuses an address.
        for _ in range(12):
            self.generatetoaddress(node, 1, self.funder.getnewaddress(), sync_fun=self.no_op)
        self.generatetoaddress(node, 100, self.burn_addr, sync_fun=self.no_op)

        self.test_walletprocesspsbt()
        self.test_send_with_external_input()
        self.test_descriptorprocesspsbt()

    def make_parties(self, tag):
        """Two wallets, each funded by a third wallet, so neither has the other's UTXO."""
        node = self.nodes[0]
        node.createwallet(wallet_name="a_" + tag, descriptors=True)
        node.createwallet(wallet_name="b_" + tag, descriptors=True)
        party_a = node.get_wallet_rpc("a_" + tag)
        party_b = node.get_wallet_rpc("b_" + tag)
        self.funder.sendtoaddress(party_a.getnewaddress(), 3)
        self.funder.sendtoaddress(party_b.getnewaddress(), 4)
        self.generatetoaddress(node, 1, self.burn_addr, sync_fun=self.no_op)
        utxo_a = party_a.listunspent()[0]
        utxo_b = party_b.listunspent()[0]
        return party_a, party_b, utxo_a, utxo_b

    def assert_input_unsigned(self, psbt, index):
        assert "final_scriptwitness" not in self.nodes[0].decodepsbt(psbt)["inputs"][index]

    def finish(self, party_a, party_b, psbt):
        """B signs its input, then A signs its own: the transaction is complete and valid."""
        second = party_b.walletprocesspsbt(psbt)
        assert_equal(second["complete"], False)
        third = party_a.walletprocesspsbt(second["psbt"])
        assert_equal(third["complete"], True)
        assert_equal(self.nodes[0].testmempoolaccept([third["hex"]])[0]["allowed"], True)

    def test_walletprocesspsbt(self):
        self.log.info("walletprocesspsbt before the other party's UTXO is known returns complete=false")
        node = self.nodes[0]
        party_a, party_b, utxo_a, utxo_b = self.make_parties("wpp")
        psbt = node.createpsbt(
            [{"txid": utxo_a["txid"], "vout": utxo_a["vout"]}, {"txid": utxo_b["txid"], "vout": utxo_b["vout"]}],
            [{self.funder.getnewaddress(): Decimal("6.99")}],
        )
        for party in (party_a, party_b):
            first = party.walletprocesspsbt(psbt)
            assert_equal(first["complete"], False)
            self.assert_input_unsigned(first["psbt"], 0)
            self.assert_input_unsigned(first["psbt"], 1)
        self.finish(party_a, party_b, party_a.walletprocesspsbt(psbt)["psbt"])

    def test_send_with_external_input(self):
        self.log.info("send with another party's coin as an input returns an incomplete PSBT")
        party_a, party_b, utxo_a, utxo_b = self.make_parties("send")
        res = party_a.send(
            outputs=[{self.funder.getnewaddress(): Decimal("6.9")}],
            options={
                "inputs": [
                    {"txid": utxo_a["txid"], "vout": utxo_a["vout"]},
                    {"txid": utxo_b["txid"], "vout": utxo_b["vout"], "weight": 16000},
                ],
                "add_inputs": False,
                "fee_rate": 25,
            },
        )
        assert_equal(res["complete"], False)
        # Coin selection may reorder the inputs; neither can be signed yet.
        self.assert_input_unsigned(res["psbt"], 0)
        self.assert_input_unsigned(res["psbt"], 1)
        self.finish(party_a, party_b, res["psbt"])

    def public_descriptor(self, wallet, address):
        """The public 2-leaf (ML-DSA, SLH-DSA) descriptor of one wallet address."""
        node = self.nodes[0]
        ml_dsa = wallet.exportpqkey(address)["pubkey"]
        slh_dsa = wallet.exportpqkey(address, "slh-dsa-shake-128s")["pubkey"]
        body = f"mr({ml_dsa},pk_slh({slh_dsa}))"
        desc = body + "#" + node.getdescriptorinfo(body)["checksum"]
        assert_equal(node.deriveaddresses(desc), [address])
        return desc

    def test_descriptorprocesspsbt(self):
        node = self.nodes[0]
        party_a, _, utxo_a, _ = self.make_parties("desc")
        # Index 0 holds utxo_a. Keep the range small: each index is a PQ key derivation.
        private_descs = [{"desc": d["desc"], "range": [0, 2]} for d in party_a.listdescriptors(True)["descriptors"] if d["active"]]
        public_descs = [self.public_descriptor(party_a, utxo_a["address"])]
        own_input = {"txid": utxo_a["txid"], "vout": utxo_a["vout"]}

        self.log.info("descriptorprocesspsbt with another input this node cannot see returns complete=false")
        psbt = node.createpsbt([own_input, UNKNOWN_OUTPOINT], [{self.funder.getnewaddress(): Decimal("3.5")}])
        for descs in (private_descs, public_descs):
            res = node.descriptorprocesspsbt(psbt, descs)
            assert_equal(res["complete"], False)
            self.assert_input_unsigned(res["psbt"], 0)

        self.log.info("With every spent output known, an unsigned multi-leaf input still needs a selected leaf")
        psbt = node.createpsbt([own_input], [{self.funder.getnewaddress(): Decimal("2.99")}])
        assert_raises_rpc_error(-25, "multi-leaf P2MR input: no leaf selected", node.descriptorprocesspsbt, psbt, public_descs)
        assert_equal(node.descriptorprocesspsbt(psbt, private_descs)["complete"], True)


if __name__ == "__main__":
    WalletP2MRMultipartyPSBTTest(__file__).main()
