#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""Exercise supplied-parent PSBT updates without local parent discovery."""
from decimal import Decimal
from io import BytesIO

from test_framework.messages import CTransaction
from test_framework.psbt import PSBT, PSBT_IN_NON_WITNESS_UTXO, PSBT_IN_WITNESS_UTXO
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_raises_rpc_error


class P2MRExternalParentTest(BitcoinTestFramework):
    def add_options(self, parser):
        self.add_wallet_options(parser, legacy=False)

    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.wallet_names = []
        # Same wallet-only regtest profile as wallet_p2mr_multiparty_psbt.py.
        self.extra_args = [[
            "-autoshieldcoinbase=0", "-modelnet=0", "-modelbind=off", "-txindex=1",
            "-regtestmatmulbindingheight=2147483647",
            "-regtestmatmulproductdigestheight=2147483647",
            "-regtestmatmulv4height=2147483647",
            "-regtestmatmulrequireproductpayload=0",
        ]]

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def assert_parent_unknown(self, parent_id, vout):
        node = self.nodes[0]
        assert parent_id not in node.getrawmempool()
        assert_equal(node.gettxout(parent_id, vout), None)
        assert_raises_rpc_error(-5, "No such mempool", node.getrawtransaction, parent_id)
        for wallet in (self.funder, self.recipient):
            assert_raises_rpc_error(-5, "Invalid or non-wallet", wallet.gettransaction, parent_id)

    def assert_no_spent_output(self, psbt):
        entry = PSBT.from_base64(psbt).i[0].map
        assert PSBT_IN_NON_WITNESS_UTXO not in entry
        assert PSBT_IN_WITNESS_UTXO not in entry
        assert "final_scriptwitness" not in self.nodes[0].decodepsbt(psbt)["inputs"][0]
        assert_equal(self.recipient.walletprocesspsbt(psbt)["complete"], False)

    def assert_spent_output(self, psbt, parent_hex, vout):
        parent = CTransaction()
        parent.deserialize(BytesIO(bytes.fromhex(parent_hex)))
        entry = PSBT.from_base64(psbt).i[0].map
        assert PSBT_IN_WITNESS_UTXO in entry or PSBT_IN_NON_WITNESS_UTXO in entry
        if PSBT_IN_WITNESS_UTXO in entry:
            assert_equal(entry[PSBT_IN_WITNESS_UTXO], parent.vout[vout].serialize())
        if PSBT_IN_NON_WITNESS_UTXO in entry:
            assert_equal(entry[PSBT_IN_NON_WITNESS_UTXO], parent.serialize_without_witness())

    def run_test(self):
        node = self.nodes[0]
        node.createwallet(wallet_name="funder", descriptors=True)
        node.createwallet(wallet_name="recipient", descriptors=True)
        self.funder = node.get_wallet_rpc("funder")
        self.recipient = node.get_wallet_rpc("recipient")
        for _ in range(3):
            self.generatetoaddress(node, 1, self.funder.getnewaddress(), sync_fun=self.no_op)
        burn = self.recipient.getnewaddress()
        self.generatetoaddress(node, 100, burn, sync_fun=self.no_op)
        receive = self.recipient.getnewaddress()
        script = self.recipient.getaddressinfo(receive)["scriptPubKey"]
        parent_psbt = self.funder.walletcreatefundedpsbt([], {receive: Decimal("1")})["psbt"]
        parent = self.funder.walletprocesspsbt(parent_psbt)
        assert_equal(parent["complete"], True)
        parent_hex = parent["hex"]
        decoded_parent = node.decoderawtransaction(parent_hex)
        parent_id = decoded_parent["txid"]
        matches = [v for v in decoded_parent["vout"] if v["scriptPubKey"]["hex"] == script]
        assert_equal(len(matches), 1)
        vout = matches[0]["n"]
        assert_equal(matches[0]["value"], Decimal("1"))
        assert_equal(node.testmempoolaccept([parent_hex])[0]["allowed"], True)
        self.assert_parent_unknown(parent_id, vout)
        destination = self.funder.getnewaddress()
        child = node.createpsbt([{"txid": parent_id, "vout": vout}], {destination: Decimal("0.99")})
        original_tx = node.decodepsbt(child)["tx"]
        old_block = node.getblockhash(1)
        irrelevant_id = node.getblock(old_block)["tx"][0]
        assert irrelevant_id != parent_id
        irrelevant = node.getrawtransaction(irrelevant_id, False, old_block)

        def descriptor_update(parents):
            result = node.descriptorprocesspsbt(child, [], {"prevtxs": parents})
            assert_equal(result["complete"], False)
            return result["psbt"]

        routes = {
            "utxoupdatepsbt": lambda parents: node.utxoupdatepsbt(psbt=child, prevtxs=parents),
            "descriptorprocesspsbt": descriptor_update,
        }
        final_hex = None
        for name, update in routes.items():
            self.log.info("%s: parent absent from node and both wallets", name)
            self.assert_parent_unknown(parent_id, vout)
            self.assert_no_spent_output(child)
            self.assert_no_spent_output(update([]))
            self.assert_no_spent_output(update([irrelevant]))
            updated = update([parent_hex])
            self.assert_spent_output(updated, parent_hex, vout)
            assert_equal(node.decodepsbt(updated)["tx"], original_tx)
            signed = self.recipient.walletprocesspsbt(updated)
            assert_equal(signed["complete"], True)
            finalized = node.finalizepsbt(signed["psbt"])
            assert_equal(finalized["complete"], True)
            final_hex = finalized["hex"]
            signed_tx = node.decoderawtransaction(final_hex)
            assert_equal(signed_tx["txid"], original_tx["txid"])
            assert_equal(signed_tx["vin"][0]["txid"], parent_id)
            assert_equal(signed_tx["vin"][0]["vout"], vout)
            assert_equal(signed_tx["vout"], original_tx["vout"])
            assert signed_tx["vin"][0]["txinwitness"]
            self.assert_parent_unknown(parent_id, vout)
            self.log.info("%s: exact spent output supplied, wallet signed and finalized", name)

        # Deliberately relay only after the offline-path assertions finish.
        assert_equal(node.sendrawtransaction(parent_hex), parent_id)
        assert_equal(node.testmempoolaccept([final_hex])[0]["allowed"], True)
        child_id = node.sendrawtransaction(final_hex)
        block = self.generatetoaddress(node, 1, burn, sync_fun=self.no_op)[0]
        txids = node.getblock(block)["tx"]
        assert parent_id in txids
        assert child_id in txids
        self.log.info("Both supplied-parent routes passed; parent and child confirmed")


if __name__ == "__main__":
    P2MRExternalParentTest(__file__).main()
