#!/usr/bin/env python3
# Copyright (c) 2018-2022 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test createwallet watchonly arguments.
"""

from test_framework.blocktools import COINBASE_MATURITY
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
    assert_raises_rpc_error
)


class CreateWalletWatchonlyTest(BitcoinTestFramework):
    def add_options(self, parser):
        self.add_wallet_options(parser, legacy=False)

    def set_test_params(self):
        self.num_nodes = 1

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def run_test(self):
        node = self.nodes[0]

        self.nodes[0].createwallet(wallet_name='default', descriptors=True)
        def_wallet = node.get_wallet_rpc('default')

        a1 = def_wallet.getnewaddress()
        wo_change = def_wallet.getnewaddress()
        wo_addr = def_wallet.getnewaddress()

        self.nodes[0].createwallet(wallet_name='wo', disable_private_keys=True, blank=True, descriptors=True)
        wo_wallet = node.get_wallet_rpc('wo')

        def fixed_p2mr_descriptor(address):
            mldsa_key = def_wallet.exportpqkey(address, "ml-dsa-44")["key"]
            slhdsa_key = def_wallet.exportpqkey(address, "slh-dsa-shake-128s")["key"]
            descriptor = node.getdescriptorinfo(f"mr({mldsa_key},{slhdsa_key})")["descriptor"]
            assert_equal(node.deriveaddresses(descriptor), [address])
            return descriptor

        imported = wo_wallet.importdescriptors([
            {
                "desc": fixed_p2mr_descriptor(wo_addr),
                "timestamp": "now",
                "active": False,
            },
            {
                "desc": fixed_p2mr_descriptor(wo_change),
                "timestamp": "now",
                "active": False,
            },
        ])
        assert_equal(imported, [{"success": True}, {"success": True}])

        # generate some btc for testing
        self.generatetoaddress(node, COINBASE_MATURITY + 1, a1)

        # send 1 btc to our watch-only address
        txid = def_wallet.sendtoaddress(wo_addr, 1)
        self.generate(self.nodes[0], 1)

        # DescriptorScriptPubKeyMan owns every imported descriptor even when
        # the wallet has no private keys. Balance/history RPCs therefore do not
        # classify these entries as legacy ISMINE_WATCH_ONLY or filter them via
        # include_watchonly. Funding RPCs below still require includeWatching
        # because the transaction must be completed by the external signer.
        self.log.info('Testing private-key-disabled descriptor balance semantics')
        assert_equal(wo_wallet.getbalance(), 1)
        assert_equal(len(wo_wallet.listtransactions()), 1)
        assert_equal(wo_wallet.getbalance(include_watchonly=False), 1)

        self.log.info('Test sending from a watch-only wallet raises RPC error')
        msg = "Error: Private keys are disabled for this wallet"
        assert_raises_rpc_error(-4, msg, wo_wallet.sendtoaddress, a1, 0.1)
        assert_raises_rpc_error(-4, msg, wo_wallet.sendmany, amounts={a1: 0.1})

        self.log.info('Testing listreceivedbyaddress descriptor ownership')
        result = wo_wallet.listreceivedbyaddress()
        assert_equal(len(result), 1)
        assert "involvesWatchonly" not in result[0]
        result = wo_wallet.listreceivedbyaddress(include_watchonly=False)
        assert_equal(len(result), 1)

        self.log.info('Testing listreceivedbylabel descriptor ownership')
        result = wo_wallet.listreceivedbylabel()
        assert_equal(len(result), 1)
        assert "involvesWatchonly" not in result[0]
        result = wo_wallet.listreceivedbylabel(include_watchonly=False)
        assert_equal(len(result), 1)

        self.log.info('Testing listtransactions descriptor ownership')
        result = wo_wallet.listtransactions()
        assert_equal(len(result), 1)
        assert "involvesWatchonly" not in result[0]
        result = wo_wallet.listtransactions(include_watchonly=False)
        assert_equal(len(result), 1)

        self.log.info('Testing listsinceblock descriptor ownership')
        result = wo_wallet.listsinceblock()
        assert_equal(len(result["transactions"]), 1)
        assert "involvesWatchonly" not in result["transactions"][0]
        result = wo_wallet.listsinceblock(include_watchonly=False)
        assert_equal(len(result["transactions"]), 1)

        self.log.info('Testing gettransaction descriptor ownership')
        result = wo_wallet.gettransaction(txid)
        assert "involvesWatchonly" not in result["details"][0]
        result = wo_wallet.gettransaction(txid=txid, include_watchonly=False)
        assert_equal(len(result["details"]), 1)

        self.log.info('Testing walletcreatefundedpsbt watch-only defaults')
        inputs = []
        outputs = [{a1: 0.5}]
        options = {'changeAddress': wo_change}
        no_wo_options = {'changeAddress': wo_change, 'includeWatching': False}

        result = wo_wallet.walletcreatefundedpsbt(inputs=inputs, outputs=outputs, **options)
        assert_equal("psbt" in result, True)
        assert_raises_rpc_error(-4, "Insufficient funds", wo_wallet.walletcreatefundedpsbt, inputs, outputs, 0, no_wo_options)

        self.log.info('Testing fundrawtransaction watch-only defaults')
        rawtx = wo_wallet.createrawtransaction(inputs=inputs, outputs=outputs)
        result = wo_wallet.fundrawtransaction(hexstring=rawtx, **options)
        assert_equal("hex" in result, True)
        assert_raises_rpc_error(-4, "Insufficient funds", wo_wallet.fundrawtransaction, rawtx, no_wo_options)



if __name__ == '__main__':
    CreateWalletWatchonlyTest(__file__).main()
