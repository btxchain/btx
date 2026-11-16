#!/usr/bin/env python3
# Copyright (c) 2018-2022 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

from decimal import Decimal

from test_framework.messages import (
    tx_from_hex,
)
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
    assert_raises_rpc_error,
)
from test_framework.blocktools import (
    TIME_GENESIS_BLOCK,
    REGTEST_GENERIC_P2P_MATMUL_ARGS,
)


class CreateTxWalletTest(BitcoinTestFramework):
    def add_options(self, parser):
        self.add_wallet_options(parser, legacy=False)

    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 1
        self.extra_args = [list(REGTEST_GENERIC_P2P_MATMUL_ARGS) + [
            "-autoshieldcoinbase=0", "-addresstype=p2mr", "-fallbackfee=0.0002",
            "-walletrejectlongchains=1", "-spendzeroconfchange=1",
            "-limitancestorcount=100", "-limitdescendantcount=100",
            "-limitancestorsize=1024", "-limitdescendantsize=1024",
            "-swapnet=0", "-autoupdate=0", "-networkactive=0",
        ]]

    def setup_network(self):
        if self.config["components"].getboolean("ENABLE_MODELNET", fallback=False):
            self.extra_args[0].append("-nomodelnet")
        super().setup_network()

    def restart_with_fee_settings(self, *fee_settings):
        # TestNode replaces extra_args; retain the shared profile, while each
        # fee row replaces rather than accumulates the previous fee override.
        self.restart_node(0, extra_args=self.extra_args[0] + list(fee_settings))

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def run_test(self):
        self.log.info('Create some old blocks')
        self.nodes[0].setmocktime(TIME_GENESIS_BLOCK)
        self.generate(self.nodes[0], 200)
        self.nodes[0].setmocktime(0)

        self.test_anti_fee_sniping()
        self.test_tx_size_too_large()
        self.test_create_too_long_mempool_chain()
        self.test_version3()
        self.test_setfeerate()

    def test_anti_fee_sniping(self):
        self.log.info('Check that we have some (old) blocks and that anti-fee-sniping is disabled')

        # sendtoaddress RPC
        assert_equal(self.nodes[0].getblockchaininfo()['blocks'], 200)
        txid = self.nodes[0].sendtoaddress(self.nodes[0].getnewaddress(), 1)
        tx = self.nodes[0].gettransaction(txid=txid, verbose=True)['decoded']
        assert_equal(tx['locktime'], 0)

        # send RPC
        outputs = [{self.nodes[0].getnewaddress(): 1}]
        res = self.nodes[0].send(outputs=outputs)
        assert(res["complete"])
        tx = self.nodes[0].gettransaction(txid=res['txid'], verbose=True)['decoded']
        assert_equal(tx['locktime'], 0)

        # sendall RPC (don't actually empty the wallet)
        res = self.nodes[0].sendall(recipients=[self.nodes[0].getnewaddress()], add_to_wallet=False)
        assert(res["complete"])
        tx = self.nodes[0].decoderawtransaction(res['hex'])
        assert_equal(tx['locktime'], 0)

        self.log.info('Check that anti-fee-sniping is enabled when we mine a recent block')
        self.generate(self.nodes[0], 1)
        txid = self.nodes[0].sendtoaddress(self.nodes[0].getnewaddress(), 1)
        tx = self.nodes[0].gettransaction(txid=txid, verbose=True)['decoded']
        assert 0 < tx['locktime'] <= 201

        # send RPC
        outputs = [{self.nodes[0].getnewaddress(): 1}]
        res = self.nodes[0].send(outputs=outputs)
        assert(res["complete"])
        tx = self.nodes[0].gettransaction(txid=res['txid'], verbose=True)['decoded']
        assert 0 < tx['locktime'] <= 201

        # sendall RPC
        res = self.nodes[0].sendall(recipients=[self.nodes[0].getnewaddress()], add_to_wallet=False)
        assert(res["complete"])
        tx = self.nodes[0].decoderawtransaction(res['hex'])
        assert 0 < tx['locktime'] <= 201

    def test_tx_size_too_large(self):
        # More than 10kB of outputs, so that we hit -maxtxfee with a high feerate
        outputs = {self.nodes[0].getnewaddress(address_type='p2mr'): 0.000025 for _ in range(400)}
        raw_tx = self.nodes[0].createrawtransaction(inputs=[], outputs=outputs)
        msg = "Fee exceeds maximum configured by user (e.g. -maxtxfee, maxfeerate)"

        for fee_setting in ['-minrelaytxfee=0.01', '-mintxfee=0.01', '-paytxfee=0.01']:
            self.log.info('Check maxtxfee in combination with {}'.format(fee_setting))
            self.restart_with_fee_settings(fee_setting)
            assert_raises_rpc_error(
                -6,
                "Fee exceeds maximum configured by user (e.g. -maxtxfee, maxfeerate)",
                lambda: self.nodes[0].sendmany(dummy="", amounts=outputs),
            )
            assert_raises_rpc_error(
                -4,
                "Fee exceeds maximum configured by user (e.g. -maxtxfee, maxfeerate)",
                lambda: self.nodes[0].fundrawtransaction(hexstring=raw_tx),
            )

        self.log.info('Check maxtxfee in combination with settxfee')
        self.restart_with_fee_settings()
        self.nodes[0].settxfee(0.01)
        assert_raises_rpc_error(
            -6,
            "Fee exceeds maximum configured by user (e.g. -maxtxfee, maxfeerate)",
            lambda: self.nodes[0].sendmany(dummy="", amounts=outputs),
        )
        assert_raises_rpc_error(
            -4,
            "Fee exceeds maximum configured by user (e.g. -maxtxfee, maxfeerate)",
            lambda: self.nodes[0].fundrawtransaction(hexstring=raw_tx),
        )
        self.nodes[0].settxfee(0)

        self.log.info('Check maxtxfee in combination with setfeerate (sat/vB)')
        self.nodes[0].setfeerate(1000)
        assert_raises_rpc_error(-6, msg, self.nodes[0].sendmany, dummy="", amounts=outputs)
        assert_raises_rpc_error(-4, msg, self.nodes[0].fundrawtransaction, hexstring=raw_tx)
        self.nodes[0].setfeerate(0)

    def test_create_too_long_mempool_chain(self):
        self.log.info('Check too-long mempool chain error')
        df_wallet = self.nodes[0].get_wallet_rpc(self.default_wallet_name)

        self.nodes[0].createwallet("too_long")
        test_wallet = self.nodes[0].get_wallet_rpc("too_long")

        # One confirmed coin avoids unsafe inbound/extra change inputs.
        # Start with 1 BTX so the final 0.3 payment is otherwise affordable.
        address = test_wallet.getnewaddress()
        funding = df_wallet.sendtoaddress(address, Decimal("1"), fee_rate=2)
        self.generate(self.nodes[0], 1)
        coins = test_wallet.listunspent()
        assert_equal(len(coins), 1)
        assert_equal(coins[0]["txid"], funding)
        previous = (funding, coins[0]["vout"])
        chain = []
        for count in range(1, 101):
            txid = test_wallet.sendall([test_wallet.getnewaddress()], fee_rate=2)["txid"]
            decoded = self.nodes[0].decoderawtransaction(test_wallet.gettransaction(txid)["hex"])
            assert_equal([(x["txid"], x["vout"]) for x in decoded["vin"]], [previous])
            assert_equal(len(decoded["vout"]), 1)
            entry = self.nodes[0].getmempoolentry(txid)
            assert_equal(entry["ancestorcount"], count)
            assert entry["ancestorsize"] <= 1024 * 1000
            previous = (txid, 0)
            chain.append(txid)
        coins = test_wallet.listunspent(0)
        assert_equal(len(coins), 1)
        assert_equal((coins[0]["txid"], coins[0]["vout"]), previous)
        assert_equal(coins[0]["confirmations"], 0)
        assert coins[0]["safe"] and coins[0]["spendable"]
        assert coins[0]["amount"] > Decimal("0.31")

        # Sending one more chained transaction will fail
        options = {"minconf": 0, "include_unsafe": True, "add_inputs": True, "fee_rate": 2}
        assert_raises_rpc_error(-4, "Unconfirmed UTXOs are available, but spending them creates a chain of transactions that will be rejected by the mempool",
                                test_wallet.send, outputs=[{test_wallet.getnewaddress(): 0.3}], options=options)

        # The refusal must not consume the otherwise affordable long-chain coin.
        assert self.nodes[0].gettxout(*previous) is not None
        assert set(chain) <= set(self.nodes[0].getrawmempool())
        test_wallet.unloadwallet()

    def test_version3(self):
        self.log.info('Check wallet does not create transactions with version=3 yet')
        wallet_rpc = self.nodes[0].get_wallet_rpc(self.default_wallet_name)

        self.nodes[0].createwallet("version3")
        wallet_v3 = self.nodes[0].get_wallet_rpc("version3")

        tx_data = wallet_rpc.send(outputs=[{wallet_v3.getnewaddress(): 25}], options={"change_position": 0})
        wallet_tx_data = wallet_rpc.gettransaction(tx_data["txid"])
        tx_current_version = tx_from_hex(wallet_tx_data["hex"])

        # While version=3 transactions are standard, the CURRENT_VERSION is 2.
        # This test can be removed if CURRENT_VERSION is changed, and replaced with tests that the
        # wallet handles TRUC rules properly.
        assert_equal(tx_current_version.version, 2)
        wallet_v3.unloadwallet()

    def test_setfeerate(self):
        self.log.info("Test setfeerate")
        self.restart_with_fee_settings(
            "-incrementalrelayfee=0.00001",
            "-mintxfee=0.00003141",  # 3.141 sat/vB
        )
        node = self.nodes[0]

        def test_response(*, requested=0, expected=0, error=None, msg):
            assert_equal(node.setfeerate(requested), {"wallet_name": self.default_wallet_name, "fee_rate": expected, ("error" if error else "result"): msg})

        # Test setfeerate with 10.0001 (CFeeRate rounding), "10.001" and "4" sat/vB
        test_response(requested=10.0001, expected=10, msg="Fee rate for transactions with this wallet successfully set to 10.000 sat/vB")
        assert_equal(node.getwalletinfo()["paytxfee"], Decimal("0.00010000"))
        test_response(requested="10.001", expected=Decimal("10.001"), msg="Fee rate for transactions with this wallet successfully set to 10.001 sat/vB")
        assert_equal(node.getwalletinfo()["paytxfee"], Decimal("0.00010001"))
        test_response(requested="4", expected=4, msg="Fee rate for transactions with this wallet successfully set to 4.000 sat/vB")
        assert_equal(node.getwalletinfo()["paytxfee"], Decimal("0.00004000"))

        # Test setfeerate with too-high/low values returns expected errors
        test_response(requested=Decimal("10000.001"), expected=4, error=True, msg="The requested fee rate of 10000.001 sat/vB cannot be greater than the wallet max fee rate of 10000.000 sat/vB. The current setting of 4.000 sat/vB for this wallet remains unchanged.")
        test_response(requested=Decimal("0.999"), expected=4, error=True, msg="The requested fee rate of 0.999 sat/vB cannot be less than the minimum relay fee rate of 1.000 sat/vB. The current setting of 4.000 sat/vB for this wallet remains unchanged.")
        test_response(requested=Decimal("3.140"), expected=4, error=True, msg="The requested fee rate of 3.140 sat/vB cannot be less than the wallet min fee rate of 3.141 sat/vB. The current setting of 4.000 sat/vB for this wallet remains unchanged.")
        assert_equal(node.getwalletinfo()["paytxfee"], Decimal("0.00004000"))

        # Test setfeerate to 3.141 sat/vB
        test_response(requested=3.141, expected=Decimal("3.141"), msg="Fee rate for transactions with this wallet successfully set to 3.141 sat/vB")
        assert_equal(node.getwalletinfo()["paytxfee"], Decimal("0.00003141"))

        # Test setfeerate with values non-representable by CFeeRate
        for invalid_value in [0.00000001, 0.0009, 0.00099999]:
            assert_raises_rpc_error(-3, "Invalid amount", node.setfeerate, amount=invalid_value)

        # Test setfeerate with values rejected by ParseFixedPoint() called in AmountFromValue()
        for invalid_value in ["", 0.000000001, "1.111111111", 11111111111]:
            assert_raises_rpc_error(-3, "Invalid amount", node.setfeerate, amount=invalid_value)

        # Test deactivating setfeerate
        test_response(msg="Fee rate for transactions with this wallet successfully unset. By default, automatic fee selection will be used.")
        assert_equal(node.getwalletinfo()["paytxfee"], 0)

        # Test currently-unset setfeerate with too-high/low values returns expected errors
        test_response(requested=Decimal("10000.001"), error=True, msg="The requested fee rate of 10000.001 sat/vB cannot be greater than the wallet max fee rate of 10000.000 sat/vB. The current setting of 0 (unset) for this wallet remains unchanged.")
        assert_equal(node.getwalletinfo()["paytxfee"], 0)
        test_response(requested=Decimal("0.999"), error=True, msg="The requested fee rate of 0.999 sat/vB cannot be less than the minimum relay fee rate of 1.000 sat/vB. The current setting of 0 (unset) for this wallet remains unchanged.")
        test_response(requested=Decimal("3.140"), error=True, msg="The requested fee rate of 3.140 sat/vB cannot be less than the wallet min fee rate of 3.141 sat/vB. The current setting of 0 (unset) for this wallet remains unchanged.")
        assert_equal(node.getwalletinfo()["paytxfee"], 0)


if __name__ == '__main__':
    CreateTxWalletTest(__file__).main()
