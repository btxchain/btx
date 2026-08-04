#!/usr/bin/env python3
# Copyright (c) 2018-2022 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test the avoid_reuse and setwalletflag features."""

from decimal import Decimal

from test_framework.blocktools import MAX_STANDARD_TX_WEIGHT
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_approx,
    assert_equal,
    assert_raises_rpc_error,
)

def reset_balance(node, discardaddr):
    '''Throw away all owned coins by the node so it gets a balance of 0.'''
    balance = node.getbalance(avoid_reuse=False)
    if balance > 0.5:
        node.sendtoaddress(address=discardaddr, amount=balance, subtractfeefromamount=True, avoid_reuse=False)

def count_unspent(node):
    '''Count the unspent outputs for the given node and return various statistics'''
    r = {
        "total": {
            "count": 0,
            "sum": 0,
        },
        "reused": {
            "count": 0,
            "sum": 0,
        },
    }
    supports_reused = True
    for utxo in node.listunspent(minconf=0):
        r["total"]["count"] += 1
        r["total"]["sum"] += utxo["amount"]
        if supports_reused and "reused" in utxo:
            if utxo["reused"]:
                r["reused"]["count"] += 1
                r["reused"]["sum"] += utxo["amount"]
        else:
            supports_reused = False
    r["reused"]["supported"] = supports_reused
    return r

def assert_unspent(node, total_count=None, total_sum=None, reused_supported=None, reused_count=None, reused_sum=None, margin=0.001):
    '''Make assertions about a node's unspent output statistics'''
    stats = count_unspent(node)
    if total_count is not None:
        assert_equal(stats["total"]["count"], total_count)
    if total_sum is not None:
        assert_approx(stats["total"]["sum"], total_sum, margin)
    if reused_supported is not None:
        assert_equal(stats["reused"]["supported"], reused_supported)
    if reused_count is not None:
        assert_equal(stats["reused"]["count"], reused_count)
    if reused_sum is not None:
        assert_approx(stats["reused"]["sum"], reused_sum, margin)

def assert_balances(node, mine, margin=0.001):
    '''Make assertions about a node's getbalances output'''
    got = node.getbalances()["mine"]
    for k,v in mine.items():
        assert_approx(got[k], v, margin)

class AvoidReuseTest(BitcoinTestFramework):
    def add_options(self, parser):
        self.add_wallet_options(parser)

    def set_test_params(self):
        self.num_nodes = 2
        # whitelist peers to speed up tx relay / mempool sync
        self.noban_tx_relay = True

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def run_test(self):
        '''Set up initial chain and run tests defined below'''

        self.test_persistence()
        self.test_immutable()

        self.generate(self.nodes[0], 110)
        self.test_change_remains_change(self.nodes[1])
        reset_balance(self.nodes[1], self.nodes[0].getnewaddress())
        self.test_sending_from_reused_address_without_avoid_reuse()
        # BTX wallets generate native P2MR destinations in both storage modes.
        # Exercise that supported reuse path instead of requesting disabled
        # Bitcoin address encodings from getnewaddress.
        reset_balance(self.nodes[1], self.nodes[0].getnewaddress())
        self.test_sending_from_reused_address_fails("p2mr")
        reset_balance(self.nodes[1], self.nodes[0].getnewaddress())
        self.test_getbalances_used()
        reset_balance(self.nodes[1], self.nodes[0].getnewaddress())
        self.test_full_destination_group_is_preferred()
        reset_balance(self.nodes[1], self.nodes[0].getnewaddress())
        self.test_all_destination_groups_are_used()

    def test_persistence(self):
        '''Test that wallet files persist the avoid_reuse flag.'''
        self.log.info("Test wallet files persist avoid_reuse flag")

        # Configure node 1 to use avoid_reuse
        self.nodes[1].setwalletflag('avoid_reuse')

        # Flags should be node1.avoid_reuse=false, node2.avoid_reuse=true
        assert_equal(self.nodes[0].getwalletinfo()["avoid_reuse"], False)
        assert_equal(self.nodes[1].getwalletinfo()["avoid_reuse"], True)

        self.restart_node(1)
        self.connect_nodes(0, 1)

        # Flags should still be node1.avoid_reuse=false, node2.avoid_reuse=true
        assert_equal(self.nodes[0].getwalletinfo()["avoid_reuse"], False)
        assert_equal(self.nodes[1].getwalletinfo()["avoid_reuse"], True)

        # Attempting to set flag to its current state should throw
        assert_raises_rpc_error(-8, "Wallet flag is already set to false", self.nodes[0].setwalletflag, 'avoid_reuse', False)
        assert_raises_rpc_error(-8, "Wallet flag is already set to true", self.nodes[1].setwalletflag, 'avoid_reuse', True)

        assert_raises_rpc_error(-8, "Unknown wallet flag: abc", self.nodes[0].setwalletflag, 'abc', True)

        # Create a wallet with avoid reuse, and test that disabling it afterwards persists
        self.nodes[1].createwallet(wallet_name="avoid_reuse_persist", avoid_reuse=True)
        w = self.nodes[1].get_wallet_rpc("avoid_reuse_persist")
        assert_equal(w.getwalletinfo()["avoid_reuse"], True)
        w.setwalletflag("avoid_reuse", False)
        assert_equal(w.getwalletinfo()["avoid_reuse"], False)
        w.unloadwallet()
        self.nodes[1].loadwallet("avoid_reuse_persist")
        assert_equal(w.getwalletinfo()["avoid_reuse"], False)
        w.unloadwallet()

    def test_immutable(self):
        '''Test immutable wallet flags'''
        self.log.info("Test immutable wallet flags")

        # Attempt to set the disable_private_keys flag; this should not work
        assert_raises_rpc_error(-8, "Wallet flag is immutable", self.nodes[1].setwalletflag, 'disable_private_keys')

        tempwallet = ".wallet_avoidreuse.py_test_immutable_wallet.dat"

        # Create a wallet with disable_private_keys set; this should work
        self.nodes[1].createwallet(wallet_name=tempwallet, disable_private_keys=True)
        w = self.nodes[1].get_wallet_rpc(tempwallet)

        # Attempt to unset the disable_private_keys flag; this should not work
        assert_raises_rpc_error(-8, "Wallet flag is immutable", w.setwalletflag, 'disable_private_keys', False)

        # Unload temp wallet
        self.nodes[1].unloadwallet(tempwallet)

    def test_change_remains_change(self, node):
        self.log.info("Test that change doesn't turn into non-change when spent")

        reset_balance(node, node.getnewaddress())
        addr = node.getnewaddress()
        txid = node.sendtoaddress(addr, 1)
        out = node.listunspent(minconf=0, query_options={'minimumAmount': 2})
        assert_equal(len(out), 1)
        assert_equal(out[0]['txid'], txid)
        changeaddr = out[0]['address']

        # Make sure it's starting out as change as expected
        assert node.getaddressinfo(changeaddr)['ischange']
        for logical_tx in node.listtransactions():
            assert logical_tx.get('address') != changeaddr

        # Spend it
        reset_balance(node, node.getnewaddress())

        # It should still be change
        assert node.getaddressinfo(changeaddr)['ischange']
        for logical_tx in node.listtransactions():
            assert logical_tx.get('address') != changeaddr

    def test_sending_from_reused_address_without_avoid_reuse(self):
        '''
        Test the same as test_sending_from_reused_address_fails, except send the 10 BTC with
        the avoid_reuse flag set to false. This means the 10 BTC send should succeed,
        where it fails in test_sending_from_reused_address_fails.
        '''
        self.log.info("Test sending from reused address with avoid_reuse=false")

        fundaddr = self.nodes[1].getnewaddress()
        retaddr = self.nodes[0].getnewaddress()

        self.nodes[0].sendtoaddress(fundaddr, 10)
        self.generate(self.nodes[0], 1)

        # listunspent should show 1 single, unused 10 btc output
        assert_unspent(self.nodes[1], total_count=1, total_sum=10, reused_supported=True, reused_count=0)
        # getbalances should show no used, 10 btc trusted
        assert_balances(self.nodes[1], mine={"used": 0, "trusted": 10})
        # node 0 should not show a used entry, as it does not enable avoid_reuse
        assert "used" not in self.nodes[0].getbalances()["mine"]

        self.nodes[1].sendtoaddress(retaddr, 5)
        self.generate(self.nodes[0], 1)

        # listunspent should show 1 single, unused 5 btc output
        assert_unspent(self.nodes[1], total_count=1, total_sum=5, reused_supported=True, reused_count=0, margin=0.005)
        # getbalances should show no used, 5 btc trusted
        assert_balances(self.nodes[1], mine={"used": 0, "trusted": 5}, margin=0.005)

        self.nodes[0].sendtoaddress(fundaddr, 10)
        self.generate(self.nodes[0], 1)

        # listunspent should show 2 total outputs (5, 10 btc), one unused (5), one reused (10)
        assert_unspent(self.nodes[1], total_count=2, total_sum=15, reused_count=1, reused_sum=10, margin=0.005)
        # getbalances should show 10 used, 5 btc trusted
        assert_balances(self.nodes[1], mine={"used": 10, "trusted": 5}, margin=0.005)

        self.nodes[1].sendtoaddress(address=retaddr, amount=10, avoid_reuse=False)

        # listunspent should show 1 total outputs (5 btc), unused
        assert_unspent(self.nodes[1], total_count=1, total_sum=5, reused_count=0, margin=0.005)
        # getbalances should show no used, 5 btc trusted
        assert_balances(self.nodes[1], mine={"used": 0, "trusted": 5}, margin=0.005)

        # node 1 should now have about 5 btc left (for both cases)
        assert_approx(self.nodes[1].getbalance(), 5, 0.005)
        assert_approx(self.nodes[1].getbalance(avoid_reuse=False), 5, 0.005)

    def test_sending_from_reused_address_fails(self, second_addr_type):
        '''
        Test the simple case where [1] generates a new address A, then
        [0] sends 10 BTC to A.
        [1] spends 5 BTC from A. (leaving roughly 5 BTC useable)
        [0] sends 10 BTC to A again.
        [1] tries to spend 10 BTC (fails; dirty).
        [1] tries to spend 4 BTC (succeeds; change address sufficient)
        '''
        self.log.info("Test sending from reused {} address fails".format(second_addr_type))

        assert_equal(second_addr_type, "p2mr")
        fundaddr = self.nodes[1].getnewaddress()
        retaddr = self.nodes[0].getnewaddress()

        self.nodes[0].sendtoaddress(fundaddr, 10)
        self.generate(self.nodes[0], 1)

        # listunspent should show 1 single, unused 10 btc output
        assert_unspent(self.nodes[1], total_count=1, total_sum=10, reused_supported=True, reused_count=0)
        # getbalances should show no used, 10 btc trusted
        assert_balances(self.nodes[1], mine={"used": 0, "trusted": 10})

        self.nodes[1].sendtoaddress(retaddr, 5)
        self.generate(self.nodes[0], 1)

        # listunspent should show 1 single, unused 5 btc output
        assert_unspent(self.nodes[1], total_count=1, total_sum=5, reused_supported=True, reused_count=0, margin=0.005)
        # getbalances should show no used, 5 btc trusted
        assert_balances(self.nodes[1], mine={"used": 0, "trusted": 5}, margin=0.005)

        self.nodes[0].sendtoaddress(fundaddr, 10)
        self.generate(self.nodes[0], 1)

        # listunspent should show 2 total outputs (5, 10 btc), one unused (5), one reused (10)
        assert_unspent(self.nodes[1], total_count=2, total_sum=15, reused_count=1, reused_sum=10, margin=0.005)
        # getbalances should show 10 used, 5 btc trusted
        assert_balances(self.nodes[1], mine={"used": 10, "trusted": 5}, margin=0.005)

        # node 1 should now have a balance of 5 (no dirty) or 15 (including dirty)
        assert_approx(self.nodes[1].getbalance(), 5, 0.005)
        assert_approx(self.nodes[1].getbalance(avoid_reuse=False), 15, 0.005)

        assert_raises_rpc_error(-6, "Insufficient funds", self.nodes[1].sendtoaddress, retaddr, 10)

        self.nodes[1].sendtoaddress(retaddr, 4)

        # listunspent should show 2 total outputs (1, 10 btc), one unused (1), one reused (10)
        assert_unspent(self.nodes[1], total_count=2, total_sum=11, reused_count=1, reused_sum=10, margin=0.005)
        # getbalances should show 10 used, 1 btc trusted
        assert_balances(self.nodes[1], mine={"used": 10, "trusted": 1}, margin=0.005)

        # node 1 should now have about 1 btc left (no dirty) and 11 (including dirty)
        assert_approx(self.nodes[1].getbalance(), 1, 0.005)
        assert_approx(self.nodes[1].getbalance(avoid_reuse=False), 11, 0.005)

    def test_getbalances_used(self):
        '''
        getbalances and listunspent should pick up on reused addresses
        immediately, even for address reusing outputs created before the first
        transaction was spending from that address
        '''
        self.log.info("Test getbalances used category")

        # node under test should be completely empty
        assert_equal(self.nodes[1].getbalance(avoid_reuse=False), 0)

        new_addr = self.nodes[1].getnewaddress()
        ret_addr = self.nodes[0].getnewaddress()

        # send multiple transactions, reusing one address
        for _ in range(101):
            self.nodes[0].sendtoaddress(new_addr, 1)

        self.generate(self.nodes[0], 1)

        # send transaction that should not use all the available outputs
        # per the current coin selection algorithm
        txid = self.nodes[1].sendtoaddress(ret_addr, 5)
        transaction = self.nodes[1].getrawtransaction(txid, 1)
        input_count = len(transaction["vin"])
        assert 1 < input_count < 101
        assert transaction["weight"] <= MAX_STANDARD_TX_WEIGHT

        # getbalances and listunspent should show the remaining outputs
        # in the reused address as used/reused. Weight-aware APS spends one
        # bounded group and returns the remainder as fresh change.
        fee = -self.nodes[1].gettransaction(txid)["fee"]
        reused_count = 101 - input_count
        trusted_change = Decimal(input_count) - Decimal(5) - fee
        assert_unspent(
            self.nodes[1],
            total_count=reused_count + 1,
            total_sum=Decimal(96) - fee,
            reused_count=reused_count,
            reused_sum=Decimal(reused_count),
        )
        assert_balances(
            self.nodes[1],
            mine={"used": Decimal(reused_count), "trusted": trusted_change},
        )

    def test_full_destination_group_is_preferred(self):
        '''
        Test the case where [1] only has 101 outputs of 1 BTC in the same reused
        address and tries to send a small payment of 0.5 BTC. The wallet should
        prefer one full, weight-bounded reused-address group over a single input.
        '''
        self.log.info("Test that full destination groups are preferred in coin selection")

        # Node under test should be empty
        assert_equal(self.nodes[1].getbalance(avoid_reuse=False), 0)

        new_addr = self.nodes[1].getnewaddress()
        ret_addr = self.nodes[0].getnewaddress()

        # Send 101 outputs of 1 BTC to the same, reused address in the wallet
        for _ in range(101):
            self.nodes[0].sendtoaddress(new_addr, 1)

        self.generate(self.nodes[0], 1)

        # Sending a transaction that is smaller than each one of the
        # available outputs
        txid = self.nodes[1].sendtoaddress(address=ret_addr, amount=0.5)
        transaction = self.nodes[1].getrawtransaction(txid, 1)
        inputs = transaction["vin"]

        assert 1 < len(inputs) < 101
        assert transaction["weight"] <= MAX_STANDARD_TX_WEIGHT
        self.full_destination_group_size = len(inputs)

    def test_all_destination_groups_are_used(self):
        '''
        Test the case where [1] only has 202 outputs of 1 BTC in the same reused
        address and must combine several weight-bounded destination groups.
        Size the payment from the full-group size observed above so it cannot be
        funded by a single group, without assuming that 100 native P2MR inputs
        fit in one standard transaction.
        '''
        self.log.info("Test that multiple destination groups are combined")

        # Node under test should be empty
        assert_equal(self.nodes[1].getbalance(avoid_reuse=False), 0)

        new_addr = self.nodes[1].getnewaddress()
        ret_addr = self.nodes[0].getnewaddress()

        # Send 202 outputs of 1 BTC to the same, reused address in the wallet.
        for _ in range(202):
            self.nodes[0].sendtoaddress(new_addr, 1)

        self.generate(self.nodes[0], 1)

        group_size = self.full_destination_group_size
        amount = Decimal(group_size) + Decimal("0.5")
        txid = self.nodes[1].sendtoaddress(address=ret_addr, amount=amount)
        transaction = self.nodes[1].getrawtransaction(txid, 1)
        assert group_size < len(transaction["vin"]) < 202
        assert transaction["weight"] <= MAX_STANDARD_TX_WEIGHT


if __name__ == '__main__':
    AvoidReuseTest(__file__).main()
